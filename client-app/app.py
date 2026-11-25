"""Aplicação web (Flask) que autentica via Keycloak com Authorization Code Flow.

APP_MODE=vulnerable  -> client `webapp-vulnerable`, com falhas DIDÁTICAS plantadas
APP_MODE=secure      -> client `webapp-secure`, com as correções

Diferenças (cada uma marcada no código com [VULN] / [SEC]):
  state            vulnerable: não envia nem valida        | secure: aleatório, validado, uso único
  PKCE             vulnerable: não usa                     | secure: S256, verifier só na sessão do servidor
  nonce / ID token vulnerable: não valida                  | secure: assinatura, iss, aud, exp e nonce
  escopos          vulnerable: pede tudo sempre            | secure: mínimo + step-up sob demanda
  armazenamento    vulnerable: tokens no cookie, sem       | secure: sessão no servidor, cookie só com id
                   HttpOnly, e token impresso no log       |         opaco (HttpOnly, SameSite=Lax)
  /search          vulnerable: XSS refletido               | secure: escape + CSP
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
from urllib.parse import urlencode

import jwt
import requests
from flask import Flask, abort, redirect, render_template, request, session, url_for
from jwt import PyJWKClient
from markupsafe import Markup
from werkzeug.exceptions import HTTPException

SECURE_BASE_SCOPES = ["openid", "profile", "email", "api:read"]
ALL_SCOPES = SECURE_BASE_SCOPES + ["api:write", "api:admin"]
STEP_UP_ALLOWED = ("api:write", "api:admin")
SAFE_NEXT = ("/", "/profile", "/notes", "/admin")   # evita open redirect via ?next=


def pkce_challenge(verifier):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def pkce_pair():
    verifier = secrets.token_urlsafe(64)        # 86 caracteres (RFC 7636: 43-128)
    return verifier, pkce_challenge(verifier)


def create_app(mode=None, **overrides):
    cfg = {
        "MODE": mode or os.environ.get("APP_MODE", "vulnerable"),
        "KC_PUBLIC": os.environ.get("KEYCLOAK_PUBLIC_URL", "http://localhost:8080"),
        "KC_INTERNAL": os.environ.get("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080"),
        "REALM": os.environ.get("KEYCLOAK_REALM", "seminario"),
        "API_URL": os.environ.get("API_URL", "http://resource-api:5001"),
        "REDIRECT_URI": os.environ.get("REDIRECT_URI", "http://localhost:5000/callback"),
        "POST_LOGOUT_URI": os.environ.get("POST_LOGOUT_URI", "http://localhost:5000/"),
        "SECRET": os.environ.get("FLASK_SECRET_KEY", "troque-esta-chave"),
        "KEY_GETTER": None,
    }
    cfg.update(overrides)
    if cfg["MODE"] not in ("vulnerable", "secure"):
        raise ValueError("APP_MODE deve ser 'vulnerable' ou 'secure'")
    secure_mode = cfg["MODE"] == "secure"
    client_id = "webapp-secure" if secure_mode else "webapp-vulnerable"

    oidc = f"/realms/{cfg['REALM']}/protocol/openid-connect"
    issuer = f"{cfg['KC_PUBLIC']}/realms/{cfg['REALM']}"
    auth_url = f"{cfg['KC_PUBLIC']}{oidc}/auth"            # o navegador acessa por aqui
    logout_url = f"{cfg['KC_PUBLIC']}{oidc}/logout"
    token_url = f"{cfg['KC_INTERNAL']}{oidc}/token"        # o servidor acessa por aqui (Docker)
    jwks = PyJWKClient(f"{cfg['KC_INTERNAL']}{oidc}/certs")
    key_getter = cfg["KEY_GETTER"] or (lambda token: jwks.get_signing_key_from_jwt(token).key)

    app = Flask(__name__)
    app.secret_key = cfg["SECRET"]
    app.config.update(
        SESSION_COOKIE_NAME=f"session_{cfg['MODE']}",
        SESSION_COOKIE_HTTPONLY=secure_mode,                     # [VULN] JS consegue ler o cookie
        SESSION_COOKIE_SAMESITE="Lax" if secure_mode else None,
        SESSION_COOKIE_SECURE=False,                             # laboratório em HTTP
    )

    # ------------------------------------------------------------------ sessão
    store = {}   # [SEC] sid -> dados da sessão (só existe no servidor)

    def data(create=True):
        """Dados do usuário. [VULN] vulnerable: o próprio cookie assinado (tokens ficam no cliente).
        [SEC] secure: dicionário no servidor, o cookie só carrega um id aleatório."""
        if not secure_mode:
            return session
        sid = session.get("sid")
        if sid in store:
            return store[sid]
        if not create:
            return {}
        sid = secrets.token_urlsafe(32)
        session["sid"] = sid
        store[sid] = {}
        return store[sid]

    def new_session():
        """Sessão nova após o login (evita session fixation)."""
        if not secure_mode:
            session.clear()
            return session
        store.pop(session.get("sid"), None)
        session.clear()
        sid = secrets.token_urlsafe(32)
        session["sid"] = sid
        store[sid] = {}
        return store[sid]

    def check_csrf():
        sent = request.form.get("csrf", "").encode()
        expected = data(create=False).get("csrf", "").encode()
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, "Token CSRF inválido")

    # ------------------------------------------------------------------ templates
    @app.context_processor
    def inject():
        d = data(create=False)
        return {"mode": cfg["MODE"], "client_id": client_id, "user": d.get("username"),
                "csrf": d.get("csrf", ""), "granted": d.get("granted_scopes", [])}

    @app.errorhandler(HTTPException)
    def http_error(e):
        return render_template("error.html", code=e.code, message=e.description), e.code

    @app.after_request
    def security_headers(resp):
        if secure_mode:   # [SEC]
            resp.headers["Content-Security-Policy"] = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'"
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Referrer-Policy"] = "no-referrer"
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ------------------------------------------------------------------ fluxo OAuth2 / OIDC
    @app.get("/login")
    def login():
        d = data()
        extra = request.args.get("scope", "").split()
        nxt = request.args.get("next", "/")
        d["next"] = nxt if nxt in SAFE_NEXT else "/"

        if secure_mode:   # [SEC] escopo mínimo; escopos extras só de uma lista permitida
            scopes = list(SECURE_BASE_SCOPES)
            wanted = set(extra) | set(d.get("granted_scopes", []))
            scopes += [s for s in STEP_UP_ALLOWED if s in wanted]
            d["stepup_tried"] = " ".join(s for s in extra if s in STEP_UP_ALLOWED)
        else:             # [VULN] pede todos os escopos, sempre
            scopes = list(ALL_SCOPES)

        params = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": cfg["REDIRECT_URI"],
            "scope": " ".join(scopes),
        }
        if secure_mode:   # [SEC] state + nonce + PKCE
            verifier, challenge = pkce_pair()
            oauth = {"state": secrets.token_urlsafe(32), "nonce": secrets.token_urlsafe(32),
                     "verifier": verifier}
            d["oauth"] = oauth
            params.update(state=oauth["state"], nonce=oauth["nonce"],
                          code_challenge=challenge, code_challenge_method="S256")
        # [VULN] sem state, sem nonce, sem PKCE
        return redirect(f"{auth_url}?{urlencode(params)}")

    @app.get("/callback")
    def callback():
        if "error" in request.args:
            abort(400, f"O servidor de autorização retornou erro: {request.args.get('error')}")
        code = request.args.get("code")
        if not code:
            abort(400, "Parâmetro 'code' ausente")
        d = data()
        verifier = nonce = None
        if secure_mode:   # [SEC] valida state (uso único) antes de qualquer coisa
            oauth = d.pop("oauth", None)
            got = request.args.get("state", "").encode()
            if not oauth or not hmac.compare_digest(oauth["state"].encode(), got):
                abort(400, "state inválido ou ausente: possível CSRF no login")
            verifier, nonce = oauth["verifier"], oauth["nonce"]
        # [VULN] aceita qualquer code que chegue aqui, mesmo sem ter iniciado o login

        form = {"grant_type": "authorization_code", "code": code,
                "redirect_uri": cfg["REDIRECT_URI"], "client_id": client_id}
        if verifier:      # [SEC] prova de posse do code
            form["code_verifier"] = verifier
        try:
            resp = requests.post(token_url, data=form, timeout=10)
        except requests.RequestException:
            abort(502, "Falha ao contatar o servidor de autorização")
        if resp.status_code != 200:
            abort(400, "O servidor de autorização recusou a troca do code")
        tok = resp.json()
        if not secure_mode:   # [VULN] token completo no log da aplicação
            app.logger.info("[VULNERAVEL] resposta do endpoint de token: %s", tok)

        access = tok.get("access_token")
        if not access:
            abort(502, "Resposta sem access_token")
        try:
            if secure_mode:   # [SEC] valida o ID token
                claims = jwt.decode(
                    tok.get("id_token", ""), key_getter(tok.get("id_token", "")),
                    algorithms=["RS256"], audience=client_id, issuer=issuer,
                    options={"require": ["exp", "iss", "aud", "sub"]})
                if not hmac.compare_digest(str(claims.get("nonce", "")).encode(), nonce.encode()):
                    raise jwt.InvalidTokenError("nonce divergente")
            else:             # [VULN] lê o ID token sem verificar nada
                claims = (jwt.decode(tok["id_token"], options={"verify_signature": False})
                          if tok.get("id_token") else {})
        except jwt.PyJWTError:
            abort(400, "ID token inválido")

        keep_next, tried = d.get("next", "/"), d.get("stepup_tried")
        d = new_session()
        d.update(access_token=access, granted_scopes=(tok.get("scope") or "").split(),
                 username=claims.get("preferred_username", "?"), csrf=secrets.token_urlsafe(24),
                 fresh=True)
        if tried:
            d["stepup_tried"] = tried
        return redirect(keep_next if keep_next in SAFE_NEXT else "/")

    @app.post("/logout")
    def logout():
        check_csrf()
        data().clear()
        if secure_mode:
            store.pop(session.get("sid"), None)
        session.clear()
        q = urlencode({"client_id": client_id, "post_logout_redirect_uri": cfg["POST_LOGOUT_URI"]})
        return redirect(f"{logout_url}?{q}")

    # ------------------------------------------------------------------ chamadas à API
    def gate(scope, path):
        """Exige login e, no modo secure, faz step-up se o token não tem o escopo."""
        d = data()
        if not d.get("access_token"):
            return redirect(url_for("login", next=path, scope=scope or ""))
        if scope and scope not in d.get("granted_scopes", []):
            if d.get("stepup_tried") == scope:       # já tentamos e o IdP não concedeu
                d.pop("stepup_tried", None)
                abort(403, f"O escopo '{scope}' não foi concedido")
            return redirect(url_for("login", next=path, scope=scope))
        d.pop("stepup_tried", None)
        return None

    def call_api(method, path, **kw):
        try:
            r = requests.request(method, f"{cfg['API_URL']}{path}", timeout=10,
                                 headers={"Authorization": f"Bearer {data().get('access_token')}"}, **kw)
            try:
                body = r.json()
            except ValueError:
                body = {"raw": r.text}
            return r.status_code, body
        except requests.RequestException:
            return 502, {"error": "API indisponível"}

    def expired(path):
        """401 da API: token expirou -> novo login (sem laço se acabou de logar)."""
        d = data()
        if d.pop("fresh", False):
            return None
        d.pop("access_token", None)
        return redirect(url_for("login", next=path))

    def api_view(title, path, scope):
        g = gate(scope, request.path)
        if g:
            return g
        status, body = call_api("GET", path)
        if status == 401:
            r = expired(request.path)
            if r:
                return r
        else:
            data().pop("fresh", None)
        return render_template("result.html", title=title, status=status,
                               body=json.dumps(body, indent=2, ensure_ascii=False))

    # ------------------------------------------------------------------ páginas
    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/profile")
    def profile():
        return api_view("GET /api/profile", "/api/profile", "api:read")

    @app.get("/admin")
    def admin():
        return api_view("GET /api/admin/users", "/api/admin/users", "api:admin")

    @app.route("/notes", methods=["GET", "POST"])
    def notes():
        g = gate("api:write" if request.method == "POST" else "api:read", "/notes")
        if g:
            return g
        message = None
        if request.method == "POST":
            check_csrf()
            status, body = call_api("POST", "/api/notes", json={"text": request.form.get("text", "")})
            message = "Nota criada." if status == 201 else f"Erro {status}: {body.get('error_description') or body.get('error')}"
        status, items = call_api("GET", "/api/notes")
        if status == 401:
            r = expired("/notes")
            if r:
                return r
        data().pop("fresh", None)
        return render_template("notes.html", notes=items if status == 200 else [], message=message)

    @app.get("/search")
    def search():
        q = request.args.get("q", "")
        if not secure_mode:
            q = Markup(q)   # [VULN] desliga o escape do Jinja -> XSS refletido
        return render_template("search.html", q=q)   # [SEC] autoescape + CSP

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": cfg["MODE"]}

    return app


app = create_app()