"""Resource API protegida por OAuth2/OIDC (JWT emitido pelo Keycloak).

Controles aplicados em TODOS os endpoints protegidos:
  - assinatura verificada com a chave pública do Keycloak (JWKS)
  - algoritmo fixo RS256 (bloqueia alg=none e confusão RS256/HS256)
  - iss (emissor) e aud (esta API) validados; exp obrigatório
  - RBAC: roles (realm_access.roles) e escopos (claim "scope") checados por endpoint
"""
import os
from functools import wraps

import jwt
from flask import Flask, jsonify, request
from jwt import PyJWKClient

ISSUER = os.environ.get("OIDC_ISSUER", "http://localhost:8080/realms/seminario")
# O browser enxerga o Keycloak em localhost:8080 (e é isso que vai no "iss"), mas a API,
# dentro do Docker, busca as chaves pelo nome do serviço.
JWKS_URL = os.environ.get("OIDC_JWKS_URL", f"{ISSUER}/protocol/openid-connect/certs")
AUDIENCE = os.environ.get("API_AUDIENCE", "resource-api")

app = Flask(__name__)
_jwks = PyJWKClient(JWKS_URL, cache_keys=True, lifespan=300)

NOTES = {}      # sub -> lista de notas (em memória)
_next_id = 1


def get_signing_key(token):
    return _jwks.get_signing_key_from_jwt(token).key


def _error(status, error, description, scope=None):
    resp = jsonify(error=error, error_description=description)
    resp.status_code = status
    challenge = f'Bearer realm="{AUDIENCE}", error="{error}"'
    if scope:
        challenge += f', scope="{scope}"'
    resp.headers["WWW-Authenticate"] = challenge
    return resp


def authenticate():
    """Retorna (claims, None) se o token é válido, ou (None, resposta_de_erro)."""
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        resp = jsonify(error="unauthorized", error_description="Bearer token ausente")
        resp.status_code = 401
        resp.headers["WWW-Authenticate"] = f'Bearer realm="{AUDIENCE}"'
        return None, resp
    token = token.strip()
    try:
        key = get_signing_key(token)
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except jwt.PyJWKClientConnectionError:
        return None, _error(503, "temporarily_unavailable", "Falha ao obter chaves do IdP")
    except jwt.PyJWTError as exc:
        app.logger.warning("token rejeitado: %s", exc)   # detalhe só no log
        return None, _error(401, "invalid_token", "Token inválido ou expirado")
    return claims, None


def require(scopes=(), roles=()):
    """scopes: todos obrigatórios. roles: basta uma delas."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            claims, err = authenticate()
            if err:
                return err
            token_scopes = set(claims.get("scope", "").split())
            token_roles = set(claims.get("realm_access", {}).get("roles", []))
            missing = [s for s in scopes if s not in token_scopes]
            if missing:
                return _error(403, "insufficient_scope",
                              "Escopo insuficiente", scope=" ".join(missing))
            if roles and not token_roles.intersection(roles):
                return _error(403, "forbidden", "Role insuficiente")
            request.claims = claims
            return fn(*args, **kwargs)
        return wrapper
    return decorator


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/api/public")
def public():
    return jsonify(message="Endpoint público, não exige token")


@app.get("/api/profile")
@require(scopes=["api:read"])
def profile():
    c = request.claims
    return jsonify(
        sub=c["sub"],
        username=c.get("preferred_username"),
        email=c.get("email"),
        roles=c.get("realm_access", {}).get("roles", []),
        scopes=c.get("scope", "").split(),
        exp=c["exp"],
    )


@app.get("/api/notes")
@require(scopes=["api:read"])
def list_notes():
    return jsonify(NOTES.get(request.claims["sub"], []))


@app.post("/api/notes")
@require(scopes=["api:write"])
def create_note():
    global _next_id
    body = request.get_json(silent=True) or {}
    text = body.get("text")
    if not isinstance(text, str) or not text.strip() or len(text) > 500:
        return jsonify(error="invalid_request", error_description="'text' deve ter 1-500 caracteres"), 400
    note = {"id": _next_id, "text": text.strip()}
    _next_id += 1
    NOTES.setdefault(request.claims["sub"], []).append(note)
    return jsonify(note), 201


@app.get("/api/admin/users")
@require(scopes=["api:admin"], roles=["admin"])
def admin_users():
    # Dados fictícios; o ponto é demonstrar RBAC (role) + escopo no mesmo endpoint.
    return jsonify([
        {"username": "alice", "roles": ["user"]},
        {"username": "bob", "roles": ["user", "admin"]},
        {"username": "mallory", "roles": ["user"]},
    ])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)