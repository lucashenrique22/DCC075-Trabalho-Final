# Client app (Flask): Authorization Code Flow + PKCE

Código em `client-app/app.py`. A mesma base de código roda em dois modos, escolhidos por
`APP_MODE` no `.env`:

| `APP_MODE` | client no Keycloak | Objetivo |
|------------|--------------------|----------|
| `vulnerable` | `webapp-vulnerable` | Falhas plantadas, usadas nas demonstrações de ataque |
| `secure` | `webapp-secure` | Mesmas funcionalidades, com as correções |

Para trocar de modo: altere `APP_MODE` no `.env` e rode `docker compose up -d --build client-app`.
A página mostra uma faixa vermelha (vulnerable) ou verde (secure) com o `client_id` em uso.

## Fluxo implementado

```
Navegador          client-app (:5000)            Keycloak (:8080)         resource-api (:5001)
   │  GET /login        │                              │                         │
   │ ◄── 302 ───────────┤ (state, nonce, PKCE*)        │                         │
   │ ──────────── GET /auth?... ─────────────────────► │  login do usuário       │
   │ ◄──────────── 302 /callback?code=...&state=... ── │                         │
   │ GET /callback ───► │ POST /token (code, verifier*)► │                       │
   │                    │ ◄── access_token, id_token ──┤                         │
   │                    │ valida ID token*             │                         │
   │ GET /profile ────► │ GET /api/profile (Bearer) ─────────────────────────► │
   │ ◄── página ────────┤ ◄──────────────── JSON ─────────────────────────────── │
```
`*` apenas no modo `secure`.

O navegador fala com o Keycloak em `localhost:8080`; o servidor da aplicação, dentro do Docker,
fala em `keycloak:8080` (token e JWKS). Por isso há duas variáveis de URL.

## Diferenças entre os modos

| Aspecto | `vulnerable` | `secure` |
|---------|--------------|----------|
| `state` | não envia, não valida | aleatório (32 bytes), validado em tempo constante, uso único |
| PKCE | não usa | `S256`, verifier guardado só no servidor |
| `nonce` / ID token | não valida (lê sem verificar assinatura) | valida assinatura, `iss`, `aud`, `exp` e `nonce` |
| `redirect_uri` no IdP | wildcard `http://localhost:*` | exato: `http://localhost:5000/callback` |
| Escopos pedidos | todos, sempre (`api:read api:write api:admin`) | mínimo (`api:read`); `api:write`/`api:admin` só sob demanda (step-up) |
| Escopos extras em `/login?scope=` | aceita qualquer coisa (o app ignora) | só uma lista permitida |
| Onde ficam os tokens | no cookie de sessão (assinado, **legível**), sem `HttpOnly` | na memória do servidor; cookie só com id opaco, `HttpOnly`, `SameSite=Lax` |
| Log da aplicação | imprime a resposta do endpoint de token | nunca registra tokens |
| `/search?q=` | XSS refletido (escape desligado) | escape + `Content-Security-Policy` |
| Sessão após login | mantida | renovada (evita session fixation) |
| Cabeçalhos | nenhum | CSP, `nosniff`, `Referrer-Policy: no-referrer`, `no-store`, anti-framing |
| Tempo de vida do access token | 24 h | 5 min |

Controles que existem **nos dois** modos, para que as diferenças acima sejam as únicas falhas
em jogo: token CSRF nos formulários (`/notes`, `/logout`), lista de destinos permitidos para
`?next=` (sem open redirect) e Jinja com autoescape (exceto o ponto marcado em `/search`).

## Páginas

| Rota | Escopo exigido | Descrição |
|------|----------------|-----------|
| `/` | — | Estado da sessão e escopos concedidos |
| `/profile` | `api:read` | Chama `GET /api/profile` |
| `/notes` | `api:read` (listar), `api:write` (criar) | Chama a API de notas |
| `/admin` | `api:admin` + role `admin` | Chama `GET /api/admin/users` |
| `/search?q=` | — | Página de busca (ponto de XSS no modo vulnerable) |

**Step-up (modo secure):** ao abrir `/admin` com um token sem `api:admin`, a aplicação
redireciona para `/login?scope=api:admin`; o Keycloak emite um novo token com o escopo extra
e o usuário volta para a página original. Se o IdP não conceder o escopo, a aplicação mostra
403 em vez de entrar em laço de redirecionamentos.

## Como executar

```bash
cp .env.example .env              # APP_MODE=vulnerable (padrão) ou secure
docker compose down -v && docker compose up -d --build
```

Abra http://localhost:5000 e entre com `alice` / `alice123` (ou `bob` / `bob123` para testar `/admin`).

## Testes

Unitários offline (Keycloak e API simulados, 23 testes):

```bash
cd client-app
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Cobrem: vetor de teste da RFC 7636, URL de autorização de cada modo, rejeição de `state`
ausente/errado/reutilizado, verifier enviado na troca do code, ID token com `nonce` ou
`aud` incorretos, flags do cookie, ausência do token no cookie (secure) e presença (vulnerable),
step-up de escopo, ausência de laço de redirect, `?next=` externo, XSS refletido vs. escapado,
CSRF no logout.

## Limitações assumidas

- Tudo roda em HTTP (laboratório local). Em produção seria obrigatório HTTPS, cookie `Secure`
  e HSTS. O tráfego em texto claro é, aliás, o que torna as capturas no Wireshark possíveis.
- Não há refresh token nem renovação silenciosa: com o access token expirado, o usuário
  refaz o login (rápido, pois o SSO do Keycloak continua ativo).
- Sessões do modo secure ficam em memória (perdem-se ao reiniciar o container).