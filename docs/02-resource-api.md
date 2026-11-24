# Resource API (Flask) com RBAC

Código em `resource-api/app.py`. Valida o JWT emitido pelo Keycloak e aplica autorização
por **escopo** e por **role** em cada endpoint.

## Endpoints

| Endpoint | Requisito | Respostas |
|----------|-----------|-----------|
| `GET /health` | nenhum | 200 |
| `GET /api/public` | nenhum | 200 |
| `GET /api/profile` | escopo `api:read` | 200 / 401 / 403 |
| `GET /api/notes` | escopo `api:read` (só notas do próprio `sub`) | 200 / 401 / 403 |
| `POST /api/notes` | escopo `api:write` | 201 / 400 / 401 / 403 |
| `GET /api/admin/users` | escopo `api:admin` **e** role `admin` | 200 / 401 / 403 |

- **401** = token ausente, inválido, expirado, assinatura/iss/aud incorretos (`WWW-Authenticate: Bearer ... error="invalid_token"`)
- **403** = token válido, mas sem o escopo (`insufficient_scope`) ou sem a role (`forbidden`)

## Validações aplicadas ao token

| Verificação | Por quê |
|-------------|---------|
| Assinatura via JWKS do Keycloak | Impede tokens forjados |
| `algorithms=["RS256"]` fixo | Bloqueia `alg: none` e confusão RS256/HS256 |
| `iss` = `http://localhost:8080/realms/seminario` | Aceita só tokens do nosso IdP |
| `aud` = `resource-api` | Um token emitido para outra aplicação (ou um ID token) não serve nesta API |
| `exp` obrigatório | Tokens sem validade são recusados |
| Escopo **e** role no endpoint admin | Ter só um dos dois não basta (defesa em profundidade) |

Detalhes do motivo da rejeição vão apenas para o log do servidor, nunca para o cliente.

## Configuração (variáveis de ambiente)

| Variável | Padrão | Observação |
|----------|--------|------------|
| `OIDC_ISSUER` | `http://localhost:8080/realms/seminario` | Valor exato do claim `iss` |
| `OIDC_JWKS_URL` | `<issuer>/protocol/openid-connect/certs` | No Docker: `http://keycloak:8080/realms/seminario/protocol/openid-connect/certs` |
| `API_AUDIENCE` | `resource-api` | |

O `iss` usa `localhost:8080` (o que o navegador enxerga), mas dentro do Docker a API busca as
chaves em `keycloak:8080`. Por isso as duas variáveis são separadas.

## Como executar e testar

Testes unitários offline (tokens assinados com chave RSA local, sem Keycloak):

```bash
cd resource-api
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v          # 17 testes
```

Teste de integração (Keycloak + API no ar, tokens reais):

```bash
docker compose down -v && docker compose up -d --build
python3 scripts/test_rbac.py
```

Saída esperada: `10/10 casos conforme o esperado`.

Para inspecionar um token manualmente, cole o `access_token` em https://jwt.io ou decodifique:

```bash
echo "<token>" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```