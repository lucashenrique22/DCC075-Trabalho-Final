# Realm `seminario` (Keycloak)

O realm é importado automaticamente na subida do container a partir de
`keycloak/seminario-realm.json` (`start-dev --import-realm`).
A importação só ocorre se o realm ainda não existir. Para reimportar do zero:

```bash
docker compose down -v && docker compose up -d
```

## Usuários (apenas laboratório)

| Usuário | Senha | Roles | Papel no cenário |
|---------|-------|-------|------------------|
| alice | alice123 | user | Vítima |
| bob | bob123 | user, admin | Administrador legítimo |
| mallory | mallory123 | user | Atacante |

## Clients

Os dois clients são **públicos** (sem client secret), de modo que o PKCE seja o controle
que protege o authorization code. A diferença entre eles é só a configuração.

| Configuração | `webapp-vulnerable` | `webapp-secure` |
|--------------|---------------------|-----------------|
| Redirect URI | `http://localhost:*` (wildcard) | `http://localhost:5000/callback` (exato) |
| PKCE | opcional | `S256` obrigatório |
| Web origins (CORS) | `*` | `http://localhost:5000` |
| Escopos padrão | `api:read`, `api:write`, `api:admin` | `api:read` |
| Escopos opcionais | nenhum | `api:write`, `api:admin` |
| Vida do access token | 24 h | 5 min |
| Implicit / password grant | desabilitados | desabilitados |

O client `cli-test` existe **só para testes automatizados** (`scripts/test_rbac.py`): habilita
password grant para obter tokens com escopos controlados. As aplicações do projeto usam
Authorization Code + PKCE e nunca o password grant.

O client `resource-api` (bearer-only) existe para ser a **audience** (`aud`) dos tokens.
A API deve rejeitar tokens cuja audience não seja ela.

## Escopos e claims

- `api:read`, `api:write`, `api:admin`: escopos customizados; cada um inclui `aud=resource-api`
- `roles`: coloca as realm roles em `realm_access.roles` no access token
- `fullScopeAllowed=false` nos clients: o token só carrega as roles explicitamente mapeadas ao client
  (`scopeMappings` do realm: `user` e `admin`). Quem decide quais roles aparecem é o usuário real;
  o mapeamento apenas libera que elas possam ser emitidas

## Verificação rápida

```bash
# Discovery document
curl -s http://localhost:8080/realms/seminario/.well-known/openid-configuration | python3 -m json.tool | head -20

# Os clients existem? (abra o console admin)
# http://localhost:8080/admin/master/console/#/seminario/clients
```

Teste manual de autorização (cole no navegador; deve abrir a tela de login):

```
http://localhost:8080/realms/seminario/protocol/openid-connect/auth?client_id=webapp-secure&response_type=code&scope=openid&redirect_uri=http://localhost:5000/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
```

Após o login o navegador tenta ir para `localhost:5000/callback` (ainda sem app, vai dar erro de
conexão, o que é esperado nesta etapa; o importante é a URL conter `?code=...`).
Repita sem `code_challenge` no `webapp-secure`: o Keycloak deve recusar (PKCE obrigatório).

## Alterar o realm

Edite `keycloak/seminario-realm.json` e reimporte do zero (o realm só é importado se ainda
não existir, e o banco do Keycloak fica no container):

```bash
docker compose down -v && docker compose up -d
```