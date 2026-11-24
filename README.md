# Segurança em fluxos OAuth2 / OpenID Connect

Trabalho da disciplina de **Segurança em Sistemas de Computação**.

Laboratório que implementa **Authorization Code Flow + PKCE** com **RBAC** nos endpoints,
explora falhas comuns de configuração e demonstra as correções. Inclui também a análise de
um ambiente real, com escopo e autorização documentados.

> ⚠️ **Aviso:** todo o código vulnerável deste repositório é didático e deve ser executado
> apenas localmente. Os testes em ambiente real seguem estritamente o escopo descrito em
> [`docs/ambiente-real.md`](docs/ambiente-real.md).

## Integrantes

| Nome | Responsabilidade |
|------|------------------|
| Lucas Henrique de Arruda Ferreira | Código e documentação |
| Gustavo Ribeiro Martins | Slides |
| Lucas Gonçalves Rocha | Relatório |

## Status do projeto

- [x] Estrutura do repositório e Docker Compose com Keycloak
- [ ] Realm do Keycloak (clients, roles, usuários)
- [ ] Resource API com RBAC
- [ ] Client app (Authorization Code + PKCE)
- [ ] Ataque 1: ausência de `state` (CSRF no login)
- [ ] Ataque 2: `redirect_uri` permissivo (roubo de authorization code)
- [ ] Ataque 3: vazamento de token
- [ ] Ataque 4: escopos excessivos
- [ ] Correções de cada ataque (modo `secure`)
- [ ] Teste em ambiente real
- [ ] Capturas Burp Suite / Wireshark

## Arquitetura

```
 Navegador ──► client-app (Flask :5000) ──► Keycloak (:8080)
                    │                            ▲
                    └──► resource-api (Flask :5001, valida JWT + RBAC)
 attacker (Flask :6666) ── servidor controlado pelo atacante (demonstrações)
```

| Componente | Porta | Função |
|------------|-------|--------|
| Keycloak | 8080 | Identity Provider (realm `seminario`) |
| client-app | 5000 | Aplicação web, Authorization Code + PKCE |
| resource-api | 5001 | API protegida, autorização por role/escopo |
| attacker | 6666 | Simula o servidor malicioso |

Detalhes do realm (usuários, clients, escopos): [`docs/01-keycloak-realm.md`](docs/01-keycloak-realm.md)

## Pré-requisitos

- Docker e Docker Compose v2
- Python 3.11+ (apenas se for rodar fora do Docker)
- Burp Suite Community e Wireshark (para reproduzir as capturas)

## Como executar

```bash
git clone <URL-DO-REPOSITORIO>
cd oauth2-security-lab
cp .env.example .env
docker compose up -d
```

Console de administração do Keycloak: http://localhost:8080 (`admin` / `admin`).

_As seções abaixo serão preenchidas conforme o projeto evolui._

## Reprodução dos ataques

_(em construção)_

## Correções aplicadas

_(em construção)_

## Teste em ambiente real

_(em construção, ver `docs/ambiente-real.md`)_

## Referências

- RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), RFC 9700 (OAuth 2.0 Security Best Current Practice)
- OpenID Connect Core 1.0
- Documentação do Keycloak