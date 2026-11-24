#!/usr/bin/env python3
"""Teste de integração do RBAC: obtém tokens reais no Keycloak e consulta a Resource API.

Usa o client `cli-test` (password grant, só para laboratório) para pedir tokens com
combinações controladas de usuário e escopo. Somente biblioteca padrão.

Uso:  python3 scripts/test_rbac.py
Env:  KEYCLOAK_URL (padrão http://localhost:8080)  API_URL (padrão http://localhost:5001)
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KC = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
API = os.environ.get("API_URL", "http://localhost:5001")
TOKEN_URL = f"{KC}/realms/seminario/protocol/openid-connect/token"
PASSWORDS = {"alice": "alice123", "bob": "bob123"}


def wait_for_keycloak(timeout=120):
    """Espera o realm responder (o Keycloak leva ~30-60s para subir com --import-realm)."""
    url = f"{KC}/realms/seminario/.well-known/openid-configuration"
    deadline, last = time.time() + timeout, "sem resposta"
    print(f"Aguardando o Keycloak em {KC} ...", end="", flush=True)
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5):
                print(" pronto.\n")
                return
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
        except (urllib.error.URLError, OSError) as e:
            last = str(getattr(e, "reason", e))
        except Exception as e:  # ex.: RemoteDisconnected enquanto o Keycloak ainda sobe
            last = type(e).__name__
        print(".", end="", flush=True)
        time.sleep(3)
    sys.exit(f"\nKeycloak/realm 'seminario' indisponível após {timeout}s (último erro: {last}).\n"
             "Verifique: docker compose ps  e  docker compose logs keycloak")


def get_token(user, scope):
    data = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "cli-test",
        "username": user, "password": PASSWORDS[user], "scope": f"openid {scope}",
    }).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(TOKEN_URL, data=data)) as r:
            return json.load(r)["access_token"]
    except urllib.error.HTTPError as e:
        sys.exit(f"Keycloak recusou o token de {user} (HTTP {e.code}): {e.read().decode()[:300]}")


def call(method, path, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{API}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


# (usuário, escopos pedidos, método, caminho, corpo, status esperado, comentário)
CASES = [
    (None,    None,                "GET",  "/api/public",      None,           200, "público"),
    (None,    None,                "GET",  "/api/profile",     None,           401, "sem token"),
    ("alice", "api:read",          "GET",  "/api/profile",     None,           200, "escopo read"),
    ("alice", "api:read",          "GET",  "/api/notes",       None,           200, "escopo read"),
    ("alice", "api:read",          "POST", "/api/notes",       {"text": "x"},  403, "falta api:write"),
    ("alice", "api:read api:write","POST", "/api/notes",       {"text": "x"},  201, "escopo write"),
    ("alice", "api:read api:admin","GET",  "/api/admin/users", None,           403, "escopo ok, role user"),
    ("bob",   "api:read",          "GET",  "/api/admin/users", None,           403, "role ok, falta api:admin"),
    ("bob",   "api:read api:admin","GET",  "/api/admin/users", None,           200, "role admin + api:admin"),
    ("bob",   "api:read api:admin","POST", "/api/notes",       {"text": "x"},  403, "api:admin não implica write"),
]


def main():
    wait_for_keycloak()
    cache, failures = {}, 0
    print(f"{'usuário':8} {'escopos':20} {'requisição':26} {'esperado':>8} {'obtido':>7}  resultado")
    for user, scope, method, path, body, expected, note in CASES:
        token = None
        if user:
            key = (user, scope)
            if key not in cache:
                cache[key] = get_token(user, scope)
            token = cache[key]
        got = call(method, path, token, body)
        ok = got == expected
        failures += not ok
        print(f"{user or '-':8} {scope or '-':20} {method + ' ' + path:26} {expected:>8} {got:>7}  "
              f"{'OK ' if ok else 'FALHOU'} ({note})")
    print(f"\n{len(CASES) - failures}/{len(CASES)} casos conforme o esperado")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()