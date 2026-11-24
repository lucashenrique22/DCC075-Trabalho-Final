"""Testes offline da Resource API: gera um par RSA local e assina tokens de teste.
Execução (dentro de resource-api/):  python -m unittest discover -s tests -v
"""
import os
import sys
import time
import unittest

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import app as api  # noqa: E402

PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
api.get_signing_key = lambda token: PRIVATE.public_key()


def make_token(sub="u1", scope="api:read", roles=("user",), aud=None, iss=None,
               exp_delta=300, key=PRIVATE):
    now = int(time.time())
    claims = {
        "sub": sub, "iss": iss or api.ISSUER, "aud": aud or api.AUDIENCE,
        "iat": now, "exp": now + exp_delta, "scope": scope,
        "realm_access": {"roles": list(roles)}, "preferred_username": sub,
    }
    return jwt.encode(claims, key, algorithm="RS256")


class RbacTests(unittest.TestCase):
    def setUp(self):
        api.NOTES.clear()
        self.c = api.app.test_client()

    def get(self, path, token=None):
        h = {"Authorization": f"Bearer {token}"} if token else {}
        return self.c.get(path, headers=h)

    def post_note(self, token, text="oi"):
        return self.c.post("/api/notes", json={"text": text},
                           headers={"Authorization": f"Bearer {token}"})

    # ---- autenticação / validação do JWT
    def test_public_sem_token(self):
        self.assertEqual(self.get("/api/public").status_code, 200)

    def test_sem_token(self):
        r = self.get("/api/profile")
        self.assertEqual(r.status_code, 401)
        self.assertIn("Bearer", r.headers["WWW-Authenticate"])

    def test_token_lixo(self):
        self.assertEqual(self.get("/api/profile", "abc.def.ghi").status_code, 401)

    def test_expirado(self):
        self.assertEqual(self.get("/api/profile", make_token(exp_delta=-10)).status_code, 401)

    def test_audience_errada(self):
        self.assertEqual(self.get("/api/profile", make_token(aud="webapp-secure")).status_code, 401)

    def test_issuer_errado(self):
        self.assertEqual(self.get("/api/profile", make_token(iss="http://evil/realms/x")).status_code, 401)

    def test_assinatura_de_outra_chave(self):
        self.assertEqual(self.get("/api/profile", make_token(key=OTHER)).status_code, 401)

    def test_alg_none(self):
        now = int(time.time())
        t = jwt.encode({"sub": "x", "iss": api.ISSUER, "aud": api.AUDIENCE, "exp": now + 99,
                        "scope": "api:read"}, key=None, algorithm="none")
        self.assertEqual(self.get("/api/profile", t).status_code, 401)

    def test_hs256(self):
        now = int(time.time())
        t = jwt.encode({"sub": "x", "iss": api.ISSUER, "aud": api.AUDIENCE, "exp": now + 99,
                        "scope": "api:read"}, "segredo-qualquer-0123456789abcdef", algorithm="HS256")
        self.assertEqual(self.get("/api/profile", t).status_code, 401)

    # ---- escopos
    def test_profile_com_api_read(self):
        r = self.get("/api/profile", make_token())
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["username"], "u1")

    def test_escrita_sem_api_write(self):
        r = self.post_note(make_token(scope="api:read"))
        self.assertEqual(r.status_code, 403)
        self.assertIn("insufficient_scope", r.headers["WWW-Authenticate"])

    def test_escrita_com_api_write(self):
        self.assertEqual(self.post_note(make_token(scope="api:read api:write")).status_code, 201)

    def test_nota_invalida(self):
        self.assertEqual(self.post_note(make_token(scope="api:write"), text="").status_code, 400)

    def test_notas_isoladas_por_usuario(self):
        self.post_note(make_token(sub="alice", scope="api:write"), "segredo da alice")
        r = self.get("/api/notes", make_token(sub="bob", scope="api:read"))
        self.assertEqual(r.get_json(), [])

    # ---- RBAC (role + escopo)
    def test_admin_role_user_com_escopo_admin(self):
        t = make_token(scope="api:admin", roles=("user",))
        self.assertEqual(self.get("/api/admin/users", t).status_code, 403)

    def test_admin_role_admin_sem_escopo(self):
        t = make_token(scope="api:read", roles=("user", "admin"))
        self.assertEqual(self.get("/api/admin/users", t).status_code, 403)

    def test_admin_role_e_escopo(self):
        t = make_token(scope="api:admin", roles=("user", "admin"))
        self.assertEqual(self.get("/api/admin/users", t).status_code, 200)


if __name__ == "__main__":
    unittest.main()