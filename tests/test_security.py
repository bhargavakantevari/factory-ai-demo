import base64
import os
import pickle
import tempfile
import unittest
from pathlib import Path

from werkzeug.security import check_password_hash

ADMIN_PASSWORD = "correct-horse-battery"


class SecurityTestCase(unittest.TestCase):
    def setUp(self):
        self._old_cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)
        os.environ["ADMIN_PASSWORD"] = ADMIN_PASSWORD
        os.environ["SECRET_KEY"] = "test-secret"
        import run  # noqa: F401  (registers the security headers)
        from flask_webgoat import create_app

        self.app = create_app()
        self.app.after_request(run.add_security_headers)
        self.client = self.app.test_client()

    def tearDown(self):
        os.chdir(self._old_cwd)
        self._tmp.cleanup()

    def login(self, username="admin", password=ADMIN_PASSWORD):
        return self.client.post(
            "/login", data={"username": username, "password": password}
        )

    def test_login_with_valid_credentials(self):
        self.assertEqual(self.login().status_code, 200)

    def test_login_sql_injection_rejected(self):
        for payload in ["admin' --", "' OR '1'='1' --", "' OR 1=1 --"]:
            res = self.login(username=payload, password="x")
            self.assertEqual(res.status_code, 400, payload)
        res = self.login(password="' OR '1'='1")
        self.assertEqual(res.status_code, 400)

    def test_old_hardcoded_admin_password_rejected(self):
        self.assertEqual(self.login(password="maximumentropy").status_code, 400)

    def test_passwords_are_hashed(self):
        from flask_webgoat import query_db

        stored = query_db("SELECT password FROM user WHERE id = 1", one=True)[0]
        self.assertNotEqual(stored, ADMIN_PASSWORD)
        self.assertTrue(check_password_hash(stored, ADMIN_PASSWORD))

    def test_create_user_sql_injection_is_stored_literally(self):
        self.login()
        evil = "x', 'pw', 0); DROP TABLE user; --"
        res = self.client.post(
            "/create_user",
            data={"username": evil, "password": "longenough", "access_level": "3"},
        )
        self.assertEqual(res.get_json(), {"success": True})
        from flask_webgoat import query_db

        row = query_db(
            "SELECT username, access_level FROM user WHERE username = ?", (evil,), True
        )
        self.assertEqual(row, (evil, 3))
        self.assertEqual(self.login(username=evil, password="longenough").status_code, 200)

    def test_create_user_requires_admin(self):
        res = self.client.post(
            "/create_user",
            data={"username": "u", "password": "longenough", "access_level": "0"},
        )
        self.assertEqual(res.status_code, 401)

    def test_create_user_rejects_bad_input(self):
        self.login()
        res = self.client.post(
            "/create_user", data={"username": "u", "password": "short", "access_level": "1"}
        )
        self.assertEqual(res.status_code, 400)
        res = self.client.post(
            "/create_user",
            data={"username": "u", "password": "longenough", "access_level": "abc"},
        )
        self.assertEqual(res.status_code, 400)

    def test_open_redirect_blocked(self):
        for url in [
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "javascript:alert(1)",
        ]:
            res = self.client.get(
                "/login_and_redirect",
                query_string={"username": "a", "password": "b", "url": url},
            )
            self.assertEqual(res.status_code, 400, url)
        res = self.client.get(
            "/login_and_redirect",
            query_string={"username": "a", "password": "b", "url": "/search?query=a"},
        )
        self.assertEqual(res.status_code, 302)
        self.assertEqual(res.headers["Location"], "/search?query=a")

    def test_directory_traversal_blocked(self):
        self.login()
        for name in ["../../escaped", "../1/x", "/tmp/abs", "a/b"]:
            res = self.client.post("/message", data={"filename": name, "text": "hi"})
            self.assertEqual(res.status_code, 400, name)
        self.assertFalse(Path("escaped.txt").exists())
        res = self.client.post("/message", data={"filename": "note_1", "text": "hi"})
        self.assertEqual(res.get_json(), {"success": True})
        self.assertEqual(Path("data/1/note_1.txt").read_text(encoding="utf-8"), "hi")

    def test_grep_processes_no_command_injection(self):
        marker = Path("pwned")
        res = self.client.get("/grep_processes", query_string={"name": "x; touch pwned"})
        self.assertEqual(res.status_code, 200)
        self.assertFalse(marker.exists())
        res = self.client.get("/grep_processes", query_string={"name": "ps aux"})
        self.assertTrue(res.get_json()["success"])
        self.assertIn("ps", res.get_json()["names"])

    def test_pickle_payload_not_executed(self):
        class Exploit:
            def __reduce__(self):
                return (open, ("pwned", "w"))

        payload = base64.urlsafe_b64encode(pickle.dumps(Exploit())).decode()
        res = self.client.post("/deserialized_descr", data={"pickled": payload})
        self.assertEqual(res.status_code, 400)
        self.assertFalse(Path("pwned").exists())
        payload = base64.urlsafe_b64encode(b'{"a": 1}').decode()
        res = self.client.post("/deserialized_descr", data={"pickled": payload})
        self.assertEqual(res.get_json()["description"], "{'a': 1}")

    def test_search_output_is_escaped(self):
        res = self.client.get("/search", query_string={"query": "<script>alert(1)</script>"})
        self.assertNotIn(b"<script>alert(1)</script>", res.data)
        self.assertIn(b"&lt;script&gt;", res.data)

    def test_security_headers(self):
        res = self.client.get("/status")
        self.assertNotIn("Access-Control-Allow-Origin", res.headers)
        self.assertNotIn("unsafe-inline", res.headers["Content-Security-Policy"])
        self.assertEqual(res.headers["X-Content-Type-Options"], "nosniff")

    def test_session_cookie_flags(self):
        res = self.login()
        cookie = res.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)


if __name__ == "__main__":
    unittest.main()
