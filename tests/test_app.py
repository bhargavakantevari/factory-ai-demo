import os
import tempfile
import unittest


class AppSmokeTest(unittest.TestCase):
    """Checks that the app runs on the pinned dependency versions."""

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        # create_app() recreates database.db in the working directory.
        os.chdir(self._tmp.name)
        from flask_webgoat import create_app

        self.client = create_app().test_client()

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def test_status(self):
        resp = self.client.get("/status")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"success": True})

    def test_login_sets_session_and_admin_can_create_user(self):
        resp = self.client.post(
            "/login", data={"username": "admin", "password": "maximumentropy"}
        )
        self.assertEqual(resp.get_json(), {"success": True})
        resp = self.client.post(
            "/create_user",
            data={"username": "bob", "password": "secret", "access_level": "2"},
        )
        self.assertEqual(resp.get_json(), {"success": True})

    def test_bad_login_rejected(self):
        resp = self.client.post("/login", data={"username": "admin", "password": "x"})
        self.assertEqual(resp.status_code, 400)

    def test_search_template_autoescapes(self):
        resp = self.client.get("/search", query_string={"query": "<script>x</script>"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"&lt;script&gt;", resp.data)
        self.assertNotIn(b"<script>x</script>", resp.data)


if __name__ == "__main__":
    unittest.main()
