import base64
import importlib
import json
import pickle
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from flask_webgoat import create_app  # noqa: E402

ADMIN_PASSWORD = "correct horse battery staple"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("WEBGOAT_ADMIN_PASSWORD", ADMIN_PASSWORD)
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def login(client, username="admin", password=ADMIN_PASSWORD):
    return client.post("/login", data={"username": username, "password": password})


def test_admin_login_works_and_password_is_hashed(client, tmp_path):
    assert login(client).status_code == 200
    import sqlite3

    stored = sqlite3.connect(tmp_path / "database.db").execute(
        "SELECT password FROM user WHERE id = 1"
    ).fetchone()[0]
    assert ADMIN_PASSWORD not in stored


def test_old_default_admin_password_rejected(client):
    assert login(client, password="maximumentropy").status_code == 400


def test_random_secret_key_and_admin_password_without_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)
    monkeypatch.delenv("WEBGOAT_ADMIN_PASSWORD", raising=False)
    a, b = create_app(), create_app()
    assert a.secret_key and a.secret_key != b.secret_key
    assert login(b.test_client(), password="maximumentropy").status_code == 400


@pytest.mark.parametrize("password", ["' OR '1'='1", "x' OR 1=1 --"])
def test_login_sql_injection_blocked(client, password):
    assert login(client, username="admin' --", password=password).status_code == 400
    assert login(client, password=password).status_code == 400


def test_create_user_sql_injection_stored_literally(client):
    login(client)
    evil = "eve', 'pw', 0); --"
    res = client.post(
        "/create_user", data={"username": evil, "password": "secret", "access_level": "2"}
    )
    assert res.get_json() == {"success": True}
    assert login(client, username=evil, password="secret").status_code == 200


def test_create_user_bad_access_level(client):
    login(client)
    res = client.post(
        "/create_user", data={"username": "bob", "password": "secret", "access_level": "x"}
    )
    assert res.status_code == 400


def test_message_path_traversal_rejected(client, tmp_path):
    login(client)
    for name in ["../../evil", "/tmp/evil", "a/b", "..", ""]:
        res = client.post("/message", data={"filename": name, "text": "pwned"})
        assert res.status_code == 400, name
    assert not (tmp_path / "evil.txt").exists()


def test_message_valid_write(client, tmp_path):
    login(client)
    res = client.post("/message", data={"filename": "note_1", "text": "hello"})
    assert res.get_json() == {"success": True}
    assert (tmp_path / "data" / "1" / "note_1.txt").read_text() == "hello"


def test_grep_processes_requires_login(client):
    assert client.get("/grep_processes?name=python").status_code == 401


def test_grep_processes_no_command_injection(client, tmp_path):
    login(client)
    marker = tmp_path / "pwned"
    res = client.get("/grep_processes", query_string={"name": f"x; touch {marker}"})
    assert res.status_code == 200
    assert not marker.exists()


def test_deserialization_rejects_pickle(client, tmp_path):
    class Exploit:
        def __reduce__(self):
            import os

            return (os.system, (f"touch {tmp_path / 'rce'}",))

    payload = base64.urlsafe_b64encode(pickle.dumps(Exploit())).decode()
    res = client.post("/deserialized_descr", data={"pickled": payload})
    assert res.status_code == 400
    assert not (tmp_path / "rce").exists()


def test_deserialization_accepts_json(client):
    payload = base64.urlsafe_b64encode(json.dumps({"a": 1}).encode()).decode()
    res = client.post("/deserialized_descr", data={"pickled": payload})
    assert res.get_json() == {"success": True, "description": "{'a': 1}"}


@pytest.mark.parametrize(
    "url", ["https://evil.example", "//evil.example", "/\\evil.example", "javascript:alert(1)"]
)
def test_open_redirect_blocked(client, url):
    res = client.get(
        "/login_and_redirect", query_string={"username": "x", "password": "y", "url": url}
    )
    assert res.status_code == 302
    assert res.headers["Location"] == "/"


def test_relative_redirect_allowed(client):
    res = client.get(
        "/login_and_redirect",
        query_string={"username": "x", "password": "y", "url": "/search?query=a"},
    )
    assert res.headers["Location"] == "/search?query=a"


def test_search_escapes_html(client):
    res = client.get("/search", query_string={"query": "<script>alert(1)</script>"})
    assert b"<script>alert(1)</script>" not in res.data
    assert b"&lt;script&gt;" in res.data


def test_session_cookie_flags(client):
    res = login(client)
    cookie = res.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_run_headers(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sys.modules.pop("run", None)
    run = importlib.import_module("run")
    res = run.app.test_client().get("/status")
    assert "Access-Control-Allow-Origin" not in res.headers
    assert "unsafe-inline" not in res.headers["Content-Security-Policy"]
