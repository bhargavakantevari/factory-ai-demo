import os
import secrets
import sqlite3
from pathlib import Path

from flask import Flask
from werkzeug.security import generate_password_hash

DB_FILENAME = "database.db"


def query_db(query, args=(), one=False, commit=False):
    with sqlite3.connect(DB_FILENAME) as conn:
        cur = conn.cursor().execute(query, args)
        if commit:
            conn.commit()
        return cur.fetchone() if one else cur.fetchall()


def create_app():
    app = Flask(__name__)
    # Falling back to a random key keeps the app runnable in development; sessions
    # then do not survive a restart, so production must set FLASK_SECRET_KEY.
    app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "1") == "1",
        MAX_CONTENT_LENGTH=1024 * 1024,
    )

    db_path = Path(DB_FILENAME)
    if db_path.exists():
        db_path.unlink()

    # Without ADMIN_PASSWORD the admin account gets an unknown random password,
    # so no default credential ever exists.
    admin_password = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(32)

    conn = sqlite3.connect(DB_FILENAME)
    create_table_query = """CREATE TABLE IF NOT EXISTS user
    (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
    access_level INTEGER NOT NULL)"""
    conn.execute(create_table_query)

    insert_admin_query = """INSERT INTO user (id, username, password, access_level)
    VALUES (1, 'admin', ?, 0)"""
    conn.execute(insert_admin_query, (generate_password_hash(admin_password),))
    conn.commit()
    conn.close()

    with app.app_context():
        from . import actions
        from . import auth
        from . import status
        from . import ui
        from . import users

        app.register_blueprint(actions.bp)
        app.register_blueprint(auth.bp)
        app.register_blueprint(status.bp)
        app.register_blueprint(ui.bp)
        app.register_blueprint(users.bp)
        return app
