from urllib.parse import urlsplit

from flask import Blueprint, request, jsonify, session, redirect
from werkzeug.security import check_password_hash

from . import query_db

bp = Blueprint("auth", __name__)


def authenticate(username, password):
    query = "SELECT id, username, access_level, password FROM user WHERE username = ?"
    row = query_db(query, (username,), True)
    if row is None or not check_password_hash(row[3], password):
        return None
    return row[0], row[1], row[2]


def start_session(user_info):
    # Clearing first drops any attacker-planted session values (session fixation).
    session.clear()
    session["user_info"] = user_info


def safe_redirect_target(url):
    """Allow only same-site relative paths such as "/search"."""
    url = url.replace("\\", "/")
    parts = urlsplit(url)
    if parts.scheme or parts.netloc or not url.startswith("/") or url.startswith("//"):
        return "/"
    return url


@bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return (
            jsonify({"error": "username and password parameter have to be provided"}),
            400,
        )

    user_info = authenticate(username, password)
    if user_info is None:
        return jsonify({"bad_login": True}), 400
    start_session(user_info)
    return jsonify({"success": True})


@bp.route("/login_and_redirect")
def login_and_redirect():
    username = request.args.get("username")
    password = request.args.get("password")
    url = request.args.get("url")
    if username is None or password is None or url is None:
        return (
            jsonify(
                {"error": "username, password, and url parameters have to be provided"}
            ),
            400,
        )

    user_info = authenticate(username, password)
    if user_info is None:
        return redirect(safe_redirect_target(url))
    start_session(user_info)
    return jsonify({"success": True})
