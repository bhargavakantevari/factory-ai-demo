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
    return row[:3]


def is_safe_redirect(url):
    # Only same-site relative paths; "//host" and "/\host" are treated as
    # absolute URLs by browsers.
    if not url.startswith("/") or url.startswith(("//", "/\\")):
        return False
    parts = urlsplit(url)
    return not parts.scheme and not parts.netloc


@bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return (
            jsonify({"error": "username and password parameter have to be provided"}),
            400,
        )

    result = authenticate(username, password)
    if result is None:
        return jsonify({"bad_login": True}), 400
    session.clear()
    session["user_info"] = (result[0], result[1], result[2])
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

    result = authenticate(username, password)
    if result is None:
        return redirect(url if is_safe_redirect(url) else "/")
    session.clear()
    session["user_info"] = (result[0], result[1], result[2])
    return jsonify({"success": True})
