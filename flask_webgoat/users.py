import sqlite3

from flask import Blueprint, jsonify, session, request
from werkzeug.security import generate_password_hash

from . import query_db

bp = Blueprint("users", __name__)

MIN_PASSWORD_LENGTH = 8


@bp.route("/create_user", methods=["POST"])
def create_user():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"}), 401

    access_level = user_info[2]
    if access_level != 0:
        return jsonify({"error": "access level of 0 is required for this action"}), 403
    username = request.form.get("username")
    password = request.form.get("password")
    access_level = request.form.get("access_level")
    if username is None or password is None or access_level is None:
        return (
            jsonify(
                {
                    "error": "username, password and access_level parameters have to be provided"
                }
            ),
            400,
        )
    try:
        access_level = int(access_level)
    except ValueError:
        access_level = -1
    if access_level < 0:
        return jsonify({"error": "access_level must be a non-negative integer"}), 400
    if len(password) < MIN_PASSWORD_LENGTH:
        return (
            jsonify(
                {
                    "error": f"the password needs to be at least {MIN_PASSWORD_LENGTH} characters long"
                }
            ),
            400,
        )

    query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"

    try:
        query_db(
            query,
            (username, generate_password_hash(password), access_level),
            False,
            True,
        )
        return jsonify({"success": True})
    except sqlite3.IntegrityError:
        return jsonify({"error": "could not create user: username already exists"}), 409
    except sqlite3.Error:
        return jsonify({"error": "could not create user"}), 500
