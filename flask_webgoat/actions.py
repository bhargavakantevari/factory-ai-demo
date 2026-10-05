import base64
import binascii
import json
import re
import subprocess
from pathlib import Path

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)

DATA_DIR = Path("data")
FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@bp.route("/message", methods=["POST"])
def log_entry():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})
    access_level = user_info[2]
    if access_level > 2:
        return jsonify({"error": "access level < 2 is required for this action"})
    filename_param = request.form.get("filename")
    if filename_param is None:
        return jsonify({"error": "filename parameter is required"})
    if not FILENAME_PATTERN.fullmatch(filename_param):
        return (
            jsonify(
                {"error": "filename may only contain letters, digits, '_' and '-'"}
            ),
            400,
        )
    text_param = request.form.get("text")
    if text_param is None:
        return jsonify({"error": "text parameter is required"})

    user_dir_path = DATA_DIR / str(int(user_info[0]))
    user_dir_path.mkdir(parents=True, exist_ok=True)

    path = user_dir_path / (filename_param + ".txt")
    with path.open("w", encoding="utf-8") as open_file:
        open_file.write(text_param)
    return jsonify({"success": True})


@bp.route("/grep_processes")
def grep_processes():
    if session.get("user_info", None) is None:
        return jsonify({"error": "no user_info found in session"}), 401
    name = request.args.get("name")
    if not name:
        return jsonify({"error": "name parameter is required"}), 400
    res = subprocess.run(
        ["ps", "-eo", "args="],
        capture_output=True,
        text=True,
        check=False,
    )
    if not res.stdout:
        return jsonify({"error": "no stdout returned"})
    names = [
        line.split()[0]
        for line in res.stdout.splitlines()
        if name in line and line.split()
    ]
    return jsonify({"success": True, "names": names})


@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    # Accepts base64url-encoded JSON; pickle must never be used on client data
    # because unpickling can execute arbitrary code.
    encoded = request.form.get("encoded")
    if encoded is None:
        return jsonify({"error": "encoded parameter is required"}), 400
    try:
        data = json.loads(base64.urlsafe_b64decode(encoded))
    except (binascii.Error, ValueError):
        return jsonify({"error": "encoded must be base64url-encoded JSON"}), 400
    return jsonify({"success": True, "description": str(data)})
