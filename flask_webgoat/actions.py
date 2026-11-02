import base64
import binascii
import json
import re
import subprocess
from pathlib import Path

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)

FILENAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
DATA_DIR = Path("data")


@bp.route("/message", methods=["POST"])
def log_entry():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"}), 401
    access_level = user_info[2]
    if access_level > 2:
        return jsonify({"error": "access level < 2 is required for this action"}), 403
    filename_param = request.form.get("filename")
    if filename_param is None:
        return jsonify({"error": "filename parameter is required"}), 400
    if not FILENAME_RE.fullmatch(filename_param):
        return (
            jsonify(
                {"error": "filename may only contain letters, digits, '_' and '-'"}
            ),
            400,
        )
    text_param = request.form.get("text")
    if text_param is None:
        return jsonify({"error": "text parameter is required"}), 400

    user_dir_path = DATA_DIR / str(int(user_info[0]))
    user_dir_path.mkdir(parents=True, exist_ok=True)

    path = user_dir_path / (filename_param + ".txt")
    with path.open("w", encoding="utf-8") as open_file:
        open_file.write(text_param)
    return jsonify({"success": True})


@bp.route("/grep_processes")
def grep_processes():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"}), 401
    if user_info[2] != 0:
        return jsonify({"error": "access level of 0 is required for this action"}), 403
    name = request.args.get("name")
    if not name:
        return jsonify({"error": "name parameter is required"}), 400

    # No shell: the search term is matched in Python and never reaches a command line.
    res = subprocess.run(
        ["ps", "-eo", "args="], capture_output=True, text=True, timeout=5, check=False
    )
    names = [
        line.split()[0]
        for line in res.stdout.splitlines()
        if name in line and line.strip()
    ]
    return jsonify({"success": True, "names": names})


@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    encoded = request.form.get("pickled")
    if encoded is None:
        return jsonify({"error": "pickled parameter is required"}), 400
    try:
        deserialized = json.loads(base64.urlsafe_b64decode(encoded))
    except (binascii.Error, ValueError):
        return jsonify({"error": "pickled must be base64-encoded JSON"}), 400
    return jsonify({"success": True, "description": str(deserialized)})
