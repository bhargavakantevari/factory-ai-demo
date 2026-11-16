import base64
import binascii
import json
import re
import subprocess
from pathlib import Path

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)

DATA_DIR = Path("data")
FILENAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


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
    if not FILENAME_RE.fullmatch(filename_param):
        return (
            jsonify({"error": "filename may only contain letters, digits, '_' and '-'"}),
            400,
        )
    text_param = request.form.get("text")
    if text_param is None:
        return jsonify({"error": "text parameter is required"})

    user_id = int(user_info[0])
    user_dir_path = (DATA_DIR / str(user_id)).resolve()
    user_dir_path.mkdir(parents=True, exist_ok=True)

    path = (user_dir_path / (filename_param + ".txt")).resolve()
    if path.parent != user_dir_path:
        return jsonify({"error": "invalid filename"}), 400
    with path.open("w", encoding="utf-8") as open_file:
        open_file.write(text_param)
    return jsonify({"success": True})


@bp.route("/grep_processes")
def grep_processes():
    if session.get("user_info") is None:
        return jsonify({"error": "no user_info found in session"}), 401
    name = request.args.get("name")
    if name is None:
        return jsonify({"error": "name parameter is required"}), 400
    # No shell: the search term is matched in Python, never interpreted.
    res = subprocess.run(["ps", "aux"], capture_output=True, check=False)
    if res.stdout is None:
        return jsonify({"error": "no stdout returned"})
    names = []
    for line in res.stdout.decode("utf-8", errors="replace").splitlines()[1:]:
        if name in line:
            fields = line.split(None, 10)
            if len(fields) > 10:
                names.append(fields[10].split()[0])
    return jsonify({"success": True, "names": names})


@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    encoded = request.form.get("pickled")
    if encoded is None:
        return jsonify({"error": "pickled parameter is required"}), 400
    # JSON instead of pickle: decoding untrusted data must never execute code.
    try:
        deserialized = json.loads(base64.urlsafe_b64decode(encoded))
    except (binascii.Error, ValueError):
        return jsonify({"error": "payload must be base64-encoded JSON"}), 400
    return jsonify({"success": True, "description": str(deserialized)})
