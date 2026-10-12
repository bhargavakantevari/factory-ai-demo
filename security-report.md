# Security Audit Report

- **Repository:** flask-webgoat (`master`, commit `25b11cd`)
- **Scope:** Full-project audit of every file in the repo: `run.py`, `flask_webgoat/*.py`, `flask_webgoat/templates/*.html`, `requirements.txt`, `azure-pipelines.yml`, `.github/workflows/main.yml`, `README.md`, `LICENSE`
- **Method:** STRIDE and OWASP Top 10:2021, plus `pip-audit` (PyPI advisory database) for dependencies
- **Context:** The README says this is a *deliberately vulnerable* training app. The code-level vulnerabilities below are intentional. This audit documents each one with a recommended fix. It does not change the application code, because that would defeat the project's purpose. Only the dependencies were updated.

## Summary

| Severity | Count |
| --- | --- |
| Critical (P0) | 5 |
| High (P1) | 3 |
| Medium (P2) | 4 |
| Low (P3) | 2 |
| Vulnerable dependencies | 37 advisory hits (20 unique) in 3 packages, all **fixed** |

> Note: This is a Python project. There is no `package.json`. The dependency manifest is `requirements.txt`.

---

## 1. Dependency Vulnerabilities (fixed)

`pip-audit` reported 20 unique advisories in the pinned versions. `requirements.txt` was upgraded to current releases. After the upgrade, `pip-audit -r requirements.txt` reports **No known vulnerabilities found**.

| Package | Old | New | Advisories fixed |
| --- | --- | --- | --- |
| Flask | 0.12.5 | **3.1.3** | CVE-2019-1010083 (JSON DoS), CVE-2023-30861 (session data cached by proxies), CVE-2026-27205 (missing `Vary: Cookie`) |
| Werkzeug | 0.16.1 | **3.1.9** | CVE-2022-29361 (request smuggling, disputed), CVE-2023-23934 (nameless cookies), CVE-2023-25577 (multipart DoS), CVE-2023-46136 (multipart DoS), CVE-2024-34069 (debugger RCE), CVE-2024-49766, CVE-2025-66221, CVE-2026-21860, CVE-2026-27199, GHSA-g6x2-hccm-hh4m (`safe_join` bypasses on Windows) |
| Jinja2 | 2.8 | **3.1.6** | CVE-2016-10745, CVE-2019-10906, CVE-2024-56326, CVE-2025-27516 (sandbox escapes), CVE-2020-28493 (ReDoS), CVE-2024-22195, CVE-2024-34064 (`xmlattr` injection) |
| MarkupSafe | 1.1.1 | 3.0.3 | None. Upgraded for Jinja2 3.x compatibility. |
| itsdangerous | 1.1.0 | 2.2.0 | None. Required by Flask 3.1. |
| click | 7.1.2 | 8.1.8 | None. Required by Flask 3.1. |
| blinker | — | 1.9.0 | New, required by Flask 3.1. It is a long-established Pallets package, not a typosquat. |

**Supply chain checks:** All packages are pinned to exact versions. All names match the official Pallets packages, so there is no typosquatting. All of them install from prebuilt wheels, which do not run install scripts. `blinker` is the only new dependency, and it is a mature package (1.9.0, released 2024), not a recently published one.

**Compatibility:** Flask 3.1 requires Python 3.9 or later. The app was installed and smoke-tested under Python 3.12. `/status`, `/search`, `/login`, and `/login_and_redirect` all behave the same as before.

---

## 2. Findings

### [P0] [security] SQL injection in login allows authentication bypass as admin
**File:** `flask_webgoat/auth.py:18-22` · **OWASP:** A03 Injection, A07 · **CWE-89**

`username` and `password` are inserted into the SQL string with `%` formatting. A username such as `admin' --` comments out the password check and logs the attacker in as the admin user (access level 0). That gives full privileges, including `/create_user`.

**Fix:** Use a parameterized query, the same way `/login_and_redirect` already does:
```python
query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
result = query_db(query, (username, password), True)
```

### [P0] [security] Unauthenticated OS command injection in `/grep_processes`
**File:** `flask_webgoat/actions.py:42-48` · **OWASP:** A03 Injection · **CWE-78**

The `name` query parameter is concatenated into a shell command that runs with `shell=True`. The route has no authentication. A request such as `/grep_processes?name=x;id` runs arbitrary commands on the server (remote code execution).

**Fix:** Do not use a shell. Enumerate processes in Python (for example with `psutil`) and filter by `name`. Alternatively, call `subprocess.run(["ps", "-eo", "comm"], shell=False)` and filter the output in Python. Also require authentication.

### [P0] [security] Unauthenticated insecure deserialization with `pickle.loads`
**File:** `flask_webgoat/actions.py:58-61` · **OWASP:** A08 Integrity Failures · **CWE-502**

The `pickled` form field is base64-decoded and passed to `pickle.loads`. The route has no authentication. A crafted pickle (an object with `__reduce__` returning `os.system`) runs arbitrary code on the server.

**Fix:** Never unpickle untrusted data. Accept JSON and parse it with `json.loads`, then validate its structure.

### [P0] [security] Hardcoded Flask `secret_key` allows session forgery
**File:** `flask_webgoat/__init__.py:22` · **OWASP:** A02, A07 · **CWE-798**

The session-signing key is a fixed constant in source code. Flask sessions are client-side cookies signed with this key. Anyone who reads the repo can forge a cookie with `user_info = (1, "admin", 0)` and gain admin access without credentials.

**Fix:** Load the key from the environment and refuse to start without it:
```python
app.secret_key = os.environ["FLASK_SECRET_KEY"]  # e.g. secrets.token_hex(32)
```

### [P0] [security] Hardcoded admin credentials stored in plaintext
**File:** `flask_webgoat/__init__.py:33-35` · **OWASP:** A07, A02 · **CWE-798, CWE-256**

Every startup seeds an admin account (access level 0) with a fixed password in source code. Anyone with repo access can log in as admin. All passwords, including those added through `/create_user`, are stored and compared in plaintext.

**Fix:** Create the initial admin from an environment-provided or one-time generated password. Store hashes with `werkzeug.security.generate_password_hash` and verify them with `check_password_hash`.

### [P1] [security] SQL injection in `/create_user`
**File:** `flask_webgoat/users.py:38-44` · **OWASP:** A03 Injection · **CWE-89**

`username` and `password` are formatted into an `INSERT` statement. The route requires access level 0, but that level is easy to reach through the login SQL injection or the forged session above. An attacker can inject arbitrary SQL, for example to tamper with other rows through a sub-select.

**Fix:**
```python
query_db("INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)",
         (username, password_hash, int(access_level)), False, True)
```

### [P1] [security] Path traversal arbitrary file write in `/message`
**File:** `flask_webgoat/actions.py:32-36` · **OWASP:** A01 · **CWE-22**

`filename` from the request is appended to `data/<user_id>/` without sanitization. Any logged-in user with access level 2 or lower can submit `filename=../../flask_webgoat/templates/x` and write attacker-controlled content to any `.txt` path the process can write to. They can also overwrite existing files.

**Fix:** Sanitize the name with `werkzeug.utils.secure_filename`, resolve the path, and verify that it stays inside the user's directory:
```python
path = (base / (secure_filename(filename_param) + ".txt")).resolve()
if not path.is_relative_to(base.resolve()): abort(400)
```

### [P1] [security] Open redirect in `/login_and_redirect`
**File:** `flask_webgoat/auth.py:44-46` · **OWASP:** A01 · **CWE-601**

When login fails, the user is redirected to the attacker-supplied `url` parameter with no validation. This enables phishing links that start on the trusted domain. The endpoint also accepts credentials in GET query strings, which leak into logs, browser history, and `Referer` headers.

**Fix:** Allow only relative paths on the same host (reject URLs with a scheme or a netloc, and reject `//`), or use a fixed allow-list. Accept credentials only through POST.

### [P2] [security] SQL statements, including plaintext passwords, logged to stdout
**File:** `flask_webgoat/__init__.py:13` · **OWASP:** A09 · **CWE-532**

`conn.set_trace_callback(print)` prints every executed SQL statement. Because of the string-built queries, this includes submitted passwords in clear text. Anyone with log access can harvest them.

**Fix:** Remove the trace callback, or route it to a debug-only logger that redacts parameters.

### [P2] [security] No CSRF protection on state-changing POST endpoints
**Files:** `flask_webgoat/users.py:10`, `flask_webgoat/actions.py:11`, `flask_webgoat/auth.py:7` · **OWASP:** A01 · **CWE-352**

`/create_user` and `/message` rely only on the session cookie and have no CSRF token. The session cookie has no explicit `SameSite` attribute. A malicious page visited by a logged-in admin can make the admin's browser create a new access-level-0 user, in browsers that do not default to `SameSite=Lax`.

**Fix:** Add CSRF tokens (for example with Flask-WTF `CSRFProtect`) and set `SESSION_COOKIE_SAMESITE="Lax"`, `SESSION_COOKIE_SECURE=True`, and `SESSION_COOKIE_HTTPONLY=True`.

### [P2] [security] No rate limiting or lockout on login endpoints
**File:** `flask_webgoat/auth.py:7, 29` · **OWASP:** A07 · **CWE-307**

`/login` and `/login_and_redirect` allow unlimited attempts. Combined with the 3-character minimum password (`users.py:31`), brute force and credential stuffing are practical.

**Fix:** Add rate limiting (for example with Flask-Limiter), require a stronger minimum password length (12 or more characters), and log failed logins.

### [P2] [security] Unauthenticated sensitive actions; access control relies only on a forgeable session
**Files:** `flask_webgoat/actions.py:40, 56` · **OWASP:** A01 · **CWE-306**

`/grep_processes` and `/deserialized_descr` have no authentication check at all. Elsewhere, authorization depends only on the client-side session tuple, which is forgeable because of the hardcoded secret. There is no central authorization decorator, so it is easy to forget the check on new routes.

**Fix:** Add a `login_required` / `require_access_level(n)` decorator, apply it to every non-public route, and fix the secret key issue.

### [P3] [security] Weak Content-Security-Policy and wildcard CORS
**File:** `run.py:8-10` · **OWASP:** A05

`script-src 'self' 'unsafe-inline'` removes CSP's main XSS protection. `Access-Control-Allow-Origin: *` lets any origin read unauthenticated responses. Browsers will not send cookies with a wildcard origin, so authenticated data is not directly exposed.

**Fix:** Use `script-src 'self'` with no `unsafe-inline`. Remove the CORS header, or restrict it to an explicit list of trusted origins.

### [P3] [security] CI pipeline downloads and runs unverified binaries
**File:** `azure-pipelines.yml:17-18, 24-27` · **OWASP:** A08

The pipeline downloads `sl-latest` and the LCOW release zip and runs them without checking a checksum or signature, then restarts Docker with experimental mode enabled. If the CDN or the release is compromised, the pipeline (which holds ShiftLeft tokens) is compromised too. Secrets are correctly sourced from a variable group and are not hardcoded.

**Fix:** Pin specific versions and verify SHA-256 hashes before extracting.

---

## 3. Areas Reviewed With No Issues

- **XSS:** `search.html` and `error.html` render `{{ query }}`, `{{ result }}`, and `{{ message }}` with Jinja autoescaping, which Flask enables by default for `.html` templates. A test confirmed that `/search?query=<script>…` is output as `&lt;script&gt;`. No `|safe`, `Markup()`, or `autoescape false` is used. **No reflected or stored XSS was found.**
- **`/search` SQL:** Uses a parameterized `LIKE ?` query, so it is not injectable.
- **Hardcoded secrets in CI:** `.github/workflows/main.yml` and `azure-pipelines.yml` use `secrets.*` and variable groups. No tokens or API keys are committed.
- **`status.py`:** Only static health endpoints.
- **Debug mode:** `app.run()` does not enable the Werkzeug debugger.

## 4. Changes Made

| File | Change |
| --- | --- |
| `requirements.txt` | Upgraded Flask, Werkzeug, Jinja2, MarkupSafe, itsdangerous, and click to patched versions; added `blinker` (a required Flask 3.x dependency). |
| `security-report.md` | This report. |

Application code was intentionally left unchanged, because this repository is a deliberately vulnerable training target. Apply the fixes listed above if you deploy any of this code outside a lab.

## 5. Validation

- `pip-audit -r requirements.txt` before the upgrade: 37 hits (20 unique advisories) in Flask, Werkzeug, and Jinja2.
- `pip-audit -r requirements.txt` after the upgrade: **No known vulnerabilities found**.
- Smoke test with the upgraded dependencies on Python 3.12, using the Flask test client: `/status` returned 200, `/search` returned 200 with escaped output, a bad `/login` returned 400, and a failed `/login_and_redirect` returned 302. All match the original behavior.
