# Security Audit Report

- **Repository:** flask-webgoat (`master`)
- **Audit date:** 2026-11-09
- **Scope:** Full project. Every file was reviewed: `run.py`, `flask_webgoat/*.py`, `flask_webgoat/templates/*.html`, `requirements.txt`, `.github/workflows/main.yml`, `azure-pipelines.yml`, `README.md`.
- **Method:** STRIDE and the OWASP Top 10 (2021) applied by manual code review; `pip-audit` (PyPI/OSV advisory data) for dependencies; PyPI release metadata for publish-date checks; harmless proof-of-concept requests sent through the Flask test client.

> **Context:** The README states that this project is a *deliberately vulnerable* training application. The code vulnerabilities below are intentional and marked with `# vulnerability:` comments. This audit **fixed the vulnerable dependencies** and **documented the code vulnerabilities with recommended fixes, without changing them**. Patching them would remove the training material this repository exists to provide. Never deploy this application to a reachable network.

## Summary

| Area | Result |
| --- | --- |
| `package.json` | Not present. This is a Python project; `requirements.txt` is the dependency manifest. |
| Vulnerable dependencies | **19 unique advisories** in Flask, Jinja2, and Werkzeug. **Fixed:** all pins upgraded; `pip-audit` now reports 0. |
| Hardcoded secrets | 2 found: the Flask `secret_key` and the seeded admin password. |
| Authentication / authorization | 6 issues, including a login bypass and session forgery. |
| SQL injection | 2 found (login and user creation). |
| XSS | None exploitable. Jinja2 autoescaping is active and was verified. |
| Other code issues | Unauthenticated RCE (2), path traversal, open redirect, sensitive data in logs. |

### Findings by severity

| ID | Severity | Title | Location |
| --- | --- | --- | --- |
| F-01 | CRITICAL [P0] | OS command injection in `/grep_processes` | `flask_webgoat/actions.py:42-48` |
| F-02 | CRITICAL [P0] | Insecure deserialization (`pickle.loads`) in `/deserialized_descr` | `flask_webgoat/actions.py:58-61` |
| F-03 | CRITICAL [P0] | SQL injection in `/login` allows authentication bypass | `flask_webgoat/auth.py:17-22` |
| F-04 | CRITICAL [P0] | Hardcoded Flask `secret_key` enables session forgery | `flask_webgoat/__init__.py:22` |
| F-05 | CRITICAL [P0] | Hardcoded admin credentials seeded at startup | `flask_webgoat/__init__.py:33-35` |
| F-06 | HIGH [P1] | Vulnerable and outdated dependencies (19 advisories) | `requirements.txt` (**fixed**) |
| F-07 | HIGH [P1] | SQL injection in `/create_user` | `flask_webgoat/users.py:37-44` |
| F-08 | HIGH [P1] | Path traversal / arbitrary file write in `/message` | `flask_webgoat/actions.py:26-36` |
| F-09 | HIGH [P1] | Passwords stored in plaintext | `flask_webgoat/__init__.py:29-35`, `users.py:38-41` |
| F-10 | MEDIUM [P2] | Open redirect in `/login_and_redirect` | `flask_webgoat/auth.py:44-46` |
| F-11 | MEDIUM [P2] | SQL statements, including passwords, printed to stdout | `flask_webgoat/__init__.py:12-13` |
| F-12 | MEDIUM [P2] | Credentials accepted in the GET query string | `flask_webgoat/auth.py:29-33` |
| F-13 | MEDIUM [P2] | No CSRF protection on state-changing POST endpoints | `users.py:10`, `actions.py:11` |
| F-14 | MEDIUM [P2] | No rate limiting or lockout on login | `flask_webgoat/auth.py:7, 29` |
| F-15 | LOW [P3] | Weak password policy (3 characters minimum) | `flask_webgoat/users.py:31` |
| F-16 | LOW [P3] | Permissive CORS and weak CSP headers | `run.py:5-11` |
| F-17 | LOW [P3] | CI downloads and runs unverified binaries | `azure-pipelines.yml:17-25`, `.github/workflows/main.yml:16` |

---

## 1. Dependency vulnerabilities (fixed)

No `package.json` exists. Running `pip-audit` on the original `requirements.txt` reported these advisories:

| Package | Old pin | Advisories (CVE) | First fixed in |
| --- | --- | --- | --- |
| Flask | 0.12.5 | CVE-2019-1010083 (DoS via crafted JSON), CVE-2023-30861 (session cookie disclosure through caching proxies), CVE-2026-27205 | 1.0, 2.2.5, 3.1.3 |
| Jinja2 | 2.8 | CVE-2016-10745 and CVE-2019-10906 (sandbox escape), CVE-2020-28493 (ReDoS), CVE-2024-22195 and CVE-2024-34064 (`xmlattr` XSS), CVE-2024-56326 and CVE-2025-27516 (sandbox escape) | 3.1.6 |
| Werkzeug | 0.16.1 | CVE-2022-29361, CVE-2023-23934, CVE-2023-25577, CVE-2023-46136, CVE-2024-34069 (debugger RCE), CVE-2024-49766, CVE-2025-66221, CVE-2026-21860, CVE-2026-27199, CVE-2026-102598 | 3.1.9 |
| click | 7.1.2 | none | – |
| itsdangerous | 1.1.0 | none | – |
| MarkupSafe | 1.1.1 | none | – |

**Fix applied to `requirements.txt`:**

| Package | Before | After | Published |
| --- | --- | --- | --- |
| blinker | – (new; required by Flask 3.x) | 1.9.0 | 2024-11-08 |
| click | 7.1.2 | 8.5.0 | 2026-08-26 |
| Flask | 0.12.5 | 3.1.3 | 2026-02-19 |
| itsdangerous | 1.1.0 | 2.2.0 | 2024-04-16 |
| Jinja2 | 2.8 | 3.1.6 | 2025-03-05 |
| MarkupSafe | 1.1.1 | 3.0.4 | 2026-10-02 |
| Werkzeug | 0.16.1 | 3.1.9 | 2026-09-27 |

Notes:
- click 8.5.1 is the newest release, but it was published on 2026-11-06, less than 7 days before this audit. Brand-new releases are a common supply-chain attack vector, so 8.5.0 was pinned instead. It has no known advisories. Move to 8.5.1 or later once it has aged.
- `blinker` is a direct runtime dependency of Flask 3.x. It is pinned so that every installed package is locked to an exact version.
- No package was renamed or replaced, and no name looks like a typosquat. All pins are exact (`==`).
- No application code changes were needed. Flask 3.1 still supports every API the app uses (`Blueprint`, `session`, `jsonify`, `redirect`, `render_template`).

**Verification:**
- `pip install -r requirements.txt` followed by `pip check` reported "No broken requirements found."
- `pip-audit -r requirements.txt` reported "No known vulnerabilities found."
- The new `tests/test_app.py` smoke tests (status endpoint, login and session, admin user creation, rejected bad login, template autoescaping) passed: 4 of 4.

Remaining recommendation: add hashes (`pip-compile --generate-hashes`) so that installs are integrity-checked.

---

## 2. Hardcoded secrets and credentials

### F-04 [P0] [security] Hardcoded Flask `secret_key` enables session forgery
`flask_webgoat/__init__.py:22`: `app.secret_key = "<40-character literal>"`

Flask signs the client-side session cookie with this key. Anyone who reads the repository can forge a cookie containing `user_info = (1, "admin", 0)` and gain admin access (access level 0) without logging in. That forged session passes the authorization checks in `/create_user` and `/message`. (The key value is deliberately not repeated in this report.)
**Fix:** Load the key from the environment or a secret store, for example `app.secret_key = os.environ["FLASK_SECRET_KEY"]`, generated with `secrets.token_hex(32)`. Rotate the key, because the committed value must be treated as compromised.

### F-05 [P0] [security] Hardcoded admin credentials seeded at startup
`flask_webgoat/__init__.py:33-35` inserts a user `admin` with a fixed plaintext password and access level 0 every time the app starts. These are well-known default credentials.
**Fix:** Do not seed privileged accounts in code. Create the admin through a one-time setup step that takes the password from the environment, and store only a hash (see F-09).

No other API keys, tokens, or private keys were found. CI secrets (`SHIFTLEFT_*`, `FACTORY_API_KEY`, `GITHUB_TOKEN`) are referenced through secret variables, not committed.

---

## 3. Authentication and authorization review

The app uses Flask's signed cookie session. `session["user_info"] = (id, username, access_level)` is set at login. Authorization reads `user_info[2]` from that session (`0` means admin; `<= 2` is allowed to write messages). The checks are present on the right endpoints, but every layer around them can be bypassed:

- **F-03 [P0] [security] SQL injection in `/login` allows authentication bypass** (`auth.py:17-22`). The username and password are interpolated into SQL with `%`. **Confirmed:** `username=admin' --` with any password returned `{"success": true}` and an admin session.
  **Fix:** `query_db("SELECT id, username, access_level FROM user WHERE username = ? AND password = ?", (username, password), True)`, then compare password hashes (F-09).
- **F-04** (session forgery through the hardcoded key) bypasses login entirely.
- **F-05** provides known default admin credentials.
- **F-09 [P1] [security] Passwords stored in plaintext** (`__init__.py:29-35`, `users.py:38-41`). Any database read or SQL injection exposes every password. **Fix:** hash passwords with `werkzeug.security.generate_password_hash` and verify them with `check_password_hash`.
- **F-12 [P2] [security] Credentials accepted in the GET query string** (`auth.py:29-33`). `/login_and_redirect` takes `username` and `password` as query parameters, which end up in access logs, browser history, and `Referer` headers. **Fix:** accept credentials only in a POST body.
- **F-13 [P2] [security] No CSRF protection** on `/create_user` and `/message`. Both rely only on the session cookie. Flask does not set `SameSite` by default, so protection depends on browser defaults. A malicious page could make a logged-in admin's browser create users. **Fix:** add CSRF tokens (Flask-WTF `CSRFProtect`) and set `SESSION_COOKIE_SAMESITE="Lax"`, `SESSION_COOKIE_SECURE=True`, and `SESSION_COOKIE_HTTPONLY=True`.
- **F-14 [P2] [security] No rate limiting or lockout** on `/login` or `/login_and_redirect`. This allows unlimited online password guessing. **Fix:** add rate limiting (for example Flask-Limiter) and log failed logins.
- **F-15 [P3] [security] Weak password policy** (`users.py:31`). Passwords only need 3 characters. **Fix:** require at least 12 characters and check against a list of breached passwords.
- **Error handling:** `/message` and `/create_user` return HTTP 200 with an error body when authorization fails. Use 401 or 403 so that clients and monitoring can tell the difference.

---

## 4. Injection and XSS

### F-01 [P0] [security] OS command injection in `/grep_processes`
`flask_webgoat/actions.py:42-48`. The unauthenticated `name` query parameter is concatenated into a shell command run with `shell=True`. **Confirmed:** `name=zzz; echo INJECTED_MARKER #` made the server run `/bin/sh -c ps aux | grep zzz; echo INJECTED_MARKER # ...`, and `INJECTED_MARKER` appeared in the response. Any remote user can execute arbitrary commands.
**Fix:** avoid the shell entirely. Use `psutil.process_iter(["name"])`, or `subprocess.run(["ps", "-eo", "comm"], capture_output=True)` and filter in Python. Require authentication.

### F-02 [P0] [security] Insecure deserialization in `/deserialized_descr`
`flask_webgoat/actions.py:58-61`. `pickle.loads` runs on attacker-supplied base64 data with no authentication. **Confirmed:** a payload whose `__reduce__` calls `eval` was executed; the response contained the evaluated result `PICKLE_EXEC_42`. This is unauthenticated remote code execution.
**Fix:** never unpickle untrusted data. Use `json.loads` with schema validation.

### F-03 [P0] SQL injection in `/login`
See section 3.

### F-07 [P1] [security] SQL injection in `/create_user`
`flask_webgoat/users.py:37-44`. `username` and `password` are interpolated into an `INSERT`. The endpoint requires access level 0, but F-03 and F-04 make that easy to get. Injected values can create extra admin accounts or corrupt the table.
**Fix:** `query_db("INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)", (username, password_hash, int(access_level)), commit=True)`.

`flask_webgoat/ui.py:17-18` (`/search`) already uses a parameterized query. It is **not** injectable.

### F-08 [P1] [security] Path traversal / arbitrary file write in `/message`
`flask_webgoat/actions.py:26-36`. `filename` is joined into `data/<user_id>/<filename>.txt` without validation. **Confirmed:** `filename=../../escaped` wrote `escaped.txt` outside the `data/` directory. An attacker can overwrite any `*.txt` file the process can write to.
**Fix:** reject path separators (for example `werkzeug.utils.secure_filename`), resolve the final path, and verify that it is inside the user's directory: `path.resolve().is_relative_to(user_dir_path.resolve())`.

### F-10 [P2] [security] Open redirect in `/login_and_redirect`
`flask_webgoat/auth.py:44-46`. When login fails, the user is redirected to the unvalidated `url` parameter. **Confirmed:** `url=https://evil.example` returned `302 Location: https://evil.example`. This is useful for phishing on a trusted domain.
**Fix:** allow only relative paths (check that `urlparse(url)` has no `netloc` or `scheme`), or use an allow-list.

### XSS: no exploitable issues found
- `search.html` and `error.html` render user input with `{{ ... }}`. Flask enables Jinja2 autoescaping for `.html` templates, and no `|safe` filter or `Markup()` call is used. **Confirmed:** `/search?query=<script>x</script>` renders as `&lt;script&gt;...` (covered by `tests/test_app.py`).
- All other endpoints return `application/json` through `jsonify`, which browsers do not render as HTML.
- The old Jinja2 2.8 pin had `xmlattr` XSS advisories (CVE-2024-22195 and CVE-2024-34064). The templates do not use `xmlattr`, and the upgrade to Jinja2 3.1.6 fixes them regardless.
- Related: the CSP in `run.py:10` allows `'unsafe-inline'` scripts, which would remove CSP as a second line of defense if an XSS bug were ever introduced (see F-16).

---

## 5. Other findings

- **F-11 [P2] [security] Sensitive data in logs** (`__init__.py:12-13`). `conn.set_trace_callback(print)` writes every SQL statement to stdout, including plaintext passwords from `/login` and `/create_user` (seen during testing). **Fix:** remove the trace callback, or log only redacted statements at debug level.
- **F-16 [P3] [security] Permissive CORS and weak CSP** (`run.py:5-11`). `Access-Control-Allow-Origin: *` lets any site read responses. Browsers do not send cookies with a wildcard origin, which limits the impact to unauthenticated data. The CSP allows inline scripts. **Fix:** remove the wildcard CORS header or restrict it to known origins, and drop `'unsafe-inline'`.
- **Error handling bug** (`ui.py:23`, `users.py:47`). `"..." + err` concatenates a string with an exception object, which raises `TypeError` and returns a 500 instead of the intended message. This is not exploitable, but use `str(err)` and avoid echoing raw database errors to clients.
- **F-17 [P3] [security] CI downloads and runs unverified binaries.** `azure-pipelines.yml:17-25` downloads `sl-latest` and a LinuxKit release zip without checksum verification. `.github/workflows/main.yml:16` pipes an install script into `sh`. **Fix:** pin versions and verify SHA-256 checksums before running downloaded code.

---

## Changes made in this audit

| File | Change |
| --- | --- |
| `requirements.txt` | Upgraded every pin to a patched release and added `blinker`. Fixes all 19 dependency advisories. |
| `tests/test_app.py`, `tests/__init__.py` | New smoke tests confirming that the app runs on the upgraded dependencies and that templates autoescape. Run with `python -m unittest discover -s tests -t .` |
| `security-report.md` | This report. |

The intentional code vulnerabilities (F-01 to F-05 and F-07 to F-17) were left unchanged because this is a deliberately vulnerable training application. Each finding includes the fix to apply in any code derived from it.
