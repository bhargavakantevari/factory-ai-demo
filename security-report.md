# Security Audit Report

- **Repository:** factory-ai-demo (flask-webgoat)
- **Branch audited:** `master` (commit `25b11cd`)
- **Scope:** full project. Every source and configuration file was reviewed.
- **Method:** STRIDE, OWASP Top 10:2021, supply chain analysis, and `pip-audit` against the PyPI advisory database.
- **Date:** 2026-10-05

## Summary

This is a Python/Flask project. There is no `package.json`, so the dependency audit covered `requirements.txt` instead.

| Severity | Found | Fixed in this change |
| --- | --- | --- |
| CRITICAL (P0) | 5 | 5 |
| HIGH (P1) | 5 | 5 |
| MEDIUM (P2) | 6 | 5 |
| LOW (P3) | 3 | 0 (recommendations) |

The pinned dependencies had **37 known vulnerability records** (19 unique advisories) across 4 packages. After the upgrade, `pip-audit` reports **no known vulnerabilities**.

The README describes this app as deliberately vulnerable. The planted vulnerabilities have now been fixed, and the README has been updated to say so. If the project must stay a training target, revert the code changes and keep only the dependency upgrade.

### Files reviewed

| File | Notes |
| --- | --- |
| `run.py` | App entry point, response headers |
| `flask_webgoat/__init__.py` | App factory, database setup, `query_db` helper |
| `flask_webgoat/auth.py` | `/login`, `/login_and_redirect` |
| `flask_webgoat/users.py` | `/create_user` |
| `flask_webgoat/actions.py` | `/message`, `/grep_processes`, `/deserialized_descr` |
| `flask_webgoat/ui.py` | `/search` |
| `flask_webgoat/status.py` | `/status`, `/ping` (no issues) |
| `flask_webgoat/templates/*.html` | Jinja templates (autoescaped, no issues) |
| `requirements.txt` | Dependencies |
| `azure-pipelines.yml`, `.github/workflows/main.yml` | CI configuration |

---

## 1. Dependency vulnerabilities (OWASP A06)

### Upgrades applied

| Package | Old | New | Advisories fixed |
| --- | --- | --- | --- |
| Flask | 0.12.5 | **3.1.3** | CVE-2019-1010083 (DoS), CVE-2023-30861 (session cookie cached across clients), CVE-2026-27205 (missing `Vary: Cookie`) |
| Werkzeug | 0.16.1 | **3.1.9** | CVE-2022-29361 (request smuggling), CVE-2023-23934 (nameless cookies), CVE-2023-25577 (multipart DoS), CVE-2023-46136 (multipart DoS), CVE-2024-34069 (debugger RCE), CVE-2024-49766, CVE-2025-66221, CVE-2026-21860, CVE-2026-27199 (`safe_join` path issues on Windows) |
| Jinja2 | 2.8 | **3.1.6** | CVE-2016-10745, CVE-2019-10906, CVE-2024-56326, CVE-2025-27516 (sandbox escapes), CVE-2020-28493 (ReDoS), CVE-2024-22195, CVE-2024-34064 (`xmlattr` attribute injection) |
| click | 7.1.2 | **8.5.0** | CVE-2026-7246 (command injection in `click.edit()`) |
| MarkupSafe | 1.1.1 | **3.0.3** | None known. Upgraded because Jinja2 3.1 requires MarkupSafe 2.0 or later. |
| itsdangerous | 1.1.0 | **2.2.0** | None known. Upgraded because Flask 3.1 requires itsdangerous 2.2 or later. |

### Supply chain checks

- **Release age:** every target version was published more than 7 days before this audit. MarkupSafe 3.0.4 (3 days old) was skipped on purpose, and 3.0.3 was pinned instead.
- **New packages:** none were added. Only existing pins were bumped.
- **Typosquatting:** all names are the official Pallets packages.
- **Pinning:** all packages are pinned to exact versions. Adding hashes (`pip-compile --generate-hashes`) is recommended.

---

## 2. Hardcoded secrets and credentials (OWASP A02, A07)

### [P0] [security] Hardcoded Flask `secret_key` — FIXED

`flask_webgoat/__init__.py:22` had a literal `app.secret_key` in source. Anyone with repository access could sign forged session cookies, for example `user_info = (1, "admin", 0)`, and become admin without a password.

**Fix:** the key is read from the `FLASK_SECRET_KEY` environment variable. If it is unset, a random 32-byte key is generated with `secrets.token_hex`.

### [P0] [security] Default admin credential `admin` / `maximumentropy` — FIXED

`flask_webgoat/__init__.py:33-35` seeded an admin account with a password published in the source code.

**Fix:** the admin password comes from `ADMIN_PASSWORD`. If it is unset, a random unknown password is used, so no default credential ships with the app.

### [P1] [security] Passwords stored and compared in plaintext — FIXED

Passwords were stored as plaintext in the `user` table and compared directly in SQL.

**Fix:** passwords are hashed with `werkzeug.security.generate_password_hash` (scrypt) and verified with `check_password_hash` (`auth.py`, `users.py`, `__init__.py`).

### CI configuration

`azure-pipelines.yml` and `.github/workflows/main.yml` reference tokens only through secret variable groups or `secrets.*`. No literal secrets were found.

---

## 3. Authentication and authorization (OWASP A01, A07)

### [P0] [security] Authentication bypass via SQL injection in `/login` — FIXED

`flask_webgoat/auth.py:18-21` built the login query with `%` string formatting. The username `admin' --` logged in as admin with any password. See section 4.

### [P1] [security] Open redirect in `/login_and_redirect` — FIXED

`auth.py:44-46` redirected to the user-supplied `url` with no validation, and did so when the login *failed*. This made the endpoint a phishing redirector on a trusted domain.

**Fix:** `url` must be a same-site relative path. Absolute URLs, `//host` and `/\host` are rejected with HTTP 400. The redirect now happens only after a successful login.

### [P2] [security] Session fixation — FIXED

The login handlers wrote to the existing session without clearing it. Both handlers now call `session.clear()` before storing the user.

### [P2] [security] Weak password policy — FIXED

`/create_user` accepted 3-character passwords. The minimum is now 12 characters. The odd HTTP 402 status was also changed to 400.

### [P2] [security] Unauthenticated process listing in `/grep_processes` — FIXED

Anyone could list the command lines of host processes (see also the RCE below). The endpoint now requires a logged-in session.

### Authorization review (no change needed)

- `/create_user` correctly requires `access_level == 0` from the signed session. This is safe now that the secret key is no longer hardcoded.
- `/message` requires `access_level <= 2`, and writes are scoped to `data/<user_id>/`.
- `/status`, `/ping` and `/search` are public by design and expose no sensitive data. `/search` returns usernames and access levels only.

---

## 4. Injection and XSS (OWASP A03, A08)

### [P0] [security] SQL injection in `/login` — FIXED

- **Location:** `flask_webgoat/auth.py:18-22`
- **Problem:** `username` and `password` were interpolated into the SQL string.
- **Fix:** the query is parameterized: `SELECT ... FROM user WHERE username = ?`.

### [P1] [security] SQL injection in `/create_user` — FIXED

- **Location:** `flask_webgoat/users.py:38-44`
- **Problem:** `username` and `password` were interpolated into an `INSERT`. An admin session, or a forged one, could inject extra rows, such as a second admin account.
- **Fix:** the insert is parameterized. `access_level` is validated as a non-negative integer and returns HTTP 400 when invalid.

### [P0] [security] OS command injection (RCE) in `/grep_processes` — FIXED

- **Location:** `flask_webgoat/actions.py:42-48`
- **Problem:** the `name` query parameter was concatenated into a `shell=True` command. `?name=;id` executed arbitrary commands without authentication.
- **Fix:** the endpoint now runs `ps -eo args=` with no shell and no user input in argv. Filtering happens in Python.

### [P0] [security] Insecure deserialization (RCE) in `/deserialized_descr` — FIXED

- **Location:** `flask_webgoat/actions.py:56-62`
- **Problem:** the endpoint called `pickle.loads` on attacker-supplied base64 data without authentication. A crafted pickle gives arbitrary code execution.
- **Fix:** the endpoint accepts base64url-encoded **JSON** in the `encoded` form field and returns HTTP 400 for malformed input. **This is an API change:** the old `pickled` field is no longer accepted.

### [P1] [security] Path traversal in `/message` — FIXED

- **Location:** `flask_webgoat/actions.py:32-36`
- **Problem:** `filename` was joined into the path unchecked, so `../../run` overwrote arbitrary `.txt` files the process could write.
- **Fix:** `filename` must match `^[A-Za-z0-9_-]{1,64}$`. Paths are built with `pathlib`, and the data directory is created with `parents=True`.

### [P1] [security] SQL statements, including credentials, printed to stdout — FIXED

`flask_webgoat/__init__.py:13` set `conn.set_trace_callback(print)`. Every executed statement was written to logs, including plaintext passwords. The trace callback was removed.

### XSS review

- All templates (`base.html`, `error.html`, `search.html`) are `.html` files rendered with `render_template`. Flask enables Jinja autoescaping for these. No `|safe`, `Markup` or `autoescape false` is used.
- A test with `/search?query=<script>alert(1)</script>` confirmed that the payload is escaped.
- **No reachable XSS found.**

### [P2] [security] Error handlers leaking details or crashing — FIXED

`ui.py:23` and `users.py:47` concatenated a `sqlite3.Error` object to a string. This raised a `TypeError` (HTTP 500) and would also have echoed internal error text. Both now return a generic message.

---

## 5. Security misconfiguration (OWASP A05)

### [P2] [security] Wildcard CORS and weak CSP in `run.py` — FIXED

`Access-Control-Allow-Origin: *` was set on every response, and the CSP allowed `'unsafe-inline'` scripts.

**Fix:**
- The CORS header was removed, so the app is same-origin only.
- The CSP is now `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`.
- `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` were added.
- Session cookies are `HttpOnly` and `SameSite=Lax`.

---

## 6. Remaining recommendations (not changed)

| Priority | Issue | Recommendation |
| --- | --- | --- |
| P2 | No rate limiting or lockout on `/login` and `/login_and_redirect` (OWASP A04/A07) | Add a limiter such as Flask-Limiter, or throttle at the reverse proxy. |
| P3 | `/login_and_redirect` takes the password as a GET query parameter, so it can land in access logs and browser history | Change it to POST. This was left as is because it would change the public API. |
| P3 | No CSRF tokens on POST endpoints | `SameSite=Lax` blocks cross-site POSTs in modern browsers. Add Flask-WTF CSRF protection if HTML forms are introduced. |
| P3 | CI downloads and runs unpinned, unverified binaries: `curl ... \| sh` in `main.yml`, and `sl-latest` and `lcow` zips in `azure-pipelines.yml` | Pin versions and verify checksums or signatures before running them. |

Also set `SESSION_COOKIE_SECURE=True` when the app is served over HTTPS.

---

## Verification

- `pip-audit -r requirements.txt` before the change: **37 records, 19 unique advisories**. After the change: **no known vulnerabilities found**.
- The updated requirements install cleanly on Python 3.12, and all modules compile.
- A smoke test with the Flask test client confirmed the following:
  - `admin' --` login is rejected (HTTP 400). The old `maximumentropy` password no longer works.
  - `url=//evil.com` is rejected (HTTP 400). `url=/status` redirects after a valid login.
  - `/grep_processes` requires login. `name=;touch /tmp/smoke/pwned` did **not** create the file.
  - `filename=../../x` is rejected (HTTP 400). A valid filename writes to `data/1/note.txt`.
  - A SQL injection payload in `/create_user` is stored as a literal username: logging in with that exact string succeeds.
  - A pickle payload in `/deserialized_descr` is rejected (HTTP 400). Valid JSON is accepted.
  - The `<script>` payload in `/search` is escaped, and no CORS header is sent.
- The repository has no automated test suite.

## New configuration

| Variable | Purpose |
| --- | --- |
| `FLASK_SECRET_KEY` | Signs session cookies. **Required** in any shared or production deployment. |
| `ADMIN_PASSWORD` | Password for the seeded `admin` account. If unset, the admin account cannot be used. |
