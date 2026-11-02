# Security Audit Report: flask-webgoat

- **Scope:** full project, `master` branch (all files: `flask_webgoat/*.py`, `flask_webgoat/templates/*.html`, `run.py`, `requirements.txt`, `azure-pipelines.yml`, `.github/workflows/main.yml`, `README.md`).
- **Method:** manual code review (STRIDE and OWASP Top 10:2021), `pip-audit` against the PyPI advisory database, and a smoke test of every endpoint with the Flask test client.
- **Note:** this repository has no `package.json` and no JavaScript dependencies. The only dependency manifest is the Python `requirements.txt`, so that is what was audited.
- **Context:** the project began as a *deliberately vulnerable* training app. All findings below were fixed in code unless marked otherwise.

## Summary

| # | Severity | Finding | Location | Status |
|---|----------|---------|----------|--------|
| 1 | P0 / CRITICAL | OS command injection (RCE) in `/grep_processes` | `flask_webgoat/actions.py` | Fixed |
| 2 | P0 / CRITICAL | Insecure deserialization (`pickle.loads`) in `/deserialized_descr` | `flask_webgoat/actions.py` | Fixed |
| 3 | P0 / CRITICAL | SQL injection in `/login` (authentication bypass) | `flask_webgoat/auth.py` | Fixed |
| 4 | P0 / CRITICAL | Hardcoded Flask `secret_key` (session forgery, privilege escalation) | `flask_webgoat/__init__.py` | Fixed |
| 5 | P0 / CRITICAL | Hardcoded admin credentials stored in plaintext | `flask_webgoat/__init__.py` | Fixed |
| 6 | P1 / HIGH | 37 known CVEs/advisories in pinned dependencies | `requirements.txt` | Fixed |
| 7 | P1 / HIGH | SQL injection in `/create_user` | `flask_webgoat/users.py` | Fixed |
| 8 | P1 / HIGH | Path traversal (arbitrary file write) in `/message` | `flask_webgoat/actions.py` | Fixed |
| 9 | P1 / HIGH | Passwords stored and compared in plaintext | `auth.py`, `users.py` | Fixed |
| 10 | P2 / MEDIUM | Open redirect in `/login_and_redirect` | `flask_webgoat/auth.py` | Fixed |
| 11 | P2 / MEDIUM | SQL statements (including passwords) printed to stdout | `flask_webgoat/__init__.py` | Fixed |
| 12 | P2 / MEDIUM | Unauthenticated user enumeration via `/search` | `flask_webgoat/ui.py` | Fixed |
| 13 | P2 / MEDIUM | Wildcard CORS and weak CSP (`'unsafe-inline'`) | `run.py` | Fixed |
| 14 | P2 / MEDIUM | Session fixation and missing cookie hardening | `auth.py`, `__init__.py` | Fixed |
| 15 | P2 / MEDIUM | Weak password policy and duplicate usernames | `users.py`, `__init__.py` | Fixed |
| 16 | P2 / MEDIUM | No rate limiting on login endpoints | `auth.py` | Open (recommendation) |
| 17 | P3 / LOW | Credentials accepted in URL query string | `auth.py` | Open (recommendation) |
| 18 | P3 / LOW | CI downloads and runs unverified binaries/scripts | `azure-pipelines.yml`, `.github/workflows/main.yml` | Open (recommendation) |

XSS check: no exploitable XSS was found. `/search` reflects the `query` parameter, but Jinja2 autoescaping is on for `.html` templates. A `<script>` payload was verified to render as `&lt;script&gt;`. The CSP was also tightened (finding 13) as defense in depth.

## 1. Dependency vulnerabilities

### [P1] [security] Update outdated Flask stack with 37 known advisories

`pip-audit` found 37 advisories across 3 of the 6 pinned packages. They include Werkzeug debugger and multipart issues, Werkzeug `safe_join` path traversal on Windows, the Jinja2 sandbox escapes and `xmlattr` XSS, and Flask session-cookie caching disclosure (PYSEC-2023-62).

| Package | Old | New | Advisories fixed |
|---------|-----|-----|------------------|
| Flask | 0.12.5 | 3.1.3 | PYSEC-2019-179, PYSEC-2023-62, PYSEC-2026-2151 |
| Werkzeug | 0.16.1 | 3.1.9 | PYSEC-2022-203, PYSEC-2023-57/58/221, PYSEC-2026-2043/2044/2045/2046/2320/4312 |
| Jinja2 | 2.8 | 3.1.6 | PYSEC-2019-217/220, PYSEC-2021-66, PYSEC-2026-1471/1473/1474/1475 |
| MarkupSafe | 1.1.1 | 3.0.3 | (required by Jinja2 3.x) |
| itsdangerous | 1.1.0 | 2.2.0 | (required by Flask 3.x) |
| click | 7.1.2 | 8.1.8 | (required by Flask 3.x) |
| blinker | (none) | 1.9.0 | new required dependency of Flask 3.x |

After the update, `pip-audit -r requirements.txt` reports **No known vulnerabilities found**. All packages remain pinned to exact versions. `blinker` is a long-established Pallets dependency (not newly published) and is required by Flask 2.3+. Typosquatting check: all package names are the canonical Pallets project names.

Recommendation: add hash pinning (`pip-compile --generate-hashes`) and run `pip-audit` in CI.

## 2. Hardcoded secrets

### [P0] [security] Remove hardcoded Flask secret key

`flask_webgoat/__init__.py:22` set `app.secret_key` to a constant string. Flask signs the session cookie, which holds `user_info` including `access_level`, with this key. Anyone with the source can forge a cookie with `access_level = 0` and become admin.

**Fix:** the key is read from `FLASK_SECRET_KEY`. When it is unset, a random 32-byte key is generated per process, so sessions cannot be forged (they do not survive restarts).

### [P0] [security] Remove hardcoded admin password

`flask_webgoat/__init__.py:33-34` seeded `admin` / `maximumentropy` in plaintext. The password is published in the repository, so anyone can log in as admin.

**Fix:** the admin password comes from `ADMIN_PASSWORD`. When unset, a random, unknown password is used, so no default credential exists. It is stored as a salted hash (`werkzeug.security.generate_password_hash`).

Other secrets scan: no API keys, tokens, or private keys found. CI tokens in `azure-pipelines.yml` (`$(SHIFTLEFT_*)`) and `.github/workflows/main.yml` (`secrets.FACTORY_API_KEY`, `secrets.GITHUB_TOKEN`) are correctly referenced from secret stores.

## 3. Authentication and authorization

### [P0] [security] Fix SQL injection authentication bypass in /login

`auth.py:18-21` built the query with `%` string formatting. `username=admin' --` logs in as admin without a password.

**Fix:** parameterized query that looks up the user by name, then a constant-time hash check with `check_password_hash`.

### [P1] [security] Hash stored passwords

Passwords were stored and compared in plaintext, and the SQL trace logging (finding 11) printed them. **Fix:** all passwords are hashed on insert (`users.py`, `__init__.py`) and verified with `check_password_hash` (`auth.py`).

### [P2] [security] Prevent session fixation and harden session cookie

The session was not cleared on login, and cookie flags were defaults. **Fix:** `session.clear()` before setting `user_info`, and `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE=Lax` (mitigates CSRF on the POST endpoints), and `SESSION_COOKIE_SECURE` (on by default; set `SESSION_COOKIE_SECURE=0` for local HTTP development).

### [P2] [security] Require login for /search (user enumeration)

`/search?query=%` returned every username and access level to unauthenticated visitors, which aids targeted attacks on the admin account. **Fix:** the endpoint now requires an authenticated session.

### [P1] [security] Authorize /grep_processes

The endpoint was unauthenticated (see finding 1 for the injection). **Fix:** it now requires an admin session (`access_level == 0`).

### [P2] [security] Strengthen password policy and enforce unique usernames

The minimum password length was 3, and `username` had no uniqueness constraint. A duplicate `admin` row made login ambiguous. `access_level` accepted any integer, including negative values. **Fix:** minimum length 8, `UNIQUE NOT NULL` on `username` (duplicate returns 409), and `access_level` must be a non-negative integer.

Authorization checks on `/message` (access level ≤ 2) and `/create_user` (access level 0) are logically correct. They were only bypassable through the forged session cookie (finding 4) and SQL injection (finding 3), both fixed. Failed checks now return 401/403 instead of 200.

## 4. Injection and other code findings

### [P0] [security] Remove shell command injection in /grep_processes

`actions.py:44-48` ran `"ps aux | grep " + name` with `shell=True`. `?name=x;id` executed arbitrary commands, without authentication.

**Fix:** `subprocess.run(["ps", "-eo", "args="])` with no shell and a 5 s timeout, and the name is filtered in Python. Verified: `name=x;id` returns an empty list.

### [P0] [security] Replace pickle deserialization in /deserialized_descr

`pickle.loads` on request data allows remote code execution through a crafted `__reduce__` payload, without authentication. **Fix:** the payload is decoded as base64 JSON with `json.loads`. Invalid input returns 400. Pickle payloads are rejected. Clients must now send base64-encoded JSON in the `pickled` field.

### [P1] [security] Fix SQL injection in /create_user

`users.py:38-41` interpolated `username` and `password` into an `INSERT`. **Fix:** parameterized query. Verified: `bob','x',0)--` is stored as a literal username.

### [P1] [security] Fix path traversal in /message

`filename` was concatenated into a file path, so `../../app/run` (plus `.txt`) wrote anywhere the process can write. **Fix:** `filename` must match `[A-Za-z0-9_-]{1,64}`, and the path is built with `pathlib`. `MAX_CONTENT_LENGTH` (1 MiB) bounds request size.

### [P2] [security] Fix open redirect in /login_and_redirect

On a failed login the app redirected to any user-supplied `url`, which enables phishing. **Fix:** only same-site relative paths are allowed. `//evil.com`, `/\evil.com`, and `https://evil.com` all redirect to `/`.

### [P2] [security] Stop logging SQL statements

`conn.set_trace_callback(print)` printed every SQL statement, including passwords, to stdout and logs. **Fix:** removed.

### [P2] [security] Remove wildcard CORS and unsafe-inline CSP

`run.py` sent `Access-Control-Allow-Origin: *` and `script-src 'self' 'unsafe-inline'`. **Fix:** CORS header removed (same-origin only), and the CSP is now `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`, plus `X-Content-Type-Options: nosniff`.

Error messages in `ui.py` and `users.py` also concatenated user input and `sqlite3.Error` objects. Those raised `TypeError` (500 with traceback in debug mode), and they now return generic messages.

## 5. Open recommendations (not changed)

- **[P2] Rate limiting:** `/login` and `/login_and_redirect` allow unlimited password guessing. Add `Flask-Limiter` or rate limiting at the reverse proxy. Not added, to avoid introducing a new dependency without review.
- **[P3] Credentials in query string:** `/login_and_redirect` takes `username` and `password` as GET parameters, which end up in server logs, browser history, and `Referer` headers. Migrate clients to `POST /login`. Not changed because it would break the endpoint's API.
- **[P3] CI supply chain:** `.github/workflows/main.yml` runs `curl -fsSL https://app.factory.ai/cli | sh`, and `azure-pipelines.yml` downloads `sl-latest-windows-x64.zip` and an LCOW release without checksum verification. Pin versions and verify checksums. Also add a minimal `permissions:` block to the GitHub workflow, because it creates issues and PRs with `GITHUB_TOKEN`. CI files were not modified.

## Configuration changes required for deployment

| Variable | Purpose | Default when unset |
|----------|---------|--------------------|
| `FLASK_SECRET_KEY` | Session signing key (set a long random value) | Random per process |
| `ADMIN_PASSWORD` | Initial `admin` password | Random, unknown (admin login disabled) |
| `SESSION_COOKIE_SECURE` | `1` = cookie only over HTTPS | `1` |

## Validation

- `pip-audit` before: 37 known vulnerabilities in 3 packages. After: none.
- Endpoint smoke test (Flask test client, temporary directory). All of these were confirmed: SQLi login rejected, unauthenticated `/search` and `/grep_processes` return 401, open redirect targets fall back to `/`, CORS header absent, XSS payload escaped, traversal filename rejected, valid message written, command-injection payload inert, SQLi username stored literally, duplicate user gets 409, negative access level gets 400, pickle payload rejected, JSON payload accepted, valid admin login succeeds.
- The repository has no automated test suite.
