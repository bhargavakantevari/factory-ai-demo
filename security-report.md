# Security Audit Report

- **Repository:** flask-webgoat (`factory-ai-demo`), branch `master` at `25b11cd`
- **Date:** 2026-11-16
- **Scope:** Full project. Every source and config file was reviewed:
  `run.py`, `flask_webgoat/{__init__,actions,auth,users,ui,status}.py`,
  `flask_webgoat/templates/{base,search,error}.html`, `requirements.txt`,
  `.github/workflows/main.yml`, `azure-pipelines.yml`, `README.md`.
- **Method:** STRIDE and OWASP Top 10 (2021) manual review, `pip-audit` against
  the OSV/PyPI advisory database, and PyPI metadata checks. The project has no
  LLM integration, so the OWASP LLM Top 10 does not apply.

> **Note on "package.json":** this is a Python project. There is no
> `package.json`, `package-lock.json`, or any Node.js code. The dependency audit
> was run against `requirements.txt`, which is the project's only manifest.

## Summary

| # | Severity | Finding | Location | Status |
|---|----------|---------|----------|--------|
| 1 | CRITICAL | OS command injection (RCE), unauthenticated | `flask_webgoat/actions.py` `/grep_processes` | Fixed |
| 2 | CRITICAL | Insecure deserialization with `pickle` (RCE), unauthenticated | `flask_webgoat/actions.py` `/deserialized_descr` | Fixed |
| 3 | CRITICAL | SQL injection in login (authentication bypass) | `flask_webgoat/auth.py` `/login` | Fixed |
| 4 | CRITICAL | Hardcoded Flask `secret_key` (session forgery, admin takeover) | `flask_webgoat/__init__.py:22` | Fixed (rotate) |
| 5 | CRITICAL | Hardcoded admin credential `admin` / `maximumentropy` | `flask_webgoat/__init__.py:33-35` | Fixed |
| 6 | HIGH | 37 known vulnerabilities in pinned dependencies | `requirements.txt` | Fixed |
| 7 | HIGH | SQL injection in user creation | `flask_webgoat/users.py` `/create_user` | Fixed |
| 8 | HIGH | Path traversal / arbitrary file write | `flask_webgoat/actions.py` `/message` | Fixed |
| 9 | HIGH | Passwords stored in plaintext | `__init__.py`, `auth.py`, `users.py` | Fixed |
| 10 | MEDIUM | Open redirect | `flask_webgoat/auth.py` `/login_and_redirect` | Fixed |
| 11 | MEDIUM | SQL statements (with passwords) printed to stdout | `flask_webgoat/__init__.py:13` | Fixed |
| 12 | MEDIUM | No CSRF protection on state-changing POST routes | `actions.py`, `users.py`, `auth.py` | Mitigated (SameSite=Lax) |
| 13 | MEDIUM | Credentials sent in the URL query string | `flask_webgoat/auth.py` `/login_and_redirect` | Open (recommendation) |
| 14 | MEDIUM | No rate limiting on login | `flask_webgoat/auth.py` | Open (recommendation) |
| 15 | LOW | Wildcard CORS and CSP allowing `unsafe-inline` scripts | `run.py` | Fixed |
| 16 | LOW | Database error details leaked / string concat crash | `users.py`, `ui.py` | Fixed |
| 17 | LOW | CI downloads and runs unverified binaries | `.github/workflows/main.yml`, `azure-pipelines.yml` | Open (recommendation) |

No XSS was found: Flask enables Jinja2 autoescaping for `.html` templates, and
`search.html` / `error.html` only use `{{ }}` output (no `|safe`, no
`Markup`). A test confirms `<script>` in the search query is escaped.

---

## 1. Dependency vulnerabilities (A06)

`pip-audit -r requirements.txt` on the original pins reported **37 known
vulnerabilities in 3 packages**:

| Package | Old | New | Advisories (fixed in) |
|---------|-----|-----|-----------------------|
| Flask | 0.12.5 | **3.1.3** | PYSEC-2019-179 (1.0, JSON DoS), PYSEC-2023-62 / CVE-2023-30861 (2.2.5, session cookie disclosure via caching proxy), PYSEC-2026-2151 (3.1.3) |
| Jinja2 | 2.8 | **3.1.6** | PYSEC-2019-220 / CVE-2016-10745 (2.8.1, sandbox escape), PYSEC-2019-217 / CVE-2019-10906 (2.10.1, sandbox escape), PYSEC-2021-66 / CVE-2020-28493 (2.11.3, ReDoS), CVE-2024-22195 (3.1.3), CVE-2024-34064 (3.1.4), CVE-2024-56201/56326 (3.1.5), CVE-2025-27516 (3.1.6) |
| Werkzeug | 0.16.1 | **3.1.9** | PYSEC-2022-203 / CVE-2022-29361 (2.1.1), CVE-2023-23934 and CVE-2023-25577 (2.2.3, cookie parsing and multipart DoS), CVE-2023-46136 (3.0.1), CVE-2024-34069 (3.0.3, debugger RCE), CVE-2024-49766/49767 (3.0.6), and further advisories fixed in 3.1.4, 3.1.5, 3.1.6, 3.1.9 |
| MarkupSafe | 1.1.1 | 3.0.4 | none (upgraded for Jinja2 3.x compatibility) |
| itsdangerous | 1.1.0 | 2.2.0 | none (required by Flask 3.x) |
| click | 7.1.2 | 8.5.1 | none (required by Flask 3.x) |
| blinker | — | 1.9.0 | none (new transitive dependency of Flask 3.x, pinned explicitly) |

After the update, `pip-audit -r requirements.txt` reports **No known
vulnerabilities found**.

Supply chain checks (PyPI metadata, 2026-11-16): all new versions are from the
official Pallets projects, versions are pinned exactly (`==`), and none was
published in the last 7 days (the newest, click 8.5.1, was published
2026-11-06). `blinker` is the only newly added package; it is the official
Pallets signal library (1.9.0, published 2024-11-08). No typosquatted names.
All packages are pure-Python wheels with no install scripts. The pins are not
hash-locked; consider `pip-compile --generate-hashes`.

## 2. Hardcoded secrets (A02 / A07)

**[P0] Hardcoded Flask secret key** (`flask_webgoat/__init__.py:22`). The
session-signing key was a literal string in source. Anyone with repository
access can forge a session cookie with `user_info = [1, "admin", 0]` and act as
the admin. **Fix:** the key is read from `FLASK_SECRET_KEY`; if unset, a random
32-byte key is generated per process. **Action required:** the old key remains
in git history and must be treated as compromised. Never reuse it.

**[P0] Hardcoded admin credential** (`flask_webgoat/__init__.py:33-35`). The
admin account was created with a fixed plaintext password. **Fix:** the
password comes from `WEBGOAT_ADMIN_PASSWORD`, or is an unguessable random value
if unset, and is stored as a salted hash.

CI secrets were also checked: `main.yml` uses `secrets.FACTORY_API_KEY` and
`secrets.GITHUB_TOKEN`, and `azure-pipelines.yml` uses a variable group. No
other keys, tokens, or credentials were found in the repository.

## 3. Authentication and authorization (A01 / A07)

**[P0] Login SQL injection → authentication bypass** (`auth.py` `/login`).
Username and password were interpolated into the SQL string with `%`. Posting
`password=' OR '1'='1` logged in as admin with no credentials. **Fix:** the
query is parameterized, looks up by username only, and verifies the password
with `werkzeug.security.check_password_hash`.

**[P1] Plaintext password storage.** Passwords were stored and compared in
cleartext. **Fix:** `generate_password_hash` on insert (admin seed and
`/create_user`), `check_password_hash` on login.

**[P1] Unauthenticated process listing** (`actions.py` `/grep_processes`). The
endpoint had no session check (see also finding 4). **Fix:** it now returns
401 without a logged-in session.

**[P2] No CSRF tokens.** `/message`, `/create_user`, and `/login` change state
with POST and no CSRF token. **Mitigation applied:** the session cookie is now
`SameSite=Lax` and `HttpOnly` (and `Secure` when `SESSION_COOKIE_SECURE=1`),
which stops cross-site POSTs from carrying the session in modern browsers.
**Recommendation:** add Flask-WTF `CSRFProtect` for full coverage.

**[P2] Credentials in the URL** (`/login_and_redirect`). Username and password
are GET query parameters, so they end up in server logs, browser history, and
`Referer` headers. Left unchanged to keep the existing API; **recommendation:**
switch the route to POST.

**[P2] No login rate limiting.** Brute force is unthrottled.
**Recommendation:** add Flask-Limiter (for example 5/minute per IP on
`/login` and `/login_and_redirect`).

Also hardened: `session.clear()` before setting `user_info` on login, to
prevent session fixation carry-over.

## 4. Injection (A03)

**[P0] OS command injection / RCE** (`actions.py` `/grep_processes`). The
`name` parameter was concatenated into a `shell=True` command, so
`?name=x; id` ran arbitrary commands. **Fix:** `subprocess.run(["ps", "aux"])`
with no shell, and matching is done in Python.

**[P0] Insecure deserialization / RCE** (`actions.py` `/deserialized_descr`).
`pickle.loads` on user-supplied data executes arbitrary code via
`__reduce__`. **Fix:** the payload is decoded as base64 JSON with `json.loads`;
malformed input returns 400. The form field name `pickled` is kept for API
compatibility.

**[P1] SQL injection in `/create_user`** (`users.py`). Username and password
were `%`-formatted into an `INSERT`. **Fix:** parameterized query; a
non-integer `access_level` now returns 400 instead of a 500.

**[P1] Path traversal / arbitrary file write** (`actions.py` `/message`).
`filename=../../../somewhere/file` wrote outside `data/<user_id>/`. **Fix:**
filenames must match `[A-Za-z0-9_-]{1,64}`, and the resolved path must sit
directly in the user's directory. The directory is now created with
`parents=True` (it previously failed when `data/` did not exist).

**XSS:** none found (see summary). `ui.py` `/search` already used a
parameterized `LIKE` query.

## 5. Other findings

**[P2] Open redirect** (`auth.py` `/login_and_redirect`). On a failed login the
user was redirected to any `url`, enabling phishing via a trusted domain.
**Fix:** only same-site relative paths are allowed (`//host`, `/\host`,
`https:`, `javascript:` are rejected); otherwise the redirect goes to `/`.

**[P2] SQL trace logging** (`__init__.py:13`). `conn.set_trace_callback(print)`
printed every SQL statement, including passwords, to stdout. **Fix:** removed.

**[P3] Permissive headers** (`run.py`). `Access-Control-Allow-Origin: *` and
`script-src 'self' 'unsafe-inline'` were set on every response. **Fix:** CORS
header removed; CSP is now `default-src 'self'; object-src 'none';
frame-ancestors 'none'`, plus `X-Content-Type-Options: nosniff`.

**[P3] Error handling** (`users.py`, `ui.py`). `"..." + err` concatenated a
`sqlite3.Error` to a string (a `TypeError` crash) and would have echoed DB
error details. **Fix:** generic error messages.

**[P3] CI supply chain** (recommendations, not changed):
- `.github/workflows/main.yml` installs the Droid CLI with `curl … | sh` and
  does not declare `permissions:`; add explicit least-privilege
  `permissions` (`contents: write`, `issues: write`, `pull-requests: write`).
- `azure-pipelines.yml` downloads `sl-latest-windows-x64.zip` and an LCOW
  release zip and runs them without checksum verification; pin versions and
  verify SHA-256 hashes.

## Validation

- `pip-audit` before: 37 vulnerabilities in 3 packages. After: none.
- New test suite `tests/test_security.py` (21 tests): SQL injection on login
  and user creation, command injection, pickle RCE, path traversal, open
  redirect, XSS escaping, hashed password storage, removal of the default
  credential, random secret key, cookie flags, and response headers.
  - Against the fixed code: **21 passed**.
  - Against the original code (with the new dependencies): **19 failed**,
    confirming the tests detect each vulnerability. The 2 that passed cover
    behavior that was already safe: XSS escaping in `/search` and allowing a
    legitimate relative redirect.
- Smoke test with `FLASK_APP=run.py flask run`: `/status` returns 200 with the
  new headers; the `' OR '1'='1` login returns 400.

## Behavior changes to note

- Set `FLASK_SECRET_KEY` and `WEBGOAT_ADMIN_PASSWORD` before running (see
  README). The old admin password no longer works.
- `/grep_processes` requires a logged-in session.
- `/deserialized_descr` accepts base64-encoded JSON, not pickle.
- `/message` rejects filenames with characters other than letters, digits,
  `_`, and `-`.
- This repository was a deliberately vulnerable training app. The original
  vulnerable code remains in git history if it is needed for training.
