# Security Audit Report

**Date:** 2026-10-19
**Scope:** Full-project audit of `flask-webgoat` (branch `master`, commit `25b11cd`)
**Method:** STRIDE + OWASP Top 10 (2021) analysis, supply-chain scan with `pip-audit` 2.10.1, manual secret scan, smoke test.

> **Context note:** This repository is a deliberately-vulnerable training application
> (per `README.md`). The application code was therefore **not** modified — the
> intentional code-level vulnerabilities are documented below with recommended fixes.
> Dependencies **were** updated, since outdated packages are not part of the intended
> training surface.

## Summary

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | 37 known CVEs in pinned dependencies (Flask, Werkzeug, Jinja2) | CRITICAL | **Fixed** (requirements.txt updated) |
| 2 | Hardcoded Flask `secret_key` | HIGH | Documented (intentional) |
| 3 | Hardcoded admin credentials in source | HIGH | Documented (intentional) |
| 4 | SQL injection in `/login` (`auth.py`) | CRITICAL | Documented (intentional) |
| 5 | SQL injection in `/create_user` (`users.py`) | HIGH | Documented (intentional) |
| 6 | Remote code execution in `/grep_processes` (`actions.py`) | CRITICAL | Documented (intentional) |
| 7 | Insecure deserialization (`pickle.loads`) in `/deserialized_descr` | CRITICAL | Documented (intentional) |
| 8 | Directory traversal in `/message` (`actions.py`) | HIGH | Documented (intentional) |
| 9 | Open redirect in `/login_and_redirect` (`auth.py`) | MEDIUM | Documented (intentional) |
| 10 | SQL queries (incl. credentials) printed to logs | HIGH | Documented (intentional) |
| 11 | Overly permissive CORS and weak CSP (`run.py`) | MEDIUM | Documented (intentional) |
| 12 | Plaintext password storage, no hashing | HIGH | Documented (intentional) |
| 13 | No rate limiting / CSRF protection on auth endpoints | MEDIUM | Documented (intentional) |
| 14 | XSS exposure: templates use autoescaping (OK); CSP `'unsafe-inline'` weakens it | LOW | Documented |

---

## 1. Dependency Vulnerabilities (Supply Chain)

**Note:** There is no `package.json` in this repository — it is a Python/Flask project,
so `requirements.txt` was audited instead (this is the correct artifact for step 1 of
the requested checklist).

### Before (37 known vulnerabilities, per pip-audit / OSV)

| Package | Pinned | Vulnerabilities | Examples |
|---------|--------|-----------------|----------|
| Flask | 0.12.5 (2017) | 3 advisories | PYSEC-2019-179, PYSEC-2023-62, PYSEC-2026-2151 |
| Werkzeug | 0.16.1 (2020) | 9 advisories | PYSEC-2022-203, PYSEC-2023-57/58/221, PYSEC-2026-2043..2320, PYSEC-2026-4312 |
| Jinja2 | 2.8 (2016) | 7 advisories | PYSEC-2019-217/220, PYSEC-2021-66, PYSEC-2026-1471..1475 |
| click, itsdangerous, MarkupSafe | 7.1.2 / 1.1.0 / 1.1.1 | none flagged, but incompatible with fixed versions | — |

### Fix applied — `requirements.txt` updated

| Package | Old | New (latest stable, verified on PyPI) |
|---------|-----|----------------------------------------|
| Flask | 0.12.5 | **3.1.3** |
| Werkzeug | 0.16.1 | **3.1.9** |
| Jinja2 | 2.8 | **3.1.6** |
| click | 7.1.2 | **8.5.0** |
| itsdangerous | 1.1.0 | **2.2.0** |
| MarkupSafe | 1.1.1 | **3.0.4** |
| blinker | — (new transitive dep of Flask 3.1) | **1.9.0** |

**Verification:**
- `pip-audit` on the updated file: **No known vulnerabilities found** (0 advisories).
- Smoke test on the upgraded stack passed: `GET /status`, `POST /login`, and
  `GET /search?query=admin` all returned HTTP 200 on Python 3.12.
- All dependencies are pinned to exact versions (no `*` or `>=` ranges).

---

## 2. Hardcoded Secrets / API Keys

- **[P1] Hardcoded Flask session key** — `flask_webgoat/__init__.py:22`.
  `app.secret_key` is a static string committed to source control. Because Flask
  sessions are only signed (not encrypted) with this key, anyone with repo access can
  **forge session cookies**, including `user_info` with `access_level = 0`, bypassing
  the authorization checks in `users.py` and `actions.py`.
  *Fix:* load from an environment variable / secrets manager:
  `app.secret_key = os.environ["FLASK_SECRET_KEY"]` and generate it with `secrets.token_hex(32)`.

- **[P1] Hardcoded admin credentials** — `flask_webgoat/__init__.py:33`. The admin
  password is seeded in plaintext in source on every startup.
  *Fix:* seed from environment or a one-time setup step; store only a password hash.

- No AWS keys, GitHub tokens, Slack tokens, JWTs, or private key material were found.
  CI pipelines (`azure-pipelines.yml`, `.github/workflows/main.yml`) correctly
  reference secrets via variable groups / `${{ secrets.* }}` rather than literals.

---

## 3. Authentication & Authorization Review

- **[P1] Plaintext password storage and comparison** — passwords are stored and
  compared in cleartext (`auth.py:19`, `users.py:39`). A database leak compromises
  all accounts. *Fix:* hash with `werkzeug.security.generate_password_hash` /
  `check_password_hash` (or bcrypt/argon2).
- **[P2] Client-side trust of `access_level`** — authorization decisions read
  `access_level` from the Flask session cookie (`users.py:16`, `actions.py:14`),
  which is forgeable given finding #2 (hardcoded secret key).
- **[P2] Credentials in URL query string** — `/login_and_redirect` (`auth.py:30`)
  accepts `username`/`password` as GET parameters, exposing them in browser history,
  server access logs, and proxy logs. *Fix:* POST body only.
- **[P2] No rate limiting or lockout** on `/login` — enables credential stuffing and
  brute force. *Fix:* add Flask-Limiter or equivalent.
- **[P2] No CSRF protection** on state-changing POST endpoints (`/login`,
  `/create_user`, `/message`, `/deserialized_descr`). *Fix:* Flask-WTF CSRF tokens.
- **[P3] No audit logging** of authentication successes/failures or admin actions
  (OWASP A09).

---

## 4. Injection Vulnerabilities (SQLi / XSS / Command)

### SQL Injection

- **[P0] `/login`** — `auth.py:19`: username/password are interpolated into SQL via
  `%` formatting. Classic auth bypass: `username=' OR '1'='1' --`.
  *Fix:* parameterized query (the pattern already used correctly in
  `login_and_redirect` at `auth.py:42`).
- **[P1] `/create_user`** — `users.py:39`: `username` and `password` interpolated into
  an INSERT. Reachable only at access level 0, but the session is forgeable (see #2).
  *Fix:* parameterized query.
- `/search` (`ui.py:16`) already uses a parameterized query — no issue.

### XSS

- Templates (`search.html`, `error.html`) render user-controlled values through
  Jinja2's `{{ }}` with autoescaping — no direct XSS sink found.
- **[P2] However**, `run.py:9` sets `Content-Security-Policy: script-src 'self' 'unsafe-inline'`,
  which would allow inline script execution if any injection point is introduced.
  *Fix:* remove `'unsafe-inline'`.

### Command Injection / RCE

- **[P0] `/grep_processes`** — `actions.py:45`: the `name` query parameter is
  concatenated into a shell command (`shell=True`). Unauthenticated arbitrary command
  execution, e.g. `?name=x;id`. *Fix:* avoid the shell (`subprocess.run(["ps","aux"])`
  then filter in Python) and validate input against an allow-list.
- **[P0] `/deserialized_descr`** — `actions.py:60`: `pickle.loads()` on
  attacker-controlled base64 input = arbitrary code execution.
  *Fix:* never unpickle untrusted data; use JSON or a signed/verified format.

---

## 5. Other Findings

- **[P1] Directory traversal** — `actions.py:35`: `filename` is concatenated into a
  file path; `../../etc/...` escapes the user's data directory, allowing arbitrary
  file write. *Fix:* validate with a strict allow-list (e.g. `^[A-Za-z0-9_-]+$`) and
  resolve + verify the path stays under the user directory.
- **[P2] Open redirect** — `auth.py:45`: on failed login the user is redirected to an
  arbitrary `url` parameter, enabling phishing. *Fix:* allow-list relative paths only.
- **[P1] Sensitive data exposure in logs** — `__init__.py:13`:
  `conn.set_trace_callback(print)` prints every SQL statement, **including plaintext
  credentials**, to stdout/logs (confirmed live during the smoke test). *Fix:* remove
  the trace callback in production.
- **[P2] Overly permissive CORS** — `run.py:7`: `Access-Control-Allow-Origin: *`
  on every response. *Fix:* restrict to trusted origins.
- **[P3] Verbose error reflection** — `ui.py:22` and `users.py:46` echo internal
  error details and query parameters back to the client.

---

## Files Reviewed (full coverage)

- `run.py`, `README.md`, `requirements.txt`
- `flask_webgoat/__init__.py`, `auth.py`, `users.py`, `actions.py`, `ui.py`, `status.py`
- `flask_webgoat/templates/base.html`, `search.html`, `error.html`
- `azure-pipelines.yml`, `.github/workflows/main.yml`

No LLM/AI integrations exist in this codebase, so the OWASP LLM Top 10 checks are not
applicable. No `.factory/threat-model.md` exists.
