# Security Audit Report: flask-webgoat

## Summary

| Area | Findings | Status |
| --- | --- | --- |
| Dependencies (`requirements.txt`) | 20 unique known vulnerabilities (CVEs) in Flask, Jinja2 and Werkzeug | Fixed: all pins upgraded, `pip-audit` now reports none |
| Hardcoded secrets | Flask `secret_key` and admin password committed in source | Fixed in code; **the old values must be treated as leaked** |
| Authentication / authorization | Plaintext passwords, session fixation, weak password policy, wrong status codes | Fixed |
| Injection | 2 SQL injections, OS command injection (RCE), insecure deserialization (RCE), directory traversal | Fixed |
| XSS / browser security | Permissive CORS, CSP allows inline script, open redirect | Fixed |
| CI/CD | Unpinned `curl \| sh`, no `permissions:` block in GitHub workflow | Recommendation only (not changed) |

There is no `package.json` in this repository. It is a Python/Flask project, so
the dependency audit was run on `requirements.txt`, its Python equivalent.

## 1. Dependency vulnerabilities

Scanned with `pip-audit -r requirements.txt` (PyPI advisory database).

### Before

| Package | Version | Advisory | CVE | Fixed in | Issue |
| --- | --- | --- | --- | --- | --- |
| Flask | 0.12.5 | PYSEC-2019-179 | CVE-2019-1010083 | 1.0 | DoS via crafted encoded JSON |
| Flask | 0.12.5 | PYSEC-2023-62 | CVE-2023-30861 | 2.2.5 / 2.3.2 | Session cookie response cached by proxies and sent to other clients |
| Flask | 0.12.5 | PYSEC-2026-2151 | CVE-2026-27205 | 3.1.3 | Missing `Vary: Cookie` when session is accessed |
| Jinja2 | 2.8 | PYSEC-2019-220 | CVE-2016-10745 | 2.8.1 | Sandbox escape via `str.format` |
| Jinja2 | 2.8 | PYSEC-2019-217 | CVE-2019-10906 | 2.10.1 | Sandbox escape via `str.format_map` |
| Jinja2 | 2.8 | PYSEC-2021-66 | CVE-2020-28493 | 2.11.3 | ReDoS in `urlize` |
| Jinja2 | 2.8 | PYSEC-2026-1473 | CVE-2024-22195 | 3.1.3 | XSS via `xmlattr` keys with spaces |
| Jinja2 | 2.8 | PYSEC-2026-1474 | CVE-2024-34064 | 3.1.4 | XSS via `xmlattr` non-attribute characters |
| Jinja2 | 2.8 | PYSEC-2026-1475 | CVE-2024-56326 | 3.1.5 | Sandbox escape via indirect `str.format` |
| Jinja2 | 2.8 | PYSEC-2026-1471 | CVE-2025-27516 | 3.1.6 | Sandbox escape via `\|attr` filter |
| Werkzeug | 0.16.1 | PYSEC-2022-203 | CVE-2022-29361 | 2.1.1 | HTTP request smuggling (disputed) |
| Werkzeug | 0.16.1 | PYSEC-2023-57 | CVE-2023-23934 | 2.2.3 | Nameless cookie parsing |
| Werkzeug | 0.16.1 | PYSEC-2023-58 | CVE-2023-25577 | 2.2.3 | DoS via unlimited multipart parts |
| Werkzeug | 0.16.1 | PYSEC-2023-221 | CVE-2023-46136 | 2.3.8 / 3.0.1 | DoS in multipart parsing |
| Werkzeug | 0.16.1 | PYSEC-2026-2043 | CVE-2024-34069 | 3.0.3 | Debugger RCE |
| Werkzeug | 0.16.1 | PYSEC-2026-2045 | CVE-2024-49766 | 3.0.6 | `safe_join` UNC path bypass (Windows) |
| Werkzeug | 0.16.1 | PYSEC-2026-2046 | CVE-2025-66221 | 3.1.4 | `safe_join` Windows device names |
| Werkzeug | 0.16.1 | PYSEC-2026-2044 | CVE-2026-21860 | 3.1.5 | `safe_join` device names with extensions |
| Werkzeug | 0.16.1 | PYSEC-2026-2320 | CVE-2026-27199 | 3.1.6 | `safe_join` device names after segments |
| Werkzeug | 0.16.1 | PYSEC-2026-4312 | CVE-2026-102598 | 3.1.9 | `safe_join` device names with ADS marker |

click 7.1.2, itsdangerous 1.1.0 and MarkupSafe 1.1.1 had no known advisories
but are end-of-life and incompatible with the patched Flask.

### After (`requirements.txt`)

| Package | Old | New |
| --- | --- | --- |
| blinker | (not pinned) | 1.9.0 (new Flask 3 dependency) |
| click | 7.1.2 | 8.1.8 |
| Flask | 0.12.5 | 3.1.3 |
| itsdangerous | 1.1.0 | 2.2.0 |
| Jinja2 | 2.8 | 3.1.6 |
| MarkupSafe | 1.1.1 | 3.0.2 |
| Werkzeug | 0.16.1 | 3.1.9 |

Result: `pip-audit` reports `No known vulnerabilities found`, and `pip check`
reports `No broken requirements found`. Python 3.9 or newer is now required.

## 2. Hardcoded secrets

| # | Location | Finding | Severity | Fix |
| --- | --- | --- | --- | --- |
| S1 | `flask_webgoat/__init__.py` (`app.secret_key = "..."`) | Session signing key committed in source. Anyone with repo access can forge session cookies, for example `user_info = (1, "admin", 0)`, and become admin. | Critical | Key now read from `SECRET_KEY`; a random 256-bit key is generated if unset. |
| S2 | `flask_webgoat/__init__.py` (admin `INSERT`) | Admin password `maximumentropy` hardcoded and stored in plaintext. | Critical | Password read from `ADMIN_PASSWORD` and stored as a Werkzeug password hash. If unset, a random password is used, so the account is locked. |
| S3 | `flask_webgoat/__init__.py` (`conn.set_trace_callback(print)`) | Every SQL statement, including usernames and passwords, printed to stdout and logs. | High | Trace callback removed. |

No API keys, tokens or cloud credentials were found. `azure-pipelines.yml`
and `.github/workflows/main.yml` correctly reference secrets through
variable groups and `secrets.*`.

**Action required:** both old values remain in git history. Rotate any
deployment that used that secret key or admin password.

## 3. Authentication and authorization

| # | Location | Finding | Severity | Fix |
| --- | --- | --- | --- | --- |
| A1 | `auth.py` `login` | SQL injection allowed login as any user without a password (`username=admin' --`). | Critical | Parameterized query; see I1. |
| A2 | `auth.py`, `users.py` | Passwords stored and compared in plaintext. | High | `generate_password_hash` on create, `check_password_hash` on login. |
| A3 | `auth.py` | Session not reset on login (session fixation). | Medium | `session.clear()` before storing the user. |
| A4 | `__init__.py` | Session cookie lacked `SameSite`; no `Secure` option. | Medium | `HttpOnly`, `SameSite=Lax` set; `Secure` enabled with `SESSION_COOKIE_SECURE=1`. `SameSite=Lax` also blocks cross-site POSTs, which mitigates CSRF on the state-changing endpoints. |
| A5 | `users.py` | Minimum password length was 3 characters; non-numeric `access_level` caused a 500 error; negative levels accepted. | Low | Minimum length 8, input validated, 400 returned. |
| A6 | `users.py`, `actions.py` | Auth failures returned HTTP 200 (and one used 402). | Low | 401 for missing session, 403 for insufficient level, 400 for bad input. |
| A7 | `users.py` | DB error handler did `"..." + err`, which raised `TypeError` (500) and would have leaked DB errors. | Low | Generic error message. |

Role checks themselves (`access_level == 0` for user creation, `<= 2` for
`/message`) are applied server-side from the signed session and are correct
once the secret key is no longer public.

## 4. Injection, XSS and other code vulnerabilities

| # | Location | Finding | Severity | Fix |
| --- | --- | --- | --- | --- |
| I1 | `auth.py` `login` | SQL injection through `%`-formatted `username` / `password`. | Critical | `?` placeholders. |
| I2 | `users.py` `create_user` | SQL injection through `username` / `password` (stacked values, privilege escalation). | Critical | `?` placeholders. |
| I3 | `actions.py` `grep_processes` | OS command injection: `name` concatenated into a `shell=True` command (`name=x; rm -rf ~`). | Critical | Runs fixed argv `["ps", "aux"]` without a shell and filters lines in Python. Output format (11th column) is unchanged. |
| I4 | `actions.py` `deserialized_descr` | `pickle.loads` on user input gives remote code execution. | Critical | Replaced with `json.loads` on the base64 payload; invalid input returns 400. |
| I5 | `actions.py` `log_entry` | Directory traversal: `filename=../../../anything` wrote arbitrary `.txt` files. Also crashed if `data/` did not exist. | High | Filename restricted to `[A-Za-z0-9_-]{1,64}`, resolved path checked to stay in the user directory, directories created with `parents=True`. |
| I6 | `auth.py` `login_and_redirect` | Open redirect to any URL, including `javascript:` and `//evil.example`. | Medium | Only same-site relative paths starting with `/` are accepted (no scheme, host, `//`, backslash, or control characters). |
| X1 | `run.py` | `Access-Control-Allow-Origin: *` exposed all responses to any origin. | Medium | Header removed (the app has no cross-origin clients). |
| X2 | `run.py` | CSP `script-src 'self' 'unsafe-inline'` allowed inline-script XSS. | Medium | `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`, plus `X-Content-Type-Options`, `X-Frame-Options` and `Referrer-Policy`. |
| X3 | `templates/*.html`, `ui.py` | Reflected values (`query`, `message`). | None found | Jinja2 autoescaping is on for `.html` templates; verified that `<script>` in `query` is rendered escaped. The `ui.py` error handler `+ err` bug (TypeError) was fixed. |

## 5. Remaining risks and recommendations (not changed)

- `/login_and_redirect` takes credentials in the query string, so they end up
  in server logs, browser history and `Referer`. Prefer POST.
- `/search` lets unauthenticated users list all usernames and access levels
  (`query=%`). Consider requiring login.
- No rate limiting or lockout on `/login`; consider Flask-Limiter or a proxy rule.
- No CSRF tokens; `SameSite=Lax` is the current mitigation. Add Flask-WTF CSRF
  protection if browser forms are added.
- `/grep_processes` still discloses running process names to anyone; consider
  restricting it to admins.
- `.github/workflows/main.yml`: installs the droid CLI with an unpinned
  `curl | sh` and declares no `permissions:` block, so `GITHUB_TOKEN` gets the
  repository default scope. Add `permissions: {contents: write, issues: write,
  pull-requests: write}` and pin or checksum the installer. This file was not
  modified here because a `GITHUB_TOKEN` push that touches workflow files is
  rejected by GitHub.
- Run with a production WSGI server (gunicorn, waitress) behind HTTPS and set
  `SESSION_COOKIE_SECURE=1`.

## 6. Verification

- `pip-audit -r requirements.txt`: 37 findings (20 unique CVEs) before, `No known vulnerabilities found` after.
- `pip check`: `No broken requirements found`.
- New regression tests in `tests/test_security.py` (stdlib `unittest`, run with
  `python -m unittest discover -s tests -t . -v`): 14 tests, all passing. They
  cover SQL injection on both endpoints, password hashing, removal of the old
  admin password, open redirect payloads, traversal payloads, command
  injection, malicious pickle payloads, template escaping, security headers and
  cookie flags.
- Manual smoke test against `flask run`: SQLi login rejected, valid login
  works, traversal blocked, normal file write works, external redirect returns
  400, CSP header present, no CORS header, search output escaped.
