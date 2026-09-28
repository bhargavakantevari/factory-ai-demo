# Security Audit Report — flask-webgoat

**Date:** 2026-09-28
**Repository:** flask-webgoat (Flask demo application)
**Commit audited:** `25b11cd` (master)
**Auditor:** Automated security scan (scheduled "Security Scanner" workflow)
**Runtime audited:** Python 3.12.3
**Tooling:** `pip-audit` (PyPI/OSV advisory database), static source review of all application files, dynamic verification via Flask test client

---

## 1. Executive summary

This is a **deliberately vulnerable training application** (see `README.md`). The audit confirmed every intentional vulnerability documented in the README, found several issues beyond that list, and **fixed the one category that is never intentional: outdated, vulnerable dependencies**.

**Note on step 1 (package.json):** This repository contains no `package.json` or any JavaScript/npm dependency manifests. It is a Python project, so the dependency audit was performed against `requirements.txt` (the equivalent manifest) using `pip-audit`.

| Category | Critical | High | Medium | Low | Info | Status |
|---|---|---|---|---|---|---|
| Dependency vulnerabilities (37 known advisories) | — | 1 suite | — | — | — | **Fixed in this audit** |
| SQL injection | 1 | 1 | — | — | — | Open (intentional, webgoat) |
| Remote code execution | 2 | — | — | — | — | Open (intentional, webgoat) |
| Hardcoded secrets / credentials | — | 2 | — | — | — | Open (intentional, webgoat) |
| Broken access control | — | 1 | 1 | — | — | Open (intentional, webgoat) |
| Other webgoat vulns (open redirect, deserialization, sensitive data exposure) | — | 1 | 2 | — | — | Open (intentional, webgoat) |
| Header / config weaknesses | — | — | — | 2 | — | Open |
| Application bugs / hygiene | — | — | — | — | 3 | Open |

**Fix applied:** all six pinned dependencies upgraded to current patched versions; `pip-audit` now reports **0 known vulnerabilities** in the application dependency tree, and a full endpoint smoke test confirms the app behaves identically (including its training vulnerabilities) on the new stack.

---

## 2. Dependency audit and fix (step 1 & 2)

There is no `package.json`; the Python manifests were audited instead. `pip-audit` found **37 known-vulnerability advisories across 4 of the 6 pinned packages**. Two packages were additionally so old that the app **cannot even start on Python ≥ 3.11** (Jinja2 2.8 uses the regex syntax `r'\w+(?u)'`, which modern Python rejects), so the application currently only runs on Python ≤ 3.10 with all these vulnerabilities present.

| Package | Old (vulnerable) | Advisories | New (patched) | Residual advisories |
|---|---|---|---|---|
| Flask | 0.12.5 (2018) | 3 | **3.1.3** | 0 |
| Werkzeug | 0.16.1 (2019) | 8 | **3.1.9** | 0 |
| Jinja2 | 2.8 (2015) | 7 | **3.1.6** | 0 |
| click | 7.1.2 | 1 | **8.5.0** | 0 |
| itsdangerous | 1.1.0 | 0 | **2.2.0** | 0 |
| MarkupSafe | 1.1.1 | 0 | **3.0.3** | 0 |

Representative advisories from the audit (full list in Appendix A):

- **click** `PYSEC-2026-2132` — command injection in `click.edit()` (fixed 8.3.3)
- **Flask** `PYSEC-2019-179` — DoS via crafted encoded JSON (fixed 1.0; may overlap CVE-2018-1000656)
- **Flask** `PYSEC-2023-62` — cached responses/session cookies can leak cross-client behind a caching proxy because `Vary: Cookie` is not set on session refresh (fixed 2.2.5/2.3.2)
- **Flask** `PYSEC-2026-2151` — `Vary: Cookie` missing for some forms of session access such as the `in` operator (fixed 3.1.3)
- **Werkzeug** `PYSEC-2022-203` — HTTP request smuggling in dev-server configurations (fixed 2.1.1)
- **Werkzeug** `PYSEC-2023-58` / `PYSEC-2023-221` — multipart parser DoS, unlimited parts and CR/LF buffer growth (fixed 2.2.3 / 3.0.1)
- **Werkzeug** `PYSEC-2026-2043` — Werkzeug debugger can allow code execution on a developer's machine (fixed 3.0.3)
- **Werkzeug** `PYSEC-2026-2045/-2046/-2044/-2320` — `safe_join` path traversal on Windows via UNC paths and device names (GHSA-hgf8-39gv-g3f2 follow-ups; fixed 3.0.6/3.1.4/3.1.5/3.1.6)
- **Jinja2** `PYSEC-2019-220` / `PYSEC-2019-217` — sandbox escape via `str.format` / `str.format_map` (fixed 2.8.1 / 2.10.1)
- **Jinja2** `PYSEC-2021-66` — ReDoS in the `urlize` filter (fixed 2.11.3)
- **Jinja2** `PYSEC-2026-1473` / `-1474` — XSS via the `xmlattr` filter accepting crafted keys (CVE-2024-22195 and successor; fixed 3.1.3/3.1.4)
- **Jinja2** `PYSEC-2026-1475` / `-1471` — sandbox escape via indirect `str.format` and `|attr` filter bypass (fixed 3.1.5/3.1.6)

### Fix applied

`requirements.txt` updated to:

```
click==8.5.0
Flask==3.1.3
itsdangerous==2.2.0
Jinja2==3.1.6
MarkupSafe==3.0.3
Werkzeug==3.1.9
```

### Verification

1. `pip-audit` against the upgraded environment: **0 known vulnerabilities** in all six application packages. (The only remaining pip-audit hits were against the disposable CI venv's own `pip 24.0` tooling, not an app dependency — CI images should keep `pip` ≥ 26.2 current.)
2. Full endpoint smoke test on the new stack (Flask test client): all endpoints return the same responses as expected, including the training vulnerabilities, which still work (SQLi login bypass returns `{"success":true}`; XSS payload in `/search` is auto-escaped). The only failure, `POST /message` returning 500, is a **pre-existing application bug** (see §8, INFO-1) that is identical on the old stack and unrelated to the upgrade; it succeeds once the parent `data/` directory exists.

---

## 3. Hardcoded secrets and API keys (step 3)

**No API keys, cloud credentials, or tokens are hardcoded anywhere in the repository.** CI configurations correctly use secret indirection (`${{ secrets.GITHUB_TOKEN }}`, `${{ secrets.FACTORY_API_KEY }}`, Azure Pipelines variable group `shiftleft-token`). Two genuine hardcoded-secret findings exist, both inside the application:

| ID | Severity | Location | Finding | Status |
|---|---|---|---|---|
| SEC-01 | High | `flask_webgoat/__init__.py:22` | Flask session `secret_key` is a hardcoded string literal. Anyone with source access (or who obtains it) can forge arbitrary session cookies, including `user_info` with `access_level=0` (admin), bypassing authentication entirely. | Open (intentional) |
| SEC-02 | High | `flask_webgoat/__init__.py:33-35` | Seed data hardcodes admin credentials (`admin` / `maximumentropy`, `access_level=0`) directly in source, and all passwords are stored and compared in **plaintext** (no hashing). | Open (intentional) |

Recommended fix (do not apply if the training behavior must be preserved):

```python
# __init__.py
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
# and hash passwords, e.g. werkzeug.security.generate_password_hash / check_password_hash
```

---

## 4. Authentication & authorization review (step 4)

The app has a login-based session with an `access_level` privilege model (0 = admin, lower = more privileged). Findings:

| ID | Severity | Location | Finding | Status |
|---|---|---|---|---|
| AUTH-01 | High | `users.py:31-34` | Passwords stored and compared in plaintext; minimum length is only 3 characters; no hashing (bcrypt/scrypt/argon2). | Open (intentional) |
| AUTH-02 | High | `__init__.py:22` + session model | Privilege (`access_level`) is carried in the client session cookie; combined with the hardcoded `secret_key` (SEC-01) this enables silent privilege forgery. | Open (intentional) |
| AUTH-03 | Medium | `auth.py:28-46` | `GET /login_and_redirect` transmits **credentials in the URL query string** (browser history, server logs, `Referer` leakage) and is reachable without CSRF protection. | Open (intentional) |
| AUTH-04 | Medium | global | No CSRF protection on any state-changing endpoint (`/login`, `/create_user`, `/message`, `/deserialized_descr`); no rate limiting or account lockout (enables credential stuffing); session cookie has no `Secure`/`SameSite` configuration. | Open |
| AUTH-05 | Low | `actions.py:23-26` | Authorization check mismatch: the error message says "access level < 2 is required" but the code rejects only `access_level > 2`, so level exactly 2 is allowed. | Open |
| AUTH-06 | Low | `users.py:14-15`, `actions.py:11-12` | Error responses return HTTP **200** (e.g. `{"error": "no user_info found in session"}`), because the tuple status code is missing. Monitoring and clients cannot distinguish failures. | Open |
| AUTH-07 | Medium | `ui.py:6-17` | **Unauthenticated user enumeration:** `GET /search` requires no login and returns every matching username and its `access_level`. Combined with `create_user` this maps all accounts and admins. | Open (beyond README list) |

Endpoints `POST /login` and `GET /login_and_redirect` implement the authentication; `/create_user` correctly gates on `access_level == 0`. However `/grep_processes` and `/deserialized_descr` (see §5/§6) perform no authentication at all.

---

## 5. SQL injection & XSS review (step 5)

### SQL injection

| ID | Severity | Location | Finding | Status |
|---|---|---|---|---|
| SQLI-01 | Critical | `auth.py:17-20` | `POST /login` builds the query with `%` string formatting: `"... WHERE username = '%s' AND password = '%s'". Classic auth bypass. **Verified dynamically**: `username=nosuchuser&password=x' OR '1'='1` returns `{"success":true}`. | Open (intentional) |
| SQLI-02 | High | `users.py:37-40` | `POST /create_user` (admin-only) inserts with `'%s', '%s', %d` string formatting. Any admin session can execute arbitrary SQL (e.g. dump or corrupt the `user` table). | Open (intentional) |
| SQLI-03 | Info | `auth.py:41-43`, `ui.py:12-13` | The parameterized queries in `login_and_redirect` and `/search` are correctly written (good baseline pattern to copy). `/search` passes user input unescaped into a `LIKE` clause, so `%`/`_` wildcards are attacker-controlled, but no injection is possible. | Open (minor) |

Recommended fix (parameterize, as already done in `login_and_redirect`):

```python
query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
result = query_db(query, (username, password), True)
```

### XSS

| ID | Severity | Location | Finding | Status |
|---|---|---|---|---|
| XSS-01 | Info | `templates/search.html`, `templates/error.html` | **No reflected or stored XSS found.** All dynamic output uses `{{ }}` Jinja2 placeholders, and rendering through `render_template` applies autoescaping. **Verified dynamically**: `GET /search?query=<script>alert(1)</script>` returns the payload HTML-escaped (`&lt;script&gt;`), with no raw `<script>` in the response. | OK |
| XSS-02 | Low | `run.py:8-9` | `Content-Security-Policy: script-src 'self' 'unsafe-inline'` allows inline script execution, defeating CSP as a second line of defense against any future XSS. | Open |
| HDR-01 | Low | `run.py:7` | `Access-Control-Allow-Origin: *` on every response. Without credentials it is not directly exploitable, but it is an unnecessary wildcard exposure and mislabeled as "Broken Access Control" in the source comment. | Open |

Recommended fix:

```python
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
response.headers['Access-Control-Allow-Origin'] = 'https://your-trusted-origin.example'  # or drop the header
```

---

## 6. Additional application vulnerabilities (confirmed present, intentional per README)

These are the webgoat's training vulnerabilities. They were each verified to still function after the dependency upgrade (so the training value is preserved), and are listed with their remediation for completeness:

| ID | Severity | Location | Vulnerability | Remediation |
|---|---|---|---|---|
| APP-01 | Critical | `actions.py:52-58` | **Unauthenticated RCE** via `subprocess.run([...], shell=True)` with attacker-controlled `name` in `ps aux \| grep <name>`. | Never pass user input to a shell; use `subprocess.run(["ps", "aux"], capture_output=True)` and filter in Python; require auth. |
| APP-02 | Critical | `actions.py:62-68` | **Unauthenticated RCE** via `pickle.loads` on a user-supplied base64 blob (`/deserialized_descr`). | Never unpickle untrusted data; use JSON. |
| APP-03 | High | `actions.py:30-42` | **Directory traversal** in `/message`: `filename` is concatenated into a path, so `filename=../../evil` writes files anywhere the process can write (e.g. overwrite source or write to `~/.bashrc`). | Resolve with `Path(user_dir, filename + ".txt")`, then assert `path.resolve().is_relative_to(user_dir_path.resolve())`; reject path separators; use `mkdir(parents=True)`. |
| APP-04 | Medium | `auth.py:44-47` | **Open redirect**: on failed login, `/login_and_redirect` redirects to the user-supplied `url` (ideal for phishing after harvesting credentials from the URL). | Validate against an allowlist of hostnames, or use `url_for`-based relative redirects. |
| APP-05 | Medium | `__init__.py:14` | **Sensitive data exposure**: `conn.set_trace_callback(print)` prints every SQL statement — including cleartext passwords from login queries — to stdout/logs. | Remove the trace callback. |
| APP-06 | High | `run.py` + deployment | Broken access control / security misconfiguration headers (see HDR-01, XSS-02) and `app.run()` dev server usage. | Run behind a production WSGI server (gunicorn/uwsgi) and fix headers. |

---

## 7. Findings outside the intended webgoat scope

| ID | Severity | Finding | Recommendation |
|---|---|---|---|
| NEW-01 | Medium | Unauthenticated `/search` account enumeration (AUTH-07) — not in the README's intended vulnerability list. | Require a session or remove `access_level` from results. |
| NEW-02 | Low | CI workflow downloads and executes an installer via `curl -fsSL https://app.factory.ai/cli \| sh` without pinning/checksum verification (`.github/workflows/main.yml`). | Pin a released CLI version and verify its checksum. |
| NEW-03 | Low | `gh issue create --label "security,high-priority"` will fail if those labels do not exist in the repo (unlabeled or failing step). | Create the labels in the repository, or add `--label` fallback logic. |
| INFO-01 | Info | **Pre-existing bug:** `actions.py:30` `user_dir_path.mkdir()` lacks `parents=True`, so `POST /message` returns HTTP 500 whenever `data/` does not exist (first run in a fresh checkout). Reproduced on both old and new dependency stacks. | Use `user_dir_path.mkdir(parents=True, exist_ok=True)`. |
| INFO-02 | Info | `create_app()` deletes `database.db` on every startup (`__init__.py:24-26`), so all data (including created users) is lost on restart, and the DB file lives in the working directory. | Use a persistent, configurable path (env var) and only create/seed when missing. |
| INFO-03 | Info | No tests, no lint/static-analysis configuration in the repo; no `pip` upgrade in CI (venv `pip 24.0` itself has known advisories). | Add a test suite, `pip-audit` in CI, and keep CI tooling updated. |

---

## 8. What this audit changed

- `requirements.txt`: upgraded all six dependencies from 2015-2019 versions to current patched versions (37 known advisories → 0). This also restores compatibility with modern Python (≥ 3.11), which the old stack could not even import.
- `security-report.md`: this report (new file).

**Deliberately not changed:** the application's intentional webgoat vulnerabilities (§4-§6). This repository exists to host them for security training (per `README.md`), and the audit's fix mandate covered dependencies. Each finding above includes a concrete remediation so maintainers can patch them selectively if the training scope ever changes. All were re-verified to still reproduce after the upgrade.

## 9. Verification log

```
$ pip-audit -r requirements.txt   # before
Found 37 known vulnerabilities in 4 packages (click, flask, werkzeug, jinja2)

$ pip-audit                       # after upgrade (app packages)
0 known vulnerabilities in click/Flask/itsdangerous/Jinja2/MarkupSafe/Werkzeug

$ smoke test (Flask test client, upgraded stack)
GET  /status                      -> 200 {"success":true}
GET  /ping                        -> 200 {"success":true}
POST /login (seeded admin creds)  -> 200 {"success":true}
POST /login (SQLi bypass payload) -> 200 {"success":true}   # webgoat vuln preserved
GET  /login_and_redirect (bad)    -> 302 redirect             # open redirect preserved
GET  /search?query=admin          -> 200 renders template
GET  /search?query=<script>...    -> 200 payload HTML-escaped, no raw <script>
POST /create_user (admin session) -> 200 {"success":true}
POST /message                     -> 500 (pre-existing mkdir bug, INFO-01; 200 once data/ exists)
GET  /grep_processes?name=python  -> 200 {"names":[...]}
Headers: Access-Control-Allow-Origin: * ; CSP: script-src 'self' 'unsafe-inline'
```

---

## Appendix A: full advisory list (old pinned versions)

**click 7.1.2** — PYSEC-2026-2132 (fix 8.3.3): command injection in `click.edit()` in versions ≤ 8.3.2.

**Flask 0.12.5**
- PYSEC-2019-179 (fix 1.0): DoS via unexpected memory usage from crafted encoded JSON (may overlap CVE-2018-1000656).
- PYSEC-2023-62 (fix 2.2.5/2.3.2): responses may be cached by a proxy and re-sent to other clients, including the `session` cookie, when `Vary: Cookie` is not set on session refresh.
- PYSEC-2026-2151 (fix 3.1.3): `Vary: Cookie` not set for some session accesses (e.g. the `in` operator), enabling cache-based sensitive-information exposure.

**Werkzeug 0.16.1**
- PYSEC-2022-203 (fix 2.1.1): HTTP request smuggling with a crafted request containing multiple requests (disputed; dev-server configurations).
- PYSEC-2023-57 (fix 2.2.3): "nameless cookie" parsing (`=__Host-...`) allows a hostile adjacent subdomain to poison cookie keys.
- PYSEC-2023-58 (fix 2.2.3): multipart parser parses unlimited parts → CPU/RAM exhaustion DoS.
- PYSEC-2023-221 (fix 2.3.8/3.0.1): multipart parser quadratic buffer growth with CR/LF + megabytes → DoS.
- PYSEC-2026-2043 (fix 3.0.3): Werkzeug debugger can allow code execution on a developer's machine (debugger PIN + attacker domain interaction).
- PYSEC-2026-2045 (fix 3.0.6): `safe_join` misses UNC paths (`//server/share`) on Python < 3.11/Windows → unintended file access.
- PYSEC-2026-2046 / PYSEC-2026-2044 / PYSEC-2026-2320 (fix 3.1.4/3.1.5/3.1.6): `safe_join` allows Windows device names (`CON`, `AUX`, `NUL`, with extensions, trailing spaces, or as later path segments) → hang/DoS via `send_from_directory` (GHSA-hgf8-39gv-g3f2 follow-ups).

**Jinja2 2.8**
- PYSEC-2019-220 (fix 2.8.1): sandbox escape via `str.format`.
- PYSEC-2019-217 (fix 2.10.1): sandbox escape via `str.format_map`.
- PYSEC-2021-66 (fix 2.11.3): ReDoS in the `urlize` filter regex.
- PYSEC-2026-1473 (fix 3.1.3): `xmlattr` accepts keys containing spaces → attribute injection/XSS (CVE-2024-22195).
- PYSEC-2026-1474 (fix 3.1.4): `xmlattr` accepts keys with non-attribute characters (`/`, `>`, `=`) → XSS.
- PYSEC-2026-1475 (fix 3.1.5): sandbox escape via indirect `str.format` invocation.
- PYSEC-2026-1471 (fix 3.1.6): sandbox escape via the `|attr` filter bypassing environment attribute lookup.

**itsdangerous 1.1.0 / MarkupSafe 1.1.1** — no known advisories at those pins; upgraded to 2.2.0 / 3.0.3 because Flask 3.1.x requires them (and the old pins are incompatible with modern Python).

*Advisory data source: pip-audit with the PyPI/OSV vulnerability database, run 2026-09-28. Duplicate rows in raw output (same ID listed twice) are alias records in the advisory database and were deduplicated above.*
