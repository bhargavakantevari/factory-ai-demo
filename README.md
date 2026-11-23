# flask-webgoat

flask-webgoat is a deliberately-vulnerable application written with the Flask
web framework.

```
                                                (_(
                                                /_/'_____/)
                                                "  |      |
                                                   |""""""|
███████╗██╗      █████╗ ███████╗██╗  ██╗    ██╗    ██╗███████╗██████╗  ██████╗  ██████╗  █████╗ ████████╗
██╔════╝██║     ██╔══██╗██╔════╝██║ ██╔╝    ██║    ██║██╔════╝██╔══██╗██╔════╝ ██╔═══██╗██╔══██╗╚══██╔══╝
█████╗  ██║     ███████║███████╗█████╔╝     ██║ █╗ ██║█████╗  ██████╔╝██║  ███╗██║   ██║███████║   ██║
██╔══╝  ██║     ██╔══██║╚════██║██╔═██╗     ██║███╗██║██╔══╝  ██╔══██╗██║   ██║██║   ██║██╔══██║   ██║
██║     ███████╗██║  ██║███████║██║  ██╗    ╚███╔███╔╝███████╗██████╔╝╚██████╔╝╚██████╔╝██║  ██║   ██║
╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝     ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝
```

### Run

```
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export ADMIN_PASSWORD='choose-a-strong-password'
FLASK_APP=run.py flask run
```

`SECRET_KEY` signs session cookies; if it is unset a random key is generated
on every start. `ADMIN_PASSWORD` sets the password of the `admin` account; if
it is unset the admin account gets a random password and cannot be used. Set
`SESSION_COOKIE_SECURE=1` when serving over HTTPS.

### Tests

```
python -m unittest discover -s tests -t . -v
```

### Vulnerabilities

The application originally shipped with the following deliberate
vulnerabilities. They have been fixed; see `security-report.md` for the
details of each finding and fix.

- Remote Code Execution
- SQL injection
- Insecure Deserialization
- Directory Traversal
- Open Redirect
- Sensitive Data Exposure
- Broken Access Control
- Security Misconfiguration
