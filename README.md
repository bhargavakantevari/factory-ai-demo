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
FLASK_SECRET_KEY=<random-value> ADMIN_PASSWORD=<admin-password> FLASK_APP=run.py flask run
```

For local development over plain HTTP, also set `SESSION_COOKIE_SECURE=0`.

### Vulnerabilities

The deliberately planted vulnerabilities (Remote Code Execution, SQL injection,
Insecure Deserialization, Directory Traversal, Open Redirect, Sensitive Data
Exposure, Broken Access Control, Security Misconfiguration) have been
remediated. See `security-report.md` for each finding and its fix.
