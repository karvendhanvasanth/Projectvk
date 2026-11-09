# Northstar Authentication Website

Responsive authentication website with Python FastAPI backend and SQLite persistence.

## Run locally (Windows PowerShell)
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn backend.main:app --reload
```
Open http://localhost:8000. API health: http://localhost:8000/api/health.

## macOS / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn backend.main:app --reload
```

## Included
- Registration, login, logout, current-user endpoint, forgot password and password reset.
- SQLite database created automatically at `data/northstar.db`.
- Passwords hashed with PBKDF2-HMAC-SHA256; never stored in plain text.
- Signed HTTP-only session cookie; one-time reset tokens expire after 30 minutes and are stored hashed.
- Development reset URL is printed to the server terminal and returned by the API for local testing.
- Configure SMTP variables in `.env` for reset email delivery.

## Before production
Set `APP_ENV=production`, a strong random `SECRET_KEY`, `APP_BASE_URL` to your HTTPS domain, and SMTP settings. Add rate limiting, backups, migrations, and monitoring before public launch. Google/Apple sign-in buttons are not configured yet. SQLite is suitable for local/small deployments; use PostgreSQL for multi-instance/high-traffic deployment.

Figma source: https://www.figma.com/design/keSAqYJZHbFn182obHSonG
