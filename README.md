# Campus Hardware Inventory System

This is the Experiment 8 version of the Flask application. It keeps SQLite as
the local fallback and automatically uses Supabase PostgreSQL when the
`DATABASE_URL` environment variable is present.

## Local setup on Windows

Open the project folder in VS Code, then run these commands in PowerShell:

```powershell
py -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>. Without `DATABASE_URL`, the application uses the
local `hardware_inventory.db` file.

## Supabase migration

1. Create a Supabase project and copy its PostgreSQL connection string.
2. Keep `hardware_inventory.db` in this folder for the one-time migration.
3. Set the connection string only in the current PowerShell window:

```powershell
$env:DATABASE_URL = "YOUR_SUPABASE_POSTGRESQL_CONNECTION_STRING"
python -c "import os; print(os.getenv('DATABASE_URL','')[:13])"
python migrate_sqlite_to_postgresql.py
```

The verification command must show `postgresql://`. Do not print or screenshot
the full value. The migration refuses to write into non-empty destination
tables to prevent duplicate records.

After migration, run `python app.py` in the same terminal and complete the
login, inventory, borrow, approval, return, and password-reset tests.

## GitHub upload

Create an empty repository, then run:

```powershell
git init
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/Campus-hardware-inventory.git
git add .
git status
git commit -m "Prepare Experiment 8 deployment"
git push -u origin main
```

Before committing, confirm that Git does **not** list `.env`, `.venv`,
`hardware_inventory.db`, `__pycache__`, or `app_logging`. The provided
`.gitignore` excludes them.

## Render deployment

Create a Python Web Service from the GitHub repository with:

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app`
- Environment variable `DATABASE_URL`: the Supabase PostgreSQL connection
- Environment variable `SECRET_KEY`: a long random value

The included `render.yaml` contains the same build and start settings. Once the
service is live, test the public URL and verify new transactions in Supabase.

## Architecture

- GitHub stores the source code.
- Supabase stores the persistent PostgreSQL data.
- Render runs the Flask web application.

Never commit or submit real passwords, connection strings, secret keys, or
account credentials.
