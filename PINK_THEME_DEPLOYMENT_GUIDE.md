# RoseLab Pink Frontend Edition

This edition keeps the Flask routes, Supabase/PostgreSQL database layer,
authentication, inventory operations, borrowing workflow, reports, and tests.
Only the browser-facing templates and CSS theme were redesigned.

## Frontend files changed

- `static/style.css`
- `templates/base.html`
- `templates/login.html`
- `templates/dashboard.html`
- `templates/register.html`
- `templates/reset.html`
- `templates/profile.html`
- `templates/error.html`

## Test locally on Windows

Open the extracted project folder in VS Code, then run:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe app.py
```

Open `http://127.0.0.1:5000` in the browser.

Without `DATABASE_URL`, the app uses the included local SQLite database. With
`DATABASE_URL`, it uses the configured Supabase PostgreSQL database.

## Publish as a separate GitHub project

Create a new empty GitHub repository. Do not add a README, `.gitignore`, or
license on GitHub. Then run these commands from the project folder:

```powershell
git init
git branch -M main
git add .
git commit -m "Create RoseLab pink inventory interface"
git remote add origin https://github.com/YOUR_USERNAME/YOUR_NEW_REPOSITORY.git
git push -u origin main
```

If the extracted folder still contains an old `.git` folder, delete only that
hidden `.git` folder before running `git init`. The cleaned ZIP supplied with
this guide does not include one.

## Deploy on Render

1. In Render, create a new **Web Service** from the new GitHub repository.
2. Choose Python as the runtime.
3. Use `pip install -r requirements.txt` as the build command.
4. Use `gunicorn app:app` as the start command.
5. Add `DATABASE_URL` using the complete Supabase **Session Pooler URI**.
6. Add `SECRET_KEY` and let Render generate its value.
7. Deploy the service and open the generated public URL.

The existing Supabase database may be reused by placing the same working
`DATABASE_URL` in the new Render service. Do not rerun the migration when the
tables already contain data.

## Updating the published design

After editing the frontend, publish changes with:

```powershell
git add static templates
git commit -m "Update RoseLab interface"
git push
```

Render will normally redeploy automatically after the push.
