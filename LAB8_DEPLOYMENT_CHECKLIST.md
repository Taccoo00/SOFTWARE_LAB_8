# Experiment 8 Deployment Checklist

The project code is ready. The remaining work requires your own GitHub,
Supabase, and Render accounts, so complete the items below in order.

## 1. Verify locally

- [ ] Extract the project to a normal folder.
- [ ] Open that folder in VS Code.
- [ ] Create and activate `.venv`.
- [ ] Run `python -m pip install -r requirements.txt`.
- [ ] Run `python -m pytest -q`; the expected result is `7 passed`.
- [ ] Run `python app.py` and test <http://127.0.0.1:5000>.

## 2. Create the empty GitHub repository

- [ ] Repository name: `Campus-hardware-inventory`.
- [ ] Use the visibility required by your instructor.
- [ ] Leave **Add README**, **.gitignore**, and **license** off because the
      project already includes the required files.
- [ ] Run the Git commands from `README.md`.
- [ ] Before committing, confirm the database, `.venv`, `.env`, caches, and
      logs are absent from `git status`.
- [ ] Capture a screenshot of the repository file list.

## 3. Create Supabase and migrate

- [ ] Create a Supabase project and save the database password privately.
- [ ] Copy the PostgreSQL connection string.
- [ ] Set `$env:DATABASE_URL` in PowerShell.
- [ ] Run `python migrate_sqlite_to_postgresql.py` once.
- [ ] Capture the successful migration output without showing the URL.
- [ ] Verify these tables in Supabase: `users`, `hardware`,
      `password_reset_requests`, `asset_transactions`, and
      `web_return_requests`.
- [ ] Capture a screenshot of the Supabase table list with no credentials.

## 4. Test Flask with Supabase

- [ ] Keep `DATABASE_URL` set and run `python app.py`.
- [ ] Test login, registration, inventory, borrow approval, return approval,
      and password reset.
- [ ] Confirm new changes appear in Supabase.
- [ ] Capture a local browser screenshot.

## 5. Deploy on Render

- [ ] Create a Python Web Service from the GitHub repository.
- [ ] Build command: `pip install -r requirements.txt`.
- [ ] Start command: `gunicorn app:app`.
- [ ] Add `DATABASE_URL` and `SECRET_KEY` as private environment variables.
- [ ] Wait for the service to show **Live**.
- [ ] Capture the Render status without revealing environment values.
- [ ] Open the public URL and repeat the main workflow.
- [ ] Capture the public application and write the URL in the report.

## 6. Submit

- [ ] Add the required screenshots to the supplied submission report.
- [ ] Confirm no password, connection string, secret key, or account token is
      visible in any screenshot.
- [ ] Submit the GitHub URL, public Render URL, and completed report.
