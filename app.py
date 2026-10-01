"""Flask bridge for the Campus Hardware Inventory System.

The original Tkinter module remains intact. This file reuses its validation,
authentication, inventory, and borrowing services while replacing only the UI.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import os
import secrets
import smtplib
import ssl
import time
from datetime import date, timedelta
from email.message import EmailMessage
from email.utils import formataddr
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import database as sqlite3
from database import using_postgres
import guigui_engineering_lab_asset_tracking_app as desktop


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("HARDWARE_DB", BASE_DIR / "hardware_inventory.db"))

# All reused desktop services read this module-level value. Pointing it at the
# web project's database preserves the existing logic without copying it.
desktop.DB_NAME = str(DB_PATH)

auth_service = desktop.AuthService()
inventory_service = desktop.InventoryService()
asset_service = desktop.AssetTrackingService()


def _env_int(name: str, default: int) -> int:
    """Read an integer setting without breaking startup on a bad value."""
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _mask_email(email: str) -> str:
    """Return a destination hint without exposing the complete address."""
    local, separator, domain = email.partition("@")
    if not separator:
        return email
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}{'*' * max(3, len(local) - len(visible))}@{domain}"


def _otp_digest(otp: str, salt: str) -> str:
    """Hash an OTP before placing it in Flask's signed session cookie."""
    secret = str(current_app.config["SECRET_KEY"]).encode("utf-8")
    value = f"{salt}:{otp}".encode("utf-8")
    return hmac.new(secret, value, hashlib.sha256).hexdigest()


def send_otp_email(receiver_email: str, otp: str, action: str) -> tuple[bool, str]:
    """Send a registration or password-reset OTP through Brevo SMTP."""
    login = current_app.config.get("BREVO_SMTP_LOGIN", "")
    password = current_app.config.get("BREVO_SMTP_PASSWORD", "")
    sender_email = current_app.config.get("BREVO_SENDER_EMAIL", "")
    if not login or not password or not sender_email:
        current_app.logger.error("Brevo SMTP environment variables are incomplete.")
        return False, "Email verification is not configured yet. Please contact the administrator."

    purpose = "account registration" if action == "register" else "password reset request"
    ttl_minutes = max(1, current_app.config["OTP_TTL_SECONDS"] // 60)
    message = EmailMessage()
    message["Subject"] = "Your RoseLab verification code"
    message["From"] = formataddr(
        (current_app.config["BREVO_SENDER_NAME"], sender_email)
    )
    message["To"] = receiver_email
    message.set_content(
        "RoseLab Hardware Inventory\n\n"
        f"Your verification code for {purpose} is: {otp}\n\n"
        f"This code expires in {ttl_minutes} minutes. "
        "If you did not request this code, you can ignore this email."
    )

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(
            current_app.config["BREVO_SMTP_HOST"],
            current_app.config["BREVO_SMTP_PORT"],
            timeout=20,
        ) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(login, password)
            server.send_message(message)
    except (OSError, smtplib.SMTPException) as error:
        current_app.logger.exception("Brevo could not send a verification email: %s", error)
        return False, "We could not send the verification email. Please try again shortly."

    return True, "Verification code sent."


def _registration_error(username: str, email: str, password: str, role: str) -> str | None:
    """Validate registration before spending a Brevo email send."""
    try:
        desktop.UserSchema(username=username, email=email, password=password, role=role)
    except desktop.ValidationError as error:
        messages = [item["msg"] for item in error.errors()]
        return "Registration Requirements:\n\n" + "\n".join(messages)

    username_account = auth_service._get_account(username)
    email_account = auth_service._get_account(email)
    errors = []
    if username_account and username_account[0] == username:
        errors.append("Username already taken.")
    if email_account and email_account[1] == email:
        errors.append("Email address already registered.")
    return "\n".join(errors) if errors else None


def _reset_error(identifier: str, new_password: str, confirm_password: str) -> tuple[str | None, tuple | None]:
    """Validate a reset request and resolve its verified email destination."""
    if not identifier:
        return "Please enter your username or email.", None
    if new_password != confirm_password:
        return "New password and confirmation do not match.", None
    try:
        desktop.validate_password_complexity(new_password)
    except ValueError as error:
        return str(error), None
    account = auth_service._get_account(identifier)
    if not account:
        return "No account found with that username or email.", None
    if not account[1]:
        return "This account does not have an email address for verification.", None
    return None, account


def _begin_otp(action: str, receiver_email: str, payload: dict) -> tuple[bool, str]:
    otp = f"{secrets.randbelow(1_000_000):06d}"
    salt = secrets.token_hex(16)
    ok, message = send_otp_email(receiver_email, otp, action)
    if not ok:
        return False, message
    session["otp_verification"] = {
        "action": action,
        "digest": _otp_digest(otp, salt),
        "salt": salt,
        "expires_at": int(time.time()) + current_app.config["OTP_TTL_SECONDS"],
        "attempts": 0,
        "destination": _mask_email(receiver_email),
        "payload": payload,
    }
    session.modified = True
    return True, message


def db_connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_web_db() -> None:
    """Initialize the reused schema plus the small web return-approval bridge."""
    if not using_postgres():
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    desktop.init_db()
    if using_postgres():
        return
    with db_connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS web_return_requests (
                return_request_id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id INTEGER NOT NULL,
                requested_by TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
                resolved_at TEXT,
                resolved_by TEXT,
                UNIQUE (transaction_id, status),
                FOREIGN KEY (transaction_id)
                    REFERENCES asset_transactions(transaction_id)
                    ON DELETE CASCADE
            )
            """
        )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get("role") != "ADMIN":
            flash("Administrator access is required.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf() -> None:
    sent = request.form.get("csrf_token", "")
    saved = session.get("csrf_token", "")
    if not sent or not saved or not secrets.compare_digest(sent, saved):
        abort(400, "Invalid or expired form token. Refresh the page and try again.")


def load_dashboard_data(search_text: str = "", category: str = "All") -> dict:
    prices = {row[0]: row[4] for row in inventory_service.fetch_all()}
    all_equipment = [tuple(row) + (prices.get(row[0], 0.0),) for row in asset_service.list_equipment()]
    search_lower = search_text.strip().lower()
    equipment = [
        row
        for row in all_equipment
        if (not search_lower or search_lower in row[1].lower() or search_lower in row[2].lower())
        and (category == "All" or row[2] == category)
    ]

    with db_connect() as connection:
        username = session["username"]
        role = session["role"]
        params: list[object] = []
        where = ""
        if role != "ADMIN":
            where = "WHERE t.borrower_username = ?"
            params.append(username)

        transactions = connection.execute(
            f"""
            SELECT t.*,
                   rr.return_request_id,
                   rr.status AS return_request_status
            FROM asset_transactions AS t
            LEFT JOIN web_return_requests AS rr
              ON rr.transaction_id = t.transaction_id
             AND rr.status = 'PENDING'
            {where}
            ORDER BY t.transaction_id DESC
            """,
            params,
        ).fetchall()

        pending_borrows = [row for row in transactions if row["status"] == "PENDING"]
        borrowed = [
            row for row in transactions if row["status"] in ("APPROVED", "BORROWED", "OVERDUE")
        ]
        pending_returns = [row for row in transactions if row["return_request_status"] == "PENDING"]

        reset_requests = []
        if role == "ADMIN":
            reset_requests = connection.execute(
                """
                SELECT request_id, username, email, requested_at, status
                FROM password_reset_requests
                WHERE status = 'PENDING'
                ORDER BY request_id DESC
                """
            ).fetchall()

    return {
        "equipment": equipment,
        "categories": inventory_service.get_categories(),
        "transactions": transactions,
        "pending_borrows": pending_borrows,
        "borrowed": borrowed,
        "pending_returns": pending_returns,
        "reset_requests": reset_requests,
        "total_stocks": sum(row[5] for row in all_equipment),
        "borrowed_units": sum(row["quantity"] for row in borrowed),
        "search_text": search_text,
        "selected_category": category,
        "today": date.today().isoformat(),
        "default_return": (date.today() + timedelta(days=7)).isoformat(),
    }


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "lab7-local-development-key-change-me"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get(
            "SESSION_COOKIE_SECURE", "1" if os.environ.get("RENDER") else "0"
        ) == "1",
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        BREVO_SMTP_HOST=os.environ.get("BREVO_SMTP_HOST", "smtp-relay.brevo.com"),
        BREVO_SMTP_PORT=_env_int("BREVO_SMTP_PORT", 587),
        BREVO_SMTP_LOGIN=os.environ.get("BREVO_SMTP_LOGIN", ""),
        BREVO_SMTP_PASSWORD=os.environ.get("BREVO_SMTP_PASSWORD", ""),
        BREVO_SENDER_EMAIL=os.environ.get("BREVO_SENDER_EMAIL", ""),
        BREVO_SENDER_NAME=os.environ.get(
            "BREVO_SENDER_NAME", "RoseLab Hardware Inventory"
        ),
        OTP_TTL_SECONDS=_env_int("OTP_TTL_SECONDS", 600),
        OTP_MAX_ATTEMPTS=_env_int("OTP_MAX_ATTEMPTS", 5),
    )
    if test_config:
        app.config.update(test_config)
    app.jinja_env.globals["csrf_token"] = csrf_token
    init_web_db()

    @app.context_processor
    def shared_template_values():
        return {
            "current_year": date.today().year,
            "status_label": {
                "PENDING": "Pending borrow",
                "APPROVED": "Approved",
                "BORROWED": "Borrowed",
                "OVERDUE": "Overdue",
                "RETURNED": "Returned",
                "REJECTED": "Rejected",
                "CANCELLED": "Cancelled",
            },
        }

    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if "username" in session else "login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            validate_csrf()
            identifier = request.form.get("identifier", "").strip()
            password = request.form.get("password", "")
            ok, message, locked = auth_service.login_user(identifier, password)
            if ok:
                account = auth_service._get_account(identifier)
                session.clear()
                session["username"] = account[0]
                session["email"] = account[1] or ""
                session["role"] = account[3]
                csrf_token()
                flash(message, "success")
                return redirect(url_for("dashboard"))
            flash(message, "danger" if not locked else "warning")
        return render_template("login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            validate_csrf()
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            role = request.form.get("role", "USER").upper()
            if role not in desktop.VALID_ROLES:
                role = "USER"
            error = _registration_error(username, email, password, role)
            if error:
                flash(error, "danger")
                return render_template("register.html")
            ok, message = _begin_otp(
                "register",
                email,
                {
                    "username": username,
                    "email": email,
                    "password": password,
                    "role": role,
                },
            )
            flash(message, "success" if ok else "danger")
            if ok:
                return redirect(url_for("verify_otp", action="register"))
        return render_template("register.html")

    @app.route("/reset", methods=["GET", "POST"])
    def reset_request():
        if request.method == "POST":
            validate_csrf()
            identifier = request.form.get("identifier", "").strip()
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            error, account = _reset_error(identifier, new_password, confirm_password)
            if error:
                flash(error, "danger")
                return render_template("reset.html")
            ok, message = _begin_otp(
                "reset",
                account[1],
                {
                    "identifier": account[0],
                    "new_password": new_password,
                    "confirm_password": confirm_password,
                },
            )
            flash(message, "success" if ok else "danger")
            if ok:
                return redirect(url_for("verify_otp", action="reset"))
        return render_template("reset.html")

    @app.route("/verify-otp/<action>", methods=["GET", "POST"])
    def verify_otp(action: str):
        if action not in ("register", "reset"):
            abort(404)
        pending = session.get("otp_verification")
        if not pending or pending.get("action") != action:
            flash("Start the verification process again to receive a new code.", "warning")
            return redirect(url_for("register" if action == "register" else "reset_request"))

        if int(pending.get("expires_at", 0)) < int(time.time()):
            session.pop("otp_verification", None)
            flash("That verification code has expired. Request a new one.", "warning")
            return redirect(url_for("register" if action == "register" else "reset_request"))

        if request.method == "POST":
            validate_csrf()
            entered = request.form.get("otp", "").strip()
            expected = pending.get("digest", "")
            actual = _otp_digest(entered, pending.get("salt", ""))
            if not entered or not hmac.compare_digest(actual, expected):
                pending["attempts"] = int(pending.get("attempts", 0)) + 1
                if pending["attempts"] >= current_app.config["OTP_MAX_ATTEMPTS"]:
                    session.pop("otp_verification", None)
                    flash("Too many incorrect attempts. Request a new code.", "danger")
                    return redirect(url_for("register" if action == "register" else "reset_request"))
                session["otp_verification"] = pending
                remaining = current_app.config["OTP_MAX_ATTEMPTS"] - pending["attempts"]
                flash(f"Incorrect verification code. {remaining} attempt(s) remaining.", "danger")
                return render_template(
                    "otp_verify.html",
                    action=action,
                    destination=pending["destination"],
                    ttl_minutes=max(1, current_app.config["OTP_TTL_SECONDS"] // 60),
                )

            payload = pending.get("payload", {})
            session.pop("otp_verification", None)
            if action == "register":
                ok, message = auth_service.register_user(
                    payload.get("username", ""),
                    payload.get("email", ""),
                    payload.get("password", ""),
                    payload.get("role", "USER"),
                )
            else:
                ok, message = auth_service.request_password_reset(
                    payload.get("identifier", ""),
                    payload.get("new_password", ""),
                    payload.get("confirm_password", ""),
                )
            flash(message, "success" if ok else "danger")
            if ok:
                return redirect(url_for("login"))
            return redirect(url_for("register" if action == "register" else "reset_request"))

        return render_template(
            "otp_verify.html",
            action=action,
            destination=pending["destination"],
            ttl_minutes=max(1, current_app.config["OTP_TTL_SECONDS"] // 60),
        )

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template(
            "dashboard.html",
            **load_dashboard_data(
                request.args.get("q", ""), request.args.get("category", "All")
            ),
        )

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        if request.method == "POST":
            validate_csrf()
            ok, message = auth_service.change_password(
                session["username"],
                request.form.get("current_password", ""),
                request.form.get("new_password", ""),
                request.form.get("confirm_password", ""),
            )
            flash(message, "success" if ok else "danger")
        return render_template("profile.html")

    @app.route("/inventory/add", methods=["POST"])
    @admin_required
    def inventory_add():
        validate_csrf()
        ok, message = inventory_service.add_item(
            request.form.get("item_name", ""),
            request.form.get("category", ""),
            request.form.get("quantity", ""),
            request.form.get("unit_price", ""),
        )
        flash(message, "success" if ok else "danger")
        return redirect(url_for("dashboard"))

    @app.route("/inventory/<int:item_id>/update", methods=["POST"])
    @admin_required
    def inventory_update(item_id: int):
        validate_csrf()
        ok, message = inventory_service.update_item(
            item_id,
            request.form.get("item_name", ""),
            request.form.get("category", ""),
            request.form.get("quantity", ""),
            request.form.get("unit_price", ""),
        )
        flash(message, "success" if ok else "danger")
        return redirect(url_for("dashboard"))

    @app.route("/inventory/<int:item_id>/delete", methods=["POST"])
    @admin_required
    def inventory_delete(item_id: int):
        validate_csrf()
        ok, message = inventory_service.delete_item(item_id)
        flash(message, "success" if ok else "danger")
        return redirect(url_for("dashboard"))

    @app.route("/borrow", methods=["POST"])
    @login_required
    def borrow():
        validate_csrf()
        ok, message = asset_service.submit_request(
            session["username"],
            request.form.get("item_id"),
            request.form.get("quantity"),
            request.form.get("purpose", "Laboratory activity"),
            request.form.get("start_date", date.today().isoformat()),
            request.form.get("expected_return_date", (date.today() + timedelta(days=7)).isoformat()),
        )
        flash(message, "success" if ok else "danger")
        return redirect(url_for("dashboard"))

    @app.route("/borrow/<int:transaction_id>/cancel", methods=["POST"])
    @login_required
    def borrow_cancel(transaction_id: int):
        validate_csrf()
        ok, message = asset_service.cancel_request(transaction_id, session["username"])
        flash(message, "success" if ok else "danger")
        return redirect(url_for("dashboard"))

    @app.route("/admin/borrow/<int:transaction_id>/<action>", methods=["POST"])
    @admin_required
    def borrow_action(transaction_id: int, action: str):
        validate_csrf()
        if action == "reject":
            ok, message = asset_service.reject_request(transaction_id, session["username"])
        elif action == "approve":
            ok, message = asset_service.approve_request(transaction_id, session["username"])
            if ok:
                issued, issue_message = asset_service.issue_equipment(transaction_id, session["username"])
                if issued:
                    message = f"{message} Equipment is now marked as borrowed."
                else:
                    message = f"{message} {issue_message}"
        else:
            abort(404)
        flash(message, "success" if ok else "danger")
        return redirect(url_for("dashboard"))

    @app.route("/return/<int:transaction_id>/request", methods=["POST"])
    @login_required
    def return_request(transaction_id: int):
        validate_csrf()
        with db_connect() as connection:
            row = connection.execute(
                """
                SELECT transaction_id FROM asset_transactions
                WHERE transaction_id = ? AND borrower_username = ?
                  AND status IN ('BORROWED', 'OVERDUE')
                """,
                (transaction_id, session["username"]),
            ).fetchone()
            if not row:
                flash("Only your borrowed equipment can be submitted for return.", "danger")
            else:
                existing = connection.execute(
                    """
                    SELECT 1 FROM web_return_requests
                    WHERE transaction_id = ? AND status = 'PENDING'
                    """,
                    (transaction_id,),
                ).fetchone()
                if existing:
                    flash("A return request is already pending.", "warning")
                else:
                    connection.execute(
                        """
                        INSERT INTO web_return_requests
                            (transaction_id, requested_by, requested_at, status)
                        VALUES (?, ?, ?, 'PENDING')
                        """,
                        (transaction_id, session["username"], desktop.now_str()),
                    )
                    flash("Return request submitted for administrator approval.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/admin/return/<int:return_request_id>/<action>", methods=["POST"])
    @admin_required
    def return_action(return_request_id: int, action: str):
        validate_csrf()
        with db_connect() as connection:
            pending = connection.execute(
                """
                SELECT transaction_id FROM web_return_requests
                WHERE return_request_id = ? AND status = 'PENDING'
                """,
                (return_request_id,),
            ).fetchone()
        if not pending:
            flash("Pending return request not found.", "danger")
            return redirect(url_for("dashboard"))

        if action == "approve":
            ok, message = asset_service.return_equipment(
                pending["transaction_id"], session["username"]
            )
            new_status = "APPROVED" if ok else None
        elif action == "reject":
            ok, message, new_status = True, "Return request rejected; item remains borrowed.", "REJECTED"
        else:
            abort(404)

        if new_status:
            with db_connect() as connection:
                connection.execute(
                    """
                    UPDATE web_return_requests
                    SET status = ?, resolved_at = ?, resolved_by = ?
                    WHERE return_request_id = ? AND status = 'PENDING'
                    """,
                    (new_status, desktop.now_str(), session["username"], return_request_id),
                )
        flash(message, "success" if ok else "danger")
        return redirect(url_for("dashboard"))

    @app.route("/admin/reset/<int:request_id>/<action>", methods=["POST"])
    @admin_required
    def reset_action(request_id: int, action: str):
        validate_csrf()
        if action not in ("approve", "reject"):
            abort(404)
        ok, message = auth_service.resolve_request(
            request_id, action == "approve", session["username"]
        )
        flash(message, "success" if ok else "danger")
        return redirect(url_for("dashboard"))

    @app.route("/export/inventory")
    @login_required
    def export_inventory():
        rows = inventory_service.fetch_all()
        stream = io.StringIO()
        writer = csv.writer(stream)
        writer.writerow(["ID", "Name", "Category", "Quantity", "Unit Price", "Status"])
        writer.writerows(rows)
        return Response(
            stream.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=inventory_report.csv"},
        )

    @app.route("/export/borrow-audit")
    @admin_required
    def export_borrow_audit():
        rows = asset_service.list_transactions(session["username"], all_records=True)
        stream = io.StringIO()
        writer = csv.writer(stream)
        writer.writerow([
            "Transaction ID", "Borrower", "Equipment", "Quantity", "Purpose",
            "Start Date", "Expected Return", "Requested At", "Approved At",
            "Approved By", "Issued At", "Issued By", "Returned At", "Returned By",
            "Rejected At", "Rejected By", "Cancelled At", "Status",
        ])
        writer.writerows(rows)
        return Response(
            stream.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=borrow_audit.csv"},
        )

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        validate_csrf()
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", code=400, message=str(error.description)), 400

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="That page does not exist."), 404

    return app


app = create_app()


if __name__ == "__main__":
    print("\n" + "=" * 58)
    print(" CAMPUS HARDWARE INVENTORY - WEB PORTAL")
    print("=" * 58)
    print("\n Open Google Chrome and go to:")
    print(" http://127.0.0.1:5000")
    print("\n Press CTRL+C to stop the server.")
    print("=" * 58 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
