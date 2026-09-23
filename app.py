"""Flask bridge for the Campus Hardware Inventory System.

The original Tkinter module remains intact. This file reuses its validation,
authentication, inventory, and borrowing services while replacing only the UI.
"""

from __future__ import annotations

import csv
import io
import os
import secrets
from datetime import date, timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
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
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
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
            role = request.form.get("role", "USER").upper()
            if role not in desktop.VALID_ROLES:
                role = "USER"
            ok, message = auth_service.register_user(
                request.form.get("username", "").strip(),
                request.form.get("email", "").strip(),
                request.form.get("password", ""),
                role,
            )
            flash(message, "success" if ok else "danger")
            if ok:
                return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/reset", methods=["GET", "POST"])
    def reset_request():
        if request.method == "POST":
            validate_csrf()
            ok, message = auth_service.request_password_reset(
                request.form.get("identifier", "").strip(),
                request.form.get("new_password", ""),
                request.form.get("confirm_password", ""),
            )
            flash(message, "success" if ok else "danger")
            if ok:
                return redirect(url_for("login"))
        return render_template("reset.html")

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
