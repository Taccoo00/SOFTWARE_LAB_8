import csv
import logging
import os
import re
from datetime import datetime

import database as sqlite3
from database import init_postgres_schema, using_postgres

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    TKINTER_AVAILABLE = True
except ImportError:
    tk = None
    ttk = None
    messagebox = None
    TKINTER_AVAILABLE = False

import bcrypt
from pydantic import BaseModel, Field, ValidationError, field_validator


DB_NAME = "hardware_inventory.db"
LOG_DIR = "app_logging"
LOG_FILE = os.path.join(LOG_DIR, "app.log")
CSV_REPORT = "inventory_report.csv"
ASSET_REPORT = "asset_tracking_report.csv"

# Account lockout settings.
# NOTE: the old design used a 30-second, in-memory countdown lockout.
# That has been replaced with a persistent (DB-backed) lockout that can
# only be lifted by an ADMIN approving a password-reset request.
MAX_FAILED_ATTEMPTS = 3

VALID_ROLES = ("USER", "ADMIN")

# Borrowing states. Only the active states reserve laboratory equipment.
ACTIVE_ASSET_STATUSES = ("APPROVED", "BORROWED", "OVERDUE")
FINAL_ASSET_STATUSES = ("REJECTED", "RETURNED", "CANCELLED")
DATE_FORMAT = "%Y-%m-%d"

# A restrained visual theme shared by the original screens and the new
# laboratory asset-tracking windows.
APP_BG = "#F4F7FB"
SURFACE_COLOR = "#FFFFFF"
TEXT_COLOR = "#1F2937"
MUTED_COLOR = "#64748B"
PRIMARY_COLOR = "#2563EB"
SUCCESS_COLOR = "#15803D"
WARNING_COLOR = "#B45309"
DANGER_COLOR = "#DC2626"
TEAL_COLOR = "#0F766E"
SLATE_COLOR = "#475569"
PURPLE_COLOR = "#7C3AED"
BORDER_COLOR = "#CBD5E1"

BODY_FONT = ("Segoe UI", 10)
SMALL_FONT = ("Segoe UI", 9)
BUTTON_FONT = ("Segoe UI Semibold", 9)
TITLE_FONT = ("Segoe UI Semibold", 16)
SECTION_TITLE_FONT = ("Segoe UI Semibold", 15)
SUBTITLE_FONT = ("Segoe UI Semibold", 12)


def apply_app_theme(window):
    """Apply light visual polish without changing any screen behavior."""

    window.configure(bg=APP_BG)
    window.option_add("*Font", BODY_FONT)
    window.option_add("*Background", APP_BG)
    window.option_add("*Foreground", TEXT_COLOR)
    window.option_add("*Button.Font", BUTTON_FONT)
    window.option_add("*Button.Background", "#E2E8F0")
    window.option_add("*Button.ActiveBackground", "#CBD5E1")
    window.option_add("*Button.Relief", "flat")
    window.option_add("*Button.BorderWidth", 0)
    window.option_add("*Button.Padx", 9)
    window.option_add("*Button.Pady", 5)
    window.option_add("*Entry.Background", SURFACE_COLOR)
    window.option_add("*Entry.Relief", "solid")
    window.option_add("*Entry.BorderWidth", 1)
    window.option_add("*Text.Background", SURFACE_COLOR)
    window.option_add("*Text.Relief", "solid")
    window.option_add("*Listbox.Background", SURFACE_COLOR)
    window.option_add("*selectBackground", PRIMARY_COLOR)
    window.option_add("*selectForeground", "#FFFFFF")

    style = ttk.Style(window)

    if "clam" in style.theme_names():
        style.theme_use("clam")

    style.configure(
        "Treeview",
        background=SURFACE_COLOR,
        fieldbackground=SURFACE_COLOR,
        foreground=TEXT_COLOR,
        rowheight=28,
        bordercolor=BORDER_COLOR,
        lightcolor=BORDER_COLOR,
        darkcolor=BORDER_COLOR,
        font=BODY_FONT,
    )
    style.map(
        "Treeview",
        background=[("selected", PRIMARY_COLOR)],
        foreground=[("selected", "#FFFFFF")],
    )
    style.configure(
        "Treeview.Heading",
        background="#E2E8F0",
        foreground="#334155",
        relief="flat",
        padding=(8, 7),
        font=("Segoe UI Semibold", 10),
    )
    style.map(
        "Treeview.Heading",
        background=[("active", "#CBD5E1")],
    )
    style.configure(
        "TCombobox",
        padding=4,
        fieldbackground=SURFACE_COLOR,
        background=SURFACE_COLOR,
        foreground=TEXT_COLOR,
        arrowcolor=TEXT_COLOR,
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", SURFACE_COLOR)],
        selectbackground=[("readonly", SURFACE_COLOR)],
        selectforeground=[("readonly", TEXT_COLOR)],
    )
    style.configure(
        "Vertical.TScrollbar",
        background="#CBD5E1",
        troughcolor="#E2E8F0",
        arrowcolor=TEXT_COLOR,
    )
    style.configure(
        "Horizontal.TScrollbar",
        background="#CBD5E1",
        troughcolor="#E2E8F0",
        arrowcolor=TEXT_COLOR,
    )


def setup_logger():
    os.makedirs(LOG_DIR, exist_ok=True)

    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    return logging.getLogger("HardwareInventoryLogger")


logger = setup_logger()


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def validate_password_complexity(value):
    """Shared password-complexity check used by registration, password
    reset requests, and direct password changes so the rules and error
    messages stay consistent everywhere."""

    errors = []

    if len(value) < 8:
        errors.append("Password must be at least 8 characters long.")

    if not re.search(r"[A-Z]", value):
        errors.append("Password must contain at least one uppercase letter.")

    if not re.search(r"\d", value):
        errors.append("Password must contain at least one number.")

    if not re.search(r"[^A-Za-z0-9]", value):
        errors.append(
            "Password must contain at least one special character (@#$%^&*)."
        )

    if errors:
        raise ValueError("\n".join(errors))

    return value


class UserSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=20)
    email: str = Field(..., min_length=5, max_length=254)
    password: str = Field(...)
    role: str = Field(default="USER")

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, value):
        if not value.isalnum():
            raise ValueError(
                "Username must contain only letters and numbers."
            )
        return value

    @field_validator("email")
    @classmethod
    def valid_email(cls, value):
        pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"

        if not re.fullmatch(pattern, value):
            raise ValueError(
                "Email Address must be a valid email address "
                "(example: user@gmail.com)."
            )

        return value

    @field_validator("password")
    @classmethod
    def password_complexity(cls, value):
        return validate_password_complexity(value)

    @field_validator("role")
    @classmethod
    def valid_role(cls, value):
        value = (value or "").strip().upper()

        if value not in VALID_ROLES:
            raise ValueError("Role must be either USER or ADMIN.")

        return value


class HardwareSchema(BaseModel):
    item_name: str = Field(..., min_length=2, max_length=100)
    category: str = Field(..., min_length=2, max_length=50)
    quantity: int = Field(..., ge=0)
    unit_price: float = Field(..., ge=0)


def init_db():
    if using_postgres():
        init_postgres_schema()
        return

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Create the new users table (with email + role + lockout tracking)
    # for a fresh database.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'USER',
            is_locked INTEGER NOT NULL DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0
        )
    """)

    # Migration for an older hardware_inventory.db whose users table
    # predates one or more of: email, role, is_locked, failed_attempts.
    cursor.execute("PRAGMA table_info(users)")
    user_columns = [row[1] for row in cursor.fetchall()]

    if "email" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
        logger.info("Database migration: email column added to users table.")

    if "role" not in user_columns:
        cursor.execute(
            "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'USER'"
        )
        logger.info("Database migration: role column added to users table.")

    if "is_locked" not in user_columns:
        cursor.execute(
            "ALTER TABLE users ADD COLUMN is_locked INTEGER NOT NULL DEFAULT 0"
        )
        logger.info(
            "Database migration: is_locked column added to users table."
        )

    if "failed_attempts" not in user_columns:
        cursor.execute(
            "ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0"
        )
        logger.info(
            "Database migration: failed_attempts column added to users table."
        )

    # Add a unique index for emails. NULL values from old accounts are allowed.
    try:
        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email
            ON users(email)
        """)
    except sqlite3.IntegrityError:
        logger.warning(
            "Could not create unique email index because duplicate email values exist."
        )

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hardware (
            item_id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_name TEXT NOT NULL,
            category TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            status TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_requests (
            request_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            email TEXT,
            new_password_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            requested_at TEXT NOT NULL,
            resolved_at TEXT,
            resolved_by TEXT
        )
    """)

    # Migration for older password_reset_requests tables.
    cursor.execute("PRAGMA table_info(password_reset_requests)")
    reset_columns = [row[1] for row in cursor.fetchall()]

    if "new_password_hash" not in reset_columns:
        cursor.execute(
            "ALTER TABLE password_reset_requests "
            "ADD COLUMN new_password_hash TEXT"
        )
        logger.info(
            "Database migration: new_password_hash column added "
            "to password_reset_requests table."
        )
    if "user_id" not in reset_columns:
        cursor.execute(
            "ALTER TABLE password_reset_requests "
            "ADD COLUMN user_id INTEGER"
        )
        logger.info(
            "Database migration: user_id column added "
            "to password_reset_requests table."
        )

    if "resolved_at" not in reset_columns:
        cursor.execute(
            "ALTER TABLE password_reset_requests "
            "ADD COLUMN resolved_at TEXT"
        )
        logger.info(
            "Database migration: resolved_at column added "
            "to password_reset_requests table."
        )

    if "resolved_by" not in reset_columns:
        cursor.execute(
            "ALTER TABLE password_reset_requests "
            "ADD COLUMN resolved_by TEXT"
        )
        logger.info(
            "Database migration: resolved_by column added "
            "to password_reset_requests table."
        )

    # Additive migration for the digital engineering-laboratory logbook.
    # Existing account, password-reset, and hardware records are left intact.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asset_transactions (
            transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            borrower_username TEXT NOT NULL,
            item_id INTEGER,
            item_name_snapshot TEXT NOT NULL,
            quantity INTEGER NOT NULL CHECK (quantity > 0),
            purpose TEXT NOT NULL,
            start_date TEXT NOT NULL,
            expected_return_date TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            approved_at TEXT,
            approved_by TEXT,
            issued_at TEXT,
            issued_by TEXT,
            returned_at TEXT,
            returned_by TEXT,
            rejected_at TEXT,
            rejected_by TEXT,
            cancelled_at TEXT,
            status TEXT NOT NULL DEFAULT 'PENDING'
                CHECK (status IN (
                    'PENDING', 'APPROVED', 'REJECTED', 'BORROWED',
                    'OVERDUE', 'RETURNED', 'CANCELLED'
                )),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (item_id) REFERENCES hardware(item_id)
                ON DELETE SET NULL
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_asset_transactions_item_schedule
        ON asset_transactions(item_id, status, start_date, expected_return_date)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_asset_transactions_user_status
        ON asset_transactions(user_id, status)
    """)

    conn.commit()
    conn.close()


def calculate_status(quantity):
    if quantity > 5:
        return "In Stock"
    if 1 <= quantity <= 5:
        return "Low Stock"
    return "Out of Stock"


def peak_active_commitment(cursor, item_id):
    """Return the greatest number of units committed at one time.

    Hardware.quantity continues to mean total units owned. Approved
    reservations and checked-out units are deducted only when availability is
    calculated, so checkout and return never modify the physical stock total.
    """

    cursor.execute("""
        SELECT quantity, start_date, expected_return_date, status
        FROM asset_transactions
        WHERE item_id = ?
          AND status IN ('APPROVED', 'BORROWED', 'OVERDUE')
    """, (item_id,))

    rows = cursor.fetchall()
    today = datetime.now().strftime(DATE_FORMAT)
    indefinite_quantity = 0
    scheduled = []
    check_dates = set()

    for quantity, start_date, end_date, status in rows:
        if status == "OVERDUE" or (
            status == "BORROWED" and end_date < today
        ):
            indefinite_quantity += quantity
            continue

        scheduled.append((quantity, start_date, end_date))
        check_dates.add(start_date)
        check_dates.add(end_date)

    peak = indefinite_quantity

    for check_date in check_dates:
        concurrent = indefinite_quantity

        for quantity, start_date, end_date in scheduled:
            if start_date <= check_date <= end_date:
                concurrent += quantity

        peak = max(peak, concurrent)

    return peak


class AuthService:
    def _get_account(self, identifier):
        """Find an account by username OR email using a parameterized query."""
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT username, email, password_hash, role, is_locked, failed_attempts
            FROM users
            WHERE username = ? OR email = ?
        """, (identifier, identifier))

        row = cursor.fetchone()
        conn.close()
        return row

    def register_user(self, username, email, password, role="USER"):
        try:
            validated = UserSchema(
                username=username,
                email=email,
                password=password,
                role=role
            )
        except ValidationError as e:
            messages = []

            for error in e.errors():
                messages.append(error["msg"])

            msg = "\n".join(messages)

            logger.warning(
                f"Registration validation failed: {msg}"
            )

            return False, f"Registration Requirements:\n\n{msg}"

        # Hash password BEFORE inserting into database
        password_hash = bcrypt.hashpw(
            validated.password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        conn = None

        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()

            # Check if username or email already exists
            cursor.execute("""
                SELECT username, email
                FROM users
                WHERE username = ? OR email = ?
            """, (validated.username, validated.email))

            existing_records = cursor.fetchall()

            errors = []

            for record in existing_records:
                if record[0] == validated.username:
                    errors.append("Username already taken.")

                if record[1] == validated.email:
                    errors.append("Email address already registered.")

            if errors:
                msg = "\n".join(dict.fromkeys(errors))

                logger.warning(
                    f"Registration failed for '{validated.username}': {msg}"
                )

                return False, msg

            # Insert new user
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, is_locked, failed_attempts)
                VALUES (?, ?, ?, ?, 0, 0)
            """, (
                validated.username,
                validated.email,
                password_hash,
                validated.role
            ))

            # Save the new account permanently
            conn.commit()

            logger.info(
                f"Account created: {validated.username} ({validated.email}) "
                f"role={validated.role}"
            )

            return True, "Registration successful! You may now log in."

        except sqlite3.IntegrityError as e:
            error_text = str(e).lower()

            if "email" in error_text:
                msg = "Email address already registered."
            elif "username" in error_text:
                msg = "Username already taken."
            else:
                msg = "Username or email already exists."

            logger.warning(
                f"Registration failed for '{validated.username}': {msg}"
            )

            return False, msg

        except sqlite3.Error as e:
            logger.error(f"Registration database error: {e}")
            return False, "Registration failed."

        finally:
            if conn is not None:
                conn.close()

    def login_user(self, identifier, password):
        """Returns (success, message, locked)."""

        identifier = identifier.strip()

        if not identifier:
            logger.warning("Login validation failed: username/email was empty.")
            return False, "Please enter your username or email.", False

        if not password:
            logger.warning("Login validation failed: password was empty.")
            return False, "Please enter your password.", False

        account = self._get_account(identifier)

        if not account:
            logger.warning(
                f"Authentication failed for unknown identifier: {identifier}"
            )
            return False, "Invalid username/email or password.", False

        username, email, stored_hash, role, is_locked, failed_attempts = account

        if is_locked:
            logger.warning(f"Login blocked for locked account: {username}")
            return (
                False,
                "This account is locked due to too many failed login "
                "attempts. Please submit a password reset request.",
                True,
            )

        try:
            password_ok = bcrypt.checkpw(
                password.encode("utf-8"),
                stored_hash.encode("utf-8")
            )
        except (ValueError, TypeError):
            password_ok = False

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        if password_ok:
            cursor.execute(
                "UPDATE users SET failed_attempts = 0 WHERE username = ?",
                (username,)
            )
            conn.commit()
            conn.close()

            logger.info(f"User logged in: {username} (role={role})")
            return True, "Login successful!", False

        attempts = failed_attempts + 1

        logger.warning(
            f"Authentication failed for account: {username} "
            f"(attempt {attempts}/{MAX_FAILED_ATTEMPTS})"
        )

        if attempts >= MAX_FAILED_ATTEMPTS:
            cursor.execute(
                "UPDATE users SET is_locked = 1, failed_attempts = 0 WHERE username = ?",
                (username,)
            )
            conn.commit()
            conn.close()

            logger.warning(f"Account locked after repeated failures: {username}")

            return (
                False,
                "Too many failed attempts. This account is now locked. "
                "Please submit a password reset request.",
                True,
            )

        cursor.execute(
            "UPDATE users SET failed_attempts = ? WHERE username = ?",
            (attempts, username)
        )
        conn.commit()
        conn.close()

        remaining_attempts = MAX_FAILED_ATTEMPTS - attempts
        return (
            False,
            f"Invalid username/email or password. "
            f"{remaining_attempts} attempt(s) remaining.",
            False,
        )

    def request_password_reset(self, identifier, new_password, confirm_password):
        identifier = identifier.strip()

        if not identifier:
            return False, "Please enter your username or email."

        if new_password != confirm_password:
            return False, "New password and confirmation do not match."

        try:
            validate_password_complexity(new_password)
        except ValueError as e:
            return False, str(e)

        account = self._get_account(identifier)

        if not account:
            logger.warning(
                f"Password reset requested for unknown identifier: {identifier}"
            )
            return False, "No account found with that username or email."

        username, email, _stored_hash, _role, _is_locked, _failed = account

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Gets the user ID required by your older database table.
        cursor.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        )

        user_row = cursor.fetchone()

        if not user_row:
            conn.close()
            return False, "Account not found."

        user_id = user_row[0]

        cursor.execute("""
            SELECT request_id FROM password_reset_requests
            WHERE username = ? AND status = 'PENDING'
        """, (username,))

        if cursor.fetchone():
            conn.close()
            return (
                False,
                "A password reset request is already pending for this "
                "account. Please wait for admin review.",
            )

        new_hash = bcrypt.hashpw(
            new_password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        cursor.execute("""
            INSERT INTO password_reset_requests
            (user_id, username, email, new_password_hash, status, requested_at)
            VALUES (?, ?, ?, ?, 'PENDING', ?)
        """, (user_id, username, email, new_hash, now_str()))

        conn.commit()
        conn.close()

        logger.info(f"Password reset request submitted for user: {username}")

        return (
            True,
            "Your password reset request has been submitted. An "
            "administrator will review it before your account is unlocked.",
        )

    def get_all_reset_requests(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT request_id, username, email, requested_at,
                status, resolved_at, resolved_by
            FROM password_reset_requests
            ORDER BY request_id DESC
        """)

        rows = cursor.fetchall()
        conn.close()
        return rows

    def resolve_request(self, request_id, approve, admin_username):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT username, new_password_hash, status
            FROM password_reset_requests
            WHERE request_id = ?
        """, (request_id,))

        row = cursor.fetchone()

        if not row:
            conn.close()
            return False, "Request not found."

        username, new_password_hash, status = row

        if status != "PENDING":
            conn.close()
            return False, "This request has already been resolved."

        resolved_status = "APPROVED" if approve else "REJECTED"

        if approve:
            cursor.execute("""
                UPDATE users
                SET password_hash = ?, is_locked = 0, failed_attempts = 0
                WHERE username = ?
            """, (new_password_hash, username))

        cursor.execute("""
            UPDATE password_reset_requests
            SET status = ?, resolved_at = ?, resolved_by = ?
            WHERE request_id = ?
        """, (resolved_status, now_str(), admin_username, request_id))

        conn.commit()
        conn.close()

        logger.info(
            f"Password reset request #{request_id} for user '{username}' "
            f"{resolved_status.lower()} by admin '{admin_username}'."
        )

        if approve:
            return True, f"Request approved. '{username}' has been unlocked with the new password."

        return True, f"Request rejected for '{username}'."

    def change_password(self, username, current_password, new_password, confirm_password):
        if new_password != confirm_password:
            return False, "New password and confirmation do not match."

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()

        if not row:
            conn.close()
            return False, "Account not found."

        stored_hash = row[0]

        try:
            current_ok = bcrypt.checkpw(
                current_password.encode("utf-8"),
                stored_hash.encode("utf-8")
            )
        except (ValueError, TypeError):
            current_ok = False

        if not current_ok:
            conn.close()
            logger.warning(f"Password change failed (wrong current password): {username}")
            return False, "Current password is incorrect."

        try:
            validate_password_complexity(new_password)
        except ValueError as e:
            conn.close()
            return False, str(e)

        new_hash = bcrypt.hashpw(
            new_password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        cursor.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (new_hash, username)
        )
        conn.commit()
        conn.close()

        logger.info(f"Password changed directly by user: {username}")

        return True, "Password updated successfully."


class LoginWindow:
    def __init__(self, root, on_login_success, show_register, show_reset):
        self.root = root
        self.on_login_success = on_login_success
        self.show_register = show_register
        self.show_reset = show_reset
        self.auth = AuthService()

        self.root.title("Campus Hardware Inventory - Login")
        self.root.geometry("420x400")
        self.root.resizable(False, False)

        tk.Label(
            root,
            text="Campus Hardware Inventory",
            font=TITLE_FONT
        ).pack(pady=(25, 20))

        tk.Label(root, text="Username or Email:").pack(anchor="w", padx=55)
        self.entry_identifier = tk.Entry(root, width=34)
        self.entry_identifier.pack(padx=55, pady=(4, 14))

        tk.Label(root, text="Password:").pack(anchor="w", padx=55)
        self.entry_pass = tk.Entry(root, show="*", width=34)
        self.entry_pass.pack(padx=55, pady=(4, 8))

        self.show_password_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            root,
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password
        ).pack(anchor="w", padx=55)

        tk.Button(
            root,
            text="Login",
            command=self.handle_login,
            bg=SUCCESS_COLOR,
            fg="white",
            width=18
        ).pack(pady=(18, 8))

        tk.Button(
            root,
            text="Create an Account",
            command=self.show_register,
            bg=PRIMARY_COLOR,
            fg="white",
            width=18
        ).pack()

        tk.Button(
            root,
            text="Reset / Unlock Password",
            command=self.show_reset,
            bg=WARNING_COLOR,
            fg="white",
            width=18
        ).pack(pady=(8, 0))

    def toggle_password(self):
        self.entry_pass.config(
            show="" if self.show_password_var.get() else "*"
        )

    def handle_login(self):
        identifier = self.entry_identifier.get().strip()
        password = self.entry_pass.get()

        success, msg, locked = self.auth.login_user(identifier, password)

        if success:
            messagebox.showinfo("Success", msg)
            self.on_login_success(identifier)
        elif locked:
            messagebox.showerror("Account Locked", msg)
        else:
            messagebox.showerror("Authentication Failed", msg)


class RegisterWindow:
    def __init__(self, root, on_registered, show_login):
        self.root = root
        self.on_registered = on_registered
        self.show_login = show_login
        self.auth = AuthService()

        self.root.title("Campus Hardware Inventory - Register")
        self.root.geometry("440x560")
        self.root.resizable(False, False)

        tk.Label(
            root,
            text="Create Account",
            font=TITLE_FONT
        ).pack(pady=(25, 18))

        tk.Label(root, text="Username:").pack(anchor="w", padx=55)
        self.entry_user = tk.Entry(root, width=35)
        self.entry_user.pack(padx=55, pady=(4, 12))

        tk.Label(root, text="Email Address:").pack(anchor="w", padx=55)
        self.entry_email = tk.Entry(root, width=35)
        self.entry_email.pack(padx=55, pady=(4, 12))

        tk.Label(root, text="Password:").pack(anchor="w", padx=55)
        self.entry_pass = tk.Entry(root, show="*", width=35)
        self.entry_pass.pack(padx=55, pady=(4, 8))

        self.show_password_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            root,
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password
        ).pack(anchor="w", padx=55)

        tk.Label(root, text="User Role:").pack(anchor="w", padx=55, pady=(12, 0))
        self.role_var = tk.StringVar(value="USER")
        self.role_combo = ttk.Combobox(
            root,
            textvariable=self.role_var,
            values=list(VALID_ROLES),
            state="readonly",
            width=32
        )
        self.role_combo.pack(padx=55, pady=(4, 4))

        tk.Label(
            root,
            text="Password must have 8+ characters, 1 uppercase,\n"
                 "1 number, and 1 special character (@#$%^&*).",
            font=SMALL_FONT,
            justify="left"
        ).pack(anchor="w", padx=55, pady=(10, 15))

        tk.Button(
            root,
            text="Register",
            command=self.handle_register,
            bg=PRIMARY_COLOR,
            fg="white",
            width=18
        ).pack(pady=(0, 8))

        tk.Button(
            root,
            text="Back to Login",
            command=self.show_login,
            width=18
        ).pack()

    def toggle_password(self):
        self.entry_pass.config(
            show="" if self.show_password_var.get() else "*"
        )

    def handle_register(self):
        username = self.entry_user.get().strip()
        email = self.entry_email.get().strip()
        password = self.entry_pass.get()
        role = self.role_var.get().strip()

        success, msg = self.auth.register_user(
            username,
            email,
            password,
            role
        )

        if success:
            messagebox.showinfo("Registration Successful", msg)
            self.on_registered()
        else:
            messagebox.showwarning("Registration Alert", msg)


class ResetPasswordWindow:
    def __init__(self, root, show_login):
        self.root = root
        self.show_login = show_login
        self.auth = AuthService()

        self.root.title("Campus Hardware Inventory - Reset / Unlock Password")
        self.root.geometry("440x460")
        self.root.resizable(False, False)

        tk.Label(
            root,
            text="Reset / Unlock Password",
            font=TITLE_FONT
        ).pack(pady=(25, 6))

        tk.Label(
            root,
            text="Submitting a request does not change your password\n"
                 "immediately - an administrator must approve it first.",
            font=SMALL_FONT,
            justify="center"
        ).pack(pady=(0, 16))

        tk.Label(root, text="Username or Email:").pack(anchor="w", padx=55)
        self.entry_identifier = tk.Entry(root, width=35)
        self.entry_identifier.pack(padx=55, pady=(4, 12))

        tk.Label(root, text="New Password:").pack(anchor="w", padx=55)
        self.entry_new = tk.Entry(root, show="*", width=35)
        self.entry_new.pack(padx=55, pady=(4, 12))

        tk.Label(root, text="Confirm New Password:").pack(anchor="w", padx=55)
        self.entry_confirm = tk.Entry(root, show="*", width=35)
        self.entry_confirm.pack(padx=55, pady=(4, 8))

        self.show_password_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            root,
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password
        ).pack(anchor="w", padx=55)

        tk.Button(
            root,
            text="Submit Reset Request",
            command=self.handle_submit,
            bg=WARNING_COLOR,
            fg="white",
            width=20
        ).pack(pady=(18, 8))

        tk.Button(
            root,
            text="Back to Login",
            command=self.show_login,
            width=20
        ).pack()

    def toggle_password(self):
        show = "" if self.show_password_var.get() else "*"
        self.entry_new.config(show=show)
        self.entry_confirm.config(show=show)

    def handle_submit(self):
        try:
            identifier = self.entry_identifier.get().strip()
            new_password = self.entry_new.get()
            confirm_password = self.entry_confirm.get()

            success, msg = self.auth.request_password_reset(
                identifier,
                new_password,
                confirm_password
            )

            if success:
                messagebox.showinfo("Request Submitted", msg)
                self.show_login()
            else:
                messagebox.showerror("Request Failed", msg)

        except Exception as e:
            logger.exception("Password-reset request failed unexpectedly.")
            messagebox.showerror(
                "System Error",
                f"Could not submit the reset request.\n\nError: {e}"
            )


class AdminApprovalsWindow:
    def __init__(self, root, admin_username, show_back):
        self.root = root
        self.admin_username = admin_username
        self.show_back = show_back
        self.auth = AuthService()

        self.root.title("Campus Hardware Inventory - Admin Approvals")
        self.root.geometry("900x500")
        self.root.resizable(False, False)

        header = tk.Frame(root, padx=12, pady=10)
        header.pack(fill="x")

        tk.Label(
            header,
            text="Password Reset Request Records",
            font=SECTION_TITLE_FONT
        ).pack(side="left")

        tk.Button(
            header,
            text="Back",
            command=self.show_back,
            width=10
        ).pack(side="right")

        tk.Label(
            root,
            text="Select a PENDING request to approve or reject it.",
            font=SMALL_FONT
        ).pack(pady=(0, 5))

        table_frame = tk.Frame(root)
        table_frame.pack(fill="both", expand=True, padx=12, pady=8)

        scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL)

        self.tree = ttk.Treeview(
            table_frame,
            columns=(
                "ID", "Username", "Email", "Requested At",
                "Status", "Resolved At", "Resolved By"
            ),
            show="headings",
            yscrollcommand=scroll.set
        )

        scroll.config(command=self.tree.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        columns = (
            ("ID", 50),
            ("Username", 120),
            ("Email", 190),
            ("Requested At", 135),
            ("Status", 90),
            ("Resolved At", 135),
            ("Resolved By", 120),
        )

        for col, width in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="center")

        self.tree.tag_configure("pending", background="#FEF3C7")
        self.tree.tag_configure("approved", background="#DCFCE7")
        self.tree.tag_configure("rejected", background="#FEE2E2")

        self.tree.pack(fill="both", expand=True)

        actions = tk.Frame(root, padx=12, pady=8)
        actions.pack(fill="x")

        tk.Button(
            actions,
            text="Approve Selected",
            command=lambda: self.resolve_selected(True),
            bg=SUCCESS_COLOR,
            fg="white",
            width=16
        ).pack(side="left")

        tk.Button(
            actions,
            text="Reject Selected",
            command=lambda: self.resolve_selected(False),
            bg=DANGER_COLOR,
            fg="white",
            width=16
        ).pack(side="left", padx=8)

        tk.Button(
            actions,
            text="Refresh Records",
            command=self.load_data,
            width=16
        ).pack(side="right")

        self.load_data()

    def load_data(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for row in self.auth.get_all_reset_requests():
            status = row[4]

            if status == "PENDING":
                tag = "pending"
            elif status == "APPROVED":
                tag = "approved"
            else:
                tag = "rejected"

            self.tree.insert("", tk.END, values=row, tags=(tag,))

    def resolve_selected(self, approve):
        selected = self.tree.selection()

        if not selected:
            messagebox.showwarning(
                "Selection Warning",
                "Please select a password-reset request first."
            )
            return

        values = self.tree.item(selected[0], "values")
        request_id = values[0]
        request_status = values[4]

        if request_status != "PENDING":
            messagebox.showwarning(
                "Request Already Resolved",
                "Only PENDING password-reset requests can be approved or rejected."
            )
            return

        success, msg = self.auth.resolve_request(
            request_id,
            approve,
            self.admin_username
        )

        if success:
            messagebox.showinfo("Request Resolved", msg)
            self.load_data()
        else:
            messagebox.showerror("Error", msg)


class ProfileWindow:
    def __init__(self, root, username, email, role, show_back):
        self.root = root
        self.username = username
        self.role = role
        self.show_back = show_back
        self.auth = AuthService()

        self.root.title("Campus Hardware Inventory - My Profile & Security")
        self.root.geometry("440x480")
        self.root.resizable(False, False)

        tk.Label(
            root,
            text="My Profile & Security",
            font=TITLE_FONT
        ).pack(pady=(25, 18))

        info = tk.LabelFrame(root, text="Account Information", padx=12, pady=10)
        info.pack(fill="x", padx=30)

        tk.Label(info, text=f"Username: {username}").pack(anchor="w")
        tk.Label(info, text=f"Email: {email or '(none on file)'}").pack(anchor="w")
        tk.Label(info, text=f"Role: {role}").pack(anchor="w")

        change_frame = tk.LabelFrame(root, text="Change Password", padx=12, pady=10)
        change_frame.pack(fill="x", padx=30, pady=(18, 0))

        tk.Label(change_frame, text="Current Password:").pack(anchor="w")
        self.entry_current = tk.Entry(change_frame, show="*", width=32)
        self.entry_current.pack(pady=(2, 10))

        tk.Label(change_frame, text="New Password:").pack(anchor="w")
        self.entry_new = tk.Entry(change_frame, show="*", width=32)
        self.entry_new.pack(pady=(2, 10))

        tk.Label(change_frame, text="Confirm New Password:").pack(anchor="w")
        self.entry_confirm = tk.Entry(change_frame, show="*", width=32)
        self.entry_confirm.pack(pady=(2, 6))

        self.show_password_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            change_frame,
            text="Show Passwords",
            variable=self.show_password_var,
            command=self.toggle_password
        ).pack(anchor="w")

        tk.Button(
            root,
            text="Update Password",
            command=self.handle_change,
            bg=PRIMARY_COLOR,
            fg="white",
            width=18
        ).pack(pady=(18, 8))

        tk.Button(
            root,
            text="Back",
            command=self.show_back,
            width=18
        ).pack()

    def toggle_password(self):
        show = "" if self.show_password_var.get() else "*"
        self.entry_current.config(show=show)
        self.entry_new.config(show=show)
        self.entry_confirm.config(show=show)

    def handle_change(self):
        current_password = self.entry_current.get()
        new_password = self.entry_new.get()
        confirm_password = self.entry_confirm.get()

        success, msg = self.auth.change_password(
            self.username, current_password, new_password, confirm_password
        )

        if success:
            messagebox.showinfo("Password Updated", msg)
            self.entry_current.delete(0, tk.END)
            self.entry_new.delete(0, tk.END)
            self.entry_confirm.delete(0, tk.END)
        else:
            messagebox.showerror("Password Update Failed", msg)


class InventoryService:
    def fetch_all(self, search_text="", category="All"):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        query = """
            SELECT item_id, item_name, category, quantity, unit_price, status
            FROM hardware
        """
        conditions = []
        params = []

        search_text = (search_text or "").strip()

        if search_text:
            conditions.append("(item_name LIKE ? OR category LIKE ?)")
            like_term = f"%{search_text}%"
            params.extend([like_term, like_term])

        if category and category != "All":
            conditions.append("category = ?")
            params.append(category)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY item_id"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        return rows

    def get_categories(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("SELECT DISTINCT category FROM hardware ORDER BY category")
        categories = [row[0] for row in cursor.fetchall()]

        conn.close()
        return categories

    def add_item(self, item_name, category, quantity, unit_price):
        try:
            validated = HardwareSchema(
                item_name=item_name,
                category=category,
                quantity=quantity,
                unit_price=unit_price
            )
        except ValidationError as e:
            msg = e.errors()[0]["msg"]
            logger.warning(f"Inventory validation failed: {msg}")
            return False, f"Validation Error: {msg}"

        # Status is computed in Python before database insertion.
        status = calculate_status(validated.quantity)

        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO hardware
                (item_name, category, quantity, unit_price, status)
                VALUES (?, ?, ?, ?, ?)
            """, (
                validated.item_name,
                validated.category,
                validated.quantity,
                validated.unit_price,
                status
            ))

            conn.commit()
            conn.close()

            logger.info(f"Hardware item added: '{validated.item_name}'")
            return True, "Hardware item added successfully!"

        except sqlite3.Error as e:
            logger.error(f"Hardware insertion error: {e}")
            return False, "Database insertion failed."

    def update_item(self, item_id, item_name, category, quantity, unit_price):
        try:
            validated = HardwareSchema(
                item_name=item_name,
                category=category,
                quantity=quantity,
                unit_price=unit_price
            )
        except ValidationError as e:
            msg = e.errors()[0]["msg"]
            logger.warning(f"Inventory update validation failed: {msg}")
            return False, f"Validation Error: {msg}"

        status = calculate_status(validated.quantity)

        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()

            # Serialize stock changes with borrowing approvals. This prevents
            # an administrator from reducing stock below already committed
            # reservations while another window is approving a request.
            cursor.execute("BEGIN IMMEDIATE")
            committed_quantity = peak_active_commitment(cursor, item_id)

            if validated.quantity < committed_quantity:
                conn.rollback()
                conn.close()
                return (
                    False,
                    "Quantity cannot be lower than the currently committed "
                    f"quantity ({committed_quantity}).",
                )

            cursor.execute("""
                UPDATE hardware
                SET item_name = ?, category = ?, quantity = ?,
                    unit_price = ?, status = ?
                WHERE item_id = ?
            """, (
                validated.item_name,
                validated.category,
                validated.quantity,
                validated.unit_price,
                status,
                item_id
            ))

            conn.commit()
            conn.close()

            logger.info(f"Hardware item updated: ID {item_id}")
            return True, "Hardware item updated successfully!"

        except sqlite3.Error as e:
            logger.error(f"Hardware update error: {e}")
            return False, "Database update failed."

    def delete_item(self, item_id):
        try:
            conn = sqlite3.connect(DB_NAME)
            conn.execute("PRAGMA foreign_keys = ON")
            cursor = conn.cursor()

            cursor.execute("BEGIN IMMEDIATE")
            cursor.execute("""
                SELECT COUNT(*)
                FROM asset_transactions
                WHERE item_id = ?
                  AND status IN (
                      'PENDING', 'APPROVED', 'BORROWED', 'OVERDUE'
                  )
            """, (item_id,))

            if cursor.fetchone()[0] > 0:
                conn.rollback()
                conn.close()
                return (
                    False,
                    "This item has an open borrowing request or active loan "
                    "and cannot be deleted.",
                )

            cursor.execute(
                "DELETE FROM hardware WHERE item_id = ?",
                (item_id,)
            )

            conn.commit()
            conn.close()

            logger.info(f"Hardware item deleted: ID {item_id}")
            return True, "Hardware item deleted successfully!"

        except sqlite3.Error as e:
            logger.error(f"Hardware deletion error: {e}")
            return False, "Failed to delete hardware item."

    def total_value(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT COALESCE(SUM(quantity * unit_price), 0) FROM hardware"
        )

        total = cursor.fetchone()[0]
        conn.close()
        return float(total)

    def export_csv(self, search_text="", category="All"):
        try:
            rows = self.fetch_all(search_text, category)

            with open(
                CSV_REPORT,
                "w",
                newline="",
                encoding="utf-8"
            ) as file:
                writer = csv.writer(file)
                writer.writerow(
                    ["ID", "Name", "Category", "Qty", "Price ($)", "Status"]
                )
                writer.writerows(rows)

            logger.info(f"Inventory report generated: {CSV_REPORT}")
            return True, f"Inventory exported to {CSV_REPORT}."

        except (OSError, sqlite3.Error) as e:
            logger.error(f"Inventory report generation failed: {e}")
            return False, "Failed to generate inventory report."


class AssetTrackingService:
    """Database operations for the automated borrowing/return logbook."""

    def _connect(self):
        conn = sqlite3.connect(DB_NAME, timeout=15)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _refresh_overdue_conn(self, cursor):
        today = datetime.now().strftime(DATE_FORMAT)
        cursor.execute("""
            UPDATE asset_transactions
            SET status = 'OVERDUE'
            WHERE status = 'BORROWED'
              AND expected_return_date < ?
        """, (today,))
        return cursor.rowcount

    def refresh_overdue(self):
        conn = None

        try:
            conn = self._connect()
            cursor = conn.cursor()
            changed = self._refresh_overdue_conn(cursor)
            conn.commit()

            if changed:
                logger.warning(
                    f"{changed} asset transaction(s) marked overdue."
                )

            return changed

        except sqlite3.Error as e:
            if conn is not None:
                conn.rollback()
            logger.error(f"Overdue refresh failed: {e}")
            return 0

        finally:
            if conn is not None:
                conn.close()

    def _get_actor(self, cursor, username):
        cursor.execute(
            "SELECT id, username, role FROM users WHERE username = ?",
            ((username or "").strip(),)
        )
        return cursor.fetchone()

    def _require_admin(self, cursor, admin_username):
        actor = self._get_actor(cursor, admin_username)
        return actor if actor and actor[2] == "ADMIN" else None

    def _validate_schedule(
        self,
        start_date,
        expected_return_date,
        require_today_or_later=True
    ):
        start_text = (start_date or "").strip()
        end_text = (expected_return_date or "").strip()

        try:
            start_value = datetime.strptime(
                start_text, DATE_FORMAT
            ).date()
            end_value = datetime.strptime(
                end_text, DATE_FORMAT
            ).date()
        except ValueError:
            return (
                False,
                "Dates must use YYYY-MM-DD format (example: 2026-09-03).",
                None,
                None,
            )

        # strptime accepts some non-zero-padded values; normalize them so
        # SQLite's text date comparisons remain reliable.
        start_text = start_value.strftime(DATE_FORMAT)
        end_text = end_value.strftime(DATE_FORMAT)

        if end_value < start_value:
            return (
                False,
                "Expected return date cannot be earlier than the start date.",
                None,
                None,
            )

        if require_today_or_later and start_value < datetime.now().date():
            return (
                False,
                "Start date cannot be earlier than today.",
                None,
                None,
            )

        return True, "", start_text, end_text

    def _availability_conn(
        self,
        cursor,
        item_id,
        start_date,
        expected_return_date,
        exclude_transaction_id=None
    ):
        cursor.execute("""
            SELECT item_name, quantity
            FROM hardware
            WHERE item_id = ?
        """, (item_id,))
        item = cursor.fetchone()

        if not item:
            return None

        item_name, total_quantity = item
        query = """
            SELECT COALESCE(SUM(quantity), 0)
            FROM asset_transactions
            WHERE item_id = ?
              AND (
                    status = 'OVERDUE'
                    OR (
                        status IN ('APPROVED', 'BORROWED')
                        AND start_date <= ?
                        AND expected_return_date >= ?
                    )
              )
        """
        params = [item_id, expected_return_date, start_date]

        if exclude_transaction_id is not None:
            query += " AND transaction_id <> ?"
            params.append(exclude_transaction_id)

        cursor.execute(query, params)
        committed = int(cursor.fetchone()[0] or 0)
        available = max(0, int(total_quantity) - committed)

        return {
            "item_name": item_name,
            "total": int(total_quantity),
            "committed": committed,
            "available": available,
        }

    def availability_for_period(
        self,
        item_id,
        start_date,
        expected_return_date
    ):
        valid, msg, start_text, end_text = self._validate_schedule(
            start_date,
            expected_return_date,
            require_today_or_later=False
        )

        if not valid:
            return False, msg, None

        conn = None

        try:
            conn = self._connect()
            cursor = conn.cursor()
            self._refresh_overdue_conn(cursor)
            details = self._availability_conn(
                cursor, item_id, start_text, end_text
            )
            conn.commit()

            if details is None:
                return False, "The selected equipment no longer exists.", None

            return True, "", details

        except sqlite3.Error as e:
            if conn is not None:
                conn.rollback()
            logger.error(f"Availability check failed: {e}")
            return False, "Could not check equipment availability.", None

        finally:
            if conn is not None:
                conn.close()

    def list_equipment(self):
        """Return total, currently committed, and currently available units."""
        conn = None

        try:
            conn = self._connect()
            cursor = conn.cursor()
            self._refresh_overdue_conn(cursor)
            today = datetime.now().strftime(DATE_FORMAT)

            cursor.execute("""
                SELECT item_id, item_name, category, quantity, status
                FROM hardware
                ORDER BY LOWER(item_name), item_id
            """)
            items = cursor.fetchall()
            results = []

            for item_id, item_name, category, total, stock_status in items:
                cursor.execute("""
                    SELECT COALESCE(SUM(quantity), 0)
                    FROM asset_transactions
                    WHERE item_id = ?
                      AND (
                            status IN ('BORROWED', 'OVERDUE')
                            OR (
                                status = 'APPROVED'
                                AND start_date <= ?
                                AND expected_return_date >= ?
                            )
                      )
                """, (item_id, today, today))
                committed = int(cursor.fetchone()[0] or 0)
                available = max(0, int(total) - committed)

                if available == 0:
                    availability_status = "Unavailable"
                elif available <= 5:
                    availability_status = "Limited"
                else:
                    availability_status = "Available"

                results.append((
                    item_id,
                    item_name,
                    category,
                    int(total),
                    committed,
                    available,
                    availability_status,
                    stock_status,
                ))

            conn.commit()
            return results

        except sqlite3.Error as e:
            if conn is not None:
                conn.rollback()
            logger.error(f"Equipment availability listing failed: {e}")
            return []

        finally:
            if conn is not None:
                conn.close()

    def submit_request(
        self,
        username,
        item_id,
        quantity,
        purpose,
        start_date,
        expected_return_date
    ):
        try:
            item_id = int(item_id)
            quantity = int(quantity)
        except (TypeError, ValueError):
            return False, "Equipment and quantity must be valid whole numbers."

        if quantity <= 0:
            return False, "Requested quantity must be at least 1."

        purpose = (purpose or "").strip()

        if not purpose:
            return False, "Please enter the laboratory, project, or purpose."

        if len(purpose) > 500:
            return False, "Purpose must not exceed 500 characters."

        valid, msg, start_text, end_text = self._validate_schedule(
            start_date, expected_return_date
        )

        if not valid:
            return False, msg

        conn = None

        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            self._refresh_overdue_conn(cursor)
            actor = self._get_actor(cursor, username)

            if not actor:
                conn.rollback()
                return False, "Your account could not be found."

            user_id, canonical_username, _role = actor
            availability = self._availability_conn(
                cursor, item_id, start_text, end_text
            )

            if availability is None:
                conn.rollback()
                return False, "The selected equipment no longer exists."

            if quantity > availability["available"]:
                conn.rollback()
                return (
                    False,
                    f"Only {availability['available']} unit(s) of "
                    f"{availability['item_name']} are available for those "
                    "dates.",
                )

            cursor.execute("""
                SELECT transaction_id
                FROM asset_transactions
                WHERE user_id = ?
                  AND item_id = ?
                  AND quantity = ?
                  AND purpose = ?
                  AND start_date = ?
                  AND expected_return_date = ?
                  AND status = 'PENDING'
            """, (
                user_id,
                item_id,
                quantity,
                purpose,
                start_text,
                end_text,
            ))

            if cursor.fetchone():
                conn.rollback()
                return False, "An identical request is already pending."

            cursor.execute("""
                INSERT INTO asset_transactions (
                    user_id,
                    borrower_username,
                    item_id,
                    item_name_snapshot,
                    quantity,
                    purpose,
                    start_date,
                    expected_return_date,
                    requested_at,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')
            """, (
                user_id,
                canonical_username,
                item_id,
                availability["item_name"],
                quantity,
                purpose,
                start_text,
                end_text,
                now_str(),
            ))
            transaction_id = cursor.lastrowid
            conn.commit()

            logger.info(
                f"Asset request #{transaction_id} submitted by "
                f"'{canonical_username}' for item ID {item_id}, "
                f"quantity={quantity}, dates={start_text}..{end_text}."
            )
            return (
                True,
                f"Borrowing request #{transaction_id} was submitted for "
                "administrator review.",
            )

        except sqlite3.Error as e:
            if conn is not None:
                conn.rollback()
            logger.error(f"Asset request submission failed: {e}")
            return False, "The borrowing request could not be saved."

        finally:
            if conn is not None:
                conn.close()

    def approve_request(self, transaction_id, admin_username):
        conn = None

        try:
            transaction_id = int(transaction_id)
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")

            if not self._require_admin(cursor, admin_username):
                conn.rollback()
                logger.warning(
                    f"Unauthorized asset approval attempt by "
                    f"'{admin_username}'."
                )
                return False, "Administrator permission is required."

            self._refresh_overdue_conn(cursor)
            cursor.execute("""
                SELECT item_id, item_name_snapshot, quantity,
                       start_date, expected_return_date, status
                FROM asset_transactions
                WHERE transaction_id = ?
            """, (transaction_id,))
            request = cursor.fetchone()

            if not request:
                conn.rollback()
                return False, "Borrowing request not found."

            (
                item_id,
                item_name,
                quantity,
                start_date,
                end_date,
                status,
            ) = request

            if status != "PENDING":
                conn.rollback()
                return (
                    False,
                    f"Only PENDING requests can be approved "
                    f"(current status: {status}).",
                )

            if item_id is None:
                conn.rollback()
                return False, "The requested equipment was deleted."

            today = datetime.now().strftime(DATE_FORMAT)

            if end_date < today:
                conn.rollback()
                return (
                    False,
                    "This request has expired because its expected return "
                    f"date was {end_date}.",
                )

            availability = self._availability_conn(
                cursor,
                item_id,
                start_date,
                end_date,
                exclude_transaction_id=transaction_id
            )

            if availability is None:
                conn.rollback()
                return False, "The requested equipment no longer exists."

            if quantity > availability["available"]:
                conn.rollback()
                return (
                    False,
                    f"Conflict prevented: only "
                    f"{availability['available']} unit(s) of {item_name} "
                    "remain available for the requested dates.",
                )

            cursor.execute("""
                UPDATE asset_transactions
                SET status = 'APPROVED',
                    approved_at = ?,
                    approved_by = ?
                WHERE transaction_id = ?
                  AND status = 'PENDING'
            """, (now_str(), admin_username, transaction_id))

            if cursor.rowcount != 1:
                conn.rollback()
                return False, "The request changed before it was approved."

            conn.commit()
            logger.info(
                f"Asset request #{transaction_id} approved by "
                f"'{admin_username}'."
            )
            return True, f"Request #{transaction_id} approved."

        except (TypeError, ValueError):
            return False, "Invalid transaction ID."

        except sqlite3.Error as e:
            if conn is not None:
                conn.rollback()
            logger.error(f"Asset approval failed: {e}")
            return False, "The request could not be approved."

        finally:
            if conn is not None:
                conn.close()

    def reject_request(self, transaction_id, admin_username):
        conn = None

        try:
            transaction_id = int(transaction_id)
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")

            if not self._require_admin(cursor, admin_username):
                conn.rollback()
                logger.warning(
                    f"Unauthorized asset rejection attempt by "
                    f"'{admin_username}'."
                )
                return False, "Administrator permission is required."

            cursor.execute("""
                UPDATE asset_transactions
                SET status = 'REJECTED',
                    rejected_at = ?,
                    rejected_by = ?
                WHERE transaction_id = ?
                  AND status = 'PENDING'
            """, (now_str(), admin_username, transaction_id))

            if cursor.rowcount != 1:
                conn.rollback()
                return (
                    False,
                    "Only an existing PENDING request can be rejected.",
                )

            conn.commit()
            logger.info(
                f"Asset request #{transaction_id} rejected by "
                f"'{admin_username}'."
            )
            return True, f"Request #{transaction_id} rejected."

        except (TypeError, ValueError):
            return False, "Invalid transaction ID."

        except sqlite3.Error as e:
            if conn is not None:
                conn.rollback()
            logger.error(f"Asset rejection failed: {e}")
            return False, "The request could not be rejected."

        finally:
            if conn is not None:
                conn.close()

    def issue_equipment(self, transaction_id, admin_username):
        conn = None

        try:
            transaction_id = int(transaction_id)
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")

            if not self._require_admin(cursor, admin_username):
                conn.rollback()
                logger.warning(
                    f"Unauthorized equipment issue attempt by "
                    f"'{admin_username}'."
                )
                return False, "Administrator permission is required."

            cursor.execute("""
                SELECT start_date, status
                FROM asset_transactions
                WHERE transaction_id = ?
            """, (transaction_id,))
            row = cursor.fetchone()

            if not row:
                conn.rollback()
                return False, "Borrowing request not found."

            start_date, status = row

            if status != "APPROVED":
                conn.rollback()
                return (
                    False,
                    f"Only APPROVED requests can be released "
                    f"(current status: {status}).",
                )

            today = datetime.now().strftime(DATE_FORMAT)

            if start_date > today:
                conn.rollback()
                return (
                    False,
                    f"This reservation starts on {start_date}; it cannot be "
                    "released early.",
                )

            cursor.execute("""
                UPDATE asset_transactions
                SET status = 'BORROWED',
                    issued_at = ?,
                    issued_by = ?
                WHERE transaction_id = ?
                  AND status = 'APPROVED'
            """, (now_str(), admin_username, transaction_id))

            if cursor.rowcount != 1:
                conn.rollback()
                return False, "The request changed before release."

            conn.commit()
            logger.info(
                f"Equipment for request #{transaction_id} released by "
                f"'{admin_username}'."
            )
            return True, f"Equipment for request #{transaction_id} released."

        except (TypeError, ValueError):
            return False, "Invalid transaction ID."

        except sqlite3.Error as e:
            if conn is not None:
                conn.rollback()
            logger.error(f"Equipment release failed: {e}")
            return False, "The equipment could not be released."

        finally:
            if conn is not None:
                conn.close()

    def return_equipment(self, transaction_id, admin_username):
        conn = None

        try:
            transaction_id = int(transaction_id)
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")

            if not self._require_admin(cursor, admin_username):
                conn.rollback()
                logger.warning(
                    f"Unauthorized return attempt by '{admin_username}'."
                )
                return False, "Administrator permission is required."

            self._refresh_overdue_conn(cursor)
            cursor.execute("""
                UPDATE asset_transactions
                SET status = 'RETURNED',
                    returned_at = ?,
                    returned_by = ?
                WHERE transaction_id = ?
                  AND status IN ('BORROWED', 'OVERDUE')
            """, (now_str(), admin_username, transaction_id))

            if cursor.rowcount != 1:
                conn.rollback()
                return (
                    False,
                    "Only BORROWED or OVERDUE equipment can be returned.",
                )

            conn.commit()
            logger.info(
                f"Equipment for request #{transaction_id} returned to "
                f"'{admin_username}'."
            )
            return True, f"Request #{transaction_id} marked RETURNED."

        except (TypeError, ValueError):
            return False, "Invalid transaction ID."

        except sqlite3.Error as e:
            if conn is not None:
                conn.rollback()
            logger.error(f"Equipment return failed: {e}")
            return False, "The return could not be recorded."

        finally:
            if conn is not None:
                conn.close()

    def cancel_request(self, transaction_id, username):
        conn = None

        try:
            transaction_id = int(transaction_id)
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            actor = self._get_actor(cursor, username)

            if not actor:
                conn.rollback()
                return False, "Your account could not be found."

            cursor.execute("""
                UPDATE asset_transactions
                SET status = 'CANCELLED',
                    cancelled_at = ?
                WHERE transaction_id = ?
                  AND user_id = ?
                  AND status = 'PENDING'
            """, (now_str(), transaction_id, actor[0]))

            if cursor.rowcount != 1:
                conn.rollback()
                return False, "Only your own PENDING request can be cancelled."

            conn.commit()
            logger.info(
                f"Asset request #{transaction_id} cancelled by "
                f"'{actor[1]}'."
            )
            return True, f"Request #{transaction_id} cancelled."

        except (TypeError, ValueError):
            return False, "Invalid transaction ID."

        except sqlite3.Error as e:
            if conn is not None:
                conn.rollback()
            logger.error(f"Asset cancellation failed: {e}")
            return False, "The request could not be cancelled."

        finally:
            if conn is not None:
                conn.close()

    def list_transactions(
        self,
        requester_username,
        all_records=False,
        status_filter="All"
    ):
        conn = None

        try:
            conn = self._connect()
            cursor = conn.cursor()
            self._refresh_overdue_conn(cursor)
            actor = self._get_actor(cursor, requester_username)

            if not actor:
                conn.rollback()
                return []

            if all_records and actor[2] != "ADMIN":
                logger.warning(
                    f"Unauthorized all-records view attempted by "
                    f"'{requester_username}'."
                )
                conn.rollback()
                return []

            query = """
                SELECT transaction_id,
                       borrower_username,
                       item_name_snapshot,
                       quantity,
                       purpose,
                       start_date,
                       expected_return_date,
                       requested_at,
                       approved_at,
                       approved_by,
                       issued_at,
                       issued_by,
                       returned_at,
                       returned_by,
                       rejected_at,
                       rejected_by,
                       cancelled_at,
                       status
                FROM asset_transactions
            """
            conditions = []
            params = []

            if not all_records:
                conditions.append("user_id = ?")
                params.append(actor[0])

            allowed_statuses = (
                "PENDING",
                "APPROVED",
                "REJECTED",
                "BORROWED",
                "OVERDUE",
                "RETURNED",
                "CANCELLED",
            )

            if status_filter in allowed_statuses:
                conditions.append("status = ?")
                params.append(status_filter)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY transaction_id DESC"
            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.commit()
            return rows

        except sqlite3.Error as e:
            if conn is not None:
                conn.rollback()
            logger.error(f"Asset transaction listing failed: {e}")
            return []

        finally:
            if conn is not None:
                conn.close()

    def export_transactions(
        self,
        requester_username,
        all_records=False,
        status_filter="All"
    ):
        conn = None

        try:
            conn = self._connect()
            cursor = conn.cursor()
            actor = self._get_actor(cursor, requester_username)

            if not actor:
                return False, "Your account could not be found."

            if all_records and actor[2] != "ADMIN":
                logger.warning(
                    f"Unauthorized transaction export attempted by "
                    f"'{requester_username}'."
                )
                return False, "Administrator permission is required."

        except sqlite3.Error as e:
            logger.error(f"Transaction export authorization failed: {e}")
            return False, "The report could not be generated."

        finally:
            if conn is not None:
                conn.close()

        try:
            rows = self.list_transactions(
                requester_username,
                all_records=all_records,
                status_filter=status_filter
            )

            with open(
                ASSET_REPORT,
                "w",
                newline="",
                encoding="utf-8"
            ) as file:
                writer = csv.writer(file)
                writer.writerow([
                    "Transaction ID",
                    "Borrower",
                    "Equipment",
                    "Quantity",
                    "Purpose / Laboratory",
                    "Start Date",
                    "Expected Return",
                    "Requested At",
                    "Approved At",
                    "Approved By",
                    "Issued At",
                    "Issued By",
                    "Returned At",
                    "Returned By",
                    "Rejected At",
                    "Rejected By",
                    "Cancelled At",
                    "Status",
                ])
                writer.writerows(rows)

            logger.info(
                f"Asset tracking report generated by "
                f"'{requester_username}': {ASSET_REPORT}"
            )
            return True, f"Asset transactions exported to {ASSET_REPORT}."

        except (OSError, sqlite3.Error) as e:
            logger.error(f"Asset report generation failed: {e}")
            return False, "Failed to generate the asset tracking report."


class EditItemDialog:
    def __init__(self, parent, service, item, on_saved):
        self.service = service
        self.on_saved = on_saved

        item_id, name, category, qty, price, status = item
        self.item_id = item_id

        self.win = tk.Toplevel(parent)
        self.win.title(f"Edit Hardware Item #{item_id}")
        self.win.geometry("360x300")
        self.win.resizable(False, False)
        self.win.grab_set()

        tk.Label(self.win, text="Item Name:").pack(anchor="w", padx=25, pady=(15, 0))
        self.entry_name = tk.Entry(self.win, width=32)
        self.entry_name.insert(0, name)
        self.entry_name.pack(padx=25, pady=(2, 8))

        tk.Label(self.win, text="Category:").pack(anchor="w", padx=25)
        self.entry_category = tk.Entry(self.win, width=32)
        self.entry_category.insert(0, category)
        self.entry_category.pack(padx=25, pady=(2, 8))

        tk.Label(self.win, text="Quantity:").pack(anchor="w", padx=25)
        self.entry_qty = tk.Entry(self.win, width=32)
        self.entry_qty.insert(0, str(qty))
        self.entry_qty.pack(padx=25, pady=(2, 8))

        tk.Label(self.win, text="Unit Price ($):").pack(anchor="w", padx=25)
        self.entry_price = tk.Entry(self.win, width=32)
        self.entry_price.insert(0, str(price))
        self.entry_price.pack(padx=25, pady=(2, 12))

        btn_frame = tk.Frame(self.win)
        btn_frame.pack()

        tk.Button(
            btn_frame,
            text="Save Changes",
            command=self.handle_save,
            bg=SUCCESS_COLOR,
            fg="white",
            width=14
        ).pack(side="left", padx=6)

        tk.Button(
            btn_frame,
            text="Cancel",
            command=self.win.destroy,
            width=14
        ).pack(side="left", padx=6)

    def handle_save(self):
        try:
            quantity = int(self.entry_qty.get().strip())
        except ValueError:
            messagebox.showerror("Validation Error", "Quantity must be a whole number.")
            return

        try:
            unit_price = float(self.entry_price.get().strip())
        except ValueError:
            messagebox.showerror("Validation Error", "Unit Price must be a number.")
            return

        success, msg = self.service.update_item(
            self.item_id,
            self.entry_name.get().strip(),
            self.entry_category.get().strip(),
            quantity,
            unit_price
        )

        if success:
            messagebox.showinfo("Success", msg)
            self.win.destroy()
            self.on_saved()
        else:
            messagebox.showerror("Validation Error", msg)


class BorrowRequestDialog:
    def __init__(self, parent, username, on_saved):
        self.username = username
        self.on_saved = on_saved
        self.service = AssetTrackingService()

        self.win = tk.Toplevel(parent)
        self.win.title("Request Engineering Laboratory Equipment")
        self.win.geometry("900x650")
        self.win.minsize(820, 600)
        self.win.transient(parent)
        self.win.grab_set()

        tk.Label(
            self.win,
            text="New Equipment Borrowing Request",
            font=SECTION_TITLE_FONT
        ).pack(anchor="w", padx=14, pady=(12, 2))

        tk.Label(
            self.win,
            text=(
                "Select equipment, enter the required dates, and submit the "
                "request for administrator approval."
            )
        ).pack(anchor="w", padx=14, pady=(0, 8))

        equipment_frame = tk.LabelFrame(
            self.win,
            text="Equipment Availability Today",
            padx=8,
            pady=8
        )
        equipment_frame.pack(fill="both", expand=True, padx=14, pady=6)

        equipment_scroll = ttk.Scrollbar(
            equipment_frame, orient=tk.VERTICAL
        )
        self.equipment_tree = ttk.Treeview(
            equipment_frame,
            columns=(
                "ID",
                "Equipment",
                "Category",
                "Total",
                "Committed",
                "Available",
                "Availability",
            ),
            show="headings",
            height=9,
            yscrollcommand=equipment_scroll.set
        )
        equipment_scroll.config(command=self.equipment_tree.yview)
        equipment_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        headings = {
            "ID": "ID",
            "Equipment": "Equipment",
            "Category": "Category",
            "Total": "Total",
            "Committed": "Reserved / Out",
            "Available": "Available",
            "Availability": "Status",
        }

        for column, text in headings.items():
            self.equipment_tree.heading(column, text=text)

        self.equipment_tree.column("ID", width=55, anchor="center")
        self.equipment_tree.column("Equipment", width=220)
        self.equipment_tree.column("Category", width=150)
        self.equipment_tree.column("Total", width=75, anchor="center")
        self.equipment_tree.column(
            "Committed", width=105, anchor="center"
        )
        self.equipment_tree.column(
            "Available", width=85, anchor="center"
        )
        self.equipment_tree.column("Availability", width=100, anchor="center")
        self.equipment_tree.tag_configure(
            "unavailable", background="#FEE2E2"
        )
        self.equipment_tree.tag_configure("limited", background="#FEF3C7")
        self.equipment_tree.tag_configure("available", background="#DCFCE7")
        self.equipment_tree.pack(fill="both", expand=True)

        request_frame = tk.LabelFrame(
            self.win,
            text="Request Details",
            padx=10,
            pady=10
        )
        request_frame.pack(fill="x", padx=14, pady=6)

        tk.Label(request_frame, text="Quantity:").grid(
            row=0, column=0, sticky="e", padx=4, pady=5
        )
        self.quantity_entry = tk.Entry(request_frame, width=12)
        self.quantity_entry.insert(0, "1")
        self.quantity_entry.grid(
            row=0, column=1, sticky="w", padx=4, pady=5
        )

        today = datetime.now().strftime(DATE_FORMAT)

        tk.Label(request_frame, text="Start Date:").grid(
            row=0, column=2, sticky="e", padx=4, pady=5
        )
        self.start_entry = tk.Entry(request_frame, width=14)
        self.start_entry.insert(0, today)
        self.start_entry.grid(
            row=0, column=3, sticky="w", padx=4, pady=5
        )

        tk.Label(request_frame, text="Expected Return:").grid(
            row=0, column=4, sticky="e", padx=4, pady=5
        )
        self.return_entry = tk.Entry(request_frame, width=14)
        self.return_entry.insert(0, today)
        self.return_entry.grid(
            row=0, column=5, sticky="w", padx=4, pady=5
        )

        tk.Label(
            request_frame,
            text="Use YYYY-MM-DD for both dates."
        ).grid(row=1, column=2, columnspan=4, sticky="w", padx=4)

        tk.Label(
            request_frame,
            text="Laboratory / Project / Purpose:"
        ).grid(row=2, column=0, sticky="ne", padx=4, pady=(10, 4))
        self.purpose_text = tk.Text(
            request_frame, width=70, height=4, wrap="word"
        )
        self.purpose_text.grid(
            row=2, column=1, columnspan=5, sticky="ew", padx=4, pady=(10, 4)
        )
        request_frame.grid_columnconfigure(5, weight=1)

        self.availability_label = tk.Label(
            request_frame,
            text="Availability is rechecked atomically when an admin approves.",
            fg="#333366"
        )
        self.availability_label.grid(
            row=3, column=0, columnspan=6, sticky="w", padx=4, pady=(6, 0)
        )

        buttons = tk.Frame(self.win)
        buttons.pack(fill="x", padx=14, pady=(4, 12))

        tk.Button(
            buttons,
            text="Check Selected Dates",
            command=self.check_availability,
            bg=PRIMARY_COLOR,
            fg="white",
            width=20
        ).pack(side="left")

        tk.Button(
            buttons,
            text="Submit Request",
            command=self.submit,
            bg=SUCCESS_COLOR,
            fg="white",
            width=18
        ).pack(side="right")

        tk.Button(
            buttons,
            text="Cancel",
            command=self.win.destroy,
            width=12
        ).pack(side="right", padx=8)

        self.load_equipment()

    def load_equipment(self):
        for row_id in self.equipment_tree.get_children():
            self.equipment_tree.delete(row_id)

        for row in self.service.list_equipment():
            (
                item_id,
                name,
                category,
                total,
                committed,
                available,
                availability_status,
                _stock_status,
            ) = row
            tag = availability_status.lower()
            self.equipment_tree.insert(
                "",
                tk.END,
                values=(
                    item_id,
                    name,
                    category,
                    total,
                    committed,
                    available,
                    availability_status,
                ),
                tags=(tag,)
            )

    def _selected_item_id(self):
        selected = self.equipment_tree.selection()

        if not selected:
            messagebox.showwarning(
                "Selection Required",
                "Please select an equipment item.",
                parent=self.win
            )
            return None

        return int(self.equipment_tree.item(selected[0], "values")[0])

    def check_availability(self):
        item_id = self._selected_item_id()

        if item_id is None:
            return

        success, msg, details = self.service.availability_for_period(
            item_id,
            self.start_entry.get(),
            self.return_entry.get()
        )

        if not success:
            messagebox.showerror(
                "Availability Check", msg, parent=self.win
            )
            return

        self.availability_label.config(
            text=(
                f"{details['item_name']}: {details['available']} available "
                f"of {details['total']} total for the selected dates "
                f"({details['committed']} already committed)."
            )
        )

    def submit(self):
        item_id = self._selected_item_id()

        if item_id is None:
            return

        success, msg = self.service.submit_request(
            self.username,
            item_id,
            self.quantity_entry.get().strip(),
            self.purpose_text.get("1.0", tk.END).strip(),
            self.start_entry.get().strip(),
            self.return_entry.get().strip()
        )

        if success:
            messagebox.showinfo("Request Submitted", msg, parent=self.win)
            self.on_saved()
            self.win.destroy()
        else:
            messagebox.showerror("Request Failed", msg, parent=self.win)


class AssetTrackingWindow:
    def __init__(self, parent, username, role):
        self.username = username
        self.role = role
        self.is_admin = (role == "ADMIN")
        self.service = AssetTrackingService()
        self._after_id = None

        self.win = tk.Toplevel(parent)
        self.win.title("Engineering Laboratory Asset Tracking")
        self.win.geometry("1240x760")
        self.win.minsize(1050, 680)
        self.win.transient(parent)
        self.win.protocol("WM_DELETE_WINDOW", self.close)

        header = tk.Frame(self.win, padx=12, pady=10)
        header.pack(fill="x")

        tk.Label(
            header,
            text=(
                "Engineering Laboratory Asset Tracking "
                f"({username} - {role})"
            ),
            font=SECTION_TITLE_FONT
        ).pack(side="left")

        tk.Button(
            header,
            text="Request Equipment",
            command=self.open_request_dialog,
            bg=SUCCESS_COLOR,
            fg="white",
            width=18
        ).pack(side="right", padx=4)

        availability_frame = tk.LabelFrame(
            self.win,
            text="Live Equipment Availability",
            padx=8,
            pady=8
        )
        availability_frame.pack(fill="x", padx=12, pady=4)

        availability_scroll = ttk.Scrollbar(
            availability_frame, orient=tk.VERTICAL
        )
        self.availability_tree = ttk.Treeview(
            availability_frame,
            columns=(
                "ID",
                "Equipment",
                "Category",
                "Total",
                "Committed",
                "Available",
                "Status",
            ),
            show="headings",
            height=5,
            yscrollcommand=availability_scroll.set
        )
        availability_scroll.config(command=self.availability_tree.yview)
        availability_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        availability_headings = {
            "ID": "ID",
            "Equipment": "Equipment",
            "Category": "Category",
            "Total": "Total Owned",
            "Committed": "Reserved / Out",
            "Available": "Available Now",
            "Status": "Availability",
        }

        for column, text in availability_headings.items():
            self.availability_tree.heading(column, text=text)

        self.availability_tree.column("ID", width=55, anchor="center")
        self.availability_tree.column("Equipment", width=240)
        self.availability_tree.column("Category", width=160)
        self.availability_tree.column("Total", width=95, anchor="center")
        self.availability_tree.column(
            "Committed", width=105, anchor="center"
        )
        self.availability_tree.column(
            "Available", width=105, anchor="center"
        )
        self.availability_tree.column("Status", width=110, anchor="center")
        self.availability_tree.tag_configure(
            "unavailable", background="#FEE2E2"
        )
        self.availability_tree.tag_configure(
            "limited", background="#FEF3C7"
        )
        self.availability_tree.tag_configure(
            "available", background="#DCFCE7"
        )
        self.availability_tree.pack(fill="x")

        transaction_frame = tk.LabelFrame(
            self.win,
            text=(
                "All Borrowing Transactions"
                if self.is_admin
                else "My Borrowing Records"
            ),
            padx=8,
            pady=8
        )
        transaction_frame.pack(
            fill="both", expand=True, padx=12, pady=(6, 4)
        )

        filter_bar = tk.Frame(transaction_frame)
        filter_bar.pack(fill="x", pady=(0, 6))

        tk.Label(filter_bar, text="Status:").pack(side="left")
        self.status_var = tk.StringVar(value="All")
        self.status_combo = ttk.Combobox(
            filter_bar,
            textvariable=self.status_var,
            values=(
                "All",
                "PENDING",
                "APPROVED",
                "BORROWED",
                "OVERDUE",
                "RETURNED",
                "REJECTED",
                "CANCELLED",
            ),
            state="readonly",
            width=14
        )
        self.status_combo.pack(side="left", padx=5)
        self.status_combo.bind(
            "<<ComboboxSelected>>", lambda _event: self.load_all()
        )

        tk.Button(
            filter_bar,
            text="Refresh",
            command=self.load_all,
            width=10
        ).pack(side="left", padx=4)

        self.summary_label = tk.Label(
            filter_bar, text="", font=("Segoe UI Semibold", 10)
        )
        self.summary_label.pack(side="left", padx=14)

        tk.Button(
            filter_bar,
            text="Export Asset Report",
            command=self.export_report,
            bg=PRIMARY_COLOR,
            fg="white",
            width=18
        ).pack(side="right")

        table_area = tk.Frame(transaction_frame)
        table_area.pack(fill="both", expand=True)
        vertical_scroll = ttk.Scrollbar(table_area, orient=tk.VERTICAL)
        horizontal_scroll = ttk.Scrollbar(
            table_area, orient=tk.HORIZONTAL
        )

        self.transaction_tree = ttk.Treeview(
            table_area,
            columns=(
                "ID",
                "Borrower",
                "Equipment",
                "Qty",
                "Purpose",
                "Start",
                "Due",
                "Requested",
                "ApprovedBy",
                "Status",
            ),
            show="headings",
            yscrollcommand=vertical_scroll.set,
            xscrollcommand=horizontal_scroll.set
        )
        vertical_scroll.config(command=self.transaction_tree.yview)
        horizontal_scroll.config(command=self.transaction_tree.xview)
        vertical_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        horizontal_scroll.pack(side=tk.BOTTOM, fill=tk.X)

        transaction_headings = {
            "ID": "Transaction",
            "Borrower": "Borrower",
            "Equipment": "Equipment",
            "Qty": "Qty",
            "Purpose": "Laboratory / Project / Purpose",
            "Start": "Start",
            "Due": "Expected Return",
            "Requested": "Requested At",
            "ApprovedBy": "Approved By",
            "Status": "Status",
        }

        for column, text in transaction_headings.items():
            self.transaction_tree.heading(column, text=text)

        self.transaction_tree.column("ID", width=85, anchor="center")
        self.transaction_tree.column("Borrower", width=110)
        self.transaction_tree.column("Equipment", width=180)
        self.transaction_tree.column("Qty", width=50, anchor="center")
        self.transaction_tree.column("Purpose", width=260)
        self.transaction_tree.column("Start", width=95, anchor="center")
        self.transaction_tree.column("Due", width=110, anchor="center")
        self.transaction_tree.column("Requested", width=145)
        self.transaction_tree.column("ApprovedBy", width=100)
        self.transaction_tree.column("Status", width=95, anchor="center")
        self.transaction_tree.tag_configure(
            "PENDING", background="#F1F5F9"
        )
        self.transaction_tree.tag_configure(
            "APPROVED", background="#DBEAFE"
        )
        self.transaction_tree.tag_configure(
            "BORROWED", background="#FEF3C7"
        )
        self.transaction_tree.tag_configure(
            "OVERDUE", background="#FEE2E2"
        )
        self.transaction_tree.tag_configure(
            "RETURNED", background="#DCFCE7"
        )
        self.transaction_tree.pack(fill="both", expand=True)

        actions = tk.Frame(self.win, padx=12, pady=8)
        actions.pack(fill="x")

        if self.is_admin:
            tk.Button(
                actions,
                text="Approve Pending",
                command=lambda: self.admin_action("approve"),
                bg=SUCCESS_COLOR,
                fg="white",
                width=16
            ).pack(side="left")

            tk.Button(
                actions,
                text="Reject Pending",
                command=lambda: self.admin_action("reject"),
                bg=DANGER_COLOR,
                fg="white",
                width=16
            ).pack(side="left", padx=6)

            tk.Button(
                actions,
                text="Release Equipment",
                command=lambda: self.admin_action("issue"),
                bg=WARNING_COLOR,
                fg="white",
                width=18
            ).pack(side="left")

            tk.Button(
                actions,
                text="Record Return",
                command=lambda: self.admin_action("return"),
                bg=SLATE_COLOR,
                fg="white",
                width=16
            ).pack(side="left", padx=6)
        else:
            tk.Button(
                actions,
                text="Cancel Selected Pending Request",
                command=self.cancel_selected,
                bg=DANGER_COLOR,
                fg="white",
                width=28
            ).pack(side="left")

        tk.Button(
            actions,
            text="Close",
            command=self.close,
            width=12
        ).pack(side="right")

        self.load_all()
        self.schedule_refresh()

    def open_request_dialog(self):
        BorrowRequestDialog(self.win, self.username, self.load_all)

    def _selected_transaction_id(self):
        selected = self.transaction_tree.selection()

        if not selected:
            messagebox.showwarning(
                "Selection Required",
                "Please select a borrowing transaction.",
                parent=self.win
            )
            return None

        return int(
            self.transaction_tree.item(selected[0], "values")[0]
        )

    def load_all(self):
        if not self.win.winfo_exists():
            return

        selected_id = None
        selected = self.transaction_tree.selection()

        if selected:
            selected_id = int(
                self.transaction_tree.item(selected[0], "values")[0]
            )

        for row_id in self.availability_tree.get_children():
            self.availability_tree.delete(row_id)

        for row in self.service.list_equipment():
            (
                item_id,
                name,
                category,
                total,
                committed,
                available,
                availability_status,
                _stock_status,
            ) = row
            self.availability_tree.insert(
                "",
                tk.END,
                values=(
                    item_id,
                    name,
                    category,
                    total,
                    committed,
                    available,
                    availability_status,
                ),
                tags=(availability_status.lower(),)
            )

        for row_id in self.transaction_tree.get_children():
            self.transaction_tree.delete(row_id)

        rows = self.service.list_transactions(
            self.username,
            all_records=self.is_admin,
            status_filter=self.status_var.get()
        )
        restored_item = None
        counts = {
            "PENDING": 0,
            "APPROVED": 0,
            "BORROWED": 0,
            "OVERDUE": 0,
        }

        for row in rows:
            (
                transaction_id,
                borrower,
                equipment,
                quantity,
                purpose,
                start_date,
                due_date,
                requested_at,
                _approved_at,
                approved_by,
                _issued_at,
                _issued_by,
                _returned_at,
                _returned_by,
                _rejected_at,
                _rejected_by,
                _cancelled_at,
                status,
            ) = row

            if status in counts:
                counts[status] += 1

            tree_item = self.transaction_tree.insert(
                "",
                tk.END,
                values=(
                    transaction_id,
                    borrower,
                    equipment,
                    quantity,
                    purpose,
                    start_date,
                    due_date,
                    requested_at,
                    approved_by or "",
                    status,
                ),
                tags=(status,)
            )

            if transaction_id == selected_id:
                restored_item = tree_item

        if restored_item:
            self.transaction_tree.selection_set(restored_item)
            self.transaction_tree.focus(restored_item)

        self.summary_label.config(
            text=(
                f"Pending: {counts['PENDING']}   "
                f"Approved: {counts['APPROVED']}   "
                f"Borrowed: {counts['BORROWED']}   "
                f"Overdue: {counts['OVERDUE']}"
            )
        )

    def admin_action(self, action):
        transaction_id = self._selected_transaction_id()

        if transaction_id is None:
            return

        labels = {
            "approve": "approve",
            "reject": "reject",
            "issue": "release the equipment for",
            "return": "record the return of",
        }

        if not messagebox.askyesno(
            "Confirm Action",
            f"Do you want to {labels[action]} request "
            f"#{transaction_id}?",
            parent=self.win
        ):
            return

        if action == "approve":
            success, msg = self.service.approve_request(
                transaction_id, self.username
            )
        elif action == "reject":
            success, msg = self.service.reject_request(
                transaction_id, self.username
            )
        elif action == "issue":
            success, msg = self.service.issue_equipment(
                transaction_id, self.username
            )
        else:
            success, msg = self.service.return_equipment(
                transaction_id, self.username
            )

        if success:
            messagebox.showinfo("Asset Tracking", msg, parent=self.win)
        else:
            messagebox.showerror("Asset Tracking", msg, parent=self.win)

        self.load_all()

    def cancel_selected(self):
        transaction_id = self._selected_transaction_id()

        if transaction_id is None:
            return

        if not messagebox.askyesno(
            "Cancel Request",
            f"Cancel pending request #{transaction_id}?",
            parent=self.win
        ):
            return

        success, msg = self.service.cancel_request(
            transaction_id, self.username
        )

        if success:
            messagebox.showinfo("Request Cancelled", msg, parent=self.win)
        else:
            messagebox.showerror("Cancellation Failed", msg, parent=self.win)

        self.load_all()

    def export_report(self):
        success, msg = self.service.export_transactions(
            self.username,
            all_records=self.is_admin,
            status_filter=self.status_var.get()
        )

        if success:
            messagebox.showinfo("Export Complete", msg, parent=self.win)
        else:
            messagebox.showerror("Export Error", msg, parent=self.win)

    def schedule_refresh(self):
        if self.win.winfo_exists():
            self._after_id = self.win.after(3000, self.auto_refresh)

    def auto_refresh(self):
        self._after_id = None

        if self.win.winfo_exists():
            self.load_all()
            self.schedule_refresh()

    def close(self):
        if self._after_id is not None:
            try:
                self.win.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None

        if self.win.winfo_exists():
            self.win.destroy()


class InventoryWindow:
    def __init__(self, root, username, role, on_logout, show_profile, show_admin_approvals):
        self.root = root
        self.username = username
        self.role = role
        self.on_logout = on_logout
        self.show_profile = show_profile
        self.show_admin_approvals = show_admin_approvals
        self.service = InventoryService()
        self.is_admin = (role == "ADMIN")

        self.current_search = ""
        self.current_category = "All"
        self.locked_item_id = None
        self.refresh_after_id = None

        self.root.title("Campus Hardware & Component Inventory")
        self.root.geometry("1120x700")
        self.root.minsize(1120, 700)

        header = tk.Frame(root, padx=12, pady=10)
        header.pack(fill="x")

        info_frame = tk.Frame(header)
        info_frame.pack(side="left", fill="x", expand=True)

        action_frame = tk.Frame(header)
        action_frame.pack(side="right")

        tk.Label(
            info_frame,
            text=f"Campus Hardware Inventory ({username} - {role})",
            font=SECTION_TITLE_FONT
        ).pack(anchor="w")

        self.total_label = tk.Label(
            info_frame,
            text="Total Inventory Value: $0.00",
            font=SUBTITLE_FONT
        )
        self.total_label.pack(anchor="w", pady=(4, 0))

        tk.Button(
            action_frame,
            text="Asset Tracking",
            command=self.open_asset_tracking,
            bg=TEAL_COLOR,
            fg="white",
            width=14
        ).pack(side="left", padx=4)

        if self.is_admin:
            tk.Button(
                action_frame,
                text="Password Resets",
                command=self.open_admin_approvals,
                bg=PURPLE_COLOR,
                fg="white",
                width=16
            ).pack(side="left", padx=4)

        tk.Button(
            action_frame,
            text="My Profile & Security",
            command=self.open_profile,
            bg=SLATE_COLOR,
            fg="white",
            width=18
        ).pack(side="left", padx=4)

        tk.Button(
            action_frame,
            text="Logout",
            command=self.logout,
            bg=DANGER_COLOR,
            fg="white",
            width=10
        ).pack(side="left", padx=4)

        if self.is_admin:
            form = tk.LabelFrame(
                root,
                text="Add Hardware Item (Admin Only)",
                padx=10,
                pady=10
            )
            form.pack(fill="x", padx=12, pady=5)

            tk.Label(form, text="Item Name:").grid(row=0, column=0, sticky="e")
            self.entry_name = tk.Entry(form, width=22)
            self.entry_name.grid(row=0, column=1, padx=5, pady=5)

            tk.Label(form, text="Category:").grid(row=0, column=2, sticky="e")
            self.entry_category = tk.Entry(form, width=18)
            self.entry_category.grid(row=0, column=3, padx=5, pady=5)

            tk.Label(form, text="Quantity:").grid(row=1, column=0, sticky="e")
            self.entry_qty = tk.Entry(form, width=22)
            self.entry_qty.grid(row=1, column=1, padx=5, pady=5)

            tk.Label(form, text="Unit Price ($):").grid(row=1, column=2, sticky="e")
            self.entry_price = tk.Entry(form, width=18)
            self.entry_price.grid(row=1, column=3, padx=5, pady=5)

            tk.Button(
                form,
                text="Save New Item",
                command=self.add_item,
                bg=SUCCESS_COLOR,
                fg="white"
            ).grid(row=1, column=4, padx=10, pady=5)

        filter_frame = tk.LabelFrame(root, text="Search & Filter", padx=10, pady=10)
        filter_frame.pack(fill="x", padx=12, pady=5)

        tk.Label(filter_frame, text="Search (name/category):").grid(row=0, column=0, sticky="e")
        self.entry_search = tk.Entry(filter_frame, width=24)
        self.entry_search.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(filter_frame, text="Category:").grid(row=0, column=2, sticky="e")
        self.category_var = tk.StringVar(value="All")
        self.category_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.category_var,
            state="readonly",
            width=18
        )
        self.category_combo.grid(row=0, column=3, padx=5, pady=5)

        tk.Button(
            filter_frame,
            text="Search",
            command=self.apply_filter,
            bg=PRIMARY_COLOR,
            fg="white"
        ).grid(row=0, column=4, padx=6)

        tk.Button(
            filter_frame,
            text="Clear",
            command=self.clear_filter
        ).grid(row=0, column=5, padx=6)

        table_frame = tk.Frame(root)
        table_frame.pack(fill="both", expand=True, padx=12, pady=8)

        scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL)

        self.tree = ttk.Treeview(
            table_frame,
            columns=("Select", "ID", "Name", "Category", "Qty", "Price", "Status"),
            show="headings",
            yscrollcommand=scroll.set
        )

        scroll.config(command=self.tree.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        headings = {
            "Select": "Select",
            "ID": "ID",
            "Name": "Name",
            "Category": "Category",
            "Qty": "Qty",
            "Price": "Price ($)",
            "Status": "Status"
        }

        for col, text in headings.items():
            self.tree.heading(col, text=text)

        self.tree.column("Select", width=60, anchor="center")
        self.tree.column("ID", width=50, anchor="center")
        self.tree.column("Name", width=220)
        self.tree.column("Category", width=140)
        self.tree.column("Qty", width=70, anchor="center")
        self.tree.column("Price", width=100, anchor="center")
        self.tree.column("Status", width=120, anchor="center")

        self.tree.tag_configure("out", background="#FEE2E2")
        self.tree.tag_configure("low", background="#FEF3C7")
        self.tree.tag_configure("in", background="#DCFCE7")

        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Button-1>", self.handle_checkbox_click)

        actions = tk.Frame(root, padx=12, pady=5)
        actions.pack(fill="x")

        if self.is_admin:
            tk.Button(
                actions,
                text="Edit Selected Item",
                command=self.edit_selected,
                bg=WARNING_COLOR,
                fg="white"
            ).pack(side="left")

            tk.Button(
                actions,
                text="Delete Selected Item",
                command=self.delete_selected,
                bg=DANGER_COLOR,
                fg="white"
            ).pack(side="left", padx=8)

        tk.Button(
            actions,
            text="Export Inventory to CSV Report",
            command=self.export_report,
            bg=PRIMARY_COLOR,
            fg="white"
        ).pack(side="right")

        self.refresh_category_filter()
        self.load_data()
        self.auto_refresh()

    def refresh_category_filter(self):
        categories = ["All"] + self.service.get_categories()
        self.category_combo["values"] = categories

        if self.category_var.get() not in categories:
            self.category_var.set("All")

    def apply_filter(self):
        self.current_search = self.entry_search.get().strip()
        self.current_category = self.category_var.get()
        self.load_data()

    def clear_filter(self):
        self.entry_search.delete(0, tk.END)
        self.category_var.set("All")
        self.current_search = ""
        self.current_category = "All"
        self.locked_item_id = None
        self.load_data()

    def load_data(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        locked_row_found = False

        for row in self.service.fetch_all(
            self.current_search,
            self.current_category
        ):
            status = row[5]

            if status == "Out of Stock":
                tag = "out"
            elif status == "Low Stock":
                tag = "low"
            else:
                tag = "in"

            item_id = row[0]

            # Displays checked when this item is locked/selected.
            checkbox = "☑" if item_id == self.locked_item_id else "☐"

            display_row = (
                checkbox,
                row[0],
                row[1],
                row[2],
                row[3],
                f"{row[4]:.2f}",
                row[5]
            )

            tree_item = self.tree.insert(
                "",
                tk.END,
                values=display_row,
                tags=(tag,)
            )

            # Restores the selection after automatic refresh.
            if item_id == self.locked_item_id:
                self.tree.selection_set(tree_item)
                self.tree.focus(tree_item)
                locked_row_found = True

        # Unlock if the item was deleted or no longer matches the filter.
        if self.locked_item_id is not None and not locked_row_found:
            self.locked_item_id = None

        self.total_label.config(
            text=(
                f"Total Inventory Value: "
                f"${self.service.total_value():,.2f}"
            )
        )

    def handle_checkbox_click(self, event):
        # Column #1 is the Select checkbox column.
        if self.tree.identify_column(event.x) != "#1":
            return

        tree_item = self.tree.identify_row(event.y)

        if not tree_item:
            return "break"

        values = self.tree.item(tree_item, "values")
        item_id = int(values[1])

        # Clicking the same checked item unlocks it.
        if self.locked_item_id == item_id:
            self.locked_item_id = None
        else:
            # Only one item can be locked at a time.
            self.locked_item_id = item_id

        self.load_data()

        # Prevent normal Treeview selection behavior.
        return "break"

    def add_item(self):
        try:
            quantity = int(self.entry_qty.get().strip())
        except ValueError:
            logger.warning("Inventory validation failed: quantity must be an integer.")
            messagebox.showerror("Validation Error", "Quantity must be a whole number.")
            return

        try:
            unit_price = float(self.entry_price.get().strip())
        except ValueError:
            logger.warning("Inventory validation failed: unit price must be numeric.")
            messagebox.showerror("Validation Error", "Unit Price must be a number.")
            return

        success, msg = self.service.add_item(
            self.entry_name.get().strip(),
            self.entry_category.get().strip(),
            quantity,
            unit_price
        )

        if success:
            messagebox.showinfo("Success", msg)

            self.entry_name.delete(0, tk.END)
            self.entry_category.delete(0, tk.END)
            self.entry_qty.delete(0, tk.END)
            self.entry_price.delete(0, tk.END)

            self.refresh_category_filter()
            self.load_data()
        else:
            messagebox.showerror("Validation Error", msg)

    def edit_selected(self):
        selected = self.tree.selection()

        if not selected:
            messagebox.showwarning("Selection Warning", "Please select an item to edit.")
            return

        values = self.tree.item(selected[0], "values")
        item = (
            int(values[1]),
            values[2],
            values[3],
            int(values[4]),
            float(values[5]),
            values[6]
        )

        def on_saved():
            self.refresh_category_filter()
            self.load_data()

        EditItemDialog(self.root, self.service, item, on_saved)

    def delete_selected(self):
        selected = self.tree.selection()

        if not selected:
            messagebox.showwarning(
                "Selection Warning",
                "Please select an item to delete."
            )
            return

        item_id = self.tree.item(selected[0], "values")[1]

        if not messagebox.askyesno(
            "Confirm Delete",
            f"Delete hardware item ID {item_id}?"
        ):
            return

        success, msg = self.service.delete_item(item_id)

        if success:
            messagebox.showinfo("Deleted", msg)
            self.refresh_category_filter()
            self.load_data()
        else:
            messagebox.showerror("Error", msg)

    def export_report(self):
        success, msg = self.service.export_csv(
            self.current_search, self.current_category
        )

        if success:
            messagebox.showinfo("Export Complete", msg)
        else:
            messagebox.showerror("Export Error", msg)

    def logout(self):
        self.stop_auto_refresh()
        logger.info(f"User logged out: {self.username}")
        self.on_logout()

    def open_asset_tracking(self):
        AssetTrackingWindow(self.root, self.username, self.role)

    def open_profile(self):
        self.stop_auto_refresh()
        self.show_profile()

    def open_admin_approvals(self):
        self.stop_auto_refresh()
        self.show_admin_approvals()

    def stop_auto_refresh(self):
        if self.refresh_after_id is not None:
            try:
                self.root.after_cancel(self.refresh_after_id)
            except tk.TclError:
                pass
            self.refresh_after_id = None

    def auto_refresh(self):
        self.refresh_after_id = None

        try:
            if not self.total_label.winfo_exists():
                return
        except tk.TclError:
            return

        self.load_data()
        self.refresh_after_id = self.root.after(2000, self.auto_refresh)


def show_login():
    for widget in root.winfo_children():
        widget.destroy()

    LoginWindow(
        root,
        on_login_success=show_inventory,
        show_register=show_register,
        show_reset=show_reset
    )


def show_register():
    for widget in root.winfo_children():
        widget.destroy()

    RegisterWindow(
        root,
        on_registered=show_login,
        show_login=show_login
    )


def show_reset():
    for widget in root.winfo_children():
        widget.destroy()

    ResetPasswordWindow(
        root,
        show_login=show_login
    )


def show_inventory(identifier):
    # Resolve the username/role for session display/logging.
    account = AuthService()._get_account(identifier)

    if account:
        username, email, _hash, role, _locked, _failed = account
    else:
        username, email, role = identifier, "", "USER"

    for widget in root.winfo_children():
        widget.destroy()

    InventoryWindow(
        root,
        username,
        role,
        on_logout=show_login,
        show_profile=lambda: show_profile(username, email, role),
        show_admin_approvals=lambda: show_admin_approvals(username)
    )


def show_profile(username, email, role):
    for widget in root.winfo_children():
        widget.destroy()

    ProfileWindow(
        root,
        username,
        email,
        role,
        show_back=lambda: show_inventory(username)
    )


def show_admin_approvals(admin_username):
    for widget in root.winfo_children():
        widget.destroy()

    AdminApprovalsWindow(
        root,
        admin_username,
        show_back=lambda: show_inventory(admin_username)
    )


if __name__ == "__main__":
    init_db()

    root = tk.Tk()
    apply_app_theme(root)
    show_login()
    root.mainloop()
