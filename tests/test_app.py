import sqlite3
from datetime import date, timedelta

import pytest

import app as app_module
import database


PASSWORD = "ValidPass1!"


@pytest.fixture()
def flask_app(tmp_path, monkeypatch):
    test_db = tmp_path / "test_inventory.db"
    monkeypatch.setattr(app_module, "DB_PATH", test_db)
    monkeypatch.setattr(app_module.desktop, "DB_NAME", str(test_db))
    application = app_module.create_app({"TESTING": True, "SECRET_KEY": "test-secret"})
    assert app_module.auth_service.register_user("student1", "student1@example.com", PASSWORD, "USER")[0]
    assert app_module.auth_service.register_user("admin1", "admin1@example.com", PASSWORD, "ADMIN")[0]
    assert app_module.inventory_service.add_item("Arduino Uno", "Microcontroller", 10, 550)[0]
    return application


@pytest.fixture()
def client(flask_app):
    return flask_app.test_client()


def csrf(client):
    with client.session_transaction() as sess:
        sess.setdefault("csrf_token", "test-csrf")
        return sess["csrf_token"]


def login(client, identifier, password=PASSWORD):
    return client.post(
        "/login",
        data={"identifier": identifier, "password": password, "csrf_token": csrf(client)},
        follow_redirects=True,
    )


def logout(client):
    return client.post("/logout", data={"csrf_token": csrf(client)}, follow_redirects=True)


def available_quantity():
    return app_module.asset_service.list_equipment()[0][5]


def test_protected_page_redirects_after_logout(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_valid_login_and_invalid_login(client):
    response = login(client, "student1", "WrongPass1!")
    assert b"Invalid username/email or password" in response.data
    response = login(client, "student1")
    assert b"Hardware dashboard" in response.data


def test_three_failures_lock_account(client):
    for _ in range(3):
        response = login(client, "student1", "WrongPass1!")
    assert b"account is now locked" in response.data
    response = login(client, "student1")
    assert b"account is locked" in response.data


def test_quantity_borrow_approval_and_return(client):
    login(client, "student1")
    start = date.today().isoformat()
    expected_return = (date.today() + timedelta(days=7)).isoformat()
    response = client.post(
        "/borrow",
        data={
            "csrf_token": csrf(client),
            "item_id": "1",
            "quantity": "3",
            "purpose": "Embedded systems laboratory",
            "start_date": start,
            "expected_return_date": expected_return,
        },
        follow_redirects=True,
    )
    assert b"submitted for administrator review" in response.data
    assert available_quantity() == 10

    with app_module.db_connect() as connection:
        transaction_id = connection.execute(
            "SELECT transaction_id FROM asset_transactions WHERE borrower_username='student1'"
        ).fetchone()[0]

    logout(client)
    login(client, "admin1")
    response = client.post(
        f"/admin/borrow/{transaction_id}/approve",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert b"marked as borrowed" in response.data
    assert available_quantity() == 7

    logout(client)
    login(client, "student1")
    response = client.post(
        f"/return/{transaction_id}/request",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert b"Return request submitted" in response.data
    assert available_quantity() == 7

    with app_module.db_connect() as connection:
        return_request_id = connection.execute(
            "SELECT return_request_id FROM web_return_requests WHERE status='PENDING'"
        ).fetchone()[0]

    logout(client)
    login(client, "admin1")
    response = client.post(
        f"/admin/return/{return_request_id}/approve",
        data={"csrf_token": csrf(client)},
        follow_redirects=True,
    )
    assert b"marked RETURNED" in response.data
    assert available_quantity() == 10


def test_borrow_quantity_cannot_exceed_available_stock(client):
    login(client, "student1")
    response = client.post(
        "/borrow",
        data={
            "csrf_token": csrf(client),
            "item_id": "1",
            "quantity": "11",
            "purpose": "Laboratory",
            "start_date": date.today().isoformat(),
            "expected_return_date": (date.today() + timedelta(days=2)).isoformat(),
        },
        follow_redirects=True,
    )
    assert b"Only 10 unit(s)" in response.data


def test_csrf_rejects_state_change(client):
    login(client, "admin1")
    response = client.post(
        "/inventory/add",
        data={"item_name": "Oscilloscope", "category": "Test", "quantity": 1, "unit_price": 1000},
    )
    assert response.status_code == 400


def test_postgresql_placeholder_conversion_preserves_string_literals():
    query = "SELECT '?' AS literal FROM users WHERE username = ? OR email = ?"
    assert database._postgres_query(query) == (
        "SELECT '?' AS literal FROM users WHERE username = %s OR email = %s"
    )
