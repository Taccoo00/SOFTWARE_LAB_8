"""One-time migration from the Lab 7 SQLite database to Supabase PostgreSQL.

Set DATABASE_URL before running this file.  The script refuses to copy into
tables that already contain rows, which prevents accidental duplicate data.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import psycopg
from psycopg import sql

from database import database_url, init_postgres_schema


BASE_DIR = Path(__file__).resolve().parent
SQLITE_DB = Path(os.environ.get("SQLITE_DB", BASE_DIR / "hardware_inventory.db"))
TABLES = (
    ("users", "id"),
    ("hardware", "item_id"),
    ("password_reset_requests", "request_id"),
    ("asset_transactions", "transaction_id"),
    ("web_return_requests", "return_request_id"),
)


def source_columns(cursor: sqlite3.Cursor, table_name: str) -> list[str]:
    return [row[1] for row in cursor.execute(f'PRAGMA table_info("{table_name}")')]


def destination_columns(cursor, table_name: str) -> list[str]:
    cursor.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        ORDER BY ordinal_position
        """,
        (table_name,),
    )
    return [row[0] for row in cursor.fetchall()]


def main() -> None:
    url = database_url()
    if not url:
        raise RuntimeError("DATABASE_URL is not set.")
    if not SQLITE_DB.is_file():
        raise FileNotFoundError(f"SQLite database not found: {SQLITE_DB}")

    init_postgres_schema()
    sqlite_connection = sqlite3.connect(SQLITE_DB)
    sqlite_connection.row_factory = sqlite3.Row
    postgres_connection = psycopg.connect(url)
    postgres_connection.autocommit = False

    try:
        sqlite_cursor = sqlite_connection.cursor()
        postgres_cursor = postgres_connection.cursor()

        for table_name, _id_column in TABLES:
            postgres_cursor.execute(
                sql.SQL("SELECT COUNT(*) FROM {}").format(sql.Identifier(table_name))
            )
            if postgres_cursor.fetchone()[0] > 0:
                raise RuntimeError(
                    f"Destination table '{table_name}' is not empty. "
                    "Use a new Supabase project or clear it deliberately first."
                )

        counts: dict[str, int] = {}
        for table_name, _id_column in TABLES:
            available_source = source_columns(sqlite_cursor, table_name)
            available_destination = destination_columns(postgres_cursor, table_name)
            columns = [name for name in available_source if name in available_destination]
            if not columns:
                counts[table_name] = 0
                continue

            select_columns = ", ".join(f'"{name}"' for name in columns)
            rows = sqlite_cursor.execute(
                f'SELECT {select_columns} FROM "{table_name}"'
            ).fetchall()
            counts[table_name] = len(rows)
            if not rows:
                continue

            insert_query = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                sql.Identifier(table_name),
                sql.SQL(", ").join(sql.Identifier(name) for name in columns),
                sql.SQL(", ").join(sql.Placeholder() for _ in columns),
            )
            for row in rows:
                postgres_cursor.execute(insert_query, [row[name] for name in columns])

        for table_name, id_column in TABLES:
            postgres_cursor.execute(
                sql.SQL(
                    "SELECT setval(pg_get_serial_sequence({}, {}), "
                    "COALESCE(MAX({}), 1), MAX({}) IS NOT NULL) FROM {}"
                ).format(
                    sql.Literal(table_name),
                    sql.Literal(id_column),
                    sql.Identifier(id_column),
                    sql.Identifier(id_column),
                    sql.Identifier(table_name),
                )
            )

        postgres_connection.commit()
        print("Migration completed successfully.")
        for table_name, _id_column in TABLES:
            print(f"  {table_name:<26} {counts[table_name]}")
    except Exception:
        postgres_connection.rollback()
        raise
    finally:
        sqlite_connection.close()
        postgres_connection.close()


if __name__ == "__main__":
    main()
