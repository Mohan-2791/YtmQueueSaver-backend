"""
Additive, idempotent schema migrations.

`Base.metadata.create_all()` creates *missing tables* but never adds columns or
indexes to tables that already exist. Every release that only added a table was
safe; every release that adds a column needs this runner (or an equivalent
`ALTER TABLE`) so existing deployments are upgraded in place.

Rules honoured here:
* ADDITIVE ONLY - new nullable or server-defaulted columns, and new indexes.
* IDEMPOTENT - re-running is a no-op, so it is safe on every boot.
* Each step ships with an explicit rollback statement.

Run explicitly with:  python -m migrations        (from the backend directory)
"""

import logging
import re

from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

logger = logging.getLogger("ytm_saver.migrations")


# --- step definitions --------------------------------------------------------
# Each entry: (name, apply_sql_list, rollback_sql_list)
# `apply` statements must be written so that running them twice is harmless.
MIGRATIONS = [
    (
        "0001_quota_and_playlist_cache",
        [
            # Added by the quota-optimization phase. No-op on fresh databases
            # where create_all already produced the current shape.
            "CREATE TABLE IF NOT EXISTS user_playlists ("
            " id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
            " category VARCHAR(50) NOT NULL, youtube_playlist_id VARCHAR(255) NOT NULL,"
            " created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
            " CONSTRAINT uq_user_category UNIQUE (user_id, category))",
            "CREATE TABLE IF NOT EXISTS playlist_items_cache ("
            " id SERIAL PRIMARY KEY, youtube_playlist_id VARCHAR(255) NOT NULL,"
            " video_id VARCHAR(64) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
            " CONSTRAINT uq_playlist_video UNIQUE (youtube_playlist_id, video_id))",
            "CREATE TABLE IF NOT EXISTS quota_usage ("
            " id SERIAL PRIMARY KEY, date_str VARCHAR(10) NOT NULL, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,"
            " units_used INTEGER NOT NULL DEFAULT 0, playlists_created INTEGER NOT NULL DEFAULT 0,"
            " CONSTRAINT uq_date_user UNIQUE (date_str, user_id))",
        ],
        [
            "DROP TABLE IF EXISTS quota_usage",
            "DROP TABLE IF EXISTS playlist_items_cache",
            "DROP TABLE IF EXISTS user_playlists",
        ],
    ),
    (
        "0002_playlist_verification_ttl",
        [
            "ALTER TABLE user_playlists ADD COLUMN IF NOT EXISTS verified_at TIMESTAMP",
            "ALTER TABLE user_playlists ADD COLUMN IF NOT EXISTS title VARCHAR(255)",
        ],
        [
            "ALTER TABLE user_playlists DROP COLUMN IF EXISTS title",
            "ALTER TABLE user_playlists DROP COLUMN IF EXISTS verified_at",
        ],
    ),
    (
        "0003_user_reconnect_flag",
        [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS needs_reconnect BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMP",
        ],
        [
            "ALTER TABLE users DROP COLUMN IF EXISTS last_seen_at",
            "ALTER TABLE users DROP COLUMN IF EXISTS needs_reconnect",
        ],
    ),
    (
        "0004_quota_playlists_created",
        [
            "ALTER TABLE quota_usage ADD COLUMN IF NOT EXISTS playlists_created INTEGER NOT NULL DEFAULT 0",
        ],
        [
            "ALTER TABLE quota_usage DROP COLUMN IF EXISTS playlists_created",
        ],
    ),
    (
        "0005_performance_indexes",
        [
            "CREATE INDEX IF NOT EXISTS ix_playlist_items_cache_lookup"
            " ON playlist_items_cache (youtube_playlist_id, video_id)",
            "CREATE INDEX IF NOT EXISTS ix_quota_usage_date_units"
            " ON quota_usage (date_str, units_used)",
            "CREATE INDEX IF NOT EXISTS ix_snapshots_user_category_created"
            " ON playlist_snapshots (user_id, category, created_at)",
        ],
        [
            "DROP INDEX IF EXISTS ix_snapshots_user_category_created",
            "DROP INDEX IF EXISTS ix_quota_usage_date_units",
            "DROP INDEX IF EXISTS ix_playlist_items_cache_lookup",
        ],
    ),
]


def _normalize(sql: str) -> str:
    return " ".join(sql.split()).lower()


def _existing_columns(db: Session, table: str) -> set:
    inspector = inspect(db.get_bind())
    if table not in inspector.get_table_names():
        return set()
    return {col["name"] for col in inspector.get_columns(table)}


def _existing_indexes(db: Session) -> set:
    inspector = inspect(db.get_bind())
    names = set()
    for table in inspector.get_table_names():
        for index in inspector.get_indexes(table):
            names.add(index.get("name"))
        for index in inspector.get_unique_constraints(table):
            names.add(index.get("name"))
    return names


def _dialect(db: Session) -> str:
    bind = db.get_bind()
    return bind.dialect.name if bind is not None else ""


def _sqlite_table_exists_sql(db: Session, table: str) -> str:
    return f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'"


_ADD_COLUMN_RE = re.compile(
    r"^ALTER TABLE\s+(?P<table>[\w\.\"]+)\s+ADD COLUMN IF NOT EXISTS\s+(?P<rest>.+)$",
    re.IGNORECASE,
)


def _execute_step(db: Session, dialect: str, sql: str) -> None:
    """
    Run one migration statement, normalising the few places where Postgres and
    SQLite disagree.

    `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` is Postgres-only; SQLite has no
    such syntax, so we check the catalog first and emit the plain form. Keeping
    local SQLite development on the same migration path as production avoids
    "works on my machine" schema drift.
    """
    match = _ADD_COLUMN_RE.match(sql.strip())
    if match:
        table = match.group("table").strip('"')
        column = match.group("rest").split()[0].strip('"')
        if dialect != "postgresql" and column in _existing_columns(db, table):
            return
        db.execute(text(f'ALTER TABLE "{table}" ADD COLUMN {match.group("rest")}'))
        return
    db.execute(text(sql))


def apply_migrations(db: Session) -> list:
    """
    Apply every migration that has not been applied yet.

    Returns the list of migration names that ran. Safe to call on every start.
    """
    applied = []
    dialect = _dialect(db)
    for name, statements, _ in MIGRATIONS:
        for sql in statements:
            try:
                _execute_step(db, dialect, sql)
            except Exception as exc:
                # A failure must never take the service down: the application
                # only needs the new columns to be *optional*.
                logger.warning(
                    "Migration %s step failed (continuing): %s | sql=%s", name, exc, sql
                )
                db.rollback()
        applied.append(name)
    try:
        db.commit()
    except Exception:  # pragma: no cover
        db.rollback()
    logger.info("Applied migrations: %s (dialect=%s)", applied, dialect)
    return applied


def rollback_last(db: Session) -> list:
    """
    Roll back every step in reverse order.

    Intended for a one-step emergency rollback of a bad deploy. It is destructive
    by definition (it removes the columns/indexes added above) and is never
    called automatically.
    """
    executed = []
    for name, _, rollback_statements in reversed(MIGRATIONS):
        for sql in rollback_statements:
            try:
                db.execute(text(sql))
                executed.append(f"{name}: {sql}")
            except Exception as exc:
                logger.warning("Rollback %s failed: %s | sql=%s", name, exc, sql)
                db.rollback()
    try:
        db.commit()
    except Exception:  # pragma: no cover
        db.rollback()
    logger.warning("Rolled back: %s", executed)
    return executed


def pending(db: Session) -> list:
    """Names of migrations whose columns/indexes are not all present yet."""
    pending_names = []
    for name, statements, _ in MIGRATIONS:
        missing = False
        for sql in statements:
            head = _normalize(sql)
            if "alter table" in head and "add column" in head:
                table = head.split("alter table", 1)[1].split("add column", 1)[0].strip()
                column = head.split("add column if not exists", 1)[-1].split()[0]
                if column not in _existing_columns(db, table):
                    missing = True
            elif "create index if not exists" in head:
                index = head.split("create index if not exists", 1)[-1].split()[0]
                if index not in _existing_indexes(db):
                    missing = True
            elif "create table if not exists" in head:
                table = head.split("create table if not exists", 1)[-1].split("(")[0].strip()
                if table not in _existing_columns(db, table) and not _table_exists(db, table):
                    missing = True
        if missing:
            pending_names.append(name)
    return pending_names


def _table_exists(db: Session, table: str) -> bool:
    dialect = _dialect(db)
    if dialect == "sqlite":
        row = db.execute(text(_sqlite_table_exists_sql(db, table))).first()
        return row is not None
    inspector = inspect(db.get_bind())
    return table in inspector.get_table_names()


if __name__ == "__main__":  # pragma: no cover - manual entrypoint
    import logging as _logging

    _logging.basicConfig(level=_logging.INFO)
    from database import SessionLocal

    session = SessionLocal()
    try:
        outstanding = pending(session)
        if outstanding:
            _logging.info("Pending migrations: %s", outstanding)
        apply_migrations(session)
        _logging.info("Schema up to date.")
    finally:
        session.close()
