"""SQLite schema initialization and forward migration with automatic pre-migration backup."""

from __future__ import annotations

import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

from ugav.paths import get_package_dir

CURRENT_SCHEMA_VERSION = 1

DEFAULT_MIGRATIONS: dict[int, list[str]] = {}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_schema_sql() -> str:
    schema_path = get_package_dir() / "db" / "schema.sql"
    return schema_path.read_text(encoding="utf-8")


def _get_current_version(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    if row is None:
        has_games = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='games'"
        ).fetchone()
        return 0 if has_games is None else 1
    ver_row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    return int(ver_row[0]) if ver_row and ver_row[0] is not None else 0


def ensure_migrated(
    db_path: Path,
    target_version: int = CURRENT_SCHEMA_VERSION,
    migrations: Mapping[int, Sequence[str]] | None = None,
) -> int:
    """Initialize or forward-migrate db_path, backing up existing DBs before migrating."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_existed = db_path.exists() and db_path.stat().st_size > 0
    mig_map = DEFAULT_MIGRATIONS if migrations is None else migrations

    conn = sqlite3.connect(str(db_path), timeout=10.0)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        current = _get_current_version(conn)
        if current == 0:
            conn.executescript(_load_schema_sql())
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (CURRENT_SCHEMA_VERSION, _utc_now_iso()),
            )
            conn.commit()
            current = CURRENT_SCHEMA_VERSION

        if current < target_version:
            conn.close()
            if db_existed:
                bak_path = db_path.with_suffix(db_path.suffix + ".bak")
                shutil.copy2(db_path, bak_path)
            conn = sqlite3.connect(str(db_path), timeout=10.0)
            conn.execute("PRAGMA foreign_keys = ON;")
            with conn:
                for ver in range(current + 1, target_version + 1):
                    for stmt in mig_map.get(ver, ()):
                        conn.execute(stmt)
                    conn.execute(
                        "INSERT OR REPLACE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                        (ver, _utc_now_iso()),
                    )
            current = target_version
        return current
    finally:
        conn.close()
