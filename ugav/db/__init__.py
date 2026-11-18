"""SQLite API-ready database schema, migrations, and repository."""

from ugav.db.migrations import CURRENT_SCHEMA_VERSION, ensure_migrated
from ugav.db.repository import DatabaseRepository

__all__ = ["CURRENT_SCHEMA_VERSION", "DatabaseRepository", "ensure_migrated"]
