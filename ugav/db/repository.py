"""Thread-safe SQLite repository with WAL mode, batched upserts, FTS5 search, relocate, and merge."""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ugav.db.migrations import ensure_migrated


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return cleaned or "item"


class DatabaseRepository:
    """API-ready SQLite persistence layer for UGAV."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        ensure_migrated(self.db_path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=10.0)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._conn.execute("PRAGMA busy_timeout=10000;")

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            except sqlite3.Error:
                pass
            self._conn.close()

    def _unique_game_slug(self, base_slug: str, root_path: str) -> str:
        existing = self._conn.execute(
            "SELECT slug FROM games WHERE root_path = ?", (root_path,)
        ).fetchone()
        if existing:
            return str(existing["slug"])
        candidate = base_slug
        idx = 2
        while self._conn.execute("SELECT 1 FROM games WHERE slug = ?", (candidate,)).fetchone():
            candidate = f"{base_slug}-{idx}"
            idx += 1
        return candidate

    def upsert_game(
        self,
        *,
        name: str,
        root_path: str,
        detected_engine: str,
        middleware: list[str] | None = None,
        cpu_arch: str = "unknown",
        source_platform: str = "windows",
        confidence: float = 0.0,
        is_online_stub: bool = False,
        fingerprint_hash: str = "",
        metadata: dict[str, Any] | None = None,
        slug: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now_iso()
        with self._lock:
            resolved_slug = slug or self._unique_game_slug(slugify(name), root_path)
            mw_json = json.dumps(middleware or [])
            meta_json = json.dumps(metadata or {})
            row = self._conn.execute(
                "SELECT id FROM games WHERE root_path = ?", (root_path,)
            ).fetchone()
            if row is None and fingerprint_hash:
                row = self._conn.execute(
                    "SELECT id FROM games WHERE slug = ?", (resolved_slug,)
                ).fetchone()
            with self._conn:
                if row is None:
                    cur = self._conn.execute(
                        """
                        INSERT INTO games (
                            slug, name, root_path, fingerprint_hash, source_platform,
                            detected_engine, middleware_json, cpu_arch, confidence,
                            is_online_stub, metadata_json, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            resolved_slug,
                            name,
                            root_path,
                            fingerprint_hash,
                            source_platform,
                            detected_engine,
                            mw_json,
                            cpu_arch,
                            confidence,
                            1 if is_online_stub else 0,
                            meta_json,
                            now,
                            now,
                        ),
                    )
                    game_id = int(cur.lastrowid)
                else:
                    game_id = int(row["id"])
                    self._conn.execute(
                        """
                        UPDATE games SET
                            name = ?, root_path = ?, fingerprint_hash = ?, source_platform = ?,
                            detected_engine = ?, middleware_json = ?, cpu_arch = ?,
                            confidence = ?, is_online_stub = ?, metadata_json = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            name,
                            root_path,
                            fingerprint_hash,
                            source_platform,
                            detected_engine,
                            mw_json,
                            cpu_arch,
                            confidence,
                            1 if is_online_stub else 0,
                            meta_json,
                            now,
                            game_id,
                        ),
                    )
            return self.get_game_by_id(game_id)  # type: ignore[return-value]

    def get_game_by_id(self, game_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM games WHERE id = ?", (game_id,)).fetchone()
            return self._game_row_to_dict(row) if row else None

    def get_game_by_slug(self, slug: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM games WHERE slug = ?", (slug,)).fetchone()
            return self._game_row_to_dict(row) if row else None

    def list_games(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT g.*,
                    (SELECT COUNT(*) FROM assets a WHERE a.game_id = g.id AND a.is_missing = 0) AS asset_count,
                    (SELECT COUNT(*) FROM entities e WHERE e.game_id = g.id) AS entity_count,
                    (SELECT COUNT(*) FROM scan_warnings w WHERE w.game_id = g.id) AS warning_count
                FROM games g
                ORDER BY g.updated_at DESC
                """
            ).fetchall()
            out: list[dict[str, Any]] = []
            for r in rows:
                d = self._game_row_to_dict(r)
                d["asset_count"] = r["asset_count"]
                d["entity_count"] = r["entity_count"]
                d["warning_count"] = r["warning_count"]
                out.append(d)
            return out

    @staticmethod
    def _game_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["middleware"] = json.loads(d.pop("middleware_json", "[]"))
        d["metadata"] = json.loads(d.pop("metadata_json", "{}"))
        d["is_online_stub"] = bool(d["is_online_stub"])
        return d

    def start_scan_run(self, game_id: int, copy_mode: str) -> int:
        with self._lock:
            with self._conn:
                cur = self._conn.execute(
                    """
                    INSERT INTO scan_runs(game_id, copy_mode, status, started_at)
                    VALUES (?, ?, 'running', ?)
                    """,
                    (game_id, copy_mode, utc_now_iso()),
                )
                return int(cur.lastrowid)

    def finish_scan_run(
        self,
        scan_run_id: int,
        status: str,
        files_scanned: int,
        assets_indexed: int,
        entities_parsed: int,
    ) -> None:
        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    UPDATE scan_runs SET
                        status = ?, files_scanned = ?, assets_indexed = ?,
                        entities_parsed = ?, finished_at = ?
                    WHERE id = ?
                    """,
                    (status, files_scanned, assets_indexed, entities_parsed, utc_now_iso(), scan_run_id),
                )

    def log_warning(
        self, scan_run_id: int, game_id: int, path: str, stage: str, severity: str, message: str
    ) -> None:
        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO scan_warnings(scan_run_id, game_id, path, stage, severity, message, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (scan_run_id, game_id, path, stage, severity, message, utc_now_iso()),
                )

    def get_known_assets_map(self, game_id: int) -> dict[tuple[str, str], tuple[int, int, int | None, str | None]]:
        """Map (source_kind, original_path) -> (id, source_size, source_mtime_ns, blob_sha256)."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, source_kind, original_path, source_size, source_mtime_ns, blob_sha256
                FROM assets WHERE game_id = ?
                """,
                (game_id,),
            ).fetchall()
            return {
                (r["source_kind"], r["original_path"]): (
                    int(r["id"]),
                    int(r["source_size"]),
                    r["source_mtime_ns"],
                    r["blob_sha256"],
                )
                for r in rows
            }

    def upsert_blobs_and_assets_batch(
        self,
        blobs: Iterable[dict[str, Any]],
        assets: Iterable[dict[str, Any]],
    ) -> dict[tuple[str, str], int]:
        """Upsert a batch of blobs and assets inside one transaction; return (source_kind, original_path)->id."""
        now = utc_now_iso()
        blob_list = list(blobs)
        asset_list = list(assets)
        out_ids: dict[tuple[str, str], int] = {}
        with self._lock:
            with self._conn:
                for b in blob_list:
                    self._conn.execute(
                        """
                        INSERT INTO blobs(
                            sha256, size_bytes, vault_rel_path, preview_rel_path,
                            detected_mime, detected_format, entropy, encryption_flag, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(sha256) DO UPDATE SET
                            vault_rel_path = COALESCE(excluded.vault_rel_path, blobs.vault_rel_path),
                            preview_rel_path = COALESCE(excluded.preview_rel_path, blobs.preview_rel_path),
                            detected_mime = CASE WHEN blobs.detected_format = 'unknown' THEN excluded.detected_mime ELSE blobs.detected_mime END,
                            detected_format = CASE WHEN blobs.detected_format = 'unknown' THEN excluded.detected_format ELSE blobs.detected_format END
                        """,
                        (
                            b["sha256"],
                            b["size_bytes"],
                            b.get("vault_rel_path"),
                            b.get("preview_rel_path"),
                            b["detected_mime"],
                            b["detected_format"],
                            b.get("entropy", 0.0),
                            b.get("encryption_flag", "none"),
                            now,
                        ),
                    )
                for a in asset_list:
                    self._conn.execute(
                        """
                        INSERT INTO assets(
                            game_id, parent_asset_id, blob_sha256, original_path, source_kind,
                            source_offset, source_size, source_mtime_ns, extension,
                            asset_category, is_missing, metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                        ON CONFLICT(game_id, source_kind, original_path) DO UPDATE SET
                            parent_asset_id = excluded.parent_asset_id,
                            blob_sha256 = excluded.blob_sha256,
                            source_offset = excluded.source_offset,
                            source_size = excluded.source_size,
                            source_mtime_ns = excluded.source_mtime_ns,
                            extension = excluded.extension,
                            asset_category = excluded.asset_category,
                            is_missing = 0,
                            metadata_json = excluded.metadata_json
                        """,
                        (
                            a["game_id"],
                            a.get("parent_asset_id"),
                            a.get("blob_sha256"),
                            a["original_path"],
                            a["source_kind"],
                            a.get("source_offset"),
                            a["source_size"],
                            a.get("source_mtime_ns"),
                            a["extension"],
                            a["asset_category"],
                            json.dumps(a.get("metadata") or {}),
                        ),
                    )
                    row = self._conn.execute(
                        "SELECT id FROM assets WHERE game_id = ? AND source_kind = ? AND original_path = ?",
                        (a["game_id"], a["source_kind"], a["original_path"]),
                    ).fetchone()
                    if row:
                        out_ids[(a["source_kind"], a["original_path"])] = int(row["id"])
        return out_ids

    def mark_missing_assets(self, game_id: int, seen_keys: set[tuple[str, str]]) -> int:
        """Mark previously known assets not present in seen_keys as is_missing=1."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, source_kind, original_path FROM assets WHERE game_id = ? AND is_missing = 0",
                (game_id,),
            ).fetchall()
            missing_ids = [
                int(r["id"]) for r in rows if (r["source_kind"], r["original_path"]) not in seen_keys
            ]
            if not missing_ids:
                return 0
            with self._conn:
                for i in range(0, len(missing_ids), 400):
                    chunk = missing_ids[i : i + 400]
                    placeholders = ",".join("?" for _ in chunk)
                    self._conn.execute(
                        f"UPDATE assets SET is_missing = 1 WHERE id IN ({placeholders})", chunk
                    )
            return len(missing_ids)

    def upsert_localization_batch(self, rows: Iterable[dict[str, Any]]) -> int:
        row_list = list(rows)
        if not row_list:
            return 0
        with self._lock:
            with self._conn:
                self._conn.executemany(
                    """
                    INSERT INTO localization_strings(game_id, lang, str_key, str_value, source_asset_id)
                    VALUES (:game_id, :lang, :str_key, :str_value, :source_asset_id)
                    ON CONFLICT(game_id, lang, str_key) DO UPDATE SET
                        str_value = excluded.str_value,
                        source_asset_id = excluded.source_asset_id
                    """,
                    row_list,
                )
        return len(row_list)

    def get_localization_map(self, game_id: int, lang: str = "English") -> dict[str, str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT str_key, str_value FROM localization_strings WHERE game_id = ? AND LOWER(lang) = LOWER(?)",
                (game_id, lang),
            ).fetchall()
            if not rows:
                rows = self._conn.execute(
                    "SELECT str_key, str_value FROM localization_strings WHERE game_id = ?",
                    (game_id,),
                ).fetchall()
            return {r["str_key"]: r["str_value"] for r in rows}

    def upsert_entities_batch(self, entities: Iterable[dict[str, Any]]) -> dict[tuple[str, str], int]:
        ent_list = list(entities)
        if not ent_list:
            return {}
        id_map: dict[tuple[str, str], int] = {}
        with self._lock:
            with self._conn:
                for e in ent_list:
                    self._conn.execute(
                        """
                        INSERT INTO entities(
                            game_id, source_asset_id, entity_type, external_key,
                            slug, display_name, raw_json, resolved_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(game_id, entity_type, external_key) DO UPDATE SET
                            source_asset_id = excluded.source_asset_id,
                            slug = excluded.slug,
                            display_name = excluded.display_name,
                            raw_json = excluded.raw_json,
                            resolved_json = excluded.resolved_json
                        """,
                        (
                            e["game_id"],
                            e.get("source_asset_id"),
                            e["entity_type"],
                            e["external_key"],
                            e.get("slug") or slugify(e["external_key"]),
                            e.get("display_name"),
                            json.dumps(e.get("raw") or {}),
                            json.dumps(e.get("resolved") or {}),
                        ),
                    )
                    row = self._conn.execute(
                        "SELECT id FROM entities WHERE game_id = ? AND entity_type = ? AND external_key = ?",
                        (e["game_id"], e["entity_type"], e["external_key"]),
                    ).fetchone()
                    if row:
                        id_map[(e["entity_type"], e["external_key"])] = int(row["id"])
        return id_map

    def get_entities_key_map(self, game_id: int) -> dict[tuple[str, str], int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, entity_type, external_key FROM entities WHERE game_id = ?",
                (game_id,),
            ).fetchall()
            return {(r["entity_type"], r["external_key"]): int(r["id"]) for r in rows}

    def replace_entity_relations(self, game_id: int, relations: Iterable[dict[str, Any]]) -> int:
        rel_list = list(relations)
        with self._lock:
            with self._conn:
                self._conn.execute("DELETE FROM entity_relations WHERE game_id = ?", (game_id,))
                if rel_list:
                    self._conn.executemany(
                        """
                        INSERT INTO entity_relations(
                            game_id, source_entity_id, relation_type,
                            target_entity_id, target_ref, metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        [
                            (
                                game_id,
                                r["source_entity_id"],
                                r["relation_type"],
                                r.get("target_entity_id"),
                                r["target_ref"],
                                json.dumps(r.get("metadata") or {}),
                            )
                            for r in rel_list
                        ],
                    )
        return len(rel_list)

    def query_assets_paginated(
        self,
        game_id: int,
        *,
        category: str | None = None,
        encryption_flag: str | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        page = max(1, page)
        page_size = min(200, max(1, page_size))
        offset = (page - 1) * page_size
        clauses = ["a.game_id = ?", "a.is_missing = 0"]
        params: list[Any] = [game_id]
        if category:
            clauses.append("a.asset_category = ?")
            params.append(category)
        if encryption_flag:
            clauses.append("b.encryption_flag = ?")
            params.append(encryption_flag)
        if search:
            clauses.append("a.original_path LIKE ?")
            params.append(f"%{search}%")
        where = " AND ".join(clauses)
        with self._lock:
            total = int(
                self._conn.execute(
                    f"SELECT COUNT(*) FROM assets a LEFT JOIN blobs b ON b.sha256 = a.blob_sha256 WHERE {where}",
                    params,
                ).fetchone()[0]
            )
            rows = self._conn.execute(
                f"""
                SELECT a.*, b.vault_rel_path, b.preview_rel_path, b.detected_mime,
                       b.detected_format, b.entropy, b.encryption_flag
                FROM assets a
                LEFT JOIN blobs b ON b.sha256 = a.blob_sha256
                WHERE {where}
                ORDER BY a.id ASC
                LIMIT ? OFFSET ?
                """,
                [*params, page_size, offset],
            ).fetchall()
            items = []
            for r in rows:
                d = dict(r)
                d["metadata"] = json.loads(d.pop("metadata_json", "{}"))
                items.append(d)
            return {"total": total, "page": page, "page_size": page_size, "items": items}

    def query_entities_paginated(
        self,
        game_id: int,
        *,
        entity_type: str | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        page = max(1, page)
        page_size = min(200, max(1, page_size))
        offset = (page - 1) * page_size
        clauses = ["e.game_id = ?"]
        params: list[Any] = [game_id]
        if entity_type:
            clauses.append("e.entity_type = ?")
            params.append(entity_type)
        if search:
            clauses.append("(e.display_name LIKE ? OR e.external_key LIKE ? OR e.resolved_json LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])
        where = " AND ".join(clauses)
        with self._lock:
            total = int(
                self._conn.execute(f"SELECT COUNT(*) FROM entities e WHERE {where}", params).fetchone()[0]
            )
            rows = self._conn.execute(
                f"""
                SELECT e.id, e.game_id, e.entity_type, e.external_key, e.slug, e.display_name, e.resolved_json
                FROM entities e
                WHERE {where}
                ORDER BY e.id ASC
                LIMIT ? OFFSET ?
                """,
                [*params, page_size, offset],
            ).fetchall()
            items = []
            for r in rows:
                d = dict(r)
                d["resolved"] = json.loads(d.pop("resolved_json", "{}"))
                items.append(d)
            return {"total": total, "page": page, "page_size": page_size, "items": items}

    def get_entity_detail(self, entity_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
            if row is None:
                return None
            d = dict(row)
            d["raw"] = json.loads(d.pop("raw_json", "{}"))
            d["resolved"] = json.loads(d.pop("resolved_json", "{}"))
            rels = self._conn.execute(
                """
                SELECT r.relation_type, r.target_ref, r.target_entity_id, r.metadata_json,
                       te.display_name AS target_display_name, te.entity_type AS target_type
                FROM entity_relations r
                LEFT JOIN entities te ON te.id = r.target_entity_id
                WHERE r.source_entity_id = ?
                """,
                (entity_id,),
            ).fetchall()
            d["relations"] = [
                {
                    "relation_type": rr["relation_type"],
                    "target_ref": rr["target_ref"],
                    "target_entity_id": rr["target_entity_id"],
                    "target_display_name": rr["target_display_name"],
                    "target_type": rr["target_type"],
                    "metadata": json.loads(rr["metadata_json"] or "{}"),
                }
                for rr in rels
            ]
            return d

    def search_entities_fts(
        self, query: str, game_slug: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        clean = re.sub(r'["\'*():^]', " ", query).strip()
        if not clean:
            return []
        terms = [f'"{tok}"*' for tok in clean.split() if tok]
        fts_expr = " AND ".join(terms)
        sql = """
            SELECT e.id, e.game_id, g.slug AS game_slug, g.name AS game_name,
                   e.entity_type, e.external_key, e.slug, e.display_name, e.resolved_json
            FROM entities_fts f
            JOIN entities e ON e.id = f.rowid
            JOIN games g ON g.id = e.game_id
            WHERE entities_fts MATCH ?
        """
        params: list[Any] = [fts_expr]
        if game_slug:
            sql += " AND g.slug = ?"
            params.append(game_slug)
        sql += " ORDER BY bm25(entities_fts) LIMIT ?"
        params.append(min(200, max(1, limit)))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["resolved"] = json.loads(d.pop("resolved_json", "{}"))
                out.append(d)
            return out

    def get_blob(self, sha256: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM blobs WHERE sha256 = ?", (sha256,)).fetchone()
            return dict(row) if row else None

    def get_warnings(self, game_id: int | None = None, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            if game_id is not None:
                rows = self._conn.execute(
                    "SELECT * FROM scan_warnings WHERE game_id = ? ORDER BY id DESC LIMIT ?",
                    (game_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM scan_warnings ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(r) for r in rows]

    def get_stats(self, game_slug: str | None = None) -> dict[str, Any]:
        with self._lock:
            game_filter = ""
            params: list[Any] = []
            if game_slug:
                g = self.get_game_by_slug(game_slug)
                if not g:
                    return {"games": [], "assets_by_category": {}, "entities_by_type": {}, "warnings": 0}
                game_filter = "WHERE game_id = ?"
                params = [g["id"]]

            games = [self.get_game_by_slug(game_slug)] if game_slug else self.list_games()
            cat_rows = self._conn.execute(
                f"SELECT asset_category, COUNT(*) AS cnt, COALESCE(SUM(source_size), 0) AS bytes FROM assets {game_filter} GROUP BY asset_category",
                params,
            ).fetchall()
            ent_rows = self._conn.execute(
                f"SELECT entity_type, COUNT(*) AS cnt FROM entities {game_filter} GROUP BY entity_type",
                params,
            ).fetchall()
            warn_cnt = int(
                self._conn.execute(f"SELECT COUNT(*) FROM scan_warnings {game_filter}", params).fetchone()[0]
            )
            blob_stats = self._conn.execute(
                "SELECT COUNT(*) AS cnt, COALESCE(SUM(size_bytes), 0) AS total_bytes, SUM(CASE WHEN vault_rel_path IS NOT NULL THEN size_bytes ELSE 0 END) AS vaulted_bytes FROM blobs"
            ).fetchone()
            return {
                "games": games,
                "assets_by_category": {
                    r["asset_category"]: {"count": r["cnt"], "bytes": r["bytes"]} for r in cat_rows
                },
                "entities_by_type": {r["entity_type"]: r["cnt"] for r in ent_rows},
                "warnings": warn_cnt,
                "unique_blobs": blob_stats["cnt"],
                "unique_blob_bytes": blob_stats["total_bytes"] or 0,
                "vaulted_blob_bytes": blob_stats["vaulted_bytes"] or 0,
            }

    def relocate_game(self, slug: str, new_root_path: Path) -> dict[str, Any]:
        resolved = str(Path(new_root_path).resolve())
        with self._lock:
            game = self.get_game_by_slug(slug)
            if not game:
                raise KeyError(f"Game not found: {slug}")
            with self._conn:
                self._conn.execute(
                    "UPDATE games SET root_path = ?, updated_at = ? WHERE id = ?",
                    (resolved, utc_now_iso(), game["id"]),
                )
            return self.get_game_by_id(game["id"])  # type: ignore[return-value]

    def merge_from_other_db(
        self, other_db_path: Path, other_vault_dir: Path, target_vault_dir: Path
    ) -> dict[str, int]:
        """Merge another UGAV SQLite DB and CAS Vault blobs into this repository."""
        src = sqlite3.connect(str(other_db_path), timeout=10.0)
        src.row_factory = sqlite3.Row
        stats = {"games_merged": 0, "blobs_copied": 0, "assets_merged": 0, "entities_merged": 0}
        try:
            with self._lock:
                # Copy blobs first
                for b in src.execute("SELECT * FROM blobs").fetchall():
                    bd = dict(b)
                    for rel_key in ("vault_rel_path", "preview_rel_path"):
                        rel = bd.get(rel_key)
                        if rel:
                            src_file = other_vault_dir / rel
                            dst_file = target_vault_dir / rel
                            if src_file.is_file() and not dst_file.exists():
                                dst_file.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copy2(src_file, dst_file)
                                if rel_key == "vault_rel_path":
                                    stats["blobs_copied"] += 1
                    with self._conn:
                        self._conn.execute(
                            """
                            INSERT INTO blobs(
                                sha256, size_bytes, vault_rel_path, preview_rel_path,
                                detected_mime, detected_format, entropy, encryption_flag, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(sha256) DO UPDATE SET
                                vault_rel_path = COALESCE(blobs.vault_rel_path, excluded.vault_rel_path),
                                preview_rel_path = COALESCE(blobs.preview_rel_path, excluded.preview_rel_path)
                            """,
                            (
                                bd["sha256"],
                                bd["size_bytes"],
                                bd["vault_rel_path"],
                                bd["preview_rel_path"],
                                bd["detected_mime"],
                                bd["detected_format"],
                                bd["entropy"],
                                bd["encryption_flag"],
                                bd["created_at"],
                            ),
                        )

                for g in src.execute("SELECT * FROM games").fetchall():
                    gd = dict(g)
                    target_game = self.upsert_game(
                        name=gd["name"],
                        root_path=gd["root_path"],
                        detected_engine=gd["detected_engine"],
                        middleware=json.loads(gd.get("middleware_json") or "[]"),
                        cpu_arch=gd.get("cpu_arch", "unknown"),
                        source_platform=gd.get("source_platform", "windows"),
                        confidence=float(gd.get("confidence", 0.0)),
                        is_online_stub=bool(gd.get("is_online_stub", 0)),
                        fingerprint_hash=gd.get("fingerprint_hash", ""),
                        metadata=json.loads(gd.get("metadata_json") or "{}"),
                        slug=gd["slug"],
                    )
                    new_gid = int(target_game["id"])
                    old_gid = int(gd["id"])
                    stats["games_merged"] += 1

                    # Map assets preserving parent hierarchy (root first, children second)
                    old_to_new_asset: dict[int, int] = {}
                    src_assets = [
                        dict(r)
                        for r in src.execute(
                            "SELECT * FROM assets WHERE game_id = ? ORDER BY parent_asset_id IS NOT NULL, id ASC",
                            (old_gid,),
                        ).fetchall()
                    ]
                    with self._conn:
                        for a in src_assets:
                            new_parent = (
                                old_to_new_asset.get(a["parent_asset_id"])
                                if a["parent_asset_id"] is not None
                                else None
                            )
                            self._conn.execute(
                                """
                                INSERT INTO assets(
                                    game_id, parent_asset_id, blob_sha256, original_path, source_kind,
                                    source_offset, source_size, source_mtime_ns, extension,
                                    asset_category, is_missing, metadata_json
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                ON CONFLICT(game_id, source_kind, original_path) DO UPDATE SET
                                    blob_sha256 = excluded.blob_sha256,
                                    is_missing = excluded.is_missing
                                """,
                                (
                                    new_gid,
                                    new_parent,
                                    a["blob_sha256"],
                                    a["original_path"],
                                    a["source_kind"],
                                    a["source_offset"],
                                    a["source_size"],
                                    a["source_mtime_ns"],
                                    a["extension"],
                                    a["asset_category"],
                                    a["is_missing"],
                                    a["metadata_json"],
                                ),
                            )
                            row = self._conn.execute(
                                "SELECT id FROM assets WHERE game_id = ? AND source_kind = ? AND original_path = ?",
                                (new_gid, a["source_kind"], a["original_path"]),
                            ).fetchone()
                            if row:
                                old_to_new_asset[int(a["id"])] = int(row["id"])
                            stats["assets_merged"] += 1

                        # Localization strings
                        loc_rows = src.execute(
                            "SELECT * FROM localization_strings WHERE game_id = ?", (old_gid,)
                        ).fetchall()
                        for lr in loc_rows:
                            self._conn.execute(
                                """
                                INSERT OR REPLACE INTO localization_strings(game_id, lang, str_key, str_value, source_asset_id)
                                VALUES (?, ?, ?, ?, ?)
                                """,
                                (
                                    new_gid,
                                    lr["lang"],
                                    lr["str_key"],
                                    lr["str_value"],
                                    old_to_new_asset.get(lr["source_asset_id"])
                                    if lr["source_asset_id"]
                                    else None,
                                ),
                            )

                        # Entities & relations
                        old_to_new_ent: dict[int, int] = {}
                        for e in src.execute("SELECT * FROM entities WHERE game_id = ?", (old_gid,)).fetchall():
                            self._conn.execute(
                                """
                                INSERT INTO entities(
                                    game_id, source_asset_id, entity_type, external_key,
                                    slug, display_name, raw_json, resolved_json
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                ON CONFLICT(game_id, entity_type, external_key) DO UPDATE SET
                                    display_name = excluded.display_name,
                                    resolved_json = excluded.resolved_json
                                """,
                                (
                                    new_gid,
                                    old_to_new_asset.get(e["source_asset_id"])
                                    if e["source_asset_id"]
                                    else None,
                                    e["entity_type"],
                                    e["external_key"],
                                    e["slug"],
                                    e["display_name"],
                                    e["raw_json"],
                                    e["resolved_json"],
                                ),
                            )
                            erow = self._conn.execute(
                                "SELECT id FROM entities WHERE game_id = ? AND entity_type = ? AND external_key = ?",
                                (new_gid, e["entity_type"], e["external_key"]),
                            ).fetchone()
                            if erow:
                                old_to_new_ent[int(e["id"])] = int(erow["id"])
                            stats["entities_merged"] += 1

                        for r in src.execute(
                            "SELECT * FROM entity_relations WHERE game_id = ?", (old_gid,)
                        ).fetchall():
                            src_eid = old_to_new_ent.get(r["source_entity_id"])
                            if src_eid:
                                self._conn.execute(
                                    """
                                    INSERT INTO entity_relations(
                                        game_id, source_entity_id, relation_type,
                                        target_entity_id, target_ref, metadata_json
                                    ) VALUES (?, ?, ?, ?, ?, ?)
                                    """,
                                    (
                                        new_gid,
                                        src_eid,
                                        r["relation_type"],
                                        old_to_new_ent.get(r["target_entity_id"])
                                        if r["target_entity_id"]
                                        else None,
                                        r["target_ref"],
                                        r["metadata_json"],
                                    ),
                                )
        finally:
            src.close()
        return stats
