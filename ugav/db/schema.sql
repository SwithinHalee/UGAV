PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS games (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    slug             TEXT NOT NULL UNIQUE,
    name             TEXT NOT NULL,
    root_path        TEXT NOT NULL UNIQUE,
    fingerprint_hash TEXT NOT NULL DEFAULT '',
    source_platform  TEXT NOT NULL DEFAULT 'windows',
    detected_engine  TEXT NOT NULL,
    middleware_json  TEXT NOT NULL DEFAULT '[]',
    cpu_arch         TEXT NOT NULL DEFAULT 'unknown',
    confidence       REAL NOT NULL DEFAULT 0.0,
    is_online_stub   INTEGER NOT NULL DEFAULT 0,
    metadata_json    TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    game_id         INTEGER NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    copy_mode       TEXT NOT NULL,
    status          TEXT NOT NULL,
    files_scanned   INTEGER NOT NULL DEFAULT 0,
    assets_indexed  INTEGER NOT NULL DEFAULT 0,
    entities_parsed INTEGER NOT NULL DEFAULT 0,
    started_at      TEXT NOT NULL,
    finished_at     TEXT
);

CREATE TABLE IF NOT EXISTS blobs (
    sha256           TEXT PRIMARY KEY,
    size_bytes       INTEGER NOT NULL,
    vault_rel_path   TEXT,
    preview_rel_path TEXT,
    detected_mime    TEXT NOT NULL,
    detected_format  TEXT NOT NULL,
    entropy          REAL NOT NULL DEFAULT 0.0,
    encryption_flag  TEXT NOT NULL DEFAULT 'none',
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    game_id         INTEGER NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    parent_asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    blob_sha256     TEXT REFERENCES blobs(sha256),
    original_path   TEXT NOT NULL,
    source_kind     TEXT NOT NULL,
    source_offset   INTEGER,
    source_size     INTEGER NOT NULL,
    source_mtime_ns INTEGER,
    extension       TEXT NOT NULL,
    asset_category  TEXT NOT NULL,
    is_missing      INTEGER NOT NULL DEFAULT 0,
    metadata_json   TEXT NOT NULL DEFAULT '{}',
    UNIQUE(game_id, source_kind, original_path)
);

CREATE INDEX IF NOT EXISTS idx_assets_game_cat ON assets(game_id, asset_category, is_missing);
CREATE INDEX IF NOT EXISTS idx_assets_blob ON assets(blob_sha256);
CREATE INDEX IF NOT EXISTS idx_assets_parent ON assets(parent_asset_id);

CREATE TABLE IF NOT EXISTS entities (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    game_id         INTEGER NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    source_asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    entity_type     TEXT NOT NULL,
    external_key    TEXT NOT NULL,
    slug            TEXT NOT NULL,
    display_name    TEXT,
    raw_json        TEXT NOT NULL,
    resolved_json   TEXT NOT NULL DEFAULT '{}',
    UNIQUE(game_id, entity_type, external_key)
);

CREATE INDEX IF NOT EXISTS idx_entities_lookup ON entities(game_id, entity_type, slug);

CREATE TABLE IF NOT EXISTS entity_relations (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    game_id          INTEGER NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    source_entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    relation_type    TEXT NOT NULL,
    target_entity_id INTEGER REFERENCES entities(id) ON DELETE CASCADE,
    target_ref       TEXT NOT NULL,
    metadata_json    TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_relations_source ON entity_relations(source_entity_id);
CREATE INDEX IF NOT EXISTS idx_relations_target ON entity_relations(target_entity_id);

CREATE TABLE IF NOT EXISTS localization_strings (
    game_id         INTEGER NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    lang            TEXT NOT NULL,
    str_key         TEXT NOT NULL,
    str_value       TEXT NOT NULL,
    source_asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    PRIMARY KEY (game_id, lang, str_key)
);

CREATE TABLE IF NOT EXISTS scan_warnings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    game_id     INTEGER NOT NULL REFERENCES games(id) ON DELETE CASCADE,
    path        TEXT NOT NULL,
    stage       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    message     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS entities_fts USING fts5(
    display_name, external_key, entity_type, resolved_json,
    content='entities', content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS entities_ai AFTER INSERT ON entities BEGIN
    INSERT INTO entities_fts(rowid, display_name, external_key, entity_type, resolved_json)
    VALUES (new.id, COALESCE(new.display_name, ''), new.external_key, new.entity_type, new.resolved_json);
END;

CREATE TRIGGER IF NOT EXISTS entities_ad AFTER DELETE ON entities BEGIN
    INSERT INTO entities_fts(entities_fts, rowid, display_name, external_key, entity_type, resolved_json)
    VALUES ('delete', old.id, COALESCE(old.display_name, ''), old.external_key, old.entity_type, old.resolved_json);
END;

CREATE TRIGGER IF NOT EXISTS entities_au AFTER UPDATE ON entities BEGIN
    INSERT INTO entities_fts(entities_fts, rowid, display_name, external_key, entity_type, resolved_json)
    VALUES ('delete', old.id, COALESCE(old.display_name, ''), old.external_key, old.entity_type, old.resolved_json);
    INSERT INTO entities_fts(rowid, display_name, external_key, entity_type, resolved_json)
    VALUES (new.id, COALESCE(new.display_name, ''), new.external_key, new.entity_type, new.resolved_json);
END;
