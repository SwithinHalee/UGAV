"""Tests for generic structured translators, XXE protection, and declarative YAML rule engine."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from ugav.config import ScanConfig
from ugav.db.repository import DatabaseRepository
from ugav.pipeline import ScanPipeline
from ugav.translators.generic_structured import parse_structured_bytes, strip_jsonc
from ugav.vault.storage import VaultStorage


def test_generic_structured_parsers_and_xxe_safety(tmp_path: Path) -> None:
    # JSONC with comments and trailing comma
    jsonc_raw = b'// header comment\n{\n  "name": "Plasma Rifle",\n  /* block */\n  "damage": 45,\n}'
    assert '"damage": 45' in strip_jsonc(jsonc_raw.decode("utf-8"))
    ents, _ = parse_structured_bytes(jsonc_raw, "jsonc", "weapons/plasma.jsonc")
    assert ents[0].display_name == "Plasma Rifle"

    # XXE XML protection: external file entity must NOT resolve
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("TOP_SECRET_PASSWORD", encoding="utf-8")
    xxe_xml = (
        f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{secret_file.as_uri()}">]>'
        f"<item><name>&xxe;</name></item>"
    ).encode("utf-8")
    xents, _ = parse_structured_bytes(xxe_xml, "xml", "items/bad.xml")
    assert "TOP_SECRET_PASSWORD" not in str(xents[0].raw)

    # Embedded SQLite DB translation
    dbp = tmp_path / "items.sqlite"
    conn = sqlite3.connect(str(dbp))
    conn.execute("CREATE TABLE weapons (id INTEGER, name TEXT, atk INTEGER)")
    conn.execute("INSERT INTO weapons VALUES (1, 'Power Sword', 99)")
    conn.commit()
    conn.close()
    sents, _ = parse_structured_bytes(dbp.read_bytes(), "sqlite", "db/items.sqlite")
    assert any(e.display_name == "Power Sword" for e in sents)


def test_declarative_rule_engine_2pass_gladius_style(tmp_path: Path) -> None:
    game = tmp_path / "MiniGladius"
    (game / "Data" / "Core" / "Languages" / "English").mkdir(parents=True)
    (game / "Data" / "World" / "Factions").mkdir(parents=True)
    (game / "Data" / "World" / "Weapons").mkdir(parents=True)
    (game / "Data" / "World" / "Units" / "SpaceMarines").mkdir(parents=True)

    (game / "Data" / "Core" / "Languages" / "English" / "Units.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?><language>'
        '<entry name="TacticalMarine" value="Tactical Space Marine"/>'
        '<entry name="TacticalMarineDescription" value="Versatile Astartes infantry."/>'
        "</language>",
        encoding="utf-8",
    )
    (game / "Data" / "World" / "Factions" / "SpaceMarines.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?><faction/>', encoding="utf-8"
    )
    (game / "Data" / "World" / "Weapons" / "Bolter.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?><weapon><modifiers><modifier><effects><rangedDamage add="2"/></effects></modifier></modifiers></weapon>',
        encoding="utf-8",
    )
    (game / "Data" / "World" / "Units" / "SpaceMarines" / "TacticalMarine.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>'
        "<unit><weapons><weapon name=\"Bolter\"/></weapons>"
        "<modifiers><modifier><effects><armor base=\"8\"/></effects></modifier></modifiers></unit>",
        encoding="utf-8",
    )

    data_dir = tmp_path / "ugav_data"
    repo = DatabaseRepository(data_dir / "ugav.sqlite")
    vault = VaultStorage(data_dir / "vault", min_free_gb=0.0)
    try:
        summary = ScanPipeline(repo, vault, data_dir, ScanConfig(min_free_gb=0.0)).scan_game(game)
        assert summary.status == "completed"
        hits = repo.search_entities_fts("Tactical Space Marine")
        assert len(hits) == 1
        detail = repo.get_entity_detail(hits[0]["id"])
        assert detail is not None
        assert detail["resolved"]["stats"]["armor"]["base"] == "8"
        rel_targets = {(r["relation_type"], r["target_ref"]) for r in detail["relations"]}
        assert ("uses_weapon", "Bolter") in rel_targets
        assert ("belongs_to_faction", "SpaceMarines") in rel_targets
        assert all(r["target_entity_id"] is not None for r in detail["relations"])
    finally:
        repo.close()
