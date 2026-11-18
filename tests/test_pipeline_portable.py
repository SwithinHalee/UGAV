"""Tests for incremental scanning, DDS->PNG conversion, relocate, and cross-device vault merge."""

from __future__ import annotations

from pathlib import Path

from tests.conftest import make_dds_bytes, make_png_bytes
from ugav.config import ScanConfig
from ugav.db.repository import DatabaseRepository
from ugav.pipeline import ScanPipeline
from ugav.vault.storage import VaultStorage


def test_incremental_scan_and_dds_conversion(tmp_path: Path) -> None:
    game = tmp_path / "MyGame"
    (game / "textures").mkdir(parents=True)
    (game / "data").mkdir(parents=True)
    (game / "textures" / "shield.dds").write_bytes(make_dds_bytes(16, 16))
    (game / "data" / "stats.json").write_text('{"id": 1, "name": "Aegis"}', encoding="utf-8")

    data_dir = tmp_path / "ugav_data"
    repo = DatabaseRepository(data_dir / "ugav.sqlite")
    vault = VaultStorage(data_dir / "vault", min_free_gb=0.0)
    try:
        pipe = ScanPipeline(repo, vault, data_dir, ScanConfig(min_free_gb=0.0, convert_textures=True))
        s1 = pipe.scan_game(game)
        assert s1.status == "completed"
        assert s1.assets_indexed == 2
        g = repo.get_game_by_slug(s1.game["slug"])
        assert g is not None
        assets = repo.query_assets_paginated(g["id"])["items"]
        dds_row = [a for a in assets if a["extension"] == ".dds"][0]
        assert dds_row["preview_rel_path"] is not None
        assert (vault.vault_dir / dds_row["preview_rel_path"]).is_file()
        # Verify per-game clean mirror folder vault/<slug>/ was created automatically (without a1/b2 hash folders)
        mirror_dir = vault.vault_dir / s1.game["slug"]
        assert (mirror_dir / "textures" / "shield.dds").is_file()
        assert (mirror_dir / "data" / "stats.json").is_file()
        assert not (vault.vault_dir / "objects").exists()

        # Re-scan unchanged -> 0 new bytes copied; delete shield.dds -> marked missing
        (game / "textures" / "shield.dds").unlink()
        s2 = pipe.scan_game(game)
        assert s2.bytes_copied == 0
        assert s2.missing_marked == 1
    finally:
        repo.close()


def test_relocate_and_merge_across_devices(tmp_path: Path) -> None:
    # Device A
    game_a = tmp_path / "DeviceA" / "CoolGame"
    game_a.mkdir(parents=True)
    (game_a / "sprite.png").write_bytes(make_png_bytes(10, 10))
    data_a = tmp_path / "data_a"
    repo_a = DatabaseRepository(data_a / "ugav.sqlite")
    vault_a = VaultStorage(data_a / "vault", min_free_gb=0.0)

    # Device B
    game_b = tmp_path / "DeviceB" / "OtherGame"
    game_b.mkdir(parents=True)
    (game_b / "config.json").write_text('{"name": "OtherTitle", "hp": 50}', encoding="utf-8")
    data_b = tmp_path / "data_b"
    repo_b = DatabaseRepository(data_b / "ugav.sqlite")
    vault_b = VaultStorage(data_b / "vault", min_free_gb=0.0)

    try:
        sa = ScanPipeline(repo_a, vault_a, data_a, ScanConfig(min_free_gb=0.0)).scan_game(game_a)
        ScanPipeline(repo_b, vault_b, data_b, ScanConfig(min_free_gb=0.0)).scan_game(game_b)

        # Relocate Game A to a new drive path
        moved_dir = tmp_path / "NewDrive" / "CoolGame"
        moved_dir.mkdir(parents=True)
        relocated = repo_a.relocate_game(sa.game["slug"], moved_dir)
        assert Path(relocated["root_path"]) == moved_dir.resolve()

        repo_b.close()
        merge_res = repo_a.merge_from_other_db(data_b / "ugav.sqlite", vault_b.vault_dir, vault_a.vault_dir)
        assert merge_res["games_merged"] == 1
        assert merge_res["blobs_copied"] == 1
        assert len(repo_a.list_games()) == 2
        assert len(repo_a.search_entities_fts("OtherTitle")) == 1
    finally:
        repo_a.close()


def test_custom_per_game_vault_location(tmp_path: Path) -> None:
    game = tmp_path / "CustomLocGame"
    (game / "art").mkdir(parents=True)
    (game / "art" / "hero.png").write_bytes(make_png_bytes(16, 16))

    custom_vault = tmp_path / "MyCustomExports" / "CustomLocGameAssets"
    data_dir = tmp_path / "ugav_data"
    repo = DatabaseRepository(data_dir / "ugav.sqlite")
    vault = VaultStorage(data_dir / "vault", min_free_gb=0.0)
    try:
        cfg = ScanConfig(min_free_gb=0.0, output_vault_dir=str(custom_vault))
        summary = ScanPipeline(repo, vault, data_dir, cfg).scan_game(game)
        assert summary.status == "completed"
        assert summary.game["metadata"]["vault_location"] == str(custom_vault.resolve())
        assert (custom_vault / "art" / "hero.png").is_file()
    finally:
        repo.close()
