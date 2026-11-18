"""Tests for cross-device auto-discovery and GameRootResolver."""

from __future__ import annotations

import json
from pathlib import Path

from ugav.discovery import discover_installed_games, resolve_game_root
from ugav.paths import VAULT_MARKER_FILENAME


def test_resolve_game_root_from_nested_exe(tmp_path: Path) -> None:
    game_root = tmp_path / "Games" / "CoolUnrealGame"
    (game_root / "Engine").mkdir(parents=True)
    exe_dir = game_root / "MyGame" / "Binaries" / "Win64"
    exe_dir.mkdir(parents=True)
    exe_file = exe_dir / "MyGame-Win64-Shipping.exe"
    exe_file.write_bytes(b"MZ")

    resolved = resolve_game_root(exe_file)
    assert resolved == game_root.resolve()


def test_resolve_game_root_stops_before_common_container(tmp_path: Path) -> None:
    common = tmp_path / "steamapps" / "common"
    game_root = common / "IndieGame"
    game_root.mkdir(parents=True)
    exe = game_root / "IndieGame.exe"
    exe.write_bytes(b"MZ")

    resolved = resolve_game_root(exe)
    assert resolved == game_root.resolve()


def test_discover_steam_vdf_acf_and_epic_excludes_vault(tmp_path: Path) -> None:
    steam_main = tmp_path / "SteamMain"
    steam_lib2 = tmp_path / "SteamLib2"
    (steam_main / "steamapps").mkdir(parents=True)
    (steam_lib2 / "steamapps" / "common" / "AwesomeRPG").mkdir(parents=True)
    (steam_main / "steamapps" / "common" / "Steamworks Shared").mkdir(parents=True)

    vdf_text = f'"libraryfolders"\n{{\n\t"0"\n\t{{\n\t\t"path"\t\t"{str(steam_lib2).replace("\\", "\\\\")}"\n\t}}\n}}\n'
    (steam_main / "steamapps" / "libraryfolders.vdf").write_text(vdf_text, encoding="utf-8")
    (steam_lib2 / "steamapps" / "appmanifest_1234.acf").write_text(
        '"AppState"\n{\n\t"appid"\t\t"1234"\n\t"name"\t\t"Awesome RPG"\n\t"installdir"\t\t"AwesomeRPG"\n}\n',
        encoding="utf-8",
    )

    epic_dir = tmp_path / "EpicManifests"
    epic_dir.mkdir()
    epic_game = tmp_path / "EpicGames" / "SpaceSim"
    epic_game.mkdir(parents=True)
    (epic_dir / "abc.item").write_text(
        json.dumps({"DisplayName": "Space Sim", "InstallLocation": str(epic_game), "CatalogItemId": "xyz"}),
        encoding="utf-8",
    )

    # Vault self-exclusion inside extra_roots
    data_dir = tmp_path / "ugav_data"
    data_dir.mkdir()
    (data_dir / VAULT_MARKER_FILENAME).write_text("marker", encoding="utf-8")

    found = discover_installed_games(
        extra_roots=[data_dir],
        data_dir=data_dir,
        steam_paths=[steam_main],
        epic_manifests_dir=epic_dir,
    )
    names = {g.name for g in found}
    assert "Awesome RPG" in names
    assert "Space Sim" in names
    assert "Steamworks Shared" not in names
    assert "ugav_data" not in names
