"""Tests for CAS Vault deduplication, long paths, case collisions, and traversal defense."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from ugav.vault.storage import VaultStorage, sanitize_export_relpath


def test_vault_deduplication_and_case_collision(tmp_path: Path) -> None:
    vault = VaultStorage(tmp_path / "vault", min_free_gb=0.0)
    payload = b"identical-texture-payload" * 50

    sha1, sz1, rel1, dedup1 = vault.store_stream(io.BytesIO(payload), ".png", copy_to_vault=True)
    sha2, sz2, rel2, dedup2 = vault.store_stream(io.BytesIO(payload), ".png", copy_to_vault=True)

    assert sha1 == sha2
    assert sz1 == sz2 == len(payload)
    assert rel1 == rel2
    assert dedup1 is False
    assert dedup2 is True

    # Simulate exporting both Icon.png and icon.png safely without path crash
    export_dir = tmp_path / "exported"
    res = vault.export_assets_tree(
        [
            {"original_path": "UI/Icon.png", "vault_rel_path": rel1},
            {"original_path": "UI/Sub/CON.png", "vault_rel_path": rel2},
        ],
        export_dir,
    )
    assert res["exported"] == 2
    assert (export_dir / "UI" / "Icon.png").is_file()
    assert (export_dir / "UI" / "Sub" / "_CON.png").is_file()


def test_sanitize_export_rejects_traversal_and_cleans_illegal_chars() -> None:
    with pytest.raises(ValueError):
        sanitize_export_relpath("../../Windows/System32/evil.dll")

    cleaned = sanitize_export_relpath(r'C:\weird:dir*?/name|file?.txt')
    assert ".." not in str(cleaned)
    assert ":" not in str(cleaned)
    assert "*" not in str(cleaned)
    assert "?" not in str(cleaned)
    assert "|" not in str(cleaned)


def test_long_path_export_on_windows(tmp_path: Path) -> None:
    vault = VaultStorage(tmp_path / "vault", min_free_gb=0.0)
    sha, _, rel, _ = vault.store_stream(io.BytesIO(b"deep-data"), ".txt", copy_to_vault=True)
    deep_rel = "/".join(["nested_directory_segment_1234567890"] * 10) + "/deep_asset.txt"
    out_dir = tmp_path / "out"
    res = vault.export_assets_tree([{"original_path": deep_rel, "vault_rel_path": rel}], out_dir)
    assert res["exported"] == 1
