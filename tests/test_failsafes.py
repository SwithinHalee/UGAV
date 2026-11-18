"""Tests specifically verifying all 12 resilience & security failsafes."""

from __future__ import annotations

import ast
import io
import json
import os
import pickle
import sqlite3
import zipfile
from pathlib import Path

import pytest

from tests.conftest import build_synthetic_cpk, make_png_bytes
from ugav.adapters.base import AdapterOptions, EntryBoundsError
from ugav.adapters.cri_cpk import CriCpkAdapter
from ugav.adapters.external_bridge import reap_orphan_staging_dirs
from ugav.adapters.renpy_rpa import safe_unpickle_primitives
from ugav.config import ScanConfig
from ugav.db.migrations import ensure_migrated
from ugav.db.repository import DatabaseRepository
from ugav.gui.launcher import check_existing_instance
from ugav.paths import SelfScanError, VAULT_MARKER_FILENAME
from ugav.pipeline import ScanPipeline
from ugav.vault.storage import DiskSpaceExhaustedError, VaultStorage


def test_failsafe_disk_space_floor_cleans_tmp(tmp_path: Path, monkeypatch) -> None:
    vault = VaultStorage(tmp_path / "vault", min_free_gb=2.0)

    class _LowDisk:
        total = 100 * 1024**3
        used = 99 * 1024**3
        free = 512 * 1024**2  # 0.5 GB < 2.0 GB floor

    monkeypatch.setattr("ugav.vault.storage.shutil.disk_usage", lambda _: _LowDisk())
    with pytest.raises(DiskSpaceExhaustedError):
        vault.store_stream(io.BytesIO(b"abc"), ".bin", copy_to_vault=True)
    assert list(vault.tmp_dir.glob("*.tmp")) == []


def test_failsafe_corrupt_archive_entry_and_memory_bomb_isolation(tmp_path: Path) -> None:
    # Build a valid CPK, then corrupt only entry 0's ExtractSize in the TOC on disk to 0xFFFFFFFF (memory bomb)
    # while leaving entry 1 valid and readable!
    import struct

    cpk = build_synthetic_cpk(
        tmp_path / "mixed.cpk",
        [
            ("bad", "bomb.bin", b"A" * 512, True),
            ("good", "ok.png", make_png_bytes(), False),
        ],
    )
    raw = bytearray(cpk.read_bytes())
    # Replace big-endian ExtractSize=512 (0x00000200) inside TOC (@0x800..0x900) with 0xFFFFFFFF
    toc_slice = raw[0x800:0x900]
    marker = struct.pack(">I", 512)
    rel_idx = toc_slice.index(marker)
    raw[0x800 + rel_idx : 0x800 + rel_idx + 4] = b"\xff\xff\xff\xff"
    cpk.write_bytes(bytes(raw))

    entries = list(CriCpkAdapter().iter_entries(cpk, AdapterOptions()))
    assert entries[0].uncompressed_size == 0xFFFFFFFF
    with pytest.raises(EntryBoundsError):
        entries[0].open_stream()
    # Entry 1 must still extract cleanly
    assert entries[1].open_stream().read().startswith(b"\x89PNG")


def test_failsafe_zip_bomb_stream_cap(tmp_path: Path) -> None:
    zp = tmp_path / "bomb.zip"
    with zipfile.ZipFile(zp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge.txt", b"Z" * 100_000)

    from ugav.adapters.zip_adapter import ZipArchiveAdapter

    entries = list(ZipArchiveAdapter().iter_entries(zp, AdapterOptions(max_entry_bytes=4096, max_ratio=5.0)))
    with pytest.raises(EntryBoundsError):
        with entries[0].open_stream() as s:
            s.read()


def test_failsafe_self_scan_rejected(tmp_path: Path) -> None:
    data_dir = tmp_path / "ugav_data"
    repo = DatabaseRepository(data_dir / "ugav.sqlite")
    vault = VaultStorage(data_dir / "vault", min_free_gb=0.0)
    try:
        pipe = ScanPipeline(repo, vault, data_dir, ScanConfig(min_free_gb=0.0))
        with pytest.raises(SelfScanError):
            pipe.scan_game(vault.vault_dir)
    finally:
        repo.close()


def test_failsafe_vault_subdir_skipped_when_inside_target(tmp_path: Path) -> None:
    game = tmp_path / "ParentGames"
    sub_game = game / "GameOne"
    sub_game.mkdir(parents=True)
    (sub_game / "hello.txt").write_text("hi", encoding="utf-8")

    # Put ugav_data INSIDE the scanned directory!
    data_dir = game / "ugav_data"
    repo = DatabaseRepository(data_dir / "ugav.sqlite")
    vault = VaultStorage(data_dir / "vault", min_free_gb=0.0)
    try:
        assert (data_dir / VAULT_MARKER_FILENAME).is_file()
        summary = ScanPipeline(repo, vault, data_dir, ScanConfig(min_free_gb=0.0)).scan_game(game)
        # Only GameOne/hello.txt should be indexed, never ugav_data files!
        assert summary.assets_indexed == 1
    finally:
        repo.close()


def test_failsafe_orphan_staging_reaper(tmp_path: Path) -> None:
    data_dir = tmp_path / "ugav_data"
    dead_stage = data_dir / "staging" / "99999999_deadbeef"
    live_stage = data_dir / "staging" / f"{os.getpid()}_alive123"
    dead_stage.mkdir(parents=True)
    live_stage.mkdir(parents=True)
    (dead_stage / "orphan.tmp").write_bytes(b"junk")
    (live_stage / "active.tmp").write_bytes(b"keep")

    removed = reap_orphan_staging_dirs(data_dir)
    assert removed == 1
    assert not dead_stage.exists()
    assert live_stage.exists()


def test_failsafe_schema_migration_creates_backup(tmp_path: Path) -> None:
    db_path = tmp_path / "ugav.sqlite"
    assert ensure_migrated(db_path, target_version=1) == 1
    ver2 = ensure_migrated(
        db_path,
        target_version=2,
        migrations={2: ["ALTER TABLE games ADD COLUMN notes TEXT DEFAULT '';"]},
    )
    assert ver2 == 2
    assert db_path.with_suffix(".sqlite.bak").is_file()
    conn = sqlite3.connect(str(db_path))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(games)").fetchall()]
    conn.close()
    assert "notes" in cols


def test_failsafe_restricted_renpy_pickle_rejects_code_execution() -> None:
    class _Evil:
        def __reduce__(self):
            return (os.system, ("echo pwned",))

    malicious = pickle.dumps({"x": _Evil()})
    with pytest.raises(pickle.UnpicklingError):
        safe_unpickle_primitives(malicious)


def test_failsafe_single_instance_runtime_check(tmp_path: Path, monkeypatch) -> None:
    data_dir = tmp_path / "ugav_data"
    data_dir.mkdir()
    (data_dir / "ugav.runtime.json").write_text(
        json.dumps({"pid": 424242, "port": 55555, "token": "abc"}), encoding="utf-8"
    )
    monkeypatch.setattr("ugav.gui.launcher.psutil.pid_exists", lambda pid: pid == 424242)
    monkeypatch.setattr("ugav.gui.launcher._is_port_listening", lambda h, p: p == 55555)
    assert check_existing_instance(data_dir) == "http://127.0.0.1:55555/?token=abc"


def test_failsafe_zero_network_egress_in_scan_modules() -> None:
    pkg_root = Path(__file__).resolve().parent.parent / "ugav"
    forbidden_modules = {"requests", "httpx", "urllib", "urllib3", "aiohttp", "websockets"}
    scan_dirs = ("detectors", "adapters", "vault")
    scan_files = [pkg_root / "pipeline.py"]
    for sd in scan_dirs:
        scan_files.extend((pkg_root / sd).glob("*.py"))

    for py_file in scan_files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert top not in forbidden_modules, f"Forbidden HTTP import {top} in {py_file}"
            elif isinstance(node, ast.ImportFrom) and node.module:
                top = node.module.split(".")[0]
                assert top not in forbidden_modules, f"Forbidden HTTP import {top} in {py_file}"
