"""Tests for PyInstaller frozen _MEIPASS path resolution and --noconsole stdio fallback."""

from __future__ import annotations

import sys
from pathlib import Path

from ugav import paths
from ugav.gui.launcher import ensure_stdio_for_noconsole


def test_frozen_paths_separate_meipass_from_portable_data(tmp_path: Path, monkeypatch) -> None:
    fake_meipass = tmp_path / "_MEI12345"
    fake_exe_dir = tmp_path / "PortableApp"
    fake_meipass.mkdir()
    fake_exe_dir.mkdir()
    (fake_meipass / "rules").mkdir()

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(fake_meipass), raising=False)
    monkeypatch.setattr(sys, "executable", str(fake_exe_dir / "UGAV.exe"), raising=False)
    monkeypatch.delenv("UGAV_DATA_DIR", raising=False)

    assert paths.get_bundle_root() == fake_meipass.resolve()
    data_dir = paths.get_portable_data_dir()
    assert data_dir == (fake_exe_dir / "ugav_data").resolve()
    assert (data_dir / paths.VAULT_MARKER_FILENAME).is_file()
    assert fake_meipass.resolve() not in data_dir.parents


def test_noconsole_stdout_stderr_none_safe(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    ensure_stdio_for_noconsole(tmp_path / "logs")
    assert sys.stdout is not None
    assert sys.stderr is not None
    assert sys.stdout.isatty() is False
    print("noconsole print test")
    assert (tmp_path / "logs" / "ugav.log").is_file()
