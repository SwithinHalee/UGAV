"""Tests for engine fingerprinting, magic-byte sniffer, and entropy detection."""

from __future__ import annotations

import os
from pathlib import Path

from tests.conftest import build_synthetic_gamemaker_win, make_png_bytes
from ugav.detectors.engine_fingerprint import fingerprint_game_directory
from ugav.detectors.entropy import calculate_bytes_entropy, classify_encryption_flag
from ugav.detectors.magic_sniffer import sniff_bytes


def test_magic_sniffer_ignores_fake_extension() -> None:
    png = make_png_bytes()
    res = sniff_bytes(png, extension=".dat")
    assert res.detected_format == "png"
    assert res.asset_category == "texture"
    assert res.detected_mime == "image/png"


def test_magic_sniffer_detects_shift_jis_xml() -> None:
    xml_sjis = '<?xml version="1.0" encoding="Shift_JIS"?><data><name>剣士</name></data>'.encode("cp932")
    res = sniff_bytes(xml_sjis, extension=".xml")
    assert res.detected_format == "xml"
    assert res.asset_category == "data"


def test_entropy_classifies_plain_vs_random() -> None:
    plain = b"A" * 4096
    rand = os.urandom(8192)
    h_plain = calculate_bytes_entropy(plain)
    h_rand = calculate_bytes_entropy(rand)
    assert h_plain == 0.0
    assert h_rand > 7.7
    assert classify_encryption_flag(h_plain, "text") == "none"
    assert classify_encryption_flag(h_rand, "unknown") == "suspected_encrypted"
    assert classify_encryption_flag(h_rand, "png") == "compressed"


def test_fingerprint_detects_gamemaker_and_middleware(tmp_path: Path) -> None:
    gm_dir = tmp_path / "GMGame"
    gm_dir.mkdir()
    build_synthetic_gamemaker_win(gm_dir / "data.win", make_png_bytes(), b"RIFF")
    (gm_dir / "bgm.ogg").write_bytes(b"OggS" + b"\x00" * 64)
    (gm_dir / "voice.wem").write_bytes(b"RIFF" + b"\x00" * 32)

    fp = fingerprint_game_directory(gm_dir)
    assert fp.detected_engine == "gamemaker"
    assert "wwise" in fp.middleware
    assert fp.is_online_stub is False


def test_fingerprint_flags_online_stub(tmp_path: Path) -> None:
    stub = tmp_path / "OnlineOnly"
    stub.mkdir()
    (stub / "Updater.exe").write_bytes(b"MZ" + b"\x00" * 1024)
    (stub / "online_manifest.json").write_text('{"cdn": "https://example.invalid"}', encoding="utf-8")

    fp = fingerprint_game_directory(stub)
    assert fp.is_online_stub is True
