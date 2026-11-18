"""Tests for all native archive adapters, non-ASCII ZIPs, CRILAYLA, and Binary Carver."""

from __future__ import annotations

import json
import struct
import zipfile
import zlib
from pathlib import Path

from tests.conftest import (
    build_synthetic_asar,
    build_synthetic_cpk,
    build_synthetic_gamemaker_win,
    build_synthetic_rpa,
    make_dds_bytes,
    make_png_bytes,
    make_wav_bytes,
)
from ugav.adapters.asar_adapter import AsarAdapter
from ugav.adapters.base import AdapterOptions
from ugav.adapters.bethesda_bsa import BethesdaBsaAdapter
from ugav.adapters.binary_carver import carve_embedded_assets
from ugav.adapters.cri_cpk import CriCpkAdapter
from ugav.adapters.gamemaker_iff import GameMakerIffAdapter
from ugav.adapters.godot_pck import GodotPckAdapter
from ugav.adapters.renpy_rpa import RenPyRpaAdapter
from ugav.adapters.rpgmaker import RpgMakerMediaAdapter
from ugav.adapters.valve_vpk import ValveVpkAdapter
from ugav.adapters.zip_adapter import ZipArchiveAdapter


def test_zip_adapter_recovers_shift_jis_filename(tmp_path: Path) -> None:
    zp = tmp_path / "sjis.zip"
    sjis_bytes = "テスト/画像.png".encode("cp932")
    placeholder = b"A" * len(sjis_bytes)
    assert len(placeholder) == len(sjis_bytes)
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("normal.txt", b"hello")
        zf.writestr(placeholder.decode("ascii"), make_png_bytes())
    # Patch ASCII placeholder bytes in both local header and central directory with Shift-JIS bytes
    zp.write_bytes(zp.read_bytes().replace(placeholder, sjis_bytes))

    entries = list(ZipArchiveAdapter().iter_entries(zp, AdapterOptions()))
    paths = [e.virtual_path for e in entries]
    assert "normal.txt" in paths
    assert "テスト/画像.png" in paths


def test_cri_cpk_plain_and_lcg_encrypted_with_crilayla(tmp_path: Path) -> None:
    dds_raw = make_dds_bytes(16, 16)
    assert len(dds_raw) > 0x100
    plain_cpk = build_synthetic_cpk(
        tmp_path / "plain.cpk",
        [("tex", "hero.dds", dds_raw, True), ("cfg", "info.txt", b"hello-cpk", False)],
        encrypt_utf=False,
    )
    enc_cpk = build_synthetic_cpk(
        tmp_path / "encrypted_utf.cpk",
        [("tex", "boss.dds", dds_raw, True)],
        encrypt_utf=True,
    )

    ad = CriCpkAdapter()
    opts = AdapterOptions()

    plain_entries = {e.virtual_path: e for e in ad.iter_entries(plain_cpk, opts)}
    assert set(plain_entries) == {"tex/hero.dds", "cfg/info.txt"}
    with plain_entries["tex/hero.dds"].open_stream() as s:
        assert s.read() == dds_raw
    with plain_entries["cfg/info.txt"].open_stream() as s:
        assert s.read() == b"hello-cpk"

    enc_entries = {e.virtual_path: e for e in ad.iter_entries(enc_cpk, opts)}
    assert "tex/boss.dds" in enc_entries
    with enc_entries["tex/boss.dds"].open_stream() as s:
        assert s.read() == dds_raw


def test_gamemaker_iff_extracts_txtr_and_audo(tmp_path: Path) -> None:
    png = make_png_bytes()
    wav = make_wav_bytes()
    win_p = build_synthetic_gamemaker_win(tmp_path / "data.win", png, wav)
    entries = {e.virtual_path: e for e in GameMakerIffAdapter().iter_entries(win_p, AdapterOptions())}
    assert "textures/txtr_0000.png" in entries
    assert "audio/audo_0000.wav" in entries
    with entries["textures/txtr_0000.png"].open_stream() as s:
        assert s.read() == png
    with entries["audio/audo_0000.wav"].open_stream() as s:
        assert s.read() == wav


def test_gamemaker_iff_decodes_2zoq_qoi_to_png() -> None:
    import bz2
    from ugav.adapters.gamemaker_iff import decode_fioq_to_png

    # 2x2 solid red QOI run: 1x RGBA literal + 3x run (0xC0 | 2)
    qoi_pixels = bytes([0xFF, 255, 0, 0, 255, 0xC0 | 2])
    fioq = b"fioq" + struct.pack("<HHI", 2, 2, len(qoi_pixels)) + qoi_pixels
    png_out = decode_fioq_to_png(fioq)
    assert png_out is not None and png_out.startswith(b"\x89PNG")
    # Also verify bz2 roundtrip as used by 2zoq
    comp = bz2.compress(fioq)
    assert decode_fioq_to_png(bz2.decompress(comp)) == png_out


def test_godot_pck_and_renpy_rpa_and_asar(tmp_path: Path) -> None:
    # Godot PCK v1
    pck = tmp_path / "game.pck"
    payload = b'{"hp": 100}'
    hdr = bytearray(20 + 64)
    hdr[0:4] = b"GDPC"
    struct.pack_into("<IIII", hdr, 4, 1, 4, 2, 0)
    res_path = b"res://data/stats.json\x00"
    data_off = len(hdr) + 4 + 4 + len(res_path) + 32
    rec = struct.pack("<I", len(res_path)) + res_path + struct.pack("<QQ16s", data_off, len(payload), b"\x00" * 16)
    pck.write_bytes(bytes(hdr) + struct.pack("<I", 1) + rec + payload)
    pck_entries = list(GodotPckAdapter().iter_entries(pck, AdapterOptions()))
    assert pck_entries[0].virtual_path == "data/stats.json"
    assert pck_entries[0].open_stream().read() == payload

    # RenPy RPA
    rpa = build_synthetic_rpa(tmp_path / "data.rpa", {"script.rpy": b"label start:\n  pass\n"})
    rpa_entries = list(RenPyRpaAdapter().iter_entries(rpa, AdapterOptions()))
    assert rpa_entries[0].virtual_path == "script.rpy"
    assert b"label start" in rpa_entries[0].open_stream().read()

    # Electron ASAR
    asar = build_synthetic_asar(tmp_path / "app.asar", {"package.json": b'{"name":"demo"}'})
    asar_entries = list(AsarAdapter().iter_entries(asar, AdapterOptions()))
    assert asar_entries[0].virtual_path == "package.json"
    assert asar_entries[0].open_stream().read() == b'{"name":"demo"}'


def test_rpgmaker_xor_media_and_vpk_and_ba2_and_carver(tmp_path: Path) -> None:
    # RPG Maker .rpgmvp with System.json key
    rm_dir = tmp_path / "RPGM"
    (rm_dir / "data").mkdir(parents=True)
    (rm_dir / "img").mkdir(parents=True)
    key_hex = "00112233445566778899aabbccddeeff"
    key = bytes.fromhex(key_hex)
    (rm_dir / "data" / "System.json").write_text(json.dumps({"encryptionKey": key_hex}), encoding="utf-8")
    orig_png = make_png_bytes()
    enc_body = bytearray(orig_png)
    for i in range(16):
        enc_body[i] ^= key[i]
    rpgmvp = rm_dir / "img" / "hero.rpgmvp"
    rpgmvp.write_bytes(b"RPGMV\x00\x00\x00" + b"\x00" * 8 + bytes(enc_body))
    rm_entries = list(RpgMakerMediaAdapter().iter_entries(rpgmvp, AdapterOptions()))
    assert rm_entries[0].virtual_path == "hero.png"
    assert rm_entries[0].open_stream().read() == orig_png

    # Valve VPK v1
    vpk = tmp_path / "pak01_dir.vpk"
    tree = b"txt\x00cfg\x00autoexec\x00" + struct.pack("<IHHIIH", 0, 0, 0x7FFF, 0, 7, 0xFFFF) + b"\x00\x00\x00"
    vpk_hdr = struct.pack("<III", 0x55AA1234, 1, len(tree))
    vpk.write_bytes(vpk_hdr + tree + b"sv_lan1")
    vpk_entries = list(ValveVpkAdapter().iter_entries(vpk, AdapterOptions()))
    assert vpk_entries[0].virtual_path == "cfg/autoexec.txt"
    assert vpk_entries[0].open_stream().read() == b"sv_lan1"

    # Bethesda BA2 GNRL
    ba2 = tmp_path / "test.ba2"
    raw_txt = b"hello bethesda ba2" * 5
    comp_txt = zlib.compress(raw_txt)
    name_bytes = b"misc/readme.txt"
    name_tbl = struct.pack("<H", len(name_bytes)) + name_bytes
    rec_off = 24 + 36
    name_off = rec_off + len(comp_txt)
    ba2_hdr = struct.pack("<4sI4sIQ", b"BTDX", 1, b"GNRL", 1, name_off)
    ba2_rec = struct.pack("<I4sIIQIII", 0, b"txt\x00", 0, 0, rec_off, len(comp_txt), len(raw_txt), 0xBAADF00D)
    ba2.write_bytes(ba2_hdr + ba2_rec + comp_txt + name_tbl)
    ba2_entries = list(BethesdaBsaAdapter().iter_entries(ba2, AdapterOptions()))
    assert ba2_entries[0].virtual_path == "misc/readme.txt"
    assert ba2_entries[0].open_stream().read() == raw_txt

    # Binary Carver fallback
    blob = tmp_path / "mystery.dat"
    wav = make_wav_bytes()
    blob.write_bytes(b"JUNKHEAD" + orig_png + b"MIDJUNK" + wav + b"TAIL")
    carved = list(carve_embedded_assets(blob, AdapterOptions()))
    assert len(carved) >= 2
    assert carved[0].open_stream().read() == orig_png
    assert carved[1].open_stream().read() == wav
