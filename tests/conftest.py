"""Shared synthetic fixture builders for UGAV test suite."""

from __future__ import annotations

import io
import json
import pickle
import struct
import zlib
from pathlib import Path

from PIL import Image


def make_png_bytes(width: int = 8, height: int = 8, color: tuple[int, int, int, int] = (255, 0, 128, 255)) -> bytes:
    buf = io.BytesIO()
    img = Image.new("RGBA", (width, height), color)
    img.save(buf, format="PNG")
    return buf.getvalue()


def make_wav_bytes(samples: int = 64) -> bytes:
    data = b"\x00\x00" * samples
    byte_rate = 44100 * 2
    riff_size = 36 + len(data)
    return b"RIFF" + struct.pack("<I", riff_size) + b"WAVEfmt " + struct.pack(
        "<IHHIIHH", 16, 1, 1, 44100, byte_rate, 2, 16
    ) + b"data" + struct.pack("<I", len(data)) + data


def make_dds_bytes(width: int = 8, height: int = 8) -> bytes:
    # Uncompressed 32-bit RGBA DDS
    pixel_data = b"\xff\x00\x80\xff" * (width * height)
    hdr = bytearray(128)
    hdr[0:4] = b"DDS "
    struct.pack_into("<IIIIIII", hdr, 4, 124, 0x1007, height, width, width * 4, 0, 1)
    # DDS_PIXELFORMAT at offset 76 (32 bytes): size=32, flags=0x41 (RGB+ALPHA), rgbBits=32, masks
    struct.pack_into("<IIIIIIII", hdr, 76, 32, 0x41, 0, 32, 0x00FF0000, 0x0000FF00, 0x000000FF, 0xFF000000)
    struct.pack_into("<I", hdr, 108, 0x1000)
    return bytes(hdr) + pixel_data


def build_utf_table(table_name: str, columns: list[tuple[str, int]], rows: list[dict]) -> bytes:
    """Build a minimal valid CRIWARE @UTF table (storage=5 per-row for simplicity)."""
    # Column types: 4=uint32, 6=uint64, 10=string
    str_pool = bytearray(b"<NULL>\x00")
    str_cache: dict[str, int] = {"<NULL>": 0}

    def add_str(s: str) -> int:
        if s in str_cache:
            return str_cache[s]
        off = len(str_pool)
        str_pool.extend(s.encode("utf-8") + b"\x00")
        str_cache[s] = off
        return off

    tname_off = add_str(table_name)
    col_defs = bytearray()
    row_len = 0
    for cname, ctype in columns:
        cname_off = add_str(cname)
        flags = (5 << 4) | ctype
        col_defs.append(flags)
        col_defs.extend(struct.pack(">I", cname_off))
        row_len += 8 if ctype in (6, 7) else 4

    rows_buf = bytearray()
    for row in rows:
        for cname, ctype in columns:
            val = row[cname]
            if ctype == 10:
                rows_buf.extend(struct.pack(">I", add_str(str(val))))
            elif ctype == 6:
                rows_buf.extend(struct.pack(">Q", int(val)))
            else:
                rows_buf.extend(struct.pack(">I", int(val)))

    rows_off = 24 + len(col_defs)
    str_off = rows_off + len(rows_buf)
    data_off = str_off + len(str_pool)
    body = (
        struct.pack(">IIIIHHI", rows_off, str_off, data_off, tname_off, len(columns), row_len, len(rows))
        + bytes(col_defs)
        + bytes(rows_buf)
        + bytes(str_pool)
    )
    return struct.pack(">4sI", b"@UTF", len(body)) + body


def encrypt_cri_utf(data: bytes) -> bytes:
    m = 0x655F
    t = 0x4115
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ (m & 0xFF)
        m = (m * t) & 0xFFFF
    return bytes(out)


def encode_crilayla_literal(payload: bytes) -> bytes:
    """Encode payload > 0x100 bytes as valid CRILAYLA stream (literal bits for roundtrip tests)."""
    assert len(payload) > 0x100
    prefix = payload[:0x100]
    tail = payload[0x100:]
    # Reverse encode bits: flag=0 (1 bit) + 8-bit literal for each byte from len(tail)-1 down to 0
    bit_stream = bytearray()
    cur_byte = 0
    cur_bits = 0
    for b in reversed(tail):
        # Write 9 bits (0 followed by 8 bits of b) MSB-first
        for bit_idx in range(8, -1, -1):
            bit = 0 if bit_idx == 8 else ((b >> bit_idx) & 1)
            cur_byte = (cur_byte << 1) | bit
            cur_bits += 1
            if cur_bits == 8:
                bit_stream.append(cur_byte)
                cur_byte = 0
                cur_bits = 0
    if cur_bits > 0:
        bit_stream.append(cur_byte << (8 - cur_bits))
    # decompressor reads bytes backwards from end of encoded buffer!
    encoded_rev = bytes(reversed(bit_stream))
    return b"CRILAYLA" + struct.pack("<II", len(tail), len(encoded_rev)) + encoded_rev + prefix


def build_synthetic_cpk(
    out_path: Path,
    entries: list[tuple[str, str, bytes, bool]],
    encrypt_utf: bool = False,
) -> Path:
    """Build a valid CRIWARE CPK file. entries: [(dir_name, file_name, raw_bytes, compress_crilayla)]."""
    toc_offset = 0x800
    payloads: list[tuple[str, str, bytes, int, int]] = []
    for dname, fname, raw, do_cmp in entries:
        stored = encode_crilayla_literal(raw) if (do_cmp and len(raw) > 0x100) else raw
        payloads.append((dname, fname, stored, len(stored), len(raw)))

    # First pass to get TOC size
    dummy_rows = [
        {"DirName": d, "FileName": f, "FileSize": fs, "ExtractSize": es, "FileOffset": 0, "ID": idx}
        for idx, (d, f, _, fs, es) in enumerate(payloads)
    ]
    cols = [("DirName", 10), ("FileName", 10), ("FileSize", 4), ("ExtractSize", 4), ("FileOffset", 6), ("ID", 4)]
    dummy_toc = build_utf_table("CpkTocInfo", cols, dummy_rows)
    content_offset = ((toc_offset + 16 + len(dummy_toc) + 0x7FF) // 0x800) * 0x800

    cur_off = content_offset
    real_rows = []
    for idx, (d, f, _st, fs, es) in enumerate(payloads):
        # FileOffset relative to min(TocOffset, ContentOffset) == toc_offset
        real_rows.append(
            {
                "DirName": d,
                "FileName": f,
                "FileSize": fs,
                "ExtractSize": es,
                "FileOffset": cur_off - toc_offset,
                "ID": idx,
            }
        )
        cur_off += fs

    toc_utf = build_utf_table("CpkTocInfo", cols, real_rows)
    if encrypt_utf:
        toc_utf = encrypt_cri_utf(toc_utf)

    hdr_cols = [("TocOffset", 6), ("ContentOffset", 6)]
    hdr_utf = build_utf_table("CpkHeader", hdr_cols, [{"TocOffset": toc_offset, "ContentOffset": content_offset}])
    if encrypt_utf:
        hdr_utf = encrypt_cri_utf(hdr_utf)

    buf = bytearray(cur_off)
    buf[0:4] = b"CPK "
    buf[4] = 0x00 if encrypt_utf else 0xFF
    buf[16 : 16 + len(hdr_utf)] = hdr_utf

    buf[toc_offset : toc_offset + 4] = b"TOC "
    buf[toc_offset + 16 : toc_offset + 16 + len(toc_utf)] = toc_utf

    pos = content_offset
    for _, _, stored, fs, _ in payloads:
        buf[pos : pos + fs] = stored
        pos += fs

    out_path.write_bytes(bytes(buf))
    return out_path


def build_synthetic_gamemaker_win(out_path: Path, png_bytes: bytes, wav_bytes: bytes) -> Path:
    gen8 = b"\x00" * 64
    strg = struct.pack("<I", 2) + b"\x00" * 8
    txtr = b"\x00\x00\x00\x00" + png_bytes
    # Build chunks sequentially so AUDO absolute offset is exact
    offset_after_audo_header = (
        8  # FORM + total
        + (8 + len(gen8))
        + (8 + len(strg))
        + (8 + len(txtr))
        + 8  # AUDO header
    )
    audio_ptr = offset_after_audo_header + 8  # count(4) + ptr(4)
    audo = struct.pack("<II", 1, audio_ptr) + struct.pack("<I", len(wav_bytes)) + wav_bytes

    def chunk(tag: bytes, data: bytes) -> bytes:
        return tag + struct.pack("<I", len(data)) + data

    body = chunk(b"GEN8", gen8) + chunk(b"STRG", strg) + chunk(b"TXTR", txtr) + chunk(b"AUDO", audo)
    out_path.write_bytes(b"FORM" + struct.pack("<I", len(body)) + body)
    return out_path


def build_synthetic_rpa(out_path: Path, files: dict[str, bytes], key: int = 0x12345678) -> Path:
    data_start = 34  # len("RPA-3.0 0000000000000000 00000000\n")
    buf = bytearray(b" " * data_start)
    index: dict[str, list[tuple[int, int, bytes]]] = {}
    pos = data_start
    for vpath, payload in files.items():
        buf.extend(payload)
        index[vpath] = [(pos ^ key, len(payload) ^ key, b"")]
        pos += len(payload)
    idx_off = pos
    buf.extend(zlib.compress(pickle.dumps(index)))
    header = f"RPA-3.0 {idx_off:016x} {key:08x}\n".encode("ascii")
    assert len(header) == data_start
    buf[:data_start] = header
    out_path.write_bytes(bytes(buf))
    return out_path


def build_synthetic_asar(out_path: Path, files: dict[str, bytes]) -> Path:
    tree: dict = {"files": {}}
    data = bytearray()
    for name, payload in files.items():
        tree["files"][name] = {"offset": str(len(data)), "size": len(payload)}
        data.extend(payload)
    jbytes = json.dumps(tree).encode("utf-8")
    pad = (4 - (len(jbytes) % 4)) % 4
    jbytes_padded = jbytes + (b"\x00" * pad)
    hdr_size = 8 + len(jbytes_padded)
    hdr = struct.pack("<IIII", 4, hdr_size, hdr_size - 4, len(jbytes)) + jbytes_padded
    out_path.write_bytes(hdr + bytes(data))
    return out_path
