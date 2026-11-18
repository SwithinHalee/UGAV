"""GameMaker Studio IFF/FORM container unpacker (TXTR PNG & 2zoq/fioq QOI, AUDO, STRG, SPRT, OBJT, ROOM)."""

from __future__ import annotations

import bz2
import io
import json
import struct
from pathlib import Path
from typing import BinaryIO, Iterator

from PIL import Image

from ugav.adapters.base import (
    AdapterOptions,
    ArchiveCorruptError,
    ArchiveEntry,
    BaseArchiveAdapter,
    BoundedFileSlice,
    validate_entry_bounds,
)


def _iter_iff_chunks(f: BinaryIO, file_size: int) -> dict[str, tuple[int, int]]:
    f.seek(0, 0)
    hdr = f.read(8)
    if len(hdr) < 8 or hdr[:4] != b"FORM":
        raise ArchiveCorruptError("Not a GameMaker FORM IFF container.")
    chunks: dict[str, tuple[int, int]] = {}
    pos = 8
    while pos + 8 <= file_size:
        f.seek(pos, 0)
        ch_hdr = f.read(8)
        if len(ch_hdr) < 8:
            break
        name = ch_hdr[:4].decode("ascii", errors="replace")
        size = struct.unpack("<I", ch_hdr[4:8])[0]
        data_off = pos + 8
        if data_off + size > file_size:
            size = max(0, file_size - data_off)
        chunks[name] = (data_off, size)
        pos = data_off + size
    return chunks


def decode_qoi_pixels(qoi_data: bytes, width: int, height: int) -> bytes:
    """Decode QOI pixel stream into raw RGBA bytes (width * height * 4)."""
    total_pixels = width * height
    out = bytearray(total_pixels * 4)
    index = [(0, 0, 0, 0)] * 64
    r, g, b, a = 0, 0, 0, 255
    px = 0
    pos = 0
    n = len(qoi_data)

    while px < total_pixels and pos < n:
        b1 = qoi_data[pos]
        pos += 1
        if b1 == 0xFF and pos + 4 <= n:
            r, g, b, a = qoi_data[pos], qoi_data[pos + 1], qoi_data[pos + 2], qoi_data[pos + 3]
            pos += 4
            run = 1
        elif b1 == 0xFE and pos + 3 <= n:
            r, g, b = qoi_data[pos], qoi_data[pos + 1], qoi_data[pos + 2]
            pos += 3
            run = 1
        elif (b1 & 0xC0) == 0x00:
            r, g, b, a = index[b1]
            run = 1
        elif (b1 & 0xC0) == 0x40:
            r = (r + ((b1 >> 4) & 0x03) - 2) & 0xFF
            g = (g + ((b1 >> 2) & 0x03) - 2) & 0xFF
            b = (b + (b1 & 0x03) - 2) & 0xFF
            run = 1
        elif (b1 & 0xC0) == 0x80:
            if pos >= n:
                break
            b2 = qoi_data[pos]
            pos += 1
            vg = (b1 & 0x3F) - 32
            r = (r + vg - 8 + ((b2 >> 4) & 0x0F)) & 0xFF
            g = (g + vg) & 0xFF
            b = (b + vg - 8 + (b2 & 0x0F)) & 0xFF
            run = 1
        else:
            run = (b1 & 0x3F) + 1

        idx_pos = (r * 3 + g * 5 + b * 7 + a * 11) & 63
        index[idx_pos] = (r, g, b, a)
        for _ in range(run):
            if px >= total_pixels:
                break
            off = px * 4
            out[off] = r
            out[off + 1] = g
            out[off + 2] = b
            out[off + 3] = a
            px += 1

    return bytes(out)


def decode_fioq_to_png(fioq_bytes: bytes) -> bytes | None:
    """Decode GameMaker 'fioq' QOI wrapper into PNG bytes."""
    if len(fioq_bytes) < 12 or fioq_bytes[:4] != b"fioq":
        return None
    w, h, qoi_len = struct.unpack_from("<HHI", fioq_bytes, 4)
    if w == 0 or h == 0 or w > 8192 or h > 8192 or 12 + qoi_len > len(fioq_bytes):
        return None
    rgba = decode_qoi_pixels(fioq_bytes[12 : 12 + qoi_len], w, h)
    buf = io.BytesIO()
    Image.frombytes("RGBA", (w, h), rgba).save(buf, format="PNG")
    return buf.getvalue()


def _extract_txtr_entries(f: BinaryIO, chunk_off: int, chunk_size: int) -> list[tuple[str, int, int, bytes | None]]:
    """
    Extract both raw PNGs and GameMaker 2zoq (BZ2+QOI) / fioq (QOI) texture pages.
    Returns list of (kind: 'png'|'2zoq'|'fioq', abs_off, size, optional_predecoded_png).
    """
    f.seek(chunk_off, 0)
    buf = f.read(chunk_size)
    entries: list[tuple[str, int, int, bytes | None]] = []

    # 1. Raw PNGs
    png_sig = b"\x89PNG\r\n\x1a\n"
    iend_sig = b"IEND\xae\x42\x60\x82"
    pos = 0
    while True:
        start = buf.find(png_sig, pos)
        if start < 0:
            break
        end = buf.find(iend_sig, start + 8)
        if end < 0:
            break
        end_abs = end + len(iend_sig)
        entries.append(("png", chunk_off + start, end_abs - start, None))
        pos = end_abs

    # 2. BZ2+QOI (2zoq)
    pos = 0
    while True:
        hit = buf.find(b"2zoq", pos)
        if hit < 0:
            break
        if hit + 15 <= len(buf) and buf[hit + 12 : hit + 15] == b"BZh":
            try:
                decomp = bz2.BZ2Decompressor()
                fioq = decomp.decompress(buf[hit + 12 :])
                comp_consumed = len(buf[hit + 12 :]) - len(decomp.unused_data)
                png_bytes = decode_fioq_to_png(fioq)
                if png_bytes:
                    entries.append(("2zoq", chunk_off + hit, 12 + comp_consumed, png_bytes))
                    pos = hit + 12 + max(1, comp_consumed)
                    continue
            except Exception:
                pass
        pos = hit + 4

    # 3. Uncompressed fioq (QOI)
    pos = 0
    while True:
        hit = buf.find(b"fioq", pos)
        if hit < 0:
            break
        if hit + 12 <= len(buf):
            _w, _h, qlen = struct.unpack_from("<HHI", buf, hit + 4)
            if 0 < qlen <= len(buf) - (hit + 12):
                png_bytes = decode_fioq_to_png(buf[hit : hit + 12 + qlen])
                if png_bytes:
                    entries.append(("fioq", chunk_off + hit, 12 + qlen, png_bytes))
                    pos = hit + 12 + qlen
                    continue
        pos = hit + 4

    return entries


def _extract_audo_slices(f: BinaryIO, chunk_off: int, chunk_size: int, file_size: int) -> list[tuple[int, int, str]]:
    if chunk_size < 4:
        return []
    f.seek(chunk_off, 0)
    count = struct.unpack("<I", f.read(4))[0]
    if count == 0 or 4 + count * 4 > chunk_size:
        return []
    ptrs = struct.unpack(f"<{count}I", f.read(count * 4))
    out: list[tuple[int, int, str]] = []
    for ptr in ptrs:
        if ptr + 4 > file_size:
            continue
        f.seek(ptr, 0)
        sz = struct.unpack("<I", f.read(4))[0]
        if sz == 0 or ptr + 4 + sz > file_size:
            continue
        mag = f.read(4)
        ext = ".wav" if mag == b"RIFF" else (".ogg" if mag == b"OggS" else ".bin")
        out.append((ptr + 4, sz, ext))
    return out


def _read_gm_name_list(f: BinaryIO, chunk_off: int, chunk_size: int, file_size: int) -> list[str]:
    if chunk_size < 4:
        return []
    f.seek(chunk_off, 0)
    count = struct.unpack("<I", f.read(4))[0]
    if count == 0 or count > 200_000 or 4 + count * 4 > chunk_size:
        return []
    ptrs = struct.unpack(f"<{count}I", f.read(count * 4))
    names: list[str] = []
    for ptr in ptrs:
        if ptr + 4 > file_size:
            continue
        f.seek(ptr, 0)
        str_ptr = struct.unpack("<I", f.read(4))[0]
        if 4 <= str_ptr < file_size:
            f.seek(str_ptr - 4, 0)
            slen = struct.unpack("<I", f.read(4))[0]
            if 0 < slen <= 512 and str_ptr + slen <= file_size:
                names.append(f.read(slen).decode("utf-8", errors="replace"))
    return names


class GameMakerIffAdapter(BaseArchiveAdapter):
    name = "gamemaker_iff"

    def can_handle(self, path: Path, header: bytes) -> bool:
        return header.startswith(b"FORM") and len(header) >= 12 and header[8:12] == b"GEN8"

    def iter_entries(self, path: Path, options: AdapterOptions) -> Iterator[ArchiveEntry]:
        file_size = path.stat().st_size
        with path.open("rb") as f:
            chunks = _iter_iff_chunks(f, file_size)

            strg_count = 0
            if "STRG" in chunks:
                soff, ssz = chunks["STRG"]
                if ssz >= 4:
                    f.seek(soff, 0)
                    strg_count = struct.unpack("<I", f.read(4))[0]

            gm_catalog: dict[str, list[str]] = {}
            for ctag in ("SPRT", "OBJT", "ROOM", "SOND", "BGND", "FONT"):
                if ctag in chunks:
                    gm_catalog[ctag.lower()] = _read_gm_name_list(f, *chunks[ctag], file_size)

            meta_payload = json.dumps(
                {
                    "name": f"{path.stem} GameMaker Data",
                    "container": path.name,
                    "chunks": {k: {"offset": v[0], "size": v[1]} for k, v in chunks.items()},
                    "string_count": strg_count,
                    "catalog": gm_catalog,
                },
                indent=2,
            ).encode("utf-8")

            txtr_entries = _extract_txtr_entries(f, *chunks["TXTR"]) if "TXTR" in chunks else []
            audo_slices = _extract_audo_slices(f, *chunks["AUDO"], file_size) if "AUDO" in chunks else []

        yield ArchiveEntry(
            virtual_path="metadata/gamemaker_info.json",
            compressed_size=len(meta_payload),
            uncompressed_size=len(meta_payload),
            offset=0,
            is_compressed=False,
            is_encrypted=False,
            opener=lambda b=meta_payload: io.BytesIO(b),
        )

        for idx, (kind, off, sz, predecoded) in enumerate(txtr_entries):
            if predecoded is not None:
                yield ArchiveEntry(
                    virtual_path=f"textures/txtr_{idx:04d}.png",
                    compressed_size=sz,
                    uncompressed_size=len(predecoded),
                    offset=off,
                    is_compressed=True,
                    is_encrypted=False,
                    opener=lambda b=predecoded: io.BytesIO(b),
                )
            else:
                def _open_tx(o: int = off, s: int = sz) -> BinaryIO:
                    validate_entry_bounds(file_size, o, s, s, options)
                    return BoundedFileSlice(path, o, s)

                yield ArchiveEntry(
                    virtual_path=f"textures/txtr_{idx:04d}.png",
                    compressed_size=sz,
                    uncompressed_size=sz,
                    offset=off,
                    is_compressed=False,
                    is_encrypted=False,
                    opener=_open_tx,
                )

        for idx, (off, sz, ext) in enumerate(audo_slices):
            def _open_au(o: int = off, s: int = sz) -> BinaryIO:
                validate_entry_bounds(file_size, o, s, s, options)
                return BoundedFileSlice(path, o, s)

            yield ArchiveEntry(
                virtual_path=f"audio/audo_{idx:04d}{ext}",
                compressed_size=sz,
                uncompressed_size=sz,
                offset=off,
                is_compressed=False,
                is_encrypted=False,
                opener=_open_au,
            )
