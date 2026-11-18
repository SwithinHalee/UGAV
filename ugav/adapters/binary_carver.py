"""Fallback binary signature carver for unknown low-entropy container files."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import BinaryIO, Iterator

from ugav.adapters.base import AdapterOptions, ArchiveEntry, BoundedFileSlice, validate_entry_bounds


def _carve_png(buf: bytes, start: int) -> int | None:
    iend = buf.find(b"IEND\xae\x42\x60\x82", start + 8)
    if iend < 0:
        return None
    return iend + 8 - start


def _carve_riff_wave(buf: bytes, start: int) -> int | None:
    if start + 12 > len(buf) or buf[start + 8 : start + 12] != b"WAVE":
        return None
    riff_size = struct.unpack_from("<I", buf, start + 4)[0] + 8
    if riff_size < 44 or start + riff_size > len(buf):
        return None
    return riff_size


def _carve_dds(buf: bytes, start: int) -> int | None:
    if start + 128 > len(buf):
        return None
    hdr_sz = struct.unpack_from("<I", buf, start + 4)[0]
    if hdr_sz != 124:
        return None
    height, width = struct.unpack_from("<II", buf, start + 12)
    pitch_or_linear = struct.unpack_from("<I", buf, start + 20)[0]
    if width == 0 or height == 0 or width > 16384 or height > 16384 or pitch_or_linear == 0:
        return None
    # Conservative single-surface estimate when embedded; avoid over-reading
    est = min(len(buf) - start, 128 + max(pitch_or_linear, width * height // 2))
    return est if est > 128 else None


def carve_embedded_assets(
    path: Path,
    options: AdapterOptions,
    max_scan_bytes: int = 32 * 1024 * 1024,
) -> Iterator[ArchiveEntry]:
    """Scan an unknown container for embedded PNG or RIFF/WAVE assets."""
    archive_size = path.stat().st_size
    read_len = min(archive_size, max_scan_bytes)
    with path.open("rb") as f:
        buf = f.read(read_len)

    found: list[tuple[str, int, int]] = []
    idx = 0
    for sig, tag, ext in (
        (b"\x89PNG\r\n\x1a\n", "png", ".png"),
        (b"RIFF", "wav", ".wav"),
        (b"DDS ", "dds", ".dds"),
    ):
        pos = 0
        while True:
            hit = buf.find(sig, pos)
            if hit < 0:
                break
            length: int | None = None
            if tag == "png":
                length = _carve_png(buf, hit)
            elif tag == "wav":
                length = _carve_riff_wave(buf, hit)
            elif tag == "dds":
                length = _carve_dds(buf, hit)
            if length and length > 16 and hit + length <= read_len:
                found.append((f"carved/{tag}_{idx:04d}_0x{hit:x}{ext}", hit, length))
                idx += 1
                pos = hit + length
            else:
                pos = hit + 4

    for vpath, off, ln in found:
        def _make_opener(o: int = off, s: int = ln) -> callable:  # type: ignore[valid-type]
            def _open() -> BinaryIO:
                validate_entry_bounds(archive_size, o, s, s, options, check_offset_bounds=True)
                return BoundedFileSlice(path, o, s)

            return _open

        yield ArchiveEntry(
            virtual_path=vpath,
            compressed_size=ln,
            uncompressed_size=ln,
            offset=off,
            is_compressed=False,
            is_encrypted=False,
            opener=_make_opener(),
        )
