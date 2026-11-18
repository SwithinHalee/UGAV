"""Godot Engine .pck (GDPC v1/v2) unpacker."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import BinaryIO, Iterator

from ugav.adapters.base import (
    AdapterOptions,
    ArchiveCorruptError,
    ArchiveEntry,
    BaseArchiveAdapter,
    BoundedFileSlice,
    validate_entry_bounds,
)


class GodotPckAdapter(BaseArchiveAdapter):
    name = "godot_pck"

    def can_handle(self, path: Path, header: bytes) -> bool:
        return header.startswith(b"GDPC") or path.suffix.lower() == ".pck"

    def iter_entries(self, path: Path, options: AdapterOptions) -> Iterator[ArchiveEntry]:
        archive_size = path.stat().st_size
        with path.open("rb") as f:
            hdr = f.read(32)
            if len(hdr) < 20 or hdr[:4] != b"GDPC":
                raise ArchiveCorruptError(f"Invalid Godot PCK header in {path.name}")
            pack_ver = struct.unpack_from("<I", hdr, 4)[0]
            # major, minor, patch = struct.unpack_from("<III", hdr, 8)
            file_base = 0
            if pack_ver >= 2:
                # v2 header: magic(4) + pack_ver(4) + maj/min/patch(12) + flags(4) + file_base(8) + reserved(16*4=64)
                f.seek(20, 0)
                extra = f.read(12)
                if len(extra) < 12:
                    raise ArchiveCorruptError("Truncated Godot PCK v2 header.")
                _flags, file_base = struct.unpack("<IQ", extra)
                f.seek(20 + 12 + 64, 0)
            else:
                # v1 header: magic(4) + pack_ver(4) + maj/min/patch(12) + reserved(16*4=64)
                f.seek(20 + 64, 0)

            cnt_raw = f.read(4)
            if len(cnt_raw) < 4:
                raise ArchiveCorruptError("Truncated Godot PCK file count.")
            file_count = struct.unpack("<I", cnt_raw)[0]
            if file_count > 500_000:
                raise ArchiveCorruptError(f"Unreasonable Godot PCK file count: {file_count}")

            parsed: list[tuple[str, int, int]] = []
            for _ in range(file_count):
                plen_raw = f.read(4)
                if len(plen_raw) < 4:
                    break
                plen = struct.unpack("<I", plen_raw)[0]
                if plen > 4096:
                    raise ArchiveCorruptError(f"Godot path length out of bounds: {plen}")
                raw_path = f.read(plen)
                vpath = raw_path.rstrip(b"\x00").decode("utf-8", errors="replace")
                if vpath.startswith("res://"):
                    vpath = vpath[6:]
                vpath = vpath.lstrip("/")
                meta = f.read(32 if pack_ver < 2 else 36)
                if len(meta) < 32:
                    break
                offset, size = struct.unpack_from("<QQ", meta, 0)
                abs_off = file_base + offset
                parsed.append((vpath, abs_off, size))

        for vpath, abs_off, size in parsed:
            def _make_opener(o: int = abs_off, s: int = size) -> callable:  # type: ignore[valid-type]
                def _open() -> BinaryIO:
                    validate_entry_bounds(archive_size, o, s, s, options, check_offset_bounds=True)
                    return BoundedFileSlice(path, o, s)

                return _open

            yield ArchiveEntry(
                virtual_path=vpath,
                compressed_size=size,
                uncompressed_size=size,
                offset=abs_off,
                is_compressed=False,
                is_encrypted=False,
                opener=_make_opener(),
            )
