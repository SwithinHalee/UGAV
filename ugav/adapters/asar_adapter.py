"""Electron .asar archive unpacker."""

from __future__ import annotations

import json
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


class AsarAdapter(BaseArchiveAdapter):
    name = "electron_asar"

    def can_handle(self, path: Path, header: bytes) -> bool:
        return path.suffix.lower() == ".asar" and len(header) >= 16 and header[:4] == b"\x04\x00\x00\x00"

    def iter_entries(self, path: Path, options: AdapterOptions) -> Iterator[ArchiveEntry]:
        archive_size = path.stat().st_size
        with path.open("rb") as f:
            hdr = f.read(16)
            if len(hdr) < 16:
                raise ArchiveCorruptError("Truncated ASAR header.")
            _p1, hdr_size, _p2, str_len = struct.unpack("<IIII", hdr)
            if str_len > 64 * 1024 * 1024 or 16 + str_len > archive_size:
                raise ArchiveCorruptError(f"Invalid ASAR header JSON size: {str_len}")
            json_bytes = f.read(str_len)
        try:
            tree = json.loads(json_bytes.decode("utf-8"))
        except Exception as exc:
            raise ArchiveCorruptError(f"Invalid ASAR JSON index: {exc}") from exc

        base_offset = 8 + hdr_size

        def _walk_tree(node: dict, prefix: str) -> Iterator[tuple[str, int, int]]:
            files = node.get("files")
            if not isinstance(files, dict):
                return
            for name, meta in files.items():
                if not isinstance(meta, dict):
                    continue
                vpath = f"{prefix}/{name}".lstrip("/")
                if "files" in meta:
                    yield from _walk_tree(meta, vpath)
                elif "offset" in meta and "size" in meta and not meta.get("unpacked"):
                    yield vpath, base_offset + int(meta["offset"]), int(meta["size"])

        for vpath, abs_off, size in _walk_tree(tree, ""):
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
