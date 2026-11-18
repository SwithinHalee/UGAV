"""Ren'Py .rpa (RPA-2.0 / RPA-3.0) unpacker with restricted safe pickle unpickler."""

from __future__ import annotations

import io
import pickle
import zlib
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


class _RestrictedUnpickler(pickle.Unpickler):
    """Allow only primitive data types when parsing untrusted RPA pickle indexes."""

    def find_class(self, module: str, name: str) -> object:
        raise pickle.UnpicklingError(f"Unsafe pickle global rejected: {module}.{name}")


def safe_unpickle_primitives(raw: bytes) -> object:
    return _RestrictedUnpickler(io.BytesIO(raw)).load()


class RenPyRpaAdapter(BaseArchiveAdapter):
    name = "renpy_rpa"

    def can_handle(self, path: Path, header: bytes) -> bool:
        return header.startswith((b"RPA-3.0 ", b"RPA-2.0 ")) or path.suffix.lower() == ".rpa"

    def iter_entries(self, path: Path, options: AdapterOptions) -> Iterator[ArchiveEntry]:
        archive_size = path.stat().st_size
        with path.open("rb") as f:
            first_line = f.readline(256).decode("ascii", errors="replace").strip()
            parts = first_line.split()
            if len(parts) < 2 or not parts[0].startswith("RPA-"):
                raise ArchiveCorruptError(f"Invalid RPA header in {path.name}")
            try:
                index_offset = int(parts[1], 16)
                key = int(parts[2], 16) if len(parts) >= 3 else 0
            except ValueError as exc:
                raise ArchiveCorruptError(f"Malformed RPA header integers: {exc}") from exc

            if index_offset <= 0 or index_offset >= archive_size:
                raise ArchiveCorruptError("RPA index offset out of bounds.")
            f.seek(index_offset, 0)
            compressed_idx = f.read(min(64 * 1024 * 1024, archive_size - index_offset))

        try:
            raw_idx = zlib.decompress(compressed_idx)
            index_obj = safe_unpickle_primitives(raw_idx)
        except Exception as exc:
            raise ArchiveCorruptError(f"Failed to parse RPA index safely: {exc}") from exc

        if not isinstance(index_obj, dict):
            raise ArchiveCorruptError("RPA index root is not a dictionary.")

        for raw_path, blocks in index_obj.items():
            vpath = str(raw_path).replace("\\", "/").lstrip("/")
            if not isinstance(blocks, list) or not blocks:
                continue
            parsed_blocks: list[tuple[int, int, bytes]] = []
            total_size = 0
            for blk in blocks:
                if not isinstance(blk, (tuple, list)) or len(blk) < 2:
                    continue
                off = int(blk[0]) ^ key
                length = int(blk[1]) ^ key
                prefix = bytes(blk[2]) if len(blk) >= 3 and blk[2] else b""
                parsed_blocks.append((off, length, prefix))
                total_size += length

            if not parsed_blocks:
                continue
            first_off = parsed_blocks[0][0]

            def _make_opener(blks: list[tuple[int, int, bytes]] = parsed_blocks, tsz: int = total_size) -> callable:  # type: ignore[valid-type]
                def _open() -> BinaryIO:
                    if len(blks) == 1 and not blks[0][2]:
                        off, ln, _ = blks[0]
                        validate_entry_bounds(archive_size, off, ln, ln, options)
                        return BoundedFileSlice(path, off, ln)
                    buf = bytearray()
                    with path.open("rb") as rf:
                        for off, ln, prefix in blks:
                            need_from_file = max(0, ln - len(prefix))
                            validate_entry_bounds(archive_size, off, need_from_file, ln, options)
                            if prefix:
                                buf.extend(prefix)
                            if need_from_file > 0:
                                rf.seek(off, 0)
                                buf.extend(rf.read(need_from_file))
                    return io.BytesIO(bytes(buf))

                return _open

            yield ArchiveEntry(
                virtual_path=vpath,
                compressed_size=total_size,
                uncompressed_size=total_size,
                offset=first_off,
                is_compressed=False,
                is_encrypted=key != 0,
                opener=_make_opener(),
            )
