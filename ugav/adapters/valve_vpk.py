"""Valve Source Engine .vpk (v1/v2) unpacker."""

from __future__ import annotations

import io
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

_VPK_MAGIC = 0x55AA1234


def _read_cstr(f: BinaryIO) -> str:
    buf = bytearray()
    while True:
        ch = f.read(1)
        if not ch or ch == b"\x00":
            break
        buf.extend(ch)
    return buf.decode("utf-8", errors="replace")


class ValveVpkAdapter(BaseArchiveAdapter):
    name = "valve_vpk"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if len(header) >= 4 and struct.unpack_from("<I", header, 0)[0] == _VPK_MAGIC:
            return True
        return False

    def iter_entries(self, path: Path, options: AdapterOptions) -> Iterator[ArchiveEntry]:
        archive_size = path.stat().st_size
        with path.open("rb") as f:
            hdr = f.read(12)
            if len(hdr) < 12:
                raise ArchiveCorruptError("Truncated VPK header.")
            magic, version, tree_size = struct.unpack("<III", hdr)
            if magic != _VPK_MAGIC or version not in (1, 2):
                raise ArchiveCorruptError(f"Unsupported VPK magic/version: 0x{magic:x} v{version}")
            if version == 2:
                extra = f.read(16)
                if len(extra) < 16:
                    raise ArchiveCorruptError("Truncated VPK v2 header.")
                header_len = 28
            else:
                header_len = 12
            data_base = header_len + tree_size

            parsed: list[tuple[str, int, int, int, bytes]] = []
            while True:
                ext = _read_cstr(f)
                if ext == "":
                    break
                while True:
                    dir_path = _read_cstr(f)
                    if dir_path == "":
                        break
                    while True:
                        fname = _read_cstr(f)
                        if fname == "":
                            break
                        entry_meta = f.read(18)
                        if len(entry_meta) < 18:
                            break
                        _crc, preload_bytes, arch_idx, entry_off, entry_len, term = struct.unpack(
                            "<IHHIIH", entry_meta
                        )
                        if term != 0xFFFF:
                            raise ArchiveCorruptError("Invalid VPK entry terminator.")
                        preload = f.read(preload_bytes) if preload_bytes > 0 else b""
                        prefix = "" if dir_path == " " else f"{dir_path.strip('/')}/"
                        ext_part = "" if ext == " " else f".{ext}"
                        vpath = f"{prefix}{fname}{ext_part}".lstrip("/")
                        parsed.append((vpath, arch_idx, entry_off, entry_len, preload))

        stem = path.stem
        is_dir_vpk = stem.endswith("_dir")
        base_stem = stem[:-4] if is_dir_vpk else stem

        for vpath, arch_idx, entry_off, entry_len, preload in parsed:
            if arch_idx == 0x7FFF:
                target_file = path
                abs_off = data_base + entry_off
            else:
                target_file = path.with_name(f"{base_stem}_{arch_idx:03d}.vpk")
                if not target_file.is_file():
                    continue
                abs_off = entry_off

            total_sz = len(preload) + entry_len
            target_size = target_file.stat().st_size

            def _make_opener(
                tf: Path = target_file,
                tsz: int = target_size,
                off: int = abs_off,
                ln: int = entry_len,
                pre: bytes = preload,
                tot: int = total_sz,
            ) -> callable:  # type: ignore[valid-type]
                def _open() -> BinaryIO:
                    validate_entry_bounds(tsz, off, ln, tot, options, check_offset_bounds=True)
                    if not pre:
                        return BoundedFileSlice(tf, off, ln)
                    buf = bytearray(pre)
                    if ln > 0:
                        with tf.open("rb") as rf:
                            rf.seek(off, 0)
                            buf.extend(rf.read(ln))
                    return io.BytesIO(bytes(buf))

                return _open

            yield ArchiveEntry(
                virtual_path=vpath,
                compressed_size=total_sz,
                uncompressed_size=total_sz,
                offset=abs_off,
                is_compressed=False,
                is_encrypted=False,
                opener=_make_opener(),
            )
