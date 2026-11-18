"""Bethesda .bsa (BSA\\x00) and .ba2 (BTDX GNRL) archive unpacker."""

from __future__ import annotations

import io
import struct
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


class BethesdaBsaAdapter(BaseArchiveAdapter):
    name = "bethesda_bsa"

    def can_handle(self, path: Path, header: bytes) -> bool:
        return header.startswith((b"BSA\x00", b"BTDX")) or path.suffix.lower() in (".bsa", ".ba2")

    def iter_entries(self, path: Path, options: AdapterOptions) -> Iterator[ArchiveEntry]:
        with path.open("rb") as f:
            mag = f.read(4)
        if mag == b"BSA\x00":
            yield from self._iter_bsa(path, options)
        elif mag == b"BTDX":
            yield from self._iter_ba2(path, options)
        else:
            raise ArchiveCorruptError(f"Unsupported Bethesda archive header in {path.name}")

    def _iter_bsa(self, path: Path, options: AdapterOptions) -> Iterator[ArchiveEntry]:
        archive_size = path.stat().st_size
        with path.open("rb") as f:
            hdr = f.read(36)
            if len(hdr) < 36:
                raise ArchiveCorruptError("Truncated BSA header.")
            (
                _magic,
                version,
                dir_offset,
                arch_flags,
                folder_count,
                file_count,
                _tot_folder_len,
                tot_file_len,
                _file_flags,
            ) = struct.unpack("<4sIIIIIIII", hdr)
            if folder_count > 100_000 or file_count > 500_000:
                raise ArchiveCorruptError("Unreasonable BSA folder/file counts.")

            f.seek(dir_offset, 0)
            folders: list[int] = []
            for _ in range(folder_count):
                if version >= 105:
                    rec = f.read(24)
                    if len(rec) < 24:
                        raise ArchiveCorruptError("Truncated SSE BSA folder record.")
                    _hash, cnt, _pad, _off = struct.unpack("<QIIQ", rec)
                else:
                    rec = f.read(16)
                    if len(rec) < 16:
                        raise ArchiveCorruptError("Truncated BSA folder record.")
                    _hash, cnt, _off = struct.unpack("<QII", rec)
                folders.append(cnt)

            default_comp = bool(arch_flags & 0x4)
            has_dir_names = bool(arch_flags & 0x1)
            has_file_names = bool(arch_flags & 0x2)
            embed_name = bool(arch_flags & 0x100)

            raw_entries: list[tuple[str, int, int, bool]] = []
            for cnt in folders:
                dir_name = ""
                if has_dir_names:
                    nlen = struct.unpack("<B", f.read(1))[0]
                    dir_name = f.read(nlen).rstrip(b"\x00").decode("utf-8", errors="replace").replace("\\", "/")
                for _ in range(cnt):
                    frec = f.read(16)
                    if len(frec) < 16:
                        break
                    _fhash, raw_sz, foff = struct.unpack("<QII", frec)
                    is_comp = default_comp ^ bool(raw_sz & 0x40000000)
                    sz = raw_sz & 0x3FFFFFFF
                    raw_entries.append((dir_name, sz, foff, is_comp))

            file_names: list[str] = []
            if has_file_names and tot_file_len > 0:
                name_blob = f.read(tot_file_len)
                file_names = [
                    part.decode("utf-8", errors="replace")
                    for part in name_blob.split(b"\x00")[: len(raw_entries)]
                ]

        for idx, (dname, sz, foff, is_comp) in enumerate(raw_entries):
            fname = file_names[idx] if idx < len(file_names) and file_names[idx] else f"file_{idx:05d}.bin"
            vpath = f"{dname}/{fname}".strip("/")

            def _make_opener(
                off: int = foff,
                size: int = sz,
                comp: bool = is_comp,
                emb: bool = embed_name,
            ) -> callable:  # type: ignore[valid-type]
                def _open() -> BinaryIO:
                    validate_entry_bounds(archive_size, off, size, size, options, check_offset_bounds=True)
                    with path.open("rb") as rf:
                        rf.seek(off, 0)
                        payload_off = off
                        payload_sz = size
                        if emb and size > 1:
                            blen = struct.unpack("<B", rf.read(1))[0]
                            rf.seek(blen, 1)
                            payload_off = off + 1 + blen
                            payload_sz = max(0, size - 1 - blen)
                        if not comp:
                            return BoundedFileSlice(path, payload_off, payload_sz)
                        if payload_sz < 4:
                            raise ArchiveCorruptError("Compressed BSA entry too small.")
                        uncomp_sz = struct.unpack("<I", rf.read(4))[0]
                        validate_entry_bounds(
                            archive_size, payload_off + 4, payload_sz - 4, uncomp_sz, options
                        )
                        comp_data = rf.read(payload_sz - 4)
                    try:
                        return io.BytesIO(zlib.decompress(comp_data))
                    except zlib.error as exc:
                        raise ArchiveCorruptError(f"BSA zlib decompression failed: {exc}") from exc

                return _open

            yield ArchiveEntry(
                virtual_path=vpath,
                compressed_size=sz,
                uncompressed_size=sz,
                offset=foff,
                is_compressed=is_comp,
                is_encrypted=False,
                opener=_make_opener(),
            )

    def _iter_ba2(self, path: Path, options: AdapterOptions) -> Iterator[ArchiveEntry]:
        archive_size = path.stat().st_size
        with path.open("rb") as f:
            hdr = f.read(24)
            if len(hdr) < 24:
                raise ArchiveCorruptError("Truncated BA2 header.")
            magic, version, arch_type, file_count, name_off = struct.unpack("<4sI4sIQ", hdr)
            if magic != b"BTDX" or arch_type != b"GNRL":
                raise ArchiveCorruptError(f"Unsupported BA2 type: {arch_type!r}")
            if file_count > 500_000:
                raise ArchiveCorruptError("Unreasonable BA2 file count.")

            records: list[tuple[int, int, int]] = []
            for _ in range(file_count):
                rec = f.read(36)
                if len(rec) < 36:
                    break
                _nh, _ext, _dh, _fl, off, packed_sz, unpacked_sz, _align = struct.unpack(
                    "<I4sIIQIII", rec
                )
                records.append((off, packed_sz, unpacked_sz))

            names: list[str] = []
            if 0 < name_off < archive_size:
                f.seek(name_off, 0)
                for _ in range(len(records)):
                    lraw = f.read(2)
                    if len(lraw) < 2:
                        break
                    slen = struct.unpack("<H", lraw)[0]
                    names.append(f.read(slen).decode("utf-8", errors="replace").replace("\\", "/"))

        for idx, (off, packed_sz, unpacked_sz) in enumerate(records):
            vpath = names[idx].lstrip("/") if idx < len(names) else f"ba2_file_{idx:05d}.bin"
            is_comp = packed_sz != 0
            disk_sz = packed_sz if is_comp else unpacked_sz

            def _make_opener(
                o: int = off,
                ds: int = disk_sz,
                us: int = unpacked_sz,
                comp: bool = is_comp,
            ) -> callable:  # type: ignore[valid-type]
                def _open() -> BinaryIO:
                    validate_entry_bounds(archive_size, o, ds, us, options, check_offset_bounds=True)
                    if not comp:
                        return BoundedFileSlice(path, o, ds)
                    with path.open("rb") as rf:
                        rf.seek(o, 0)
                        raw = rf.read(ds)
                    try:
                        return io.BytesIO(zlib.decompress(raw))
                    except zlib.error as exc:
                        raise ArchiveCorruptError(f"BA2 zlib decompression failed: {exc}") from exc

                return _open

            yield ArchiveEntry(
                virtual_path=vpath,
                compressed_size=disk_sz,
                uncompressed_size=unpacked_sz,
                offset=off,
                is_compressed=is_comp,
                is_encrypted=False,
                opener=_make_opener(),
            )
