"""ZIP / PK3 / PK4 / APK / JAR / LOVE / NW adapter with Shift-JIS fallback & Zip-bomb guard."""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Iterator

from charset_normalizer import from_bytes

from ugav.adapters.base import (
    AdapterOptions,
    ArchiveCorruptError,
    ArchiveEntry,
    BaseArchiveAdapter,
    SizeCappedStream,
    validate_entry_bounds,
)

_ZIP_EXTS = frozenset({".zip", ".pk3", ".pk4", ".apk", ".jar", ".love", ".nw"})


def _recover_zip_filename(info: zipfile.ZipInfo) -> str:
    if info.flag_bits & 0x800:
        return info.filename
    try:
        raw = info.filename.encode("cp437")
    except UnicodeEncodeError:
        return info.filename
    for enc in ("utf-8", "cp932", "cp949", "gbk"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    best = from_bytes(raw).best()
    return str(best) if best is not None else info.filename


class ZipArchiveAdapter(BaseArchiveAdapter):
    name = "zip"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if header.startswith((b"PK\x03\x04", b"PK\x05\x06")):
            return True
        return path.suffix.lower() in _ZIP_EXTS and header.startswith(b"PK")

    def iter_entries(self, path: Path, options: AdapterOptions) -> Iterator[ArchiveEntry]:
        archive_size = path.stat().st_size
        try:
            zf = zipfile.ZipFile(path, "r")
        except (zipfile.BadZipFile, OSError) as exc:
            raise ArchiveCorruptError(f"Invalid ZIP archive {path.name}: {exc}") from exc

        try:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                vpath = _recover_zip_filename(info).replace("\\", "/").lstrip("/")
                is_enc = bool(info.flag_bits & 0x1)

                def _make_opener(zi: zipfile.ZipInfo) -> callable:  # type: ignore[valid-type]
                    def _open() -> SizeCappedStream:
                        validate_entry_bounds(
                            archive_size=archive_size,
                            offset=max(0, zi.header_offset),
                            compressed_size=max(0, zi.compress_size),
                            uncompressed_size=max(0, zi.file_size),
                            options=options,
                            check_offset_bounds=False,
                        )
                        inner_zf = zipfile.ZipFile(path, "r")
                        raw_stream = inner_zf.open(zi, "r")
                        capped = SizeCappedStream(raw_stream, options.max_entry_bytes)
                        orig_close = capped.close

                        def _close_both() -> None:
                            try:
                                orig_close()
                            finally:
                                inner_zf.close()

                        capped.close = _close_both  # type: ignore[method-assign]
                        return capped

                    return _open

                yield ArchiveEntry(
                    virtual_path=vpath,
                    compressed_size=info.compress_size,
                    uncompressed_size=info.file_size,
                    offset=info.header_offset,
                    is_compressed=info.compress_type != zipfile.ZIP_STORED,
                    is_encrypted=is_enc,
                    opener=_make_opener(info),
                )
        finally:
            zf.close()
