"""RPG Maker MV/MZ XOR-obfuscated media unpacker (.rpgmvp/.rpgmvo/.png_/.ogg_)."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import BinaryIO, Iterator

from ugav.adapters.base import (
    AdapterOptions,
    ArchiveCorruptError,
    ArchiveEntry,
    BaseArchiveAdapter,
    validate_entry_bounds,
)

_EXT_MAP = {
    ".rpgmvp": ".png",
    ".png_": ".png",
    ".rpgmvo": ".ogg",
    ".ogg_": ".ogg",
    ".rpgmvm": ".m4a",
    ".m4a_": ".m4a",
}
_PNG_HEADER_16 = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
_OGG_MAGIC_4 = b"OggS"


def find_rpgmaker_key(start_path: Path) -> bytes | None:
    """Locate encryptionKey in nearby RPG Maker System.json if present."""
    cur = start_path.parent
    for _ in range(4):
        for candidate in (cur / "data" / "System.json", cur / "www" / "data" / "System.json", cur / "System.json"):
            if candidate.is_file():
                try:
                    data = json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
                    hex_key = data.get("encryptionKey")
                    if isinstance(hex_key, str) and len(hex_key) >= 32:
                        return bytes.fromhex(hex_key[:32])
                except Exception:
                    pass
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


class RpgMakerMediaAdapter(BaseArchiveAdapter):
    """Unwrap single RPG Maker MV/MZ obfuscated media files into standard PNG/OGG/M4A."""

    name = "rpgmaker_media"

    def can_handle(self, path: Path, header: bytes) -> bool:
        return path.suffix.lower() in _EXT_MAP or header.startswith(b"RPGMV\x00\x00\x00")

    def iter_entries(self, path: Path, options: AdapterOptions) -> Iterator[ArchiveEntry]:
        file_size = path.stat().st_size
        if file_size < 32:
            raise ArchiveCorruptError(f"RPG Maker media too small: {path.name}")
        target_ext = _EXT_MAP.get(path.suffix.lower(), ".bin")
        out_name = path.with_suffix(target_ext).name
        key_hex = options.keys.get("rpgmaker")
        key_bytes = bytes.fromhex(key_hex[:32]) if key_hex and len(key_hex) >= 32 else find_rpgmaker_key(path)

        def _open() -> BinaryIO:
            validate_entry_bounds(file_size, 0, file_size, file_size, options, check_offset_bounds=True)
            raw = path.read_bytes()
            payload = bytearray(raw[16:]) if raw.startswith(b"RPGMV") else bytearray(raw)
            if len(payload) < 16:
                raise ArchiveCorruptError("RPG Maker payload truncated.")
            if key_bytes is not None and len(key_bytes) >= 16:
                for i in range(16):
                    payload[i] ^= key_bytes[i]
            elif target_ext == ".png":
                payload[:16] = _PNG_HEADER_16
            else:
                raise ArchiveCorruptError(
                    f"Missing RPG Maker encryptionKey in System.json for {path.name}"
                )
            if target_ext == ".ogg" and payload[:4] != _OGG_MAGIC_4:
                raise ArchiveCorruptError("Decrypted OGG header mismatch (wrong RPG Maker key).")
            return io.BytesIO(bytes(payload))

        yield ArchiveEntry(
            virtual_path=out_name,
            compressed_size=file_size,
            uncompressed_size=max(0, file_size - 16),
            offset=16,
            is_compressed=False,
            is_encrypted=True,
            opener=_open,
        )
