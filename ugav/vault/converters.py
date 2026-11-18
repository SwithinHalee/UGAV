"""Preview image converters (.dds, .tga, RPG Maker .rpgmvp/.png_ -> .png) stored in readable _previews/ folders."""

from __future__ import annotations

import io
from pathlib import Path

from PIL import Image

from ugav.paths import to_long_path
from ugav.vault.storage import sanitize_export_relpath

_PNG_HEADER_16 = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"


def decode_rpgmaker_xor_png(data: bytes, key: bytes | None = None) -> bytes | None:
    """Decrypt RPG Maker MV/MZ .rpgmvp/.png_ image bytes back to standard PNG."""
    if len(data) < 32:
        return None
    payload = bytearray(data[16:]) if data.startswith(b"RPGMV") else bytearray(data)
    if len(payload) < 16:
        return None

    if key is not None and len(key) >= 16:
        for i in range(16):
            payload[i] ^= key[i]
    else:
        payload[:16] = _PNG_HEADER_16

    if not bytes(payload[:8]).startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    return bytes(payload)


def convert_to_preview_png(
    source: bytes | Path,
    detected_format: str,
    vault_dir: Path,
    sha256: str,
    rpgmaker_key: bytes | None = None,
    game_slug: str | None = None,
    rel_path: str | None = None,
    target_vault_dir: Path | None = None,
) -> str | None:
    """Convert supported textures (.dds, .tga, .rpgmvp) into PNG preview under <game_vault>/_previews/."""
    fmt = detected_format.lower()
    if fmt not in ("dds", "tga", "rpgmaker_xor_img"):
        return None

    if target_vault_dir is not None:
        base_dir = target_vault_dir.resolve()
    elif game_slug:
        safe_slug = sanitize_export_relpath(game_slug).name
        base_dir = (vault_dir / safe_slug).resolve()
    else:
        base_dir = vault_dir.resolve()

    if rel_path:
        clean_rel = sanitize_export_relpath(rel_path.replace("!", "/")).with_suffix(".png")
        dest = (base_dir / "_previews" / clean_rel).resolve()
    else:
        dest = (base_dir / "_previews" / f"{sha256[:12]}.png").resolve()

    if not dest.is_relative_to(base_dir):
        return None

    stored_ref = (
        dest.relative_to(vault_dir.resolve()).as_posix()
        if dest.is_relative_to(vault_dir.resolve())
        else str(dest)
    )
    if dest.exists() and dest.stat().st_size > 0:
        return stored_ref

    try:
        if fmt == "rpgmaker_xor_img":
            raw = source if isinstance(source, (bytes, bytearray)) else Path(source).read_bytes()
            png_bytes = decode_rpgmaker_xor_png(bytes(raw), key=rpgmaker_key)
            if not png_bytes:
                return None
            with Image.open(io.BytesIO(png_bytes)) as im:
                im.load()
                dest.parent.mkdir(parents=True, exist_ok=True)
                tmp = dest.with_suffix(".tmp.png")
                im.save(to_long_path(tmp), format="PNG")
                tmp.replace(dest)
            return stored_ref

        if isinstance(source, (bytes, bytearray)):
            with Image.open(io.BytesIO(source)) as im:
                im.load()
                dest.parent.mkdir(parents=True, exist_ok=True)
                tmp = dest.with_suffix(".tmp.png")
                im.save(to_long_path(tmp), format="PNG")
                tmp.replace(dest)
        else:
            with Image.open(to_long_path(Path(source))) as im:
                im.load()
                dest.parent.mkdir(parents=True, exist_ok=True)
                tmp = dest.with_suffix(".tmp.png")
                im.save(to_long_path(tmp), format="PNG")
                tmp.replace(dest)
        return stored_ref
    except Exception:
        return None
