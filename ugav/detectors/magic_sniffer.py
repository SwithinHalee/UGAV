"""Magic-byte signature sniffer and text/encoding detector."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from charset_normalizer import from_bytes


@dataclass(frozen=True)
class SniffResult:
    detected_format: str
    detected_mime: str
    asset_category: str
    encoding: str | None = None
    is_archive: bool = False


_EXT_CATEGORIES: dict[str, tuple[str, str]] = {
    ".xml": ("xml", "application/xml"),
    ".json": ("json", "application/json"),
    ".jsonc": ("jsonc", "application/json"),
    ".yaml": ("yaml", "application/yaml"),
    ".yml": ("yaml", "application/yaml"),
    ".csv": ("csv", "text/csv"),
    ".tsv": ("tsv", "text/tab-separated-values"),
    ".ini": ("ini", "text/plain"),
    ".cfg": ("ini", "text/plain"),
    ".toml": ("toml", "application/toml"),
    ".txt": ("text", "text/plain"),
    ".md": ("markdown", "text/markdown"),
    ".srt": ("srt", "text/plain"),
    ".lua": ("lua", "text/x-lua"),
    ".py": ("python", "text/x-python"),
    ".js": ("javascript", "text/javascript"),
    ".ts": ("typescript", "text/typescript"),
    ".ms": ("maxscript", "text/plain"),
    ".sh": ("shell", "text/x-shellscript"),
    ".bash": ("shell", "text/x-shellscript"),
    ".bat": ("batch", "text/plain"),
    ".ps1": ("powershell", "text/plain"),
    ".hlsl": ("shader_source", "text/plain"),
    ".glsl": ("shader_source", "text/plain"),
    ".dds": ("dds", "image/vnd-ms.dds"),
    ".tga": ("tga", "image/x-tga"),
    ".png": ("png", "image/png"),
    ".jpg": ("jpeg", "image/jpeg"),
    ".jpeg": ("jpeg", "image/jpeg"),
    ".webp": ("webp", "image/webp"),
    ".bmp": ("bmp", "image/bmp"),
    ".ico": ("ico", "image/x-icon"),
    ".wav": ("wav", "audio/wav"),
    ".ogg": ("ogg", "audio/ogg"),
    ".mp3": ("mp3", "audio/mpeg"),
    ".flac": ("flac", "audio/flac"),
    ".wem": ("wwise_wem", "audio/x-wwise"),
    ".bnk": ("wwise_bnk", "application/octet-stream"),
    ".awb": ("cri_awb", "audio/x-cri-awb"),
    ".acb": ("cri_acb", "audio/x-cri-acb"),
    ".acf": ("cri_acf", "application/octet-stream"),
    ".mkv": ("mkv", "video/x-matroska"),
    ".mp4": ("mp4", "video/mp4"),
    ".ogv": ("ogv", "video/ogg"),
    ".usm": ("cri_usm", "video/x-cri-usm"),
    ".bik": ("bink_video", "video/x-bink"),
    ".bk2": ("bink_video", "video/x-bink"),
    ".glb": ("glb", "model/gltf-binary"),
    ".gltf": ("gltf", "model/gltf+json"),
    ".obj": ("obj", "model/obj"),
    ".fbx": ("fbx", "application/octet-stream"),
    ".msh": ("mesh", "application/octet-stream"),
    ".anm": ("animation", "application/octet-stream"),
    ".ttf": ("ttf", "font/ttf"),
    ".otf": ("otf", "font/otf"),
    ".woff2": ("woff2", "font/woff2"),
    ".spv": ("spirv_shader", "application/octet-stream"),
    ".bmd": ("atlus_bmd", "application/octet-stream"),
    ".bf": ("atlus_bf", "application/octet-stream"),
    ".tmx": ("atlus_tmx", "image/x-atlus-tmx"),
    ".pm1": ("atlus_pm1", "application/octet-stream"),
    ".pm2": ("atlus_pm2", "application/octet-stream"),
    ".pm3": ("atlus_pm3", "application/octet-stream"),
    ".epl": ("atlus_epl", "application/octet-stream"),
    ".bed": ("atlus_bed", "application/octet-stream"),
    ".arc": ("archive_generic", "application/octet-stream"),
    ".pac": ("archive_generic", "application/octet-stream"),
    ".bin": ("binary", "application/octet-stream"),
    ".dat": ("binary", "application/octet-stream"),
    ".exe": ("pe_binary", "application/vnd.microsoft.portable-executable"),
    ".dll": ("pe_binary", "application/vnd.microsoft.portable-executable"),
    ".so": ("elf_binary", "application/x-sharedlib"),
    ".pdb": ("pdb", "application/octet-stream"),
    ".pdf": ("pdf", "application/pdf"),
}

_FORMAT_TO_CATEGORY: dict[str, str] = {
    "png": "texture",
    "jpeg": "texture",
    "dds": "texture",
    "webp": "texture",
    "bmp": "texture",
    "tga": "texture",
    "ico": "texture",
    "atlus_tmx": "texture",
    "rpgmaker_xor_img": "texture",
    "wav": "audio",
    "ogg": "audio",
    "mp3": "audio",
    "flac": "audio",
    "wwise_wem": "audio",
    "wwise_bnk": "audio",
    "cri_awb": "audio",
    "cri_acb": "audio",
    "cri_acf": "audio",
    "fmod_fsb": "audio",
    "rpgmaker_xor_audio": "audio",
    "mkv": "video",
    "mp4": "video",
    "ogv": "video",
    "cri_usm": "video",
    "bink_video": "video",
    "glb": "model_3d",
    "gltf": "model_3d",
    "obj": "model_3d",
    "fbx": "model_3d",
    "gladius_msh": "model_3d",
    "gladius_anm": "model_3d",
    "mesh": "model_3d",
    "animation": "model_3d",
    "atlus_pm1": "model_3d",
    "atlus_pm2": "model_3d",
    "atlus_pm3": "model_3d",
    "atlus_epl": "model_3d",
    "atlus_bed": "model_3d",
    "xml": "data",
    "json": "data",
    "jsonc": "data",
    "yaml": "data",
    "csv": "data",
    "tsv": "data",
    "ini": "data",
    "toml": "data",
    "sqlite": "data",
    "atlus_bmd": "data",
    "atlus_bf": "data",
    "text": "data",
    "markdown": "data",
    "srt": "localization",
    "lua": "script",
    "python": "script",
    "javascript": "script",
    "typescript": "script",
    "maxscript": "script",
    "shell": "script",
    "batch": "script",
    "powershell": "script",
    "shader_source": "script",
    "spirv_shader": "binary",
    "pe_binary": "binary",
    "elf_binary": "binary",
    "macho_binary": "binary",
    "pdb": "binary",
    "ttf": "font",
    "otf": "font",
    "woff2": "font",
    "pdf": "document",
    "cri_cpk": "archive",
    "zip": "archive",
    "7z": "archive",
    "rar": "archive",
    "gamemaker_iff": "archive",
    "godot_pck": "archive",
    "renpy_rpa": "archive",
    "bethesda_bsa": "archive",
    "bethesda_ba2": "archive",
    "valve_vpk": "archive",
    "electron_asar": "archive",
    "unity_bundle": "archive",
    "archive_generic": "archive",
    "cri_utf": "data",
}

_ARCHIVE_FORMATS: frozenset[str] = frozenset(
    {
        "cri_cpk",
        "zip",
        "gamemaker_iff",
        "godot_pck",
        "renpy_rpa",
        "bethesda_bsa",
        "bethesda_ba2",
        "valve_vpk",
        "electron_asar",
        "unity_bundle",
        "7z",
        "rar",
    }
)


def _category_for(fmt: str, path_hint: str = "") -> str:
    cat = _FORMAT_TO_CATEGORY.get(fmt, "unknown")
    low = path_hint.lower().replace("\\", "/")
    if cat == "data" and any(
        tok in low for tok in ("/languages/", "/localization/", "/locale/", "lang_", "strings")
    ):
        return "localization"
    return cat


def _probe_text_format(sample: bytes, ext: str) -> tuple[str, str, str] | None:
    if not sample:
        return None
    # Reject binary data containing NUL bytes unless UTF-16 BOM is present
    encoding: str | None = None
    payload = sample
    if sample.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"
        payload = sample[3:]
    elif sample.startswith(b"\xff\xfe") or sample.startswith(b"\xfe\xff"):
        encoding = "utf-16"
    elif b"\x00" in sample[:512]:
        return None
    else:
        try:
            sample.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            best = from_bytes(sample).best()
            if best is None:
                return None
            # Require mostly printable characters
            text_cand = str(best)
            printable = sum(1 for ch in text_cand if ch.isprintable() or ch in "\r\n\t")
            if len(text_cand) == 0 or (printable / len(text_cand)) < 0.85:
                return None
            encoding = best.encoding

    try:
        text = payload.decode(encoding, errors="replace").lstrip()
    except Exception:
        return None

    if not text:
        return ("text", "text/plain", encoding)

    if text.startswith("<?xml") or re.match(r"^<[A-Za-z_][\w:.-]*[\s>]", text):
        return ("xml", "application/xml", encoding)
    if text[0] in ("{", "["):
        if ext in (".json", ".jsonc") or _looks_like_json(text):
            fmt = "jsonc" if ext == ".jsonc" else "json"
            return (fmt, "application/json", encoding)

    if ext in _EXT_CATEGORIES:
        fmt, mime = _EXT_CATEGORIES[ext]
        if _FORMAT_TO_CATEGORY.get(fmt) in ("data", "script", "localization"):
            return (fmt, mime, encoding)

    if ext in (".dat", ".bin", "") and any(line.startswith("[") and line.endswith("]") for line in text.splitlines()[:10]):
        return ("ini", "text/plain", encoding)

    return ("text", "text/plain", encoding)


def _looks_like_json(text: str) -> bool:
    stripped = text.strip()
    if len(stripped) < 2:
        return False
    try:
        json.loads(stripped)
        return True
    except Exception:
        # Could be truncated header slice of a valid large JSON
        return bool(re.match(r'^\{\s*"[^"]+"\s*:', stripped) or re.match(r'^\[\s*[\{"\d\[]', stripped))


def sniff_bytes(
    header: bytes,
    extension: str = "",
    tail: bytes = b"",
    path_hint: str = "",
) -> SniffResult:
    """Detect real asset format and category from magic bytes and text heuristics."""
    ext = extension.lower() if (not extension or extension.startswith(".")) else f".{extension.lower()}"

    # 1. Binary Magic Signatures
    magic_match: tuple[str, str] | None = None
    if header.startswith(b"CPK "):
        magic_match = ("cri_cpk", "application/x-cri-cpk")
    elif header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06"):
        magic_match = ("zip", "application/zip")
    elif header.startswith(b"FORM") and len(header) >= 12 and header[8:12] == b"GEN8":
        magic_match = ("gamemaker_iff", "application/x-gamemaker-iff")
    elif header.startswith(b"GDPC"):
        magic_match = ("godot_pck", "application/x-godot-pck")
    elif header.startswith((b"RPA-3.0 ", b"RPA-2.0 ")):
        magic_match = ("renpy_rpa", "application/x-renpy-rpa")
    elif header.startswith(b"BSA\x00"):
        magic_match = ("bethesda_bsa", "application/x-bethesda-bsa")
    elif header.startswith(b"BTDX"):
        magic_match = ("bethesda_ba2", "application/x-bethesda-ba2")
    elif header.startswith(b"\x34\x12\xaa\x55"):
        magic_match = ("valve_vpk", "application/x-valve-vpk")
    elif header.startswith(b"UnityFS") or header.startswith(b"UnityWeb"):
        magic_match = ("unity_bundle", "application/x-unity-bundle")
    elif header.startswith(b"7z\xbc\xaf\x27\x1c"):
        magic_match = ("7z", "application/x-7z-compressed")
    elif header.startswith(b"Rar!\x1a\x07"):
        magic_match = ("rar", "application/vnd.rar")
    elif header.startswith(b"RPGMV\x00\x00\x00") or ext in (".rpgmvp", ".png_"):
        magic_match = ("rpgmaker_xor_img", "image/x-rpgmaker-encrypted")
    elif ext in (".rpgmvo", ".rpgmvm", ".ogg_", ".m4a_"):
        magic_match = ("rpgmaker_xor_audio", "audio/x-rpgmaker-encrypted")
    elif header.startswith(b"\x89PNG\r\n\x1a\n"):
        magic_match = ("png", "image/png")
    elif header.startswith(b"\xff\xd8\xff"):
        magic_match = ("jpeg", "image/jpeg")
    elif header.startswith(b"DDS "):
        magic_match = ("dds", "image/vnd-ms.dds")
    elif header.startswith(b"RIFF") and len(header) >= 12:
        fourcc = header[8:12]
        if fourcc == b"WEBP":
            magic_match = ("webp", "image/webp")
        elif fourcc == b"WAVE":
            if ext == ".wem":
                magic_match = ("wwise_wem", "audio/x-wwise")
            else:
                magic_match = ("wav", "audio/wav")
    elif header.startswith(b"OggS"):
        magic_match = ("ogv" if ext == ".ogv" else "ogg", "video/ogg" if ext == ".ogv" else "audio/ogg")
    elif header.startswith(b"ID3") or (len(header) >= 2 and header[0] == 0xFF and (header[1] & 0xE0) == 0xE0 and ext == ".mp3"):
        magic_match = ("mp3", "audio/mpeg")
    elif header.startswith(b"fLaC"):
        magic_match = ("flac", "audio/flac")
    elif header.startswith(b"AFS2"):
        magic_match = ("cri_awb", "audio/x-cri-awb")
    elif header.startswith(b"@UTF"):
        magic_match = ("cri_utf", "application/x-cri-utf")
    elif header.startswith(b"CRID"):
        magic_match = ("cri_usm", "video/x-cri-usm")
    elif header.startswith((b"BIKi", b"KB2")):
        magic_match = ("bink_video", "video/x-bink")
    elif header.startswith(b"FSB5"):
        magic_match = ("fmod_fsb", "audio/x-fmod-fsb")
    elif header.startswith(b"BKHD"):
        magic_match = ("wwise_bnk", "audio/x-wwise-bnk")
    elif header.startswith(b"\x1a\x45\xdf\xa3"):
        magic_match = ("mkv", "video/x-matroska")
    elif len(header) >= 8 and header[4:8] == b"ftyp":
        magic_match = ("mp4", "video/mp4")
    elif header.startswith(b"SQLite format 3\x00"):
        magic_match = ("sqlite", "application/vnd.sqlite3")
    elif header.startswith(b"\x03\x02\x23\x07"):
        magic_match = ("spirv_shader", "application/octet-stream")
    elif header.startswith(b"MSH1.0"):
        magic_match = ("gladius_msh", "model/x-gladius-msh")
    elif header.startswith(b"ANM1.0"):
        magic_match = ("gladius_anm", "application/x-gladius-anm")
    elif header.startswith(b"BM") and ext == ".bmp":
        magic_match = ("bmp", "image/bmp")
    elif header.startswith(b"%PDF-"):
        magic_match = ("pdf", "application/pdf")
    elif header.startswith(b"MZ") and ext in (".exe", ".dll", ".sys", ""):
        magic_match = ("pe_binary", "application/vnd.microsoft.portable-executable")
    elif header.startswith(b"\x7fELF"):
        magic_match = ("elf_binary", "application/x-elf")
    elif header[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        magic_match = ("macho_binary", "application/x-mach-binary")
    elif len(header) >= 12 and header[8:12] == b"TMX0":
        magic_match = ("atlus_tmx", "image/x-atlus-tmx")
    elif ext == ".asar" and len(header) >= 16 and header[:4] == b"\x04\x00\x00\x00" and b'"files"' in header[:256]:
        magic_match = ("electron_asar", "application/x-asar")
    elif tail.endswith(b"TRUEVISION-XFILE.\x00") or ext == ".tga":
        magic_match = ("tga", "image/x-tga")

    if magic_match is not None:
        fmt, mime = magic_match
        return SniffResult(
            detected_format=fmt,
            detected_mime=mime,
            asset_category=_category_for(fmt, path_hint),
            encoding=None,
            is_archive=fmt in _ARCHIVE_FORMATS,
        )

    # 2. Text / Structured Data Probe
    text_probe = _probe_text_format(header, ext)
    if text_probe is not None:
        fmt, mime, enc = text_probe
        return SniffResult(
            detected_format=fmt,
            detected_mime=mime,
            asset_category=_category_for(fmt, path_hint),
            encoding=enc,
            is_archive=False,
        )

    # 3. Extension fallback
    if ext in _EXT_CATEGORIES:
        fmt, mime = _EXT_CATEGORIES[ext]
        return SniffResult(
            detected_format=fmt,
            detected_mime=mime,
            asset_category=_category_for(fmt, path_hint),
            encoding=None,
            is_archive=fmt in _ARCHIVE_FORMATS,
        )

    return SniffResult(
        detected_format="unknown",
        detected_mime="application/octet-stream",
        asset_category="unknown",
        encoding=None,
        is_archive=False,
    )


def sniff_file(path: Path) -> SniffResult:
    """Read header and tail slices of a file safely and return SniffResult."""
    size = path.stat().st_size
    with path.open("rb") as f:
        header = f.read(4096)
        tail = b""
        if size > 32:
            f.seek(max(0, size - 32))
            tail = f.read(32)
    return sniff_bytes(header, extension=path.suffix, tail=tail, path_hint=str(path))


def is_stream_text_like(stream: BinaryIO, ext: str = "") -> SniffResult:
    pos = stream.tell()
    stream.seek(0)
    header = stream.read(4096)
    stream.seek(pos)
    return sniff_bytes(header, extension=ext)
