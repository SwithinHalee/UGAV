"""Configuration dataclasses and persistent settings / keyring loaders."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

CopyMode = Literal["vault_extracted", "vault_all", "vault_selective", "index_only"]
VALID_COPY_MODES: tuple[str, ...] = ("vault_extracted", "vault_all", "vault_selective", "index_only")


@dataclass
class ScanConfig:
    """Per-scan policy, safety limits, and filter configuration."""

    copy_mode: CopyMode = "vault_extracted"
    convert_textures: bool = True
    carve_unknown: bool = False
    min_free_gb: float = 2.0
    max_file_mb: float | None = 500.0
    max_entry_uncompressed_mb: float = 512.0
    max_compression_ratio: float = 100.0
    max_archive_depth: int = 3
    include_categories: list[str] | None = None
    exclude_extensions: list[str] = field(default_factory=list)
    workers: int = 1
    keys: dict[str, str] = field(default_factory=dict)
    force_online_stub: bool = False
    incremental: bool = True
    batch_size: int = 500
    mirror_per_game: bool = True
    output_vault_dir: str | None = None

    def normalized_exclude_extensions(self) -> set[str]:
        return {
            ext.lower() if ext.startswith(".") else f".{ext.lower()}"
            for ext in self.exclude_extensions
            if ext.strip()
        }

    def max_entry_bytes(self) -> int:
        return int(self.max_entry_uncompressed_mb * 1024 * 1024)


@dataclass
class AppSettings:
    """Persistent user preferences stored in ugav_data/settings.json."""

    custom_vault_dir: str | None = None
    default_copy_mode: CopyMode = "vault_extracted"
    convert_textures: bool = True
    min_free_gb: float = 2.0
    max_file_mb: float | None = 500.0
    extra_scan_roots: list[str] = field(default_factory=list)
    workers: int = 1

    @classmethod
    def load(cls, data_dir: Path) -> "AppSettings":
        path = data_dir / "settings.json"
        if not path.exists():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return cls(
                custom_vault_dir=raw.get("custom_vault_dir"),
                default_copy_mode=raw.get("default_copy_mode", "vault_extracted")
                if raw.get("default_copy_mode") in VALID_COPY_MODES
                else "vault_extracted",
                convert_textures=bool(raw.get("convert_textures", True)),
                min_free_gb=float(raw.get("min_free_gb", 2.0)),
                max_file_mb=float(raw["max_file_mb"]) if raw.get("max_file_mb") is not None else None,
                extra_scan_roots=[str(x) for x in raw.get("extra_scan_roots", [])],
                workers=max(1, int(raw.get("workers", 1))),
            )
        except Exception:
            return cls()

    def save(self, data_dir: Path) -> Path:
        path = data_dir / "settings.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        return path


def load_keyring(data_dir: Path, cli_keys: dict[str, str] | None = None) -> dict[str, str]:
    """Load optional decryption keys from ugav_data/keyring.json merged with CLI keys."""
    merged: dict[str, str] = {}
    keyring_path = data_dir / "keyring.json"
    if keyring_path.exists():
        try:
            data = json.loads(keyring_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                merged.update({str(k): str(v) for k, v in data.items()})
        except Exception:
            pass
    if cli_keys:
        merged.update(cli_keys)
    return merged


def save_keyring(data_dir: Path, keys: dict[str, str]) -> Path:
    """Persist keyring entries to ugav_data/keyring.json."""
    keyring_path = data_dir / "keyring.json"
    keyring_path.parent.mkdir(parents=True, exist_ok=True)
    keyring_path.write_text(json.dumps(keys, indent=2), encoding="utf-8")
    return keyring_path
