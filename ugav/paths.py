"""Frozen-aware path resolution and self-scan vault guard utilities."""

from __future__ import annotations

import os
import sys
from pathlib import Path

VAULT_MARKER_FILENAME = ".ugav_vault_marker"


class SelfScanError(ValueError):
    """Raised when attempting to scan UGAV's own data or vault directory."""


def get_bundle_root() -> Path:
    """Return the read-only bundle root (_MEIPASS when frozen, repo root otherwise)."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS")).resolve()
    return Path(__file__).resolve().parent.parent


def get_package_dir() -> Path:
    """Return the ugav package directory (works in source and frozen layouts)."""
    bundle_root = get_bundle_root()
    pkg = bundle_root / "ugav"
    if pkg.exists():
        return pkg
    return Path(__file__).resolve().parent


def ensure_vault_markers(data_dir: Path, vault_dir: Path | None = None) -> None:
    """Ensure data_dir, vault_dir, and their self-exclusion markers exist."""
    v_dir = vault_dir if vault_dir is not None else data_dir / "vault"
    for directory in (data_dir, v_dir):
        directory.mkdir(parents=True, exist_ok=True)
    for marker_dir in (data_dir, v_dir):
        marker = marker_dir / VAULT_MARKER_FILENAME
        if not marker.exists():
            marker.write_text("UGAV_SELF_EXCLUSION_MARKER\n", encoding="utf-8")


def get_portable_data_dir(custom_dir: Path | str | None = None) -> Path:
    """Return persistent portable data directory next to executable or CWD."""
    if custom_dir is not None:
        data_dir = Path(custom_dir).expanduser().resolve()
    elif os.environ.get("UGAV_DATA_DIR"):
        data_dir = Path(os.environ["UGAV_DATA_DIR"]).expanduser().resolve()
    elif getattr(sys, "frozen", False):
        data_dir = Path(sys.executable).resolve().parent / "ugav_data"
    else:
        data_dir = Path.cwd().resolve() / "ugav_data"
    ensure_vault_markers(data_dir)
    return data_dir


def _is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def is_vault_or_self_dir(target: Path, data_dir: Path, vault_dir: Path | None = None) -> bool:
    """Return True if target has a vault marker, is inside data/vault dir, or wraps data_dir."""
    resolved_target = target.resolve()
    resolved_data = data_dir.resolve()
    resolved_vault = (vault_dir or (resolved_data / "vault")).resolve()

    if (resolved_target / VAULT_MARKER_FILENAME).exists():
        return True
    if _is_relative_to(resolved_target, resolved_data) or _is_relative_to(resolved_target, resolved_vault):
        return True
    if _is_relative_to(resolved_data, resolved_target) or _is_relative_to(resolved_vault, resolved_target):
        return True
    return False


def validate_scan_target(target: Path, data_dir: Path, vault_dir: Path | None = None) -> None:
    """Reject scanning directly inside a vault/data directory."""
    resolved_target = target.resolve()
    resolved_data = data_dir.resolve()
    resolved_vault = (vault_dir or (resolved_data / "vault")).resolve()

    if (resolved_target / VAULT_MARKER_FILENAME).exists():
        raise SelfScanError(f"Refusing to scan UGAV vault/data directory: {resolved_target}")
    if _is_relative_to(resolved_target, resolved_data) or _is_relative_to(resolved_target, resolved_vault):
        raise SelfScanError(f"Refusing to scan inside UGAV data directory: {resolved_target}")


def get_rules_dirs(data_dir: Path | None = None) -> list[Path]:
    """Return bundled and user-custom declarative translator rules directories."""
    dirs: list[Path] = []
    bundle_rules = get_bundle_root() / "rules"
    if bundle_rules.is_dir():
        dirs.append(bundle_rules)
    if data_dir is not None:
        user_rules = data_dir / "rules"
        if user_rules.is_dir() and user_rules not in dirs:
            dirs.append(user_rules)
    return dirs


def to_long_path(path: Path) -> str:
    """Convert Windows path to extended-length \\\\?\\ prefix when needed."""
    resolved = str(path.resolve())
    if os.name == "nt" and len(resolved) >= 240 and not resolved.startswith("\\\\?\\"):
        if resolved.startswith("\\\\"):
            return "\\\\?\\UNC\\" + resolved[2:]
        return "\\\\?\\" + resolved
    return resolved
