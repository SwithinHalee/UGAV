"""Readable per-game Vault storage with SHA-256 content tracking, disk-space guard, and safe exporter."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import threading
from pathlib import Path
from typing import Any, BinaryIO

from ugav.paths import ensure_vault_markers, to_long_path

_WINDOWS_RESERVED_NAMES: frozenset[str] = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)
_ILLEGAL_CHARS_RE = re.compile(r'[<>:"|?*\x00-\x1f]')


class DiskSpaceExhaustedError(RuntimeError):
    """Raised when free disk space drops below the configured safety floor."""


def sanitize_export_relpath(rel_path: str) -> Path:
    """Sanitize any virtual/OS relative path so it cannot escape export root or fail on NTFS."""
    normalized = rel_path.replace("\\", "/").strip()
    if len(normalized) >= 2 and normalized[1] == ":" and normalized[0].isalpha():
        normalized = normalized[2:]
    normalized = normalized.lstrip("/")

    parts: list[str] = []
    for raw_seg in normalized.split("/"):
        if not raw_seg or raw_seg == ".":
            continue
        if raw_seg == "..":
            raise ValueError(f"Path traversal segment '..' rejected in: {rel_path}")
        cleaned = _ILLEGAL_CHARS_RE.sub("_", raw_seg).rstrip(" .")
        if not cleaned:
            cleaned = "_"
        stem_upper = cleaned.split(".")[0].upper()
        if stem_upper in _WINDOWS_RESERVED_NAMES:
            cleaned = f"_{cleaned}"
        parts.append(cleaned)

    if not parts:
        return Path("_unnamed")
    return Path(*parts)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(to_long_path(path), "rb") as f:
        while True:
            chunk = f.read(4 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class VaultStorage:
    """Human-readable per-game Vault storage backed by SHA-256 content tracking."""

    def __init__(self, vault_dir: Path, min_free_gb: float = 2.0) -> None:
        self.vault_dir = Path(vault_dir).resolve()
        self.min_free_gb = max(0.0, float(min_free_gb))
        self.tmp_dir = self.vault_dir / "_tmp"
        ensure_vault_markers(self.vault_dir.parent, self.vault_dir)
        self.tmp_dir.mkdir(parents=True, exist_ok=True)

    def free_bytes(self) -> int:
        return int(shutil.disk_usage(self.vault_dir).free)

    def check_disk_space(self, required_bytes: int = 0, target_dir: Path | None = None) -> None:
        floor_bytes = int(self.min_free_gb * (1024**3))
        probe_dir = target_dir if (target_dir and target_dir.exists()) else self.vault_dir
        free = int(shutil.disk_usage(probe_dir).free)
        if free < floor_bytes + max(0, required_bytes):
            raise DiskSpaceExhaustedError(
                f"Free disk space ({free / (1024**3):.2f} GB) below safety floor "
                f"({self.min_free_gb:.2f} GB + {required_bytes / (1024**2):.1f} MB)."
            )

    @staticmethod
    def _clean_ext(extension: str) -> str:
        ext = extension.lower().strip()
        if not ext:
            return ""
        if not ext.startswith("."):
            ext = f".{ext}"
        cleaned = re.sub(r"[^a-z0-9.]", "", ext)
        return cleaned if len(cleaned) <= 16 else cleaned[:16]

    def resolve_vault_path(self, rel_or_abs: str) -> Path:
        p = Path(rel_or_abs)
        if p.is_absolute():
            return p.resolve()
        target = (self.vault_dir / rel_or_abs).resolve()
        if not target.is_relative_to(self.vault_dir):
            raise ValueError(f"Vault path escape rejected: {rel_or_abs}")
        return target

    def store_stream(
        self,
        stream: BinaryIO,
        extension: str = "",
        copy_to_vault: bool = True,
        expected_size: int = 0,
        game_slug: str | None = None,
        rel_path: str | None = None,
        target_vault_dir: Path | None = None,
    ) -> tuple[str, int, str | None, bool]:
        """
        Stream data in 4 MB chunks, compute SHA-256, and store under a clear readable path:
          - <target_vault_dir>/<sanitized_rel_path>  (when custom per-game location is given)
          - <vault_dir>/<game_slug>/<sanitized_rel_path>  (default per-game folder)
          - <vault_dir>/misc/<sha256[:12]><ext>  (fallback when no rel_path given)
        Returns (sha256, size_bytes, stored_rel_or_abs_path, deduplicated).
        """
        hasher = hashlib.sha256()
        total_bytes = 0
        tmp_path: Path | None = None
        tmp_file: BinaryIO | None = None

        active_tmp_dir = (target_vault_dir / "_tmp") if target_vault_dir is not None else self.tmp_dir
        if copy_to_vault:
            if target_vault_dir is not None:
                ensure_vault_markers(target_vault_dir, target_vault_dir)
                active_tmp_dir.mkdir(parents=True, exist_ok=True)
            self.check_disk_space(expected_size, target_dir=target_vault_dir)
            tmp_name = f"part_{os.getpid()}_{threading.get_ident()}.tmp"
            tmp_path = active_tmp_dir / tmp_name

        try:
            if tmp_path is not None:
                tmp_file = open(to_long_path(tmp_path), "wb")

            while True:
                chunk = stream.read(4 * 1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
                total_bytes += len(chunk)
                if tmp_file is not None:
                    if total_bytes % (16 * 1024 * 1024) < len(chunk):
                        self.check_disk_space(0, target_dir=target_vault_dir)
                    tmp_file.write(chunk)

            if tmp_file is not None:
                tmp_file.flush()
                tmp_file.close()
                tmp_file = None

            sha256 = hasher.hexdigest()
            if not copy_to_vault:
                return sha256, total_bytes, None, False

            if rel_path:
                clean_rel = sanitize_export_relpath(rel_path.replace("!", "/"))
                if target_vault_dir is not None:
                    base_dir = target_vault_dir.resolve()
                elif game_slug:
                    safe_slug = sanitize_export_relpath(game_slug).name
                    if safe_slug in ("_tmp", "_previews", "misc", "_unnamed"):
                        safe_slug = f"game-{safe_slug}"
                    base_dir = (self.vault_dir / safe_slug).resolve()
                else:
                    base_dir = self.vault_dir
                dest = (base_dir / clean_rel).resolve()
                if not dest.is_relative_to(base_dir):
                    raise ValueError(f"Vault path escape rejected: {rel_path}")
            else:
                safe_ext = self._clean_ext(extension)
                base_dir = (target_vault_dir or self.vault_dir).resolve()
                dest = (base_dir / "misc" / f"{sha256[:12]}{safe_ext}").resolve()

            # Handle identical content vs case-insensitive collision on NTFS
            if dest.exists():
                if dest.stat().st_size == total_bytes and _sha256_file(dest) == sha256:
                    if tmp_path is not None:
                        tmp_path.unlink(missing_ok=True)
                    stored_ref = (
                        dest.relative_to(self.vault_dir).as_posix()
                        if dest.is_relative_to(self.vault_dir)
                        else str(dest)
                    )
                    return sha256, total_bytes, stored_ref, True
                # Different file collided (e.g. Icon.png vs icon.png on Windows)
                dest = dest.with_name(f"{dest.stem}_{sha256[:6]}{dest.suffix}")

            dest.parent.mkdir(parents=True, exist_ok=True)
            assert tmp_path is not None
            os.replace(to_long_path(tmp_path), to_long_path(dest))
            stored_ref = (
                dest.relative_to(self.vault_dir).as_posix()
                if dest.is_relative_to(self.vault_dir)
                else str(dest)
            )
            return sha256, total_bytes, stored_ref, False
        except Exception:
            if tmp_file is not None:
                try:
                    tmp_file.close()
                except Exception:
                    pass
            if tmp_path is not None:
                try:
                    tmp_path.unlink(missing_ok=True)
                except Exception:
                    pass
            raise

    @staticmethod
    def _link_or_copy(src_file: Path, dest: Path, use_hardlinks: bool) -> None:
        src_str = to_long_path(src_file)
        dst_str = to_long_path(dest)
        if dest.exists():
            try:
                if os.path.samefile(src_str, dst_str):
                    return
            except OSError:
                pass
            dest.unlink(missing_ok=True)
        if use_hardlinks:
            try:
                os.link(src_str, dst_str)
                return
            except OSError:
                pass
        shutil.copy2(src_str, dst_str)

    def export_assets_tree(
        self,
        assets: list[dict],
        out_dir: Path,
        prefer_preview: bool = False,
        use_hardlinks: bool = False,
    ) -> dict[str, int]:
        """Export vaulted assets to a clean, traversal-safe directory tree."""
        out_root = Path(out_dir).resolve()
        out_root.mkdir(parents=True, exist_ok=True)
        exported = 0
        skipped = 0
        seen_ci: dict[str, str] = {}
        for asset in assets:
            rel_src = (
                asset.get("preview_rel_path")
                if (prefer_preview and asset.get("preview_rel_path"))
                else asset.get("vault_rel_path")
            )
            if not rel_src:
                skipped += 1
                continue
            src_file = self.resolve_vault_path(rel_src)
            if not src_file.is_file():
                skipped += 1
                continue
            orig = str(asset["original_path"]).replace("!", "/")
            safe_rel = sanitize_export_relpath(orig)
            if prefer_preview and asset.get("preview_rel_path"):
                safe_rel = safe_rel.with_suffix(".png")
            dest = (out_root / safe_rel).resolve()
            if not dest.is_relative_to(out_root):
                skipped += 1
                continue

            sha = str(asset.get("blob_sha256") or "")
            ci_key = str(dest).lower()
            if ci_key in seen_ci and seen_ci[ci_key] != sha:
                dest = dest.with_name(f"{dest.stem}_{sha[:6]}{dest.suffix}")
            seen_ci[str(dest).lower()] = sha

            dest.parent.mkdir(parents=True, exist_ok=True)
            self._link_or_copy(src_file, dest, use_hardlinks=use_hardlinks)
            exported += 1
        return {"exported": exported, "skipped": skipped}
