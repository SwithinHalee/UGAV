"""Core universal game scanning, unpacking, CAS vaulting, and translation pipeline."""

from __future__ import annotations

import os
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from ugav.adapters.base import (
    AdapterOptions,
    ArchiveCorruptError,
    ArchiveEntry,
    EntryBoundsError,
)
from ugav.adapters.binary_carver import carve_embedded_assets
from ugav.adapters.registry import AdapterRegistry
from ugav.config import ScanConfig
from ugav.db.repository import DatabaseRepository
from ugav.detectors.engine_fingerprint import FingerprintResult, fingerprint_game_directory
from ugav.detectors.entropy import calculate_stream_entropy, classify_encryption_flag
from ugav.detectors.magic_sniffer import SniffResult, sniff_bytes, sniff_file
from ugav.discovery import resolve_game_root
from ugav.paths import VAULT_MARKER_FILENAME, ensure_vault_markers, is_vault_or_self_dir, validate_scan_target
from ugav.translators.generic_structured import parse_structured_bytes
from ugav.translators.rule_engine import DeclarativeRuleEngine
from ugav.vault.converters import convert_to_preview_png
from ugav.vault.storage import DiskSpaceExhaustedError, VaultStorage


@dataclass
class ScanProgress:
    phase: str
    files_scanned: int = 0
    total_files: int = 0
    assets_indexed: int = 0
    bytes_copied: int = 0
    deduplicated_bytes: int = 0
    entities_parsed: int = 0
    warnings_count: int = 0
    current_path: str = ""
    elapsed_sec: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanSummary:
    game: dict[str, Any]
    scan_run_id: int
    status: str
    files_scanned: int
    assets_indexed: int
    entities_parsed: int
    missing_marked: int
    warnings_count: int
    bytes_copied: int
    deduplicated_bytes: int
    elapsed_sec: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _walk_game_files(
    root: Path,
    data_dir: Path,
    vault_dir: Path,
    warnings_out: list[tuple[str, str]],
) -> list[tuple[Path, str, int, int]]:
    """Safely walk root directory avoiding symlinks, junctions, and UGAV vault folders."""
    results: list[tuple[Path, str, int, int]] = []
    visited_dirs: set[tuple[int, int]] = set()
    stack: list[Path] = [root]

    while stack:
        current = stack.pop()
        try:
            if os.path.islink(current) or (hasattr(os.path, "isjunction") and os.path.isjunction(current)):
                warnings_out.append((str(current), "Skipped symlink/junction directory"))
                continue
            st = os.stat(current, follow_symlinks=False)
            if st.st_ino:
                key = (st.st_dev, st.st_ino)
                if key in visited_dirs:
                    warnings_out.append((str(current), "Detected directory loop; skipped"))
                    continue
                visited_dirs.add(key)

            with os.scandir(current) as it:
                for de in it:
                    p = Path(de.path)
                    if de.name == VAULT_MARKER_FILENAME:
                        continue
                    try:
                        if de.is_symlink():
                            warnings_out.append((str(p), "Skipped symlink"))
                            continue
                        if hasattr(os.path, "isjunction") and os.path.isjunction(p):
                            warnings_out.append((str(p), "Skipped NTFS junction"))
                            continue
                        if de.is_dir(follow_symlinks=False):
                            if (p / VAULT_MARKER_FILENAME).exists() or p.resolve() in (
                                data_dir.resolve(),
                                vault_dir.resolve(),
                            ):
                                warnings_out.append((str(p), "Skipped UGAV vault/data subdirectory"))
                                continue
                            stack.append(p)
                        elif de.is_file(follow_symlinks=False):
                            fst = de.stat(follow_symlinks=False)
                            rel = p.relative_to(root).as_posix()
                            results.append((p, rel, fst.st_size, fst.st_mtime_ns))
                    except OSError as exc:
                        warnings_out.append((str(p), f"Walk error: {exc}"))
        except OSError as exc:
            warnings_out.append((str(current), f"Directory access error: {exc}"))

    results.sort(key=lambda item: item[1])
    return results


class ScanPipeline:
    """Universal offline game scanning, unpacking, vaulting, and translation orchestrator."""

    def __init__(
        self,
        repo: DatabaseRepository,
        vault: VaultStorage,
        data_dir: Path,
        config: ScanConfig | None = None,
        registry: AdapterRegistry | None = None,
    ) -> None:
        self.repo = repo
        self.vault = vault
        self.data_dir = Path(data_dir).resolve()
        self.config = config or ScanConfig()
        self.registry = registry or AdapterRegistry()

    def scan_game(
        self,
        target_path: Path | str,
        *,
        progress_callback: Callable[[ScanProgress], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> ScanSummary:
        t0 = time.monotonic()
        raw_target = Path(target_path).expanduser()
        if raw_target.exists():
            validate_scan_target(raw_target, self.data_dir, self.vault.vault_dir)
        game_root = resolve_game_root(raw_target)
        if not game_root.is_dir():
            raise FileNotFoundError(f"Game directory not found: {game_root}")

        validate_scan_target(game_root, self.data_dir, self.vault.vault_dir)

        custom_vault_dir: Path | None = None
        if self.config.output_vault_dir:
            custom_vault_dir = Path(self.config.output_vault_dir).expanduser().resolve()
            validate_scan_target(game_root, custom_vault_dir, custom_vault_dir)
            if is_vault_or_self_dir(game_root, custom_vault_dir, custom_vault_dir):
                raise ValueError(f"Output vault location cannot overlap game directory: {custom_vault_dir}")

        fp: FingerprintResult = fingerprint_game_directory(game_root)
        meta_with_vault = dict(fp.details)
        game = self.repo.upsert_game(
            name=fp.name,
            root_path=str(fp.root_path),
            detected_engine=fp.detected_engine,
            middleware=fp.middleware,
            cpu_arch=fp.cpu_arch,
            source_platform=fp.source_platform,
            confidence=fp.confidence,
            is_online_stub=fp.is_online_stub,
            fingerprint_hash=fp.fingerprint_hash,
            metadata=meta_with_vault,
        )
        game_slug = str(game["slug"])
        effective_vault_loc = custom_vault_dir if custom_vault_dir is not None else (self.vault.vault_dir / game_slug)
        if self.config.copy_mode != "index_only":
            ensure_vault_markers(effective_vault_loc, effective_vault_loc)
        meta_with_vault["vault_location"] = str(effective_vault_loc)
        game = self.repo.upsert_game(
            name=fp.name,
            root_path=str(fp.root_path),
            detected_engine=fp.detected_engine,
            middleware=fp.middleware,
            cpu_arch=fp.cpu_arch,
            source_platform=fp.source_platform,
            confidence=fp.confidence,
            is_online_stub=fp.is_online_stub,
            fingerprint_hash=fp.fingerprint_hash,
            metadata=meta_with_vault,
            slug=game_slug,
        )
        game_id = int(game["id"])
        scan_run_id = self.repo.start_scan_run(game_id, self.config.copy_mode)

        prog = ScanProgress(phase="fingerprint", total_files=fp.total_files)
        if progress_callback:
            progress_callback(prog)

        if fp.is_online_stub and not self.config.force_online_stub:
            self.repo.log_warning(
                scan_run_id,
                game_id,
                str(game_root),
                "fingerprint",
                "warning",
                "Skipped target detected as online-only launcher/stub.",
            )
            self.repo.finish_scan_run(scan_run_id, "skipped_online", 0, 0, 0)
            return ScanSummary(
                game=game,
                scan_run_id=scan_run_id,
                status="skipped_online",
                files_scanned=0,
                assets_indexed=0,
                entities_parsed=0,
                missing_marked=0,
                warnings_count=1,
                bytes_copied=0,
                deduplicated_bytes=0,
                elapsed_sec=round(time.monotonic() - t0, 3),
            )

        if self.config.copy_mode != "index_only":
            self.vault.check_disk_space(0)

        walk_warnings: list[tuple[str, str]] = []
        files = _walk_game_files(game_root, self.data_dir, self.vault.vault_dir, walk_warnings)
        prog.total_files = len(files)
        prog.phase = "scanning"

        for wpath, wmsg in walk_warnings:
            self.repo.log_warning(scan_run_id, game_id, wpath, "walk", "warning", wmsg)
            prog.warnings_count += 1

        known_map = self.repo.get_known_assets_map(game_id) if self.config.incremental else {}
        seen_keys: set[tuple[str, str]] = set()
        exclude_exts = self.config.normalized_exclude_extensions()
        include_cats = set(self.config.include_categories) if self.config.include_categories else None
        max_file_bytes = (
            int(self.config.max_file_mb * 1024 * 1024)
            if self.config.max_file_mb is not None
            else None
        )

        blobs_batch: dict[str, dict[str, Any]] = {}
        assets_batch: list[dict[str, Any]] = []
        pending_archives: list[tuple[Path, str, str, bytes]] = []  # (full_path, rel_path, source_kind, header)
        status = "completed"
        aborted_incomplete = False

        def _flush_batch() -> dict[tuple[str, str], int]:
            if not blobs_batch and not assets_batch:
                return {}
            ids = self.repo.upsert_blobs_and_assets_batch(blobs_batch.values(), assets_batch)
            blobs_batch.clear()
            assets_batch.clear()
            return ids

        def _should_copy(category: str, ext: str, size: int, is_archive: bool) -> bool:
            if self.config.copy_mode == "index_only":
                return False
            if ext in exclude_exts:
                return False
            if max_file_bytes is not None and size > max_file_bytes:
                return False
            if self.config.copy_mode == "vault_extracted" and is_archive:
                return False
            if self.config.copy_mode == "vault_selective" and include_cats is not None:
                return category in include_cats
            if include_cats is not None and category not in include_cats:
                return False
            return True

        adapter_opts = AdapterOptions(
            max_entry_bytes=self.config.max_entry_bytes(),
            max_ratio=self.config.max_compression_ratio,
            keys=self.config.keys,
            metadata_only=(self.config.copy_mode == "index_only"),
        )

        try:
            for full_path, rel_path, fsize, fmtime in files:
                if cancel_event and cancel_event.is_set():
                    status = "cancelled"
                    aborted_incomplete = True
                    break

                prog.files_scanned += 1
                prog.current_path = rel_path
                ext = full_path.suffix.lower()
                fs_key = ("filesystem", rel_path)
                seen_keys.add(fs_key)

                # Incremental skip check
                known = known_map.get(fs_key)
                if known is not None:
                    _aid, prev_sz, prev_mt, prev_sha = known
                    if prev_sz == fsize and prev_mt == fmtime:
                        if self.config.copy_mode == "index_only" or prev_sha is not None:
                            # Still check if it's an archive we might need to process if new mode wants extraction
                            pass
                        # Skip re-hashing unchanged non-archive file when blob is already present
                        if prev_sha is not None:
                            blob_info = self.repo.get_blob(prev_sha)
                            is_arch_prev = bool(blob_info and blob_info["detected_format"] in (
                                "cri_cpk", "zip", "gamemaker_iff", "godot_pck", "renpy_rpa",
                                "valve_vpk", "electron_asar", "bethesda_bsa", "bethesda_ba2",
                            ))
                            if not is_arch_prev and (
                                self.config.copy_mode == "index_only"
                                or (blob_info and blob_info.get("vault_rel_path"))
                            ):
                                prog.assets_indexed += 1
                                continue

                try:
                    with full_path.open("rb") as f:
                        header = f.read(4096)
                        tail = b""
                        if fsize > 32:
                            f.seek(max(0, fsize - 32), 0)
                            tail = f.read(32)
                        sniff: SniffResult = sniff_bytes(header, extension=ext, tail=tail, path_hint=rel_path)

                        adapter = self.registry.find_adapter(full_path, header)
                        is_arch = sniff.is_archive or (adapter is not None)
                        want_copy = _should_copy(sniff.asset_category, ext, fsize, is_arch)

                        # Skip full-file stream hashing when not copying large files or in index_only mode
                        skip_stream_read = not want_copy and (
                            self.config.copy_mode == "index_only"
                            or fsize > 16 * 1024 * 1024
                        )

                        sha256: str | None = None
                        vault_rel: str | None = None
                        preview_rel: str | None = None
                        entropy = 0.0
                        enc_flag = "none"

                        if not skip_stream_read:
                            f.seek(0, 0)
                            entropy = calculate_stream_entropy(f, total_size=fsize)
                            enc_flag = classify_encryption_flag(entropy, sniff.detected_format)
                            f.seek(0, 0)
                            sha256, actual_sz, vault_rel, dedup = self.vault.store_stream(
                                f,
                                extension=ext,
                                copy_to_vault=want_copy,
                                expected_size=fsize if want_copy else 0,
                                game_slug=game_slug,
                                rel_path=rel_path,
                                target_vault_dir=custom_vault_dir,
                            )
                            if want_copy and vault_rel:
                                if dedup:
                                    prog.deduplicated_bytes += actual_sz
                                else:
                                    prog.bytes_copied += actual_sz
                                if self.config.convert_textures and sniff.detected_format in (
                                    "dds",
                                    "tga",
                                    "rpgmaker_xor_img",
                                ):
                                    preview_rel = convert_to_preview_png(
                                        self.vault.resolve_vault_path(vault_rel),
                                        sniff.detected_format,
                                        self.vault.vault_dir,
                                        sha256,
                                        game_slug=game_slug,
                                        rel_path=rel_path,
                                        target_vault_dir=custom_vault_dir,
                                    )
                            blobs_batch[sha256] = {
                                "sha256": sha256,
                                "size_bytes": actual_sz,
                                "vault_rel_path": vault_rel,
                                "preview_rel_path": preview_rel,
                                "detected_mime": sniff.detected_mime,
                                "detected_format": sniff.detected_format,
                                "entropy": entropy,
                                "encryption_flag": enc_flag,
                            }

                        assets_batch.append(
                            {
                                "game_id": game_id,
                                "parent_asset_id": None,
                                "blob_sha256": sha256,
                                "original_path": rel_path,
                                "source_kind": "filesystem",
                                "source_offset": 0,
                                "source_size": fsize,
                                "source_mtime_ns": fmtime,
                                "extension": ext,
                                "asset_category": sniff.asset_category,
                                "metadata": {
                                    "encoding": sniff.encoding,
                                    "is_archive": is_arch,
                                    "skipped_hash_due_to_size": skip_stream_read,
                                },
                            }
                        )
                        prog.assets_indexed += 1

                        if adapter is not None:
                            pending_archives.append((full_path, rel_path, "adapter", header))
                        elif (
                            self.config.carve_unknown
                            and sniff.asset_category == "unknown"
                            and enc_flag != "suspected_encrypted"
                            and fsize >= 256
                        ):
                            pending_archives.append((full_path, rel_path, "carve", header))

                except DiskSpaceExhaustedError as exc:
                    self.repo.log_warning(scan_run_id, game_id, rel_path, "vault", "error", str(exc))
                    prog.warnings_count += 1
                    status = "partial"
                    aborted_incomplete = True
                    break
                except (PermissionError, OSError) as exc:
                    self.repo.log_warning(scan_run_id, game_id, rel_path, "read", "warning", str(exc))
                    prog.warnings_count += 1

                if len(assets_batch) >= self.config.batch_size:
                    _flush_batch()
                    prog.elapsed_sec = round(time.monotonic() - t0, 2)
                    if progress_callback:
                        progress_callback(prog)

            parent_id_map = _flush_batch()

            # Process archives / carved containers
            if not aborted_incomplete and pending_archives:
                prog.phase = "unpacking"
                for arch_path, arch_rel, mode_tag, arch_hdr in pending_archives:
                    if cancel_event and cancel_event.is_set():
                        status = "cancelled"
                        aborted_incomplete = True
                        break
                    parent_id = parent_id_map.get(("filesystem", arch_rel))
                    if parent_id is None:
                        existing = self.repo.get_known_assets_map(game_id).get(("filesystem", arch_rel))
                        parent_id = existing[0] if existing else None

                    try:
                        if mode_tag == "adapter":
                            adapter = self.registry.find_adapter(arch_path, arch_hdr)
                            if adapter is None:
                                continue
                            entry_iter = adapter.iter_entries(arch_path, adapter_opts)
                            source_kind = "archive_entry"
                        else:
                            entry_iter = carve_embedded_assets(arch_path, adapter_opts)
                            source_kind = "carved"

                        for entry in entry_iter:
                            if cancel_event and cancel_event.is_set():
                                status = "cancelled"
                                aborted_incomplete = True
                                break
                            v_full = f"{arch_rel}!{entry.virtual_path}"
                            seen_keys.add((source_kind, v_full))
                            entry_ext = Path(entry.virtual_path).suffix.lower()
                            prog.current_path = v_full

                            # Incremental check for archive entry in index_only mode
                            if (
                                self.config.copy_mode == "index_only"
                                and (source_kind, v_full) in known_map
                                and known_map[(source_kind, v_full)][1] == entry.uncompressed_size
                            ):
                                prog.assets_indexed += 1
                                continue

                            if self.config.copy_mode == "index_only" and mode_tag == "adapter":
                                sniff = sniff_bytes(b"", extension=entry_ext, path_hint=entry.virtual_path)
                                assets_batch.append(
                                    {
                                        "game_id": game_id,
                                        "parent_asset_id": parent_id,
                                        "blob_sha256": None,
                                        "original_path": v_full,
                                        "source_kind": source_kind,
                                        "source_offset": entry.offset,
                                        "source_size": entry.uncompressed_size,
                                        "source_mtime_ns": None,
                                        "extension": entry_ext,
                                        "asset_category": sniff.asset_category,
                                        "metadata": {
                                            "compressed_size": entry.compressed_size,
                                            "is_compressed": entry.is_compressed,
                                            "is_encrypted": entry.is_encrypted,
                                        },
                                    }
                                )
                                prog.assets_indexed += 1
                            else:
                                try:
                                    with entry.open_stream() as estream:
                                        hdr_sample = estream.read(4096)
                                        sniff = sniff_bytes(
                                            hdr_sample, extension=entry_ext, path_hint=entry.virtual_path
                                        )
                                        want_entry_copy = _should_copy(
                                            sniff.asset_category, entry_ext, entry.uncompressed_size, False
                                        )
                                        # Rewind or wrap header + remainder
                                        if hasattr(estream, "seek") and estream.seekable():
                                            estream.seek(0, 0)
                                            entropy = calculate_stream_entropy(
                                                estream, total_size=entry.uncompressed_size
                                            )
                                            estream.seek(0, 0)
                                            sha256, esz, evrel, ededup = self.vault.store_stream(
                                                estream,
                                                extension=entry_ext,
                                                copy_to_vault=want_entry_copy,
                                                expected_size=entry.uncompressed_size if want_entry_copy else 0,
                                                game_slug=game_slug,
                                                rel_path=v_full,
                                                target_vault_dir=custom_vault_dir,
                                            )
                                        else:
                                            import io

                                            rest = estream.read()
                                            full_bytes = hdr_sample + rest
                                            bio = io.BytesIO(full_bytes)
                                            entropy = calculate_stream_entropy(bio, total_size=len(full_bytes))
                                            bio.seek(0, 0)
                                            sha256, esz, evrel, ededup = self.vault.store_stream(
                                                bio,
                                                extension=entry_ext,
                                                copy_to_vault=want_entry_copy,
                                                expected_size=len(full_bytes) if want_entry_copy else 0,
                                                game_slug=game_slug,
                                                rel_path=v_full,
                                                target_vault_dir=custom_vault_dir,
                                            )

                                    enc_flag = "suspected_encrypted" if entry.is_encrypted else classify_encryption_flag(
                                        entropy, sniff.detected_format, entry.is_compressed
                                    )
                                    eprev_rel: str | None = None
                                    if want_entry_copy and evrel:
                                        if ededup:
                                            prog.deduplicated_bytes += esz
                                        else:
                                            prog.bytes_copied += esz
                                        if self.config.convert_textures and sniff.detected_format in (
                                            "dds",
                                            "tga",
                                            "rpgmaker_xor_img",
                                        ):
                                            eprev_rel = convert_to_preview_png(
                                                self.vault.resolve_vault_path(evrel),
                                                sniff.detected_format,
                                                self.vault.vault_dir,
                                                sha256,
                                                game_slug=game_slug,
                                                rel_path=v_full,
                                                target_vault_dir=custom_vault_dir,
                                            )

                                    blobs_batch[sha256] = {
                                        "sha256": sha256,
                                        "size_bytes": esz,
                                        "vault_rel_path": evrel,
                                        "preview_rel_path": eprev_rel,
                                        "detected_mime": sniff.detected_mime,
                                        "detected_format": sniff.detected_format,
                                        "entropy": entropy,
                                        "encryption_flag": enc_flag,
                                    }
                                    assets_batch.append(
                                        {
                                            "game_id": game_id,
                                            "parent_asset_id": parent_id,
                                            "blob_sha256": sha256,
                                            "original_path": v_full,
                                            "source_kind": source_kind,
                                            "source_offset": entry.offset,
                                            "source_size": esz,
                                            "source_mtime_ns": None,
                                            "extension": entry_ext,
                                            "asset_category": sniff.asset_category,
                                            "metadata": {
                                                "compressed_size": entry.compressed_size,
                                                "is_compressed": entry.is_compressed,
                                            },
                                        }
                                    )
                                    prog.assets_indexed += 1
                                except DiskSpaceExhaustedError as exc:
                                    self.repo.log_warning(
                                        scan_run_id, game_id, v_full, "vault", "error", str(exc)
                                    )
                                    prog.warnings_count += 1
                                    status = "partial"
                                    aborted_incomplete = True
                                    break
                                except (EntryBoundsError, ArchiveCorruptError, OSError) as exc:
                                    self.repo.log_warning(
                                        scan_run_id,
                                        game_id,
                                        v_full,
                                        "unpack_entry",
                                        "warning",
                                        f"Isolated corrupt/unsafe entry: {exc}",
                                    )
                                    prog.warnings_count += 1

                            if len(assets_batch) >= self.config.batch_size:
                                _flush_batch()
                                prog.elapsed_sec = round(time.monotonic() - t0, 2)
                                if progress_callback:
                                    progress_callback(prog)

                        if aborted_incomplete:
                            break
                    except (ArchiveCorruptError, OSError) as exc:
                        self.repo.log_warning(
                            scan_run_id, game_id, arch_rel, "unpack_archive", "warning", str(exc)
                        )
                        prog.warnings_count += 1

            _flush_batch()
        finally:
            _flush_batch()

        missing_marked = 0
        if not aborted_incomplete:
            missing_marked = self.repo.mark_missing_assets(game_id, seen_keys)

        # Pass 3: Structured Data & Rule-Based Translation
        entities_parsed = 0
        if status in ("completed", "partial"):
            prog.phase = "translating"
            if progress_callback:
                progress_callback(prog)
            entities_parsed = self._run_translations(game_id, game_root, scan_run_id)
            prog.entities_parsed = entities_parsed

        prog.phase = "done"
        prog.elapsed_sec = round(time.monotonic() - t0, 2)
        if progress_callback:
            progress_callback(prog)

        self.repo.finish_scan_run(
            scan_run_id,
            status=status,
            files_scanned=prog.files_scanned,
            assets_indexed=prog.assets_indexed,
            entities_parsed=entities_parsed,
        )
        updated_game = self.repo.get_game_by_id(game_id) or game
        return ScanSummary(
            game=updated_game,
            scan_run_id=scan_run_id,
            status=status,
            files_scanned=prog.files_scanned,
            assets_indexed=prog.assets_indexed,
            entities_parsed=entities_parsed,
            missing_marked=missing_marked,
            warnings_count=prog.warnings_count,
            bytes_copied=prog.bytes_copied,
            deduplicated_bytes=prog.deduplicated_bytes,
            elapsed_sec=prog.elapsed_sec,
        )

    def _run_translations(self, game_id: int, game_root: Path, scan_run_id: int) -> int:
        # Fetch data & localization assets up to 10 MB
        all_data_assets: list[dict[str, Any]] = []
        for cat in ("data", "localization"):
            page = 1
            while True:
                res = self.repo.query_assets_paginated(
                    game_id, category=cat, page=page, page_size=200
                )
                all_data_assets.extend(res["items"])
                if page * 200 >= res["total"]:
                    break
                page += 1

        if not all_data_assets:
            return 0

        def _bytes_provider(asset: dict[str, Any]) -> bytes | None:
            if asset.get("source_size", 0) > 10 * 1024 * 1024:
                return None
            vrel = asset.get("vault_rel_path")
            if vrel:
                try:
                    vp = self.vault.resolve_vault_path(vrel)
                    if vp.is_file():
                        return vp.read_bytes()
                except Exception:
                    pass
            if asset.get("source_kind") == "filesystem":
                src = game_root / asset["original_path"]
                if src.is_file():
                    try:
                        return src.read_bytes()
                    except OSError:
                        return None
            return None

        rule_engine = DeclarativeRuleEngine(self.data_dir)
        rule_count, handled_ids = rule_engine.run_for_game(
            self.repo, game_id, game_root, _bytes_provider, all_data_assets
        )

        # Fallback generic parser for structured files not handled by domain rules
        generic_entities: list[dict[str, Any]] = []
        generic_locs: list[dict[str, Any]] = []
        supported_fmt = {"xml", "json", "jsonc", "yaml", "csv", "tsv", "ini", "sqlite"}
        for asset in all_data_assets:
            aid = int(asset["id"])
            if aid in handled_ids:
                continue
            fmt = str(asset.get("detected_format") or asset.get("extension", "").lstrip(".")).lower()
            if fmt not in supported_fmt:
                continue
            raw = _bytes_provider(asset)
            if not raw:
                continue
            try:
                ents, locs = parse_structured_bytes(
                    raw,
                    fmt=fmt,
                    rel_path=asset["original_path"],
                    source_asset_id=aid,
                )
                for e in ents:
                    generic_entities.append(
                        {
                            "game_id": game_id,
                            "source_asset_id": e.source_asset_id,
                            "entity_type": e.entity_type,
                            "external_key": e.external_key,
                            "slug": e.slug,
                            "display_name": e.display_name,
                            "raw": e.raw,
                            "resolved": e.resolved,
                        }
                    )
                for l in locs:
                    generic_locs.append(
                        {
                            "game_id": game_id,
                            "lang": l.lang,
                            "str_key": l.str_key,
                            "str_value": l.str_value,
                            "source_asset_id": l.source_asset_id,
                        }
                    )
            except Exception as exc:
                self.repo.log_warning(
                    scan_run_id, game_id, asset["original_path"], "translate", "warning", str(exc)
                )

        if generic_locs:
            self.repo.upsert_localization_batch(generic_locs)
        if generic_entities:
            self.repo.upsert_entities_batch(generic_entities)
        return rule_count + len(generic_entities)
