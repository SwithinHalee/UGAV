"""Multi-engine, middleware, CPU architecture, and online-stub fingerprinting."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pefile


@dataclass
class FingerprintResult:
    root_path: Path
    name: str
    detected_engine: str
    middleware: list[str] = field(default_factory=list)
    cpu_arch: str = "unknown"
    source_platform: str = "windows"
    confidence: float = 0.0
    is_online_stub: bool = False
    fingerprint_hash: str = ""
    total_files: int = 0
    total_bytes: int = 0
    details: dict[str, Any] = field(default_factory=dict)


def _detect_pe_arch_and_imports(exe_path: Path) -> tuple[str, list[str]]:
    try:
        pe = pefile.PE(str(exe_path), fast_load=True)
        try:
            machine = pe.FILE_HEADER.Machine
            arch_map = {
                0x8664: "x86_64",
                0x014C: "x86",
                0xAA64: "arm64",
                0x01C4: "arm",
            }
            arch = arch_map.get(machine, f"pe_0x{machine:x}")
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            imports: list[str] = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if entry.dll:
                        imports.append(entry.dll.decode("ascii", errors="ignore").lower())
            return arch, imports
        finally:
            pe.close()
    except Exception:
        return "unknown", []


def _detect_elf_arch(so_path: Path) -> str:
    try:
        with so_path.open("rb") as f:
            hdr = f.read(20)
        if len(hdr) >= 20 and hdr[:4] == b"\x7fELF":
            em = int.from_bytes(hdr[18:20], "little")
            return {62: "x86_64", 3: "x86", 183: "arm64", 40: "arm"}.get(em, f"elf_{em}")
    except Exception:
        pass
    return "unknown"


def _safe_walk(root: Path, max_files: int = 50000) -> tuple[list[tuple[Path, str, int]], list[str]]:
    """Walk directory avoiding symlink and NTFS junction loops."""
    entries: list[tuple[Path, str, int]] = []
    warnings: list[str] = []
    visited_dirs: set[tuple[int, int]] = set()

    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            st = os.stat(current, follow_symlinks=False)
            if os.path.islink(current) or (hasattr(os.path, "isjunction") and os.path.isjunction(current)):
                continue
            dir_key = (st.st_dev, st.st_ino)
            if st.st_ino and dir_key in visited_dirs:
                continue
            visited_dirs.add(dir_key)

            with os.scandir(current) as it:
                for de in it:
                    p = Path(de.path)
                    if de.name == ".ugav_vault_marker":
                        continue
                    try:
                        if de.is_symlink():
                            continue
                        if hasattr(os.path, "isjunction") and os.path.isjunction(p):
                            continue
                        if de.is_dir(follow_symlinks=False):
                            if not (p / ".ugav_vault_marker").exists():
                                stack.append(p)
                        elif de.is_file(follow_symlinks=False):
                            fst = de.stat(follow_symlinks=False)
                            rel = p.relative_to(root).as_posix()
                            entries.append((p, rel, fst.st_size))
                            if len(entries) >= max_files:
                                return entries, warnings
                    except OSError as exc:
                        warnings.append(f"{p}: {exc}")
        except OSError as exc:
            warnings.append(f"{current}: {exc}")
    return entries, warnings


def fingerprint_game_directory(root_path: Path) -> FingerprintResult:
    """Detect engine, middleware, CPU arch, and online-stub status for a game directory."""
    root = Path(root_path).resolve()
    entries, walk_warnings = _safe_walk(root)

    ext_counts: dict[str, int] = {}
    ext_bytes: dict[str, int] = {}
    rel_lower_set: set[str] = set()
    exe_candidates: list[tuple[int, Path]] = []
    elf_candidates: list[Path] = []
    total_bytes = 0

    for full_p, rel, sz in entries:
        total_bytes += sz
        ext = full_p.suffix.lower() or "(none)"
        ext_counts[ext] = ext_counts.get(ext, 0) + 1
        ext_bytes[ext] = ext_bytes.get(ext, 0) + sz
        rel_l = rel.lower()
        rel_lower_set.add(rel_l)
        if ext == ".exe" and "unins" not in full_p.name.lower() and "crash" not in full_p.name.lower():
            exe_candidates.append((sz, full_p))
        elif ext == ".so":
            elf_candidates.append(full_p)

    # Detect platform and CPU architecture
    cpu_arch = "unknown"
    source_platform = "windows"
    pe_imports: list[str] = []
    if exe_candidates:
        exe_candidates.sort(key=lambda item: item[0], reverse=True)
        for _, exe_p in exe_candidates[:3]:
            arch, imps = _detect_pe_arch_and_imports(exe_p)
            if cpu_arch == "unknown" and arch != "unknown":
                cpu_arch = arch
            pe_imports.extend(imps)
    elif elf_candidates:
        source_platform = "linux"
        cpu_arch = _detect_elf_arch(elf_candidates[0])
    elif any(rel.endswith(".app/contents/macos") or "/contents/macos/" in rel for rel in rel_lower_set):
        source_platform = "macos"

    if any(rel == "androidmanifest.xml" or rel.endswith(".apk") for rel in rel_lower_set):
        source_platform = "android"

    # Engine detection scoring
    scores: dict[str, float] = {}
    middleware: set[str] = set()

    has_unity_player = any(rel.endswith("unityplayer.dll") for rel in rel_lower_set)
    has_unity_data = any(
        rel.endswith("globalgamemanagers") or rel.endswith(".assets") or rel.endswith("resources.assets")
        for rel in rel_lower_set
    )
    if has_unity_player or has_unity_data:
        scores["unity"] = 0.95 if (has_unity_player and has_unity_data) else 0.78

    has_ue_bins = any("engine/binaries/" in rel or "-shipping.exe" in rel for rel in rel_lower_set)
    has_ue_paks = (ext_counts.get(".pak", 0) > 0 and (ext_counts.get(".utoc", 0) > 0 or ext_counts.get(".ucas", 0) > 0 or has_ue_bins))
    if has_ue_paks or has_ue_bins:
        scores["unreal"] = 0.92 if has_ue_paks else 0.75

    cpk_count = ext_counts.get(".cpk", 0)
    if cpk_count > 0:
        scores["criware_cpk"] = 0.93
        middleware.add("criware")

    if "data.win" in rel_lower_set or any(rel.endswith("/data.win") for rel in rel_lower_set):
        # Verify FORM+GEN8 header
        for full_p, rel, _ in entries:
            if rel.lower().endswith("data.win"):
                try:
                    with full_p.open("rb") as f:
                        h = f.read(16)
                    if h[:4] == b"FORM" and h[8:12] == b"GEN8":
                        scores["gamemaker"] = 0.96
                except OSError:
                    pass
                break

    if ext_counts.get(".bsa", 0) > 0 or ext_counts.get(".ba2", 0) > 0 or ext_counts.get(".esm", 0) > 0:
        scores["bethesda"] = 0.94

    if ext_counts.get(".pck", 0) > 0 or "project.godot" in rel_lower_set:
        scores["godot"] = 0.90

    if (
        "www/data/system.json" in rel_lower_set
        or "data/system.json" in rel_lower_set
        or ext_counts.get(".rgss3a", 0) > 0
        or ext_counts.get(".rpgmvp", 0) > 0
    ):
        scores["rpgmaker"] = 0.92

    if ext_counts.get(".rpa", 0) > 0 or any(rel.startswith("renpy/") for rel in rel_lower_set):
        scores["renpy"] = 0.92

    if ext_counts.get(".vpk", 0) > 0:
        scores["source_vpk"] = 0.88

    if any(rel.endswith("app.asar") for rel in rel_lower_set):
        scores["electron"] = 0.90

    xml_cnt = ext_counts.get(".xml", 0)
    json_cnt = ext_counts.get(".json", 0)
    media_cnt = sum(ext_counts.get(e, 0) for e in (".dds", ".png", ".jpg", ".tga", ".wav", ".ogg", ".mp3"))
    if xml_cnt >= 20 and media_cnt >= 10:
        scores["loose_xml"] = 0.85
    elif (xml_cnt + json_cnt + ext_counts.get(".csv", 0) + ext_counts.get(".yaml", 0)) >= 5 and media_cnt >= 5:
        scores["loose_structured"] = 0.78

    # Middleware tags
    if any(ext_counts.get(e, 0) > 0 for e in (".cpk", ".acf", ".acb", ".awb", ".usm")) or any(
        "cri_" in imp for imp in pe_imports
    ):
        middleware.add("criware")
    if any(ext_counts.get(e, 0) > 0 for e in (".wem", ".bnk")) or any("ak" in imp and "sound" in imp for imp in pe_imports):
        middleware.add("wwise")
    if any(ext_counts.get(e, 0) > 0 for e in (".bank", ".fsb")) or any("fmod" in imp for imp in pe_imports):
        middleware.add("fmod")
    if ext_counts.get(".bik", 0) > 0 or ext_counts.get(".bk2", 0) > 0:
        middleware.add("bink")
    if any("steam_api" in rel for rel in rel_lower_set):
        middleware.add("steamworks")

    if scores:
        detected_engine, confidence = max(scores.items(), key=lambda kv: kv[1])
    else:
        detected_engine, confidence = ("custom_native", 0.40)

    # Online-stub check: require tiny offline asset footprint AND explicit launcher/updater clues
    non_bin_bytes = total_bytes - ext_bytes.get(".exe", 0) - ext_bytes.get(".dll", 0) - ext_bytes.get(".pdb", 0)
    archive_count = sum(
        ext_counts.get(e, 0)
        for e in (".cpk", ".pak", ".bsa", ".ba2", ".assets", ".pck", ".rpa", ".vpk", ".asar", ".zip", ".win")
    )
    stub_names = any(
        any(tok in rel for tok in ("updater.exe", "patcher.exe", "bootstrapper", "online_manifest"))
        for rel in rel_lower_set
    )
    is_online_stub = bool(
        non_bin_bytes < 2 * 1024 * 1024 and archive_count == 0 and media_cnt < 3 and stub_names
    )

    # Deterministic fingerprint hash across top structure + largest exe name/size
    fp_seed = "|".join(
        [
            root.name.lower(),
            detected_engine,
            cpu_arch,
            str(len(entries)),
            ",".join(f"{k}:{v}" for k, v in sorted(ext_counts.items())[:15]),
        ]
    )
    fp_hash = hashlib.sha256(fp_seed.encode("utf-8")).hexdigest()[:16]

    return FingerprintResult(
        root_path=root,
        name=root.name,
        detected_engine=detected_engine,
        middleware=sorted(middleware),
        cpu_arch=cpu_arch,
        source_platform=source_platform,
        confidence=round(confidence, 2),
        is_online_stub=is_online_stub,
        fingerprint_hash=fp_hash,
        total_files=len(entries),
        total_bytes=total_bytes,
        details={
            "top_extensions": sorted(ext_counts.items(), key=lambda kv: kv[1], reverse=True)[:15],
            "engine_scores": scores,
            "walk_warnings": walk_warnings[:20],
        },
    )
