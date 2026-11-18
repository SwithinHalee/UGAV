"""Cross-device game auto-discovery and game root resolution."""

from __future__ import annotations

import json
import os
import re
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ugav.paths import VAULT_MARKER_FILENAME, is_vault_or_self_dir

_STOP_PARENT_NAMES: frozenset[str] = frozenset(
    {
        "common",
        "games",
        "xboxgames",
        "epic games",
        "gog games",
        "program files",
        "program files (x86)",
        "steamapps",
        "steamlibrary",
    }
)

_SKIP_STEAM_DIRS: frozenset[str] = frozenset(
    {
        "steamworks shared",
        "steam controller configs",
        "steamlinuxruntime",
        "steamlinuxruntime_sniper",
        "steamlinuxruntime_soldier",
    }
)

_SUBBIN_DIR_NAMES: frozenset[str] = frozenset(
    {
        "bin",
        "binaries",
        "win64",
        "win32",
        "windows-x86_64",
        "windowsnoeditor",
        "x64",
        "x86",
        "macos",
        "contents",
        "linux64",
    }
)


@dataclass
class DiscoveredGame:
    name: str
    root_path: Path
    source: str
    app_id: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "name": self.name,
            "root_path": str(self.root_path),
            "source": self.source,
            "app_id": self.app_id,
        }


def _has_root_markers(directory: Path) -> bool:
    if not directory.is_dir() or (directory / VAULT_MARKER_FILENAME).exists():
        return False
    try:
        names_lower: set[str] = set()
        for entry in os.scandir(directory):
            low = entry.name.lower()
            names_lower.add(low)
            if low.endswith("_data") and entry.is_dir(follow_symlinks=False):
                sub = Path(entry.path)
                if not (sub / VAULT_MARKER_FILENAME).exists() and (
                    (sub / "globalgamemanagers").is_file()
                    or (sub / "Managed").is_dir()
                    or (sub / "resources.assets").is_file()
                    or any(sub.glob("*.assets"))
                ):
                    return True
            if low.endswith((".cpk", ".bsa", ".ba2", ".esm", ".pck", ".rpa")):
                return True
        if names_lower & {
            "data",
            "cpk",
            "engine",
            "data.win",
            "unityplayer.dll",
            "steam_api64.dll",
            "steam_api.dll",
            "project.godot",
        }:
            return True
        if (directory / "www" / "data").is_dir():
            return True
    except OSError:
        return False
    return False


def resolve_game_root(input_path: Path | str) -> Path:
    """Resolve a user-provided folder or nested executable path to the game's root folder."""
    p = Path(input_path).expanduser().resolve()
    if (p / VAULT_MARKER_FILENAME).exists():
        return p
    if p.is_file():
        start = p.parent
    else:
        start = p

    if not start.exists():
        return start
    if p.is_dir() and start.name.lower() not in _SUBBIN_DIR_NAMES and _has_root_markers(start):
        return start

    best = start
    cur = start
    for step in range(4):
        if cur.parent == cur or cur.name.lower() in _STOP_PARENT_NAMES:
            break
        if step > 0 and _has_root_markers(cur):
            best = cur
            break
        if cur.name.lower() in _SUBBIN_DIR_NAMES or cur.parent.name.lower() in _SUBBIN_DIR_NAMES:
            cand = cur.parent
            if cand.parent != cand and cand.name.lower() not in _STOP_PARENT_NAMES:
                best = cand
        cur = cur.parent
    return best


def _parse_vdf_kv(text: str) -> dict[str, str]:
    """Extract flat key-value pairs from Valve KeyValues (.vdf / .acf) text."""
    pairs: dict[str, str] = {}
    for m in re.finditer(r'"([^"]+)"\s+"([^"]*)"', text):
        pairs[m.group(1).lower()] = m.group(2).replace("\\\\", "\\")
    return pairs


def _get_steam_paths() -> list[Path]:
    candidates: list[Path] = []
    if os.name == "nt":
        try:
            import winreg  # type: ignore

            for root_key, subkey in (
                (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam"),
            ):
                try:
                    with winreg.OpenKey(root_key, subkey) as k:
                        val, _ = winreg.QueryValueEx(k, "SteamPath")
                        if val:
                            candidates.append(Path(val))
                except OSError:
                    pass
        except ImportError:
            pass
        candidates.extend(
            [
                Path(r"C:\Program Files (x86)\Steam"),
                Path(r"C:\Program Files\Steam"),
            ]
        )
    else:
        home = Path.home()
        candidates.extend(
            [
                home / ".local" / "share" / "Steam",
                home / ".steam" / "steam",
                home / "Library" / "Application Support" / "Steam",
            ]
        )
    seen: set[str] = set()
    existing: list[Path] = []
    for c in candidates:
        try:
            rc = c.resolve()
            key = str(rc).lower() if os.name == "nt" else str(rc)
            if key not in seen and rc.is_dir():
                seen.add(key)
                existing.append(rc)
        except OSError:
            pass
    return existing


def parse_steam_library_vdf(vdf_path: Path) -> list[Path]:
    """Parse Steam libraryfolders.vdf and return library root paths."""
    libs: list[Path] = []
    if not vdf_path.is_file():
        return libs
    try:
        text = vdf_path.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r'"path"\s+"([^"]+)"', text, flags=re.IGNORECASE):
            raw = m.group(1).replace("\\\\", "\\")
            p = Path(raw)
            if p.is_dir():
                libs.append(p.resolve())
    except OSError:
        pass
    return libs


def parse_steam_acf(acf_path: Path) -> tuple[str, str, str] | None:
    """Return (appid, name, installdir) from a Steam appmanifest_*.acf file."""
    try:
        kv = _parse_vdf_kv(acf_path.read_text(encoding="utf-8", errors="replace"))
        installdir = kv.get("installdir")
        if not installdir:
            return None
        return (kv.get("appid", ""), kv.get("name", installdir), installdir)
    except OSError:
        return None


def _available_drive_roots() -> list[Path]:
    if os.name == "nt":
        roots: list[Path] = []
        for letter in string.ascii_uppercase:
            p = Path(f"{letter}:\\")
            try:
                if p.exists():
                    roots.append(p)
            except OSError:
                pass
        return roots
    return [Path("/"), Path.home()]


def discover_installed_games(
    extra_roots: Iterable[Path] | None = None,
    data_dir: Path | None = None,
    steam_paths: Iterable[Path] | None = None,
    epic_manifests_dir: Path | None = None,
) -> list[DiscoveredGame]:
    """Discover installed games across Steam, Epic, GOG, Xbox, and common game folders."""
    discovered: list[DiscoveredGame] = []
    seen_paths: set[str] = set()

    def _add(game: DiscoveredGame) -> None:
        try:
            rp = game.root_path.resolve()
        except OSError:
            return
        if not rp.is_dir():
            return
        if (rp / VAULT_MARKER_FILENAME).exists():
            return
        if data_dir is not None and is_vault_or_self_dir(rp, data_dir):
            return
        norm = str(rp).lower() if os.name == "nt" else str(rp)
        if norm in seen_paths:
            return
        seen_paths.add(norm)
        discovered.append(
            DiscoveredGame(
                name=game.name,
                root_path=rp,
                source=game.source,
                app_id=game.app_id,
            )
        )

    # 1. Steam Libraries
    steam_libs: list[Path] = []
    for sp in (steam_paths if steam_paths is not None else _get_steam_paths()):
        steam_libs.append(sp)
        steam_libs.extend(parse_steam_library_vdf(sp / "steamapps" / "libraryfolders.vdf"))

    seen_libs: set[str] = set()
    for lib in steam_libs:
        key = str(lib).lower() if os.name == "nt" else str(lib)
        if key in seen_libs:
            continue
        seen_libs.add(key)
        steamapps = lib / "steamapps"
        if not steamapps.is_dir():
            continue
        # Parse .acf manifests first for clean game names
        for acf in steamapps.glob("appmanifest_*.acf"):
            parsed = parse_steam_acf(acf)
            if not parsed:
                continue
            appid, name, installdir = parsed
            if installdir.lower() in _SKIP_STEAM_DIRS:
                continue
            target = steamapps / "common" / installdir
            if target.is_dir():
                _add(DiscoveredGame(name=name, root_path=target, source="steam", app_id=appid or None))
        # Fallback: direct subdirectories under steamapps/common
        common_dir = steamapps / "common"
        if common_dir.is_dir():
            try:
                for entry in os.scandir(common_dir):
                    if entry.is_dir(follow_symlinks=False):
                        low = entry.name.lower()
                        if low in _SKIP_STEAM_DIRS or low.startswith("proton"):
                            continue
                        _add(DiscoveredGame(name=entry.name, root_path=Path(entry.path), source="steam"))
            except OSError:
                pass

    # 2. Epic Games Manifests
    epic_dir = (
        epic_manifests_dir
        if epic_manifests_dir is not None
        else Path(r"C:\ProgramData\Epic\EpicGamesLauncher\Data\Manifests")
    )
    if epic_dir.is_dir():
        for item_file in epic_dir.glob("*.item"):
            try:
                data = json.loads(item_file.read_text(encoding="utf-8", errors="replace"))
                loc = data.get("InstallLocation")
                disp = data.get("DisplayName") or data.get("AppName")
                if loc and disp and Path(loc).is_dir():
                    _add(
                        DiscoveredGame(
                            name=str(disp),
                            root_path=Path(loc),
                            source="epic",
                            app_id=str(data.get("CatalogItemId") or "") or None,
                        )
                    )
            except Exception:
                pass

    # 3. Common Folders across drives + extra_roots
    common_subfolders = ("Games", "XboxGames", "GOG Games", r"Program Files (x86)\GOG Galaxy\Games")
    scan_containers: list[tuple[Path, str]] = []
    if steam_paths is None and epic_manifests_dir is None:
        for drv in _available_drive_roots():
            for sub in common_subfolders:
                cand = drv / sub
                if cand.is_dir():
                    src = "xbox" if "xbox" in sub.lower() else ("gog" if "gog" in sub.lower() else "local_folder")
                    scan_containers.append((cand, src))
    if extra_roots:
        for er in extra_roots:
            p = Path(er).resolve()
            if p.is_dir():
                if _has_root_markers(p):
                    _add(DiscoveredGame(name=p.name, root_path=p, source="custom"))
                else:
                    scan_containers.append((p, "custom"))

    for container, src in scan_containers:
        try:
            for entry in os.scandir(container):
                if entry.is_dir(follow_symlinks=False):
                    ep = Path(entry.path)
                    if (ep / VAULT_MARKER_FILENAME).exists():
                        continue
                    _add(DiscoveredGame(name=entry.name, root_path=ep, source=src))
        except OSError:
            pass

    discovered.sort(key=lambda g: g.name.lower())
    return discovered
