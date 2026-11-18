"""Sanitized diagnostic report generator for troubleshooting across devices."""

from __future__ import annotations

import getpass
import json
import platform
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ugav import __version__
from ugav.adapters.external_bridge import ExternalBridgeManager
from ugav.db.repository import DatabaseRepository


def _redact_path(text: str) -> str:
    try:
        user = getpass.getuser()
    except Exception:
        user = ""
    home = str(Path.home())
    out = text.replace(home, "<HOME>")
    if user:
        out = out.replace(f"\\{user}\\", "\\<USER>\\").replace(f"/{user}/", "/<USER>/")
    return out


def build_diagnostic_report(repo: DatabaseRepository, data_dir: Path) -> dict[str, Any]:
    """Build a JSON-serializable, username-redacted diagnostic snapshot."""
    bridge = ExternalBridgeManager(data_dir)
    stats = repo.get_stats()
    warnings = repo.get_warnings(limit=200)
    redacted_warnings = [
        {**w, "path": _redact_path(str(w.get("path", ""))), "message": _redact_path(str(w.get("message", "")))}
        for w in warnings
    ]
    games_safe = [
        {
            "slug": g["slug"],
            "name": g["name"],
            "root_path": _redact_path(str(g["root_path"])),
            "detected_engine": g["detected_engine"],
            "middleware": g.get("middleware", []),
            "cpu_arch": g.get("cpu_arch"),
            "asset_count": g.get("asset_count", 0),
            "entity_count": g.get("entity_count", 0),
        }
        for g in (stats.get("games") or [])
        if g
    ]
    log_tail: list[str] = []
    log_file = data_dir / "logs" / "ugav.log"
    if log_file.is_file():
        try:
            lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
            log_tail = [_redact_path(line) for line in lines[-200:]]
        except OSError:
            pass

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ugav_version": __version__,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "external_tools": [t.to_dict() for t in bridge.probe_tools()],
        "games": games_safe,
        "summary": {
            "unique_blobs": stats.get("unique_blobs", 0),
            "warnings_total": stats.get("warnings", 0),
            "assets_by_category": stats.get("assets_by_category", {}),
            "entities_by_type": stats.get("entities_by_type", {}),
        },
        "recent_warnings": redacted_warnings,
        "log_tail": log_tail,
    }


def export_diagnostic_zip(repo: DatabaseRepository, data_dir: Path, out_zip: Path) -> Path:
    report = build_diagnostic_report(repo, data_dir)
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("diagnostic_report.json", json.dumps(report, indent=2))
    return out_zip
