"""External tool bridge (UnityPy, CUE4Parse/repak, vgmstream, ffmpeg) & orphan staging reaper."""

from __future__ import annotations

import importlib
import shutil
import subprocess
import sys
import uuid
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

TOOL_CATALOG: dict[str, dict[str, str | None]] = {
    "UnityPy": {
        "kind": "python_module",
        "description": "Ekstrak aset Unity Engine (.assets, AssetBundle, Texture2D, AudioClip).",
        "install_command": "python -m pip install UnityPy",
        "homepage_url": "https://github.com/K0lb3/UnityPy",
    },
    "ffmpeg": {
        "kind": "cli",
        "description": "Konversi & demux audio/video umum (.usm, .bik, .ogv, .wav, .mp4).",
        "install_command": "winget install -e --id Gyan.FFmpeg",
        "homepage_url": "https://ffmpeg.org/download.html",
    },
    "vgmstream-cli": {
        "kind": "cli",
        "description": "Dekode audio game Wwise (.wem/.bnk), FMOD (.fsb), & CRIWARE (.awb/.hca).",
        "install_command": None,
        "homepage_url": "https://github.com/vgmstream/vgmstream/releases",
    },
    "repak": {
        "kind": "cli",
        "description": "Unpacker cepat untuk arsip Unreal Engine (.pak).",
        "install_command": "cargo install repak_cli",
        "homepage_url": "https://github.com/trumank/repak/releases",
    },
    "CUE4Parse": {
        "kind": "cli",
        "description": "Parser aset Unreal Engine 4/5 (.pak, .utoc, .ucas, .uasset).",
        "install_command": None,
        "homepage_url": "https://github.com/FabianFG/CUE4Parse",
    },
    "quickbms": {
        "kind": "cli",
        "description": "Ekstraktor arsip universal berbasis script .bms untuk format custom.",
        "install_command": None,
        "homepage_url": "https://aluigi.altervista.org/quickbms.htm",
    },
}


@dataclass
class ExternalToolStatus:
    name: str
    available: bool
    kind: str  # 'python_module' | 'cli'
    location: str | None = None
    description: str = ""
    install_command: str | None = None
    homepage_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "available": self.available,
            "kind": self.kind,
            "location": self.location,
            "description": self.description,
            "install_command": self.install_command,
            "homepage_url": self.homepage_url,
        }


def reap_orphan_staging_dirs(data_dir: Path) -> int:
    """Delete leftover staging directories whose owning PID is no longer alive."""
    staging_root = Path(data_dir) / "staging"
    if not staging_root.is_dir():
        return 0
    removed = 0
    for child in list(staging_root.iterdir()):
        if not child.is_dir():
            continue
        pid_str = child.name.split("_", 1)[0]
        try:
            pid = int(pid_str)
            alive = psutil.pid_exists(pid)
        except ValueError:
            alive = False
        if not alive:
            shutil.rmtree(child, ignore_errors=True)
            removed += 1
    return removed


class ExternalBridgeManager:
    """Discovers, installs, and invokes optional external extractors in isolated staging directories."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.staging_root = self.data_dir / "staging"
        self.staging_root.mkdir(parents=True, exist_ok=True)

    def probe_tools(self) -> list[ExternalToolStatus]:
        statuses: list[ExternalToolStatus] = []
        for name, meta in TOOL_CATALOG.items():
            kind = str(meta["kind"])
            desc = str(meta.get("description") or "")
            cmd = meta.get("install_command")
            url = str(meta.get("homepage_url") or "")
            if kind == "python_module":
                try:
                    mod = importlib.import_module(name)
                    statuses.append(
                        ExternalToolStatus(
                            name=name,
                            available=True,
                            kind=kind,
                            location=getattr(mod, "__file__", None),
                            description=desc,
                            install_command=cmd,
                            homepage_url=url,
                        )
                    )
                except Exception:
                    statuses.append(
                        ExternalToolStatus(
                            name=name,
                            available=False,
                            kind=kind,
                            description=desc,
                            install_command=cmd,
                            homepage_url=url,
                        )
                    )
            else:
                found = shutil.which(name)
                statuses.append(
                    ExternalToolStatus(
                        name=name,
                        available=found is not None,
                        kind=kind,
                        location=found,
                        description=desc,
                        install_command=cmd,
                        homepage_url=url,
                    )
                )
        return statuses

    def install_tool(self, tool_name: str, open_url: bool = True) -> dict[str, Any]:
        """Install a known allowlisted external tool or open its official download page."""
        if tool_name not in TOOL_CATALOG:
            raise KeyError(f"Unknown tool: {tool_name}")

        meta = TOOL_CATALOG[tool_name]
        url = str(meta.get("homepage_url") or "")
        cmd_list: list[str] | None = None

        if tool_name == "UnityPy":
            py_exe = None if getattr(sys, "frozen", False) else sys.executable
            if not py_exe:
                py_exe = shutil.which("python") or shutil.which("python3")
            if py_exe:
                cmd_list = [py_exe, "-m", "pip", "install", "UnityPy"]
        elif tool_name == "ffmpeg":
            winget = shutil.which("winget")
            if winget:
                cmd_list = [
                    winget,
                    "install",
                    "-e",
                    "--id",
                    "Gyan.FFmpeg",
                    "--accept-source-agreements",
                    "--accept-package-agreements",
                ]
        elif tool_name == "repak":
            cargo = shutil.which("cargo")
            if cargo:
                cmd_list = [cargo, "install", "repak_cli"]

        if cmd_list is not None:
            try:
                proc = subprocess.run(
                    cmd_list,
                    capture_output=True,
                    text=True,
                    timeout=240,
                    check=False,
                )
                if proc.returncode == 0:
                    note = f"{tool_name} berhasil diinstall."
                    if tool_name == "UnityPy" and getattr(sys, "frozen", False):
                        note += " (Terpasang di Python sistem; restart/CLI Python diperlukan untuk memuat modul)."
                    return {"status": "installed", "tool": tool_name, "message": note}
                err_tail = (proc.stderr or proc.stdout or "").strip()[-300:]
                return {
                    "status": "error",
                    "tool": tool_name,
                    "url": url,
                    "message": f"Install gagal (exit {proc.returncode}): {err_tail}",
                }
            except Exception as exc:
                return {"status": "error", "tool": tool_name, "url": url, "message": str(exc)}

        if open_url and url:
            webbrowser.open(url)
        return {
            "status": "opened_url",
            "tool": tool_name,
            "url": url,
            "message": f"Halaman download resmi {tool_name} dibuka di browser ({url}). Setelah download, letakkan binary di folder PATH.",
        }

    def create_staging_dir(self) -> Path:
        import os

        stage = self.staging_root / f"{os.getpid()}_{uuid.uuid4().hex[:8]}"
        stage.mkdir(parents=True, exist_ok=True)
        return stage

    def run_cli_extractor(
        self,
        cmd: list[str],
        timeout_sec: int = 300,
    ) -> tuple[int, str, str]:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
