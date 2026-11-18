"""Unified entrypoint: double-click EXE launches GUI; CLI arguments route to Click CLI."""

from __future__ import annotations

import os
import sys


def _attach_parent_console_if_needed() -> None:
    """When a Windows GUI-subsystem EXE is invoked with CLI args, attach to parent console."""
    if os.name != "nt":
        return
    if sys.stdout is not None and sys.stderr is not None:
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        if kernel32.AttachConsole(-1):
            if sys.stdout is None:
                sys.stdout = open("CONOUT$", "w", encoding="utf-8", buffering=1)
            if sys.stderr is None:
                sys.stderr = open("CONOUT$", "w", encoding="utf-8", buffering=1)
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args:
        from ugav.gui.launcher import launch_gui

        launch_gui()
        return 0

    _attach_parent_console_if_needed()
    from ugav.cli import cli

    cli.main(args=args, prog_name="ugav", standalone_mode=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
