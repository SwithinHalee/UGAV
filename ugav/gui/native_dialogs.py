"""Native OS dialog dispatchers (PyWebView native dialog + headless noop fallback)."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Protocol


class DialogDispatcher(Protocol):
    def pick_folder(self, title: str = "Select Game Folder") -> Path | None: ...
    def pick_exe(self, title: str = "Select Game Executable") -> Path | None: ...
    def stop(self) -> None: ...


class NoopDialogDispatcher:
    """Headless fallback used in automated tests or environments without display."""

    def __init__(self, fixed_folder: Path | None = None, fixed_exe: Path | None = None) -> None:
        self.fixed_folder = fixed_folder
        self.fixed_exe = fixed_exe
        self._stop_event = threading.Event()

    def pick_folder(self, title: str = "Select Game Folder") -> Path | None:
        return self.fixed_folder

    def pick_exe(self, title: str = "Select Game Executable") -> Path | None:
        return self.fixed_exe

    def run_loop(self, stop_event: threading.Event | None = None) -> None:
        ev = stop_event or self._stop_event
        ev.wait()

    def stop(self) -> None:
        self._stop_event.set()


class PyWebViewDialogDispatcher:
    """Uses the native pywebview application window to open OS Folder/File dialogs."""

    def __init__(self) -> None:
        self.window: Any = None

    def attach_window(self, window: Any) -> None:
        self.window = window

    def pick_folder(self, title: str = "Select Game Folder") -> Path | None:
        if self.window is None:
            return None
        import webview

        res = self.window.create_file_dialog(webview.FileDialog.FOLDER)
        if res and len(res) > 0:
            return Path(res[0])
        return None

    def pick_exe(self, title: str = "Select Game Executable") -> Path | None:
        if self.window is None:
            return None
        import webview

        res = self.window.create_file_dialog(
            webview.FileDialog.OPEN,
            allow_multiple=False,
            file_types=("Game Executables (*.exe;*.bin;*.sh;*.AppImage)", "All Files (*.*)"),
        )
        if res and len(res) > 0:
            return Path(res[0])
        return None

    def stop(self) -> None:
        if self.window is not None:
            try:
                self.window.destroy()
            except Exception:
                pass
