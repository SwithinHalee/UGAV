"""Native Desktop GUI launcher using pywebview (Win32/WebView2 app frame), --noconsole logging fix, and pre-bound socket."""

from __future__ import annotations

import json
import logging
import os
import secrets
import socket
import sys
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

import psutil
import uvicorn

from ugav.adapters.external_bridge import reap_orphan_staging_dirs
from ugav.gui.native_dialogs import PyWebViewDialogDispatcher
from ugav.gui.server import create_app
from ugav.paths import get_portable_data_dir


class _NullSafeWriter:
    """Fallback text stream for PyInstaller --noconsole when stdout/stderr are None."""

    def __init__(self, logger: logging.Logger, level: int) -> None:
        self._logger = logger
        self._level = level

    def write(self, msg: str) -> int:
        clean = msg.rstrip()
        if clean:
            self._logger.log(self._level, clean)
        return len(msg)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


def ensure_stdio_for_noconsole(log_dir: Path) -> logging.Logger:
    """Redirect None stdout/stderr to rotating file log to prevent uvicorn/click crashes."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "ugav.log"
    logger = logging.getLogger("ugav")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(handler)
    if sys.stdout is None:
        sys.stdout = _NullSafeWriter(logger, logging.INFO)  # type: ignore[assignment]
    if sys.stderr is None:
        sys.stderr = _NullSafeWriter(logger, logging.ERROR)  # type: ignore[assignment]
    return logger


def _is_port_listening(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.4):
            return True
    except OSError:
        return False


def check_existing_instance(data_dir: Path) -> str | None:
    """Return running instance URL if another UGAV GUI process already owns this data_dir."""
    runtime_file = data_dir / "ugav.runtime.json"
    if not runtime_file.is_file():
        return None
    try:
        info = json.loads(runtime_file.read_text(encoding="utf-8"))
        pid = int(info["pid"])
        port = int(info["port"])
        token = str(info.get("token", ""))
        if pid != os.getpid() and psutil.pid_exists(pid) and _is_port_listening("127.0.0.1", port):
            return f"http://127.0.0.1:{port}/?token={token}"
    except Exception:
        pass
    return None


def launch_gui(data_dir_override: str | None = None, open_browser: bool = True) -> None:
    """Start local FastAPI server on pre-bound port and open native pywebview desktop window."""
    data_dir = get_portable_data_dir(data_dir_override)
    logger = ensure_stdio_for_noconsole(data_dir / "logs")
    reap_orphan_staging_dirs(data_dir)

    existing_url = check_existing_instance(data_dir)
    if existing_url:
        logger.info("UGAV already running at %s", existing_url)
        return

    token = secrets.token_urlsafe(24)
    shutdown_event = threading.Event()
    dispatcher = PyWebViewDialogDispatcher()
    app = create_app(
        data_dir=data_dir,
        session_token=token,
        dialog_dispatcher=dispatcher,
        shutdown_event=shutdown_event,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    port = sock.getsockname()[1]

    runtime_file = data_dir / "ugav.runtime.json"
    runtime_file.write_text(
        json.dumps({"pid": os.getpid(), "port": port, "token": token}),
        encoding="utf-8",
    )

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_config=None, access_log=False)
    server = uvicorn.Server(config)

    def _serve() -> None:
        try:
            server.run(sockets=[sock])
        except Exception as exc:
            logger.exception("Server exited unexpectedly: %s", exc)
        finally:
            shutdown_event.set()
            dispatcher.stop()

    srv_thread = threading.Thread(target=_serve, name="ugav-uvicorn", daemon=True)
    srv_thread.start()

    url = f"http://127.0.0.1:{port}/?token={token}"
    logger.info("UGAV native desktop window starting at %s", url)

    try:
        if open_browser:
            import webview

            window = webview.create_window(
                "UGAV — Universal Game Asset Vault & Translator",
                url=url,
                width=1280,
                height=840,
                min_size=(960, 640),
                background_color="#0f1218",
            )
            dispatcher.attach_window(window)
            storage_dir = data_dir / "webview_storage"
            storage_dir.mkdir(parents=True, exist_ok=True)
            webview.start(private_mode=False, storage_path=str(storage_dir))
        else:
            shutdown_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        shutdown_event.set()
        server.should_exit = True
        try:
            app.state.repo.close()
        except Exception:
            pass
        try:
            runtime_file.unlink(missing_ok=True)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
