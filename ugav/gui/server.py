"""FastAPI local desktop backend & API-ready preview server with SSE live scan progress."""

from __future__ import annotations

import asyncio
import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ugav import __version__
from ugav.adapters.external_bridge import ExternalBridgeManager
from ugav.config import AppSettings, ScanConfig, VALID_COPY_MODES, load_keyring, save_keyring
from ugav.db.repository import DatabaseRepository
from ugav.detectors.engine_fingerprint import fingerprint_game_directory
from ugav.diagnostics import build_diagnostic_report
from ugav.discovery import discover_installed_games, resolve_game_root
from ugav.gui.native_dialogs import DialogDispatcher, NoopDialogDispatcher
from ugav.paths import SelfScanError, get_package_dir, validate_scan_target
from ugav.pipeline import ScanPipeline, ScanProgress, ScanSummary
from ugav.translators.generic_structured import decode_text_bytes
from ugav.vault.storage import VaultStorage


class InspectRequest(BaseModel):
    path: str


class ScanStartRequest(BaseModel):
    path: str
    copy_mode: str = "vault_extracted"
    convert_textures: bool = True
    carve_unknown: bool = False
    max_file_mb: float | None = 500.0
    min_free_gb: float = 2.0
    include_categories: list[str] | None = None
    exclude_extensions: list[str] = []
    force_online_stub: bool = False
    output_vault_dir: str | None = None


class OpenPathRequest(BaseModel):
    path: str


class ExportRequest(BaseModel):
    out_dir: str
    prefer_preview: bool = True
    include_categories: list[str] | None = None


class RelocateRequest(BaseModel):
    new_root_path: str


class MergeRequest(BaseModel):
    other_data_dir: str


class SettingsUpdateRequest(BaseModel):
    custom_vault_dir: str | None = None
    default_copy_mode: str = "vault_extracted"
    convert_textures: bool = True
    min_free_gb: float = 2.0
    max_file_mb: float | None = 500.0
    extra_scan_roots: list[str] = []


class KeyringUpdateRequest(BaseModel):
    keys: dict[str, str]


class ScanManager:
    """Manages one background scan worker at a time and broadcasts SSE progress updates."""

    def __init__(self, repo: DatabaseRepository, vault: VaultStorage, data_dir: Path) -> None:
        self.repo = repo
        self.vault = vault
        self.data_dir = data_dir
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._cancel_event = threading.Event()
        self._listeners: list[queue.Queue[dict[str, Any]]] = []
        self.is_running: bool = False
        self.last_progress: dict[str, Any] = ScanProgress(phase="idle").to_dict()
        self.last_summary: dict[str, Any] | None = None
        self.last_error: str | None = None

    def subscribe(self) -> queue.Queue[dict[str, Any]]:
        q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=200)
        with self._lock:
            self._listeners.append(q)
        return q

    def unsubscribe(self, q: queue.Queue[dict[str, Any]]) -> None:
        with self._lock:
            if q in self._listeners:
                self._listeners.remove(q)

    def _broadcast(self, event_type: str, payload: dict[str, Any]) -> None:
        msg = {"event": event_type, "data": payload}
        with self._lock:
            for q in list(self._listeners):
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    pass

    def start_scan(self, req: ScanStartRequest) -> dict[str, Any]:
        if req.copy_mode not in VALID_COPY_MODES:
            raise HTTPException(status_code=400, detail=f"Invalid copy_mode: {req.copy_mode}")
        with self._lock:
            if self.is_running:
                raise HTTPException(status_code=409, detail="A scan is already running.")
            self.is_running = True
            self._cancel_event.clear()
            self.last_error = None
            self.last_summary = None
            self.last_progress = ScanProgress(phase="starting").to_dict()

        def _worker() -> None:
            try:
                cfg = ScanConfig(
                    copy_mode=req.copy_mode,  # type: ignore[arg-type]
                    convert_textures=req.convert_textures,
                    carve_unknown=req.carve_unknown,
                    min_free_gb=req.min_free_gb,
                    max_file_mb=req.max_file_mb,
                    include_categories=req.include_categories,
                    exclude_extensions=req.exclude_extensions,
                    keys=load_keyring(self.data_dir),
                    force_online_stub=req.force_online_stub,
                    output_vault_dir=req.output_vault_dir.strip() if req.output_vault_dir else None,
                )
                self.vault.min_free_gb = req.min_free_gb
                pipeline = ScanPipeline(self.repo, self.vault, self.data_dir, cfg)

                def _on_prog(p: ScanProgress) -> None:
                    pd = p.to_dict()
                    self.last_progress = pd
                    self._broadcast("progress", pd)

                summary: ScanSummary = pipeline.scan_game(
                    req.path,
                    progress_callback=_on_prog,
                    cancel_event=self._cancel_event,
                )
                sd = summary.to_dict()
                self.last_summary = sd
                self._broadcast("completed", sd)
            except Exception as exc:
                self.last_error = str(exc)
                self._broadcast("error", {"message": str(exc)})
            finally:
                with self._lock:
                    self.is_running = False

        self._thread = threading.Thread(target=_worker, name="ugav-scan-worker", daemon=True)
        self._thread.start()
        return {"started": True, "path": req.path, "copy_mode": req.copy_mode}

    def cancel_scan(self) -> dict[str, Any]:
        with self._lock:
            if not self.is_running:
                return {"cancelled": False, "reason": "No active scan."}
            self._cancel_event.set()
            return {"cancelled": True}


def create_app(
    data_dir: Path,
    session_token: str = "",
    dialog_dispatcher: DialogDispatcher | None = None,
    shutdown_event: threading.Event | None = None,
) -> FastAPI:
    """Create configured FastAPI app for UGAV Desktop GUI & API preview."""
    settings = AppSettings.load(data_dir)
    vault_dir = Path(settings.custom_vault_dir) if settings.custom_vault_dir else (data_dir / "vault")
    repo = DatabaseRepository(data_dir / "ugav.sqlite")
    vault = VaultStorage(vault_dir, min_free_gb=settings.min_free_gb)
    dispatcher = dialog_dispatcher or NoopDialogDispatcher()
    scan_mgr = ScanManager(repo, vault, data_dir)
    stop_ev = shutdown_event or threading.Event()

    app = FastAPI(title="Universal Game Asset Vault & Translator (UGAV)", version=__version__)
    app.state.repo = repo
    app.state.vault = vault
    app.state.data_dir = data_dir
    app.state.session_token = session_token
    app.state.dialog_dispatcher = dispatcher
    app.state.scan_manager = scan_mgr
    app.state.shutdown_event = stop_ev
    app.state.last_heartbeat = time.monotonic()

    static_dir = get_package_dir() / "gui" / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    def _verify_token(
        x_ugav_token: str | None = Header(default=None, alias="X-UGAV-Token"),
        token: str | None = Query(default=None),
    ) -> None:
        if not app.state.session_token:
            return
        supplied = x_ugav_token or token or ""
        if supplied != app.state.session_token:
            raise HTTPException(status_code=403, detail="Invalid or missing X-UGAV-Token.")

    @app.get("/", response_class=HTMLResponse)
    def serve_index() -> HTMLResponse:
        idx = static_dir / "index.html"
        if not idx.is_file():
            return HTMLResponse("<h1>UGAV Backend Running</h1>")
        return HTMLResponse(idx.read_text(encoding="utf-8"))

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        app.state.last_heartbeat = time.monotonic()
        return {
            "status": "ok",
            "version": __version__,
            "scan_active": scan_mgr.is_running,
            "free_gb": round(vault.free_bytes() / (1024**3), 2),
            "data_dir": str(data_dir),
            "vault_dir": str(vault.vault_dir),
        }

    @app.post("/api/system/heartbeat")
    def heartbeat() -> dict[str, Any]:
        app.state.last_heartbeat = time.monotonic()
        return {"ok": True, "scan_active": scan_mgr.is_running}

    @app.post("/api/system/closing")
    def window_closing() -> dict[str, Any]:
        # Never terminate server during an active scan or right after an F5 reload
        if not scan_mgr.is_running and session_token:
            close_ts = time.monotonic()

            def _delayed_stop() -> None:
                time.sleep(2.5)
                if not scan_mgr.is_running and app.state.last_heartbeat < close_ts:
                    stop_ev.set()
                    dispatcher.stop()

            threading.Thread(target=_delayed_stop, daemon=True).start()
            return {"shutting_down": True}
        return {"shutting_down": False, "scan_active": scan_mgr.is_running}

    @app.post("/api/system/shutdown", dependencies=[Depends(_verify_token)])
    def shutdown() -> dict[str, Any]:
        if scan_mgr.is_running:
            scan_mgr.cancel_scan()
        stop_ev.set()
        dispatcher.stop()
        return {"shutting_down": True}

    @app.post("/api/system/pick-folder", dependencies=[Depends(_verify_token)])
    def pick_folder() -> dict[str, Any]:
        chosen = dispatcher.pick_folder("Pilih Folder Game")
        if chosen is None:
            return {"cancelled": True, "path": None, "resolved_root": None}
        resolved = resolve_game_root(chosen)
        return {"cancelled": False, "path": str(chosen), "resolved_root": str(resolved)}

    @app.post("/api/system/pick-exe", dependencies=[Depends(_verify_token)])
    def pick_exe() -> dict[str, Any]:
        chosen = dispatcher.pick_exe("Pilih File .exe Game")
        if chosen is None:
            return {"cancelled": True, "selected_file": None, "resolved_root": None}
        resolved = resolve_game_root(chosen)
        return {"cancelled": False, "selected_file": str(chosen), "resolved_root": str(resolved)}

    @app.post("/api/system/open-path", dependencies=[Depends(_verify_token)])
    def open_path(req: OpenPathRequest) -> dict[str, Any]:
        target = Path(req.path).expanduser().resolve()
        if not target.exists():
            raise HTTPException(status_code=404, detail=f"Path does not exist: {target}")
        if os.name == "nt":
            os.startfile(str(target))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(target)])
        else:
            subprocess.Popen(["xdg-open", str(target)])
        return {"opened": str(target)}

    @app.get("/api/discover")
    def api_discover(extra_roots: str | None = Query(default=None)) -> dict[str, Any]:
        cur_settings = AppSettings.load(data_dir)
        roots: list[Path] = [Path(r) for r in cur_settings.extra_scan_roots if r.strip()]
        if extra_roots:
            roots.extend(Path(r.strip()) for r in extra_roots.split(";") if r.strip())
        found = discover_installed_games(extra_roots=roots or None, data_dir=data_dir)
        indexed = {Path(g["root_path"]).resolve(): g for g in repo.list_games()}
        items: list[dict[str, Any]] = []
        for dg in found:
            d = dg.to_dict()
            existing = indexed.get(dg.root_path.resolve())
            d["indexed_game"] = existing
            items.append(d)
        return {"count": len(items), "games": items}

    @app.post("/api/inspect")
    def api_inspect(req: InspectRequest) -> dict[str, Any]:
        raw_p = Path(req.path).expanduser()
        if not raw_p.exists():
            raise HTTPException(status_code=404, detail=f"Path does not exist: {req.path}")
        root = resolve_game_root(raw_p)
        try:
            validate_scan_target(root, data_dir, vault.vault_dir)
        except SelfScanError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        fp = fingerprint_game_directory(root)
        from ugav.db.repository import slugify

        return {
            "name": fp.name,
            "input_path": str(raw_p),
            "root_path": str(fp.root_path),
            "default_vault_dir": str((vault.vault_dir / slugify(fp.name)).resolve()),
            "detected_engine": fp.detected_engine,
            "middleware": fp.middleware,
            "cpu_arch": fp.cpu_arch,
            "source_platform": fp.source_platform,
            "confidence": fp.confidence,
            "is_online_stub": fp.is_online_stub,
            "total_files": fp.total_files,
            "total_bytes": fp.total_bytes,
            "total_gb": round(fp.total_bytes / (1024**3), 3),
            "free_gb": round(vault.free_bytes() / (1024**3), 2),
            "details": fp.details,
        }

    @app.post("/api/scan/start", dependencies=[Depends(_verify_token)])
    def api_scan_start(req: ScanStartRequest) -> dict[str, Any]:
        return scan_mgr.start_scan(req)

    @app.post("/api/scan/cancel", dependencies=[Depends(_verify_token)])
    def api_scan_cancel() -> dict[str, Any]:
        return scan_mgr.cancel_scan()

    @app.get("/api/scan/status")
    def api_scan_status() -> dict[str, Any]:
        return {
            "is_running": scan_mgr.is_running,
            "progress": scan_mgr.last_progress,
            "summary": scan_mgr.last_summary,
            "error": scan_mgr.last_error,
        }

    @app.get("/api/scan/events")
    async def api_scan_events(request: Request) -> StreamingResponse:
        q = scan_mgr.subscribe()

        async def _gen():
            try:
                yield f"event: status\ndata: {json.dumps({'is_running': scan_mgr.is_running, 'progress': scan_mgr.last_progress})}\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        msg = q.get_nowait()
                        yield f"event: {msg['event']}\ndata: {json.dumps(msg['data'])}\n\n"
                    except queue.Empty:
                        await asyncio.sleep(0.25)
                        yield ": keepalive\n\n"
            finally:
                scan_mgr.unsubscribe(q)

        return StreamingResponse(_gen(), media_type="text/event-stream")

    @app.get("/api/games")
    def api_list_games() -> dict[str, Any]:
        return {"games": repo.list_games()}

    @app.get("/api/stats")
    def api_stats(game: str | None = Query(default=None)) -> dict[str, Any]:
        return repo.get_stats(game)

    @app.get("/api/games/{slug}/assets")
    def api_game_assets(
        slug: str,
        category: str | None = Query(default=None),
        encryption_flag: str | None = Query(default=None),
        search: str | None = Query(default=None),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, Any]:
        g = repo.get_game_by_slug(slug)
        if not g:
            raise HTTPException(status_code=404, detail=f"Game not found: {slug}")
        return repo.query_assets_paginated(
            int(g["id"]),
            category=category or None,
            encryption_flag=encryption_flag or None,
            search=search or None,
            page=page,
            page_size=page_size,
        )

    @app.get("/api/games/{slug}/entities")
    def api_game_entities(
        slug: str,
        entity_type: str | None = Query(default=None),
        search: str | None = Query(default=None),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, Any]:
        g = repo.get_game_by_slug(slug)
        if not g:
            raise HTTPException(status_code=404, detail=f"Game not found: {slug}")
        return repo.query_entities_paginated(
            int(g["id"]),
            entity_type=entity_type or None,
            search=search or None,
            page=page,
            page_size=page_size,
        )

    @app.get("/api/entities/{entity_id}")
    def api_entity_detail(entity_id: int) -> dict[str, Any]:
        detail = repo.get_entity_detail(entity_id)
        if not detail:
            raise HTTPException(status_code=404, detail="Entity not found")
        return detail

    @app.get("/api/search")
    def api_search(
        q: str = Query(..., min_length=1),
        game: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, Any]:
        hits = repo.search_entities_fts(q, game_slug=game or None, limit=limit)
        return {"query": q, "count": len(hits), "results": hits}

    @app.get("/api/warnings")
    def api_warnings(game: str | None = Query(default=None), limit: int = Query(default=200)) -> dict[str, Any]:
        gid = None
        if game:
            g = repo.get_game_by_slug(game)
            gid = int(g["id"]) if g else -1
        return {"warnings": repo.get_warnings(game_id=gid, limit=limit)}

    @app.get("/api/blobs/{sha256}/preview")
    def api_blob_preview(sha256: str) -> FileResponse:
        blob = repo.get_blob(sha256)
        if not blob:
            raise HTTPException(status_code=404, detail="Blob not found")
        rel = blob.get("preview_rel_path") or (
            blob.get("vault_rel_path") if blob.get("detected_format") in ("png", "jpeg", "webp", "bmp", "ico") else None
        )
        if not rel:
            raise HTTPException(status_code=404, detail="No visual preview available for this blob.")
        fp = vault.resolve_vault_path(rel)
        if not fp.is_file():
            raise HTTPException(status_code=404, detail="Preview file missing on disk.")
        return FileResponse(fp)

    @app.get("/api/blobs/{sha256}/raw")
    def api_blob_raw(sha256: str) -> FileResponse:
        blob = repo.get_blob(sha256)
        if not blob or not blob.get("vault_rel_path"):
            raise HTTPException(status_code=404, detail="Raw vaulted blob not stored (index_only or filtered).")
        fp = vault.resolve_vault_path(blob["vault_rel_path"])
        if not fp.is_file():
            raise HTTPException(status_code=404, detail="Blob file missing on disk.")
        return FileResponse(fp, media_type=blob.get("detected_mime") or "application/octet-stream")

    @app.get("/api/blobs/{sha256}/text")
    def api_blob_text(sha256: str) -> Response:
        blob = repo.get_blob(sha256)
        if not blob or not blob.get("vault_rel_path"):
            raise HTTPException(status_code=404, detail="Text blob not stored in Vault.")
        fp = vault.resolve_vault_path(blob["vault_rel_path"])
        if not fp.is_file():
            raise HTTPException(status_code=404, detail="Blob file missing on disk.")
        with fp.open("rb") as f:
            raw = f.read(512 * 1024)
        txt, enc = decode_text_bytes(raw)
        return JSONResponse({"sha256": sha256, "encoding": enc, "truncated": fp.stat().st_size > 512 * 1024, "text": txt})

    @app.post("/api/games/{slug}/export", dependencies=[Depends(_verify_token)])
    def api_export_game(slug: str, req: ExportRequest) -> dict[str, Any]:
        g = repo.get_game_by_slug(slug)
        if not g:
            raise HTTPException(status_code=404, detail=f"Game not found: {slug}")
        allowed = set(req.include_categories) if req.include_categories else None
        all_assets = []
        page = 1
        while True:
            res = repo.query_assets_paginated(int(g["id"]), page=page, page_size=200)
            for item in res["items"]:
                if allowed is None or item.get("asset_category") in allowed:
                    all_assets.append(item)
            if page * 200 >= res["total"]:
                break
            page += 1
        return vault.export_assets_tree(all_assets, Path(req.out_dir), prefer_preview=req.prefer_preview)

    @app.post("/api/games/{slug}/relocate", dependencies=[Depends(_verify_token)])
    def api_relocate_game(slug: str, req: RelocateRequest) -> dict[str, Any]:
        try:
            return repo.relocate_game(slug, Path(req.new_root_path))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/vault/merge", dependencies=[Depends(_verify_token)])
    def api_merge_vault(req: MergeRequest) -> dict[str, Any]:
        other = Path(req.other_data_dir).resolve()
        other_db = other / "ugav.sqlite"
        if not other_db.is_file():
            raise HTTPException(status_code=404, detail=f"Database not found: {other_db}")
        return repo.merge_from_other_db(other_db, other / "vault", vault.vault_dir)

    @app.get("/api/tools")
    def api_tools() -> dict[str, Any]:
        tools = ExternalBridgeManager(data_dir).probe_tools()
        return {"tools": [t.to_dict() for t in tools]}

    @app.post("/api/tools/{tool_name}/install", dependencies=[Depends(_verify_token)])
    def api_install_tool(tool_name: str) -> dict[str, Any]:
        try:
            return ExternalBridgeManager(data_dir).install_tool(tool_name)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/settings")
    def api_get_settings() -> dict[str, Any]:
        s = AppSettings.load(data_dir)
        return {
            "custom_vault_dir": s.custom_vault_dir,
            "default_copy_mode": s.default_copy_mode,
            "convert_textures": s.convert_textures,
            "min_free_gb": s.min_free_gb,
            "max_file_mb": s.max_file_mb,
            "extra_scan_roots": s.extra_scan_roots,
            "workers": s.workers,
        }

    @app.post("/api/settings", dependencies=[Depends(_verify_token)])
    def api_save_settings(req: SettingsUpdateRequest) -> dict[str, Any]:
        s = AppSettings(
            custom_vault_dir=req.custom_vault_dir,
            default_copy_mode=req.default_copy_mode if req.default_copy_mode in VALID_COPY_MODES else "vault_extracted",  # type: ignore[arg-type]
            convert_textures=req.convert_textures,
            min_free_gb=req.min_free_gb,
            max_file_mb=req.max_file_mb,
            extra_scan_roots=req.extra_scan_roots,
        )
        s.save(data_dir)
        vault.min_free_gb = s.min_free_gb
        return {"saved": True}

    @app.get("/api/keyring", dependencies=[Depends(_verify_token)])
    def api_get_keyring() -> dict[str, Any]:
        return {"keys": load_keyring(data_dir)}

    @app.post("/api/keyring", dependencies=[Depends(_verify_token)])
    def api_save_keyring(req: KeyringUpdateRequest) -> dict[str, Any]:
        save_keyring(data_dir, req.keys)
        return {"saved": True, "count": len(req.keys)}

    @app.get("/api/diagnostics")
    def api_diagnostics() -> dict[str, Any]:
        return build_diagnostic_report(repo, data_dir)

    return app
