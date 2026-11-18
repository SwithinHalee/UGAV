"""Tests for FastAPI desktop GUI server endpoints, token enforcement, and SSE scan."""

from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from tests.conftest import make_png_bytes
from ugav.gui.native_dialogs import NoopDialogDispatcher
from ugav.gui.server import create_app


def test_gui_server_endpoints_and_token_security(tmp_path: Path) -> None:
    game = tmp_path / "SampleGame"
    (game / "sub").mkdir(parents=True)
    (game / "data.win").write_bytes(b"")  # marker
    (game / "logo.png").write_bytes(make_png_bytes(12, 12))
    (game / "lang_en.json").write_text('{"hero_name": "Kris", "town": "Hometown"}', encoding="utf-8")
    exe = game / "sub" / "Sample.exe"
    exe.write_bytes(b"MZ")

    data_dir = tmp_path / "ugav_data"
    dispatcher = NoopDialogDispatcher(fixed_folder=game, fixed_exe=exe)
    app = create_app(data_dir=data_dir, session_token="secret-tok", dialog_dispatcher=dispatcher)

    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200
        assert client.get("/").status_code == 200

        # Token security enforcement
        assert client.post("/api/system/pick-folder").status_code == 403
        ok_pick = client.post("/api/system/pick-exe", headers={"X-UGAV-Token": "secret-tok"})
        assert ok_pick.status_code == 200
        assert Path(ok_pick.json()["resolved_root"]) == game.resolve()

        # Inspect
        insp = client.post("/api/inspect", json={"path": str(game)})
        assert insp.status_code == 200
        assert insp.json()["total_files"] >= 3

        # Start scan
        st = client.post(
            "/api/scan/start",
            headers={"X-UGAV-Token": "secret-tok"},
            json={"path": str(game), "copy_mode": "vault_extracted", "min_free_gb": 0.0},
        )
        assert st.status_code == 200

        # Wait up to 5s for background worker
        for _ in range(50):
            status = client.get("/api/scan/status").json()
            if not status["is_running"] and status["summary"] is not None:
                break
            time.sleep(0.1)
        assert status["summary"]["status"] == "completed"

        games = client.get("/api/games").json()["games"]
        assert len(games) == 1
        slug = games[0]["slug"]

        assets = client.get(f"/api/games/{slug}/assets").json()
        png_asset = [a for a in assets["items"] if a["extension"] == ".png"][0]
        prev = client.get(f"/api/blobs/{png_asset['blob_sha256']}/preview")
        assert prev.status_code == 200
        assert prev.content.startswith(b"\x89PNG")

        # External tools list & install endpoint security
        tools_res = client.get("/api/tools")
        assert tools_res.status_code == 200
        tool_names = {t["name"] for t in tools_res.json()["tools"]}
        assert {"UnityPy", "ffmpeg", "vgmstream-cli", "repak", "CUE4Parse", "quickbms"} <= tool_names

        assert client.post("/api/tools/vgmstream-cli/install").status_code == 403
        assert (
            client.post("/api/tools/unknown_tool/install", headers={"X-UGAV-Token": "secret-tok"}).status_code
            == 404
        )

        # Export media-only (texture) filter
        export_out = tmp_path / "media_only_export"
        exp = client.post(
            f"/api/games/{slug}/export",
            headers={"X-UGAV-Token": "secret-tok"},
            json={"out_dir": str(export_out), "prefer_preview": True, "include_categories": ["texture"]},
        )
        assert exp.status_code == 200
        assert exp.json()["exported"] == 1
        assert (export_out / "logo.png").is_file()
        assert not (export_out / "lang_en.json").exists()

        app.state.repo.close()
