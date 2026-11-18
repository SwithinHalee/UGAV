# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.utils.hooks import collect_all

ROOT = Path(SPECPATH).resolve().parent

wv_datas, wv_bins, wv_hidden = collect_all("webview")
pn_datas, pn_bins, pn_hidden = collect_all("pythonnet")
clr_datas, clr_bins, clr_hidden = collect_all("clr_loader")

a = Analysis(
    [str(ROOT / "ugav" / "app.py")],
    pathex=[str(ROOT)],
    binaries=wv_bins + pn_bins + clr_bins,
    datas=[
        (str(ROOT / "ugav" / "db" / "schema.sql"), "ugav/db"),
        (str(ROOT / "ugav" / "gui" / "static"), "ugav/gui/static"),
        (str(ROOT / "rules"), "rules"),
    ] + wv_datas + pn_datas + clr_datas,
    hiddenimports=[
        "uvicorn.logging",
        "uvicorn.loops.auto",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan.on",
        "lxml.etree",
        "lxml._elementpath",
        "PIL.DdsImagePlugin",
        "PIL.TgaImagePlugin",
        "PIL.PngImagePlugin",
    ] + wv_hidden + pn_hidden + clr_hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "unittest"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe_gui = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="UGAV",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)

exe_cli = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ugav-cli",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe_gui,
    exe_cli,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="UGAV",
)
