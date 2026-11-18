"""Command-line interface for Universal Game Asset Vault & Translator (UGAV)."""

from __future__ import annotations

import json
from pathlib import Path

import click

from ugav import __version__
from ugav.config import AppSettings, ScanConfig, VALID_COPY_MODES, load_keyring
from ugav.db.repository import DatabaseRepository
from ugav.detectors.engine_fingerprint import fingerprint_game_directory
from ugav.diagnostics import export_diagnostic_zip
from ugav.discovery import discover_installed_games, resolve_game_root
from ugav.paths import get_portable_data_dir
from ugav.pipeline import ScanPipeline
from ugav.vault.storage import VaultStorage


def _open_env(data_dir_opt: str | None) -> tuple[Path, AppSettings, DatabaseRepository, VaultStorage]:
    data_dir = get_portable_data_dir(data_dir_opt)
    settings = AppSettings.load(data_dir)
    vault_dir = Path(settings.custom_vault_dir) if settings.custom_vault_dir else (data_dir / "vault")
    repo = DatabaseRepository(data_dir / "ugav.sqlite")
    vault = VaultStorage(vault_dir, min_free_gb=settings.min_free_gb)
    return data_dir, settings, repo, vault


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="ugav")
@click.option("--data-dir", default=None, help="Override portable ugav_data directory.")
@click.pass_context
def cli(ctx: click.Context, data_dir: str | None) -> None:
    """Universal Game Asset Vault & Translator (UGAV)."""
    ctx.ensure_object(dict)
    ctx.obj["data_dir"] = data_dir


@cli.command()
@click.option("--roots", multiple=True, help="Extra directories to search for games.")
@click.option("--json-out", is_flag=True, help="Print JSON output.")
@click.pass_context
def discover(ctx: click.Context, roots: tuple[str, ...], json_out: bool) -> None:
    """Auto-discover installed games across drives and launchers."""
    data_dir = get_portable_data_dir(ctx.obj.get("data_dir"))
    extra = [Path(r) for r in roots] if roots else None
    games = discover_installed_games(extra_roots=extra, data_dir=data_dir)
    if json_out:
        click.echo(json.dumps([g.to_dict() for g in games], indent=2))
        return
    if not games:
        click.echo("No installed games discovered automatically.")
        return
    click.echo(f"Discovered {len(games)} game(s):")
    for g in games:
        click.echo(f"  [{g.source}] {g.name} -> {g.root_path}")


@cli.command()
@click.argument("target_path")
@click.option("--json-out", is_flag=True, help="Print JSON output.")
def detect(target_path: str, json_out: bool) -> None:
    """Inspect a game folder or .exe without copying files."""
    root = resolve_game_root(target_path)
    if not root.is_dir():
        raise click.ClickException(f"Directory not found: {root}")
    fp = fingerprint_game_directory(root)
    payload = {
        "name": fp.name,
        "root_path": str(fp.root_path),
        "detected_engine": fp.detected_engine,
        "middleware": fp.middleware,
        "cpu_arch": fp.cpu_arch,
        "source_platform": fp.source_platform,
        "confidence": fp.confidence,
        "is_online_stub": fp.is_online_stub,
        "total_files": fp.total_files,
        "total_gb": round(fp.total_bytes / (1024**3), 3),
        "details": fp.details,
    }
    if json_out:
        click.echo(json.dumps(payload, indent=2))
        return
    click.echo(f"Game:       {fp.name} ({fp.root_path})")
    click.echo(f"Engine:     {fp.detected_engine} (confidence={fp.confidence})")
    click.echo(f"Middleware: {', '.join(fp.middleware) or 'none'}")
    click.echo(f"Platform:   {fp.source_platform} / {fp.cpu_arch}")
    click.echo(f"Size:       {fp.total_files} files ({payload['total_gb']} GB)")
    click.echo(f"OnlineStub: {fp.is_online_stub}")


@cli.command()
@click.argument("target_path")
@click.option("--mode", type=click.Choice(VALID_COPY_MODES), default="vault_extracted")
@click.option("--convert-textures/--no-convert-textures", default=True)
@click.option("--carve-unknown", is_flag=True, default=False)
@click.option("--include-category", multiple=True)
@click.option("--exclude-ext", multiple=True)
@click.option("--max-file-mb", type=float, default=500.0)
@click.option("--min-free-gb", type=float, default=2.0)
@click.option("--vault-dir", default=None, help="Custom output vault directory for this game.")
@click.option("--media-only", is_flag=True, default=False, help="Copy only media assets (texture, audio, video, model_3d).")
@click.option("--api-ready", is_flag=True, default=False, help="Copy media + structured data + localization (skip .exe/scripts).")
@click.option("--force-online-stub", is_flag=True, default=False)
@click.pass_context
def scan(
    ctx: click.Context,
    target_path: str,
    mode: str,
    convert_textures: bool,
    carve_unknown: bool,
    include_category: tuple[str, ...],
    exclude_ext: tuple[str, ...],
    max_file_mb: float,
    min_free_gb: float,
    vault_dir: str | None,
    media_only: bool,
    api_ready: bool,
    force_online_stub: bool,
) -> None:
    """Scan a game directory or .exe into the portable Vault & SQLite DB."""
    data_dir, _settings, repo, vault = _open_env(ctx.obj.get("data_dir"))
    vault.min_free_gb = min_free_gb
    eff_mode = "vault_selective" if (media_only or api_ready) else mode
    if api_ready:
        eff_cats: list[str] | None = ["texture", "audio", "video", "model_3d", "data", "localization"]
    elif media_only:
        eff_cats = ["texture", "audio", "video", "model_3d"]
    else:
        eff_cats = list(include_category) if include_category else None
    try:
        cfg = ScanConfig(
            copy_mode=eff_mode,  # type: ignore[arg-type]
            convert_textures=convert_textures,
            carve_unknown=carve_unknown,
            min_free_gb=min_free_gb,
            max_file_mb=max_file_mb,
            include_categories=eff_cats,
            exclude_extensions=list(exclude_ext),
            keys=load_keyring(data_dir),
            force_online_stub=force_online_stub,
            output_vault_dir=vault_dir,
        )
        pipeline = ScanPipeline(repo, vault, data_dir, cfg)
        summary = pipeline.scan_game(target_path)
        click.echo(json.dumps(summary.to_dict(), indent=2))
    finally:
        repo.close()


@cli.command()
@click.option("--game", default=None, help="Filter stats to a specific game slug.")
@click.pass_context
def stats(ctx: click.Context, game: str | None) -> None:
    """Show database & vault statistics."""
    _d, _s, repo, _v = _open_env(ctx.obj.get("data_dir"))
    try:
        click.echo(json.dumps(repo.get_stats(game), indent=2))
    finally:
        repo.close()


@cli.command()
@click.argument("query")
@click.option("--game", default=None, help="Filter search to a game slug.")
@click.option("--limit", default=20, type=int)
@click.pass_context
def search(ctx: click.Context, query: str, game: str | None, limit: int) -> None:
    """Full-text search across translated game entities."""
    _d, _s, repo, _v = _open_env(ctx.obj.get("data_dir"))
    try:
        hits = repo.search_entities_fts(query, game_slug=game, limit=limit)
        click.echo(json.dumps(hits, indent=2))
    finally:
        repo.close()


@cli.command("export-tree")
@click.argument("game_slug")
@click.argument("out_dir")
@click.option("--prefer-preview/--raw", default=True)
@click.option("--media-only", is_flag=True, default=False, help="Export only media (texture, audio, video, model_3d).")
@click.option("--include-category", multiple=True)
@click.pass_context
def export_tree(
    ctx: click.Context,
    game_slug: str,
    out_dir: str,
    prefer_preview: bool,
    media_only: bool,
    include_category: tuple[str, ...],
) -> None:
    """Export vaulted assets of a game into a clean directory tree."""
    _d, _s, repo, vault = _open_env(ctx.obj.get("data_dir"))
    try:
        g = repo.get_game_by_slug(game_slug)
        if not g:
            raise click.ClickException(f"Unknown game slug: {game_slug}")
        allowed = {"texture", "audio", "video", "model_3d"} if media_only else (set(include_category) if include_category else None)
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
        summary = vault.export_assets_tree(all_assets, Path(out_dir), prefer_preview=prefer_preview)
        click.echo(json.dumps(summary, indent=2))
    finally:
        repo.close()


@cli.command()
@click.argument("game_slug")
@click.argument("new_root_path")
@click.pass_context
def relocate(ctx: click.Context, game_slug: str, new_root_path: str) -> None:
    """Update stored game root path when moving Vault/DB across devices."""
    _d, _s, repo, _v = _open_env(ctx.obj.get("data_dir"))
    try:
        updated = repo.relocate_game(game_slug, Path(new_root_path))
        click.echo(json.dumps(updated, indent=2))
    finally:
        repo.close()


@cli.command()
@click.argument("other_data_dir")
@click.pass_context
def merge(ctx: click.Context, other_data_dir: str) -> None:
    """Merge another device's ugav_data (SQLite + Vault) into this Vault."""
    _d, _s, repo, vault = _open_env(ctx.obj.get("data_dir"))
    try:
        other = Path(other_data_dir).resolve()
        res = repo.merge_from_other_db(other / "ugav.sqlite", other / "vault", vault.vault_dir)
        click.echo(json.dumps(res, indent=2))
    finally:
        repo.close()


@cli.command()
@click.argument("out_zip")
@click.pass_context
def diagnostics(ctx: click.Context, out_zip: str) -> None:
    """Export sanitized diagnostic report ZIP."""
    data_dir, _s, repo, _v = _open_env(ctx.obj.get("data_dir"))
    try:
        written = export_diagnostic_zip(repo, data_dir, Path(out_zip))
        click.echo(f"Diagnostic report written to {written}")
    finally:
        repo.close()


@cli.command()
@click.pass_context
def gui(ctx: click.Context) -> None:
    """Launch Desktop GUI."""
    from ugav.gui.launcher import launch_gui

    launch_gui(data_dir_override=ctx.obj.get("data_dir"))


@cli.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8000, type=int)
@click.pass_context
def serve(ctx: click.Context, host: str, port: int) -> None:
    """Run read-only/API server directly in foreground."""
    import uvicorn
    from ugav.gui.server import create_app

    data_dir = get_portable_data_dir(ctx.obj.get("data_dir"))
    app = create_app(data_dir=data_dir)
    uvicorn.run(app, host=host, port=port)
