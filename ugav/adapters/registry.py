"""Adapter registry dispatching files by signature and extension."""

from __future__ import annotations

from pathlib import Path

from ugav.adapters.asar_adapter import AsarAdapter
from ugav.adapters.base import BaseArchiveAdapter
from ugav.adapters.bethesda_bsa import BethesdaBsaAdapter
from ugav.adapters.cri_cpk import CriCpkAdapter
from ugav.adapters.gamemaker_iff import GameMakerIffAdapter
from ugav.adapters.godot_pck import GodotPckAdapter
from ugav.adapters.renpy_rpa import RenPyRpaAdapter
from ugav.adapters.rpgmaker import RpgMakerMediaAdapter
from ugav.adapters.valve_vpk import ValveVpkAdapter
from ugav.adapters.zip_adapter import ZipArchiveAdapter


class AdapterRegistry:
    """Routes archive/container files to the appropriate built-in adapter."""

    def __init__(self, adapters: list[BaseArchiveAdapter] | None = None) -> None:
        self.adapters: list[BaseArchiveAdapter] = adapters if adapters is not None else [
            CriCpkAdapter(),
            GameMakerIffAdapter(),
            ZipArchiveAdapter(),
            GodotPckAdapter(),
            RenPyRpaAdapter(),
            RpgMakerMediaAdapter(),
            ValveVpkAdapter(),
            AsarAdapter(),
            BethesdaBsaAdapter(),
        ]

    def find_adapter(self, path: Path, header: bytes) -> BaseArchiveAdapter | None:
        for adapter in self.adapters:
            if adapter.can_handle(path, header):
                return adapter
        return None
