"""Modular archive and media-container unpacker adapters."""

from ugav.adapters.base import (
    AdapterOptions,
    ArchiveCorruptError,
    ArchiveEntry,
    BaseArchiveAdapter,
    BoundedFileSlice,
    EntryBoundsError,
)
from ugav.adapters.binary_carver import carve_embedded_assets
from ugav.adapters.external_bridge import ExternalBridgeManager, reap_orphan_staging_dirs
from ugav.adapters.registry import AdapterRegistry

__all__ = [
    "AdapterOptions",
    "AdapterRegistry",
    "ArchiveCorruptError",
    "ArchiveEntry",
    "BaseArchiveAdapter",
    "BoundedFileSlice",
    "EntryBoundsError",
    "ExternalBridgeManager",
    "carve_embedded_assets",
    "reap_orphan_staging_dirs",
]
