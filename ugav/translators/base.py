"""Data translation dataclasses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class LocalizationEntry:
    lang: str
    str_key: str
    str_value: str
    source_asset_id: int | None = None


@dataclass
class TranslatedEntity:
    entity_type: str
    external_key: str
    slug: str
    display_name: str | None
    raw: dict[str, Any]
    resolved: dict[str, Any] = field(default_factory=dict)
    source_asset_id: int | None = None
    pending_relations: list[tuple[str, str, str, dict[str, Any]]] = field(default_factory=list)
    # tuple: (relation_type, target_type, target_ref, metadata)


@dataclass
class TranslatedRelation:
    source_entity_id: int
    relation_type: str
    target_ref: str
    target_entity_id: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
