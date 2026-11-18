"""Declarative YAML 2-pass rule engine for game-specific structured XML/JSON translation."""

from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path
from typing import Any

import yaml

from ugav.db.repository import DatabaseRepository, slugify
from ugav.paths import get_rules_dirs
from ugav.translators.base import LocalizationEntry, TranslatedEntity
from ugav.translators.generic_structured import decode_text_bytes, parse_xml_bytes, xml_element_to_dict


def _glob_match(rel_path: str, pattern: str) -> bool:
    norm_p = rel_path.replace("\\", "/")
    norm_pat = pattern.replace("\\", "/")
    if "**/" in norm_pat:
        # Match both zero and multiple directory segments for **/
        variants = [norm_pat, norm_pat.replace("**/", "")]
        return any(fnmatch.fnmatch(norm_p, v) for v in variants)
    return fnmatch.fnmatch(norm_p, norm_pat)


def _humanize_identifier(identifier: str) -> str:
    leaf = identifier.rsplit("/", 1)[-1]
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", leaf)
    return spaced.replace("_", " ").strip()


class DeclarativeRuleEngine:
    """Loads YAML mapping rules and translates matched game assets into entities & relations."""

    def __init__(self, data_dir: Path | None = None) -> None:
        self.rules: list[dict[str, Any]] = []
        for rdir in get_rules_dirs(data_dir):
            for yf in sorted(rdir.glob("*.yaml")):
                try:
                    loaded = yaml.safe_load(yf.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict) and loaded.get("name"):
                        self.rules.append(loaded)
                except Exception:
                    pass

    def find_matching_rules(self, game_root: Path, rel_paths: set[str]) -> list[dict[str, Any]]:
        norm_rels = {p.replace("\\", "/") for p in rel_paths}
        matched: list[dict[str, Any]] = []
        for rule in self.rules:
            match_cfg = rule.get("match") or {}
            req_dirs = match_cfg.get("required_dirs") or []
            req_files = match_cfg.get("required_files") or []
            if req_dirs:
                ok_dirs = all(
                    (game_root / d).is_dir() or any(rp.startswith(d.rstrip("/") + "/") for rp in norm_rels)
                    for d in req_dirs
                )
                if not ok_dirs:
                    continue
            if req_files:
                ok_files = all(
                    (game_root / f).is_file() or f in norm_rels for f in req_files
                )
                if not ok_files:
                    continue
            matched.append(rule)
        return matched

    def run_for_game(
        self,
        repo: DatabaseRepository,
        game_id: int,
        game_root: Path,
        asset_bytes_provider: Any,
        assets_list: list[dict[str, Any]],
    ) -> tuple[int, set[int]]:
        """
        Execute 2-pass translation using matched YAML rules.
        asset_bytes_provider(asset_dict) -> bytes | None
        Returns (total_entities_translated, handled_asset_ids).
        """
        rel_set = {a["original_path"].replace("\\", "/") for a in assets_list}
        matched_rules = self.find_matching_rules(game_root, rel_set)
        if not matched_rules:
            return 0, set()

        loc_entries: list[LocalizationEntry] = []
        parsed_entities: list[TranslatedEntity] = []
        handled_asset_ids: set[int] = set()

        # Pass 1: Localization & Raw Entities
        for rule in matched_rules:
            for loc_cfg in rule.get("localizations") or []:
                glob_pat = loc_cfg.get("glob", "")
                fmt = loc_cfg.get("format", "xml_key_value")
                for asset in assets_list:
                    rpath = asset["original_path"].replace("\\", "/")
                    if not _glob_match(rpath, glob_pat):
                        continue
                    raw = asset_bytes_provider(asset)
                    if not raw:
                        continue
                    handled_asset_ids.add(int(asset["id"]))
                    lang = self._extract_lang_from_path(rpath, loc_cfg.get("lang_regex"))
                    if fmt == "xml_key_value":
                        loc_entries.extend(
                            self._parse_xml_loc(raw, lang, loc_cfg, int(asset["id"]))
                        )
                    elif fmt == "json_kv":
                        text, _ = decode_text_bytes(raw)
                        obj = json.loads(text)
                        if isinstance(obj, dict):
                            for k, v in obj.items():
                                if isinstance(v, str):
                                    loc_entries.append(
                                        LocalizationEntry(lang, str(k), v, int(asset["id"]))
                                    )

        if loc_entries:
            repo.upsert_localization_batch(
                [
                    {
                        "game_id": game_id,
                        "lang": le.lang,
                        "str_key": le.str_key,
                        "str_value": le.str_value,
                        "source_asset_id": le.source_asset_id,
                    }
                    for le in loc_entries
                ]
            )

        loc_map = repo.get_localization_map(game_id, "English")

        for rule in matched_rules:
            for ent_cfg in rule.get("entities") or []:
                glob_pat = ent_cfg.get("glob", "")
                ent_type = str(ent_cfg.get("entity_type", "record"))
                strip_prefix = str(ent_cfg.get("strip_prefix", "")).strip("/")
                fmt = ent_cfg.get("format", "xml")
                for asset in assets_list:
                    rpath = asset["original_path"].replace("\\", "/")
                    if not _glob_match(rpath, glob_pat):
                        continue
                    raw = asset_bytes_provider(asset)
                    if not raw:
                        continue
                    handled_asset_ids.add(int(asset["id"]))
                    if fmt == "xml":
                        parsed_entities.extend(
                            self._parse_xml_entity(
                                raw=raw,
                                rel_path=rpath,
                                strip_prefix=strip_prefix,
                                ent_type=ent_type,
                                ent_cfg=ent_cfg,
                                loc_map=loc_map,
                                asset_id=int(asset["id"]),
                            )
                        )
                    elif fmt == "json_array":
                        parsed_entities.extend(
                            self._parse_json_array_entities(
                                raw=raw,
                                ent_type=ent_type,
                                ent_cfg=ent_cfg,
                                asset_id=int(asset["id"]),
                            )
                        )

        if not parsed_entities:
            return 0, handled_asset_ids

        # Persist entities
        repo.upsert_entities_batch(
            [
                {
                    "game_id": game_id,
                    "source_asset_id": e.source_asset_id,
                    "entity_type": e.entity_type,
                    "external_key": e.external_key,
                    "slug": e.slug,
                    "display_name": e.display_name,
                    "raw": e.raw,
                    "resolved": e.resolved,
                }
                for e in parsed_entities
            ]
        )

        # Pass 2: Resolve Relations
        key_map = repo.get_entities_key_map(game_id)
        relations_to_save: list[dict[str, Any]] = []
        for e in parsed_entities:
            src_id = key_map.get((e.entity_type, e.external_key))
            if not src_id:
                continue
            for rel_type, target_type, target_ref, meta in e.pending_relations:
                target_id = key_map.get((target_type, target_ref))
                if target_id is None and "/" not in target_ref:
                    # Fallback match by leaf stem if external_key has faction prefix
                    for (et, ek), tid in key_map.items():
                        if et == target_type and ek.rsplit("/", 1)[-1] == target_ref:
                            target_id = tid
                            break
                relations_to_save.append(
                    {
                        "source_entity_id": src_id,
                        "relation_type": rel_type,
                        "target_entity_id": target_id,
                        "target_ref": target_ref,
                        "metadata": meta,
                    }
                )
        repo.replace_entity_relations(game_id, relations_to_save)
        return len(parsed_entities), handled_asset_ids

    @staticmethod
    def _extract_lang_from_path(rel_path: str, pattern: str | None) -> str:
        if pattern:
            m = re.search(pattern, rel_path, flags=re.IGNORECASE)
            if m and m.groups():
                return m.group(1)
        return "English" if "english" in rel_path.lower() else "Default"

    @staticmethod
    def _parse_xml_loc(
        raw: bytes, lang: str, cfg: dict[str, Any], asset_id: int
    ) -> list[LocalizationEntry]:
        entries: list[LocalizationEntry] = []
        try:
            root = parse_xml_bytes(raw)
        except Exception:
            return entries
        tag = cfg.get("entry_tag", "entry")
        key_attr = cfg.get("key_attr", "name")
        val_attr = cfg.get("value_attr", "value")
        for elem in root.xpath(f".//{tag}"):
            k = elem.get(key_attr)
            v = elem.get(val_attr)
            if k and v is not None:
                entries.append(LocalizationEntry(lang=lang, str_key=k, str_value=v, source_asset_id=asset_id))
        return entries

    @staticmethod
    def _parse_xml_entity(
        *,
        raw: bytes,
        rel_path: str,
        strip_prefix: str,
        ent_type: str,
        ent_cfg: dict[str, Any],
        loc_map: dict[str, str],
        asset_id: int,
    ) -> list[TranslatedEntity]:
        try:
            root = parse_xml_bytes(raw)
        except Exception:
            return []

        rel_no_ext = rel_path.rsplit(".", 1)[0]
        if strip_prefix and rel_no_ext.lower().startswith(strip_prefix.lower() + "/"):
            ext_key = rel_no_ext[len(strip_prefix) + 1 :]
        else:
            ext_key = rel_no_ext

        leaf = ext_key.rsplit("/", 1)[-1]
        display_name = loc_map.get(ext_key) or loc_map.get(leaf) or _humanize_identifier(leaf)
        description = loc_map.get(f"{leaf}Description") or loc_map.get(f"{leaf}Flavor")

        raw_dict = {str(root.tag): xml_element_to_dict(root)}
        resolved: dict[str, Any] = {
            "name": display_name,
            "key": ext_key,
            "type": ent_type,
            "dlc": root.get("dlc"),
        }
        if description:
            resolved["description"] = description

        # Extract numeric/modifier stats cleanly if present
        stats: dict[str, Any] = {}
        for eff in root.xpath(".//modifiers/modifier/effects/*"):
            if isinstance(eff.tag, str) and eff.attrib:
                stats[eff.tag] = dict(eff.attrib)
        if stats:
            resolved["stats"] = stats

        pending_rels: list[tuple[str, str, str, dict[str, Any]]] = []
        for rel_cfg in ent_cfg.get("relations") or []:
            rel_type = rel_cfg["relation_type"]
            target_type = rel_cfg["target_type"]
            if rel_cfg.get("from_parent_dir") and "/" in ext_key:
                parent_dir = ext_key.split("/", 1)[0]
                pending_rels.append((rel_type, target_type, parent_dir, {}))
            elif rel_cfg.get("xml_xpath"):
                for hit in root.xpath(rel_cfg["xml_xpath"]):
                    val = str(hit).strip()
                    if val:
                        pending_rels.append((rel_type, target_type, val, {}))

        if pending_rels:
            resolved["relation_refs"] = [
                {"relation": rt, "target_type": tt, "ref": ref}
                for rt, tt, ref, _ in pending_rels
            ]

        return [
            TranslatedEntity(
                entity_type=ent_type,
                external_key=ext_key,
                slug=slugify(ext_key),
                display_name=display_name,
                raw=raw_dict,
                resolved=resolved,
                source_asset_id=asset_id,
                pending_relations=pending_rels,
            )
        ]

    @staticmethod
    def _parse_json_array_entities(
        *,
        raw: bytes,
        ent_type: str,
        ent_cfg: dict[str, Any],
        asset_id: int,
    ) -> list[TranslatedEntity]:
        text, _ = decode_text_bytes(raw)
        data = json.loads(text)
        if not isinstance(data, list):
            return []
        name_field = ent_cfg.get("name_field", "name")
        id_field = ent_cfg.get("id_field", "id")
        out: list[TranslatedEntity] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            eid = item.get(id_field)
            name = item.get(name_field)
            if not name and eid is None:
                continue
            ext_key = f"{ent_type}/{eid}"
            dname = str(name or ext_key)
            out.append(
                TranslatedEntity(
                    entity_type=ent_type,
                    external_key=ext_key,
                    slug=slugify(f"{ent_type}-{dname}-{eid}"),
                    display_name=dname,
                    raw=item,
                    resolved=item,
                    source_asset_id=asset_id,
                )
            )
        return out
