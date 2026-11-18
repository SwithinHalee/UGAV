"""XXE-safe XML, JSON/JSONC, YAML, CSV/TSV, INI, and SQLite universal data parser."""

from __future__ import annotations

import configparser
import csv
import io
import json
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

import yaml
from charset_normalizer import from_bytes
from lxml import etree

from ugav.db.repository import slugify
from ugav.translators.base import LocalizationEntry, TranslatedEntity


def decode_text_bytes(raw: bytes, encoding_hint: str | None = None) -> tuple[str, str]:
    """Decode text bytes cleanly handling BOM, UTF-8, UTF-16, and Shift-JIS/CP932."""
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace"), "utf-8-sig"
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace"), "utf-16"

    order: list[str] = []
    if encoding_hint:
        order.append(encoding_hint)
    order.extend(["utf-8", "cp932"])
    for enc in order:
        try:
            return raw.decode(enc), enc
        except (UnicodeDecodeError, LookupError):
            continue

    best = from_bytes(raw).best()
    if best is not None:
        return str(best), best.encoding
    return raw.decode("latin-1", errors="replace"), "latin-1"


def strip_jsonc(text: str) -> str:
    """Remove // line comments, /* */ block comments, and simple trailing commas outside strings."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_str = False
    escaped = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                end = text.find("\n", i + 2)
                i = n if end < 0 else end
                continue
            if nxt == "*":
                end = text.find("*/", i + 2)
                i = n if end < 0 else end + 2
                continue
        out.append(ch)
        i += 1
    cleaned = "".join(out)
    return re.sub(r",(\s*[}\]])", r"\1", cleaned)


def parse_xml_bytes(raw: bytes, encoding_hint: str | None = None) -> etree._Element:
    """Parse XML bytes safely with external entity resolution and network disabled."""
    text, _ = decode_text_bytes(raw, encoding_hint)
    # Encode as UTF-8 and strip XML encoding declaration mismatch
    parser = etree.XMLParser(resolve_entities=False, no_network=True, recover=True)
    utf8_bytes = re.sub(r'encoding=["\'][^"\']+["\']', 'encoding="utf-8"', text, count=1).encode("utf-8")
    return etree.fromstring(utf8_bytes, parser=parser)


def xml_element_to_dict(elem: etree._Element) -> dict[str, Any]:
    """Recursively convert an lxml element into a JSON-friendly dictionary."""
    node: dict[str, Any] = {}
    if elem.attrib:
        node["@attrs"] = dict(elem.attrib)
    children = [c for c in elem if isinstance(c.tag, str)]
    if children:
        grouped: dict[str, Any] = {}
        for child in children:
            tag = str(child.tag)
            child_val = xml_element_to_dict(child)
            if tag in grouped:
                if not isinstance(grouped[tag], list):
                    grouped[tag] = [grouped[tag]]
                grouped[tag].append(child_val)
            else:
                grouped[tag] = child_val
        node.update(grouped)
    txt = (elem.text or "").strip()
    if txt:
        if not node:
            return {"#text": txt}
        node["#text"] = txt
    return node


def _guess_lang_from_path(rel_path: str) -> str:
    low = rel_path.lower().replace("\\", "/")
    for code, name in (
        ("english", "English"),
        ("lang_en", "English"),
        ("_en.", "English"),
        ("french", "French"),
        ("lang_fr", "French"),
        ("german", "German"),
        ("lang_de", "German"),
        ("japanese", "Japanese"),
        ("lang_ja", "Japanese"),
        ("spanish", "Spanish"),
        ("russian", "Russian"),
        ("chinese", "SimplifiedChinese"),
    ):
        if code in low:
            return name
    return "Default"


def _extract_display_name(obj: dict[str, Any], fallback: str) -> str:
    for key in ("display_name", "displayName", "name", "title", "label", "id"):
        val = obj.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return fallback


def parse_structured_bytes(
    raw: bytes,
    fmt: str,
    rel_path: str,
    source_asset_id: int | None = None,
    encoding_hint: str | None = None,
) -> tuple[list[TranslatedEntity], list[LocalizationEntry]]:
    """Parse generic XML, JSON/JSONC, YAML, CSV/TSV, INI, or SQLite files into entities/strings."""
    entities: list[TranslatedEntity] = []
    loc_strings: list[LocalizationEntry] = []
    stem = Path(rel_path).stem
    norm_path = rel_path.replace("\\", "/")

    if fmt in ("json", "jsonc"):
        text, _ = decode_text_bytes(raw, encoding_hint)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = json.loads(strip_jsonc(text))

        low = norm_path.lower()
        is_loc_hint = any(tok in low for tok in ("lang", "local", "string", "i18n"))
        if isinstance(data, dict):
            str_values = sum(1 for v in data.values() if isinstance(v, str))
            if is_loc_hint and data and str_values >= max(3, int(len(data) * 0.7)):
                lang = _guess_lang_from_path(norm_path)
                for k, v in data.items():
                    if isinstance(v, str):
                        loc_strings.append(LocalizationEntry(lang=lang, str_key=str(k), str_value=v, source_asset_id=source_asset_id))
                return entities, loc_strings
            entities.append(
                TranslatedEntity(
                    entity_type="json_record",
                    external_key=norm_path,
                    slug=slugify(stem),
                    display_name=_extract_display_name(data, stem),
                    raw=data,
                    resolved=data,
                    source_asset_id=source_asset_id,
                )
            )
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                if isinstance(item, dict):
                    ext_key = f"{norm_path}#{item.get('id', idx)}"
                    dname = _extract_display_name(item, f"{stem} #{idx}")
                    entities.append(
                        TranslatedEntity(
                            entity_type=stem.lower(),
                            external_key=ext_key,
                            slug=slugify(dname),
                            display_name=dname,
                            raw=item,
                            resolved=item,
                            source_asset_id=source_asset_id,
                        )
                    )
        return entities, loc_strings

    if fmt == "xml":
        root = parse_xml_bytes(raw, encoding_hint)
        data = {str(root.tag): xml_element_to_dict(root)}
        entities.append(
            TranslatedEntity(
                entity_type="xml_record",
                external_key=norm_path,
                slug=slugify(stem),
                display_name=stem,
                raw=data,
                resolved=data,
                source_asset_id=source_asset_id,
            )
        )
        return entities, loc_strings

    if fmt == "yaml":
        text, _ = decode_text_bytes(raw, encoding_hint)
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            entities.append(
                TranslatedEntity(
                    entity_type="yaml_record",
                    external_key=norm_path,
                    slug=slugify(stem),
                    display_name=_extract_display_name(data, stem),
                    raw=data,
                    resolved=data,
                    source_asset_id=source_asset_id,
                )
            )
        return entities, loc_strings

    if fmt in ("csv", "tsv"):
        text, _ = decode_text_bytes(raw, encoding_hint)
        delim = "\t" if fmt == "tsv" else ","
        reader = csv.DictReader(io.StringIO(text), delimiter=delim)
        for idx, row in enumerate(reader):
            row_dict = {str(k): v for k, v in row.items() if k is not None}
            if not row_dict:
                continue
            dname = _extract_display_name(row_dict, f"{stem} #{idx}")
            entities.append(
                TranslatedEntity(
                    entity_type=stem.lower(),
                    external_key=f"{norm_path}#{idx}",
                    slug=slugify(dname),
                    display_name=dname,
                    raw=row_dict,
                    resolved=row_dict,
                    source_asset_id=source_asset_id,
                )
            )
        return entities, loc_strings

    if fmt == "ini":
        text, _ = decode_text_bytes(raw, encoding_hint)
        cp = configparser.ConfigParser(interpolation=None)
        cp.read_string(text)
        ini_dict = {sec: dict(cp.items(sec)) for sec in cp.sections()}
        if ini_dict:
            entities.append(
                TranslatedEntity(
                    entity_type="ini_config",
                    external_key=norm_path,
                    slug=slugify(stem),
                    display_name=stem,
                    raw=ini_dict,
                    resolved=ini_dict,
                    source_asset_id=source_asset_id,
                )
            )
        return entities, loc_strings

    if fmt == "sqlite":
        with tempfile.TemporaryDirectory() as td:
            tmp_db = Path(td) / "embedded.sqlite"
            tmp_db.write_bytes(raw)
            conn = sqlite3.connect(f"file:{tmp_db.as_posix()}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            try:
                tables = [
                    r[0]
                    for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    ).fetchall()
                ]
                for tbl in tables[:20]:
                    rows = conn.execute(f'SELECT * FROM "{tbl.replace(chr(34), "")}" LIMIT 250').fetchall()
                    for idx, r in enumerate(rows):
                        rd = dict(r)
                        dname = _extract_display_name(rd, f"{tbl} #{idx}")
                        entities.append(
                            TranslatedEntity(
                                entity_type=tbl.lower(),
                                external_key=f"{norm_path}::{tbl}#{idx}",
                                slug=slugify(dname),
                                display_name=dname,
                                raw=rd,
                                resolved=rd,
                                source_asset_id=source_asset_id,
                            )
                        )
            finally:
                conn.close()
        return entities, loc_strings

    return entities, loc_strings
