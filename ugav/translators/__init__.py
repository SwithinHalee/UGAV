"""Universal structured data translators and declarative YAML rule engine."""

from ugav.translators.base import LocalizationEntry, TranslatedEntity, TranslatedRelation
from ugav.translators.generic_structured import (
    decode_text_bytes,
    parse_structured_bytes,
    parse_xml_bytes,
    strip_jsonc,
    xml_element_to_dict,
)
from ugav.translators.rule_engine import DeclarativeRuleEngine

__all__ = [
    "DeclarativeRuleEngine",
    "LocalizationEntry",
    "TranslatedEntity",
    "TranslatedRelation",
    "decode_text_bytes",
    "parse_structured_bytes",
    "parse_xml_bytes",
    "strip_jsonc",
    "xml_element_to_dict",
]
