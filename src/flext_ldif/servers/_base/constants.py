"""Base Constants for Server Quirks."""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import ClassVar

from flext_ldif import t


class FlextLdifServersBaseConstants:
    """Base class for server constants."""

    SERVER_TYPE: ClassVar[str]
    PRIORITY: ClassVar[int]
    CANONICAL_NAME: ClassVar[str] = ""
    ALIASES: ClassVar[frozenset[str]] = frozenset()
    CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset()
    CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset()
    ACL_FORMAT: ClassVar[str] = ""
    ACL_ATTRIBUTE_NAME: ClassVar[str] = ""
    SCHEMA_DN: ClassVar[str] = ""
    SCHEMA_SUP_SEPARATOR: ClassVar[str] = "$"
    ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset()
    ATTRIBUTE_ALIASES: ClassVar[t.MutableStrSequenceMapping] = {}
    OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()
    PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = frozenset()
    OBJECTCLASS_REQUIREMENTS: ClassVar[t.MutableBoolMapping] = {}
    CATEGORIZATION_PRIORITY: ClassVar[MutableSequence[str]] = []
    CATEGORY_OBJECTCLASSES: ClassVar[t.MutableFrozensetMapping] = {}
    CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()
    DETECTION_OID_PATTERN: ClassVar[str] = ""
    DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset()
    DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset()
    DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset()


__all__: list[str] = ["FlextLdifServersBaseConstants"]
