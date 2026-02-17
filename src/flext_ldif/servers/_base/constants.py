"""Base Constants for Server Quirks."""

from __future__ import annotations

from abc import ABC
from collections.abc import Mapping
from typing import ClassVar

from flext_core import FlextLogger

from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif.constants import c

logger = FlextLogger(__name__)


class FlextLdifServersBaseConstants(ABC):
    """Abstract base class for server constants."""

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
    ATTRIBUTE_ALIASES: ClassVar[Mapping[str, list[str]]] = {}
    OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()
    PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = frozenset()

    OBJECTCLASS_REQUIREMENTS: ClassVar[Mapping[str, bool]] = {}

    CATEGORIZATION_PRIORITY: ClassVar[list[str]] = []
    CATEGORY_OBJECTCLASSES: ClassVar[dict[str, frozenset[str]]] = {}
    CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()

    DETECTION_OID_PATTERN: ClassVar[str] = ""
    DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset()
    DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset()
    DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset()


def _get_server_type_from_utilities(
    quirk_class: type[object],
) -> c.Ldif.LiteralTypes.ServerTypeLiteral:
    """Get server type from utilities using type-safe access pattern."""
    return FlextLdifUtilitiesServer.get_parent_server_type(quirk_class)


def _get_priority_from_parent(parent: object | None) -> int:
    """Get priority from parent server class Constants."""
    if parent is None:
        return 100

    constants_attr = getattr(parent, "Constants", None)
    if constants_attr is None:
        return 100
    priority_value = getattr(constants_attr, "PRIORITY", None)
    if isinstance(priority_value, int):
        return priority_value
    return 100


def _get_parent_quirk_safe_impl(
    instance: object,
) -> object | None:
    """Get _parent_quirk attribute safely with type narrowing."""
    parent_raw: object | None = getattr(instance, "_parent_quirk", None)

    if parent_raw is not None and hasattr(parent_raw, "_parent_quirk"):
        return parent_raw
    return None


class QuirkMethodsMixin:
    """Mixin providing common quirk methods for Schema, Acl, and Entry classes."""

    def _get_server_type(self) -> c.Ldif.LiteralTypes.ServerTypeLiteral:
        """Get server_type from parent server class via __qualname__."""
        return _get_server_type_from_utilities(type(self))

    def _get_priority(self) -> int:
        """Get priority from parent server class Constants."""
        parent = self._get_parent_quirk_safe()
        return _get_priority_from_parent(parent)

    def _get_parent_quirk_safe(
        self,
    ) -> object | None:
        """Get _parent_quirk attribute safely with type narrowing."""
        return _get_parent_quirk_safe_impl(self)


__all__ = [
    "FlextLdifServersBaseConstants",
    "QuirkMethodsMixin",
    "_get_parent_quirk_safe_impl",
    "_get_priority_from_parent",
    "_get_server_type_from_utilities",
    "logger",
]
