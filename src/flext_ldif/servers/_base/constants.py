"""Base Constants for Server Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides shared constants and utilities for server quirk implementations.
"""

from __future__ import annotations

from abc import ABC
from collections.abc import Mapping
from typing import ClassVar, cast

from flext_core import FlextLogger

from flext_ldif.constants import c
from flext_ldif.protocols import p

logger = FlextLogger(__name__)


class FlextLdifServersBaseConstants(ABC):
    """Abstract base class for server constants.

    Business Rule: All server quirks must define constants via nested Constants
    class that inherits from this base. SERVER_TYPE and PRIORITY are mandatory.

    Architecture:
        - RFC constants provide baseline implementations
        - Server-specific constants override as needed
        - No defaults for SERVER_TYPE/PRIORITY (must be explicit)

    """

    # Required: Must be overridden in subclasses
    SERVER_TYPE: ClassVar[c.Ldif.LiteralTypes.ServerTypeLiteral]
    PRIORITY: ClassVar[int]

    # Server naming (can be overridden)
    CANONICAL_NAME: ClassVar[str] = ""
    ALIASES: ClassVar[frozenset[str]] = frozenset()

    # Conversion capabilities (can be overridden)
    CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset()
    CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset()

    # ACL configuration defaults (can be overridden)
    ACL_FORMAT: ClassVar[str] = ""
    ACL_ATTRIBUTE_NAME: ClassVar[str] = ""

    # Schema defaults (can be overridden)
    SCHEMA_DN: ClassVar[str] = ""
    SCHEMA_SUP_SEPARATOR: ClassVar[str] = "$"
    ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset()
    ATTRIBUTE_ALIASES: ClassVar[Mapping[str, list[str]]] = {}
    OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()
    PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = frozenset()

    # ObjectClass requirements (can be overridden)
    OBJECTCLASS_REQUIREMENTS: ClassVar[Mapping[str, bool]] = {}

    # Categorization defaults (can be overridden)
    CATEGORIZATION_PRIORITY: ClassVar[list[str]] = []
    CATEGORY_OBJECTCLASSES: ClassVar[dict[str, frozenset[str]]] = {}
    CATEGORIZATION_ACL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset()

    # Detection patterns (can be overridden)
    DETECTION_OID_PATTERN: ClassVar[str] = ""
    DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset()
    DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset()
    DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset()


def _get_utilities() -> type:
    """Lazy import of FlextLdifUtilities to avoid circular dependency.

    Business Rule: Breaks circular dependencies between servers and _utilities.
    Returns type because exact type cannot be inferred statically.

    Returns:
        FlextLdifUtilities class type

    """
    from flext_ldif.utilities import FlextLdifUtilities  # noqa: PLC0415

    return FlextLdifUtilities


def _get_server_type_from_utilities(
    quirk_class: type[object],
) -> c.Ldif.LiteralTypes.ServerTypeLiteral:
    """Get server type from utilities using type-safe access pattern.

    Business Rule: Server type determined by inspecting class hierarchy via
    FlextLdifUtilities.Server.get_parent_server_type().

    Args:
        quirk_class: The quirk class to get server type for

    Returns:
        Server type literal (e.g., 'oid', 'oud', 'rfc')

    """
    utilities_class = _get_utilities()
    server_util = getattr(utilities_class, "Server", None)
    if server_util is not None:
        get_parent_method = getattr(server_util, "get_parent_server_type", None)
        if get_parent_method is not None and callable(get_parent_method):
            server_type_raw = get_parent_method(quirk_class)
            return cast(
                "c.Ldif.LiteralTypes.ServerTypeLiteral",
                server_type_raw,
            )
    return "rfc"


def _get_priority_from_parent(parent: object | None) -> int:
    """Get priority from parent server class Constants.

    Business Rule: Priority is extracted from parent quirk's Constants.PRIORITY.
    Falls back to 100 (low priority) if not found.

    Args:
        parent: Parent quirk instance or None

    Returns:
        Priority value (lower = higher priority)

    """
    if parent is None:
        return 100  # Default priority
    # Safe attribute access pattern
    constants_attr = getattr(parent, "Constants", None)
    if constants_attr is None:
        return 100  # Default priority
    priority_value = getattr(constants_attr, "PRIORITY", None)
    if isinstance(priority_value, int):
        return priority_value
    return 100  # Default priority


def _get_parent_quirk_safe_impl(
    instance: object,
) -> p.Ldif.Quirks.ParentQuirkProtocol | None:
    """Get _parent_quirk attribute safely with type narrowing.

    Business Rule: Consolidates the common pattern of getting and
    type-checking the parent quirk.

    Args:
        instance: The quirk instance to get parent from

    Returns:
        ParentQuirkProtocol instance or None if not set or invalid type.

    """
    parent_raw = getattr(instance, "_parent_quirk", None)
    # Use protocol isinstance check for type narrowing
    if isinstance(parent_raw, p.Ldif.Quirks.ParentQuirkProtocol):
        return parent_raw
    return None


class QuirkMethodsMixin:
    """Mixin providing common quirk methods for Schema, Acl, and Entry classes.

    Business Rule: Eliminates code duplication by providing shared implementations
    of _get_server_type, _get_priority, and _get_parent_quirk_safe methods.

    Note: This mixin requires the class to have:
    - Access to _get_server_type_from_utilities function
    - Access to _get_parent_quirk_safe_impl function
    - Access to _get_priority_from_parent function

    """

    def _get_server_type(self) -> c.Ldif.LiteralTypes.ServerTypeLiteral:
        """Get server_type from parent server class via __qualname__.

        Business Rule: Server type is determined by inspecting the class hierarchy
        and accessing FlextLdifUtilities.Server.get_parent_server_type().

        Returns:
            Server type literal (e.g., 'oid', 'oud', 'rfc')

        """
        return _get_server_type_from_utilities(type(self))

    def _get_priority(self) -> int:
        """Get priority from parent server class Constants."""
        parent = self._get_parent_quirk_safe()
        return _get_priority_from_parent(parent)

    def _get_parent_quirk_safe(
        self,
    ) -> p.Ldif.Quirks.ParentQuirkProtocol | None:
        """Get _parent_quirk attribute safely with type narrowing.

        Returns:
            ParentQuirkProtocol instance or None if not set or invalid type.

        """
        return _get_parent_quirk_safe_impl(self)


__all__ = [
    "FlextLdifServersBaseConstants",
    "QuirkMethodsMixin",
    "_get_parent_quirk_safe_impl",
    "_get_priority_from_parent",
    "_get_server_type_from_utilities",
    "_get_utilities",
    "logger",
]
