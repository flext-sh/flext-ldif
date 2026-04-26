"""Shared utilities for flext-ldif domain.

This module provides a single class of shared helpers importable by
models and utilities without circular dependencies.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

from flext_cli import t
from flext_ldif import c


class _MissingSentinel:
    pass


_MISSING_ATTR: Final[_MissingSentinel] = _MissingSentinel()


class FlextLdifShared:
    """Shared LDIF helpers — single class per module (no loose functions)."""

    @staticmethod
    def _has_attr(obj: t.JsonValue, attr_name: str) -> bool:
        """Check if an object has a non-None attribute (canonical implementation).

        Uses a sentinel t.JsonValue to distinguish between attributes that are None
        and attributes that don't exist at all.
        """
        return getattr(obj, attr_name, _MISSING_ATTR) is not _MISSING_ATTR

    @staticmethod
    def normalize_server_type(server_type: str) -> c.Ldif.ServerTypes:
        """Normalize server type string to canonical ServerTypes enum member.

        Converts aliases and variations to canonical enum member:
        - "active_directory", "ad", "ActiveDirectory" → ServerTypes.AD
        - "oracle_oid", "oid", "OID" → ServerTypes.OID
        - etc.

        Returns canonical ServerTypes enum member. Since ServerTypes is a StrEnum,
        the returned value can be used directly as a string in comparisons.
        Raises ValueError if server_type is not recognized.
        """
        server_type_lower = server_type.lower().strip()
        alias_value = c.Ldif.SERVER_TYPE_ALIASES.get(server_type_lower)
        if alias_value is not None:
            return alias_value
        try:
            return c.Ldif.ServerTypes(server_type_lower)
        except ValueError as error:
            valid_types = [server_type.value for server_type in c.Ldif.ServerTypes]
            msg = f"Invalid server type: {server_type}. Valid types: {valid_types}"
            raise ValueError(msg) from error


__all__: list[str] = ["FlextLdifShared"]
