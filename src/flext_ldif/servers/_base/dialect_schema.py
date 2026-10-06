"""Shared dialect schema server base for pattern-driven LDAP dialects.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, override

from flext_ldif import m, u
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersDialectSchema(FlextLdifServersRfc.Schema):
    """Pattern-driven schema detection shared by LDAP dialect servers.

    Dialect families bind their ``Constants`` pattern configurations to
    ``_ATTRIBUTE_PATTERN_SETTINGS`` and ``_OBJECTCLASS_PATTERN_SETTINGS``;
    detection then flows through the centralized pattern matcher.
    """

    _ATTRIBUTE_PATTERN_SETTINGS: ClassVar[m.Ldif.ServerPatternsConfig]
    _OBJECTCLASS_PATTERN_SETTINGS: ClassVar[m.Ldif.ServerPatternsConfig]

    @override
    def can_handle_attribute(
        self,
        attr_definition: str | m.Ldif.SchemaAttribute,
    ) -> bool:
        """Detect dialect attribute definitions using bound pattern settings.

        Returns:
            The resulting ``bool``.
        """
        matches: bool = u.Ldif.matches_server_patterns(
            value=attr_definition,
            settings=self._ATTRIBUTE_PATTERN_SETTINGS,
        )
        return matches

    @override
    def can_handle_objectclass(
        self,
        oc_definition: str | m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Detect dialect objectClass definitions using bound pattern settings.

        Returns:
            The resulting ``bool``.
        """
        matches: bool = u.Ldif.matches_server_patterns(
            value=oc_definition,
            settings=self._OBJECTCLASS_PATTERN_SETTINGS,
        )
        return matches

    @classmethod
    def bind_pattern_settings(
        cls,
        attribute_settings: m.Ldif.ServerPatternsConfig,
        objectclass_settings: m.Ldif.ServerPatternsConfig,
    ) -> None:
        """Bind the dialect ``Constants`` pattern settings to this schema class.

        A nested class body cannot reference the not-yet-defined outer
        dialect class, so each dialect binds its owned settings after the
        class tree is built through this canonical binder.
        """
        cls._ATTRIBUTE_PATTERN_SETTINGS = attribute_settings
        cls._OBJECTCLASS_PATTERN_SETTINGS = objectclass_settings


__all__: list[str] = ["FlextLdifServersDialectSchema"]
