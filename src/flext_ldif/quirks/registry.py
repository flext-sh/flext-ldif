"""Quirk Registry for LDIF/LDAP Server Extension Discovery.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides centralized registry for discovering, registering, and composing
server-specific quirks with RFC-compliant base parsers.
"""

from __future__ import annotations

from flext_core import FlextLogger, FlextModels, FlextResult
from flext_ldif.quirks.base import BaseAclQuirk, BaseEntryQuirk, BaseSchemaQuirk


class QuirkRegistryService(FlextModels.Entity):
    """Centralized registry for LDIF/LDAP quirks.

    Manages discovery, registration, and composition of server-specific quirks.
    Quirks are applied in priority order to extend RFC-compliant base parsers.

    Features:
    - Auto-discovery of quirks from entry points
    - Priority-based quirk ordering
    - Conflict resolution for overlapping quirks
    - Server type detection and auto-quirk loading

    Example:
        registry = QuirkRegistryService()
        registry.register_quirk(OidSchemaQuirk(server_type="oid"))
        quirks = registry.get_quirks_for_server("oid")

    """

    def __init__(self) -> None:
        """Initialize quirk registry."""
        super().__init__()
        self._schema_quirks: dict[str, list[BaseSchemaQuirk]] = {}
        self._acl_quirks: dict[str, list[BaseAclQuirk]] = {}
        self._entry_quirks: dict[str, list[BaseEntryQuirk]] = {}
        self._logger = FlextLogger(__name__)

    def register_schema_quirk(self, quirk: BaseSchemaQuirk) -> FlextResult[None]:
        """Register a schema quirk for a server type.

        Args:
            quirk: Schema quirk instance to register

        Returns:
            FlextResult indicating success or failure

        """
        try:
            server_type = quirk.server_type
            if server_type not in self._schema_quirks:
                self._schema_quirks[server_type] = []

            self._schema_quirks[server_type].append(quirk)

            # Sort by priority (lower number = higher priority)
            self._schema_quirks[server_type].sort(key=lambda q: q.priority)

            if self._logger:
                self._logger.info(
                    f"Registered schema quirk for {server_type}",
                    extra={
                        "server_type": server_type,
                        "quirk_class": quirk.__class__.__name__,
                        "priority": quirk.priority,
                    },
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Failed to register schema quirk: {e}")

    def register_acl_quirk(self, quirk: BaseAclQuirk) -> FlextResult[None]:
        """Register an ACL quirk for a server type.

        Args:
            quirk: ACL quirk instance to register

        Returns:
            FlextResult indicating success or failure

        """
        try:
            server_type = quirk.server_type
            if server_type not in self._acl_quirks:
                self._acl_quirks[server_type] = []

            self._acl_quirks[server_type].append(quirk)

            # Sort by priority
            self._acl_quirks[server_type].sort(key=lambda q: q.priority)

            if self._logger:
                self._logger.info(
                    f"Registered ACL quirk for {server_type}",
                    extra={
                        "server_type": server_type,
                        "quirk_class": quirk.__class__.__name__,
                        "priority": quirk.priority,
                    },
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Failed to register ACL quirk: {e}")

    def register_entry_quirk(self, quirk: BaseEntryQuirk) -> FlextResult[None]:
        """Register an entry quirk for a server type.

        Args:
            quirk: Entry quirk instance to register

        Returns:
            FlextResult indicating success or failure

        """
        try:
            server_type = quirk.server_type
            if server_type not in self._entry_quirks:
                self._entry_quirks[server_type] = []

            self._entry_quirks[server_type].append(quirk)

            # Sort by priority
            self._entry_quirks[server_type].sort(key=lambda q: q.priority)

            if self._logger:
                self._logger.info(
                    f"Registered entry quirk for {server_type}",
                    extra={
                        "server_type": server_type,
                        "quirk_class": quirk.__class__.__name__,
                        "priority": quirk.priority,
                    },
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Failed to register entry quirk: {e}")

    def get_schema_quirks(self, server_type: str) -> list[BaseSchemaQuirk]:
        """Get all schema quirks for a server type.

        Args:
            server_type: Server type (e.g., 'oid', 'oud', 'openldap')

        Returns:
            List of schema quirks in priority order

        """
        return self._schema_quirks.get(server_type, [])

    def get_acl_quirks(self, server_type: str) -> list[BaseAclQuirk]:
        """Get all ACL quirks for a server type.

        Args:
            server_type: Server type

        Returns:
            List of ACL quirks in priority order

        """
        return self._acl_quirks.get(server_type, [])

    def get_entry_quirks(self, server_type: str) -> list[BaseEntryQuirk]:
        """Get all entry quirks for a server type.

        Args:
            server_type: Server type

        Returns:
            List of entry quirks in priority order

        """
        return self._entry_quirks.get(server_type, [])

    def get_all_quirks_for_server(
        self, server_type: str
    ) -> dict[str, list[BaseSchemaQuirk] | list[BaseAclQuirk] | list[BaseEntryQuirk]]:
        """Get all quirks (schema, ACL, entry) for a server type.

        Args:
            server_type: Server type

        Returns:
            Dict with 'schema', 'acl', 'entry' quirk lists

        """
        return {
            "schema": self.get_schema_quirks(server_type),
            "acl": self.get_acl_quirks(server_type),
            "entry": self.get_entry_quirks(server_type),
        }

    def find_schema_quirk_for_attribute(
        self, server_type: str, attr_definition: str
    ) -> BaseSchemaQuirk | None:
        """Find the first schema quirk that can handle an attribute definition.

        Args:
            server_type: Server type
            attr_definition: AttributeType definition string

        Returns:
            First matching quirk or None

        """
        for quirk in self.get_schema_quirks(server_type):
            if quirk.can_handle_attribute(attr_definition):
                return quirk
        return None

    def find_schema_quirk_for_objectclass(
        self, server_type: str, oc_definition: str
    ) -> BaseSchemaQuirk | None:
        """Find the first schema quirk that can handle an objectClass definition.

        Args:
            server_type: Server type
            oc_definition: ObjectClass definition string

        Returns:
            First matching quirk or None

        """
        for quirk in self.get_schema_quirks(server_type):
            if quirk.can_handle_objectclass(oc_definition):
                return quirk
        return None

    def find_acl_quirk(self, server_type: str, acl_line: str) -> BaseAclQuirk | None:
        """Find the first ACL quirk that can handle an ACL line.

        Args:
            server_type: Server type
            acl_line: ACL definition line

        Returns:
            First matching quirk or None

        """
        for quirk in self.get_acl_quirks(server_type):
            if quirk.can_handle_acl(acl_line):
                return quirk
        return None

    def find_entry_quirk(
        self, server_type: str, entry_dn: str, attributes: dict
    ) -> BaseEntryQuirk | None:
        """Find the first entry quirk that can handle an entry.

        Args:
            server_type: Server type
            entry_dn: Entry distinguished name
            attributes: Entry attributes

        Returns:
            First matching quirk or None

        """
        for quirk in self.get_entry_quirks(server_type):
            if quirk.can_handle_entry(entry_dn, attributes):
                return quirk
        return None

    def list_registered_servers(self) -> list[str]:
        """List all server types that have registered quirks.

        Returns:
            List of server type identifiers

        """
        server_types: set[str] = set()
        server_types.update(self._schema_quirks.keys())
        server_types.update(self._acl_quirks.keys())
        server_types.update(self._entry_quirks.keys())
        return sorted(server_types)

    def get_registry_stats(self) -> dict[str, object]:
        """Get statistics about registered quirks.

        Returns:
            Dict with quirk registration statistics

        """
        return {
            "total_servers": len(self.list_registered_servers()),
            "schema_quirks_by_server": {
                server: len(quirks) for server, quirks in self._schema_quirks.items()
            },
            "acl_quirks_by_server": {
                server: len(quirks) for server, quirks in self._acl_quirks.items()
            },
            "entry_quirks_by_server": {
                server: len(quirks) for server, quirks in self._entry_quirks.items()
            },
        }

    class _GlobalAccess:
        """Nested singleton management for global quirk registry."""

        _instance: QuirkRegistryService | None = None

        @classmethod
        def get_instance(cls) -> QuirkRegistryService:
            """Get or create the global registry instance."""
            if cls._instance is None:
                cls._instance = QuirkRegistryService()
            return cls._instance

    @classmethod
    def get_global_instance(cls) -> QuirkRegistryService:
        """Get or create the global quirk registry instance.

        Returns:
            Global QuirkRegistryService instance

        """
        return cls._GlobalAccess.get_instance()


__all__ = [
    "QuirkRegistryService",
]
