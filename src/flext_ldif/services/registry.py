"""Quirk Registry for LDIF/LDAP Server Extension Discovery.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides centralized registry for discovering, registering, and composing
server-specific quirks with RFC-compliant base parsers.

Registration is handled automatically via dependency injection during
FlextLdifRegistry initialization. All quirk classes are auto-discovered
from the flext_ldif.servers package and registered based on their
_REGISTRY_METHOD class variable.
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING

from flext_core import FlextLogger, FlextResult

import flext_ldif.servers as servers_package
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.base import FlextLdifServersBase

logger = FlextLogger(__name__)

if TYPE_CHECKING:
    # Type aliases for quirk types
    SchemaType = FlextLdifServersBase.Schema
    AclType = FlextLdifServersBase.Acl
    EntryType = FlextLdifServersBase.Entry


class FlextLdifRegistry:
    """Centralized registry for LDIF/LDAP quirks.

    Manages discovery, registration, and composition of server-specific quirks.
    Quirks are applied in priority order to extend RFC-compliant base parsers.

    Features:
    - Automatic discovery of quirks from flext_ldif.servers package via dependency injection
    - Priority-based quirk ordering (lower number = higher priority)
    - Unified registry per server type containing schema, ACL, and entry quirks
    - Singleton pattern for global registry access via get_global_instance()
    - Dynamic quirk lookup methods for runtime composition

    Example:
        # Automatic discovery and registration on initialization
        registry = FlextLdifRegistry()

        # Query available quirks
        quirks = registry.get_schema_quirks("oid")

        # Get global singleton instance
        global_registry = FlextLdifRegistry.get_global_instance()

    Note:
        All quirks are automatically discovered and registered during __init__.
        No manual registration needed. This is a regular Python class (not a
        Pydantic model) to avoid complications with forward references and
        model validation for internal registry state.

    """

    def __init__(self) -> None:
        """Initialize quirk registry with direct quirk model instances (no dicts)."""
        # Store all quirk instances directly as lists (no dicts)
        super().__init__()
        self._quirks: list[FlextLdifProtocols.Quirks.QuirksPort] = []
        self._schema_quirks: list[SchemaType] = []
        self._acl_quirks: list[AclType] = []
        self._entrys: list[EntryType] = []

        # Auto-discover and register all quirks via dependency injection
        self._auto_discover_and_register_quirks()

    def _auto_discover_and_register_quirks(self) -> None:
        """Discover and register all quirk classes via dependency injection.

        Scans the flext_ldif.servers package for concrete quirk implementations
        and automatically registers them. This is the core DI mechanism.

        Process:
        1. Import flext_ldif.servers package
        2. Find all concrete classes extending FlextLdifServersBase.Schema/Acl/Entry
        3. Instantiate each concrete class (including nested Schema/Acl/Entry classes)
        4. Register using appropriate register_*_quirk method based on _REGISTRY_METHOD
        5. Log all registrations at debug level

        """
        try:
            # Get all members from the servers package
            for name, obj in inspect.getmembers(servers_package):
                # Skip private/internal classes, non-classes, and the base class itself
                if (
                    name.startswith("_")
                    or not inspect.isclass(obj)
                    or obj is FlextLdifServersBase
                ):
                    continue

                # Register top-level QuirkPort implementations
                try:
                    # Instantiate first, then check for protocol conformance.
                    # issubclass() is not reliable with protocols having data attributes.
                    instance = obj()
                    if isinstance(instance, FlextLdifProtocols.Quirks.QuirksPort):
                        self._quirks.append(instance)
                        self._quirks.sort(key=lambda q: q.priority)
                        logger.debug(
                            f"Auto-discovered and registered top-level quirk: {obj.__name__}"
                        )
                except TypeError:
                    # Abstract class or instantiation error - skip gracefully
                    pass
                except Exception as e:
                    logger.debug(
                        f"Failed to auto-register {obj.__name__}: {e}", exc_info=False
                    )

                # Process nested Schema/Acl/Entry classes
                for nested_name in ["Schema", "Acl", "Entry"]:
                    if hasattr(obj, nested_name):
                        nested_class = getattr(obj, nested_name)
                        if not inspect.isclass(nested_class):
                            continue

                        nested_registry_method = getattr(
                            nested_class,
                            "_REGISTRY_METHOD",
                            None,
                        )
                        if not nested_registry_method:
                            continue

                        # Try to instantiate nested class
                        try:
                            nested_instance = nested_class()

                            # Call appropriate register method
                            register_fn = getattr(self, nested_registry_method, None)
                            if register_fn:
                                register_fn(nested_instance)
                                logger.debug(
                                    f"Auto-discovered and registered {obj.__name__}.{nested_name} ({nested_registry_method})",
                                )

                        except TypeError:
                            # Abstract class or missing required fields - skip gracefully
                            pass
                        except Exception as e:
                            # Non-critical failures
                            logger.debug(
                                f"Failed to auto-register {obj.__name__}.{nested_name}: {e}",
                                exc_info=False,
                            )

        except ImportError as e:
            logger.debug("Could not auto-discover quirks: %s", e, exc_info=False)

    def register_schema_quirk(self, quirk: SchemaType) -> FlextResult[None]:
        """Register a schema quirk instance.

        Args:
            quirk: Schema quirk model instance to register

        Returns:
            FlextResult indicating success or failure

        """
        try:
            self._schema_quirks.append(quirk)
            # Sort by priority (lower number = higher priority)
            self._schema_quirks.sort(key=lambda q: q.priority)

            logger = getattr(self, "logger", None)
            if logger:
                logger.info(
                    "Registered schema quirk",
                    extra={
                        "server_type": quirk.server_type,
                        "quirk_class": quirk.__class__.__name__,
                        "priority": quirk.priority,
                    },
                )

            return FlextResult[None].ok(None)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[None].fail(f"Failed to register schema quirk: {e}")

    def register_acl_quirk(self, quirk: FlextLdifServersBase.Acl) -> FlextResult[None]:
        """Register an ACL quirk model instance.

        Args:
            quirk: ACL quirk model instance to register

        Returns:
            FlextResult indicating success or failure

        """
        try:
            self._acl_quirks.append(quirk)
            # Sort by priority (lower number = higher priority)
            self._acl_quirks.sort(key=lambda q: q.priority)

            logger = getattr(self, "logger", None)
            if logger:
                logger.info(
                    "Registered ACL quirk",
                    extra={
                        "server_type": quirk.server_type,
                        "quirk_class": quirk.__class__.__name__,
                        "priority": quirk.priority,
                    },
                )

            return FlextResult[None].ok(None)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[None].fail(f"Failed to register ACL quirk: {e}")

    def register_entry_quirk(
        self,
        quirk: FlextLdifServersBase.Entry,
    ) -> FlextResult[None]:
        """Register an entry quirk model instance.

        Args:
            quirk: Entry quirk model instance to register

        Returns:
            FlextResult indicating success or failure

        """
        try:
            self._entrys.append(quirk)
            # Sort by priority (lower number = higher priority)
            self._entrys.sort(key=lambda q: q.priority)

            logger = getattr(self, "logger", None)
            if logger:
                logger.info(
                    "Registered entry quirk",
                    extra={
                        "server_type": quirk.server_type,
                        "quirk_class": quirk.__class__.__name__,
                        "priority": quirk.priority,
                    },
                )

            return FlextResult[None].ok(None)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[None].fail(f"Failed to register entry quirk: {e}")

    def _normalize_server_type(self, server_type: str) -> str:
        """Normalize server type to canonical short form.

        Args:
            server_type: Server type (may be long or short form)

        Returns:
            Normalized server type in short form

        """
        return FlextLdifConstants.ServerTypes.FROM_LONG.get(server_type, server_type)

    def get_schema_quirks(self, server_type: str) -> list[FlextLdifServersBase.Schema]:
        """Get all schema quirks for a server type.

        Args:
            server_type: Server type (e.g., 'oid', 'oud', 'openldap', 'oracle_oud')

        Returns:
            List of schema quirks in priority order

        """
        normalized_type = self._normalize_server_type(server_type)
        return [q for q in self._schema_quirks if q.server_type == normalized_type]

    def get_acl_quirks(self, server_type: str) -> list[FlextLdifServersBase.Acl]:
        """Get all ACL quirks for a server type.

        Args:
            server_type: Server type (may be long or short form)

        Returns:
            List of ACL quirks in priority order

        """
        normalized_type = self._normalize_server_type(server_type)
        return [q for q in self._acl_quirks if q.server_type == normalized_type]

    def get_entrys(self, server_type: str) -> list[FlextLdifServersBase.Entry]:
        """Get all entry quirks for a server type.

        Args:
            server_type: Server type (may be long or short form)

        Returns:
            List of entry quirks in priority order

        """
        normalized_type = self._normalize_server_type(server_type)
        return [q for q in self._entrys if q.server_type == normalized_type]

    def get_quirks(
        self, server_type: str
    ) -> list[FlextLdifProtocols.Quirks.QuirksPort]:
        """Get all top-level quirk implementations for a server type."""
        normalized_type = self._normalize_server_type(server_type)
        return [q for q in self._quirks if q.server_type == normalized_type]

    def get_all_quirks_for_server(
        self,
        server_type: str,
    ) -> dict[
        str,
        list[FlextLdifServersBase.Schema]
        | list[FlextLdifServersBase.Acl]
        | list[FlextLdifServersBase.Entry],
    ]:
        """Get all quirks (schema, ACL, entry) for a server type.

        Args:
        server_type: Server type

        Returns:
        Dict with 'schema', 'acl', 'entry' quirk lists

        """
        return {
            "schema": self.get_schema_quirks(server_type),
            "acl": self.get_acl_quirks(server_type),
            "entry": self.get_entrys(server_type),
        }

    def find_schema_quirk_for_attribute(
        self,
        server_type: str,
        attr_definition: str,
    ) -> FlextLdifServersBase.Schema | None:
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
        self,
        server_type: str,
        oc_definition: str,
    ) -> FlextLdifServersBase.Schema | None:
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

    def find_acl_quirk(
        self,
        server_type: str,
        acl_line: str,
    ) -> FlextLdifServersBase.Acl | None:
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
        self,
        server_type: str,
        entry_dn: str,
        attributes: dict[str, object],
    ) -> FlextLdifServersBase.Entry | None:
        """Find the first entry quirk that can handle an entry.

        Checks all server types in priority order to find the best quirk
        for handling the entry, not just the specified server type.

        Args:
        server_type: Preferred server type (higher priority)
        entry_dn: Entry distinguished name
        attributes: Entry attributes

        Returns:
        First matching quirk or None

        """
        # First check the preferred server type
        for quirk in self.get_entrys(server_type):
            if quirk.can_handle_entry(entry_dn, attributes):
                return quirk

        # Then check all other server types in priority order
        all_server_types = [
            "oid",
            "oud",
            "ad",
            "openldap",
            "apache",
            "ds389",
            "novell",
            "tivoli",
            "rfc",
        ]

        for other_server_type in all_server_types:
            if other_server_type == server_type:
                continue  # Already checked above

            for quirk in self.get_entrys(other_server_type):
                if quirk.can_handle_entry(entry_dn, attributes):
                    return quirk

        return None

    def list_registered_servers(self) -> list[str]:
        """List all server types that have registered quirks.

        Returns:
            List of server type identifiers

        """
        server_types: set[str] = set()
        server_types.update(
            q.server_type for q in self._schema_quirks + self._acl_quirks + self._entrys
        )
        return sorted(server_types)

    def get_registry_stats(self) -> dict[str, object]:
        """Get statistics about registered quirks.

        Returns:
            Dict with quirk registration statistics

        """
        # Group quirks by server type
        schema_by_server: dict[str, int] = {}
        acl_by_server: dict[str, int] = {}
        entry_by_server: dict[str, int] = {}

        for schema_quirk in self._schema_quirks:
            server_type = schema_quirk.server_type
            schema_count = schema_by_server.get(server_type, 0)
            schema_by_server[server_type] = schema_count + 1

        for acl_quirk in self._acl_quirks:
            server_type = acl_quirk.server_type
            acl_count = acl_by_server.get(server_type, 0)
            acl_by_server[server_type] = acl_count + 1

        for entry_quirk in self._entrys:
            server_type = entry_quirk.server_type
            entry_count = entry_by_server.get(server_type, 0)
            entry_by_server[server_type] = entry_count + 1

        return {
            "total_servers": len(self.list_registered_servers()),
            "schema_quirks_by_server": schema_by_server,
            "acl_quirks_by_server": acl_by_server,
            "entrys_by_server": entry_by_server,
        }

    class _GlobalAccess:
        """Nested singleton management for global quirk registry."""

        _instance: FlextLdifRegistry | None = None

        @classmethod
        def get_instance(cls) -> FlextLdifRegistry:
            """Get or create the global registry instance."""
            if cls._instance is None:
                cls._instance = FlextLdifRegistry()
            return cls._instance

    @classmethod
    def get_global_instance(cls) -> FlextLdifRegistry:
        """Get or create the global quirk registry instance.

        Returns:
        Global FlextLdifRegistry instance

        """
        return cls._GlobalAccess.get_instance()


__all__ = [
    "FlextLdifRegistry",
]
