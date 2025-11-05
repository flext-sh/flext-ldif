"""Quirk Registry for LDIF/LDAP Server Extension Discovery.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides centralized registry for discovering, registering, and composing
server-specific quirks with RFC-compliant base parsers.

Registration is handled automatically via dependency injection during
FlextLdifRegistry initialization. All quirk classes are auto-discovered
from the flext_ldif.servers package and registered automatically.
"""

from __future__ import annotations

import inspect

from flext_core import FlextLogger, FlextResult

import flext_ldif.servers as servers_package
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.servers.base import FlextLdifServersBase

logger = FlextLogger(__name__)


class FlextLdifRegistry:
    """Centralized registry for LDIF/LDAP quirks.

    Manages discovery, registration, and composition of server-specific quirks.
    All quirks are stored as base FlextLdifServersBase instances and nested
    quirks (Schema/Acl/Entry) are accessed dynamically on-demand.

    Features:
    - Automatic discovery of quirks from flext_ldif.servers package via dependency injection
    - Single base quirk storage (no duplicate registrations)
    - Dynamic access to nested Schema/Acl/Entry quirks from base instances
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
        """Initialize quirk registry with base quirk instances only.

        Stores only FlextLdifServersBase instances in a dict by server_type.
        Nested Schema/Acl/Entry quirks are accessed dynamically via properties.
        """
        super().__init__()
        # Single storage: server_type → base quirk instance
        self._base_quirks: dict[str, FlextLdifServersBase] = {}

        # Auto-discover and register all base quirks
        self._auto_discover_and_register_quirks()

    def _auto_discover_and_register_quirks(self) -> None:
        """Discover and register all base quirk classes.

        Scans the flext_ldif.servers package for concrete quirk implementations
        extending FlextLdifServersBase and automatically registers them.

        Process:
        1. Find all classes extending FlextLdifServersBase (except base itself)
        2. Instantiate each concrete class
        3. Register base instance in _base_quirks dict by server_type
        4. Log all registrations at debug level

        """
        try:
            # Get all members from the servers package
            for name, obj in inspect.getmembers(servers_package):
                # Skip private/internal classes, non-classes, and the base class itself
                if (
                    name.startswith("_")
                    or not inspect.isclass(obj)
                    or obj is FlextLdifServersBase
                    or not issubclass(obj, FlextLdifServersBase)
                ):
                    continue

                # Try to instantiate and register base class
                try:
                    instance = obj()

                    # Validate it has required properties
                    try:
                        server_type = instance.server_type
                        priority = instance.priority
                    except AttributeError as e:
                        logger.warning(
                            f"Skipping {obj.__name__}: missing Constants - {e}"
                        )
                        continue

                    # Validate that all nested quirks satisfy their protocols
                    validation_result = self._validate_quirk_protocols(instance)
                    if validation_result.is_failure:
                        logger.warning(
                            f"Skipping {obj.__name__}: protocol validation failed - "
                            f"{validation_result.error}"
                        )
                        continue

                    # Register the base quirk instance
                    self._base_quirks[server_type] = instance
                    logger.debug(
                        f"Registered base quirk: {obj.__name__} "
                        f"(server_type={server_type}, priority={priority})"
                    )

                except TypeError:
                    # Abstract class or instantiation error - skip gracefully
                    logger.debug(f"Cannot instantiate {obj.__name__} (likely abstract)")
                except Exception as e:
                    logger.debug(f"Failed to register {obj.__name__}: {e}")

        except ImportError as e:
            logger.debug(f"Could not auto-discover quirks: {e}")

    def register(self, quirk: FlextLdifServersBase) -> FlextResult[None]:
        """Register a base quirk instance.

        Validates that all nested quirks (schema, acl, entry) satisfy their
        protocols before registration.

        Args:
            quirk: A FlextLdifServersBase instance to register

        Returns:
            FlextResult indicating success or failure

        """
        try:
            # Validate it has required properties by accessing server_type
            try:
                server_type = quirk.server_type
            except AttributeError as e:
                return FlextResult[None].fail(
                    f"Quirk missing Constants.SERVER_TYPE: {e}"
                )

            # Validate that all nested quirks satisfy their protocols
            validation_result = self._validate_quirk_protocols(quirk)
            if validation_result.is_failure:
                return FlextResult[None].fail(
                    f"Protocol validation failed: {validation_result.error}"
                )

            # Register in dict by server_type
            self._base_quirks[server_type] = quirk
            logger.info(
                f"Registered base quirk: {quirk.__class__.__name__} "
                f"(server_type={server_type})"
            )
            return FlextResult[None].ok(None)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[None].fail(f"Failed to register quirk: {e}")

    def _validate_quirk_protocols(
        self, quirk: FlextLdifServersBase
    ) -> FlextResult[None]:
        """Validate that all nested quirks satisfy their protocols.

        Uses isinstance() checks to verify protocol compliance at registration time.
        This ensures quirks match the structural typing contracts defined in
        FlextLdifProtocols.

        Args:
            quirk: Base quirk instance to validate

        Returns:
            FlextResult[None]: ok(None) if all quirks valid, or fail() with reason

        """
        # Validate schema quirk if present
        schema_quirk = getattr(quirk, "schema", None)
        if schema_quirk:
            # Validate that schema quirk has required core public methods
            # All schema operations use parse/write interface
            required_methods = ["parse", "write"]
            for method in required_methods:
                if not hasattr(schema_quirk, method):
                    msg = f"Schema quirk {type(schema_quirk).__name__} missing method: {method}"
                    logger.warning(msg)
                    return FlextResult.fail(msg)

        # Validate ACL quirk if present
        acl_quirk = getattr(quirk, "acl", None)
        if acl_quirk:
            # Validate that acl quirk has required core public methods
            # All ACL operations use parse/write interface
            required_methods = ["parse", "write"]
            for method in required_methods:
                if not hasattr(acl_quirk, method):
                    msg = (
                        f"ACL quirk {type(acl_quirk).__name__} missing method: {method}"
                    )
                    logger.warning(msg)
                    return FlextResult.fail(msg)

        # Validate Entry quirk if present
        entry_quirk = getattr(quirk, "entry", None)
        if entry_quirk:
            # Validate that entry quirk has required core public methods
            # All Entry operations use parse/write interface
            required_methods = ["parse", "write"]
            for method in required_methods:
                if not hasattr(entry_quirk, method):
                    msg = f"Entry quirk {type(entry_quirk).__name__} missing method: {method}"
                    logger.warning(msg)
                    return FlextResult.fail(msg)

        return FlextResult.ok(None)

    def _normalize_server_type(self, server_type: str) -> str:
        """Normalize server type to canonical short form.

        Args:
            server_type: Server type (may be long or short form)

        Returns:
            Normalized server type in short form

        """
        return FlextLdifConstants.ServerTypes.FROM_LONG.get(server_type, server_type)

    def _get_base_quirk(self, server_type: str) -> FlextLdifServersBase | None:
        """Get base quirk instance for server type.

        Args:
            server_type: Server type (may be long or short form)

        Returns:
            Base quirk instance or None if not registered

        """
        normalized_type = self._normalize_server_type(server_type)
        return self._base_quirks.get(normalized_type)

    def get_schema_quirk(self, server_type: str) -> FlextLdifServersBase.Schema | None:
        """Get schema quirk for a server type.

        Args:
            server_type: Server type (e.g., 'oid', 'oud', 'openldap')

        Returns:
            Schema quirk instance or None

        """
        base = self._get_base_quirk(server_type)
        if base and hasattr(base, "schema"):
            # Use getattr to avoid Pydantic schema attribute confusion
            schema_attr = getattr(base, "schema", None)
            if isinstance(schema_attr, FlextLdifServersBase.Schema):
                return schema_attr
        return None

    def get_schema_quirks(self, server_type: str) -> list[FlextLdifServersBase.Schema]:
        """Get all schema quirks for a server type.

        Args:
            server_type: Server type (e.g., 'oid', 'oud', 'openldap')

        Returns:
            List of schema quirks (will be 0 or 1 item per server type)

        """
        quirk = self.get_schema_quirk(server_type)
        return [quirk] if quirk else []

    def get_acl_quirk(self, server_type: str) -> FlextLdifServersBase.Acl | None:
        """Get ACL quirk for a server type.

        Args:
            server_type: Server type (may be long or short form)

        Returns:
            ACL quirk instance or None

        """
        base = self._get_base_quirk(server_type)
        if base and hasattr(base, "acl"):
            acl_attr = getattr(base, "acl", None)
            if isinstance(acl_attr, FlextLdifServersBase.Acl):
                return acl_attr
        return None

    def get_acl_quirks(self, server_type: str) -> list[FlextLdifServersBase.Acl]:
        """Get all ACL quirks for a server type.

        Args:
            server_type: Server type (may be long or short form)

        Returns:
            List of ACL quirks (will be 0 or 1 item per server type)

        """
        quirk = self.get_acl_quirk(server_type)
        return [quirk] if quirk else []

    def get_entry_quirk(self, server_type: str) -> FlextLdifServersBase.Entry | None:
        """Get entry quirk for a server type.

        Args:
            server_type: Server type (may be long or short form)

        Returns:
            Entry quirk instance or None

        """
        base = self._get_base_quirk(server_type)
        if base and hasattr(base, "entry"):
            entry_attr = getattr(base, "entry", None)
            if isinstance(entry_attr, FlextLdifServersBase.Entry):
                return entry_attr
        return None

    def get_entrys(self, server_type: str) -> list[FlextLdifServersBase.Entry]:
        """Get all entry quirks for a server type.

        Args:
            server_type: Server type (may be long or short form)

        Returns:
            List of entry quirks (will be 0 or 1 item per server type)

        """
        quirk = self.get_entry_quirk(server_type)
        return [quirk] if quirk else []

    def get_quirks(self, server_type: str) -> list[FlextLdifServersBase]:
        """Get base quirk implementation for a server type."""
        normalized_type = self._normalize_server_type(server_type)
        quirk = self._base_quirks.get(normalized_type)
        return [quirk] if quirk else []

    def get_all_quirks_for_server(
        self,
        server_type: str,
    ) -> dict[
        str,
        FlextLdifServersBase.Schema
        | FlextLdifServersBase.Acl
        | FlextLdifServersBase.Entry
        | None,
    ]:
        """Get all quirks (schema, ACL, entry) for a server type.

        Args:
            server_type: Server type

        Returns:
            Dict with 'schema', 'acl', 'entry' quirk instances

        """
        return {
            "schema": self.get_schema_quirk(server_type),
            "acl": self.get_acl_quirk(server_type),
            "entry": self.get_entry_quirk(server_type),
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
        quirk = self.get_schema_quirk(server_type)
        if quirk and quirk._can_handle_attribute(attr_definition):
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
        quirk = self.get_schema_quirk(server_type)
        if quirk and quirk._can_handle_objectclass(oc_definition):
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
        quirk = self.get_acl_quirk(server_type)
        if quirk and quirk.__can_handle(acl_line):
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
        quirk = self.get_entry_quirk(server_type)
        if quirk and quirk._can_handle_entry(entry_dn, attributes):
            return quirk

        # Then check all other server types in priority order
        all_server_types = self.list_registered_servers()

        for other_server_type in all_server_types:
            if other_server_type == self._normalize_server_type(server_type):
                continue  # Already checked above

            other_quirk = self.get_entry_quirk(other_server_type)
            if other_quirk and other_quirk._can_handle_entry(entry_dn, attributes):
                return other_quirk

        return None

    def list_registered_servers(self) -> list[str]:
        """List all server types that have registered quirks.

        Returns:
            List of server type identifiers sorted alphabetically

        """
        return sorted(self._base_quirks.keys())

    def get_registry_stats(self) -> dict[str, object]:
        """Get statistics about registered quirks.

        Returns:
            Dict with quirk registration statistics

        """
        # Collect stats per server
        by_server: dict[str, dict[str, bool]] = {}
        for server_type, base_quirk in self._base_quirks.items():
            by_server[server_type] = {
                "has_schema": hasattr(base_quirk, "schema"),
                "has_acl": hasattr(base_quirk, "acl"),
                "has_entry": hasattr(base_quirk, "entry"),
            }

        stats: dict[str, object] = {
            "total_servers": len(self._base_quirks),
            "servers": list(self._base_quirks.keys()),
            "quirks_by_server": by_server,
        }
        return stats

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
