"""Quirk Registry for LDIF/LDAP Server Extension Discovery.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides centralized registry for discovering, registering, and composing
server-specific quirks with RFC-compliant base parsers.

Registration is handled automatically via dependency injection during
FlextLdifServer initialization. All quirk classes are auto-discovered
from the flext_ldif.servers package and registered automatically.
"""

from __future__ import annotations

import inspect
from typing import cast

from flext_core import FlextLogger, FlextResult

import flext_ldif.servers as servers_package
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.servers.base import FlextLdifServersBase

logger = FlextLogger(__name__)


class FlextLdifServer:
    """Centralized registry for LDIF/LDAP server quirks.

    Thin, DRY wrapper around auto-discovered server-specific quirks.
    Manages discovery, registration, and access to quirks for all LDAP servers.

    Features:
    - Automatic discovery from flext_ldif.servers package
    - Dynamic access to Schema/Acl/Entry quirks
    - Singleton pattern for global registry
    - Server-agnostic API for quirk operations
    - Supports RFC 4514 DN operations via quirks

    Example:
        registry = FlextLdifServer()
        schema = registry.schema("oid")     # Get OID schema quirk
        acl = registry.acl("oud")            # Get OUD ACL quirk
        entry = registry.entry("openldap")   # Get OpenLDAP entry quirk

    Note:
        All quirks are auto-discovered and registered during __init__.
        No manual registration required.

    """

    def __init__(self) -> None:
        """Initialize quirk registry with auto-discovery."""
        super().__init__()
        self._bases: dict[str, FlextLdifServersBase] = {}
        self._auto_discover_and_register()

    def _auto_discover_and_register(self) -> None:
        """Discover and register all base quirk classes.

        Scans the flext_ldif.servers package for concrete quirk implementations
        extending FlextLdifServersBase and automatically registers them.

        Process:
        1. Find all classes extending FlextLdifServersBase (except base itself)
        2. Instantiate each concrete class
        3. Register base instance in _bases dict by server_type
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
                            f"Skipping {obj.__name__}: missing Constants - {e}",
                        )
                        continue

                    # Validate that all nested quirks satisfy their protocols
                    validation_result = self._validate_protocols(instance)
                    if validation_result.is_failure:
                        logger.warning(
                            f"Skipping {obj.__name__}: protocol validation failed - "
                            f"{validation_result.error}",
                        )
                        continue

                    # Register the base quirk instance
                    self._bases[server_type] = instance
                    logger.debug(
                        f"Registered base quirk: {obj.__name__} "
                        f"(server_type={server_type}, priority={priority})",
                    )

                except TypeError:
                    # Abstract class or instantiation error - skip gracefully
                    logger.debug(f"Cannot instantiate {obj.__name__} (likely abstract)")
                except Exception as e:
                    logger.debug(f"Failed to register {obj.__name__}: {e}")

        except ImportError as e:
            logger.debug("Could not auto-discover quirks: %s", e)

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
                    f"Quirk missing Constants.SERVER_TYPE: {e}",
                )

            # Validate that all nested quirks satisfy their protocols
            validation_result = self._validate_protocols(quirk)
            if validation_result.is_failure:
                return FlextResult[None].fail(
                    f"Protocol validation failed: {validation_result.error}",
                )

            # Register in dict by server_type
            self._bases[server_type] = quirk
            logger.info(
                f"Registered base quirk: {quirk.__class__.__name__} "
                f"(server_type={server_type})",
            )
            return FlextResult[None].ok(None)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[None].fail(f"Failed to register quirk: {e}")

    def _validate_protocols(self, quirk: FlextLdifServersBase) -> FlextResult[None]:
        """Validate that quirk has all required nested quirks (schema, acl, entry).

        Args:
            quirk: Quirk instance to validate

        Returns:
            FlextResult indicating success or failure

        """
        try:
            # Check that nested quirk classes exist (capitalized class names)
            quirk_class = type(quirk)
            if not hasattr(quirk_class, "Schema"):
                return FlextResult[None].fail("Missing Schema nested class")
            if not hasattr(quirk_class, "Acl"):
                return FlextResult[None].fail("Missing Acl nested class")
            if not hasattr(quirk_class, "Entry"):
                return FlextResult[None].fail("Missing Entry nested class")

            # Verify nested classes are properly defined
            schema_class = getattr(quirk_class, "Schema", None)
            acl_class = getattr(quirk_class, "Acl", None)
            entry_class = getattr(quirk_class, "Entry", None)

            if schema_class is None or acl_class is None or entry_class is None:
                return FlextResult[None].fail("Nested quirk classes not found")

            if (
                not inspect.isclass(schema_class)
                or not inspect.isclass(acl_class)
                or not inspect.isclass(entry_class)
            ):
                return FlextResult[None].fail("Nested quirks are not classes")

            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Protocol validation error: {e}")

    def _normalize_server_type(self, server_type: str) -> str:
        """Normalize server type to canonical short form."""
        return FlextLdifConstants.ServerTypes.FROM_LONG.get(server_type, server_type)

    def _get_attr(
        self,
        server_type: str,
        attr_name: str,
    ) -> object | None:
        """Generic method to get quirk attribute (schema, acl, entry).

        Eliminates ~100 lines of DRY violations from separate get_* methods.
        """
        base = self._bases.get(self._normalize_server_type(server_type))
        return getattr(base, attr_name, None) if base else None

    # =========================================================================
    # THIN INTERFACE - Server-agnostic quirk access (no duplication)
    # =========================================================================

    def quirk(self, server_type: str) -> FlextLdifServersBase | None:
        """Get base quirk for a server type.

        Args:
            server_type: Server type (e.g., 'oid', 'oud', 'openldap')

        Returns:
            Base quirk instance or None

        """
        return self._bases.get(self._normalize_server_type(server_type))

    def schema(self, server_type: str) -> FlextLdifServersBase.Schema | None:
        """Get schema quirk for a server type.

        Args:
            server_type: Server type

        Returns:
            Schema quirk or None

        """
        result = self._get_attr(server_type, "schema")
        return cast("FlextLdifServersBase.Schema | None", result)

    def acl(self, server_type: str) -> FlextLdifServersBase.Acl | None:
        """Get ACL quirk for a server type.

        Args:
            server_type: Server type

        Returns:
            ACL quirk or None

        """
        result = self._get_attr(server_type, "acl")
        return cast("FlextLdifServersBase.Acl | None", result)

    def entry(self, server_type: str) -> FlextLdifServersBase.Entry | None:
        """Get entry quirk for a server type.

        Args:
            server_type: Server type

        Returns:
            Entry quirk or None

        """
        result = self._get_attr(server_type, "entry")
        return cast("FlextLdifServersBase.Entry | None", result)

    # =========================================================================
    # BACKWARD COMPATIBILITY - Keep old method names for now
    # =========================================================================

    def get_base(self, server_type: str) -> FlextLdifServersBase | None:
        """Deprecated: Use quirk() instead."""
        return self.quirk(server_type)

    def get_schema(self, server_type: str) -> FlextLdifServersBase.Schema | None:
        """Deprecated: Use schema() instead."""
        return self.schema(server_type)

    def get_schemas(
        self,
        server_type: str,
    ) -> list[FlextLdifServersBase.Schema]:
        """Deprecated: Use schema() and check for None instead."""
        quirk = self.schema(server_type)
        return [quirk] if quirk else []

    def get_acl(self, server_type: str) -> FlextLdifServersBase.Acl | None:
        """Deprecated: Use acl() instead."""
        return self.acl(server_type)

    def get_acls(self, server_type: str) -> list[FlextLdifServersBase.Acl]:
        """Deprecated: Use acl() and check for None instead."""
        quirk = self.acl(server_type)
        return [quirk] if quirk else []

    def get_entry(self, server_type: str) -> FlextLdifServersBase.Entry | None:
        """Deprecated: Use entry() instead."""
        return self.entry(server_type)

    def get_entrys(self, server_type: str) -> list[FlextLdifServersBase.Entry]:
        """Deprecated: Use entry() and check for None instead."""
        quirk = self.entry(server_type)
        return [quirk] if quirk else []

    def gets(self, server_type: str) -> list[FlextLdifServersBase]:
        """Get base quirk implementation for a server type."""
        normalized_type = self._normalize_server_type(server_type)
        quirk = self._bases.get(normalized_type)
        return [quirk] if quirk else []

    def get_alls_for_server(
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
            "schema": self.get_schema(server_type),
            "acl": self.get_acl(server_type),
            "entry": self.get_entry(server_type),
        }

    # =========================================================================
    # SERVER-AGNOSTIC QUIRK FINDING - Thin wrappers (no duplication)
    # =========================================================================

    def find_schema_for_attribute(
        self,
        server_type: str,
        attr_definition: str,
    ) -> FlextLdifServersBase.Schema | None:
        """Find schema quirk that handles attribute definition.

        Args:
            server_type: Server type
            attr_definition: AttributeType definition

        Returns:
            Schema quirk or None

        """
        schema = self.schema(server_type)
        if schema and schema.can_handle_attribute(attr_definition):
            return schema
        return None

    def find_schema_for_objectclass(
        self,
        server_type: str,
        oc_definition: str,
    ) -> FlextLdifServersBase.Schema | None:
        """Find schema quirk that handles objectClass definition.

        Args:
            server_type: Server type
            oc_definition: ObjectClass definition

        Returns:
            Schema quirk or None

        """
        schema = self.schema(server_type)
        if schema and schema.can_handle_objectclass(oc_definition):
            return schema
        return None

    def find_acl_for_line(
        self,
        server_type: str,
        acl_line: str,
    ) -> FlextLdifServersBase.Acl | None:
        """Find ACL quirk that handles ACL line.

        Args:
            server_type: Server type
            acl_line: ACL line

        Returns:
            ACL quirk or None

        """
        acl = self.acl(server_type)
        if acl and acl.can_handle(acl_line):
            return acl
        return None

    def find_entry_handler(
        self,
        server_type: str,
        entry_dn: str,
        attributes: dict[str, object],
    ) -> FlextLdifServersBase.Entry | None:
        """Find entry quirk that handles entry (checks all servers by priority).

        Args:
            server_type: Preferred server type
            entry_dn: Entry DN
            attributes: Entry attributes

        Returns:
            Entry quirk or None

        """
        # Check preferred server first
        entry = self.entry(server_type)
        if entry and entry.can_handle(entry_dn, attributes):
            return entry

        # Check others in priority order
        for srv_type in self.list_registered_servers():
            if srv_type == self._normalize_server_type(server_type):
                continue
            other_entry = self.entry(srv_type)
            if other_entry and other_entry.can_handle(entry_dn, attributes):
                return other_entry

        return None

    # =========================================================================
    # BACKWARD COMPATIBILITY - Old find_* method names (removed duplicates)
    # =========================================================================
    # NOTE: Removed duplicate method definitions to fix F811 errors:
    # - find_schema_for_attribute() already defined at line 338
    # - find_schema_for_objectclass() already defined at line 358
    # - find_acl_for_line() already defined at line 378
    # - find_entry_for_data() already defined at line 398

    def find_acl(
        self,
        server_type: str,
        acl_line: str,
    ) -> FlextLdifServersBase.Acl | None:
        """Deprecated: Use find_acl_for_line() instead."""
        return self.find_acl_for_line(server_type, acl_line)

    def find_entry(
        self,
        server_type: str,
        entry_dn: str,
        attributes: dict[str, object],
    ) -> FlextLdifServersBase.Entry | None:
        """Deprecated: Use find_entry_handler() instead."""
        return self.find_entry_handler(server_type, entry_dn, attributes)

    def list_registered_servers(self) -> list[str]:
        """List all server types that have registered quirks.

        Returns:
            List of server type identifiers sorted alphabetically

        """
        return sorted(self._bases.keys())

    def get_registry_stats(self) -> dict[str, object]:
        """Get statistics about registered quirks.

        Returns:
            Dict with quirk registration statistics

        """
        # Collect stats per server
        by_server: dict[str, dict[str, bool]] = {}
        for server_type, base in self._bases.items():
            by_server[server_type] = {
                "has_schema": hasattr(base, "schema"),
                "has_acl": hasattr(base, "acl"),
                "has_entry": hasattr(base, "entry"),
            }

        stats: dict[str, object] = {
            "total_servers": len(self._bases),
            "servers": list(self._bases.keys()),
            "quirks_by_server": by_server,
        }
        return stats

    class _GlobalAccess:
        """Nested singleton management for global quirk registry."""

        _instance: FlextLdifServer | None = None

        @classmethod
        def get_instance(cls) -> FlextLdifServer:
            """Get or create the global registry instance."""
            if cls._instance is None:
                cls._instance = FlextLdifServer()
            return cls._instance

    @classmethod
    def get_global_instance(cls) -> FlextLdifServer:
        """Get or create the global quirk registry instance.

        Returns:
            Global FlextLdifServer instance

        """
        return cls._GlobalAccess.get_instance()


__all__ = [
    "FlextLdifServer",
]
