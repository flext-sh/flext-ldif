"""Quirk Registry for LDIF/LDAP Server Extension Discovery.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides centralized registry for discovering, registering, and accessing
server-specific quirks with RFC-compliant base parsers.

Registration is handled automatically during FlextLdifServer initialization.
All quirk classes are auto-discovered from the flext_ldif.servers package
and registered automatically.
"""

from __future__ import annotations

import inspect
from typing import cast

from flext_core import (
    FlextLogger,
    FlextResult,
)

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
    - Idempotent registration: quirks registered only once per process

    Example:
        registry = FlextLdifServer()
        schema = registry.schema("oid")     # Get OID schema quirk
        acl = registry.acl("oud")            # Get OUD ACL quirk
        entry = registry.entry("openldap")   # Get OpenLDAP entry quirk

    Note:
        All quirks are auto-discovered and registered during __init__.
        No manual registration required. Quirks are cached at class level
        for efficient reuse across multiple instances.

    """

    # Class-level cache for idempotent registration (shared across all instances)
    _quirks_cache: dict[str, FlextLdifServersBase] | None = None
    _registration_complete: bool = False

    def __init__(self) -> None:
        """Initialize quirk registry with auto-discovery (idempotent)."""
        # Use class-level cache if already initialized
        if FlextLdifServer._quirks_cache is not None:
            self._bases = FlextLdifServer._quirks_cache
            # Quirks already cached - no logging needed (reduces verbosity)
        else:
            # First initialization - perform auto-discovery and cache results
            self._bases = {}
            self._auto_discover_and_register()
            # Cache at class level for all future instances
            FlextLdifServer._quirks_cache = self._bases
            FlextLdifServer._registration_complete = True
            logger.info(
                "Quirks registry initialized and cached for reuse",
                quirks_count=len(self._bases),
            )

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
                        # Descriptors return str/int when accessed
                        server_type = cast("str", instance.server_type)
                        priority = cast("int", instance.priority)
                    except AttributeError as e:
                        logger.warning(
                            "Skipping quirk: missing Constants",
                            quirk_name=obj.__name__,
                            error=str(e),
                        )
                        continue

                    # Validate that all nested quirks satisfy their protocols
                    validation_result = self._validate_protocols(instance)
                    if validation_result.is_failure:
                        logger.warning(
                            "Skipping quirk: protocol validation failed",
                            quirk_name=obj.__name__,
                            error=str(validation_result.error),
                        )
                        continue

                    # Register the base quirk instance
                    self._bases[server_type] = instance
                    logger.debug(
                        "Registered base quirk",
                        quirk_name=obj.__name__,
                        server_type=server_type,
                        priority=priority,
                    )

                except TypeError:
                    # Abstract class or instantiation error - skip gracefully
                    logger.debug(
                        "Cannot instantiate quirk (likely abstract)",
                        quirk_name=obj.__name__,
                    )
                except Exception as e:
                    logger.debug(
                        "Failed to register quirk",
                        quirk_name=obj.__name__,
                        error=str(e),
                    )

        except Exception as e:
            logger.exception(
                "Failed to auto-discover quirks",
                error=str(e),
            )
            raise

    def register(self, quirk: FlextLdifServersBase) -> FlextResult[bool]:
        """Register a base quirk instance.

        Validates that all nested quirks (schema, acl, entry) satisfy their
        protocols before registration.

        Args:
            quirk: A FlextLdifServersBase instance to register

        Returns:
            FlextResult[bool] with True on success, fail() on failure

        """
        try:
            # Validate it has required properties by accessing server_type
            try:
                # Descriptor returns str when accessed
                server_type = cast("str", quirk.server_type)
            except AttributeError as e:
                return FlextResult[bool].fail(
                    f"Quirk missing Constants.SERVER_TYPE: {e}",
                )

            # Validate that all nested quirks satisfy their protocols
            validation_result = self._validate_protocols(quirk)
            if validation_result.is_failure:
                return FlextResult[bool].fail(
                    f"Protocol validation failed: {validation_result.error}",
                )

            # Register in dict by server_type
            self._bases[server_type] = quirk
            logger.info(
                "Registered base quirk",
                quirk_name=quirk.__class__.__name__,
                server_type=server_type,
            )
            return FlextResult[bool].ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[bool].fail(f"Failed to register quirk: {e}")

    def _validate_protocols(self, quirk: FlextLdifServersBase) -> FlextResult[bool]:
        """Validate that quirk has all required nested quirks (schema, acl, entry).

        Args:
            quirk: Quirk instance to validate

        Returns:
            FlextResult[bool] with True on success, fail() on failure

        """
        try:
            # Check that nested quirk classes exist (capitalized class names)
            quirk_class = type(quirk)
            if not hasattr(quirk_class, "Schema"):
                return FlextResult[bool].fail("Missing Schema nested class")
            if not hasattr(quirk_class, "Acl"):
                return FlextResult[bool].fail("Missing Acl nested class")
            if not hasattr(quirk_class, "Entry"):
                return FlextResult[bool].fail("Missing Entry nested class")

            # Verify nested classes are properly defined
            schema_class = getattr(quirk_class, "Schema", None)
            acl_class = getattr(quirk_class, "Acl", None)
            entry_class = getattr(quirk_class, "Entry", None)

            if schema_class is None or acl_class is None or entry_class is None:
                return FlextResult[bool].fail("Nested quirk classes not found")

            if (
                not inspect.isclass(schema_class)
                or not inspect.isclass(acl_class)
                or not inspect.isclass(entry_class)
            ):
                return FlextResult[bool].fail("Nested quirks are not classes")

            return FlextResult[bool].ok(True)
        except Exception as e:
            return FlextResult[bool].fail(f"Protocol validation error: {e}")

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
        if not base:
            return None
        # Quirk attributes are named with _quirk suffix: schema_quirk, acl_quirk, entry_quirk
        quirk_attr_name = f"{attr_name}_quirk"
        return getattr(base, quirk_attr_name, None)

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

    def get_all_quirks(self, server_type: str) -> dict[str, object]:
        """Get all quirk types for a server.

        Args:
            server_type: Server type (e.g., 'oid', 'oud', 'openldap')

        Returns:
            Dict with 'schema', 'acl', 'entry' keys containing quirk instances

        """
        base = self._bases.get(self._normalize_server_type(server_type))
        if not base:
            return {}
        return {
            "schema": base.schema_quirk,
            "acl": base.acl_quirk,
            "entry": base.entry_quirk,
        }

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
    # SERVER-AGNOSTIC QUIRK FINDING
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
        # Type narrowing: acl is FlextLdifServersBase.Acl
        # Check if it has can_handle method (all Acl quirks should have it)
        can_handle_method = (
            getattr(acl, "can_handle", None) if acl is not None else None
        )
        if can_handle_method and can_handle_method(acl_line):
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

    def list_registered_servers(self) -> list[str]:
        """List all server types that have registered quirks.

        Returns:
            List of server type identifiers sorted alphabetically

        """
        return sorted(self._bases.keys())

    def get_registry_stats(self) -> dict[str, object]:
        """Get comprehensive registry statistics.

        Returns:
            Dictionary with registry statistics including:
            - total_servers: Number of registered server types
            - quirks_by_server: Dict mapping server types to their quirks
            - server_priorities: Dict mapping server types to their priorities

        """
        quirks_by_server = {}
        server_priorities = {}

        for server_type, base_quirk in self._bases.items():
            quirks_by_server[server_type] = {
                "schema": base_quirk.schema_quirk.__class__.__name__
                if base_quirk.schema_quirk
                else None,
                "acl": base_quirk.acl_quirk.__class__.__name__
                if base_quirk.acl_quirk
                else None,
                "entry": base_quirk.entry_quirk.__class__.__name__
                if base_quirk.entry_quirk
                else None,
            }
            server_priorities[server_type] = base_quirk.priority

        return {
            "total_servers": len(self._bases),
            "quirks_by_server": quirks_by_server,
            "server_priorities": server_priorities,
        }

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
