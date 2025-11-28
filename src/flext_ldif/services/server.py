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

from flext_core import (
    FlextLogger,
    FlextResult,
)

import flext_ldif.servers as servers_package
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.typings import FlextLdifTypes

logger = FlextLogger(__name__)

# Local type alias for quirks dict including concrete types from FlextLdifServersBase
type _QuirksDict = dict[
    str,
    FlextLdifServersBase.Schema
    | FlextLdifServersBase.Acl
    | FlextLdifServersBase.Entry
    | None,
]


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
        schema = registry.schema(FlextLdifConstants.ServerTypes.OID)     # Get OID schema quirk
        acl = registry.acl(FlextLdifConstants.ServerTypes.OUD)            # Get OUD ACL quirk
        entry = registry.entry(FlextLdifConstants.ServerTypes.OPENLDAP)   # Get OpenLDAP entry quirk

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
            self._bases: dict[str, FlextLdifServersBase] = FlextLdifServer._quirks_cache
            # Quirks already cached - no logging needed (reduces verbosity)
        else:
            # First initialization - perform auto-discovery and cache results
            self._bases: dict[str, FlextLdifServersBase] = {}
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
                        server_type_value = instance.server_type
                        priority_value = instance.priority
                        if not isinstance(server_type_value, str):
                            msg = f"server_type must be str, got {type(server_type_value)}"
                            raise TypeError(msg)
                        if not isinstance(priority_value, int):
                            msg = f"priority must be int, got {type(priority_value)}"
                            raise TypeError(msg)
                        server_type = server_type_value
                        priority: int = priority_value
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
                server_type_value = quirk.server_type
                if not isinstance(server_type_value, str):
                    msg = f"server_type must be str, got {type(server_type_value)}"
                    raise TypeError(msg)
                server_type: str = server_type_value
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

    def _normalize_server_type(
        self, server_type: str
    ) -> FlextLdifConstants.LiteralTypes.ServerTypeLiteral:
        """Normalize server type to canonical short form.

        Delegates to FlextLdifConstants.normalize_server_type() for proper
        normalization and validation with fast-fail on invalid types.
        """
        return FlextLdifConstants.normalize_server_type(server_type)

    def _get_attr(
        self,
        server_type: str,
        attr_name: str,
    ) -> FlextResult[
        FlextLdifTypes.SchemaQuirkInstance
        | FlextLdifTypes.AclQuirkInstance
        | FlextLdifTypes.EntryQuirkInstance
        | None
    ]:
        """Generic method to get quirk attribute (schema, acl, entry).

        Eliminates ~100 lines of DRY violations from separate get_* methods.
        Returns FlextResult to avoid None returns and provide proper error handling.
        """
        base = self._bases.get(self._normalize_server_type(server_type))
        if not base:
            return FlextResult[FlextLdifTypes.QuirkInstanceType | None].fail(
                f"No base found for server type: {server_type}"
            )
        # Quirk attributes are named with _quirk suffix: schema_quirk, acl_quirk, entry_quirk
        quirk_attr_name = f"{attr_name}_quirk"
        quirk = getattr(base, quirk_attr_name, None)
        return FlextResult[FlextLdifTypes.QuirkInstanceType | None].ok(quirk)

    # =========================================================================
    # THIN INTERFACE - Server-agnostic quirk access (no duplication)
    # =========================================================================

    def quirk(
        self, server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | str
    ) -> FlextResult[FlextLdifServersBase]:
        """Get base quirk for a server type.

        Args:
            server_type: Server type (e.g., 'oid', 'oud', 'openldap')
                Accepts ServerTypeLiteral or str for backward compatibility

        Returns:
            FlextResult with base quirk instance or error message

        """
        base = self._bases.get(self._normalize_server_type(server_type))
        if base is None:
            return FlextResult[FlextLdifServersBase].fail(
                f"No base found for server type: {server_type}"
            )
        return FlextResult[FlextLdifServersBase].ok(base)

    def get_all_quirks(self, server_type: str) -> FlextResult[_QuirksDict]:
        """Get all quirk types for a server.

        Args:
            server_type: Server type (e.g., 'oid', 'oud', 'openldap')

        Returns:
            FlextResult with dict containing 'schema', 'acl', 'entry' keys with quirk instances or None

        """
        base = self._bases.get(self._normalize_server_type(server_type))
        if not base:
            return FlextResult[_QuirksDict].fail(
                f"No base found for server type: {server_type}"
            )
        quirks_dict: _QuirksDict = {
            "schema": base.schema_quirk,
            "acl": base.acl_quirk,
            "entry": base.entry_quirk,
        }
        return FlextResult[_QuirksDict].ok(quirks_dict)

    def schema(self, server_type: str) -> FlextLdifServersBase.Schema | None:
        """Get schema quirk for a server type.

        Args:
            server_type: Server type

        Returns:
            Schema quirk or None

        """
        result = self._get_attr(server_type, "schema")
        if result.is_failure:
            return None
        quirk = result.unwrap()
        if quirk is None:
            return None
        if not isinstance(quirk, FlextLdifServersBase.Schema):
            msg = f"Expected FlextLdifServersBase.Schema, got {type(quirk)}"
            raise TypeError(msg)
        return quirk

    def acl(self, server_type: str) -> FlextLdifServersBase.Acl | None:
        """Get ACL quirk for a server type.

        Args:
            server_type: Server type

        Returns:
            ACL quirk or None

        """
        result = self._get_attr(server_type, "acl")
        if result.is_failure:
            return None
        quirk = result.unwrap()
        if quirk is None:
            return None
        if not isinstance(quirk, FlextLdifServersBase.Acl):
            msg = f"Expected FlextLdifServersBase.Acl, got {type(quirk)}"
            raise TypeError(msg)
        return quirk

    def entry(self, server_type: str) -> FlextLdifServersBase.Entry | None:
        """Get entry quirk for a server type.

        Args:
            server_type: Server type

        Returns:
            Entry quirk or None

        """
        result = self._get_attr(server_type, "entry")
        if result.is_failure:
            return None
        quirk = result.unwrap()
        if quirk is None:
            return None
        if not isinstance(quirk, FlextLdifServersBase.Entry):
            msg = f"Expected FlextLdifServersBase.Entry, got {type(quirk)}"
            raise TypeError(msg)
        return quirk

    def list_registered_servers(self) -> list[str]:
        """List all server types that have registered quirks.

        Returns:
            List of server type identifiers sorted alphabetically

        """
        return sorted(self._bases.keys())

    def get_registry_stats(
        self,
    ) -> FlextLdifTypes.Registry.RegistryStatsDict:
        """Get comprehensive registry statistics.

        Returns:
            Dictionary with registry statistics including:
            - total_servers: Number of registered server types
            - quirks_by_server: Dict mapping server types to their quirks
            - server_priorities: Dict mapping server types to their priorities

        """
        quirks_by_server: dict[str, FlextLdifTypes.Registry.QuirksByServerDict] = {}
        server_priorities: dict[str, int] = {}

        for server_type, base_quirk in self._bases.items():
            quirks_by_server[server_type] = FlextLdifTypes.Registry.QuirksByServerDict(
                schema=base_quirk.schema_quirk.__class__.__name__
                if base_quirk.schema_quirk
                else None,
                acl=base_quirk.acl_quirk.__class__.__name__
                if base_quirk.acl_quirk
                else None,
                entry=base_quirk.entry_quirk.__class__.__name__
                if base_quirk.entry_quirk
                else None,
            )
            server_priorities[server_type] = base_quirk.priority

        return FlextLdifTypes.Registry.RegistryStatsDict(
            total_servers=len(self._bases),
            quirks_by_server=quirks_by_server,
            server_priorities=server_priorities,
        )

    def get_constants(
        self, server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral
    ) -> FlextResult[type]:
        """Get Constants class from server quirk.

        Centralizes access to server-specific constants (CATEGORIZATION_PRIORITY,
        CATEGORY_OBJECTCLASSES, CATEGORIZATION_ACL_ATTRIBUTES, etc.).

        Args:
            server_type: Server type identifier (e.g., 'oid', 'oud', 'rfc')

        Returns:
            FlextResult with Constants class or error message

        """
        server_quirk = self.quirk(server_type)
        if not server_quirk:
            return FlextResult[type].fail(f"Unknown server type: {server_type}")

        quirk_class = type(server_quirk)
        constants = getattr(quirk_class, "Constants", None)
        if constants is None:
            return FlextResult[type].fail(
                f"Server type {server_type} missing Constants class",
            )

        # Validate required categorization constants
        if not hasattr(constants, "CATEGORIZATION_PRIORITY"):
            return FlextResult[type].fail(
                f"Server {server_type} missing CATEGORIZATION_PRIORITY",
            )
        if not hasattr(constants, "CATEGORY_OBJECTCLASSES"):
            return FlextResult[type].fail(
                f"Server {server_type} missing CATEGORY_OBJECTCLASSES",
            )

        return FlextResult[type].ok(constants)

    def get_detection_constants(
        self, server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral
    ) -> FlextResult[type]:
        """Get Constants class with detection attributes from server quirk.

        Used by FlextLdifDetector for server type auto-detection.

        Args:
            server_type: Server type identifier (e.g., 'oid', 'oud', 'openldap')

        Returns:
            FlextResult with Constants class containing DETECTION_* attributes or error message

        """
        server_quirk_result = self.quirk(server_type)
        if server_quirk_result.is_failure:
            return FlextResult[type].fail(
                f"Failed to get server quirk for {server_type}: {server_quirk_result.error}"
            )

        server_quirk = server_quirk_result.unwrap()
        quirk_class = type(server_quirk)
        constants = getattr(quirk_class, "Constants", None)
        if constants is None:
            return FlextResult[type].fail(
                f"Server type {server_type} missing Constants class"
            )

        # Validate detection-specific attributes
        if not (
            isinstance(constants, type)
            and hasattr(constants, "DETECTION_PATTERN")
            and hasattr(constants, "DETECTION_WEIGHT")
            and hasattr(constants, "DETECTION_ATTRIBUTES")
        ):
            return FlextResult[type].fail(
                f"Server type {server_type} Constants class missing required DETECTION_* attributes"
            )

        return FlextResult[type].ok(constants)

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
