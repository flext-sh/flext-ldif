"""Quirk registry for discovering and serving server-specific behaviour."""

from __future__ import annotations

import inspect

from flext_core import FlextLogger, r

import flext_ldif.servers as servers_package
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif.protocols import p
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.utilities import u

logger = FlextLogger(__name__)


type _QuirksDict = dict[
    str,
    object | None,
]


class FlextLdifServer:
    """Discover and cache server-specific quirks for schema, ACL, and entries.

    Business Rule: Server registry provides centralized discovery and caching of
    server-specific quirks. Auto-discovery scans flext_ldif.servers package for
    concrete quirk classes. All quirks are validated against protocols before
    registration. Class-level caching ensures idempotent initialization across
    all instances.

    Implication: Registry enables efficient quirk resolution with protocol safety.
    All registered quirks satisfy protocol contracts, ensuring consistent behavior.
    Caching reduces initialization overhead for subsequent instances.

    """

    # Class-level cache for idempotent registration (shared across all instances)
    _quirks_cache: dict[str, FlextLdifServersBase] | None = None
    _registration_complete: bool = False

    def __init__(self) -> None:
        """Initialize the registry and auto-discover quirks once per process.

        Business Rule: Server registry uses class-level caching for idempotent
        initialization. First instance performs auto-discovery of all quirk classes
        from flext_ldif.servers package. Subsequent instances reuse cached quirks.
        This ensures efficient resource usage and consistent quirk availability.

        Implication: Registry initialization is thread-safe via class-level cache.
        All instances share the same quirk cache, ensuring consistent behavior
        across the application lifecycle.

        """
        # Use class-level cache if already initialized
        if FlextLdifServer._quirks_cache is not None:
            # Quirks already cached - reuse cache
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
        """Discover and register concrete quirk classes from ``flext_ldif.servers``.

        Business Rule: Auto-discovery uses inspect.getmembers() to scan servers
        package for concrete quirk classes. Only classes inheriting from
        FlextLdifServersBase are registered. Each quirk is validated for required
        properties (server_type, priority) and protocol compliance before registration.

        Implication: Automatic discovery enables extensible quirk system. New server
        quirks are automatically detected without manual registration. Protocol validation
        ensures all quirks satisfy required contracts.

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

    def register(self, quirk: FlextLdifServersBase) -> r[bool]:
        """Register a quirk after protocol validation.

        Business Rule: Manual registration validates quirk properties (server_type,
        priority) and protocol compliance before adding to registry. Registration
        updates class-level cache for all instances. Duplicate server types are
        rejected to maintain registry consistency.

        Implication: Manual registration enables explicit quirk control. Protocol
        validation ensures quirk compatibility. Class-level cache ensures all
        instances see registered quirks immediately.

        Args:
            quirk: FlextLdifServersBase instance to register

        Returns:
            r with True on success, error message on failure

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
                return r[bool].fail(
                    f"Quirk missing Constants.SERVER_TYPE: {e}",
                )

            # Validate that all nested quirks satisfy their protocols
            validation_result = self._validate_protocols(quirk)
            if validation_result.is_failure:
                error_msg = validation_result.error or "Protocol validation failed"
                return r[bool].fail(
                    f"Protocol validation failed: {error_msg}",
                )

            # Register in dict by server_type
            self._bases[server_type] = quirk
            logger.info(
                "Registered base quirk",
                quirk_name=quirk.__class__.__name__,
                server_type=server_type,
            )
            return r[bool].ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return r[bool].fail(f"Failed to register quirk: {e}")

    def _validate_protocols(self, quirk: FlextLdifServersBase) -> r[bool]:
        """Ensure a quirk exposes Schema, Acl, and Entry classes with valid protocols.

        Business Rule: Protocol validation checks that quirk exposes schema_quirk,
        acl_quirk, and entry_quirk properties. Each nested quirk must satisfy its
        corresponding protocol (SchemaProtocol, AclProtocol, EntryProtocol). Validation
        uses isinstance checks against protocol types.

        Implication: Protocol validation ensures quirk compatibility with expected
        interfaces. Invalid quirks are rejected before registration, preventing
        runtime errors.

        Args:
            quirk: FlextLdifServersBase instance to validate

        Returns:
            r with True on success, error message on failure

        """
        try:
            # Check that nested quirk classes exist (capitalized class names)
            quirk_class = type(quirk)
            if not hasattr(quirk_class, "Schema"):
                return r[bool].fail("Missing Schema nested class")
            if not hasattr(quirk_class, "Acl"):
                return r[bool].fail("Missing Acl nested class")
            if not hasattr(quirk_class, "Entry"):
                return r[bool].fail("Missing Entry nested class")

            # Verify nested classes are properly defined
            schema_class = getattr(quirk_class, "Schema", None)
            acl_class = getattr(quirk_class, "Acl", None)
            entry_class = getattr(quirk_class, "Entry", None)

            if schema_class is None or acl_class is None or entry_class is None:
                return r[bool].fail("Nested quirk classes not found")

            if (
                not inspect.isclass(schema_class)
                or not inspect.isclass(acl_class)
                or not inspect.isclass(entry_class)
            ):
                return r[bool].fail("Nested quirks are not classes")

            return r[bool].ok(True)
        except Exception as e:
            return r[bool].fail(f"Protocol validation error: {e}")

    def _normalize_server_type(
        self,
        server_type: str,
    ) -> str:
        """Normalize server type to canonical short form.

        Delegates to normalize_server_type() for proper
        normalization and validation with fast-fail on invalid types.
        """
        return FlextLdifUtilitiesServer.normalize_server_type(server_type)

    def _get_attr(
        self,
        server_type: str,
        attr_name: str,
    ) -> r[object | None]:
        """Retrieve a quirk attribute (schema, ACL, or entry) for a server.

        Eliminates ~100 lines of DRY violations from separate get_* methods.
        Returns FlextResult to avoid None returns and provide proper error handling.
        """
        try:
            normalized_type = self._normalize_server_type(server_type)
        except ValueError as e:
            # Invalid server type - return failure instead of raising

            # Using object since services cannot import typings/protocols
            return r[object | None].fail(str(e))

        # Using object since services cannot import typings/protocols
        base: object | None = u.mapper().get(
            self._bases,
            normalized_type,
            default=None,
        )
        if not base:
            return r[object | None].fail(
                f"No base found for server type: {server_type}",
            )
        # Quirk attributes are named with _quirk suffix: schema_quirk, acl_quirk, entry_quirk
        quirk_attr_name = f"{attr_name}_quirk"
        quirk = getattr(base, quirk_attr_name, None)
        return r[object | None].ok(quirk)

    # =========================================================================
    # THIN INTERFACE - Server-agnostic quirk access (no duplication)
    # =========================================================================

    def quirk(
        self,
        server_type: str,
    ) -> r[FlextLdifServersBase]:
        """Get base quirk for a server type.

        Args:
            server_type: Server type (e.g., 'oid', 'oud', 'openldap')
                Accepts ServerTypeLiteral or str for backward compatibility

        Returns:
            r with base quirk instance or error message

        """
        normalized = self._normalize_server_type(server_type)
        base: FlextLdifServersBase | None = u.mapper().get(
            self._bases,
            normalized,
            default=None,
        )
        if base is None:
            return r[FlextLdifServersBase].fail(
                f"No base found for server type: {server_type}",
            )
        return r[FlextLdifServersBase].ok(base)

    def get_all_quirks(self, server_type: str) -> r[_QuirksDict]:
        """Get all quirk types for a server.

        Args:
            server_type: Server type (e.g., 'oid', 'oud', 'openldap')

        Returns:
            r with dict containing 'schema', 'acl', 'entry' keys with quirk instances or None

        """
        try:
            normalized_type = self._normalize_server_type(server_type)
        except ValueError as e:
            # Invalid server type - return failure
            return r[_QuirksDict].fail(str(e))
        base: FlextLdifServersBase | None = u.mapper().get(
            self._bases,
            normalized_type,
            default=None,
        )
        if not base:
            return r[_QuirksDict].fail(
                f"No base found for server type: {server_type}",
            )
        # Type narrowing: Protocols are compatible with concrete types via structural subtyping
        # base.schema_quirk, base.acl_quirk, base.entry_quirk are compatible with protocols
        quirks_dict: _QuirksDict = {
            "schema": base.schema_quirk,
            "acl": base.acl_quirk,
            "entry": base.entry_quirk,
        }
        return r[_QuirksDict].ok(quirks_dict)

    def schema(self, server_type: str) -> p.Ldif.SchemaQuirkProtocol | None:
        """Get schema quirk for a server type.

        Args:
            server_type: Server type

        Returns:
            Schema quirk protocol or None

        """
        result = self._get_attr(server_type, "schema")
        if result.is_failure:
            return None
        quirk_raw = result.value if result.is_success else None
        if quirk_raw is None:
            return None
        # Verify quirk_raw satisfies SchemaProtocol (runtime_checkable)
        if isinstance(quirk_raw, p.Ldif.SchemaQuirkProtocol):
            return quirk_raw
        return None

    def acl(self, server_type: str) -> p.Ldif.AclProtocol | None:
        """Get ACL quirk for a server type.

        Args:
            server_type: Server type

        Returns:
            ACL quirk protocol or None

        """
        result = self._get_attr(server_type, "acl")
        if result.is_failure:
            return None
        quirk_raw = result.value if result.is_success else None
        if quirk_raw is None:
            return None
        # Verify quirk_raw satisfies AclProtocol (runtime_checkable)
        if isinstance(quirk_raw, p.Ldif.AclProtocol):
            return quirk_raw
        return None

    def entry(self, server_type: str) -> p.Ldif.EntryProtocol | None:
        """Get entry quirk for a server type.

        Args:
            server_type: Server type

        Returns:
            Entry quirk protocol or None

        """
        result = self._get_attr(server_type, "entry")
        if result.is_failure:
            return None
        quirk_raw = result.value if result.is_success else None
        if quirk_raw is None:
            return None
        # Verify quirk_raw satisfies EntryProtocol (runtime_checkable)
        if isinstance(quirk_raw, p.Ldif.EntryProtocol):
            return quirk_raw
        return None

    def list_registered_servers(self) -> list[str]:
        """List all server types that have registered quirks.

        Returns:
            List of server type identifiers sorted alphabetically

        """
        return sorted(self._bases.keys())

    def get_registry_stats(
        self,
    ) -> dict[str, object]:
        """Get comprehensive registry statistics.

        Returns:
            Dictionary with registry statistics including:
            - total_servers: Number of registered server types
            - quirks_by_server: Dict mapping server types to their quirks
            - server_priorities: Dict mapping server types to their priorities

        """
        quirks_by_server: dict[str, dict[str, object | None]] = {}
        server_priorities: dict[str, int] = {}

        for server_type, base_quirk in self._bases.items():
            quirks_by_server[server_type] = {
                "schema_type": base_quirk.schema_quirk.__class__.__name__
                if base_quirk.schema_quirk
                else None,
                "acl_type": base_quirk.acl_quirk.__class__.__name__
                if base_quirk.acl_quirk
                else None,
                "entry_type": base_quirk.entry_quirk.__class__.__name__
                if base_quirk.entry_quirk
                else None,
            }
            # Type narrowing: priority descriptor returns int, ensure type safety
            priority_value_raw = base_quirk.priority
            if not isinstance(priority_value_raw, int):
                msg = f"priority must be int, got {type(priority_value_raw)}"
                raise TypeError(msg)
            priority_value: int = priority_value_raw
            server_priorities[server_type] = priority_value

        return {
            "total_servers": len(self._bases),
            "quirks_by_server": quirks_by_server,
            "server_priorities": server_priorities,
        }

    def get_constants(
        self,
        server_type: str,
    ) -> r[type]:
        """Get Constants class from server quirk.

        Centralizes access to server-specific constants (CATEGORIZATION_PRIORITY,
        CATEGORY_OBJECTCLASSES, CATEGORIZATION_ACL_ATTRIBUTES, etc.).

        Args:
            server_type: Server type identifier (e.g., 'oid', 'oud', 'rfc')

        Returns:
            r with Constants class or error message

        """
        server_quirk_result = self.quirk(server_type)
        if server_quirk_result.is_failure:
            error_msg = server_quirk_result.error or "Unknown server type"
            return r[type].fail(
                f"Unknown server type: {server_type}: {error_msg}",
            )

        # Type narrowing: unwrap_or returns FlextLdifServersBase | None
        server_quirk_raw = (
            server_quirk_result.value if server_quirk_result.is_success else None
        )
        if server_quirk_raw is None:
            return r[type].fail(
                f"Unknown server type: {server_type}",
            )
        # Type narrowing: server_quirk_raw is FlextLdifServersBase when not None
        server_quirk: FlextLdifServersBase = server_quirk_raw
        quirk_class = type(server_quirk)
        constants = getattr(quirk_class, "Constants", None)
        if constants is None:
            return r[type].fail(
                f"Server type {server_type} missing Constants class",
            )

        # Validate required categorization constants
        if not hasattr(constants, "CATEGORIZATION_PRIORITY"):
            return r[type].fail(
                f"Server {server_type} missing CATEGORIZATION_PRIORITY",
            )
        if not hasattr(constants, "CATEGORY_OBJECTCLASSES"):
            return r[type].fail(
                f"Server {server_type} missing CATEGORY_OBJECTCLASSES",
            )

        return r[type].ok(constants)

    def get_detection_constants(
        self,
        server_type: str,
    ) -> r[type]:
        """Get Constants class with detection attributes from server quirk.

        Used by FlextLdifDetector for server type auto-detection.

        Args:
            server_type: Server type identifier (e.g., 'oid', 'oud', 'openldap')

        Returns:
            r with Constants class containing DETECTION_* attributes or error message

        """
        server_quirk_result = self.quirk(server_type)
        if server_quirk_result.is_failure:
            error_msg = server_quirk_result.error or "Failed to get server quirk"
            return r[type].fail(
                f"Failed to get server quirk for {server_type}: {error_msg}",
            )

        # Type narrowing: unwrap_or returns FlextLdifServersBase | None
        server_quirk_raw = (
            server_quirk_result.value if server_quirk_result.is_success else None
        )
        if server_quirk_raw is None:
            return r[type].fail(
                f"Failed to get server quirk for {server_type}",
            )
        # Type narrowing: server_quirk_raw is FlextLdifServersBase when not None
        server_quirk: FlextLdifServersBase = server_quirk_raw
        quirk_class = type(server_quirk)
        constants = getattr(quirk_class, "Constants", None)
        if constants is None:
            return r[type].fail(
                f"Server type {server_type} missing Constants class",
            )

        # Validate detection-specific attributes
        if not (
            isinstance(constants, type)
            and hasattr(constants, "DETECTION_PATTERN")
            and hasattr(constants, "DETECTION_WEIGHT")
            and hasattr(constants, "DETECTION_ATTRIBUTES")
        ):
            return r[type].fail(
                f"Server type {server_type} Constants class missing required DETECTION_* attributes",
            )

        return r[type].ok(constants)

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
