"""Server quirk registry using FlextRegistry class-level plugin API.

Provides discovery and caching of server-specific quirks for LDIF processing.
Uses class-level storage for auto-discovery pattern - all instances share
the same discovered servers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import inspect
from typing import ClassVar

from flext_core import FlextLogger, FlextTypes as t, r
from flext_core.registry import FlextRegistry

import flext_ldif.servers as servers_package
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif.protocols import p
from flext_ldif.servers.base import FlextLdifServersBase

logger = FlextLogger(__name__)


class FlextLdifServer(FlextRegistry):
    """Server quirk registry using FlextRegistry class-level plugin API.

    Auto-discovers server-specific quirks from flext_ldif.servers package.
    Uses class-level storage so all instances see the same discovered servers.
    """

    SERVERS: ClassVar[str] = "ldif_servers"

    def __init__(
        self, dispatcher: p.CommandBus | None = None, **data: t.GeneralValueType
    ) -> None:
        """Initialize registry and trigger auto-discovery.

        Auto-discovery uses class-level storage (register_class_plugin) so
        it's idempotent - safe to call on every instance creation.
        """
        super().__init__(dispatcher=dispatcher, **data)
        self._auto_discover()

    def _auto_discover(self) -> None:
        """Discover and register concrete quirk classes from servers package.

        Uses register_class_plugin() for class-level storage. Registration
        is idempotent so multiple instances can call this safely.
        """
        for name, obj in inspect.getmembers(servers_package):
            if (
                name.startswith("_")
                or not inspect.isclass(obj)
                or obj is FlextLdifServersBase
                or not issubclass(obj, FlextLdifServersBase)
            ):
                continue

            try:
                instance = obj()
                server_type = getattr(instance, "server_type", None)
                if not isinstance(server_type, str):
                    continue

                # Validate nested quirk classes exist
                quirk_class = type(instance)
                if not all(hasattr(quirk_class, c) for c in ("Schema", "Acl", "Entry")):
                    continue

                self.register_class_plugin(self.SERVERS, server_type, instance)

            except (TypeError, AttributeError):
                continue

    # Core operations

    def register(self, quirk: FlextLdifServersBase) -> r[bool]:  # type: ignore[override]
        """Register a server quirk manually."""
        server_type = getattr(quirk, "server_type", None)
        if not isinstance(server_type, str):
            return r[bool].fail("Quirk missing server_type")

        quirk_class = type(quirk)
        if not all(hasattr(quirk_class, c) for c in ("Schema", "Acl", "Entry")):
            return r[bool].fail("Quirk missing nested classes")

        return self.register_class_plugin(self.SERVERS, server_type, quirk)

    def quirk(self, server_type: str) -> r[FlextLdifServersBase]:
        """Get base quirk for a server type."""
        try:
            normalized = FlextLdifUtilitiesServer.normalize_server_type(server_type)
        except ValueError as e:
            return r[FlextLdifServersBase].fail(str(e))
        result = self.get_class_plugin(self.SERVERS, normalized)
        if result.is_failure:
            return r[FlextLdifServersBase].fail(str(result.error))
        # Type narrow: get_class_plugin returns r[object]
        if isinstance(result.value, FlextLdifServersBase):
            return r[FlextLdifServersBase].ok(result.value)
        return r[FlextLdifServersBase].fail(f"Invalid quirk type: {type(result.value)}")

    def list_registered_servers(self) -> list[str]:
        """List all registered server types."""
        return sorted(self.list_class_plugins(self.SERVERS).value or [])

    # Quirk access methods

    def schema(self, server_type: str) -> p.Ldif.SchemaQuirkProtocol | None:  # type: ignore[override]
        """Get schema quirk for a server type."""
        result = self.quirk(server_type)
        if result.is_failure:
            return None
        quirk = result.value.schema_quirk
        # Use isinstance with runtime_checkable Protocol for proper type narrowing
        if isinstance(quirk, p.Ldif.SchemaQuirkProtocol):
            return quirk
        return None

    def acl(self, server_type: str) -> p.Ldif.AclQuirkProtocol | None:
        """Get ACL quirk for a server type."""
        result = self.quirk(server_type)
        if result.is_failure:
            return None
        quirk = result.value.acl_quirk
        # Use isinstance with runtime_checkable Protocol for proper type narrowing
        if isinstance(quirk, p.Ldif.AclQuirkProtocol):
            return quirk
        return None

    def entry(self, server_type: str) -> p.Ldif.EntryQuirkProtocol | None:
        """Get entry quirk for a server type."""
        result = self.quirk(server_type)
        if result.is_failure:
            return None
        quirk = result.value.entry_quirk
        # Use isinstance with runtime_checkable Protocol for proper type narrowing
        if isinstance(quirk, p.Ldif.EntryQuirkProtocol):
            return quirk
        return None

    def get_all_quirks(
        self,
        server_type: str,
    ) -> r[dict[str, object | None]]:
        """Get all quirk types for a server."""
        result = self.quirk(server_type)
        if result.is_failure:
            return r[dict[str, object | None]].fail(str(result.error))
        base = result.value
        return r[dict[str, object | None]].ok({
            "schema": base.schema_quirk,
            "acl": base.acl_quirk,
            "entry": base.entry_quirk,
        })

    def get_constants(self, server_type: str) -> r[type]:
        """Get Constants class from server quirk."""
        result = self.quirk(server_type)
        if result.is_failure:
            return r[type].fail(str(result.error))

        constants = getattr(type(result.value), "Constants", None)
        if constants is None:
            return r[type].fail(f"Server {server_type} missing Constants")

        if not hasattr(constants, "CATEGORIZATION_PRIORITY"):
            return r[type].fail(f"Server {server_type} missing CATEGORIZATION_PRIORITY")

        return r[type].ok(constants)

    def get_detection_constants(self, server_type: str) -> r[type]:
        """Get Constants class with detection attributes."""
        result = self.quirk(server_type)
        if result.is_failure:
            return r[type].fail(str(result.error))

        constants = getattr(type(result.value), "Constants", None)
        if constants is None:
            return r[type].fail(f"Server {server_type} missing Constants")

        required = ("DETECTION_PATTERN", "DETECTION_WEIGHT", "DETECTION_ATTRIBUTES")
        if not all(hasattr(constants, attr) for attr in required):
            return r[type].fail(f"Server {server_type} missing DETECTION_* attributes")

        return r[type].ok(constants)

    def get_registry_stats(self) -> dict[str, object]:
        """Get comprehensive registry statistics."""
        servers = self.list_registered_servers()
        quirks_by_server: dict[str, dict[str, str | None]] = {}
        priorities: dict[str, int] = {}

        for st in servers:
            result = self.quirk(st)
            if result.is_failure:
                continue
            base = result.value
            quirks_by_server[st] = {
                "schema": type(base.schema_quirk).__name__
                if base.schema_quirk
                else None,
                "acl": type(base.acl_quirk).__name__ if base.acl_quirk else None,
                "entry": type(base.entry_quirk).__name__ if base.entry_quirk else None,
            }
            priorities[st] = base.priority if isinstance(base.priority, int) else 0

        return {
            "total_servers": len(servers),
            "quirks_by_server": quirks_by_server,
            "server_priorities": priorities,
        }

    # Global singleton

    _global_instance: ClassVar[FlextLdifServer | None] = None

    @classmethod
    def get_global_instance(cls) -> FlextLdifServer:
        """Get or create global registry instance."""
        if cls._global_instance is None:
            cls._global_instance = cls()
        return cls._global_instance


__all__ = ["FlextLdifServer"]
