"""Server quirk registry using FlextRegistry class-level plugin API."""

from __future__ import annotations

import inspect
from typing import ClassVar

from flext_core import FlextLogger, r, t
from flext_core.registry import FlextRegistry

import flext_ldif.servers as servers_package
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif.protocols import p
from flext_ldif.servers._base import (
    FlextLdifServersBaseEntry,
    FlextLdifServersBaseSchema,
    FlextLdifServersBaseSchemaAcl,
)
from flext_ldif.servers.base import FlextLdifServersBase

logger = FlextLogger(__name__)


class FlextLdifServer(FlextRegistry):
    """Server quirk registry using FlextRegistry class-level plugin API."""

    SERVERS: ClassVar[str] = "ldif_servers"
    _discovery_initialized: ClassVar[bool] = False

    def __init__(
        self, dispatcher: p.CommandBus | None = None, **data: t.GeneralValueType
    ) -> None:
        """Initialize registry and trigger auto-discovery."""
        super().__init__(dispatcher=dispatcher, **data)
        if not type(self)._discovery_initialized:
            self._auto_discover()
            type(self)._discovery_initialized = True

    def _auto_discover(self) -> None:
        """Discover and register concrete quirk classes from servers package."""
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

                quirk_class = type(instance)
                if not all(hasattr(quirk_class, c) for c in ("Schema", "Acl", "Entry")):
                    continue

                self.register_class_plugin(self.SERVERS, server_type, instance)

            except (TypeError, AttributeError):
                continue

    def quirk(self, server_type: str) -> r[FlextLdifServersBase]:
        """Get base quirk for a server type."""
        try:
            normalized = FlextLdifUtilitiesServer.normalize_server_type(server_type)
        except ValueError as e:
            return r[FlextLdifServersBase].fail(str(e))
        result = self.get_class_plugin(self.SERVERS, normalized)
        if result.is_failure:
            return r[FlextLdifServersBase].fail(str(result.error))

        if isinstance(result.value, FlextLdifServersBase):
            return r[FlextLdifServersBase].ok(result.value)
        return r[FlextLdifServersBase].fail(f"Invalid quirk type: {type(result.value)}")

    def get_base_quirk(self, server_type: str) -> r[FlextLdifServersBase]:
        """Get base quirk for a given server type."""
        return self.quirk(server_type)

    def list_registered_servers(self) -> list[str]:
        """List all registered server types."""
        return sorted(self.list_class_plugins(self.SERVERS).value or [])

    def get_schema_quirk(self, server_type: str) -> FlextLdifServersBaseSchema | None:
        """Get schema quirk for a server type."""
        base = self.quirk(server_type).map_or(None)
        if base is None:
            return None
        quirk = base.schema_quirk

        if isinstance(quirk, FlextLdifServersBaseSchema):
            return quirk
        return None

    def acl(self, server_type: str) -> FlextLdifServersBaseSchemaAcl | None:
        """Get ACL quirk for a server type."""
        base = self.quirk(server_type).map_or(None)
        if base is None:
            return None
        quirk = base.acl_quirk

        if isinstance(quirk, FlextLdifServersBaseSchemaAcl):
            return quirk
        return None

    def entry(self, server_type: str) -> FlextLdifServersBaseEntry | None:
        """Get entry quirk for a server type."""
        base = self.quirk(server_type).map_or(None)
        if base is None:
            return None
        quirk = base.entry_quirk

        if isinstance(quirk, FlextLdifServersBaseEntry):
            return quirk
        return None

    def get_all_quirks(
        self,
        server_type: str,
    ) -> r[dict[str, t.GeneralValueType]]:
        """Get all quirk types for a server."""
        return self.quirk(server_type).map(
            lambda base: {
                "schema": base.schema_quirk,
                "acl": base.acl_quirk,
                "entry": base.entry_quirk,
            }
        )

    def get_constants(self, server_type: str) -> r[type]:
        """Get Constants class from server quirk."""

        def validate_constants(base: FlextLdifServersBase) -> r[type]:
            constants = getattr(type(base), "Constants", None)
            if constants is None:
                return r[type].fail(f"Server {server_type} missing Constants")
            if not hasattr(constants, "CATEGORIZATION_PRIORITY"):
                return r[type].fail(
                    f"Server {server_type} missing CATEGORIZATION_PRIORITY",
                )
            return r[type].ok(constants)

        return self.quirk(server_type).flat_map(validate_constants)

    def get_registry_stats(self) -> dict[str, t.GeneralValueType]:
        """Get comprehensive registry statistics."""
        servers = self.list_registered_servers()
        quirks_by_server: dict[str, dict[str, str | None]] = {}
        priorities: dict[str, int] = {}

        for st in servers:
            base = self.quirk(st).map_or(None)
            if base is None:
                continue
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

    _global_instance: ClassVar[FlextLdifServer | None] = None

    @classmethod
    def get_global_instance(cls) -> FlextLdifServer:
        """Get or create global registry instance."""
        if cls._global_instance is None:
            cls._global_instance = cls()
        instance = cls._global_instance
        if instance is None:
            msg = "Global FlextLdifServer instance was not initialized"
            raise RuntimeError(msg)
        return instance


__all__ = ["FlextLdifServer"]
