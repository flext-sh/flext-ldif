"""Server quirk registry using the canonical `p.Registry` DSL."""

from __future__ import annotations

import inspect
from collections.abc import (
    MutableMapping,
    MutableSequence,
)
from typing import ClassVar

from flext_ldif import (
    FlextLdifServersBase,
    FlextLdifServersBaseEntry,
    FlextLdifServersBaseSchema,
    FlextLdifServersBaseSchemaAcl,
    c,
    p,
    r,
    servers,
    t,
    u,
)

logger = u.fetch_logger(__name__)


class FlextLdifServer:
    """Server quirk registry using the canonical registry DSL."""

    SERVERS: ClassVar[str] = "ldif_servers"
    _discovery_initialized: ClassVar[bool] = False
    _registry: p.Registry

    def __init__(
        self,
        dispatcher: p.Dispatcher | None = None,
        **data: t.Ldif.Scalar,
    ) -> None:
        """Initialize registry and trigger auto-discovery."""
        _ = data
        self._registry = u.build_registry(dispatcher=dispatcher)
        if not type(self)._discovery_initialized:
            self._auto_discover()
            type(self)._discovery_initialized = True

    def acl(self, server_type: str) -> FlextLdifServersBaseSchemaAcl | None:
        """Get ACL quirk for a server type."""
        base = self._lookup_base_quirk(server_type)
        if base is None:
            return None
        return base.acl_quirk

    def entry(self, server_type: str) -> FlextLdifServersBaseEntry | None:
        """Get entry quirk for a server type."""
        base = self._lookup_base_quirk(server_type)
        if base is None:
            return None
        return base.entry_quirk

    def resolve_quirk_bundle(
        self,
        server_type: str,
    ) -> r[
        MutableMapping[
            str,
            FlextLdifServersBaseSchema
            | FlextLdifServersBaseSchemaAcl
            | FlextLdifServersBaseEntry,
        ]
    ]:
        """Get all quirk types for a server."""
        base = self._lookup_base_quirk(server_type)
        if base is None:
            return r[
                MutableMapping[
                    str,
                    FlextLdifServersBaseSchema
                    | FlextLdifServersBaseSchemaAcl
                    | FlextLdifServersBaseEntry,
                ]
            ].fail(f"Unknown server type: {server_type}")
        return r[
            MutableMapping[
                str,
                FlextLdifServersBaseSchema
                | FlextLdifServersBaseSchemaAcl
                | FlextLdifServersBaseEntry,
            ]
        ].ok({
            "schema": base.schema_quirk,
            "acl": base.acl_quirk,
            "entry": base.entry_quirk,
        })

    def resolve_base_quirk(self, server_type: str) -> r[FlextLdifServersBase]:
        """Get base quirk for a given server type."""
        return self.quirk(server_type)

    def resolve_server_constants(self, server_type: str) -> r[type]:
        """Get Constants class from server quirk."""
        quirk_result = self.quirk(server_type)
        if quirk_result.failure:
            return r[type].fail(quirk_result.error or server_type)
        base = quirk_result.value
        constants = getattr(type(base), "Constants", None)
        if constants is None:
            return r[type].fail(f"Server {server_type} missing Constants")
        if getattr(constants, "CATEGORIZATION_PRIORITY", None) is None:
            return r[type].fail(
                f"Server {server_type} missing CATEGORIZATION_PRIORITY",
            )
        return r[type].ok(constants)

    def summarize_registry(self) -> t.Ldif.MutableMetadataInputMapping:
        """Get comprehensive registry statistics."""
        servers = self.list_registered_servers()
        quirks_by_server: dict[str, t.JsonValue] = {}
        priorities: dict[str, t.JsonValue] = {}
        for st in servers:
            base = self._lookup_base_quirk(st)
            if base is None:
                continue
            quirks_by_server[st] = {
                "schema": type(base.schema_quirk).__name__
                if base.schema_quirk
                else None,
                "acl": type(base.acl_quirk).__name__ if base.acl_quirk else None,
                "entry": type(base.entry_quirk).__name__ if base.entry_quirk else None,
            }
            priorities[st] = base.priority
        stats: dict[str, t.JsonValue] = {
            "total_servers": len(servers),
            "quirks_by_server": quirks_by_server,
            "server_priorities": priorities,
        }
        return stats

    def schema_quirk(self, server_type: str) -> FlextLdifServersBaseSchema | None:
        """Get schema quirk for a server type."""
        return self.resolve_schema_quirk(server_type)

    def resolve_schema_quirk(
        self,
        server_type: str,
    ) -> FlextLdifServersBaseSchema | None:
        """Get schema quirk for a server type."""
        base = self._lookup_base_quirk(server_type)
        if base is None:
            return None
        return base.schema_quirk

    def _lookup_base_quirk(self, server_type: str) -> FlextLdifServersBase | None:
        """Resolve a concrete base quirk or return None on lookup failure."""
        quirk_result = self.quirk(server_type)
        if quirk_result.failure:
            return None
        return quirk_result.value

    def list_registered_servers(self) -> MutableSequence[str]:
        """List all registered server types."""
        return sorted(
            self._registry.list_plugins(
                self.SERVERS,
                scope=c.RegistrationScope.CLASS,
            ).value
            or []
        )

    def quirk(self, server_type: str) -> r[FlextLdifServersBase]:
        """Get base quirk for a server type."""
        try:
            normalized = u.Ldif.normalize_server_type(server_type)
        except ValueError as e:
            return r[FlextLdifServersBase].fail(str(e))
        plugin_result = self._registry.fetch_plugin(
            self.SERVERS,
            normalized,
            scope=c.RegistrationScope.CLASS,
        )
        if plugin_result.failure:
            return r[FlextLdifServersBase].fail(plugin_result.error or normalized)
        plugin = plugin_result.unwrap()
        if isinstance(plugin, FlextLdifServersBase):
            return r[FlextLdifServersBase].ok(plugin)
        plugin_type = type(plugin).__name__
        return r[FlextLdifServersBase].fail(f"Invalid quirk type: {plugin_type}")

    def _auto_discover(self) -> None:
        """Discover and register concrete quirk classes from servers package."""
        for name, obj in inspect.getmembers(servers):
            if (
                name.startswith("_")
                or not inspect.isclass(obj)
                or obj is FlextLdifServersBase
                or (not issubclass(obj, FlextLdifServersBase))
            ):
                continue
            try:
                instance = obj()
                server_type = getattr(instance, "server_type", None)
                if not issubclass(server_type.__class__, str):
                    continue
                quirk_class = type(instance)
                if not all(
                    getattr(quirk_class, c, None) is not None
                    for c in ("Schema", "Acl", "Entry")
                ):
                    continue
                if server_type and isinstance(server_type, str):
                    self._registry.register_plugin(
                        self.SERVERS,
                        server_type,
                        instance,
                        scope=c.RegistrationScope.CLASS,
                    )
            except (TypeError, AttributeError):
                continue

    _global_instance: ClassVar[FlextLdifServer | None] = None

    @classmethod
    def fetch_global_instance(cls) -> FlextLdifServer:
        """Return the shared registry instance, creating it on first call."""
        if cls._global_instance is None:
            cls._global_instance = cls()
        return cls._global_instance


__all__: list[str] = ["FlextLdifServer"]
