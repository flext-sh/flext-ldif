"""Server server registry using the canonical `p.Registry` DSL."""

from __future__ import annotations

import inspect
from typing import Annotated, ClassVar, override

from flext_ldif import (
    FlextLdifServersBase,
    c,
    p,
    r,
    s,
    servers,
    t,
    u,
)

logger = u.fetch_logger(__name__)


class FlextLdifServer(s):
    """Server server registry using the canonical registry DSL."""

    SERVERS: ClassVar[str] = "ldif_servers"
    _discovery_initialized: ClassVar[bool] = False
    _global_instance: ClassVar[FlextLdifServer | None] = None
    _registered_servers: ClassVar[dict[str, p.Ldif.ServerServer]] = {}

    dispatcher: Annotated[
        p.Dispatcher | None,
        u.Field(
            default=None,
            exclude=True,
            description="Optional dispatcher used to build the registry backend.",
        ),
    ]
    _registry: p.Registry = u.PrivateAttr()

    @override
    def model_post_init(self, __context: t.JsonMapping | None, /) -> None:
        """Initialize registry and trigger auto-discovery."""
        super().model_post_init(__context)
        self._registry = u.build_registry(dispatcher=self.dispatcher)
        if not type(self)._discovery_initialized:
            self._auto_discover()
            type(self)._discovery_initialized = True

    def acl(self, server_type: str) -> p.Ldif.AclServer | None:
        """Get ACL server for a server type."""
        base = self._lookup_base_server(server_type)
        if base is None:
            return None
        return base.acl_server

    def entry(self, server_type: str) -> p.Ldif.EntryServer | None:
        """Get entry server for a server type."""
        base = self._lookup_base_server(server_type)
        if base is None:
            return None
        return base.entry_server

    def resolve_server_bundle(
        self,
        server_type: str,
    ) -> r[
        t.MappingKV[
            str,
            p.Ldif.SchemaServer | p.Ldif.AclServer | p.Ldif.EntryServer,
        ]
    ]:
        """Get all server types for a server."""
        base = self._lookup_base_server(server_type)
        if base is None:
            return r[
                t.MappingKV[
                    str,
                    p.Ldif.SchemaServer | p.Ldif.AclServer | p.Ldif.EntryServer,
                ]
            ].fail_op("resolve_server_bundle", ValueError(server_type))
        return r[
            t.MappingKV[
                str,
                p.Ldif.SchemaServer | p.Ldif.AclServer | p.Ldif.EntryServer,
            ]
        ].ok({
            "schema": base.schema_server,
            "acl": base.acl_server,
            "entry": base.entry_server,
        })

    def resolve_base_server(self, server_type: str) -> r[p.Ldif.ServerServer]:
        """Get base server for a given server type."""
        return self.server(server_type)

    def resolve_server_constants(self, server_type: str) -> r[type]:
        """Get Constants class from server server."""
        server_result = self.server(server_type)
        if server_result.failure:
            return r[type].fail(server_result.error or server_type)
        base = server_result.value
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
        server_types = self.list_registered_servers()
        servers_by_server: dict[str, t.JsonValue] = {}
        priorities: dict[str, t.JsonValue] = {}
        for st in server_types:
            base = self._lookup_base_server(st)
            if base is None:
                continue
            servers_by_server[st] = {
                "schema": type(base.schema_server).__name__
                if base.schema_server
                else None,
                "acl": type(base.acl_server).__name__ if base.acl_server else None,
                "entry": type(base.entry_server).__name__
                if base.entry_server
                else None,
            }
            priorities[st] = base.priority
        stats: dict[str, t.JsonValue] = {
            "total_servers": len(server_types),
            "servers_by_server": servers_by_server,
            "server_priorities": priorities,
        }
        return stats

    def schema_server(self, server_type: str) -> p.Ldif.SchemaServer | None:
        """Get schema server for a server type."""
        return self.resolve_schema_server(server_type)

    def resolve_schema_server(
        self,
        server_type: str,
    ) -> p.Ldif.SchemaServer | None:
        """Get schema server for a server type."""
        base = self._lookup_base_server(server_type)
        if base is None:
            return None
        return base.schema_server

    def _lookup_base_server(self, server_type: str) -> p.Ldif.ServerServer | None:
        """Resolve a concrete base server or return None on lookup failure."""
        server_result = self.server(server_type)
        if server_result.failure:
            return None
        return server_result.value

    def list_registered_servers(self) -> t.MutableSequenceOf[str]:
        """List all registered server types."""
        return sorted(type(self)._registered_servers)

    @override
    def server(self, server_type: str) -> r[p.Ldif.ServerServer]:
        """Get base server for a server type."""
        try:
            normalized = u.Ldif.normalize_server_type(server_type)
        except ValueError as e:
            return r[p.Ldif.ServerServer].fail(str(e))
        plugin = type(self)._registered_servers.get(normalized)
        if plugin is None:
            return r[p.Ldif.ServerServer].fail(normalized)
        return r[p.Ldif.ServerServer].ok(plugin)

    def _auto_discover(self) -> None:
        """Discover and register concrete server classes from servers package."""
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
                if not isinstance(server_type, str):
                    continue
                server_class = type(instance)
                if not all(
                    getattr(server_class, c, None) is not None
                    for c in ("Schema", "Acl", "Entry")
                ):
                    continue
                if server_type:
                    type(self)._registered_servers[server_type] = instance
                    self._registry.register_plugin(
                        self.SERVERS,
                        server_type,
                        instance,
                        scope=c.RegistrationScope.CLASS,
                    )
            except (TypeError, AttributeError):
                continue

    @classmethod
    def fetch_global_instance(cls) -> FlextLdifServer:
        """Return the shared registry instance, creating it on first call."""
        if cls._global_instance is None:
            cls._global_instance = cls()
        return cls._global_instance


__all__: list[str] = ["FlextLdifServer"]
