"""Server server registry using the canonical `p.Registry` DSL."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import TYPE_CHECKING, Annotated, ClassVar, TypeGuard, override

from flext_core import s
from flext_ldif import c, p, r, t, u

if TYPE_CHECKING:
    from flext_ldif.servers.base import FlextLdifServersBase

# NOTE (multi-agent, mro-0ftd.3.7.2): runtime services consume only the public
# protocol facade; the former private Domain alias recreated the SCC edge.


class FlextLdifServer(s):
    """Server server registry using the canonical registry DSL."""

    SERVERS: ClassVar[str] = "ldif_servers"

    dispatcher: Annotated[
        p.Dispatcher | None,
        u.Field(
            default=None,
            exclude=True,
            description="Optional dispatcher used to build the registry backend.",
        ),
    ] = None
    _registry: p.Registry = u.PrivateAttr()
    _registered_servers: dict[str, p.Ldif.ServerServer] = u.PrivateAttr(
        default_factory=dict
    )

    @override
    def model_post_init(self, __context: t.JsonMapping | None, /) -> None:
        """Initialize registry and trigger auto-discovery."""
        super().model_post_init(__context)
        self._registry = u.build_registry(dispatcher=self.dispatcher)
        self._auto_discover()

    def acl(self, server_type: str) -> p.Ldif.AclServer | None:
        """Get ACL server for a server type."""
        server_result = self.server(server_type)
        if server_result.failure:
            return None
        base: p.Ldif.ServerServer = server_result.value
        return base.acl_server

    def entry(self, server_type: str) -> p.Ldif.EntryServer | None:
        """Get entry server for a server type."""
        server_result = self.server(server_type)
        if server_result.failure:
            return None
        base: p.Ldif.ServerServer = server_result.value
        return base.entry_server

    def resolve_server_bundle(
        self,
        server_type: str,
    ) -> p.Result[
        t.MappingKV[
            str,
            p.Ldif.SchemaServer | p.Ldif.AclServer | p.Ldif.EntryServer,
        ]
    ]:
        """Get all server types for a server."""
        server_result = self.server(server_type)
        if server_result.failure:
            return r[
                t.MappingKV[
                    str,
                    p.Ldif.SchemaServer | p.Ldif.AclServer | p.Ldif.EntryServer,
                ]
            ].fail_op(
                "resolve_server_bundle",
                ValueError(server_result.error or server_type),
            )
        base: p.Ldif.ServerServer = server_result.value
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

    def resolve_base_server(self, server_type: str) -> p.Result[p.Ldif.ServerServer]:
        """Get base server for a given server type."""
        return self.server(server_type)

    def resolve_server_constants(
        self,
        server_type: str,
    ) -> p.Result[type[p.Ldif.ServerConstants]]:
        """Get Constants class from server server."""
        server_result = self.server(server_type)
        if server_result.failure:
            return r[type[p.Ldif.ServerConstants]].fail(
                server_result.error or server_type,
            )
        base = server_result.value
        constants: type[p.Ldif.ServerConstants] | None = getattr(
            type(base),
            "Constants",
            None,
        )
        if constants is None:
            return r[type[p.Ldif.ServerConstants]].fail(
                f"Server {server_type} missing Constants",
            )
        return r[type[p.Ldif.ServerConstants]].ok(constants)

    def summarize_registry(self) -> t.MutableJsonMapping:
        """Get comprehensive registry statistics."""
        server_types = self.list_registered_servers()
        servers_by_server: t.JsonDict = {}
        priorities: t.JsonDict = {}
        for st in server_types:
            server_result = self.server(st)
            if server_result.failure:
                msg = server_result.error or st
                raise ValueError(msg)
            base = server_result.value
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
        stats: t.MutableJsonMapping = {
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
        server_result = self.server(server_type)
        if server_result.failure:
            return None
        base: p.Ldif.ServerServer = server_result.value
        return base.schema_server

    def list_registered_servers(self) -> t.MutableSequenceOf[str]:
        """List all registered server types."""
        return sorted(self._registered_servers)

    def server(self, server_type: str) -> p.Result[p.Ldif.ServerServer]:
        """Get base server for a server type."""
        try:
            normalized = u.Ldif.normalize_server_type(server_type)
        except ValueError as e:
            return r[p.Ldif.ServerServer].fail(str(e))
        plugin = self._registered_servers.get(normalized)
        if plugin is None:
            return r[p.Ldif.ServerServer].fail(normalized)
        return r[p.Ldif.ServerServer].ok(plugin)

    def _auto_discover(self) -> None:
        """Discover and register concrete classes from installed server modules."""
        # mro-0ftd.3.5: discovery owns module loading so package initializers
        # remain side-effect-free and cannot recreate the service import cycle.
        servers_package = importlib.import_module("flext_ldif.servers")
        base_candidate = getattr(
            importlib.import_module("flext_ldif.servers.base"),
            "FlextLdifServersBase",
            None,
        )
        if not isinstance(base_candidate, type):
            msg = "flext_ldif.servers.base must expose FlextLdifServersBase"
            raise TypeError(msg)
        prefix = f"{servers_package.__name__}."
        module_names = tuple(
            sorted(
                module_info.name
                for module_info in pkgutil.iter_modules(
                    servers_package.__path__, prefix=prefix
                )
                if not module_info.ispkg
                and not module_info.name.removeprefix(prefix).startswith("_")
            )
        )
        for module_name in module_names:
            module = importlib.import_module(module_name)
            for name, obj in inspect.getmembers(module):
                if not self._is_discoverable_server(
                    name, obj, module_name, base_candidate
                ):
                    continue
                self._register_discovered_server(obj)

    @staticmethod
    def _is_discoverable_server(
        name: str,
        candidate: type,
        module_name: str,
        base_class: type,
    ) -> TypeGuard[type[FlextLdifServersBase]]:
        """Return whether a module member is a concrete server class."""
        return (
            not name.startswith("_")
            and inspect.isclass(candidate)
            and candidate is not base_class
            and candidate.__module__ == module_name
            and issubclass(candidate, base_class)
        )

    def _register_discovered_server(
        self,
        server_class: type[FlextLdifServersBase],
    ) -> None:
        """Instantiate and register one discovered concrete server class."""
        instance = server_class()
        server_type = getattr(instance, "server_type", None)
        if not isinstance(server_type, str) or not server_type:
            msg = f"{server_class.__name__} must declare a non-empty server_type"
            raise TypeError(msg)
        missing = tuple(
            attr_name
            for attr_name in ("Schema", "Acl", "Entry")
            if getattr(server_class, attr_name, None) is None
        )
        if missing:
            msg = f"{server_class.__name__} missing server contracts: {missing}"
            raise TypeError(msg)
        if server_type in self._registered_servers:
            msg = f"duplicate LDIF server type: {server_type}"
            raise ValueError(msg)
        self._registered_servers[server_type] = instance
        self._registry.register_plugin(
            self.SERVERS,
            server_type,
            instance,
            scope=c.RegistrationScope.CLASS,
        )


__all__: list[str] = ["FlextLdifServer"]
