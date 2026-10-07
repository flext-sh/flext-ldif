"""Server server registry using the canonical `p.Registry` DSL.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import TYPE_CHECKING, Annotated, ClassVar, Self, TypeGuard, override

from flext_core import r
from flext_ldif import c, p, s, t, u

if TYPE_CHECKING:
    from flext_ldif.servers.base import FlextLdifServersBase


class FlextLdifServer(s):
    """Server server registry using the canonical registry DSL."""

    _discovery_initialized: ClassVar[bool] = False
    _global_instance: ClassVar[FlextLdifServer | None] = None
    _registered_servers: ClassVar[t.MutableMappingKV[str, p.Ldif.ServerServer]] = {}

    dispatcher: Annotated[
        p.Dispatcher | None,
        u.Field(
            default=None,
            exclude=True,
            description="Optional dispatcher used to build the registry backend.",
        ),
    ] = None
    _registry: p.Registry = u.PrivateAttr(default_factory=u.build_registry)

    @override
    def __new__(cls, *args: object, **kwargs: object) -> Self:
        """Pre-bind the shared singleton before pydantic initialization.

        The inherited service-base ``_server`` private-attribute default
        resolves ``fetch_global_instance`` during construction; binding the
        instance in ``__new__`` turns that re-entrant fetch into a return of
        the instance under construction instead of unbounded recursion.
        """
        _ = args, kwargs
        singleton = FlextLdifServer._global_instance
        if singleton is None:
            singleton = super().__new__(cls)
            FlextLdifServer._global_instance = singleton
        return singleton

    @override
    def model_post_init(self, __context: t.JsonMapping | None, /) -> None:
        """Initialize registry and trigger auto-discovery."""
        super().model_post_init(__context)
        self._registry = u.build_registry(dispatcher=self.dispatcher)
        if self._global_instance is None:
            FlextLdifServer._global_instance = self
        if not self._discovery_initialized:
            self._auto_discover()
            FlextLdifServer._discovery_initialized = True

    def acl(self, server_type: str) -> p.Ldif.AclServer | None:
        """Get ACL server for a server type.

        Returns:
            The resulting ``p.Ldif.AclServer | None``.
        """
        server_result = self.server(server_type)
        if server_result.success:
            return server_result.value.acl_server
        return None

    def entry(self, server_type: str) -> p.Ldif.EntryServer | None:
        """Get entry server for a server type.

        Returns:
            The resulting ``p.Ldif.EntryServer | None``.
        """
        server_result = self.server(server_type)
        if server_result.success:
            return server_result.value.entry_server
        return None

    def resolve_server_bundle(
        self,
        server_type: str,
    ) -> p.Result[
        t.MappingKV[str, p.Ldif.SchemaServer | p.Ldif.AclServer | p.Ldif.EntryServer]
    ]:
        """Get all server types for a server.

        Returns:
            The resulting ``p.Result[t.MappingKV[str, p.Ldif.SchemaServer |
                p.Ldif.AclServer | p.Ldif.EntryServer]]``.
        """
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
        """Get base server for a given server type.

        Returns:
            The resulting ``p.Result[p.Ldif.ServerServer]``.
        """
        return self.server(server_type)

    def resolve_server_constants(
        self,
        server_type: str,
    ) -> p.Result[type[p.Ldif.ServerConstants]]:
        """Get Constants class from server server.

        Returns:
            The resulting ``p.Result[type[p.Ldif.ServerConstants]]``.
        """
        server_result = self.server(server_type)
        if server_result.failure:
            return r[type[p.Ldif.ServerConstants]].from_failure(server_result)
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

    def summarize_registry(self) -> t.Ldif.MutableMetadataInputMapping:
        """Get comprehensive registry statistics.

        Returns:
            The resulting ``t.Ldif.MutableMetadataInputMapping``.
        """
        server_types = self.list_registered_servers()
        servers_by_server: t.JsonDict = {}
        priorities: t.JsonDict = {}
        for st in server_types:
            base = self.server(st).unwrap()
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
        stats: t.Ldif.MutableMetadataInputMapping = {
            "total_servers": len(server_types),
            "servers_by_server": servers_by_server,
            "server_priorities": priorities,
        }
        return stats

    def schema_server(self, server_type: str) -> p.Ldif.SchemaServer | None:
        """Get schema server for a server type.

        Returns:
            The resulting ``p.Ldif.SchemaServer | None``.
        """
        return self.resolve_schema_server(server_type)

    def resolve_schema_server(self, server_type: str) -> p.Ldif.SchemaServer | None:
        """Get schema server for a server type.

        Returns:
            The resulting ``p.Ldif.SchemaServer | None``.
        """
        server_result = self.server(server_type)
        if server_result.success:
            return server_result.value.schema_server
        return None

    def list_registered_servers(self) -> t.MutableSequenceOf[str]:
        """List all registered server types.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        return sorted(self._registered_servers)

    def server(self, server_type: str) -> p.Result[p.Ldif.ServerServer]:
        """Get base server for a server type.

        Returns:
            The resulting ``p.Result[p.Ldif.ServerServer]``.
        """
        try:
            normalized = u.Ldif.normalize_server_type(server_type)
        except ValueError as e:
            return r[p.Ldif.ServerServer].fail(str(e), exception=e)
        plugin = self._registered_servers.get(normalized)
        if plugin is None:
            return r[p.Ldif.ServerServer].fail(normalized)
        return r[p.Ldif.ServerServer].ok(plugin)

    def _auto_discover(self) -> None:
        """Discover and register concrete classes from installed server modules.

        Raises:
            TypeError: If flext_ldif.servers.base must expose FlextLdifServersBase.
        """
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
                    servers_package.__path__,
                    prefix=prefix,
                )
                if not module_info.ispkg
                and not module_info.name.removeprefix(prefix).startswith("_")
            ),
        )
        for module_name in module_names:
            module = importlib.import_module(module_name)
            for name, obj in inspect.getmembers(module):
                if not self._is_discoverable_server(
                    name,
                    obj,
                    module_name,
                    base_candidate,
                ):
                    continue
                try:
                    self._register_discovered_server(obj)
                except c.EXC_ATTR_TYPE:
                    continue

    @staticmethod
    def _is_public_module_member(name: str) -> bool:
        """Whether a module member name is public (not underscore-private).

        Returns:
            True when the member name does not start with an underscore.
        """
        return not name.startswith("_")

    @staticmethod
    def _is_concrete_server_subclass(
        candidate: type,
        base_class: type,
    ) -> bool:
        """Whether the candidate is a concrete subclass defined in the module.

        Returns:
            True when the candidate is a concrete subclass of the base.
        """
        return (
            inspect.isclass(candidate)
            and candidate is not base_class
            and issubclass(candidate, base_class)
        )

    @staticmethod
    def _is_discoverable_server(
        name: str,
        candidate: type,
        module_name: str,
        base_class: type,
    ) -> TypeGuard[type[FlextLdifServersBase]]:
        """Return whether a module member is a concrete server class."""
        return (
            FlextLdifServer._is_public_module_member(name)
            and FlextLdifServer._is_concrete_server_subclass(candidate, base_class)
            and candidate.__module__ == module_name
        )

    def _register_discovered_server(
        self,
        server_class: type[FlextLdifServersBase],
    ) -> None:
        """Instantiate and register one discovered concrete server class."""
        instance = server_class()
        server_type = getattr(instance, "server_type", None)
        if not isinstance(server_type, str):
            return
        if not all(
            getattr(server_class, attr_name, None) is not None
            for attr_name in ("Schema", "Acl", "Entry")
        ):
            return
        if server_type:
            self._registered_servers[server_type] = instance
            self._registry.register_plugin(
                c.Ldif.SERVERS,
                server_type,
                instance,
                scope=c.RegistrationScope.CLASS,
            )

    @classmethod
    def fetch_global_instance(cls) -> FlextLdifServer:
        """Return the shared registry instance, creating it on first call.

        ``__new__`` pre-binds the singleton, so plain instantiation is safe:
        the inherited service-base ``_server`` default resolves through this
        classmethod during construction and returns the instance under
        construction instead of recursing.
        """
        if cls._global_instance is None:
            cls._global_instance = cls()
        return cls._global_instance


__all__: list[str] = ["FlextLdifServer"]
