"""Dialect lookup and lifecycle over the explicitly injected core registry.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, m, p, r, s, t, u


class FlextLdifServer(s[p.Ldif.Response], m.Ldif.RegistryPortOptions):
    """Share one dialect registry port through the consuming service MRO."""

    def register_server(self, server: p.Ldif.ServerServer) -> p.Result[bool]:
        """Register the original dialect object without copying or overwriting."""
        if not isinstance(server, p.Ldif.ServerServer):
            return r[bool].fail_op("register LDIF server", "Invalid server capability")
        try:
            name = u.Ldif.normalize_server_type(server.server_type).value
        except ValueError as exc:
            return r[bool].fail_op("register LDIF server", exc)
        return self.registry.register_plugin(c.Ldif.SERVERS, name, server)

    def unregister_server(self, server_type: str) -> p.Result[bool]:
        """Remove the actual registry entry so a replacement can be registered."""
        try:
            name = u.Ldif.normalize_server_type(server_type).value
        except ValueError as exc:
            return r[bool].fail_op("unregister LDIF server", exc)
        return self.registry.unregister_plugin(c.Ldif.SERVERS, name)

    def server(self, server_type: str) -> p.Result[p.Ldif.ServerServer]:
        """Resolve a dialect by canonical name while preserving lookup failures."""
        try:
            name = u.Ldif.normalize_server_type(server_type).value
        except ValueError as exc:
            return r[p.Ldif.ServerServer].fail_op("resolve LDIF server", exc)
        result = self.registry.fetch_plugin(c.Ldif.SERVERS, name)
        if result.failure:
            return r[p.Ldif.ServerServer].from_failure(result)
        server = result.value
        if not isinstance(server, p.Ldif.ServerServer):
            return r[p.Ldif.ServerServer].fail_op(
                "resolve LDIF server", "Registered value is not a server capability"
            )
        return r[p.Ldif.ServerServer].ok(server)

    def resolve_base_server(self, server_type: str) -> p.Result[p.Ldif.ServerServer]:
        """Return the registered original dialect instance."""
        return self.server(server_type)

    def acl(self, server_type: str) -> p.Result[p.Ldif.AclServer]:
        """Resolve the dialect's real ACL implementation."""
        return self.server(server_type).map(lambda server: server.acl_server)

    def entry(self, server_type: str) -> p.Result[p.Ldif.EntryServer]:
        """Resolve the dialect's real entry implementation."""
        return self.server(server_type).map(lambda server: server.entry_server)

    def schema_server(self, server_type: str) -> p.Result[p.Ldif.SchemaServer]:
        """Resolve the dialect's real schema implementation."""
        return self.server(server_type).map(lambda server: server.schema_server)

    def resolve_schema_server(self, server_type: str) -> p.Result[p.Ldif.SchemaServer]:
        """Resolve schema through the same authoritative dialect binding."""
        return self.schema_server(server_type)

    def resolve_server_bundle(
        self,
        server_type: str,
    ) -> p.Result[
        t.MappingKV[str, p.Ldif.SchemaServer | p.Ldif.AclServer | p.Ldif.EntryServer]
    ]:
        """Resolve a coherent component bundle from one fetched dialect."""
        return self.server(server_type).map(
            lambda server: {
                "schema": server.schema_server,
                "acl": server.acl_server,
                "entry": server.entry_server,
            }
        )

    def resolve_server_constants(
        self,
        server_type: str,
    ) -> p.Result[type[p.Ldif.ServerConstants]]:
        """Read declared constants from the original registered dialect."""
        return self.server(server_type).map(lambda server: server.Constants)

    def list_registered_servers(self) -> p.Result[t.MutableSequenceOf[str]]:
        """List the authoritative registry without a mirror or class cache."""
        return self.registry.list_plugins(c.Ldif.SERVERS).map(sorted)

    def summarize_registry(self) -> p.Result[t.Ldif.MutableMetadataInputMapping]:
        """Report real stored dialects and fail if any stored value is invalid."""
        names = self.list_registered_servers()
        if names.failure:
            return r[t.Ldif.MutableMetadataInputMapping].from_failure(names)
        components: t.JsonDict = {}
        priorities: t.JsonDict = {}
        for name in names.value:
            result = self.server(name)
            if result.failure:
                return r[t.Ldif.MutableMetadataInputMapping].from_failure(result)
            server = result.value
            components[name] = {
                "schema": type(server.schema_server).__name__,
                "acl": type(server.acl_server).__name__,
                "entry": type(server.entry_server).__name__,
            }
            priorities[name] = server.priority
        return r[t.Ldif.MutableMetadataInputMapping].ok({
            "total_servers": len(names.value),
            "servers_by_server": components,
            "server_priorities": priorities,
        })


__all__: list[str] = ["FlextLdifServer"]
