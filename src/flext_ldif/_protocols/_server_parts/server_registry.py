"""ServerRegistry protocol - Registry contract for server-specific servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldif import p, t

if TYPE_CHECKING:
    from flext_ldif._protocols._server_parts import (
        SchemaServerProtocol,
        AclServerProtocol,
        EntryServerProtocol,
        ServerServerProtocol,
        ServerConstantsProtocol,
    )


@runtime_checkable
class RegistryBoundProtocol(Protocol):
    """Core registry port consumed by runtime-preserving composition."""

    @property
    def registry(self) -> p.Registry: ...


@runtime_checkable
class ServerRegistryProtocol(RegistryBoundProtocol, Protocol):
    """Registry contract for server-specific servers."""

    def server(
        self,
        server_type: str,
    ) -> p.Result[ServerServerProtocol]:
        """Return base server for a server type."""
        ...

    def resolve_base_server(
        self,
        server_type: str,
    ) -> p.Result[ServerServerProtocol]:
        """Resolve base server for a server type."""
        ...

    def schema_server(
        self,
        server_type: str,
    ) -> p.Result[SchemaServerProtocol]:
        """Return schema server for a server type."""
        ...

    def resolve_schema_server(
        self,
        server_type: str,
    ) -> p.Result[SchemaServerProtocol]:
        """Resolve schema server for a server type."""
        ...

    def acl(self, server_type: str) -> p.Result[AclServerProtocol]:
        """Return ACL server for a server type."""
        ...

    def entry(
        self,
        server_type: str,
    ) -> p.Result[EntryServerProtocol]:
        """Return entry server for a server type."""
        ...

    def resolve_server_bundle(
        self,
        server_type: str,
    ) -> p.Result[
        t.MappingKV[
            str,
            SchemaServerProtocol | AclServerProtocol | EntryServerProtocol,
        ]
    ]:
        """Return schema/acl/entry server bundle for a server type."""
        ...

    def resolve_server_constants(
        self,
        server_type: str,
    ) -> p.Result[type[ServerConstantsProtocol]]:
        """Resolve constants class for a server type."""
        ...

    def list_registered_servers(self) -> p.Result[t.MutableSequenceOf[str]]:
        """Return all registered normalized server types."""
        ...

    def summarize_registry(self) -> p.Result[t.Ldif.MutableMetadataInputMapping]:
        """Return registry summary metadata."""
        ...

    def register_server(self, server: ServerServerProtocol) -> p.Result[bool]: ...

    def unregister_server(self, server_type: str) -> p.Result[bool]: ...


__all__: tuple[str, ...] = ("ServerRegistryProtocol", "RegistryBoundProtocol")
