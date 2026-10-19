"""Higher-level LDIF service and registry contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

from flext_cli import p

if TYPE_CHECKING:
    from flext_ldif import m, t
    from flext_ldif._protocols import FlextLdifProtocolsBase


@runtime_checkable
class FlextLdifProtocolsDomain(Protocol):
    """Service-level LDIF protocols built on top of base value contracts."""

    @runtime_checkable
    class EntryStep(Protocol):
        """Callable step contract for entry-processing pipelines."""

        def __call__(self, item: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
            """Transform one entry and return the canonical result container."""
            ...

    @runtime_checkable
    class ServerServer(p.HasModelDump, Protocol):
        """Structured server server contract used by services and tests."""

        server_type: ClassVar[str]
        priority: ClassVar[int]
        Constants: ClassVar[type[FlextLdifProtocolsBase.ServerConstants]]

        @property
        def schema_server(self) -> FlextLdifProtocolsBase.SchemaServer:
            """The schema server implementation."""
            ...

        @property
        def acl_server(self) -> FlextLdifProtocolsDomain.AclServer:
            """ACL server implementation."""
            ...

        @property
        def entry_server(self) -> FlextLdifProtocolsDomain.EntryServer:
            """The entry server implementation."""
            ...

        def parse_ldif(self, value: str) -> p.Result[m.Ldif.ParseResponse]:
            """Parse LDIF text through the server's entry implementation."""
            ...

        def write(
            self,
            entries: t.MutableSequenceOf[m.Ldif.Entry],
            write_options: m.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[str]:
            """Write canonical entries through the server's entry implementation."""
            ...

    @runtime_checkable
    class AclServer(Protocol):
        """ACL server contract."""

        def resolve_acl_attributes(self) -> t.MutableSequenceOf[str]:
            """Return this server's ACL entry attributes in extraction order."""
            ...

        def parse_server(self, value: str) -> p.Result[m.Ldif.Acl]:
            """Parse an ACL line into an ACL model."""
            ...

        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this server can handle an ACL line."""
            ...

        def write(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
            """Serialize an ACL model."""
            ...

    @runtime_checkable
    class EntryServer(Protocol):
        """Entry server contract."""

        def parse_server(
            self,
            value: str,
        ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
            """Parse LDIF text into entry models."""
            ...

        def parse_input(
            self,
            ldif_text: str,
        ) -> t.MutableSequenceOf[m.Ldif.Entry] | None:
            """Compatibility parser entrypoint for direct entry server consumers."""
            ...

        def can_handle(
            self,
            entry_dn: str,
            attributes: t.MutableStrSequenceMapping,
        ) -> bool:
            """Check if this server can handle the entry."""
            ...

        def parse_entry(
            self,
            entry_dn: str,
            entry_attrs: t.Ldif.MutableEntryAttributesDict,
        ) -> p.Result[m.Ldif.Entry]:
            """Parse a single entry from DN and attribute mapping."""
            ...

        def write(
            self,
            entry_data: t.MutableSequenceOf[m.Ldif.Entry],
            write_options: m.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[str]:
            """Serialize one or more entries."""
            ...

    @runtime_checkable
    class RegistryBound(Protocol):
        """Core registry port consumed by runtime-preserving composition."""

        @property
        def registry(self) -> p.Registry: ...

    @runtime_checkable
    class ServerRegistry(RegistryBound, Protocol):
        """Registry contract for server-specific servers."""

        def server(
            self,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsDomain.ServerServer]:
            """Return base server for a server type."""
            ...

        def resolve_base_server(
            self,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsDomain.ServerServer]:
            """Resolve base server for a server type."""
            ...

        def schema_server(
            self,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsBase.SchemaServer]:
            """Return schema server for a server type."""
            ...

        def resolve_schema_server(
            self,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsBase.SchemaServer]:
            """Resolve schema server for a server type."""
            ...

        def acl(self, server_type: str) -> p.Result[FlextLdifProtocolsDomain.AclServer]:
            """Return ACL server for a server type."""
            ...

        def entry(
            self,
            server_type: str,
        ) -> p.Result[FlextLdifProtocolsDomain.EntryServer]:
            """Return entry server for a server type."""
            ...

        def resolve_server_bundle(
            self,
            server_type: str,
        ) -> p.Result[
            t.MappingKV[
                str,
                FlextLdifProtocolsBase.SchemaServer
                | FlextLdifProtocolsDomain.AclServer
                | FlextLdifProtocolsDomain.EntryServer,
            ]
        ]:
            """Return schema/acl/entry server bundle for a server type."""
            ...

        def resolve_server_constants(
            self,
            server_type: str,
        ) -> p.Result[type[FlextLdifProtocolsBase.ServerConstants]]:
            """Resolve constants class for a server type."""
            ...

        def list_registered_servers(self) -> p.Result[t.MutableSequenceOf[str]]:
            """Return all registered normalized server types."""
            ...

        def summarize_registry(self) -> p.Result[t.Ldif.MutableMetadataInputMapping]:
            """Return registry summary metadata."""
            ...

        def register_server(
            self, server: FlextLdifProtocolsDomain.ServerServer
        ) -> p.Result[bool]: ...

        def unregister_server(self, server_type: str) -> p.Result[bool]: ...


__all__: list[str] = ["FlextLdifProtocolsDomain"]
