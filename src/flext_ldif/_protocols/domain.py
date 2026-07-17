"""Higher-level LDIF service and registry contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Sequence

    from flext_cli import p, t
    from flext_ldif._protocols.base import FlextLdifProtocolsBase

# NOTE (multi-agent, mro-0ftd.3.7.2): domain contracts depend one-way on the
# declaration-only base facet; no project facade or model is resolved here.


@runtime_checkable
class FlextLdifProtocolsDomain(Protocol):
    """Service-level LDIF protocols built on top of base value contracts."""

    @runtime_checkable
    class EntryTransformer(Protocol):
        """Transformer contract for entry-processing pipelines."""

        def apply(
            self,
            item: FlextLdifProtocolsBase.Entry,
        ) -> p.Result[FlextLdifProtocolsBase.Entry]:
            """Transform one entry and return the canonical result container."""
            ...

    @runtime_checkable
    class ServerServer(Protocol):
        """Structured server server contract used by services and tests."""

        server_type: ClassVar[str]
        priority: ClassVar[int]

        @property
        def schema_server(self) -> FlextLdifProtocolsDomain.SchemaServer:
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

        def parse_ldif(
            self,
            value: str,
        ) -> p.Result[FlextLdifProtocolsBase.ParseResponse]:
            """Parse LDIF text through the server's entry implementation."""
            ...

        def write(
            self,
            entries: Sequence[FlextLdifProtocolsBase.Entry],
            write_options: FlextLdifProtocolsBase.WriteFormatOptions | None = None,
        ) -> p.Result[str]:
            """Write canonical entries through the server's entry implementation."""
            ...

    @runtime_checkable
    class SchemaServer(Protocol):
        """Schema server contract.

        ``acl_server`` was removed — it had zero workspace consumers
        (per AGENTS.md §3.5 + STRICT YAGNI). Server-level ``acl_server``
        access lives on the parent ``Server`` protocol above, where the
        actual entry-conversion code reads it.
        """

        def parse_server(
            self,
            value: str,
        ) -> p.Result[
            FlextLdifProtocolsBase.SchemaAttribute
            | FlextLdifProtocolsBase.SchemaObjectClass
        ]:
            """Parse a schema definition into a schema item."""
            ...

        def parse_attribute(
            self,
            definition: str,
        ) -> p.Result[FlextLdifProtocolsBase.SchemaAttribute]:
            """Parse an attributeType definition."""
            ...

        def parse_objectclass(
            self,
            definition: str,
        ) -> p.Result[FlextLdifProtocolsBase.SchemaObjectClass]:
            """Parse an objectClass definition."""
            ...

        def can_handle_attribute(
            self,
            attr_definition: str | FlextLdifProtocolsBase.SchemaAttribute,
        ) -> bool:
            """Check if this server can handle a schema attribute."""
            ...

        def can_handle_objectclass(
            self,
            oc_definition: str | FlextLdifProtocolsBase.SchemaObjectClass,
        ) -> bool:
            """Check if this server can handle a schema objectClass."""
            ...

        def write(
            self,
            model: FlextLdifProtocolsBase.SchemaAttribute
            | FlextLdifProtocolsBase.SchemaObjectClass,
        ) -> p.Result[str]:
            """Serialize a schema item."""
            ...

        def write_attribute(
            self,
            attr_data: FlextLdifProtocolsBase.SchemaAttribute,
        ) -> p.Result[str]:
            """Serialize an attributeType definition."""
            ...

        def write_objectclass(
            self,
            oc_data: FlextLdifProtocolsBase.SchemaObjectClass,
        ) -> p.Result[str]:
            """Serialize an objectClass definition."""
            ...

    @runtime_checkable
    class AclServer(Protocol):
        """ACL server contract."""

        def parse_server(
            self,
            value: str,
        ) -> p.Result[FlextLdifProtocolsBase.Acl]:
            """Parse an ACL line into an ACL model."""
            ...

        def can_handle_acl(
            self,
            acl_line: str | FlextLdifProtocolsBase.Acl,
        ) -> bool:
            """Check if this server can handle an ACL line."""
            ...

        def write(self, acl_data: FlextLdifProtocolsBase.Acl) -> p.Result[str]:
            """Serialize an ACL model."""
            ...

    @runtime_checkable
    class EntryServer(Protocol):
        """Entry server contract."""

        def parse_server(
            self,
            value: str,
        ) -> p.Result[Sequence[FlextLdifProtocolsBase.Entry]]:
            """Parse LDIF text into entry models."""
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
            entry_attrs: t.MutableStrSequenceMapping,
        ) -> p.Result[FlextLdifProtocolsBase.Entry]:
            """Parse a single entry from DN and attribute mapping."""
            ...

        def write(
            self,
            entry_data: FlextLdifProtocolsBase.Entry
            | Sequence[FlextLdifProtocolsBase.Entry],
            write_options: FlextLdifProtocolsBase.WriteFormatOptions | None = None,
        ) -> p.Result[str]:
            """Serialize one or more entries."""
            ...

    @runtime_checkable
    class ServerRegistry(Protocol):
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
        ) -> FlextLdifProtocolsDomain.SchemaServer | None:
            """Return schema server for a server type."""
            ...

        def resolve_schema_server(
            self,
            server_type: str,
        ) -> FlextLdifProtocolsDomain.SchemaServer | None:
            """Resolve schema server for a server type."""
            ...

        def acl(
            self,
            server_type: str,
        ) -> FlextLdifProtocolsDomain.AclServer | None:
            """Return ACL server for a server type."""
            ...

        def entry(
            self,
            server_type: str,
        ) -> FlextLdifProtocolsDomain.EntryServer | None:
            """Return entry server for a server type."""
            ...

        def resolve_server_bundle(
            self,
            server_type: str,
        ) -> p.Result[
            t.MappingKV[
                str,
                FlextLdifProtocolsDomain.SchemaServer
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

        # NOTE (multi-agent, mro-0ftd.3.7.2): return type matches the concrete
        # SSOT (services/server.py:160 -> t.MutableSequenceOf[str]); the prior
        # Sequence[str] under-declared the mutable contract the impl provides.
        def list_registered_servers(self) -> t.MutableSequenceOf[str]:
            """Return all registered normalized server types."""
            ...

        def summarize_registry(self) -> t.MutableJsonMapping:
            """Return registry summary metadata."""
            ...


__all__: list[str] = ["FlextLdifProtocolsDomain"]
