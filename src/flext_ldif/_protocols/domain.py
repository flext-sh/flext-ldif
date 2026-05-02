"""Higher-level LDIF service and registry contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

from flext_cli import p

if TYPE_CHECKING:
    from flext_ldif import m, t


class FlextLdifProtocolsDomain(Protocol):
    """Service-level LDIF protocols built on top of base value contracts."""

    @runtime_checkable
    class EntryTransformer(Protocol):
        """Transformer contract for entry-processing pipelines."""

        def apply(self, item: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
            """Transform one entry and return the canonical result container."""
            ...

    @runtime_checkable
    class ServerServer(Protocol):
        """Structured server server contract used by services and tests."""

        server_type: ClassVar[str]
        priority: ClassVar[int]

        @property
        def schema_server(self) -> FlextLdifProtocolsDomain.SchemaServer:
            """Return schema server implementation."""
            ...

        @property
        def acl_server(self) -> FlextLdifProtocolsDomain.AclServer:
            """Return ACL server implementation."""
            ...

        @property
        def entry_server(self) -> FlextLdifProtocolsDomain.EntryServer:
            """Return entry server implementation."""
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
        ) -> p.Result[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]:
            """Parse a schema definition into a schema item."""
            ...

        def parse_attribute(self, definition: str) -> p.Result[m.Ldif.SchemaAttribute]:
            """Parse an attributeType definition."""
            ...

        def parse_objectclass(
            self,
            definition: str,
        ) -> p.Result[m.Ldif.SchemaObjectClass]:
            """Parse an objectClass definition."""
            ...

        def write(
            self,
            model: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        ) -> p.Result[str]:
            """Serialize a schema item."""
            ...

        def write_attribute(
            self,
            attr_data: m.Ldif.SchemaAttribute,
        ) -> p.Result[str]:
            """Serialize an attributeType definition."""
            ...

        def write_objectclass(
            self,
            oc_data: m.Ldif.SchemaObjectClass,
        ) -> p.Result[str]:
            """Serialize an objectClass definition."""
            ...

    @runtime_checkable
    class AclServer(Protocol):
        """ACL server contract."""

        def parse_server(self, value: str) -> p.Result[m.Ldif.Acl]:
            """Parse an ACL line into an ACL model."""
            ...

        def write(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
            """Serialize an ACL model."""
            ...

    @runtime_checkable
    class EntryServer(Protocol):
        """Entry server contract."""

        def parse_server(self, value: str) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
            """Parse LDIF text into entry models."""
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
            entry_data: m.Ldif.Entry | t.MutableSequenceOf[m.Ldif.Entry],
            write_options: m.Ldif.WriteFormatOptions | None = None,
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
        ) -> p.Result[type]:
            """Resolve constants class for a server type."""
            ...

        def list_registered_servers(self) -> t.MutableSequenceOf[str]:
            """Return all registered normalized server types."""
            ...

        def summarize_registry(self) -> t.Ldif.MutableMetadataInputMapping:
            """Return registry summary metadata."""
            ...


__all__: list[str] = ["FlextLdifProtocolsDomain"]
