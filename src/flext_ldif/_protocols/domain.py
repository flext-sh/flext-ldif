"""Higher-level LDIF service and registry contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_core import p

if TYPE_CHECKING:
    from flext_ldif import m, p as lp, t


class FlextLdifProtocolsDomain(Protocol):
    """Service-level LDIF protocols built on top of base value contracts."""

    @runtime_checkable
    class EntryTransformer(Protocol):
        """Transformer contract for entry-processing pipelines."""

        def apply(self, item: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
            """Transform one entry and return the canonical result container."""
            ...

    @runtime_checkable
    class ServerQuirk(Protocol):
        """Structured server quirk contract used by services and tests."""

        @property
        def server_type(self) -> str:
            """Return normalized server type."""
            ...

        @property
        def priority(self) -> int:
            """Return quirk priority."""
            ...

        @property
        def schema_quirk(self) -> FlextLdifProtocolsDomain.SchemaQuirk:
            """Return schema quirk implementation."""
            ...

        @property
        def acl_quirk(self) -> FlextLdifProtocolsDomain.AclQuirk:
            """Return ACL quirk implementation."""
            ...

        @property
        def entry_quirk(self) -> FlextLdifProtocolsDomain.EntryQuirk:
            """Return entry quirk implementation."""
            ...

    @runtime_checkable
    class SchemaQuirk(Protocol):
        """Schema quirk contract.

        ``acl_quirk`` was removed — it had zero workspace consumers
        (per AGENTS.md §3.5 + STRICT YAGNI). Server-level ``acl_quirk``
        access lives on the parent ``Quirk`` protocol above, where the
        actual entry-conversion code reads it.
        """

        def parse_quirk(
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
    class AclQuirk(Protocol):
        """ACL quirk contract."""

        def parse_quirk(self, value: str) -> p.Result[t.Ldif.AclLike]:
            """Parse an ACL line into an ACL model."""
            ...

        def write(self, acl_data: t.Ldif.AclLike) -> p.Result[str]:
            """Serialize an ACL model."""
            ...

    @runtime_checkable
    class EntryQuirk(Protocol):
        """Entry quirk contract."""

        def parse_quirk(self, value: str) -> p.Result[t.Ldif.EntrySequence]:
            """Parse LDIF text into entry models."""
            ...

        def parse_entry(
            self,
            entry_dn: str,
            entry_attrs: t.Ldif.MutableEntryAttributesDict,
        ) -> p.Result[t.Ldif.EntryLike]:
            """Parse a single entry from DN and attribute mapping."""
            ...

        def write(
            self,
            entry_data: t.Ldif.EntryOrEntries,
            write_options: lp.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[str]:
            """Serialize one or more entries."""
            ...

    @runtime_checkable
    class QuirkRegistry(Protocol):
        """Registry contract for server-specific quirks."""

        def schema(
            self,
            server_type: str,
        ) -> FlextLdifProtocolsDomain.SchemaQuirk | None:
            """Return schema quirk for a server type."""
            ...

        def acl(
            self,
            server_type: str,
        ) -> FlextLdifProtocolsDomain.AclQuirk | None:
            """Return ACL quirk for a server type."""
            ...

        def entry(
            self,
            server_type: str,
        ) -> FlextLdifProtocolsDomain.EntryQuirk | None:
            """Return entry quirk for a server type."""
            ...


__all__: list[str] = ["FlextLdifProtocolsDomain"]
