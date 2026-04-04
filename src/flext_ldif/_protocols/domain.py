"""Higher-level LDIF service and registry contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_core import p

if TYPE_CHECKING:
    from flext_ldif import t


class FlextLdifProtocolsDomain(Protocol):
    """Service-level LDIF protocols built on top of base value contracts."""

    @runtime_checkable
    class SchemaQuirk(Protocol):
        """Schema quirk contract."""

        def parse_quirk(self, value: str) -> p.Result[t.Ldif.SchemaItem]:
            """Parse a schema definition into a schema item."""
            ...

        def parse_attribute(
            self, definition: str
        ) -> p.Result[t.Ldif.SchemaAttributeLike]:
            """Parse an attributeType definition."""
            ...

        def parse_objectclass(
            self,
            definition: str,
        ) -> p.Result[t.Ldif.SchemaObjectClassLike]:
            """Parse an objectClass definition."""
            ...

        def write(self, model: t.Ldif.SchemaItem) -> p.Result[str]:
            """Serialize a schema item."""
            ...

        def write_attribute(
            self,
            attr_data: t.Ldif.SchemaAttributeLike,
        ) -> p.Result[str]:
            """Serialize an attributeType definition."""
            ...

        def write_objectclass(
            self,
            oc_data: t.Ldif.SchemaObjectClassLike,
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
            write_options: t.Ldif.WriteOptionsLike | None = None,
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


__all__ = ["FlextLdifProtocolsDomain"]
