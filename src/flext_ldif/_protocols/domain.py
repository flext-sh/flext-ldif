"""Higher-level LDIF entry-processing contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Protocol, runtime_checkable

from flext_cli import p

from flext_ldif import t

if TYPE_CHECKING:
    from flext_ldif import m
    from flext_ldif._protocols import FlextLdifProtocolsBase


@runtime_checkable
class FlextLdifProtocolsDomain(Protocol):
    """Service-level LDIF contracts and server capabilities."""

    @runtime_checkable
    class ServerServer(Protocol):
        """Structured server contract used by services and tests."""

        server_type: ClassVar[str]
        priority: ClassVar[int]
        Constants: ClassVar[type[FlextLdifProtocolsBase.ServerConstants]]

        @property
        def schema_server(self) -> FlextLdifProtocolsDomain.SchemaServer: ...

        @property
        def acl_server(self) -> FlextLdifProtocolsDomain.AclServer: ...

        @property
        def entry_server(self) -> FlextLdifProtocolsDomain.EntryServer: ...

        def parse_ldif(self, value: str) -> p.Result[m.Ldif.ParseResponse]: ...

        def write(
            self,
            entries: t.MutableSequenceOf[m.Ldif.Entry],
            write_options: m.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[str]: ...

    @runtime_checkable
    class SchemaServer(Protocol):
        """Public schema parsing and serialization contract."""

        def parse_server(
            self, value: str
        ) -> p.Result[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]: ...

        def parse_input(
            self, schema_text: str
        ) -> p.Result[m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass]: ...

        def parse_attribute(
            self, definition: str
        ) -> p.Result[m.Ldif.SchemaAttribute]: ...

        def parse_objectclass(
            self, definition: str
        ) -> p.Result[m.Ldif.SchemaObjectClass]: ...

        def can_handle_attribute(self, attr_definition: str) -> bool: ...

        def can_handle_objectclass(self, oc_definition: str) -> bool: ...

        def write(
            self, model: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass
        ) -> p.Result[str]: ...

        def write_attribute(
            self, attr_data: m.Ldif.SchemaAttribute
        ) -> p.Result[str]: ...

        def write_objectclass(
            self, oc_data: m.Ldif.SchemaObjectClass
        ) -> p.Result[str]: ...

    @runtime_checkable
    class AclServer(Protocol):
        """ACL parsing, serialization, and attribute discovery contract."""

        def resolve_acl_attributes(self) -> t.MutableSequenceOf[str]: ...

        def parse_server(self, value: str) -> p.Result[m.Ldif.Acl]: ...

        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool: ...

        def write(self, acl_data: m.Ldif.Acl) -> p.Result[str]: ...

    @runtime_checkable
    class EntryServer(Protocol):
        """Entry parsing and serialization capability, not a dialect registry."""

        def parse_server(
            self, value: str
        ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]: ...

        def parse_input(
            self, ldif_text: str
        ) -> t.MutableSequenceOf[m.Ldif.Entry] | None: ...

        def can_handle(
            self, entry_dn: str, attributes: t.MutableStrSequenceMapping
        ) -> bool: ...

        def parse_entry(
            self, entry_dn: str, entry_attrs: t.MutableStrSequenceMapping
        ) -> p.Result[m.Ldif.Entry]: ...

        def write(
            self,
            entry_data: m.Ldif.Entry | t.MutableSequenceOf[m.Ldif.Entry],
            write_options: m.Ldif.WriteFormatOptions | None = None,
        ) -> p.Result[str]: ...

    @runtime_checkable
    class CategorizationService(Protocol):
        """Protocol for LDIF entry categorization services."""

        def categorize_entries(
            self,
            entries: t.MutableSequenceOf[m.Ldif.Entry],
        ) -> p.Result[m.Ldif.FlexibleCategories]: ...

        def filter_by_base_dn(
            self,
            categories: m.Ldif.FlexibleCategories,
        ) -> m.Ldif.FlexibleCategories: ...

        def validate_dns(
            self,
            entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
        ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]: ...

        def filter_schema_by_oids(
            self,
            schema_entries: t.MutableSequenceOf[m.Ldif.Entry],
        ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]: ...

    @runtime_checkable
    class EntryStep(Protocol):
        """Callable step contract for entry-processing pipelines."""

        def __call__(self, item: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
            """Transform one entry and return the canonical result container."""
            ...


__all__: list[str] = ["FlextLdifProtocolsDomain"]
