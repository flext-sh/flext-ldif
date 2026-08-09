"""Protocol definitions for flext-ldif tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldif import FlextLdifProtocols
from flext_tests import FlextTestsProtocols

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from flext_ldif.services.migration import FlextLdifMigrationPipeline
    from tests import c, m, t


class TestsFlextLdifProtocols(FlextTestsProtocols, FlextLdifProtocols):
    """Protocol definitions for flext-ldif tests."""

    class Ldap:
        """Structural contract of the ldap3-compatible client used by the tests.

        flext-ldif is the base library the LDAP client builds on, so the client
        can never be a declared dependency of this project. The tests describe
        only the surface they drive and resolve the concrete implementation at
        runtime through ``tests.utilities`` (see ``u.Tests.require_ldap_client``).
        """

        @runtime_checkable
        class Ldap3Server(Protocol):
            """Opaque ldap3-compatible server handle."""

            @property
            def name(self) -> str | None:
                """The configured server name."""
                ...

        @runtime_checkable
        class Ldap3Attribute(Protocol):
            """Structural contract for ldap3-compatible attribute objects."""

            @property
            def values(self) -> t.SequenceOf[object]:
                """The raw LDAP values for this attribute."""
                ...

            @property
            def value(self) -> object:
                """The resolved attribute value."""
                ...

        @runtime_checkable
        class Ldap3Entry(Protocol):
            """Structural contract for ldap3-compatible entry objects."""

            @property
            def entry_dn(self) -> str | None:
                """The entry distinguished name."""
                ...

            @property
            def entry_attributes(self) -> t.StrSequence:
                """The attribute names present in this entry."""
                ...

            def __getitem__(self, attribute_name: str) -> p.Ldap.Ldap3Attribute:
                """Return one ldap3 attribute object by attribute name."""
                ...

        @runtime_checkable
        class Ldap3Connection(Protocol):
            """Structural contract for ldap3-compatible connection objects."""

            @property
            def bound(self) -> bool:
                """Whether the connection is currently bound."""
                ...

            def bind(self) -> bool:
                """Bind the connection using the configured credentials."""
                ...

            @property
            def entries(self) -> t.SequenceOf[p.Ldap.Ldap3Entry]:
                """The entries produced by the last LDAP operation."""
                ...

            @property
            def add(self) -> Callable[..., bool]:
                """The callable implementing the add operation."""
                ...

            @property
            def delete(self) -> Callable[..., bool]:
                """The callable implementing the delete operation."""
                ...

            @property
            def modify(self) -> Callable[..., bool]:
                """The callable implementing the modify operation."""
                ...

            @property
            def search(self) -> Callable[..., bool | t.JsonValue | None]:
                """The callable implementing the search operation."""
                ...

            @property
            def unbind(self) -> Callable[..., bool]:
                """The callable implementing connection teardown."""
                ...

        @runtime_checkable
        class Ldap3EntryAdapter(Protocol):
            """Structural contract for the ldap3 entry to LDIF entry adapter."""

            def ldap3_to_ldif_entry(
                self, ldap3_entry: p.Ldap.Ldap3Entry
            ) -> p.Result[m.Ldif.Entry]:
                """Convert one ldap3 entry into the LDIF entry model."""
                ...

    class Tests(FlextTestsProtocols.Tests):
        """LDIF helper protocols used only by tests."""

        @runtime_checkable
        class ParseInputServer(Protocol):
            """Server exposing `parse_input` for schema or ACL helpers."""

            def parse_input(
                self, value: str
            ) -> p.Result[
                m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
            ]:
                """Parse server-specific raw input."""
                ...

        @runtime_checkable
        class WriteAttributeServer(Protocol):
            """Server exposing Apache/Novell attribute writer."""

            def _write_attribute(
                self, attr_data: m.Ldif.SchemaAttribute
            ) -> p.Result[str]:
                """Serialize an attribute definition."""
                ...

        @runtime_checkable
        class WriteObjectClassServer(Protocol):
            """Server exposing Apache/Novell objectclass writer."""

            def _write_objectclass(
                self, oc_data: m.Ldif.SchemaObjectClass
            ) -> p.Result[str]:
                """Serialize an objectClass definition."""
                ...

        @runtime_checkable
        class WriteAclServer(Protocol):
            """Server exposing Apache ACL writer helper."""

            def _write_acl(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
                """Serialize an ACL definition."""
                ...

        @runtime_checkable
        class ParseAclServer(Protocol):
            """Server exposing ACL parse helper with test models."""

            def parse_server(self, value: str) -> p.Result[m.Ldif.Acl]:
                """Parse ACL content into the test model."""
                ...

        @runtime_checkable
        class WriteAclContentServer(Protocol):
            """Server exposing ACL write helper with test models."""

            def write(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
                """Write ACL content from the test model."""
                ...

        class MigrationPipelineFactory(Protocol):
            """Callable contract for the migration pipeline factory fixture."""

            def __call__(
                self,
                *,
                input_dir: Path | None = None,
                output_dir: Path | None = None,
                source_server_type: c.Ldif.ServerTypes | str | None = None,
                target_server_type: c.Ldif.ServerTypes | str | None = None,
            ) -> FlextLdifMigrationPipeline: ...


p = TestsFlextLdifProtocols

__all__: list[str] = ["TestsFlextLdifProtocols", "p"]
