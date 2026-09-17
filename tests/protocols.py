"""Protocol definitions for flext-ldif tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_tests import FlextTestsProtocols

from flext_ldif import FlextLdifProtocols

if TYPE_CHECKING:
    from pathlib import Path

    from flext_ldif.services.migration import FlextLdifMigrationPipeline
    from tests import c, m


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

        # ── Shared structural contracts (SSOT: flext_ldif._protocols.ldap3) ──
        Ldap3Attribute = FlextLdifProtocols.Ldif.Ldap3Attribute
        Ldap3Entry = FlextLdifProtocols.Ldif.Ldap3Entry
        Ldap3Connection = FlextLdifProtocols.Ldif.Ldap3Connection

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
