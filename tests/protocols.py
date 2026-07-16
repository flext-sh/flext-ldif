"""Protocol definitions for flext-ldif tests."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldap import p as ldap_p
from flext_tests import FlextTestsProtocols

from flext_ldif import p as ldif_p

if TYPE_CHECKING:
    # mro-0ftd.3.6: protocol-only reverse edges never load test facades at runtime.
    from tests.constants import c


class TestsFlextLdifProtocols(
    FlextTestsProtocols,
    ldap_p,
    ldif_p,
):
    """Protocol definitions for flext-ldif tests."""

    class Ldap(ldap_p.Ldap):
        """LDAP protocol namespace re-exposed for flext-ldif tests."""

    class Tests(FlextTestsProtocols.Tests):
        """LDIF helper protocols used only by tests."""

        @runtime_checkable
        class WriteAttributeServer(Protocol):
            """Server exposing Apache/Novell attribute writer."""

            def _write_attribute(
                self,
                attr_data: p.Ldif.SchemaAttribute,
            ) -> ldif_p.Result[str]:
                """Serialize an attribute definition."""
                ...

        @runtime_checkable
        class WriteObjectClassServer(Protocol):
            """Server exposing Apache/Novell objectclass writer."""

            def _write_objectclass(
                self,
                oc_data: p.Ldif.SchemaObjectClass,
            ) -> ldif_p.Result[str]:
                """Serialize an objectClass definition."""
                ...

        @runtime_checkable
        class WriteAclServer(Protocol):
            """Server exposing Apache ACL writer helper."""

            def _write_acl(
                self,
                acl_data: p.Ldif.Acl,
            ) -> ldif_p.Result[str]:
                """Serialize an ACL definition."""
                ...

        @runtime_checkable
        class ParseAclServer(Protocol):
            """Server exposing ACL parse helper with test models."""

            def parse_server(
                self,
                value: str,
            ) -> ldif_p.Result[p.Ldif.Acl]:
                """Parse ACL content into the test model."""
                ...

        @runtime_checkable
        class ProcessEntryServer(ldif_p.Ldif.EntryServer, Protocol):
            """Entry server exposing the public normalization operation."""

            # mro-0ftd.3.6.1: retain the typed Result payload across test fixtures.
            def process_entry(
                self,
                entry: p.Ldif.Entry,
            ) -> ldif_p.Result[p.Ldif.Entry]:
                """Normalize one entry through the server-specific behavior."""
                ...

        @runtime_checkable
        class WriteAclContentServer(Protocol):
            """Server exposing ACL write helper with test models."""

            def write(
                self,
                acl_data: p.Ldif.Acl,
            ) -> ldif_p.Result[str]:
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
            ) -> ldif_p.Ldif.MigrationPipeline: ...


p = TestsFlextLdifProtocols

__all__: list[str] = ["TestsFlextLdifProtocols", "p"]
