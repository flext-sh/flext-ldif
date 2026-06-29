"""Protocol definitions for flext-ldif tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldap import p as ldap_p
from flext_tests import FlextTestsProtocols

from flext_ldif import FlextLdifProtocols

if TYPE_CHECKING:
    from tests.models import m


class TestsFlextLdifProtocols(
    FlextTestsProtocols,
    ldap_p,
    FlextLdifProtocols,
):
    """Protocol definitions for flext-ldif tests."""

    class Ldap(ldap_p.Ldap):
        """LDAP protocol namespace re-exposed for flext-ldif tests."""

    class Tests(FlextTestsProtocols.Tests):
        """LDIF helper protocols used only by tests."""

        @runtime_checkable
        class ParseInputServer(Protocol):
            """Server exposing `parse_input` for schema or ACL helpers."""

            def parse_input(
                self,
                value: str,
            ) -> p.Result[
                m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
            ]:
                """Parse server-specific raw input."""
                ...

        @runtime_checkable
        class WriteAttributeServer(Protocol):
            """Server exposing Apache/Novell attribute writer."""

            def _write_attribute(
                self,
                attr_data: m.Ldif.SchemaAttribute,
            ) -> p.Result[str]:
                """Serialize an attribute definition."""
                ...

        @runtime_checkable
        class WriteObjectClassServer(Protocol):
            """Server exposing Apache/Novell objectclass writer."""

            def _write_objectclass(
                self,
                oc_data: m.Ldif.SchemaObjectClass,
            ) -> p.Result[str]:
                """Serialize an objectClass definition."""
                ...

        @runtime_checkable
        class WriteAclServer(Protocol):
            """Server exposing Apache ACL writer helper."""

            def _write_acl(
                self,
                acl_data: m.Ldif.Acl,
            ) -> p.Result[str]:
                """Serialize an ACL definition."""
                ...

        @runtime_checkable
        class ParseAclServer(Protocol):
            """Server exposing ACL parse helper with test models."""

            def parse_server(
                self,
                value: str,
            ) -> p.Result[m.Ldif.Acl]:
                """Parse ACL content into the test model."""
                ...

        @runtime_checkable
        class WriteAclContentServer(Protocol):
            """Server exposing ACL write helper with test models."""

            def write(
                self,
                acl_data: m.Ldif.Acl,
            ) -> p.Result[str]:
                """Write ACL content from the test model."""
                ...


p = TestsFlextLdifProtocols

__all__: list[str] = ["TestsFlextLdifProtocols", "p"]
