"""Protocol definitions for flext-ldif tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldap import FlextLdapProtocols
from flext_tests import FlextTestsProtocols

from flext_ldif import FlextLdifProtocols

if TYPE_CHECKING:
    from tests import m


class TestsFlextLdifProtocols(FlextTestsProtocols, FlextLdapProtocols):
    """Protocol definitions for flext-ldif tests."""

    class Ldap(FlextLdapProtocols.Ldap):
        """LDAP protocols re-exported for tests."""

    class Ldif(FlextLdifProtocols.Ldif):
        """LDIF helper protocols."""

        class Tests(FlextTestsProtocols.Tests):
            """LDIF helper protocols used only by tests."""

            @runtime_checkable
            class ParseInputQuirk(Protocol):
                """Quirk exposing `parse_input` for schema or ACL helpers."""

                def parse_input(
                    self,
                    value: str,
                ) -> FlextLdifProtocols.Result[
                    m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | m.Ldif.Acl
                ]:
                    """Parse server-specific raw input."""
                    ...

            @runtime_checkable
            class WriteAttributeQuirk(Protocol):
                """Quirk exposing Apache/Novell attribute writer."""

                def _write_attribute(
                    self,
                    attr_data: m.Ldif.SchemaAttribute,
                ) -> FlextLdifProtocols.Result[str]:
                    """Serialize an attribute definition."""
                    ...

            @runtime_checkable
            class WriteObjectClassQuirk(Protocol):
                """Quirk exposing Apache/Novell objectclass writer."""

                def _write_objectclass(
                    self,
                    oc_data: m.Ldif.SchemaObjectClass,
                ) -> FlextLdifProtocols.Result[str]:
                    """Serialize an objectClass definition."""
                    ...

            @runtime_checkable
            class WriteAclQuirk(Protocol):
                """Quirk exposing Apache ACL writer helper."""

                def _write_acl(
                    self,
                    acl_data: m.Ldif.Acl,
                ) -> FlextLdifProtocols.Result[str]:
                    """Serialize an ACL definition."""
                    ...

            @runtime_checkable
            class ParseAclQuirk(Protocol):
                """Quirk exposing ACL parse helper with test models."""

                def parse_quirk(
                    self,
                    value: str,
                ) -> FlextLdifProtocols.Result[m.Ldif.Acl]:
                    """Parse ACL content into the test model."""
                    ...

            @runtime_checkable
            class WriteAclContentQuirk(Protocol):
                """Quirk exposing ACL write helper with test models."""

                def write(
                    self,
                    acl_data: m.Ldif.Acl,
                ) -> FlextLdifProtocols.Result[str]:
                    """Write ACL content from the test model."""
                    ...


p = TestsFlextLdifProtocols

__all__ = ["TestsFlextLdifProtocols", "p"]
