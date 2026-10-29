"""Protocol definitions for flext-ldif tests.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_tests import p as flext_tests_p

from flext_ldif import p

if TYPE_CHECKING:
    from tests import m


class TestsFlextLdifProtocolsLdap(p):
    """ldap3 client contracts grouped for composition by the tests facade."""

    @runtime_checkable
    class Ldap3Server(Protocol):
        """Opaque ldap3-compatible server handle."""

        @property
        def name(self) -> str | None:
            """The configured server name."""
            ...

    # ── Shared structural contracts (SSOT: flext_ldif._protocols.ldap3) ──
    type Ldap3Attribute = p.Ldif.Ldap3Attribute
    type Ldap3Entry = p.Ldif.Ldap3Entry
    type Ldap3Connection = p.Ldif.Ldap3Connection

    @runtime_checkable
    class Ldap3EntryAdapter(Protocol):
        """Structural contract for the ldap3 entry to LDIF entry adapter."""

        def ldap3_to_ldif_entry(
            self,
            ldap3_entry: TestsFlextLdifProtocolsLdap.Ldap3Entry,
        ) -> p.Result[m.Ldif.Entry]:
            """Convert one ldap3 entry into the LDIF entry model."""
            ...


class TestsFlextLdifProtocols(
    TestsFlextLdifProtocolsLdap,
    flext_tests_p,
    p,
):
    """Protocol definitions for flext-ldif tests.

    The ldap3 client contracts compose in through their focused module so the
    ``p.Ldap3*`` surface stays unchanged without a second nested namespace.
    """

    class Tests(flext_tests_p.Tests):
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


p = TestsFlextLdifProtocols

__all__: list[str] = [
    "TestsFlextLdifProtocols",
    "TestsFlextLdifProtocolsLdap",
    "p",
]
