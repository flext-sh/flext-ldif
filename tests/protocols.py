"""Protocol definitions for flext-ldif tests.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_tests import p as flext_tests_p

from flext_ldif import p

if TYPE_CHECKING:
    from tests import m, t


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
            ldap3_entry: TestsFlextLdifProtocolsLdap.Ldif.Ldap3Entry,
        ) -> p.Result[p.Ldif.Entry]:
            """Convert one ldap3 entry into the LDIF entry model."""
            ...


class TestsFlextLdifProtocols(
    TestsFlextLdifProtocolsLdap,
    flext_tests_p,
    p,
):
    """Protocol definitions for flext-ldif tests.

    The ldap3 client contracts compose in through their focused module so the
    ``p.Ldif.Ldap3*`` surface stays unchanged without a second nested namespace.
    """

    class Tests(flext_tests_p.Tests):
        """LDIF helper protocols used only by tests."""

        @runtime_checkable
        class LdifTestData(Protocol):
            """Structural contract of one LDIF test data record."""

            @property
            def id(self) -> str:
                """Unique identifier for the test data entry."""
                ...

            @property
            def server_type(self) -> str:
                """Type of server associated with the entry."""
                ...

            @property
            def dn(self) -> str:
                """Distinguished name of the LDAP entry."""
                ...

            @property
            def attributes(self) -> t.StrSequenceMapping:
                """LDAP attributes mapped to their values."""
                ...

        @runtime_checkable
        class FixtureMetadata(Protocol):
            """Structural contract of one discovered fixture file."""

            @property
            def server_type(self) -> t.Tests.FixtureServer:
                """Fixture server identifier."""
                ...

            @property
            def fixture_type(self) -> t.Tests.FixtureKind:
                """Fixture category identifier."""
                ...

            @property
            def file_path(self) -> Path:
                """Fixture file path."""
                ...

            @property
            def line_count(self) -> int:
                """Number of lines in the fixture file."""
                ...

            @property
            def entry_count(self) -> int:
                """Number of LDIF entries in the fixture."""
                ...

            @property
            def size_bytes(self) -> int:
                """Fixture file size in bytes."""
                ...

        @runtime_checkable
        class SchemaTestCase(Protocol):
            """Shared OID/NAME parsed-value expectations of a schema case."""

            @property
            def scenario(self) -> str:
                """Scenario identifier."""
                ...

            @property
            def expected_can_handle(self) -> bool:
                """Expected can_handle result."""
                ...

            @property
            def expected_oid(self) -> str | None:
                """Expected parsed OID."""
                ...

            @property
            def expected_name(self) -> str | None:
                """Expected parsed name."""
                ...

        @runtime_checkable
        class AttributeTestCase(SchemaTestCase, Protocol):
            """Structural contract of one attribute detection case."""

            @property
            def attr_definition(self) -> str:
                """Attribute definition."""
                ...

        @runtime_checkable
        class ObjectClassTestCase(SchemaTestCase, Protocol):
            """Structural contract of one objectClass detection case."""

            @property
            def oc_definition(self) -> str:
                """ObjectClass definition."""
                ...

            @property
            def expected_kind(self) -> str | None:
                """Expected parsed objectClass kind."""
                ...

        @runtime_checkable
        class EntryTestCase(Protocol):
            """Structural contract of one entry detection case."""

            @property
            def scenario(self) -> str:
                """Scenario identifier."""
                ...

            @property
            def expected_can_handle(self) -> bool:
                """Expected can_handle result."""
                ...

            @property
            def entry_dn(self) -> str:
                """Entry DN."""
                ...

            @property
            def attributes(self) -> t.MutableStrSequenceMapping:
                """Entry attributes."""
                ...

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
                attr_data: p.Ldif.SchemaAttribute,
            ) -> p.Result[str]:
                """Serialize an attribute definition."""
                ...

        @runtime_checkable
        class WriteObjectClassServer(Protocol):
            """Server exposing Apache/Novell objectclass writer."""

            def _write_objectclass(
                self,
                oc_data: p.Ldif.SchemaObjectClass,
            ) -> p.Result[str]:
                """Serialize an objectClass definition."""
                ...

        @runtime_checkable
        class WriteAclServer(Protocol):
            """Server exposing Apache ACL writer helper."""

            def _write_acl(self, acl_data: p.Ldif.Acl) -> p.Result[str]:
                """Serialize an ACL definition."""
                ...

        @runtime_checkable
        class ParseAclServer(Protocol):
            """Server exposing ACL parse helper with test models."""

            def parse_server(self, value: str) -> p.Result[p.Ldif.Acl]:
                """Parse ACL content into the test model."""
                ...

        @runtime_checkable
        class WriteAclContentServer(Protocol):
            """Server exposing ACL write helper with test models."""

            def write(self, acl_data: p.Ldif.Acl) -> p.Result[str]:
                """Write ACL content from the test model."""
                ...


p = TestsFlextLdifProtocols

__all__: list[str] = [
    "TestsFlextLdifProtocols",
    "TestsFlextLdifProtocolsLdap",
    "p",
]
