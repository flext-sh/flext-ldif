"""Test model definitions composing src models for centralized test objects."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, ClassVar

from flext_tests import FlextTestsModels

from flext_ldif import m, u

if TYPE_CHECKING:
    from pathlib import Path

    from tests.typings import t


class TestsFlextLdifModels(FlextTestsModels, m):
    """Test models composed from the project and shared test namespaces."""

    class Tests(FlextTestsModels.Tests):
        """Test fixture models namespace."""

        class _Frozen(m.BaseModel):
            """Base for every frozen test model in this namespace."""

            model_config: ClassVar[m.ConfigDict] = m.ConfigDict(frozen=True)

        class _CanHandleCase(_Frozen):
            """Shared fields for can_handle-style detection cases."""

            scenario: Annotated[str, u.Field(description="Scenario identifier")]
            expected_can_handle: Annotated[
                bool,
                u.Field(description="Expected can_handle result"),
            ]

        class _SchemaCase(_CanHandleCase):
            """Shared OID/NAME parsed-value expectations."""

            expected_oid: Annotated[
                str | None,
                u.Field(description="Expected parsed OID"),
            ] = None
            expected_name: Annotated[
                str | None,
                u.Field(description="Expected parsed name"),
            ] = None

        class LdifTestData(m.Value):
            """Test data for LDIF utilities."""

            id: Annotated[
                str,
                u.Field(description="Unique identifier for the test data entry"),
            ]
            server_type: Annotated[
                str,
                u.Field(description="Type of server associated with the entry"),
            ]
            dn: Annotated[
                str,
                u.Field(description="Distinguished name of the LDAP entry"),
            ]
            attributes: Annotated[
                t.StrSequenceMapping,
                u.Field(description="LDAP attributes mapped to their values"),
            ]

        class FixtureMetadata(_Frozen):
            """Metadata about a discovered fixture file."""

            server_type: Annotated[
                t.Tests.FixtureServer,
                u.Field(description="Fixture server identifier"),
            ]
            fixture_type: Annotated[
                t.Tests.FixtureKind,
                u.Field(description="Fixture category identifier"),
            ]
            file_path: Annotated[Path, u.Field(description="Fixture file path")]
            line_count: Annotated[
                int,
                u.Field(description="Number of lines in the fixture file"),
            ]
            entry_count: Annotated[
                int,
                u.Field(description="Number of LDIF entries in the fixture"),
            ]
            size_bytes: Annotated[
                int,
                u.Field(description="Fixture file size in bytes"),
            ]

        class AttributeTestCase(_SchemaCase):
            """Unified test case for attribute detection."""

            attr_definition: Annotated[str, u.Field(description="Attribute definition")]

        class ObjectClassTestCase(_SchemaCase):
            """Unified test case for objectClass detection."""

            oc_definition: Annotated[str, u.Field(description="ObjectClass definition")]
            expected_kind: Annotated[
                str | None,
                u.Field(description="Expected parsed objectClass kind"),
            ] = None

        class EntryTestCase(_CanHandleCase):
            """Unified test case for entry detection."""

            entry_dn: Annotated[str, u.Field(description="Entry DN")]
            attributes: Annotated[
                t.MutableStrSequenceMapping,
                u.Field(description="Entry attributes"),
            ]

        class ProtocolServer(_Frozen):
            """Server implementation for protocol testing."""

            name: Annotated[str, u.Field(description="Implementation name")]
            server_class: Annotated[type, u.Field(description="Server class")]
            schema_class: Annotated[type, u.Field(description="Schema class")]
            fixture_servers: Annotated[
                t.SequenceOf[t.Tests.FixtureServer],
                u.Field(description="Servers covered by the implementation"),
            ] = ()

        class AclTestCase(_Frozen):
            """Unified test case for ACL handling."""

            scenario: Annotated[str, u.Field(description="ACL scenario")]
            acl_line: Annotated[str | None, u.Field(description="ACL line")] = None
            expected_can_handle: Annotated[
                bool,
                u.Field(description="Expected can_handle result"),
            ] = False
            expected_success: Annotated[
                bool,
                u.Field(description="Expected parse success"),
            ] = False


m = TestsFlextLdifModels

__all__: list[str] = ["TestsFlextLdifModels", "m"]
