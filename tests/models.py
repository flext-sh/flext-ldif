"""Test model definitions composing src models for centralized test objects."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, ClassVar

from flext_tests import FlextTestsModels

from flext_ldif import FlextLdifModels
from tests import t

if TYPE_CHECKING:
    from pathlib import Path


class TestsFlextLdifModels(FlextTestsModels, FlextLdifModels):
    """Test models composed from the project and shared test namespaces."""

    class Tests(FlextTestsModels.Tests):
        """Test fixture models namespace."""

        class _Frozen(FlextLdifModels.BaseModel):
            """Base for every frozen test model in this namespace."""

            model_config: ClassVar[FlextLdifModels.ConfigDict] = (
                FlextLdifModels.ConfigDict(frozen=True)
            )

        class _CanHandleCase(_Frozen):
            """Shared fields for can_handle-style detection cases."""

            scenario: Annotated[
                str, FlextLdifModels.Field(description="Scenario identifier")
            ]
            expected_can_handle: Annotated[
                bool, FlextLdifModels.Field(description="Expected can_handle result")
            ]

        class _SchemaCase(_CanHandleCase):
            """Shared OID/NAME parsed-value expectations."""

            expected_oid: Annotated[
                str | None, FlextLdifModels.Field(description="Expected parsed OID")
            ] = None
            expected_name: Annotated[
                str | None, FlextLdifModels.Field(description="Expected parsed name")
            ] = None

        class LdifTestData(FlextLdifModels.Value):
            """Test data for LDIF utilities."""

            id: Annotated[
                str,
                FlextLdifModels.Field(
                    description="Unique identifier for the test data entry"
                ),
            ]
            server_type: Annotated[
                str,
                FlextLdifModels.Field(
                    description="Type of server associated with the entry"
                ),
            ]
            dn: Annotated[
                str,
                FlextLdifModels.Field(
                    description="Distinguished name of the LDAP entry"
                ),
            ]
            attributes: Annotated[
                t.StrSequenceMapping,
                FlextLdifModels.Field(
                    description="LDAP attributes mapped to their values"
                ),
            ]

        class FixtureMetadata(_Frozen):
            """Metadata about a discovered fixture file."""

            server_type: Annotated[
                t.Tests.FixtureServer,
                FlextLdifModels.Field(description="Fixture server identifier"),
            ]
            fixture_type: Annotated[
                t.Tests.FixtureKind,
                FlextLdifModels.Field(description="Fixture category identifier"),
            ]
            file_path: Annotated[
                Path, FlextLdifModels.Field(description="Fixture file path")
            ]
            line_count: Annotated[
                int,
                FlextLdifModels.Field(
                    description="Number of lines in the fixture file"
                ),
            ]
            entry_count: Annotated[
                int,
                FlextLdifModels.Field(
                    description="Number of LDIF entries in the fixture"
                ),
            ]
            size_bytes: Annotated[
                int, FlextLdifModels.Field(description="Fixture file size in bytes")
            ]

        class AttributeTestCase(_SchemaCase):
            """Unified test case for attribute detection."""

            attr_definition: Annotated[
                str, FlextLdifModels.Field(description="Attribute definition")
            ]

        class ObjectClassTestCase(_SchemaCase):
            """Unified test case for objectClass detection."""

            oc_definition: Annotated[
                str, FlextLdifModels.Field(description="ObjectClass definition")
            ]
            expected_kind: Annotated[
                str | None,
                FlextLdifModels.Field(description="Expected parsed objectClass kind"),
            ] = None

        class EntryTestCase(_CanHandleCase):
            """Unified test case for entry detection."""

            entry_dn: Annotated[str, FlextLdifModels.Field(description="Entry DN")]
            attributes: Annotated[
                t.MutableStrSequenceMapping,
                FlextLdifModels.Field(description="Entry attributes"),
            ]

        class ProtocolServer(_Frozen):
            """Server implementation for protocol testing."""

            name: Annotated[
                str, FlextLdifModels.Field(description="Implementation name")
            ]
            server_class: Annotated[
                type, FlextLdifModels.Field(description="Server class")
            ]
            schema_class: Annotated[
                type, FlextLdifModels.Field(description="Schema class")
            ]
            fixture_servers: Annotated[
                t.SequenceOf[t.Tests.FixtureServer],
                FlextLdifModels.Field(
                    description="Servers covered by the implementation"
                ),
            ] = ()

        class AclTestCase(_Frozen):
            """Unified test case for ACL handling."""

            scenario: Annotated[str, FlextLdifModels.Field(description="ACL scenario")]
            acl_line: Annotated[
                str | None, FlextLdifModels.Field(description="ACL line")
            ] = None
            expected_can_handle: Annotated[
                bool, FlextLdifModels.Field(description="Expected can_handle result")
            ] = False
            expected_success: Annotated[
                bool, FlextLdifModels.Field(description="Expected parse success")
            ] = False


m = TestsFlextLdifModels

__all__: list[str] = ["TestsFlextLdifModels", "m"]
