"""Test model definitions composing src models for centralized test objects."""

from __future__ import annotations

from collections.abc import (
    Sequence,
)
from pathlib import Path
from typing import Annotated, ClassVar

from flext_tests import FlextTestsModels

from flext_ldif import m, u
from tests import t


class TestsFlextLdifModels(FlextTestsModels, m):
    """Test models composed from the project and shared test namespaces."""

    class Ldif(m.Ldif):
        """Production LDIF models with nested test-only models."""

        class Tests:
            """Test fixture models namespace."""

            class LdifTestData(m.Value):
                """Test data for LDIF utilities."""

                id: Annotated[
                    str,
                    u.Field(description="Unique identifier for the test data entry"),
                ]
                server_type: Annotated[
                    str, u.Field(description="Type of server associated with the entry")
                ]
                dn: Annotated[
                    str, u.Field(description="Distinguished name of the LDAP entry")
                ]
                attributes: Annotated[
                    t.StrSequenceMapping,
                    u.Field(description="LDAP attributes mapped to their values"),
                ]

            class FixtureMetadata(m.BaseModel):
                """Metadata about a discovered fixture file."""

                model_config: ClassVar[m.ConfigDict] = m.ConfigDict(frozen=True)

                server_type: Annotated[
                    t.Ldif.Tests.FixtureServer,
                    u.Field(description="Fixture server identifier"),
                ]
                fixture_type: Annotated[
                    t.Ldif.Tests.FixtureKind,
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

            class AttributeTestCase(m.BaseModel):
                """Unified test case for attribute detection."""

                model_config: ClassVar[m.ConfigDict] = m.ConfigDict(frozen=True)

                scenario: Annotated[str, u.Field(description="Attribute scenario")]
                attr_definition: Annotated[
                    str, u.Field(description="Attribute definition")
                ]
                expected_can_handle: Annotated[
                    bool,
                    u.Field(description="Expected can_handle result"),
                ]
                expected_oid: Annotated[
                    str | None,
                    u.Field(description="Expected parsed OID"),
                ] = None
                expected_name: Annotated[
                    str | None,
                    u.Field(description="Expected parsed attribute name"),
                ] = None

            class ObjectClassTestCase(m.BaseModel):
                """Unified test case for objectClass detection."""

                model_config: ClassVar[m.ConfigDict] = m.ConfigDict(frozen=True)

                scenario: Annotated[str, u.Field(description="ObjectClass scenario")]
                oc_definition: Annotated[
                    str,
                    u.Field(description="ObjectClass definition"),
                ]
                expected_can_handle: Annotated[
                    bool,
                    u.Field(description="Expected can_handle result"),
                ]
                expected_oid: Annotated[
                    str | None,
                    u.Field(description="Expected parsed OID"),
                ] = None
                expected_name: Annotated[
                    str | None,
                    u.Field(description="Expected parsed objectClass name"),
                ] = None
                expected_kind: Annotated[
                    str | None,
                    u.Field(description="Expected parsed objectClass kind"),
                ] = None

            class EntryTestCase(m.BaseModel):
                """Unified test case for entry detection."""

                model_config: ClassVar[m.ConfigDict] = m.ConfigDict(frozen=True)

                scenario: Annotated[str, u.Field(description="Entry scenario")]
                entry_dn: Annotated[str, u.Field(description="Entry DN")]
                attributes: Annotated[
                    t.MutableStrSequenceMapping,
                    u.Field(description="Entry attributes"),
                ]
                expected_can_handle: Annotated[
                    bool,
                    u.Field(description="Expected can_handle result"),
                ]

            class ProtocolServer(m.BaseModel):
                """Server implementation for protocol testing."""

                model_config: ClassVar[m.ConfigDict] = m.ConfigDict(frozen=True)

                name: Annotated[str, u.Field(description="Implementation name")]
                server_class: Annotated[type, u.Field(description="Server class")]
                schema_class: Annotated[type, u.Field(description="Schema class")]
                fixture_servers: Annotated[
                    Sequence[t.Ldif.Tests.FixtureServer],
                    u.Field(description="Servers covered by the implementation"),
                ] = ()

            class AclTestCase(m.BaseModel):
                """Unified test case for ACL handling."""

                model_config: ClassVar[m.ConfigDict] = m.ConfigDict(frozen=True)

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
