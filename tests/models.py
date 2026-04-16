"""Test model definitions composing src models for centralized test objects."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, ClassVar

from flext_ldap import m
from flext_tests import FlextTestsModels
from pydantic import ConfigDict

from tests import t


class TestsFlextLdifModels(FlextTestsModels, m):
    """Test models composed from the project and shared test namespaces."""

    class Ldif(m.Ldif):
        """Production LDIF models with nested test-only models."""

        class Tests:
            """Test fixture models namespace."""

            class LdifTestData(m.Value):
                """Test data for LDIF utilities."""

                id: str
                server_type: str
                dn: str
                attributes: t.StrSequenceMapping

            class FixtureMetadata(m.BaseModel):
                """Metadata about a discovered fixture file."""

                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                server_type: Annotated[
                    t.Ldif.Tests.FixtureServer,
                    m.Field(description="Fixture server identifier"),
                ]
                fixture_type: Annotated[
                    t.Ldif.Tests.FixtureKind,
                    m.Field(description="Fixture category identifier"),
                ]
                file_path: Annotated[Path, m.Field(description="Fixture file path")]
                line_count: Annotated[
                    int,
                    m.Field(description="Number of lines in the fixture file"),
                ]
                entry_count: Annotated[
                    int,
                    m.Field(description="Number of LDIF entries in the fixture"),
                ]
                size_bytes: Annotated[
                    int,
                    m.Field(description="Fixture file size in bytes"),
                ]

            class AttributeTestCase(m.BaseModel):
                """Unified test case for attribute detection."""

                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                scenario: Annotated[str, m.Field(description="Attribute scenario")]
                attr_definition: Annotated[
                    str, m.Field(description="Attribute definition")
                ]
                expected_can_handle: Annotated[
                    bool,
                    m.Field(description="Expected can_handle result"),
                ]
                expected_oid: Annotated[
                    str | None,
                    m.Field(description="Expected parsed OID"),
                ] = None
                expected_name: Annotated[
                    str | None,
                    m.Field(description="Expected parsed attribute name"),
                ] = None

            class ObjectClassTestCase(m.BaseModel):
                """Unified test case for objectClass detection."""

                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                scenario: Annotated[str, m.Field(description="ObjectClass scenario")]
                oc_definition: Annotated[
                    str,
                    m.Field(description="ObjectClass definition"),
                ]
                expected_can_handle: Annotated[
                    bool,
                    m.Field(description="Expected can_handle result"),
                ]
                expected_oid: Annotated[
                    str | None,
                    m.Field(description="Expected parsed OID"),
                ] = None
                expected_name: Annotated[
                    str | None,
                    m.Field(description="Expected parsed objectClass name"),
                ] = None
                expected_kind: Annotated[
                    str | None,
                    m.Field(description="Expected parsed objectClass kind"),
                ] = None

            class EntryTestCase(m.BaseModel):
                """Unified test case for entry detection."""

                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                scenario: Annotated[str, m.Field(description="Entry scenario")]
                entry_dn: Annotated[str, m.Field(description="Entry DN")]
                attributes: Annotated[
                    t.MutableStrSequenceMapping,
                    m.Field(description="Entry attributes"),
                ]
                expected_can_handle: Annotated[
                    bool,
                    m.Field(description="Expected can_handle result"),
                ]

            class ProtocolServer(m.BaseModel):
                """Server implementation for protocol testing."""

                __test__ = False
                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                name: Annotated[str, m.Field(description="Implementation name")]
                server_class: Annotated[type, m.Field(description="Server class")]
                schema_class: Annotated[type, m.Field(description="Schema class")]
                fixture_servers: Annotated[
                    Sequence[t.Ldif.Tests.FixtureServer],
                    m.Field(description="Servers covered by the implementation"),
                ] = ()

            class OidServerStub:
                """Minimal nested server stub for server-type extraction tests."""

                class Constants:
                    """Server constants stub used by detection helpers."""

                    SERVER_TYPE = "oid"

                class Entry:
                    """Nested entry stub preserving the server namespace."""

            class OudServerStub:
                """Minimal server stub for server-type extraction tests."""

                class Constants:
                    """Server constants stub used by detection helpers."""

                    SERVER_TYPE = "oud"

            class AclTestCase(m.BaseModel):
                """Unified test case for ACL handling."""

                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                scenario: Annotated[str, m.Field(description="ACL scenario")]
                acl_line: Annotated[str | None, m.Field(description="ACL line")] = None
                expected_can_handle: Annotated[
                    bool,
                    m.Field(description="Expected can_handle result"),
                ] = False
                expected_success: Annotated[
                    bool,
                    m.Field(description="Expected parse success"),
                ] = False


m = TestsFlextLdifModels

__all__: list[str] = ["TestsFlextLdifModels", "m"]
