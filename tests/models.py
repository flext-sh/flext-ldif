"""Test model definitions composing src models for centralized test objects."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, ClassVar

from flext_ldap import m
from flext_tests import FlextTestsModels
from pydantic import BaseModel, ConfigDict, Field

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

            class FixtureMetadata(BaseModel):
                """Metadata about a discovered fixture file."""

                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                server_type: Annotated[
                    t.Ldif.Tests.FixtureServer,
                    Field(description="Fixture server identifier"),
                ]
                fixture_type: Annotated[
                    t.Ldif.Tests.FixtureKind,
                    Field(description="Fixture category identifier"),
                ]
                file_path: Annotated[Path, Field(description="Fixture file path")]
                line_count: Annotated[
                    int,
                    Field(description="Number of lines in the fixture file"),
                ]
                entry_count: Annotated[
                    int,
                    Field(description="Number of LDIF entries in the fixture"),
                ]
                size_bytes: Annotated[
                    int,
                    Field(description="Fixture file size in bytes"),
                ]

            class AttributeTestCase(BaseModel):
                """Unified test case for attribute detection."""

                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                scenario: Annotated[str, Field(description="Attribute scenario")]
                attr_definition: Annotated[
                    str, Field(description="Attribute definition")
                ]
                expected_can_handle: Annotated[
                    bool,
                    Field(description="Expected can_handle result"),
                ]
                expected_oid: Annotated[
                    str | None,
                    Field(description="Expected parsed OID"),
                ] = None
                expected_name: Annotated[
                    str | None,
                    Field(description="Expected parsed attribute name"),
                ] = None

            class ObjectClassTestCase(BaseModel):
                """Unified test case for objectClass detection."""

                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                scenario: Annotated[str, Field(description="ObjectClass scenario")]
                oc_definition: Annotated[
                    str,
                    Field(description="ObjectClass definition"),
                ]
                expected_can_handle: Annotated[
                    bool,
                    Field(description="Expected can_handle result"),
                ]
                expected_oid: Annotated[
                    str | None,
                    Field(description="Expected parsed OID"),
                ] = None
                expected_name: Annotated[
                    str | None,
                    Field(description="Expected parsed objectClass name"),
                ] = None
                expected_kind: Annotated[
                    str | None,
                    Field(description="Expected parsed objectClass kind"),
                ] = None

            class EntryTestCase(BaseModel):
                """Unified test case for entry detection."""

                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                scenario: Annotated[str, Field(description="Entry scenario")]
                entry_dn: Annotated[str, Field(description="Entry DN")]
                attributes: Annotated[
                    t.MutableStrSequenceMapping,
                    Field(description="Entry attributes"),
                ]
                expected_can_handle: Annotated[
                    bool,
                    Field(description="Expected can_handle result"),
                ]

            class ProtocolServer(BaseModel):
                """Server implementation for protocol testing."""

                __test__ = False
                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                name: Annotated[str, Field(description="Implementation name")]
                server_class: Annotated[type, Field(description="Server class")]
                schema_class: Annotated[type, Field(description="Schema class")]
                fixture_servers: Annotated[
                    Sequence[t.Ldif.Tests.FixtureServer],
                    Field(description="Servers covered by the implementation"),
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

            class AclTestCase(BaseModel):
                """Unified test case for ACL handling."""

                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                scenario: Annotated[str, Field(description="ACL scenario")]
                acl_line: Annotated[str | None, Field(description="ACL line")] = None
                expected_can_handle: Annotated[
                    bool,
                    Field(description="Expected can_handle result"),
                ] = False
                expected_success: Annotated[
                    bool,
                    Field(description="Expected parse success"),
                ] = False


m = TestsFlextLdifModels

__all__: list[str] = ["TestsFlextLdifModels", "m"]
