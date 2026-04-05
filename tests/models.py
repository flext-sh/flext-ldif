"""Test model definitions composing src models for centralized test objects.

This module provides test-specific model composition (NOT inheritance) from
src/flext_ldif/models.py and flext_tests/models.py. Uses composition to
avoid triggering deprecation warnings from __init_subclass__ hooks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, ClassVar

from flext_tests import FlextTestsModels
from pydantic import BaseModel, ConfigDict, Field

from flext_ldif import FlextLdifModels, FlextLdifModelsSettings
from tests import t


class FlextLdifTestModels(FlextTestsModels, FlextLdifModels):
    """Test models - composition of FlextTestsModels + FlextLdifModels.

    Uses composition instead of inheritance to avoid deprecation warnings
    from FlextTestsModels.__init_subclass__ and FlextLdifModels.__init_subclass__.

    Access patterns:
    - FlextLdifTestModels.Ldif.* - Production domain models (delegated from FlextLdifModels.Ldif)
    - FlextLdifTestModels.Ldif.Tests.* - Test fixtures (ACL, Schema, etc.)
    """

    # Production models namespace delegation
    class Ldif(FlextLdifModels.Ldif):
        """Production LDIF models with nested test fixture aliases."""

        class Tests:
            """Test fixture models namespace.

            Convenience aliases for test-only shortcuts.
            Production code should use FlextLdifModels.Ldif.* pattern.
            """

            # ACL models for testing
            Acl = FlextLdifModels.Ldif.Acl
            AclTarget = FlextLdifModels.Ldif.AclTarget
            AclSubject = FlextLdifModels.Ldif.AclSubject
            AclPermissions = FlextLdifModels.Ldif.AclPermissions
            AclWriteMetadata = FlextLdifModels.Ldif.AclWriteMetadata

            # Schema models for testing
            Syntax = FlextLdifModels.Ldif.Syntax
            SchemaAttribute = FlextLdifModels.Ldif.SchemaAttribute
            SchemaObjectClass = FlextLdifModels.Ldif.SchemaObjectClass

            # Format options for testing
            WriteFormatOptions = FlextLdifModels.Ldif.WriteFormatOptions

            # Service status models for testing
            ValidationServiceStatus = FlextLdifModels.Ldif.ValidationServiceStatus
            SchemaServiceStatus = FlextLdifModels.Ldif.SchemaServiceStatus
            StatisticsServiceStatus = FlextLdifModels.Ldif.StatisticsServiceStatus

            # Result models for testing
            ValidationBatchResult = FlextLdifModels.Ldif.ValidationBatchResult
            ValidationMetadata = FlextLdifModels.Ldif.ValidationMetadata
            StatisticsResult = FlextLdifModels.Ldif.StatisticsResult

            # Validation rules for testing
            ServerValidationRules = FlextLdifModelsSettings.ServerValidationRules

            class LdifTestData(FlextLdifModels.Value):
                """Test data for LDIF utilities."""

                id: str
                server_type: str
                dn: str
                attributes: t.StrSequenceMapping

            class LdifSample(BaseModel):
                """LDIF sample with metadata for test data generation."""

                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                content: Annotated[str, Field(description="LDIF content as string")]
                description: Annotated[
                    str,
                    Field(description="Human-readable description of the sample"),
                ]
                expected_entries: Annotated[
                    int,
                    Field(description="Expected number of entries in the LDIF"),
                ]
                has_binary: Annotated[
                    bool,
                    Field(description="Whether the sample contains binary data"),
                ] = False
                has_changes: Annotated[
                    bool,
                    Field(description="Whether the sample contains change records"),
                ] = False

            class AttributeTestCase(BaseModel):
                """Unified test case for attribute detection and parsing across all quirk servers."""

                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                scenario: Annotated[
                    str, Field(description="Attribute scenario identifier")
                ]
                attr_definition: Annotated[
                    str,
                    Field(description="Schema attribute definition string"),
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
                """Unified test case for objectClass detection and parsing across all quirk servers."""

                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                scenario: Annotated[
                    str, Field(description="ObjectClass scenario identifier")
                ]
                oc_definition: Annotated[
                    str,
                    Field(description="Schema objectClass definition string"),
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
                """Unified test case for entry detection across all quirk servers."""

                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                scenario: Annotated[
                    str, Field(description="Entry detection scenario identifier")
                ]
                entry_dn: Annotated[str, Field(description="Entry distinguished name")]
                attributes: Annotated[
                    t.MutableStrSequenceMapping,
                    Field(description="Entry attributes mapped by name"),
                ]
                expected_can_handle: Annotated[
                    bool,
                    Field(description="Expected can_handle result"),
                ]

            class ProtocolServer(BaseModel):
                """Server implementation for schema protocol testing."""

                __test__ = False
                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                name: Annotated[
                    str, Field(description="Protocol server implementation name")
                ]
                server_class: Annotated[
                    type, Field(description="Server implementation class")
                ]
                schema_class: Annotated[
                    type, Field(description="Schema implementation class")
                ]

            class OidServerStub:
                """Stub OID server for testing."""

                class Constants:
                    """OID server constants."""

                    SERVER_TYPE = "oid"

                class Entry:
                    """OID entry stub."""

            class OudServerStub:
                """Stub OUD server for testing."""

                class Constants:
                    """OUD server constants."""

                    SERVER_TYPE = "oud"

            class AclTestCase(BaseModel):
                """Unified test case for ACL handling across all quirk servers."""

                model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

                scenario: Annotated[str, Field(description="ACL scenario identifier")]
                acl_line: Annotated[
                    str | None,
                    Field(description="ACL line under test"),
                ] = None
                expected_can_handle: Annotated[
                    bool,
                    Field(description="Expected can_handle result"),
                ] = False
                expected_success: Annotated[
                    bool,
                    Field(description="Expected parse success state"),
                ] = False


m = FlextLdifTestModels

__all__ = [
    "FlextLdifTestModels",
    "m",
]
