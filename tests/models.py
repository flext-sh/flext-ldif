"""Test model definitions composing src models for centralized test objects.

This module provides test-specific model composition (NOT inheritance) from
src/flext_ldif/models.py and flext_tests/models.py. Uses composition to
avoid triggering deprecation warnings from __init_subclass__ hooks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

from flext_tests import FlextTestsModels

from flext_ldif import FlextLdifModels
from flext_ldif._models.settings import FlextLdifModelsSettings


class TestsFlextLdifModels(FlextTestsModels, FlextLdifModels):
    """Test models - composition of FlextTestsModels + FlextLdifModels.

    Uses composition instead of inheritance to avoid deprecation warnings
    from FlextTestsModels.__init_subclass__ and FlextLdifModels.__init_subclass__.

    Access patterns:
    - m.Ldif.* - Production domain models (delegated from FlextLdifModels.Ldif)
    - m.Ldif.Tests.* - Test fixtures (ACL, Schema, etc.)
    - m.WriteFormatOptions - Root-level production models
    - m.StatisticsResult - Root-level production models
    """

    # Root-level test aliases for common domain models
    WriteFormatOptions: Final = FlextLdifModels.WriteFormatOptions
    StatisticsResult: Final = FlextLdifModels.StatisticsResult

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
            EncodingRules = FlextLdifModelsSettings.EncodingRules
            DnCaseRules = FlextLdifModelsSettings.DnCaseRules
            AclFormatRules = FlextLdifModelsSettings.AclFormatRules

            class LdifTestData(FlextLdifModels.Value):
                """Test data for LDIF utilities."""

                id: str
                server_type: str
                dn: str
                attributes: dict[str, list[str]]


# Short aliases for tests

__all__ = [
    "TestsFlextLdifModels",
    "m",
]

m = TestsFlextLdifModels
