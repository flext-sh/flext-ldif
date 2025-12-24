"""Test model definitions extending src models for centralized test objects.

This module provides test-specific model extensions that inherit from
src/flext_ldif/models.py classes. This centralizes test objects without
duplicating parent class functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests.models import FlextTestsModels

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.validation import (
    AclFormatRules,
    DnCaseRules,
    EncodingRules,
    ServerValidationRules,
)
from flext_ldif.models import FlextLdifModels


class TestsFlextLdifModels(FlextTestsModels, FlextLdifModels):
    """Test models - composição de FlextTestsModels + FlextLdifModels.

    Hierarquia:
    - FlextTestsModels: Utilitários de teste genéricos
    - FlextLdifModels: Models de domínio do projeto
    - TestsFlextLdifModels: Composição + namespace .Tests

    Access patterns:
    - tm.Tests.* - Test fixtures (ACL, Schema, etc.)
    - m.Ldif.* - Production domain models
    """

    class Tests:
        """Test fixture models namespace.

        Convenience aliases for test-only shortcuts.
        Production code should use m.Ldif.* pattern.
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
        WriteFormatOptions = FlextLdifModels.Ldif.LdifResults.WriteFormatOptions

        # Service status models for testing
        ValidationServiceStatus = (
            FlextLdifModels.Ldif.LdifResults.ValidationServiceStatus
        )
        SchemaServiceStatus = FlextLdifModels.Ldif.LdifResults.SchemaServiceStatus
        StatisticsServiceStatus = (
            FlextLdifModels.Ldif.LdifResults.StatisticsServiceStatus
        )

        # Result models for testing
        ValidationBatchResult = FlextLdifModels.Ldif.LdifResults.ValidationBatchResult
        ValidationMetadata = FlextLdifModelsDomains.ValidationMetadata

        # Validation rules for testing
        ServerValidationRules = ServerValidationRules
        EncodingRules = EncodingRules
        DnCaseRules = DnCaseRules
        AclFormatRules = AclFormatRules


# Short aliases for tests
tm = TestsFlextLdifModels
m = TestsFlextLdifModels

__all__ = [
    "TestsFlextLdifModels",
    "m",
    "tm",
]
