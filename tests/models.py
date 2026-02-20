"""Test model definitions composing src models for centralized test objects.

This module provides test-specific model composition (NOT inheritance) from
src/flext_ldif/models.py and flext_tests/models.py. Uses composition to
avoid triggering deprecation warnings from __init_subclass__ hooks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.validation import (
    AclFormatRules,
    DnCaseRules,
    EncodingRules,
    ServerValidationRules,
)
from flext_ldif.models import FlextLdifModels
from flext_tests.models import FlextTestsModels


class TestsFlextLdifModels:
    """Test models - composition of FlextTestsModels + FlextLdifModels.

    Uses composition instead of inheritance to avoid deprecation warnings
    from FlextTestsModels.__init_subclass__ and FlextLdifModels.__init_subclass__.

    Access patterns:
    - tm.Tests.* - Test fixtures (ACL, Schema, etc.)
    - m.Ldif.* - Production domain models
    - m.WriteFormatOptions - Root-level test aliases for common fixtures
    - m.StatisticsResult - Root-level test aliases for common fixtures
    """

    # Production domain models namespace (composed from FlextLdifModels)
    Ldif = FlextLdifModels.Ldif

    # Root-level aliases for frequently used test models
    WriteFormatOptions = FlextLdifModels.Ldif.LdifResults.WriteFormatOptions
    StatisticsResult = FlextLdifModels.Ldif.LdifResults.StatisticsResult

    class Tests(FlextTestsModels.Tests):
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
        StatisticsResult = FlextLdifModels.Ldif.LdifResults.StatisticsResult

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
