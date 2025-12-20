"""Test model definitions extending src models for centralized test objects.

This module provides test-specific model extensions that inherit from
src/flext_ldif/models.py classes. This centralizes test objects without
duplicating parent class functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests.models import FlextTestsModels

from flext_ldif.models import FlextLdifModels


class TestsFlextLdifModels(FlextTestsModels, FlextLdifModels):
    """Test models extending FlextTestsModels and FlextLdifModels.

    Provides test-specific model extensions without duplicating parent functionality.
    All parent models are accessible via inheritance hierarchy.

    Naming convention: Tests[FlextLdif] where FlextLdif is the project name.
    Short name 'm' for convenient access in tests.
    """

    # Test-specific model extensions can be added here
    # All parent models (Entry, SchemaEventConfig, etc.) are accessible via inheritance

    # Convenience aliases for ACL models (test-only shortcuts)
    # Production code should use m.Ldif.Acl pattern
    Acl = FlextLdifModels.Ldif.Acl
    AclTarget = FlextLdifModels.Ldif.AclTarget
    AclSubject = FlextLdifModels.Ldif.AclSubject
    AclPermissions = FlextLdifModels.Ldif.AclPermissions
    AclWriteMetadata = FlextLdifModels.Ldif.AclWriteMetadata

    # Convenience aliases for schema models (test-only shortcuts)
    Syntax = FlextLdifModels.Ldif.Syntax
    SchemaAttribute = FlextLdifModels.Ldif.SchemaAttribute
    SchemaObjectClass = FlextLdifModels.Ldif.SchemaObjectClass

    # Convenience aliases for format options (test-only shortcuts)
    WriteFormatOptions = FlextLdifModels.Ldif.LdifResults.WriteFormatOptions

    # Service status models (direct aliases for test convenience)
    ValidationServiceStatus = FlextLdifModels.Ldif.LdifResults.ValidationServiceStatus
    SchemaServiceStatus = FlextLdifModels.Ldif.LdifResults.SchemaServiceStatus
    StatisticsServiceStatus = FlextLdifModels.Ldif.LdifResults.StatisticsServiceStatus

    # Result models (direct aliases for test convenience)
    ValidationBatchResult = FlextLdifModels.Ldif.LdifResults.ValidationBatchResult


# Standardized short name for use in tests (same pattern as flext-core)
m = TestsFlextLdifModels

__all__ = [
    "TestsFlextLdifModels",
    "m",
]
