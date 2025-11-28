"""Test constants and helpers for flext-ldif tests.

This module provides test-specific constants that complement but do not duplicate
src/flext_ldif/constants.py. These constants are used exclusively in tests for:
- Test data generation
- Test fixtures
- Test assertions
- Mock data

**Important:** This module should NOT duplicate constants from src/constants.py.
Instead, it should import and reuse them when possible, or define test-specific
constants that are not part of the production codebase.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

from flext_ldif.constants import FlextLdifConstants

__all__ = [
    "FlextLdifTestConstants",
]


class FlextLdifTestConstants:
    """Test-specific constants for flext-ldif tests.

    These constants are used exclusively in tests and complement the production
    constants from FlextLdifConstants. They should not duplicate production constants.
    """

    # =========================================================================
    # TEST DATA CONSTANTS
    # =========================================================================

    class TestData:
        """Test data generation constants."""

        # Sample DNs for testing
        SAMPLE_BASE_DN: Final[str] = "dc=test,dc=local"
        SAMPLE_USER_DN: Final[str] = "cn=testuser,dc=test,dc=local"
        SAMPLE_GROUP_DN: Final[str] = "cn=testgroup,dc=test,dc=local"
        SAMPLE_OU_DN: Final[str] = "ou=testou,dc=test,dc=local"

        # Sample attributes for testing
        SAMPLE_CN: Final[str] = "testuser"
        SAMPLE_UID: Final[str] = "testuser"
        SAMPLE_MAIL: Final[str] = "testuser@internal.invalid"

        # Test file paths (relative to test fixtures)
        FIXTURE_DIR: Final[str] = "tests/fixtures"
        RFC_FIXTURE_DIR: Final[str] = "tests/fixtures/rfc"

    # =========================================================================
    # TEST CONFIGURATION CONSTANTS
    # =========================================================================

    class TestConfig:
        """Test configuration constants."""

        # Timeout values for tests
        DEFAULT_TIMEOUT: Final[int] = 30
        LONG_TIMEOUT: Final[int] = 120

        # Test data sizes
        SMALL_DATASET_SIZE: Final[int] = 10
        MEDIUM_DATASET_SIZE: Final[int] = 100
        LARGE_DATASET_SIZE: Final[int] = 1000

        # Test validation levels (reusing production constants as type aliases)
        # Note: These are type aliases, not values - use FlextLdifConstants for actual values
        # Using PEP 695 type statement for better type checking
        type ValidationLevelLiteral = (
            FlextLdifConstants.LiteralTypes.ValidationLevelLiteral
        )

    # =========================================================================
    # TEST ASSERTION CONSTANTS
    # =========================================================================

    class TestAssertions:
        """Constants for test assertions."""

        # Tolerance values for floating point comparisons
        FLOAT_TOLERANCE: Final[float] = 1e-6

        # String comparison options
        CASE_SENSITIVE: Final[bool] = True
        CASE_INSENSITIVE: Final[bool] = False

    # =========================================================================
    # TEST SERVER TYPES (reusing production constants)
    # =========================================================================

    # Reuse production server types for consistency
    # Tests should use FlextLdifConstants.ServerTypes or LiteralTypes.ServerTypeLiteral
    # This is just for convenience in tests
    class TestServerTypes:
        """Test server type constants (reusing production types).

        These are convenience aliases that reference production constants.
        Always prefer using FlextLdifConstants.ServerTypes directly when possible.
        """

        # Import production server types for test use (Python 3.13+ best practices)
        # Using Final to ensure immutability and type safety
        RFC: Final[str] = FlextLdifConstants.ServerTypes.RFC
        OID: Final[str] = FlextLdifConstants.ServerTypes.OID
        OUD: Final[str] = FlextLdifConstants.ServerTypes.OUD
        OPENLDAP: Final[str] = FlextLdifConstants.ServerTypes.OPENLDAP
        GENERIC: Final[str] = FlextLdifConstants.ServerTypes.GENERIC

    # =========================================================================
    # TEST LITERAL TYPES (reusing production Literals)
    # =========================================================================

    class TestLiterals:
        """Test-specific Literal types (reusing production types).

        These type aliases reference production Literals for use in test type hints.
        Always prefer using FlextLdifConstants.LiteralTypes directly when possible.
        Using PEP 695 type statements for better type checking (Python 3.13+).
        """

        # Server type literal (reusing production type)
        type ServerTypeLiteral = FlextLdifConstants.LiteralTypes.ServerTypeLiteral

        # Validation level literal (reusing production type)
        type ValidationLevelLiteral = (
            FlextLdifConstants.LiteralTypes.ValidationLevelLiteral
        )

        # Category literal (reusing production type)
        type CategoryLiteral = FlextLdifConstants.LiteralTypes.CategoryLiteral

        # Processing stage literal (reusing production type)
        type ProcessingStageLiteral = (
            FlextLdifConstants.LiteralTypes.ProcessingStageLiteral
        )

        # Health status literal (reusing production type)
        type HealthStatusLiteral = FlextLdifConstants.LiteralTypes.HealthStatusLiteral

        # Transformation type literal (reusing production type)
        type TransformationTypeLiteral = (
            FlextLdifConstants.LiteralTypes.TransformationTypeLiteral
        )

        # Filter type literal (reusing production type)
        type FilterTypeLiteral = FlextLdifConstants.LiteralTypes.FilterTypeLiteral

        # Validation status literal (reusing production type)
        type ValidationStatusLiteral = (
            FlextLdifConstants.LiteralTypes.ValidationStatusLiteral
        )

        # Rejection category literal (reusing production type)
        type RejectionCategoryLiteral = (
            FlextLdifConstants.LiteralTypes.RejectionCategoryLiteral
        )

        # Error category literal (reusing production type)
        type ErrorCategoryLiteral = FlextLdifConstants.LiteralTypes.ErrorCategoryLiteral

        # Acl subject type literal (reusing production type)
        type AclSubjectTypeLiteral = (
            FlextLdifConstants.LiteralTypes.AclSubjectTypeLiteral
        )
