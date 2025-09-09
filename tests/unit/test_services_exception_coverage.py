"""Test exception handling coverage for services.py.

Coverage-focused tests for uncovered exception handling paths.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import Mock

from flext_tests import FlextTestsUtilities

from flext_ldif.services import FlextLDIFServices


class TestServicesExceptionCoverage:
    """Test exception handling paths in services for coverage."""

    def test_validator_service_exception_handling(self) -> None:
        """Test exception handling in ValidatorService.validate_entries."""
        validator = FlextLDIFServices.ValidatorService()

        # Create a mock entry that will raise an exception during validation
        mock_entry = Mock()
        mock_entry.validate_business_rules.side_effect = ValueError("Test validation error")
        mock_entry.dn.value = "cn=test,dc=example,dc=com"

        # Test the exception handling path (lines 482-483)
        result = validator.validate_entries([mock_entry])

        utils = FlextTestsUtilities()
        assertion = utils.assertion()

        # Verify the result is a failure
        assertion.assert_false(condition=result.is_success)
        assertion.assert_in("Validation failed for entry cn=test,dc=example,dc=com", str(result.error))
        assertion.assert_in("Test validation error", str(result.error))

    def test_validator_service_empty_entries_optimization(self) -> None:
        """Test empty entries optimization path."""
        validator = FlextLDIFServices.ValidatorService()

        # Test with empty list (should return success without processing)
        result = validator.validate_entries([])

        utils = FlextTestsUtilities()
        assertion = utils.assertion()

        assertion.assert_true(condition=result.is_success)

    def test_validator_service_none_entries_handling(self) -> None:
        """Test None entries handling."""
        validator = FlextLDIFServices.ValidatorService()

        # Test with None (should handle gracefully)
        result = validator.validate_entries(None)

        utils = FlextTestsUtilities()
        assertion = utils.assertion()

        assertion.assert_true(condition=result.is_success)
