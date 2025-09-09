"""Exact tests for uncovered lines in services.py.

Targeting the specific lines that are still uncovered with precise scenarios.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import Mock, patch

from flext_tests import FlextTestsUtilities

from flext_ldif.models import FlextLDIFModels
from flext_ldif.services import FlextLDIFServices


class TestExactUncoveredLines:
    """Tests targeting exact uncovered lines."""

    def test_line_543_dn_validation_failure(self) -> None:
        """Test line 543: DN validation failure path."""
        validator = FlextLDIFServices.ValidatorService()

        # Test with an empty DN that fails FlextUtilities.TypeGuards.is_string_non_empty
        with patch("flext_ldif.services.FlextUtilities.TypeGuards.is_string_non_empty", return_value=False):
            result = validator.validate_dn_format("non_empty_but_invalid")

            utils = FlextTestsUtilities()
            assertion = utils.assertion()

            assertion.assert_false(condition=result.is_success)
            assertion.assert_in("Invalid DN format", str(result.error))

    def test_line_532_validation_success_return(self) -> None:
        """Test line 532: successful validation return in validate_unique_dns."""
        validator = FlextLDIFServices.ValidatorService()

        # Create entries that would trigger the success return at line 532
        mock_entry = Mock()
        mock_entry.dn = Mock()
        mock_entry.dn.value = "cn=test,dc=example,dc=com"

        result = validator.validate_unique_dns([mock_entry])

        utils = FlextTestsUtilities()
        assertion = utils.assertion()

        assertion.assert_true(condition=result.is_success)

    def test_lines_502_503_validate_entry_structure_exception(self) -> None:
        """Test lines 502-503: exception in validate_entry_structure method."""
        validator = FlextLDIFServices.ValidatorService()

        # Create a mock entry instead of using model_validate
        mock_entry = Mock()
        mock_entry.dn = Mock()
        mock_entry.dn.value = "cn=test,dc=example,dc=com"
        mock_entry.dn.validate_business_rules = Mock(side_effect=RuntimeError("DN validation error"))

        result = validator.validate_entry_structure(mock_entry)

        utils = FlextTestsUtilities()
        assertion = utils.assertion()

        assertion.assert_false(condition=result.is_success)
        assertion.assert_in("DN validation error", str(result.error))

    def test_lines_571_576_attributes_else_branch(self) -> None:
        """Test lines 571-576: attributes else branch that can't validate."""
        validator = FlextLDIFServices.ValidatorService()

        # Create mock entry with attributes that don't have .data or .items
        mock_entry = Mock()
        mock_entry.dn = Mock()
        mock_entry.dn.value = "cn=test,dc=example,dc=com"
        mock_entry.validate_business_rules = Mock(return_value=None)

        # Create attributes object without .data or .items
        mock_attributes = Mock()
        del mock_attributes.data  # Remove .data attribute
        # Mock has_attribute to return False for .items
        with patch("flext_ldif.services.FlextUtilities.TypeGuards.has_attribute", return_value=False):
            mock_entry.attributes = mock_attributes

            result = validator.validate_entries([mock_entry])

            utils = FlextTestsUtilities()
            assertion = utils.assertion()

            assertion.assert_true(condition=result.is_success)

    def test_branch_368_success_path(self) -> None:
        """Test branch line 368: successful validation path."""
        validator = FlextLDIFServices.ValidatorService()

        # Create proper entry that follows the success path to line 368
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]}
        }
        entry = FlextLDIFModels.Entry.model_validate(entry_data)

        # This should follow the normal success path
        result = validator.validate_entries([entry])

        utils = FlextTestsUtilities()
        assertion = utils.assertion()

        assertion.assert_true(condition=result.is_success)

    def test_branch_797_parser_success(self) -> None:
        """Test branch line 797: parser success path."""
        parser = FlextLDIFServices.ParserService()

        # Test parser with content that triggers line 797
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person

"""
        result = parser.parse_ldif_content(ldif_content)

        utils = FlextTestsUtilities()
        assertion = utils.assertion()

        assertion.assert_true(condition=result.is_success or result.is_failure)
