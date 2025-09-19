"""Additional tests for exceptions to achieve 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.exceptions import FlextLdifExceptions


class TestFlextLdifExceptionsMissingCoverage:
    """Additional tests to achieve 100% coverage for exceptions."""

    def test_validation_error_with_dn_context(self) -> None:
        """Test validation_error with DN context."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error", dn="uid=test,ou=people,dc=example,dc=com"
        )
        assert result.is_success is False
        assert result.error is not None and "Test validation error" in result.error
        assert (
            result.error is not None
            and "(DN: uid=test,ou=people,dc=example,dc=com)" in result.error
        )

    def test_validation_error_with_attribute_context(self) -> None:
        """Test validation_error with attribute context."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error", attribute_name="objectClass"
        )
        assert result.is_success is False
        assert result.error is not None and "Test validation error" in result.error
        assert result.error is not None and "(Attribute: objectClass)" in result.error

    def test_validation_error_with_rule_context(self) -> None:
        """Test validation_error with validation rule context."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error", validation_rule="required_attribute"
        )
        assert result.is_success is False
        assert result.error is not None and "Test validation error" in result.error
        assert result.error is not None and "(Rule: required_attribute)" in result.error

    def test_validation_error_with_all_context(self) -> None:
        """Test validation_error with all context parameters."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error",
            dn="uid=test,ou=people,dc=example,dc=com",
            attribute_name="objectClass",
            validation_rule="required_attribute",
        )
        assert result.is_success is False
        assert result.error is not None and "Test validation error" in result.error
        assert (
            result.error is not None
            and "(DN: uid=test,ou=people,dc=example,dc=com)" in result.error
        )
        assert result.error is not None and "(Attribute: objectClass)" in result.error
        assert result.error is not None and "(Rule: required_attribute)" in result.error

    def test_processing_error_with_operation_context(self) -> None:
        """Test processing_error with operation context."""
        result = FlextLdifExceptions.processing_error(
            "Test processing error", operation="parse_ldif"
        )
        assert result.is_success is False
        assert result.error is not None and "Test processing error" in result.error
        assert result.error is not None and "(Operation: parse_ldif)" in result.error

    def test_processing_error_with_entry_count_context(self) -> None:
        """Test processing_error with entry count context."""
        result = FlextLdifExceptions.processing_error(
            "Test processing error", entry_count=42
        )
        assert result.is_success is False
        assert result.error is not None and "Test processing error" in result.error
        assert result.error is not None and "(Entries: 42)" in result.error

    def test_processing_error_with_all_context(self) -> None:
        """Test processing_error with all context parameters."""
        result = FlextLdifExceptions.processing_error(
            "Test processing error", operation="parse_ldif", entry_count=42
        )
        assert result.is_success is False
        assert result.error is not None and "Test processing error" in result.error
        assert result.error is not None and "(Operation: parse_ldif)" in result.error
        assert result.error is not None and "(Entries: 42)" in result.error

    def test_configuration_error_with_config_key_context(self) -> None:
        """Test configuration_error with config key context."""
        result = FlextLdifExceptions.configuration_error(
            "Test configuration error", config_key="ldif.parser.max_line_length"
        )
        assert result.is_success is False
        assert result.error is not None and "Test configuration error" in result.error
        assert (
            result.error is not None
            and "(Config: ldif.parser.max_line_length)" in result.error
        )

    def test_validation_error_with_non_string_dn(self) -> None:
        """Test validation_error with non-string DN (should not add context)."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error",
            dn=123,  # Non-string DN
        )
        assert result.is_success is False
        assert result.error is not None and "Test validation error" in result.error
        assert (
            result.error is not None and "(DN:" not in result.error
        )  # Should not add DN context

    def test_validation_error_with_non_string_attribute(self) -> None:
        """Test validation_error with non-string attribute (should not add context)."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error",
            attribute_name=123,  # Non-string attribute
        )
        assert result.is_success is False
        assert result.error is not None and "Test validation error" in result.error
        assert (
            result.error is not None and "(Attribute:" not in result.error
        )  # Should not add attribute context

    def test_validation_error_with_non_string_rule(self) -> None:
        """Test validation_error with non-string rule (should not add context)."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error",
            validation_rule=123,  # Non-string rule
        )
        assert result.is_success is False
        assert result.error is not None and "Test validation error" in result.error
        assert (
            result.error is not None and "(Rule:" not in result.error
        )  # Should not add rule context

    def test_processing_error_with_non_string_operation(self) -> None:
        """Test processing_error with non-string operation (should not add context)."""
        result = FlextLdifExceptions.processing_error(
            "Test processing error",
            operation=123,  # Non-string operation
        )
        assert result.is_success is False
        assert result.error is not None and "Test processing error" in result.error
        assert (
            result.error is not None and "(Operation:" not in result.error
        )  # Should not add operation context

    def test_processing_error_with_non_int_entry_count(self) -> None:
        """Test processing_error with non-int entry count (should not add context)."""
        result = FlextLdifExceptions.processing_error(
            "Test processing error",
            entry_count="not_a_number",  # Non-int entry count
        )
        assert result.is_success is False
        assert result.error is not None and "Test processing error" in result.error
        assert (
            result.error is not None and "(Entries:" not in result.error
        )  # Should not add entry count context

    def test_configuration_error_with_non_string_config_key(self) -> None:
        """Test configuration_error with non-string config key (should not add context)."""
        result = FlextLdifExceptions.configuration_error(
            "Test configuration error",
            config_key=123,  # Non-string config key
        )
        assert result.is_success is False
        assert result.error is not None and "Test configuration error" in result.error
        assert (
            "(Config: 123)" in result.error
        )  # Now adds config context after str() conversion

    def test_entry_error_with_entry_data_context(self) -> None:
        """Test entry_error with entry_data context."""
        entry_data = {
            "objectClass": ["person"],
            "cn": ["John Doe"],
            "sn": ["Doe"],
            "mail": ["john@example.com"],
            "uid": ["john"],
            "description": ["Test user"],
        }
        result = FlextLdifExceptions.entry_error(
            "Test entry error", entry_data=entry_data
        )
        assert result.is_success is False
        assert result.error is not None and "Test entry error" in result.error
        assert result.error is not None and "(Attributes:" in result.error
        assert (
            "+1 more" in result.error
        )  # Should show +1 more since we have 6 attributes

    def test_entry_error_with_entry_data_few_attributes(self) -> None:
        """Test entry_error with entry_data context with few attributes."""
        entry_data = {"objectClass": ["person"], "cn": ["John Doe"]}
        result = FlextLdifExceptions.entry_error(
            "Test entry error", entry_data=entry_data
        )
        assert result.is_success is False
        assert result.error is not None and "Test entry error" in result.error
        assert result.error is not None and "(Attributes:" in result.error
        assert (
            result.error is not None and "objectClass, cn" in result.error
        )  # Should show all attributes

    def test_entry_error_with_non_dict_entry_data(self) -> None:
        """Test entry_error with non-dict entry_data (should not add context)."""
        result = FlextLdifExceptions.entry_error(
            "Test entry error",
            entry_data="not_a_dict",  # Non-dict entry_data
        )
        assert result.is_success is False
        assert result.error is not None and "Test entry error" in result.error
        assert (
            result.error is not None and "(Attributes:" not in result.error
        )  # Should not add attributes context

    def test_entry_error_with_empty_entry_data(self) -> None:
        """Test entry_error with empty entry_data (should not add context)."""
        result = FlextLdifExceptions.entry_error(
            "Test entry error",
            entry_data={},  # Empty dict
        )
        assert result.is_success is False
        assert result.error is not None and "Test entry error" in result.error
        assert (
            result.error is not None and "(Attributes:" not in result.error
        )  # Should not add attributes context

    def test_create_method_with_validation_error_type(self) -> None:
        """Test create method with ValidationError type."""
        result = FlextLdifExceptions.create(
            "Test validation error", error_type="ValidationError"
        )
        assert result.is_success is False
        assert result.error is not None and "Test validation error" in result.error

    def test_create_method_with_other_error_type(self) -> None:
        """Test create method with other error type."""
        result = FlextLdifExceptions.create(
            "Test generic error", error_type="GenericError"
        )
        assert result.is_success is False
        assert result.error is not None and "Test generic error" in result.error
