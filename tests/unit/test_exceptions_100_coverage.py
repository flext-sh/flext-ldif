"""Comprehensive tests for FlextLdifExceptions to achieve 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.exceptions import FlextLdifExceptions


class TestFlextLdifExceptions:
    """Test cases for FlextLdifExceptions to achieve 100% coverage."""

    def test_validation_error_with_dn_context(self) -> None:
        """Test validation error creation with DN context."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error",
            entry_dn="cn=test,dc=example,dc=com",
        )

        assert result.is_failure
        assert result.error is not None and "Test validation error" in result.error
        assert (
            result.error is not None
            and "(DN: cn=test,dc=example,dc=com)" in result.error
        )

    def test_validation_error_with_attribute_context(self) -> None:
        """Test validation error creation with attribute context."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error",
            attribute_name="cn",
        )

        assert result.is_failure
        assert result.error is not None and "Test validation error" in result.error
        assert result.error is not None and "(Attribute: cn)" in result.error

    def test_validation_error_with_rule_context(self) -> None:
        """Test validation error creation with validation rule context."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error",
            validation_rule="required_field",
        )

        assert result.is_failure
        assert result.error is not None and "Test validation error" in result.error
        assert result.error is not None and "(Rule: required_field)" in result.error

    def test_validation_error_with_all_context(self) -> None:
        """Test validation error creation with all context types."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error",
            dn="cn=test,dc=example,dc=com",
            attribute_name="cn",
            validation_rule="required_field",
        )

        assert result.is_failure
        assert result.error is not None and "Test validation error" in result.error
        assert (
            result.error is not None
            and "(DN: cn=test,dc=example,dc=com)" in result.error
        )
        assert result.error is not None and "(Attribute: cn)" in result.error
        assert result.error is not None and "(Rule: required_field)" in result.error

    def test_validation_error_with_non_string_context(self) -> None:
        """Test validation error creation with non-string context values."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error",
            dn=123,  # Non-string value
            attribute_name=None,  # None value
            validation_rule=456,  # Non-string value
        )

        assert result.is_failure
        assert result.error is not None and "Test validation error" in result.error
        # Non-string values should be ignored
        assert result.error is not None and "(DN:" not in result.error
        assert result.error is not None and "(Attribute:" not in result.error
        assert result.error is not None and "(Rule:" not in result.error

    def test_parse_error_with_line_number_int(self) -> None:
        """Test parse error creation with integer line number."""
        result = FlextLdifExceptions.parse_error("Test parse error", line_number=42)

        assert result.is_failure
        assert result.error is not None and "Test parse error" in result.error
        assert result.error is not None and "(line 42)" in result.error

    def test_parse_error_with_line_number_string(self) -> None:
        """Test parse error creation with string line number."""
        result = FlextLdifExceptions.parse_error("Test parse error", line_number="42")

        assert result.is_failure
        assert result.error is not None and "Test parse error" in result.error
        assert result.error is not None and "(line 42)" in result.error

    def test_parse_error_with_invalid_line_number(self) -> None:
        """Test parse error creation with invalid line number."""
        result = FlextLdifExceptions.parse_error(
            "Test parse error",
            line_number="invalid",
        )

        assert result.is_failure
        assert result.error is not None and "Test parse error" in result.error
        assert result.error is not None and "(line unknown)" in result.error

    def test_parse_error_with_column_int(self) -> None:
        """Test parse error creation with integer column."""
        result = FlextLdifExceptions.parse_error(
            "Test parse error",
            line_number=42,
            column=10,
        )

        assert result.is_failure
        assert result.error is not None and "Test parse error" in result.error
        assert result.error is not None and "(line 42, column 10)" in result.error

    def test_parse_error_with_column_string(self) -> None:
        """Test parse error creation with string column."""
        result = FlextLdifExceptions.parse_error(
            "Test parse error",
            line_number=42,
            column="10",
        )

        assert result.is_failure
        assert result.error is not None and "Test parse error" in result.error
        assert result.error is not None and "(line 42, column 10)" in result.error

    def test_parse_error_with_invalid_column(self) -> None:
        """Test parse error creation with invalid column."""
        result = FlextLdifExceptions.parse_error(
            "Test parse error",
            line_number=42,
            column="invalid",
        )

        assert result.is_failure
        assert result.error is not None and "Test parse error" in result.error
        assert result.error is not None and "(line 42)" in result.error
        assert result.error is not None and "column" not in result.error

    def test_parse_error_with_content_preview(self) -> None:
        """Test parse error creation with content preview."""
        result = FlextLdifExceptions.parse_error(
            "Test parse error",
            content_preview="dn: cn=test",
        )

        assert result.is_failure
        assert result.error is not None and "Test parse error" in result.error
        assert result.error is not None and "- Content: dn: cn=test" in result.error

    def test_parse_error_with_long_content_preview(self) -> None:
        """Test parse error creation with long content preview."""
        long_content = "a" * 100  # Longer than _CONTENT_PREVIEW_LENGTH (50)
        result = FlextLdifExceptions.parse_error(
            "Test parse error",
            content_preview=long_content,
        )

        assert result.is_failure
        assert result.error is not None and "Test parse error" in result.error
        assert "- Content: " + "a" * 50 + "..." in result.error

    def test_parse_error_with_empty_content_preview(self) -> None:
        """Test parse error creation with empty content preview."""
        result = FlextLdifExceptions.parse_error("Test parse error", content_preview="")

        assert result.is_failure
        assert result.error is not None and "Test parse error" in result.error
        assert result.error is not None and "- Content:" not in result.error

    def test_parse_error_with_whitespace_content_preview(self) -> None:
        """Test parse error creation with whitespace-only content preview."""
        result = FlextLdifExceptions.parse_error(
            "Test parse error",
            content_preview="   ",
        )

        assert result.is_failure
        assert result.error is not None and "Test parse error" in result.error
        assert result.error is not None and "- Content:" not in result.error

    def test_processing_error_with_operation(self) -> None:
        """Test processing error creation with operation context."""
        result = FlextLdifExceptions.processing_error(
            "Test processing error",
            operation="parse",
        )

        assert result.is_failure
        assert result.error is not None and "Test processing error" in result.error
        assert result.error is not None and "(Operation: parse)" in result.error

    def test_processing_error_with_entry_count_int(self) -> None:
        """Test processing error creation with integer entry count."""
        result = FlextLdifExceptions.processing_error(
            "Test processing error",
            entry_count=100,
        )

        assert result.is_failure
        assert result.error is not None and "Test processing error" in result.error
        assert result.error is not None and "(Entries: 100)" in result.error

    def test_processing_error_with_entry_count_string(self) -> None:
        """Test processing error creation with string entry count."""
        result = FlextLdifExceptions.processing_error(
            "Test processing error",
            entry_count="100",
        )

        assert result.is_failure
        assert result.error is not None and "Test processing error" in result.error
        assert result.error is not None and "(Entries: 100)" in result.error

    def test_processing_error_with_invalid_entry_count(self) -> None:
        """Test processing error creation with invalid entry count."""
        result = FlextLdifExceptions.processing_error(
            "Test processing error",
            entry_count="invalid",
        )

        assert result.is_failure
        assert result.error is not None and "Test processing error" in result.error
        assert result.error is not None and "(Entries:" not in result.error

    def test_processing_error_with_negative_entry_count(self) -> None:
        """Test processing error creation with negative entry count."""
        result = FlextLdifExceptions.processing_error(
            "Test processing error",
            entry_count=-1,
        )

        assert result.is_failure
        assert result.error is not None and "Test processing error" in result.error
        assert result.error is not None and "(Entries:" not in result.error

    def test_file_error_with_path(self) -> None:
        """Test file error creation with file path."""
        result = FlextLdifExceptions.file_error(
            "Test file error",
            file_path="/test/file.ldif",
        )

        assert result.is_failure
        assert result.error is not None and "Test file error" in result.error
        assert result.error is not None and "(File: /test/file.ldif)" in result.error

    def test_file_error_with_non_string_path(self) -> None:
        """Test file error creation with non-string file path."""
        result = FlextLdifExceptions.file_error("Test file error", file_path=123)

        assert result.is_failure
        assert result.error is not None and "Test file error" in result.error
        assert result.error is not None and "(File: 123)" in result.error

    def test_configuration_error_with_key(self) -> None:
        """Test configuration error creation with config key."""
        result = FlextLdifExceptions.configuration_error(
            "Test config error",
            config_key="ldif_max_entries",
        )

        assert result.is_failure
        assert result.error is not None and "Test config error" in result.error
        assert result.error is not None and "(Config: ldif_max_entries)" in result.error

    def test_configuration_error_with_non_string_key(self) -> None:
        """Test configuration error creation with non-string config key."""
        result = FlextLdifExceptions.configuration_error(
            "Test config error",
            config_key=123,
        )

        assert result.is_failure
        assert result.error is not None and "Test config error" in result.error
        assert result.error is not None and "(Config: 123)" in result.error

    def test_connection_error(self) -> None:
        """Test connection error creation."""
        result = FlextLdifExceptions.connection_error("Connection failed")

        assert result.is_failure
        assert (
            result.error is not None
            and "LDIF Connection Error: Connection failed" in result.error
        )

    def test_timeout_error(self) -> None:
        """Test timeout error creation."""
        result = FlextLdifExceptions.timeout_error("Operation timed out")

        assert result.is_failure
        assert (
            result.error is not None
            and "LDIF Timeout Error: Operation timed out" in result.error
        )

    def test_authentication_error(self) -> None:
        """Test authentication error creation."""
        result = FlextLdifExceptions.authentication_error("Authentication failed")

        assert result.is_failure
        assert (
            result.error is not None
            and "LDIF Authentication Error: Authentication failed" in result.error
        )

    def test_generic_error(self) -> None:
        """Test generic error creation."""
        result = FlextLdifExceptions.error("Generic error occurred")

        assert result.is_failure
        assert (
            result.error is not None
            and "LDIF Error: Generic error occurred" in result.error
        )

    def test_entry_error_with_dn(self) -> None:
        """Test entry error creation with DN."""
        result = FlextLdifExceptions.entry_error(
            "Test entry error",
            dn="cn=test,dc=example,dc=com",
        )

        assert result.is_failure
        assert result.error is not None and "Test entry error" in result.error
        assert (
            result.error is not None
            and "(DN: cn=test,dc=example,dc=com)" in result.error
        )

    def test_entry_error_with_entry_dn(self) -> None:
        """Test entry error creation with entry_dn."""
        result = FlextLdifExceptions.entry_error(
            "Test entry error",
            entry_dn="cn=test,dc=example,dc=com",
        )

        assert result.is_failure
        assert result.error is not None and "Test entry error" in result.error
        assert (
            result.error is not None
            and "(DN: cn=test,dc=example,dc=com)" in result.error
        )

    def test_entry_error_with_attribute_name(self) -> None:
        """Test entry error creation with attribute name."""
        result = FlextLdifExceptions.entry_error(
            "Test entry error",
            attribute_name="cn",
        )

        assert result.is_failure
        assert result.error is not None and "Test entry error" in result.error
        assert result.error is not None and "(Attribute: cn)" in result.error

    def test_entry_error_with_mapping_entry_data(self) -> None:
        """Test entry error creation with mapping entry data."""
        entry_data = {"cn": ["test"], "sn": ["user"], "mail": ["test@example.com"]}
        result = FlextLdifExceptions.entry_error(
            "Test entry error",
            entry_data=entry_data,
        )

        assert result.is_failure
        assert result.error is not None and "Test entry error" in result.error
        assert result.error is not None and "(Attributes: cn, sn, mail)" in result.error

    def test_entry_error_with_many_attributes(self) -> None:
        """Test entry error creation with many attributes (truncation)."""
        # Create entry data with more than _MAX_ATTRIBUTES_DISPLAY (5) attributes
        entry_data = {
            "cn": ["test"],
            "sn": ["user"],
            "mail": ["test@example.com"],
            "uid": ["testuser"],
            "telephoneNumber": ["123-456-7890"],
            "description": ["Test user"],
            "title": ["Developer"],
        }
        result = FlextLdifExceptions.entry_error(
            "Test entry error",
            entry_data=entry_data,
        )

        assert result.is_failure
        assert result.error is not None and "Test entry error" in result.error
        assert (
            "(Attributes: cn, sn, mail, uid, telephoneNumber +2 more)" in result.error
        )

    def test_entry_error_with_empty_mapping(self) -> None:
        """Test entry error creation with empty mapping."""
        entry_data = {}
        result = FlextLdifExceptions.entry_error(
            "Test entry error",
            entry_data=entry_data,
        )

        assert result.is_failure
        assert result.error is not None and "Test entry error" in result.error
        assert result.error is not None and "(Attributes:" not in result.error

    def test_entry_error_with_non_mapping_entry_data(self) -> None:
        """Test entry error creation with non-mapping entry data."""
        result = FlextLdifExceptions.entry_error(
            "Test entry error",
            entry_data="not a mapping",
        )

        assert result.is_failure
        assert result.error is not None and "Test entry error" in result.error
        assert (
            result.error is not None
            and "(Entry data: non-mapping type)" in result.error
        )

    def test_entry_error_with_dn_and_entry_data(self) -> None:
        """Test entry error creation with both DN and entry data."""
        entry_data = {"cn": ["test"], "sn": ["user"]}
        result = FlextLdifExceptions.entry_error(
            "Test entry error",
            dn="cn=test,dc=example,dc=com",
            entry_data=entry_data,
        )

        assert result.is_failure
        assert result.error is not None and "Test entry error" in result.error
        assert (
            result.error is not None
            and "(DN: cn=test,dc=example,dc=com)" in result.error
        )
        assert result.error is not None and "(Attributes: cn, sn)" in result.error

    def test_create_with_validation_error_type(self) -> None:
        """Test create method with ValidationError type."""
        result = FlextLdifExceptions.create("Test error", "ValidationError")

        assert result.is_failure
        assert result.error is not None and "Test error" in result.error

    def test_create_with_other_error_type(self) -> None:
        """Test create method with other error type."""
        result = FlextLdifExceptions.create("Test error", "OtherError")

        assert result.is_failure
        assert result.error is not None and "LDIF Error: Test error" in result.error

    def test_create_without_error_type(self) -> None:
        """Test create method without error type."""
        result = FlextLdifExceptions.create("Test error")

        assert result.is_failure
        assert result.error is not None and "LDIF Error: Test error" in result.error
