"""Tests for FlextLdifExceptions methods - comprehensive coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.exceptions import FlextLdifExceptions


class TestFlextLdifExceptionsMethods:
    """Test suite for FlextLdifExceptions methods."""

    def test_parse_error_basic(self) -> None:
        """Test parse_error with basic parameters."""
        error = FlextLdifExceptions.parse_error("Parse failed")
        assert error.error == "Parse failed"
        assert error.is_failure

    def test_parse_error_with_line(self) -> None:
        """Test parse_error with line number."""
        error = FlextLdifExceptions.parse_error("Parse failed", line=42)
        assert error.error is not None
        assert "(line 42)" in error.error

    def test_parse_error_with_line_and_column(self) -> None:
        """Test parse_error with line and column."""
        error = FlextLdifExceptions.parse_error("Parse failed", line=42, column=10)
        assert error.error is not None
        assert "(line 42, column 10)" in error.error

    def test_parse_error_with_content(self) -> None:
        """Test parse_error with content."""
        content = "dn: cn=test,dc=example,dc=com"
        error = FlextLdifExceptions.parse_error("Parse failed", content=content)
        assert error.error is not None
        assert "Content: dn: cn=test,dc=example,dc=com" in error.error

    def test_parse_error_with_long_content(self) -> None:
        """Test parse_error with long content (truncated)."""
        content = "dn: cn=test,dc=example,dc=com" + "x" * 100
        error = FlextLdifExceptions.parse_error("Parse failed", content=content)
        assert error.error is not None
        assert "Content: dn: cn=test,dc=example,dc=com" in error.error
        assert error.error is not None
        assert "..." in error.error

    def test_parse_error_with_empty_content(self) -> None:
        """Test parse_error with empty content."""
        error = FlextLdifExceptions.parse_error("Parse failed", content="")
        assert error.error is not None
        assert "Content:" not in error.error

    def test_parse_error_with_whitespace_content(self) -> None:
        """Test parse_error with whitespace-only content."""
        error = FlextLdifExceptions.parse_error("Parse failed", content="   ")
        assert error.error is not None
        assert "Content:" not in error.error

    def test_entry_error_basic(self) -> None:
        """Test entry_error with basic parameters."""
        error = FlextLdifExceptions.entry_error("Entry failed")
        assert error.error == "Entry failed"
        assert error.is_failure

    def test_entry_error_with_dn(self) -> None:
        """Test entry_error with DN."""
        error = FlextLdifExceptions.entry_error(
            "Entry failed", dn="cn=test,dc=example,dc=com",
        )
        assert "DN: cn=test,dc=example,dc=com" in (error.error or "")

    def test_entry_error_with_entry_dn(self) -> None:
        """Test entry_error with entry_dn."""
        error = FlextLdifExceptions.entry_error(
            "Entry failed", entry_dn="cn=test,dc=example,dc=com",
        )
        assert "DN: cn=test,dc=example,dc=com" in (error.error or "")

    def test_entry_error_with_entry_data(self) -> None:
        """Test entry_error with entry data."""
        entry_data = {"cn": ["test"], "objectClass": ["person"]}
        error = FlextLdifExceptions.entry_error("Entry failed", entry_data=entry_data)
        assert error.error is not None
        assert "Attributes: cn, objectClass" in error.error

    def test_entry_error_with_large_entry_data(self) -> None:
        """Test entry_error with large entry data (truncated)."""
        entry_data = {f"attr{i}": [f"value{i}"] for i in range(10)}
        error = FlextLdifExceptions.entry_error("Entry failed", entry_data=entry_data)
        assert error.error is not None
        assert "Attributes: attr0, attr1, attr2" in error.error
        assert error.error is not None
        assert "+5 more" in error.error

    def test_entry_error_with_long_attribute_name(self) -> None:
        """Test entry_error with long attribute name."""
        entry_data = {"very_long_attribute_name": ["value"]}
        error = FlextLdifExceptions.entry_error("Entry failed", entry_data=entry_data)
        assert error.error is not None
        assert "Attributes: very_long_attribute_name" in error.error

    def test_validation_error_basic(self) -> None:
        """Test validation_error with basic parameters."""
        error = FlextLdifExceptions.validation_error("Validation failed")
        assert error.error == "Validation failed"

    def test_validation_error_with_dn(self) -> None:
        """Test validation_error with DN."""
        error = FlextLdifExceptions.validation_error(
            "Validation failed", entry_dn="cn=test,dc=example,dc=com",
        )
        assert "DN: cn=test,dc=example,dc=com" in (error.error or "")

    def test_validation_error_with_entry_dn(self) -> None:
        """Test validation_error with entry DN."""
        error = FlextLdifExceptions.validation_error(
            "Validation failed", entry_dn="cn=test,dc=example,dc=com",
        )
        assert "DN: cn=test,dc=example,dc=com" in (error.error or "")

    def test_validation_error_with_validation_rule(self) -> None:
        """Test validation_error with validation rule."""
        error = FlextLdifExceptions.validation_error(
            "Validation failed", validation_rule="required_dn",
        )
        assert error.is_failure
        assert error.error == "Validation failed (Rule: required_dn)"

    def test_processing_error_basic(self) -> None:
        """Test processing_error with basic parameters."""
        error = FlextLdifExceptions.processing_error("Processing failed")
        assert error.error == "Processing failed"
        assert error.is_failure

    def test_timeout_error_basic(self) -> None:
        """Test timeout_error with basic parameters."""
        error = FlextLdifExceptions.timeout_error("Timeout occurred")
        assert error.error == "LDIF Timeout Error: Timeout occurred"
        # Note: TimeoutError from flext-core doesn't have operation attribute
        # assert error.operation == "ldif_timeout"

    def test_error_basic(self) -> None:
        """Test error with basic parameters."""
        error = FlextLdifExceptions.error("Generic error")
        assert error.error == "LDIF Error: Generic error"

    def test_connection_error_basic(self) -> None:
        """Test connection_error with basic parameters."""
        error = FlextLdifExceptions.connection_error("Connection failed")
        assert error.error == "LDIF Connection Error: Connection failed"

    def test_file_error_basic(self) -> None:
        """Test file_error with basic parameters."""
        error = FlextLdifExceptions.file_error("File error", file_path="test.ldif")
        assert error.error is not None
        assert "File error" in error.error
        assert error.error is not None
        assert "(File: test.ldif)" in error.error

    def test_file_error_with_operation(self) -> None:
        """Test file_error with operation parameter."""
        error = FlextLdifExceptions.file_error(
            "File error", file_path="test.ldif", operation="read",
        )
        assert error.error is not None
        assert "File error" in error.error
        assert error.error is not None
        assert "(File: test.ldif)" in error.error

    def test_configuration_error_basic(self) -> None:
        """Test configuration_error with basic parameters."""
        error = FlextLdifExceptions.configuration_error("Config error")
        assert error.error == "Config error"

    def test_authentication_error_basic(self) -> None:
        """Test authentication_error with basic parameters."""
        error = FlextLdifExceptions.authentication_error("Auth failed")
        assert error.error == "LDIF Authentication Error: Auth failed"

    def test_parse_error_basic_alias(self) -> None:
        """Test parse_error with basic parameters - alias test."""
        error = FlextLdifExceptions.parse_error("Parse alias error")
        assert error.error == "Parse alias error"
        assert error.is_failure

    def test_parse_error_with_line_alias(self) -> None:
        """Test parse_error with line number - alias test."""
        error = FlextLdifExceptions.parse_error("Parse alias error", line=42)
        assert error.error is not None
        assert "(line 42)" in error.error

    def test_parse_error_with_column(self) -> None:
        """Test parse_error with column."""
        error = FlextLdifExceptions.parse_error("Parse alias error", column=10)
        assert error.error == "Parse alias error"
