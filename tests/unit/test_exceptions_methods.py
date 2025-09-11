"""Tests for FlextLDIFExceptions methods - comprehensive coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.exceptions import FlextLDIFExceptions


class TestFlextLDIFExceptionsMethods:
    """Test suite for FlextLDIFExceptions methods."""

    def test_parse_error_basic(self) -> None:
        """Test parse_error with basic parameters."""
        error = FlextLDIFExceptions.parse_error("Parse failed")
        assert error.message == "Parse failed"
        assert error.operation == "ldif_parsing"

    def test_parse_error_with_line(self) -> None:
        """Test parse_error with line number."""
        error = FlextLDIFExceptions.parse_error("Parse failed", line=42)
        assert "(line 42)" in error.message

    def test_parse_error_with_line_and_column(self) -> None:
        """Test parse_error with line and column."""
        error = FlextLDIFExceptions.parse_error("Parse failed", line=42, column=10)
        assert "(line 42, column 10)" in error.message

    def test_parse_error_with_content(self) -> None:
        """Test parse_error with content."""
        content = "dn: cn=test,dc=example,dc=com"
        error = FlextLDIFExceptions.parse_error("Parse failed", content=content)
        assert "Content: dn: cn=test,dc=example,dc=com" in error.message

    def test_parse_error_with_long_content(self) -> None:
        """Test parse_error with long content (truncated)."""
        content = "dn: cn=test,dc=example,dc=com" + "x" * 100
        error = FlextLDIFExceptions.parse_error("Parse failed", content=content)
        assert "Content: dn: cn=test,dc=example,dc=com" in error.message
        assert "..." in error.message

    def test_parse_error_with_empty_content(self) -> None:
        """Test parse_error with empty content."""
        error = FlextLDIFExceptions.parse_error("Parse failed", content="")
        assert "Content:" not in error.message

    def test_parse_error_with_whitespace_content(self) -> None:
        """Test parse_error with whitespace-only content."""
        error = FlextLDIFExceptions.parse_error("Parse failed", content="   ")
        assert "Content:" not in error.message

    def test_entry_error_basic(self) -> None:
        """Test entry_error with basic parameters."""
        error = FlextLDIFExceptions.entry_error("Entry failed")
        assert error.message == "Entry failed"
        assert error.operation == "ldif_entry_processing"

    def test_entry_error_with_dn(self) -> None:
        """Test entry_error with DN."""
        error = FlextLDIFExceptions.entry_error(
            "Entry failed", dn="cn=test,dc=example,dc=com"
        )
        assert "DN: cn=test,dc=example,dc=com" in error.message

    def test_entry_error_with_entry_dn(self) -> None:
        """Test entry_error with entry_dn."""
        error = FlextLDIFExceptions.entry_error(
            "Entry failed", entry_dn="cn=test,dc=example,dc=com"
        )
        assert "DN: cn=test,dc=example,dc=com" in error.message

    def test_entry_error_with_entry_data(self) -> None:
        """Test entry_error with entry data."""
        entry_data = {"cn": ["test"], "objectClass": ["person"]}
        error = FlextLDIFExceptions.entry_error("Entry failed", entry_data=entry_data)
        assert "Attributes: [cn, objectClass]" in error.message

    def test_entry_error_with_large_entry_data(self) -> None:
        """Test entry_error with large entry data (truncated)."""
        entry_data = {f"attr{i}": [f"value{i}"] for i in range(10)}
        error = FlextLDIFExceptions.entry_error("Entry failed", entry_data=entry_data)
        assert "Attributes: [attr0, attr1, attr2" in error.message
        assert "(+7 more)" in error.message

    def test_entry_error_with_long_attribute_name(self) -> None:
        """Test entry_error with long attribute name."""
        entry_data = {"very_long_attribute_name": ["value"]}
        error = FlextLDIFExceptions.entry_error("Entry failed", entry_data=entry_data)
        assert "Attributes: [very_long_attribute_name]" in error.message

    def test_validation_error_basic(self) -> None:
        """Test validation_error with basic parameters."""
        error = FlextLDIFExceptions.validation_error("Validation failed")
        assert error.message == "Validation failed"
        assert error.operation == "ldif_validation"

    def test_validation_error_with_dn(self) -> None:
        """Test validation_error with DN."""
        error = FlextLDIFExceptions.validation_error(
            "Validation failed", entry_dn="cn=test,dc=example,dc=com"
        )
        assert "DN: cn=test,dc=example,dc=com" in error.message

    def test_validation_error_with_entry_dn(self) -> None:
        """Test validation_error with entry DN."""
        error = FlextLDIFExceptions.validation_error(
            "Validation failed", entry_dn="cn=test,dc=example,dc=com"
        )
        assert "DN: cn=test,dc=example,dc=com" in error.message

    def test_validation_error_with_validation_rule(self) -> None:
        """Test validation_error with validation rule."""
        error = FlextLDIFExceptions.validation_error(
            "Validation failed", validation_rule="required_dn"
        )
        assert error.message == "Validation failed"
        assert hasattr(error, "validation_details")

    def test_processing_error_basic(self) -> None:
        """Test processing_error with basic parameters."""
        error = FlextLDIFExceptions.processing_error("Processing failed")
        assert error.message == "Processing failed"
        assert error.operation == "ldif_processing"

    def test_timeout_error_basic(self) -> None:
        """Test timeout_error with basic parameters."""
        error = FlextLDIFExceptions.timeout_error("Timeout occurred")
        assert error.message == "Timeout occurred"
        assert error.operation == "ldif_timeout"

    def test_error_basic(self) -> None:
        """Test error with basic parameters."""
        error = FlextLDIFExceptions.error("Generic error")
        assert error.message == "Generic error"

    def test_connection_error_basic(self) -> None:
        """Test connection_error with basic parameters."""
        error = FlextLDIFExceptions.connection_error("Connection failed")
        assert error.message == "Connection failed"

    def test_file_error_basic(self) -> None:
        """Test file_error with basic parameters."""
        error = FlextLDIFExceptions.file_error("File error", file_path="test.ldif")
        assert "File error" in error.message
        assert "file: test.ldif" in error.message

    def test_file_error_with_operation(self) -> None:
        """Test file_error with operation parameter."""
        error = FlextLDIFExceptions.file_error(
            "File error", file_path="test.ldif", operation="read"
        )
        assert "File error" in error.message
        assert "file: test.ldif" in error.message

    def test_configuration_error_basic(self) -> None:
        """Test configuration_error with basic parameters."""
        error = FlextLDIFExceptions.configuration_error("Config error")
        assert error.message == "Config error"

    def test_authentication_error_basic(self) -> None:
        """Test authentication_error with basic parameters."""
        error = FlextLDIFExceptions.authentication_error("Auth failed")
        assert error.message == "Auth failed"

    def test_parse_error_alias_basic(self) -> None:
        """Test parse_error_alias with basic parameters."""
        error = FlextLDIFExceptions.parse_error_alias("Parse alias error")
        assert error.message == "Parse alias error"
        assert error.operation == "ldif_parsing"

    def test_parse_error_alias_with_line(self) -> None:
        """Test parse_error_alias with line number."""
        error = FlextLDIFExceptions.parse_error_alias("Parse alias error", line=42)
        assert "(line 42)" in error.message

    def test_parse_error_alias_with_column(self) -> None:
        """Test parse_error_alias with column."""
        error = FlextLDIFExceptions.parse_error_alias("Parse alias error", column=10)
        assert error.message == "Parse alias error"
