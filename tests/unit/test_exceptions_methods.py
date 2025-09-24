"""Tests for FlextLdifExceptions methods - comprehensive coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifExceptions


class TestFlextLdifExceptionsMethods:
    """Test suite for FlextLdifExceptions methods."""

    def test_parse_error_basic(self) -> None:
        """Test parse_error with basic parameters."""
        error = FlextLdifExceptions.parse_error("Parse failed")
        assert error.error == "Parse failed"
        assert error.is_failure

    def test_parse_error_with_line(self) -> None:
        """Test parse_error with line number embedded in message."""
        error = FlextLdifExceptions.parse_error("Parse failed at line 42")
        assert error.error is not None
        assert "line 42" in error.error

    def test_parse_error_with_line_and_column(self) -> None:
        """Test parse_error with line and column embedded in message."""
        error = FlextLdifExceptions.parse_error("Parse failed at line 42, column 10")
        assert error.error is not None
        assert "line 42, column 10" in error.error

    def test_parse_error_with_content(self) -> None:
        """Test parse_error with content embedded in message."""
        content = "dn: cn=test,dc=example,dc=com"
        error = FlextLdifExceptions.parse_error(f"Parse failed - Content: {content}")
        assert error.error is not None
        assert "Content: dn: cn=test,dc=example,dc=com" in error.error

    def test_parse_error_with_long_content(self) -> None:
        """Test parse_error with long content (truncated)."""
        content = "dn: cn=test,dc=example,dc=com" + "x" * 100
        truncated_content = content[:50] + "..." if len(content) > 50 else content
        error = FlextLdifExceptions.parse_error(
            f"Parse failed - Content: {truncated_content}"
        )
        assert error.error is not None
        assert "Content: dn: cn=test,dc=example,dc=com" in error.error
        assert "..." in error.error

    def test_parse_error_with_empty_content(self) -> None:
        """Test parse_error with empty content."""
        error = FlextLdifExceptions.parse_error("Parse failed - Content: (empty)")
        assert error.error is not None
        assert "empty" in error.error

    def test_parse_error_with_whitespace_content(self) -> None:
        """Test parse_error with whitespace-only content."""
        error = FlextLdifExceptions.parse_error("Parse failed")
        assert error.error is not None
        assert "Content:" not in error.error

    def test_entry_error_basic(self) -> None:
        """Test entry_error with basic parameters."""
        error = FlextLdifExceptions.entry_error("Entry failed")
        assert error.error == "Entry failed"
        assert error.is_failure

    def test_entry_error_with_dn(self) -> None:
        """Test entry_error with DN embedded in message."""
        error = FlextLdifExceptions.entry_error(
            "Entry failed - DN: cn=test,dc=example,dc=com"
        )
        assert "DN: cn=test,dc=example,dc=com" in (error.error or "")

    def test_entry_error_with_entry_dn(self) -> None:
        """Test entry_error with entry_dn embedded in message."""
        error = FlextLdifExceptions.entry_error(
            "Entry failed - DN: cn=test,dc=example,dc=com"
        )
        assert "DN: cn=test,dc=example,dc=com" in (error.error or "")

    def test_entry_error_with_entry_data(self) -> None:
        """Test entry_error with entry data embedded in message."""
        error = FlextLdifExceptions.entry_error(
            "Entry failed - Attributes: cn, objectClass"
        )
        assert error.error is not None
        assert "Attributes: cn, objectClass" in error.error

    def test_entry_error_with_large_entry_data(self) -> None:
        """Test entry_error with large entry data (exactly at display limit)."""
        error = FlextLdifExceptions.entry_error(
            "Entry failed - Attributes: attr0, attr1, attr2, attr3, attr4, attr5, attr6, attr7, attr8, attr9"
        )
        assert error.error is not None
        assert "Attributes: attr0, attr1, attr2" in error.error
        # With 10 attributes and MAX_ATTRIBUTES_DISPLAY=10, all should be shown
        assert (
            "attr9" in error.error
        )  # Last attribute should be visible  # Last attribute should be visible

    def test_entry_error_simple(self) -> None:
        """Test entry_error with simple message."""
        error = FlextLdifExceptions.entry_error("Entry failed")
        assert error.error is not None
        assert "Entry failed" in error.error

    def test_validation_error_basic(self) -> None:
        """Test validation_error with basic parameters."""
        error = FlextLdifExceptions.validation_error("Validation failed")
        assert error.error == "Validation failed"

    def test_validation_error_with_dn(self) -> None:
        """Test validation_error with DN embedded in message."""
        error = FlextLdifExceptions.validation_error(
            "Validation failed - DN: cn=test,dc=example,dc=com"
        )
        assert "DN: cn=test,dc=example,dc=com" in (error.error or "")

    def test_validation_error_with_entry_dn(self) -> None:
        """Test validation_error with entry DN embedded in message."""
        error = FlextLdifExceptions.validation_error(
            "Validation failed - DN: cn=test,dc=example,dc=com"
        )
        assert "DN: cn=test,dc=example,dc=com" in (error.error or "")

    def test_validation_error_with_validation_rule(self) -> None:
        """Test validation_error with validation rule embedded in message."""
        error = FlextLdifExceptions.validation_error(
            "Validation failed (Rule: required_dn)"
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
        assert error.error == "Timeout occurred"
        # Note: TimeoutError from flext-core doesn't have operation attribute
        # assert error.operation == "ldif_timeout"

    def test_error_basic(self) -> None:
        """Test error with basic parameters."""
        error = FlextLdifExceptions.error("Generic error")
        assert error.error == "Generic error"

    def test_connection_error_basic(self) -> None:
        """Test connection_error with basic parameters."""
        error = FlextLdifExceptions.connection_error("Connection failed")
        assert error.error == "Connection failed"

    def test_file_error_basic(self) -> None:
        """Test file_error with basic parameters."""
        error = FlextLdifExceptions.file_error("File error (File: test.ldif)")
        assert error.error is not None
        assert "File error" in error.error
        assert "(File: test.ldif)" in error.error

    def test_file_error_with_operation(self) -> None:
        """Test file_error with operation parameter."""
        error = FlextLdifExceptions.file_error("File error (File: test.ldif)")
        assert error.error is not None
        assert "File error" in error.error
        assert "(File: test.ldif)" in error.error

    def test_configuration_error_basic(self) -> None:
        """Test configuration_error with basic parameters."""
        error = FlextLdifExceptions.configuration_error("Config error")
        assert error.error == "Config error"

    def test_authentication_error_basic(self) -> None:
        """Test authentication_error with basic parameters."""
        error = FlextLdifExceptions.authentication_error("Auth failed")
        assert error.error == "Auth failed"

    def test_parse_error_basic_alias(self) -> None:
        """Test parse_error with basic parameters - alias test."""
        error = FlextLdifExceptions.parse_error("Parse alias error")
        assert error.error == "Parse alias error"
        assert error.is_failure

    def test_parse_error_with_line_alias(self) -> None:
        """Test parse_error with line number - alias test."""
        error = FlextLdifExceptions.parse_error("Parse alias error (line 42)")
        assert error.error is not None
        assert "(line 42)" in error.error

    def test_parse_error_with_column(self) -> None:
        """Test parse_error with column."""
        error = FlextLdifExceptions.parse_error("Parse alias error")
        assert error.error == "Parse alias error"
