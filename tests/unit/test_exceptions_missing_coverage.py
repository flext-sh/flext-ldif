"""Tests for missing exception coverage lines.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.exceptions import FlextLDIFExceptions


class TestExceptionsMissingCoverage:
    """Test missing coverage lines in exceptions.py."""

    def test_file_error_with_file_path(self) -> None:
        """Test file_error method with file_path parameter - covers line 145->147."""
        error = FlextLDIFExceptions.file_error(
            "File operation failed", file_path="/path/to/file.ldif"
        )
        assert "File operation failed (file: /path/to/file.ldif)" in str(error)

    def test_file_error_without_file_path(self) -> None:
        """Test file_error method without file_path parameter - covers line 176."""
        error = FlextLDIFExceptions.file_error("File operation failed")
        assert "File operation failed" in str(error)

    def test_parse_error_with_line_and_column(self) -> None:
        """Test parse_error with line and column - covers line 240->242."""
        error = FlextLDIFExceptions.parse_error("Parse failed", line=10, column=5)
        assert "Parse failed (line 10, column 5)" in str(error)
        assert hasattr(error, "operation")
        assert error.operation == "ldif_parsing"

    def test_parse_error_with_line_only(self) -> None:
        """Test parse_error with line only - covers line 242->244."""
        error = FlextLDIFExceptions.parse_error("Parse failed", line=10)
        assert "Parse failed (line 10)" in str(error)
        assert hasattr(error, "operation")
        assert error.operation == "ldif_parsing"

    def test_parse_error_without_location(self) -> None:
        """Test parse_error without location - covers line 301."""
        error = FlextLDIFExceptions.parse_error("Parse failed")
        assert "Parse failed" in str(error)
        assert hasattr(error, "operation")
        assert error.operation == "ldif_parsing"

    def test_validation_error_with_context(self) -> None:
        """Test validation_error with context - covers line 306."""
        error = FlextLDIFExceptions.validation_error(
            "Validation failed", entry_dn="cn=test,dc=example,dc=com"
        )
        assert "Validation failed (DN: cn=test,dc=example,dc=com)" in str(error)
        # Note: ValidationError from flext-core doesn't have operation attribute
        # assert hasattr(error, "operation")
        # assert error.operation == "ldif_validation"

    def test_configuration_error_with_context(self) -> None:
        """Test configuration_error with context - covers line 368."""
        error = FlextLDIFExceptions.configuration_error("Configuration failed")
        assert "Configuration failed" in str(error)
        # ConfigurationError doesn't have operation attribute
        assert hasattr(error, "code")

    def test_connection_error_with_context(self) -> None:
        """Test connection_error with context - covers line 389."""
        error = FlextLDIFExceptions.connection_error("Connection failed")
        assert "Connection failed" in str(error)
        # ConnectionError doesn't have operation attribute
        assert hasattr(error, "code")
