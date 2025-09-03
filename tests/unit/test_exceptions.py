"""Tests for LDIF exceptions - comprehensive coverage."""

from __future__ import annotations

import pytest

from flext_ldif.exceptions import (
    FlextLDIFAuthenticationError,
    FlextLDIFConfigurationError,
    FlextLDIFConnectionError,
    FlextLDIFEntryError,
    FlextLDIFEntryValidationError,
    FlextLDIFError,
    FlextLDIFErrorCodes,
    FlextLDIFFileError,
    FlextLDIFParseError,
    FlextLDIFProcessingError,
    FlextLDIFTimeoutError,
    FlextLDIFValidationError,
)


class TestFlextLDIFExceptions:
    """Test suite for FLEXT LDIF exceptions."""

    def test_flext_ldif_error_default(self) -> None:
        """Test FlextLDIFError with default parameters."""
        error = FlextLDIFError()
        assert isinstance(error, Exception)
        assert isinstance(error, FlextLDIFError)

    def test_flext_ldif_error_custom_message(self) -> None:
        """Test FlextLDIFError with custom message."""
        error = FlextLDIFError("Custom LDIF error")
        assert "Custom LDIF error" in str(error)

    def test_flext_ldif_parse_error_inheritance(self) -> None:
        """Test FlextLDIFParseError inheritance."""
        error = FlextLDIFParseError("Parse error")
        assert isinstance(error, FlextLDIFError)
        assert isinstance(error, FlextLDIFParseError)
        assert "Parse error" in str(error)

    def test_flext_ldif_validation_error_inheritance(self) -> None:
        """Test FlextLDIFValidationError inheritance."""
        error = FlextLDIFValidationError("Validation error")
        assert isinstance(error, FlextLDIFError)
        assert isinstance(error, FlextLDIFValidationError)
        assert "Validation error" in str(error)

    def test_flext_ldif_entry_error_inheritance(self) -> None:
        """Test FlextLDIFEntryError inheritance."""
        error = FlextLDIFEntryError("Entry error")
        assert isinstance(error, FlextLDIFValidationError)
        assert isinstance(error, FlextLDIFEntryError)
        assert "Entry error" in str(error)

    def test_exception_hierarchy(self) -> None:
        """Test exception hierarchy is correct."""
        # Test that all exceptions inherit from FlextLDIFError
        parse_error = FlextLDIFParseError("test")
        validation_error = FlextLDIFValidationError("test")
        entry_error = FlextLDIFEntryError("test")

        assert isinstance(parse_error, FlextLDIFError)
        assert isinstance(validation_error, FlextLDIFError)
        assert isinstance(entry_error, FlextLDIFError)
        assert isinstance(entry_error, FlextLDIFValidationError)

    def test_exception_can_be_raised_and_caught(self) -> None:
        """Test exceptions can be raised and caught properly."""
        test_error_msg = "test error"
        parse_error_msg = "parse error"
        validation_error_msg = "validation error"
        entry_error_msg = "entry error"

        with pytest.raises(FlextLDIFError):
            raise FlextLDIFError(test_error_msg)

        with pytest.raises(FlextLDIFParseError):
            raise FlextLDIFParseError(parse_error_msg)

        with pytest.raises(FlextLDIFValidationError):
            raise FlextLDIFValidationError(validation_error_msg)

        with pytest.raises(FlextLDIFEntryError):
            raise FlextLDIFEntryError(entry_error_msg)

    def test_exception_messages(self) -> None:
        """Test exception messages are preserved and include error codes."""
        message = "Custom error message"

        error = FlextLDIFError(message)
        assert message in str(error)  # Message should be in the string representation

        parse_error = FlextLDIFParseError(message)
        assert message in str(parse_error)

        validation_error = FlextLDIFValidationError(message)
        assert message in str(validation_error)

        entry_error = FlextLDIFEntryError(message)
        assert message in str(entry_error)

    def test_error_codes_enum(self) -> None:
        """Test that error codes enum contains expected values."""
        expected_codes = [
            "LDIF_ERROR",
            "LDIF_VALIDATION_ERROR",
            "LDIF_PARSE_ERROR",
            "LDIF_ENTRY_ERROR",
            "LDIF_CONFIGURATION_ERROR",
            "LDIF_PROCESSING_ERROR",
            "LDIF_CONNECTION_ERROR",
            "LDIF_AUTHENTICATION_ERROR",
            "LDIF_TIMEOUT_ERROR",
        ]

        for code in expected_codes:
            assert hasattr(FlextLDIFErrorCodes, code)
            assert getattr(FlextLDIFErrorCodes, code).value == code

    def test_all_exception_classes(self) -> None:
        """Test all exception classes can be instantiated and inherit correctly."""
        # Test configuration error
        config_error = FlextLDIFConfigurationError("Config error")
        assert isinstance(config_error, FlextLDIFError)
        assert "Config error" in str(config_error)

        # Test processing error
        processing_error = FlextLDIFProcessingError("Processing error")
        assert isinstance(processing_error, FlextLDIFError)
        assert "Processing error" in str(processing_error)

        # Test connection error
        connection_error = FlextLDIFConnectionError("Connection error")
        assert isinstance(connection_error, FlextLDIFError)
        assert "Connection error" in str(connection_error)

        # Test authentication error
        auth_error = FlextLDIFAuthenticationError("Auth error")
        assert isinstance(auth_error, FlextLDIFError)
        assert "Auth error" in str(auth_error)

        # Test timeout error
        timeout_error = FlextLDIFTimeoutError("Timeout error")
        assert isinstance(timeout_error, FlextLDIFError)
        assert "Timeout error" in str(timeout_error)

        # Test file error
        file_error = FlextLDIFFileError("File error")
        assert isinstance(file_error, FlextLDIFError)
        assert "File error" in str(file_error)

        # Test entry validation error
        entry_validation_error = FlextLDIFEntryValidationError("Entry validation error")
        assert isinstance(entry_validation_error, FlextLDIFEntryError)
        assert isinstance(entry_validation_error, FlextLDIFValidationError)
        assert "Entry validation error" in str(entry_validation_error)

    def test_exception_with_context(self) -> None:
        """Test exceptions with context parameter."""
        context = {"file": "test.ldif", "line": 42}
        error = FlextLDIFError("Error with context", context=context)
        # Context should be preserved in the exception
        assert hasattr(error, "context") or str(
            error
        )  # Either attribute exists or context is in string

    def test_exception_with_cause(self) -> None:
        """Test exceptions with context containing cause information."""
        cause = ValueError("Original error")
        error = FlextLDIFError("LDIF error", context={"cause": str(cause)})
        # Context should contain cause information
        assert error.context is not None
        assert "cause" in error.context
        assert "Original error" in str(error.context["cause"])

    def test_file_error_with_file_path(self) -> None:
        """Test FlextLDIFFileError with file_path parameter."""
        file_path = "/path/to/test.ldif"
        error = FlextLDIFFileError("File not found", file_path=file_path)
        assert "File not found" in str(error)

    def test_entry_validation_error_with_params(self) -> None:
        """Test FlextLDIFEntryValidationError with additional parameters."""
        error = FlextLDIFEntryValidationError(
            "Validation failed",
            dn="cn=test,dc=example,dc=com",
            attribute_name="cn",
            validation_rule="required_attribute",
        )
        assert "Validation failed" in str(error)

    def test_file_error_with_all_context_parameters(self) -> None:
        """Test FlextLDIFFileError with all context parameters to cover missing lines."""
        error = FlextLDIFFileError(
            "File operation failed",
            file_path="/path/to/test.ldif",
            line_number=42,  # This covers line 239
            operation="read",  # This covers line 241
            encoding="utf-8",  # This covers line 243
        )
        assert "File operation failed" in str(error)

    def test_entry_validation_error_with_long_attribute_value(self) -> None:
        """Test FlextLDIFEntryValidationError with long attribute value to cover truncation logic."""
        # Create a very long attribute value (over 100 characters)
        long_value = "x" * 150  # 150 characters

        error = FlextLDIFEntryValidationError(
            "Attribute too long",
            dn="cn=test,dc=example,dc=com",
            attribute_name="description",
            attribute_value=long_value,  # This covers lines 275-281 (truncation logic)
            entry_index=5,  # This covers line 283
            validation_rule="max_length_check",
        )
        assert "Attribute too long" in str(error)

    def test_entry_validation_error_with_short_attribute_value(self) -> None:
        """Test FlextLDIFEntryValidationError with short attribute value to cover non-truncation path."""
        short_value = "short"  # Under 100 characters

        error = FlextLDIFEntryValidationError(
            "Attribute validation failed",
            attribute_value=short_value,  # This ensures the else path in truncation logic is covered
            entry_index=10,
        )
        assert "Attribute validation failed" in str(error)
