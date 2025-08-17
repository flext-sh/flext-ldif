"""Tests for LDIF exceptions."""

from __future__ import annotations

import pytest

from flext_ldif import (
    FlextLdifEntryError,
    FlextLdifError,
    FlextLdifParseError,
    FlextLdifValidationError,
)


class TestFlextLdifExceptions:
    """Test suite for FLEXT LDIF exceptions."""

    def test_flext_ldif_error_default(self) -> None:
        """Test FlextLdifError with default parameters."""
        error = FlextLdifError()
        assert isinstance(error, Exception)
        assert isinstance(error, FlextLdifError)

    def test_flext_ldif_error_custom_message(self) -> None:
        """Test FlextLdifError with custom message."""
        error = FlextLdifError("Custom LDIF error")
        assert "Custom LDIF error" in str(error)

    def test_flext_ldif_parse_error_inheritance(self) -> None:
        """Test FlextLdifParseError inheritance."""
        error = FlextLdifParseError("Parse error")
        assert isinstance(error, FlextLdifError)
        assert isinstance(error, FlextLdifParseError)
        assert "Parse error" in str(error)

    def test_flext_ldif_validation_error_inheritance(self) -> None:
        """Test FlextLdifValidationError inheritance."""
        error = FlextLdifValidationError("Validation error")
        assert isinstance(error, FlextLdifError)
        assert isinstance(error, FlextLdifValidationError)
        assert "Validation error" in str(error)

    def test_flext_ldif_entry_error_inheritance(self) -> None:
        """Test FlextLdifEntryError inheritance."""
        error = FlextLdifEntryError("Entry error")
        assert isinstance(error, FlextLdifValidationError)
        assert isinstance(error, FlextLdifEntryError)
        assert "Entry error" in str(error)

    def test_exception_hierarchy(self) -> None:
        """Test exception hierarchy is correct."""
        # Test that all exceptions inherit from FlextLdifError
        parse_error = FlextLdifParseError("test")
        validation_error = FlextLdifValidationError("test")
        entry_error = FlextLdifEntryError("test")

        assert isinstance(parse_error, FlextLdifError)
        assert isinstance(validation_error, FlextLdifError)
        assert isinstance(entry_error, FlextLdifError)
        assert isinstance(entry_error, FlextLdifValidationError)

    def test_exception_can_be_raised_and_caught(self) -> None:
        """Test exceptions can be raised and caught properly."""
        test_error_msg = "test error"
        parse_error_msg = "parse error"
        validation_error_msg = "validation error"
        entry_error_msg = "entry error"

        with pytest.raises(FlextLdifError):
            raise FlextLdifError(test_error_msg)

        with pytest.raises(FlextLdifParseError):
            raise FlextLdifParseError(parse_error_msg)

        with pytest.raises(FlextLdifValidationError):
            raise FlextLdifValidationError(validation_error_msg)

        with pytest.raises(FlextLdifEntryError):
            raise FlextLdifEntryError(entry_error_msg)

    def test_exception_messages(self) -> None:
        """Test exception messages are preserved."""
        message = "Custom error message"

        error = FlextLdifError(message)
        assert str(error) == message

        parse_error = FlextLdifParseError(message)
        assert str(parse_error) == message

        validation_error = FlextLdifValidationError(message)
        assert str(validation_error) == message

        entry_error = FlextLdifEntryError(message)
        assert str(entry_error) == message
