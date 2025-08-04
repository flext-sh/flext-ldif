"""Tests for LDIF exceptions using flext-core patterns.

Comprehensive test suite covering all exception functionality with enterprise-grade
testing practices and proper error handling validation.
"""

from __future__ import annotations

import pytest

from flext_ldif.exceptions import (
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
        assert "flext_ldif error" in str(error)
        assert error.error_code == "FLEXT_LDIF_ERROR"

    def test_flext_ldif_error_custom_message(self) -> None:
        """Test FlextLdifError with custom message."""
        error = FlextLdifError("Custom LDIF error")
        assert "Custom LDIF error" in str(error)
        assert error.error_code == "FLEXT_LDIF_ERROR"

    def test_flext_ldif_error_with_context(self) -> None:
        """Test FlextLdifError with context."""
        error = FlextLdifError("Error with context", source="test", operation="parse")
        assert "Error with context" in str(error)
        assert error.context["source"] == "test"
        assert error.context["operation"] == "parse"

    def test_flext_ldif_parse_error_default(self) -> None:
        """Test FlextLdifParseError with default parameters."""
        error = FlextLdifParseError()
        assert "LDIF parsing failed: LDIF parsing failed" in str(error)

    def test_flext_ldif_parse_error_custom_message(self) -> None:
        """Test FlextLdifParseError with custom message."""
        error = FlextLdifParseError("Custom parse error")
        assert "LDIF parsing failed: Custom parse error" in str(error)

    def test_flext_ldif_parse_error_with_line_number(self) -> None:
        """Test FlextLdifParseError with line number."""
        error = FlextLdifParseError("Parse error", line_number=42)
        assert "LDIF parsing failed: Parse error" in str(error)
        assert error.context["line_number"] == 42

    def test_flext_ldif_parse_error_with_entry_dn(self) -> None:
        """Test FlextLdifParseError with entry DN."""
        error = FlextLdifParseError("Parse error", entry_dn="cn=test,dc=example,dc=com")
        assert "LDIF parsing failed: Parse error" in str(error)
        assert error.context["entry_dn"] == "cn=test,dc=example,dc=com"

    def test_flext_ldif_parse_error_with_all_params(self) -> None:
        """Test FlextLdifParseError with all parameters."""
        error = FlextLdifParseError(
            "Complete parse error",
            line_number=10,
            entry_dn="cn=user,dc=example,dc=com",
            source="file.ldif",
        )
        assert "LDIF parsing failed: Complete parse error" in str(error)
        assert error.context["line_number"] == 10
        assert error.context["entry_dn"] == "cn=user,dc=example,dc=com"
        assert error.context["source"] == "file.ldif"

    def test_flext_ldif_validation_error_default(self) -> None:
        """Test FlextLdifValidationError with default parameters."""
        error = FlextLdifValidationError()
        assert "flext_ldif: flext_ldif validation failed" in str(error)

    def test_flext_ldif_validation_error_custom_message(self) -> None:
        """Test FlextLdifValidationError with custom message."""
        error = FlextLdifValidationError("Custom validation error")
        assert "flext_ldif: Custom validation error" in str(error)

    def test_flext_ldif_validation_error_with_attribute(self) -> None:
        """Test FlextLdifValidationError with attribute details."""
        error = FlextLdifValidationError(
            "Invalid attribute",
            field="cn",
            value="invalid value",
        )
        assert "flext_ldif: Invalid attribute" in str(error)
        assert error.field == "cn"
        assert error.value == "invalid value"

    def test_flext_ldif_validation_error_with_entry_dn(self) -> None:
        """Test FlextLdifValidationError with entry DN."""
        error = FlextLdifValidationError(
            "Validation error",
            entry_dn="cn=test,dc=example,dc=com",
        )
        assert "flext_ldif: Validation error" in str(error)
        assert error.context["entry_dn"] == "cn=test,dc=example,dc=com"

    def test_flext_ldif_validation_error_with_all_params(self) -> None:
        """Test FlextLdifValidationError with all parameters."""
        error = FlextLdifValidationError(
            "Complete validation error",
            field="objectClass",
            value=["invalid"],
            entry_dn="cn=user,dc=example,dc=com",
            schema="test-schema",
        )
        assert "flext_ldif: Complete validation error" in str(error)
        assert error.field == "objectClass"
        assert error.value == "['invalid']"  # Factory converts to string representation
        assert error.context["entry_dn"] == "cn=user,dc=example,dc=com"
        assert error.context["schema"] == "test-schema"

    def test_flext_ldif_entry_error_default(self) -> None:
        """Test FlextLdifEntryError with default parameters."""
        error = FlextLdifEntryError()
        assert "LDIF entry processing failed: LDIF entry error" in str(error)

    def test_flext_ldif_entry_error_custom_message(self) -> None:
        """Test FlextLdifEntryError with custom message."""
        error = FlextLdifEntryError("Custom entry error")
        assert "LDIF entry processing failed: Custom entry error" in str(error)

    def test_flext_ldif_entry_error_with_entry_dn(self) -> None:
        """Test FlextLdifEntryError with entry DN."""
        error = FlextLdifEntryError(
            "Entry error",
            entry_dn="cn=test,dc=example,dc=com",
        )
        assert "LDIF entry processing failed: Entry error" in str(error)
        assert error.context["entry_dn"] == "cn=test,dc=example,dc=com"

    def test_flext_ldif_entry_error_with_operation(self) -> None:
        """Test FlextLdifEntryError with operation."""
        error = FlextLdifEntryError("Entry error", operation="modify")
        assert "LDIF entry processing failed: Entry error" in str(error)
        assert "(operation: modify)" in str(error)
        assert error.context["operation"] == "modify"

    def test_flext_ldif_entry_error_with_all_params(self) -> None:
        """Test FlextLdifEntryError with all parameters."""
        error = FlextLdifEntryError(
            "Complete entry error",
            entry_dn="cn=user,dc=example,dc=com",
            operation="delete",
            source="ldap_server",
        )
        assert "LDIF entry processing failed: Complete entry error" in str(error)
        assert error.context["entry_dn"] == "cn=user,dc=example,dc=com"
        assert error.context["operation"] == "delete"
        assert error.context["source"] == "ldap_server"

    def test_exception_inheritance(self) -> None:
        """Test exception inheritance hierarchy."""
        # FlextLdifParseError inherits from FlextProcessingError
        parse_error = FlextLdifParseError("Parse error")
        assert isinstance(parse_error, Exception)

        # FlextLdifValidationError inherits from generated validation error
        validation_error = FlextLdifValidationError("Validation error")
        assert isinstance(validation_error, Exception)

        # FlextLdifEntryError inherits from FlextProcessingError
        entry_error = FlextLdifEntryError("Entry error")
        assert isinstance(entry_error, Exception)

    def test_exception_can_be_raised_and_caught(self) -> None:
        """Test that exceptions can be raised and caught properly."""
        test_error_msg = "Test error"
        with pytest.raises(FlextLdifError):
            raise FlextLdifError(test_error_msg)

        parse_error_msg = "Parse error"
        with pytest.raises(FlextLdifParseError):
            raise FlextLdifParseError(parse_error_msg)

        validation_error_msg = "Validation error"
        with pytest.raises(FlextLdifValidationError):
            raise FlextLdifValidationError(validation_error_msg)

        entry_error_msg = "Entry error"
        with pytest.raises(FlextLdifEntryError):
            raise FlextLdifEntryError(entry_error_msg)
