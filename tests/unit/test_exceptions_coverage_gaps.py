"""Tests for FlextLDIFExceptions coverage gaps.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.exceptions import FlextLDIFErrorCodes, FlextLDIFExceptions


class TestFlextLDIFExceptionsCoverageGaps:
    """Test coverage gaps in FlextLDIFExceptions."""

    def test_processing_error_with_operation(self) -> None:
        """Test processing_error with operation parameter."""
        error = FlextLDIFExceptions.processing_error(
            "Processing failed", operation="test_operation"
        )
        assert error.message == "Processing failed"
        assert error.operation == "ldif_processing"
        assert error.context.get("operation") == "test_operation"

    def test_timeout_error_with_duration(self) -> None:
        """Test timeout_error with timeout_duration parameter."""
        error = FlextLDIFExceptions.timeout_error(
            "Timeout occurred", timeout_duration=30.5
        )
        assert error.message == "Timeout occurred"
        assert error.operation == "ldif_timeout"
        assert error.context.get("timeout_duration") == 30.5

    def test_builder_pattern_usage(self) -> None:
        """Test exception builder pattern."""
        builder = FlextLDIFExceptions.builder()
        assert builder is not None

        # Test builder methods
        builder.message("Test error")
        builder.code("TEST_ERROR")
        builder.context({"test": "value"})
        builder.location(line=10, column=5)
        builder.dn("cn=test,dc=example,dc=com")
        builder.attribute("testAttribute")
        builder.entry_index(0)
        builder.entry_data({"cn": ["test"]})
        builder.validation_rule("required_field")
        builder.file_path("test.ldif")
        builder.operation("test_operation")

        # Build the exception
        error = builder.build()
        assert str(error) == "Test error"
        assert error.context["test"] == "value"
        assert error.context["line"] == 10
        assert error.context["column"] == 5
        assert error.context["dn"] == "cn=test,dc=example,dc=com"
        assert error.context["attribute"] == "testAttribute"
        assert error.context["entry_index"] == 0
        assert error.context["entry_data"] == {"cn": ["test"]}
        assert error.context["validation_rule"] == "required_field"
        assert error.context["file_path"] == "test.ldif"
        assert error.context["operation"] == "test_operation"

    def test_error_codes_access(self) -> None:
        """Test error codes access."""
        # Test error code values
        assert FlextLDIFErrorCodes.LDIF_PARSE_ERROR.value == "LDIF_PARSE_ERROR"
        assert FlextLDIFErrorCodes.LDIF_ENTRY_ERROR.value == "LDIF_ENTRY_ERROR"
        assert FlextLDIFErrorCodes.LDIF_ERROR.value == "LDIF_ERROR"
        assert FlextLDIFErrorCodes.LDIF_VALIDATION_ERROR.value == "LDIF_VALIDATION_ERROR"
        assert FlextLDIFErrorCodes.LDIF_CONFIGURATION_ERROR.value == "LDIF_CONFIGURATION_ERROR"
        assert FlextLDIFErrorCodes.LDIF_PROCESSING_ERROR.value == "LDIF_PROCESSING_ERROR"
        assert FlextLDIFErrorCodes.LDIF_CONNECTION_ERROR.value == "LDIF_CONNECTION_ERROR"
        assert FlextLDIFErrorCodes.LDIF_AUTHENTICATION_ERROR.value == "LDIF_AUTHENTICATION_ERROR"
        assert FlextLDIFErrorCodes.LDIF_TIMEOUT_ERROR.value == "LDIF_TIMEOUT_ERROR"
