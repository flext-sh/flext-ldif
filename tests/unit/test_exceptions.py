"""Test suite for FlextLdifExceptions.

Comprehensive testing for LDIF exception factory methods.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.exceptions import FlextLdifExceptions


class TestFlextLdifExceptions:
    """Test suite for FlextLdifExceptions factory methods."""

    def test_validation_error(self) -> None:
        """Test validation error factory method."""
        result = FlextLdifExceptions.validation_error("Validation failed")
        assert result.is_failure
        assert result.error == "Validation failed"

    def test_validation_error_with_details(self) -> None:
        """Test validation error with optional parameters."""
        result = FlextLdifExceptions.validation_error(
            "Invalid field",
            field="email",
            value="invalid@",
            validation_details={"rule": "email_format"},
        )
        assert result.is_failure
        assert result.error == "Invalid field"

    def test_parse_error(self) -> None:
        """Test parse error factory method."""
        result = FlextLdifExceptions.parse_error("Parse failed")
        assert result.is_failure
        assert result.error == "Parse failed"

    def test_processing_error(self) -> None:
        """Test processing error factory method."""
        result = FlextLdifExceptions.processing_error("Processing failed")
        assert result.is_failure
        assert result.error == "Processing failed"

    def test_processing_error_with_details(self) -> None:
        """Test processing error with business rule details."""
        result = FlextLdifExceptions.processing_error(
            "Business rule violation",
            business_rule="unique_dn",
            operation="create_entry",
        )
        assert result.is_failure
        assert result.error == "Business rule violation"

    def test_file_error(self) -> None:
        """Test file error factory method."""
        result = FlextLdifExceptions.file_error("File not found")
        assert result.is_failure
        assert result.error == "File not found"

    def test_configuration_error(self) -> None:
        """Test configuration error factory method."""
        result = FlextLdifExceptions.configuration_error("Config invalid")
        assert result.is_failure
        assert result.error == "Config invalid"

    def test_configuration_error_with_details(self) -> None:
        """Test configuration error with config details."""
        result = FlextLdifExceptions.configuration_error(
            "Missing config key", config_key="ldif_encoding", config_file="config.yaml"
        )
        assert result.is_failure
        assert result.error == "Missing config key"

    def test_connection_error(self) -> None:
        """Test connection error factory method."""
        result = FlextLdifExceptions.connection_error("Connection failed")
        assert result.is_failure
        assert result.error == "Connection failed"

    def test_connection_error_with_details(self) -> None:
        """Test connection error with service details."""
        result = FlextLdifExceptions.connection_error(
            "Service unreachable",
            service="ldap_server",
            endpoint="ldap://localhost:389",
        )
        assert result.is_failure
        assert result.error == "Service unreachable"

    def test_timeout_error(self) -> None:
        """Test timeout error factory method."""
        result = FlextLdifExceptions.timeout_error("Operation timed out")
        assert result.is_failure
        assert result.error == "Operation timed out"

    def test_timeout_error_with_duration(self) -> None:
        """Test timeout error with timeout duration."""
        result = FlextLdifExceptions.timeout_error(
            "Query timeout", timeout_seconds=30.0
        )
        assert result.is_failure
        assert result.error == "Query timeout"

    def test_authentication_error(self) -> None:
        """Test authentication error factory method."""
        result = FlextLdifExceptions.authentication_error("Auth failed")
        assert result.is_failure
        assert result.error == "Auth failed"

    def test_authentication_error_with_method(self) -> None:
        """Test authentication error with auth method."""
        result = FlextLdifExceptions.authentication_error(
            "Invalid credentials", auth_method="simple_bind"
        )
        assert result.is_failure
        assert result.error == "Invalid credentials"

    def test_error(self) -> None:
        """Test generic error factory method."""
        result = FlextLdifExceptions.error("Generic error occurred")
        assert result.is_failure
        assert result.error == "Generic error occurred"

    def test_entry_error(self) -> None:
        """Test entry error factory method."""
        result = FlextLdifExceptions.entry_error("Entry validation failed")
        assert result.is_failure
        assert result.error == "Entry validation failed"
