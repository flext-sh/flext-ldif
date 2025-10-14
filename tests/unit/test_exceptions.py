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
        result = FlextLdifExceptions.validation_error("Invalid field")
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
        result = FlextLdifExceptions.processing_error("Business rule violation")
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
        result = FlextLdifExceptions.configuration_error("Missing config key")
        assert result.is_failure
        assert result.error == "Missing config key"

    def test_connection_error(self) -> None:
        """Test connection error factory method."""
        result = FlextLdifExceptions.connection_error("Connection failed")
        assert result.is_failure
        assert result.error == "Connection failed"

    def test_connection_error_with_details(self) -> None:
        """Test connection error with service details."""
        result = FlextLdifExceptions.connection_error("Service unreachable")
        assert result.is_failure
        assert result.error == "Service unreachable"

    def test_timeout_error(self) -> None:
        """Test timeout error factory method."""
        result = FlextLdifExceptions.timeout_error("Operation timed out")
        assert result.is_failure
        assert result.error == "Operation timed out"

    def test_timeout_error_with_duration(self) -> None:
        """Test timeout error with timeout duration."""
        result = FlextLdifExceptions.timeout_error("Query timeout")
        assert result.is_failure
        assert result.error == "Query timeout"

    def test_authentication_error(self) -> None:
        """Test authentication error factory method."""
        result = FlextLdifExceptions.authentication_error("Auth failed")
        assert result.is_failure
        assert result.error == "Auth failed"

    def test_authentication_error_with_method(self) -> None:
        """Test authentication error with auth method."""
        result = FlextLdifExceptions.authentication_error("Invalid credentials")
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

    def test_dn_validation_error(self) -> None:
        """Test DN validation error factory method."""
        result = FlextLdifExceptions.dn_validation_error("Invalid DN format")
        assert result.is_failure
        assert result.error == "Invalid DN format"
        assert result.error_code == "DN_VALIDATION_ERROR"

    def test_dn_validation_error_with_dn_value(self) -> None:
        """Test DN validation error with DN value parameter."""
        result = FlextLdifExceptions.dn_validation_error("DN too long")
        assert result.is_failure
        assert result.error == "DN too long"
        assert result.error_code == "DN_VALIDATION_ERROR"

    def test_attribute_validation_error(self) -> None:
        """Test attribute validation error factory method."""
        result = FlextLdifExceptions.attribute_validation_error("Invalid attribute")
        assert result.is_failure
        assert result.error == "Invalid attribute"
        assert result.error_code == "ATTRIBUTE_VALIDATION_ERROR"

    def test_attribute_validation_error_with_details(self) -> None:
        """Test attribute validation error with attribute details."""
        result = FlextLdifExceptions.attribute_validation_error(
            "Attribute value type mismatch"
        )
        assert result.is_failure
        assert result.error == "Attribute value type mismatch"
        assert result.error_code == "ATTRIBUTE_VALIDATION_ERROR"

    def test_encoding_error(self) -> None:
        """Test encoding error factory method."""
        result = FlextLdifExceptions.encoding_error("Encoding failed")
        assert result.is_failure
        assert result.error == "Encoding failed"
        assert result.error_code == "ENCODING_ERROR"

    def test_encoding_error_with_encoding(self) -> None:
        """Test encoding error with encoding type."""
        result = FlextLdifExceptions.encoding_error("Cannot decode bytes")
        assert result.is_failure
        assert result.error == "Cannot decode bytes"
        assert result.error_code == "ENCODING_ERROR"

    def test_url_validation_error(self) -> None:
        """Test URL validation error factory method."""
        result = FlextLdifExceptions.url_validation_error("Invalid URL")
        assert result.is_failure
        assert result.error == "Invalid URL"
        assert result.error_code == "URL_VALIDATION_ERROR"

    def test_url_validation_error_with_url(self) -> None:
        """Test URL validation error with URL value."""
        result = FlextLdifExceptions.url_validation_error("Malformed LDAP URL")
        assert result.is_failure
        assert result.error == "Malformed LDAP URL"
        assert result.error_code == "URL_VALIDATION_ERROR"

    def test_schema_validation_error(self) -> None:
        """Test schema validation error factory method."""
        result = FlextLdifExceptions.schema_validation_error("Schema mismatch")
        assert result.is_failure
        assert result.error == "Schema mismatch"
        assert result.error_code == "SCHEMA_VALIDATION_ERROR"

    def test_schema_validation_error_with_schema_name(self) -> None:
        """Test schema validation error with schema name."""
        result = FlextLdifExceptions.schema_validation_error("Unknown schema")
        assert result.is_failure
        assert result.error == "Unknown schema"
        assert result.error_code == "SCHEMA_VALIDATION_ERROR"

    def test_objectclass_error(self) -> None:
        """Test objectclass error factory method."""
        result = FlextLdifExceptions.objectclass_error("Invalid objectClass")
        assert result.is_failure
        assert result.error == "Invalid objectClass"
        assert result.error_code == "OBJECTCLASS_ERROR"

    def test_objectclass_error_with_objectclass(self) -> None:
        """Test objectclass error with objectclass value."""
        result = FlextLdifExceptions.objectclass_error("Unknown objectClass")
        assert result.is_failure
        assert result.error == "Unknown objectClass"
        assert result.error_code == "OBJECTCLASS_ERROR"

    def test_ldif_format_error(self) -> None:
        """Test LDIF format error factory method."""
        result = FlextLdifExceptions.ldif_format_error("Invalid LDIF format")
        assert result.is_failure
        assert result.error == "Invalid LDIF format"
        assert result.error_code == "LDIF_FORMAT_ERROR"

    def test_ldif_format_error_with_line_number(self) -> None:
        """Test LDIF format error with line number."""
        result = FlextLdifExceptions.ldif_format_error("Missing colon after attribute")
        assert result.is_failure
        assert result.error == "Missing colon after attribute"
        assert result.error_code == "LDIF_FORMAT_ERROR"

    def test_rfc_compliance_error(self) -> None:
        """Test RFC compliance error factory method."""
        result = FlextLdifExceptions.rfc_compliance_error("RFC violation")
        assert result.is_failure
        assert result.error == "RFC violation"
        assert result.error_code == "RFC_COMPLIANCE_ERROR"

    def test_rfc_compliance_error_with_rfc_section(self) -> None:
        """Test RFC compliance error with RFC section."""
        result = FlextLdifExceptions.rfc_compliance_error("Invalid DN encoding")
        assert result.is_failure
        assert result.error == "Invalid DN encoding"
        assert result.error_code == "RFC_COMPLIANCE_ERROR"
