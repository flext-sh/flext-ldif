"""FLEXT LDIF Exceptions - Comprehensive Unit Tests.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
import time

import pytest

from flext_core import FlextExceptions, FlextResult
from flext_ldif.exceptions import FlextLdifExceptions


@pytest.mark.unit
class TestFlextLdifExceptions:
    """Comprehensive tests for FlextLdifExceptions class."""

    def test_validation_error_creation(self) -> None:
        """Test validation error creation."""
        result = FlextLdifExceptions.validation_error("Test validation error")

        assert result.is_failure
        assert result.error == "Test validation error"
        assert result.error_code == "VALIDATION_ERROR"

    def test_validation_error_with_field(self) -> None:
        """Test validation error creation with field."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error", field="dn"
        )

        assert result.is_failure
        assert result.error == "Test validation error"
        assert result.error_code == "VALIDATION_ERROR"

    def test_validation_error_with_value(self) -> None:
        """Test validation error creation with value."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error", value="invalid-dn"
        )

        assert result.is_failure
        assert result.error == "Test validation error"
        assert result.error_code == "VALIDATION_ERROR"

    def test_validation_error_with_validation_details(self) -> None:
        """Test validation error creation with validation details."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error", validation_details={"rule": "DN_FORMAT"}
        )

        assert result.is_failure
        assert result.error == "Test validation error"
        assert result.error_code == "VALIDATION_ERROR"

    def test_validation_error_with_all_parameters(self) -> None:
        """Test validation error creation with all parameters."""
        result = FlextLdifExceptions.validation_error(
            "Test validation error",
            field="dn",
            value="invalid-dn",
            validation_details={"rule": "DN_FORMAT"},
        )

        assert result.is_failure
        assert result.error == "Test validation error"
        assert result.error_code == "VALIDATION_ERROR"

    def test_parse_error_creation(self) -> None:
        """Test parse error creation."""
        result = FlextLdifExceptions.parse_error("Test parse error")

        assert result.is_failure
        assert result.error == "Test parse error"
        assert result.error_code == "PARSE_ERROR"

    def test_processing_error_creation(self) -> None:
        """Test processing error creation."""
        result = FlextLdifExceptions.processing_error("Test processing error")

        assert result.is_failure
        assert result.error == "Test processing error"
        assert result.error_code == "PROCESSING_ERROR"

    def test_processing_error_with_business_rule(self) -> None:
        """Test processing error creation with business rule."""
        result = FlextLdifExceptions.processing_error(
            "Test processing error", business_rule="DN_VALIDATION"
        )

        assert result.is_failure
        assert result.error == "Test processing error"
        assert result.error_code == "PROCESSING_ERROR"

    def test_processing_error_with_operation(self) -> None:
        """Test processing error creation with operation."""
        result = FlextLdifExceptions.processing_error(
            "Test processing error", operation="parse"
        )

        assert result.is_failure
        assert result.error == "Test processing error"
        assert result.error_code == "PROCESSING_ERROR"

    def test_processing_error_with_all_parameters(self) -> None:
        """Test processing error creation with all parameters."""
        result = FlextLdifExceptions.processing_error(
            "Test processing error", business_rule="DN_VALIDATION", operation="parse"
        )

        assert result.is_failure
        assert result.error == "Test processing error"
        assert result.error_code == "PROCESSING_ERROR"

    def test_file_error_creation(self) -> None:
        """Test file error creation."""
        result = FlextLdifExceptions.file_error("Test file error")

        assert result.is_failure
        assert result.error == "Test file error"
        assert result.error_code == "FILE_ERROR"

    def test_configuration_error_creation(self) -> None:
        """Test configuration error creation."""
        result = FlextLdifExceptions.configuration_error("Test configuration error")

        assert result.is_failure
        assert result.error == "Test configuration error"
        assert result.error_code == "CONFIGURATION_ERROR"

    def test_configuration_error_with_config_key(self) -> None:
        """Test configuration error creation with config key."""
        result = FlextLdifExceptions.configuration_error(
            "Test configuration error", config_key="invalid_key"
        )

        assert result.is_failure
        assert result.error == "Test configuration error"
        assert result.error_code == "CONFIGURATION_ERROR"

    def test_configuration_error_with_config_file(self) -> None:
        """Test configuration error creation with config file."""
        result = FlextLdifExceptions.configuration_error(
            "Test configuration error", config_file="/path/to/config.json"
        )

        assert result.is_failure
        assert result.error == "Test configuration error"
        assert result.error_code == "CONFIGURATION_ERROR"

    def test_configuration_error_with_all_parameters(self) -> None:
        """Test configuration error creation with all parameters."""
        result = FlextLdifExceptions.configuration_error(
            "Test configuration error",
            config_key="invalid_key",
            config_file="/path/to/config.json",
        )

        assert result.is_failure
        assert result.error == "Test configuration error"
        assert result.error_code == "CONFIGURATION_ERROR"

    def test_connection_error_creation(self) -> None:
        """Test connection error creation."""
        result = FlextLdifExceptions.connection_error("Test connection error")

        assert result.is_failure
        assert result.error == "Test connection error"
        assert result.error_code == "CONNECTION_ERROR"

    def test_connection_error_with_service(self) -> None:
        """Test connection error creation with service."""
        result = FlextLdifExceptions.connection_error(
            "Test connection error", service="ldap"
        )

        assert result.is_failure
        assert result.error == "Test connection error"
        assert result.error_code == "CONNECTION_ERROR"

    def test_connection_error_with_endpoint(self) -> None:
        """Test connection error creation with endpoint."""
        result = FlextLdifExceptions.connection_error(
            "Test connection error", endpoint="ldap://example.com:389"
        )

        assert result.is_failure
        assert result.error == "Test connection error"
        assert result.error_code == "CONNECTION_ERROR"

    def test_connection_error_with_all_parameters(self) -> None:
        """Test connection error creation with all parameters."""
        result = FlextLdifExceptions.connection_error(
            "Test connection error", service="ldap", endpoint="ldap://example.com:389"
        )

        assert result.is_failure
        assert result.error == "Test connection error"
        assert result.error_code == "CONNECTION_ERROR"

    def test_timeout_error_creation(self) -> None:
        """Test timeout error creation."""
        result = FlextLdifExceptions.timeout_error("Test timeout error")

        assert result.is_failure
        assert result.error == "Test timeout error"
        assert result.error_code == "TIMEOUT_ERROR"

    def test_timeout_error_with_timeout_seconds(self) -> None:
        """Test timeout error creation with timeout seconds."""
        result = FlextLdifExceptions.timeout_error(
            "Test timeout error", timeout_seconds=30.0
        )

        assert result.is_failure
        assert result.error == "Test timeout error"
        assert result.error_code == "TIMEOUT_ERROR"

    def test_authentication_error_creation(self) -> None:
        """Test authentication error creation."""
        result = FlextLdifExceptions.authentication_error("Test authentication error")

        assert result.is_failure
        assert result.error == "Test authentication error"
        assert result.error_code == "AUTHENTICATION_ERROR"

    def test_authentication_error_with_auth_method(self) -> None:
        """Test authentication error creation with auth method."""
        result = FlextLdifExceptions.authentication_error(
            "Test authentication error", auth_method="SIMPLE"
        )

        assert result.is_failure
        assert result.error == "Test authentication error"
        assert result.error_code == "AUTHENTICATION_ERROR"

    def test_generic_error_creation(self) -> None:
        """Test generic error creation."""
        result = FlextLdifExceptions.error("Test generic error")

        assert result.is_failure
        assert result.error == "Test generic error"
        assert result.error_code == "GENERIC_ERROR"

    def test_entry_error_creation(self) -> None:
        """Test entry error creation."""
        result = FlextLdifExceptions.entry_error("Test entry error")

        assert result.is_failure
        assert result.error == "Test entry error"
        assert result.error_code == "ENTRY_ERROR"

    def test_exceptions_inheritance(self) -> None:
        """Test exceptions inheritance hierarchy."""
        # Test that FlextLdifExceptions inherits from FlextExceptions

        assert issubclass(FlextLdifExceptions, FlextExceptions)

    def test_exceptions_class_methods(self) -> None:
        """Test that all exception factory methods are callable."""
        # Test that all methods are callable
        assert callable(FlextLdifExceptions.validation_error)
        assert callable(FlextLdifExceptions.parse_error)
        assert callable(FlextLdifExceptions.processing_error)
        assert callable(FlextLdifExceptions.file_error)
        assert callable(FlextLdifExceptions.configuration_error)
        assert callable(FlextLdifExceptions.connection_error)
        assert callable(FlextLdifExceptions.timeout_error)
        assert callable(FlextLdifExceptions.authentication_error)
        assert callable(FlextLdifExceptions.error)
        assert callable(FlextLdifExceptions.entry_error)

    def test_exceptions_return_types(self) -> None:
        """Test that all exception factory methods return FlextResult."""
        # Test that all methods return FlextResult[None]
        result = FlextLdifExceptions.validation_error("test")
        assert isinstance(result, FlextResult)

        result = FlextLdifExceptions.parse_error("test")
        assert isinstance(result, FlextResult)

        result = FlextLdifExceptions.processing_error("test")
        assert isinstance(result, FlextResult)

        result = FlextLdifExceptions.file_error("test")
        assert isinstance(result, FlextResult)

        result = FlextLdifExceptions.configuration_error("test")
        assert isinstance(result, FlextResult)

        result = FlextLdifExceptions.connection_error("test")
        assert isinstance(result, FlextResult)

        result = FlextLdifExceptions.timeout_error("test")
        assert isinstance(result, FlextResult)

        result = FlextLdifExceptions.authentication_error("test")
        assert isinstance(result, FlextResult)

        result = FlextLdifExceptions.error("test")
        assert isinstance(result, FlextResult)

        result = FlextLdifExceptions.entry_error("test")
        assert isinstance(result, FlextResult)

    def test_exceptions_error_codes(self) -> None:
        """Test that all exception factory methods return correct error codes."""
        # Test error codes
        result = FlextLdifExceptions.validation_error("test")
        assert result.error_code == "VALIDATION_ERROR"

        result = FlextLdifExceptions.parse_error("test")
        assert result.error_code == "PARSE_ERROR"

        result = FlextLdifExceptions.processing_error("test")
        assert result.error_code == "PROCESSING_ERROR"

        result = FlextLdifExceptions.file_error("test")
        assert result.error_code == "FILE_ERROR"

        result = FlextLdifExceptions.configuration_error("test")
        assert result.error_code == "CONFIGURATION_ERROR"

        result = FlextLdifExceptions.connection_error("test")
        assert result.error_code == "CONNECTION_ERROR"

        result = FlextLdifExceptions.timeout_error("test")
        assert result.error_code == "TIMEOUT_ERROR"

        result = FlextLdifExceptions.authentication_error("test")
        assert result.error_code == "AUTHENTICATION_ERROR"

        result = FlextLdifExceptions.error("test")
        assert result.error_code == "GENERIC_ERROR"

        result = FlextLdifExceptions.entry_error("test")
        assert result.error_code == "ENTRY_ERROR"

    def test_exceptions_performance(self) -> None:
        """Test exceptions performance characteristics."""
        # Test exception creation performance
        start_time = time.time()

        for _ in range(1000):
            FlextLdifExceptions.validation_error("test error")

        end_time = time.time()
        execution_time = end_time - start_time

        assert execution_time < 0.5  # Should complete within 0.5 seconds

    def test_exceptions_memory_usage(self) -> None:
        """Test exceptions memory usage characteristics."""
        # Test that exceptions don't leak memory
        results = []

        for _ in range(100):
            result = FlextLdifExceptions.validation_error("test error")
            results.append(result)

        # Verify all results are valid
        assert len(results) == 100
        for result in results:
            assert isinstance(result, FlextResult)
            assert result.is_failure

    def test_exceptions_edge_cases(self) -> None:
        """Test exceptions with edge cases."""
        # Test with None values
        result = FlextLdifExceptions.validation_error(None)  # type: ignore[arg-type]
        assert result.is_failure

        # Test with empty string values
        result = FlextLdifExceptions.validation_error("")
        assert result.is_failure
        # The error message might be processed by the underlying FlextResult
        assert result.error is not None

    def test_exceptions_concurrent_access(self) -> None:
        """Test exceptions concurrent access."""
        results = []

        def worker() -> None:
            result = FlextLdifExceptions.validation_error("test error")
            results.append(result)

        # Start multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify all operations succeeded
        assert len(results) == 5
        for result in results:
            assert isinstance(result, FlextResult)
            assert result.is_failure
