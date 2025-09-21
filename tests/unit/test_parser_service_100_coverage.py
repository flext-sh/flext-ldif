"""Complete tests for FlextLdifParserService - 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from flext_ldif.format_handlers import FlextLdifFormatHandler


class FormatHandlerError(Exception):
    """Custom exception for format handler errors in tests."""


class TestFlextLdifParserServiceComplete:
    """Complete tests for FlextLdifParserService to achieve 100% coverage."""

    def test_parser_service_initialization_default(self) -> None:
        """Test parser service initialization with default format handler."""
        service = FlextLdifParserService()
        assert service is not None
        assert service._format_handler is not None

    def test_parser_service_initialization_custom(self) -> None:
        """Test parser service initialization with custom format handler."""
        custom_handler = FlextLdifFormatHandler()
        service = FlextLdifParserService(format_handler=custom_handler)
        assert service is not None
        assert service._format_handler is custom_handler

    def test_get_config_info(self) -> None:
        """Test get_config_info method."""
        service = FlextLdifParserService()

        config_info = service.get_config_info()
        assert isinstance(config_info, dict)
        assert config_info["service"] == "FlextLdifParserService"
        assert "config" in config_info
        assert isinstance(config_info["config"], dict)
        assert config_info["config"]["service_type"] == "parser"
        assert config_info["config"]["status"] == "ready"
        assert "capabilities" in config_info["config"]

    def test_get_service_info(self) -> None:
        """Test get_service_info method."""
        service = FlextLdifParserService()

        service_info = service.get_service_info()
        assert isinstance(service_info, dict)
        assert service_info["service_name"] == "FlextLdifParserService"
        assert service_info["service_type"] == "parser"
        assert service_info["status"] == "ready"
        assert "capabilities" in service_info

    def test_parse_ldif_file_success(self) -> None:
        """Test parse_ldif_file with successful parsing."""
        service = FlextLdifParserService()

        # Create temporary LDIF file using secure tempfile
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as temp_f:
            ldif_content = """dn: uid=john,ou=people,dc=example,dc=com
objectClass: person
cn: John

dn: uid=jane,ou=people,dc=example,dc=com
objectClass: person
cn: Jane
"""
            temp_f.write(ldif_content)
            temp_file = Path(temp_f.name)

        try:
            result = service.parse_ldif_file(temp_file)
            assert result.is_success is True
            assert isinstance(result.value, list)
        finally:
            # Clean up
            if temp_file.exists():
                temp_file.unlink()

    def test_parse_ldif_file_exception(self) -> None:
        """Test parse_ldif_file when file reading raises exception."""
        service = FlextLdifParserService()

        # Try to parse non-existent file
        result = service.parse_ldif_file("/nonexistent/file.ldif")
        assert result.is_success is False
        assert result.error is not None and (
            "File read failed" in result.error or "File not found" in result.error
        )

    def test_parse_content_success(self) -> None:
        """Test parse_content with successful parsing."""
        service = FlextLdifParserService()

        ldif_content = """dn: uid=john,ou=people,dc=example,dc=com
objectClass: person
cn: John
"""
        result = service.parse_content(ldif_content)
        assert result.is_success is True
        assert isinstance(result.value, list)

    def test_parse_content_empty(self) -> None:
        """Test parse_content with empty content."""
        service = FlextLdifParserService()

        result = service.parse_content("")
        assert result.is_success is True
        assert result.value == []

        result = service.parse_content("   ")
        assert result.is_success is True
        assert result.value == []

    def test_parse_content_exception(self) -> None:
        """Test parse_content with malformed content that raises exception."""
        service = FlextLdifParserService()

        # Create content that will trigger an exception in the format handler
        malformed_content = "dn: test\ninvalid_line_without_colon"

        result = service.parse_content(malformed_content)

        assert result.is_failure
        assert result.error is not None and "LDIF parse failed" in result.error

    def test_validate_ldif_syntax_success(self) -> None:
        """Test validate_ldif_syntax with valid LDIF."""
        service = FlextLdifParserService()

        ldif_content = """dn: uid=john,ou=people,dc=example,dc=com
objectClass: person
cn: John
"""
        result = service.validate_ldif_syntax(ldif_content)
        assert result.is_success is True
        assert result.value is True

    def test_validate_ldif_syntax_empty(self) -> None:
        """Test validate_ldif_syntax with empty content."""
        service = FlextLdifParserService()

        result = service.validate_ldif_syntax("")
        assert result.is_success is False
        assert result.error is not None and "Empty LDIF content" in result.error

        result = service.validate_ldif_syntax("   ")
        assert result.is_success is False
        assert result.error is not None and "Empty LDIF content" in result.error

    def test_validate_ldif_syntax_invalid_start(self) -> None:
        """Test validate_ldif_syntax with invalid start."""
        service = FlextLdifParserService()

        ldif_content = """objectClass: person
cn: John
dn: uid=john,ou=people,dc=example,dc=com
"""
        result = service.validate_ldif_syntax(ldif_content)
        assert result.is_success is False
        assert result.error is not None and "LDIF must start with dn:" in result.error

    def test_validate_ldif_syntax_whitespace_only_lines(self) -> None:
        """Test validate_ldif_syntax with whitespace-only lines before dn."""
        service = FlextLdifParserService()

        ldif_content = """

dn: uid=john,ou=people,dc=example,dc=com
objectClass: person
cn: John
"""
        result = service.validate_ldif_syntax(ldif_content)
        assert result.is_success is True
        assert result.value is True

    def test_parse_entry_block_success(self) -> None:
        """Test _parse_entry_block with successful parsing."""
        service = FlextLdifParserService()

        block = """dn: uid=john,ou=people,dc=example,dc=com
objectClass: person
cn: John
"""
        result = service._parse_entry_block(block)
        assert result.is_success is True
        assert isinstance(result.value, list)

    def test_parse_entry_block_empty(self) -> None:
        """Test _parse_entry_block with empty block."""
        service = FlextLdifParserService()

        result = service._parse_entry_block("")
        assert result.is_failure is True
        assert result.error is not None and "Empty entry block" in result.error

    def test_parse_content_exception_malformed(self) -> None:
        """Test parse_content with malformed content that raises exception."""
        service = FlextLdifParserService()

        # Create content that will trigger an exception in the format handler
        malformed_content = "dn: test\ninvalid_line_without_colon"

        result = service.parse_content(malformed_content)

        assert result.is_failure
        assert result.error is not None and "LDIF parse failed" in result.error

    def test_execute_method(self) -> None:
        """Test execute method."""
        service = FlextLdifParserService()

        result = service.execute()
        assert result.is_success is True
        assert result.value == []

    def test_health_check_healthy(self) -> None:
        """Test health_check under healthy conditions."""
        service = FlextLdifParserService()

        result = service.health_check()
        assert result.is_success

        health_data = result.unwrap()
        assert health_data["service"] == "FlextLdifParserService"
        assert health_data["status"] == "healthy"
        assert "checks" in health_data
        assert "circuit_breaker" in health_data["checks"]
        assert "format_handler" in health_data["checks"]
        assert "memory" in health_data["checks"]
        assert "performance" in health_data["checks"]

    def test_health_check_circuit_breaker_open(self) -> None:
        """Test health_check with circuit breaker open."""
        service = FlextLdifParserService()

        # Open the circuit breaker
        service._circuit_breaker_open = True
        service._consecutive_failures = 10

        result = service.health_check()
        assert result.is_success

        health_data = result.unwrap()
        assert health_data["status"] == "degraded"
        assert health_data["checks"]["circuit_breaker"]["status"] == "open"
        assert health_data["checks"]["circuit_breaker"]["consecutive_failures"] == 10

    def test_health_check_format_handler_error(self) -> None:
        """Test health_check with format handler error."""
        service = FlextLdifParserService()

        # Mock format handler to raise exception
        original_parse_ldif = service._format_handler.parse_ldif

        def broken_parse_ldif(*_args: object, **_kwargs: object) -> None:
            msg = "Format handler test failure"
            raise RuntimeError(msg)

        service._format_handler.parse_ldif = broken_parse_ldif

        try:
            result = service.health_check()
            assert result.is_success

            health_data = result.unwrap()
            assert health_data["status"] == "unhealthy"
            assert health_data["checks"]["format_handler"]["status"] == "error"
            assert (
                "Format handler test failure"
                in health_data["checks"]["format_handler"]["error"]
            )
        finally:
            service._format_handler.parse_ldif = original_parse_ldif

    def test_health_check_exception(self) -> None:
        """Test health_check with internal exception."""
        service = FlextLdifParserService()

        # Mock the _calculate_success_rate method to raise an exception
        original_method = service._calculate_success_rate

        def broken_method() -> None:
            msg = "Success rate calculation error"
            raise RuntimeError(msg)

        service._calculate_success_rate = broken_method

        try:
            result = service.health_check()
            assert result.is_failure
            assert "Health check error" in str(result.error)
        finally:
            # Restore original method
            service._calculate_success_rate = original_method

    def test_circuit_breaker_functionality(self) -> None:
        """Test circuit breaker check and recovery."""
        service = FlextLdifParserService()

        # Test when circuit breaker is closed
        result = service._check_circuit_breaker()
        assert result.is_success

        # Open circuit breaker
        service._circuit_breaker_open = True
        service._last_failure_time = time.time()

        # Should fail when open
        result = service._check_circuit_breaker()
        assert result.is_failure
        assert "Circuit breaker" in str(result.error)

        # Test timeout recovery (simulate time passage)
        service._last_failure_time = time.time() - service._circuit_breaker_timeout - 1
        result = service._check_circuit_breaker()
        # Should succeed and reset the circuit breaker
        assert result.is_success
        assert not service._circuit_breaker_open

    def test_record_success_and_failure(self) -> None:
        """Test success and failure recording functionality."""
        service = FlextLdifParserService()

        # Test recording success
        service._record_success()
        assert service._consecutive_failures == 0
        assert not service._circuit_breaker_open

        # Test recording failures
        for _ in range(service._max_consecutive_failures):
            service._record_failure("test failure")

        # Should open circuit breaker after max failures
        assert service._circuit_breaker_open
        assert service._consecutive_failures == service._max_consecutive_failures

    def test_calculate_success_rate(self) -> None:
        """Test success rate calculation."""
        service = FlextLdifParserService()

        # Test with no operations
        rate = service._calculate_success_rate()
        assert rate == 1.0

        # Test with some operations
        service._total_files_parsed = 100
        service._parse_failures = 10  # 90% success rate
        rate = service._calculate_success_rate()
        assert rate == 0.9

    def test_get_current_memory_usage(self) -> None:
        """Test memory usage calculation."""
        service = FlextLdifParserService()

        memory_usage = service._get_current_memory_usage()
        assert isinstance(memory_usage, int)
        assert memory_usage >= 0

    def test_performance_metrics(self) -> None:
        """Test get_performance_metrics method."""
        service = FlextLdifParserService()

        # Add some test data
        service._total_files_parsed = 5
        service._total_entries_parsed = 50
        service._total_bytes_processed = 1024
        service._parse_failures = 1

        metrics = service.get_performance_metrics()
        assert isinstance(metrics, dict)
        assert "uptime_seconds" in metrics
        assert metrics["total_files_parsed"] == 5
        assert metrics["total_entries_parsed"] == 50
        assert metrics["total_bytes_processed"] == 1024
        assert metrics["parse_failures"] == 1
        assert "performance" in metrics
        assert "memory" in metrics
        assert "circuit_breaker" in metrics

    def test_reset_performance_metrics(self) -> None:
        """Test reset_performance_metrics method."""
        service = FlextLdifParserService()

        # Set some data
        service._total_files_parsed = 10
        service._total_entries_parsed = 100
        service._parse_failures = 2

        # Reset metrics
        service.reset_performance_metrics()

        # Verify reset
        assert service._total_files_parsed == 0
        assert service._total_entries_parsed == 0
        assert service._parse_failures == 0
        assert service._consecutive_failures == 0

    def test_parse_ldif_file_with_circuit_breaker_open(self) -> None:
        """Test parse_ldif_file when circuit breaker is open."""
        service = FlextLdifParserService()

        # Open circuit breaker
        service._circuit_breaker_open = True
        service._last_failure_time = time.time()

        # Create a temporary file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as temp_file:
            temp_file.write("dn: cn=test,dc=example,dc=com\ncn: test\n")
            temp_path = Path(temp_file.name)

        try:
            result = service.parse_ldif_file(temp_path)
            assert result.is_failure
            assert "Circuit breaker" in str(result.error)
        finally:
            temp_path.unlink()  # Clean up

    def test_parse_content_with_circuit_breaker_recovery(self) -> None:
        """Test parse_content with circuit breaker recovery scenario."""
        service = FlextLdifParserService()

        # Set up circuit breaker timeout scenario
        service._circuit_breaker_open = True
        service._last_failure_time = time.time() - service._circuit_breaker_timeout - 1

        # This should trigger recovery and succeed
        content = "dn: cn=test,dc=example,dc=com\ncn: test\n"
        result = service.parse_content(content)

        # Should succeed and reset circuit breaker
        assert result.is_success
        assert not service._circuit_breaker_open
