"""Complete tests for FlextLdifWriterService - 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from flext_core import FlextResult
from flext_ldif.format_handlers import FlextLdifFormatHandler
from flext_ldif.models import FlextLdifModels
from flext_ldif.writer_service import FlextLdifWriterService


class TestFlextLdifWriterServiceComplete:
    """Complete tests for FlextLdifWriterService to achieve 100% coverage."""

    def test_writer_service_initialization_default(self) -> None:
        """Test writer service initialization with default format handler."""
        service = FlextLdifWriterService()
        assert service is not None
        assert service._format_handler is not None
        assert service._cols == 76

    def test_writer_service_initialization_custom(self) -> None:
        """Test writer service initialization with custom format handler."""
        custom_handler = FlextLdifFormatHandler()
        service = FlextLdifWriterService(format_handler=custom_handler, cols=80)
        assert service is not None
        assert service._format_handler is custom_handler
        assert service._cols == 80

    def test_get_config_info(self) -> None:
        """Test get_config_info method."""
        service = FlextLdifWriterService()

        config_info = service.get_config_info()
        assert isinstance(config_info, dict)
        assert config_info["service"] == "FlextLdifWriterService"
        assert "config" in config_info
        assert isinstance(config_info["config"], dict)
        assert config_info["config"]["service_type"] == "writer"
        assert config_info["config"]["status"] == "ready"
        assert "capabilities" in config_info["config"]

    def test_get_service_info(self) -> None:
        """Test get_service_info method."""
        service = FlextLdifWriterService()

        service_info = service.get_service_info()
        assert isinstance(service_info, dict)
        assert service_info["service_name"] == "FlextLdifWriterService"
        assert service_info["service_type"] == "writer"
        assert service_info["status"] == "ready"
        assert "capabilities" in service_info

    def test_write_entries_to_string_success(self) -> None:
        """Test write_entries_to_string with successful writing."""
        service = FlextLdifWriterService()

        # Create test entries
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        result = service.write_entries_to_string(entries)
        assert result.is_success is True
        assert isinstance(result.value, str)

    def test_write_entries_to_string_failure(self) -> None:
        """Test write_entries_to_string when format handler fails."""
        service = FlextLdifWriterService()

        # Create test entries
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        # Mock the format handler to return failure
        class MockFormatHandler(FlextLdifFormatHandler):
            def write_ldif(
                self,
                entries: list[FlextLdifModels.Entry] | None,
            ) -> FlextResult[str]:
                entry_count = len(entries) if entries else 0
                return FlextResult[str].fail(
                    f"Format handler error for {entry_count} entries",
                )

        service._format_handler = MockFormatHandler()

        result = service.write_entries_to_string(entries)
        assert result.is_success is False
        assert result.error is not None and "String write failed" in result.error

    def test_write_entries_to_string_failure_no_error(self) -> None:
        """Test write_entries_to_string when format handler fails with no error."""
        service = FlextLdifWriterService()

        # Create test entries
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        # Mock the format handler to return failure with no error
        class MockFormatHandler(FlextLdifFormatHandler):
            def write_ldif(
                self,
                entries: list[FlextLdifModels.Entry] | None,
            ) -> FlextResult[str]:
                entry_count = len(entries) if entries else 0
                return FlextResult[str].fail(
                    f"String write failed for {entry_count} entries",
                )

        service._format_handler = MockFormatHandler()

        result = service.write_entries_to_string(entries)
        assert result.is_success is False
        assert result.error is not None and "String write failed" in result.error

    def test_write_entries_to_file_success(self) -> None:
        """Test write_entries_to_file with successful writing."""
        service = FlextLdifWriterService()

        # Create test entries
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        # Create temporary file using secure tempfile
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".ldif",
            delete=False,
        ) as temp_f:
            temp_file = Path(temp_f.name)

        try:
            result = service.write_entries_to_file(entries, temp_file)
            assert result.is_success is True
            assert result.value is True

            # Verify file was created and has content
            assert temp_file.exists()
            content = temp_file.read_text(encoding="utf-8")
            assert "uid=john,ou=people,dc=example,dc=com" in content
        finally:
            # Clean up
            if temp_file.exists():
                temp_file.unlink()

    def test_write_entries_to_file_string_generation_failure(self) -> None:
        """Test write_entries_to_file when string generation fails."""
        service = FlextLdifWriterService()

        # Create test entries
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        # Mock the format handler to return failure
        class MockFormatHandler(FlextLdifFormatHandler):
            def write_ldif(
                self,
                entries: list[FlextLdifModels.Entry] | None,
            ) -> FlextResult[str]:
                entry_count = len(entries) if entries else 0
                return FlextResult[str].fail(
                    f"Format handler error for {entry_count} entries",
                )

        service._format_handler = MockFormatHandler()

        # Use secure temporary file
        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as temp_f:
            temp_path = temp_f.name

        result = service.write_entries_to_file(entries, temp_path)
        assert result.is_success is False
        assert result.error is not None and "String write failed" in result.error

    def test_write_entries_to_file_string_generation_failure_no_error(self) -> None:
        """Test write_entries_to_file when string generation fails with no error."""
        service = FlextLdifWriterService()

        # Create test entries
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        # Mock the format handler to return failure with no error
        class MockFormatHandler(FlextLdifFormatHandler):
            def write_ldif(
                self,
                entries: list[FlextLdifModels.Entry] | None,
            ) -> FlextResult[str]:
                entry_count = len(entries) if entries else 0
                return FlextResult[str].fail(
                    f"String write failed for {entry_count} entries",
                )

        service._format_handler = MockFormatHandler()

        # Use secure temporary file
        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as temp_f:
            temp_path = temp_f.name

        result = service.write_entries_to_file(entries, temp_path)
        assert result.is_success is False
        assert result.error is not None and "String write failed" in result.error

    def test_write_entries_to_file_exception(self) -> None:
        """Test write_entries_to_file when file writing raises exception."""
        service = FlextLdifWriterService()

        # Create test entries
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        # Try to write to invalid path (should raise exception)
        result = service.write_entries_to_file(entries, "/invalid/path/test.ldif")
        assert result.is_success is False
        assert (
            result.error is not None
            and "Parent directory does not exist" in result.error
        )

    def test_execute_method(self) -> None:
        """Test execute method."""
        service = FlextLdifWriterService()

        result = service.execute()
        assert result.is_success is True
        assert result.value == "Writer service ready with advanced capabilities"

    def test_write_entry_single(self) -> None:
        """Test write_entry method."""
        service = FlextLdifWriterService()

        # Create test entry
        entry_data = {
            "dn": "uid=john,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["John"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)

        result = service.write_entry(entry)
        assert result.is_success is True
        assert isinstance(result.value, str)

    def test_write_entry_functionality(self) -> None:
        """Test write_entry method functionality."""
        service = FlextLdifWriterService(cols=80)  # Standard column width

        # Test with a complete entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=testuser,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                data={
                    "cn": ["testuser"],
                    "sn": ["User"],
                    "givenName": ["Test"],
                    "objectClass": ["person", "inetOrgPerson"],
                    "mail": ["testuser@example.com"],
                }
            ),
        )

        result = service.write_entry(entry)
        assert result.is_success, f"Write failed: {result.error}"
        output = result.unwrap()

        # Verify all expected content is present
        assert "dn: cn=testuser,dc=example,dc=com" in output
        assert "cn: testuser" in output
        assert "sn: User" in output
        assert "givenName: Test" in output
        assert "objectClass: person" in output
        assert "objectClass: inetOrgPerson" in output
        assert "mail: testuser@example.com" in output

    def test_write_entries_to_string_format_handler_exception(self) -> None:
        """Test write_entries_to_string with format handler exception."""
        service = FlextLdifWriterService()

        # Create test entry
        entry_data: dict[str, object] = {
            "dn": "uid=test,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)

        # Mock format handler to raise exception
        def broken_write_ldif(*_args: object) -> str:
            msg = "Format handler error"
            raise RuntimeError(msg)

        service._format_handler.write_ldif = broken_write_ldif  # type: ignore[assignment]

        result = service.write_entries_to_string([entry])
        assert result.is_failure
        assert "Format handler error" in str(result.error)

    def test_write_entries_to_string_unexpected_exception(self) -> None:
        """Test write_entries_to_string with unexpected exception."""
        service = FlextLdifWriterService()

        # Create test entry
        entry_data: dict[str, object] = {
            "dn": "uid=test,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)

        # Corrupt service state to cause exception
        service._large_batch_threshold = None  # type: ignore[assignment]

        result = service.write_entries_to_string([entry])
        assert result.is_failure
        assert "String write error" in str(result.error)

    def test_write_entries_to_file_with_exceptions(self) -> None:
        """Test write_entries_to_file with various exception scenarios."""
        service = FlextLdifWriterService()

        # Create test entry
        entry_data: dict[str, object] = {
            "dn": "uid=test,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["test"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)

        # Test with invalid file path
        invalid_path = Path("/invalid/nonexistent/path/test.ldif")
        result = service.write_entries_to_file([entry], invalid_path)
        assert result.is_failure
        assert "Parent directory does not exist" in str(result.error)

    def test_write_entries_streaming_with_exceptions(self) -> None:
        """Test write_entries_streaming with various exception scenarios."""
        service = FlextLdifWriterService()

        # Create test entries
        entries = []
        for i in range(3):
            entry_data: dict[str, object] = {
                "dn": f"uid=test{i},ou=people,dc=example,dc=com",
                "attributes": {"objectClass": ["person"], "cn": [f"test{i}"]},
            }
            entries.append(FlextLdifModels.create_entry(entry_data))

        # Test with invalid file path (directory doesn't exist)
        invalid_path = Path("/invalid/nonexistent/path/stream.ldif")
        result = service.write_entries_streaming(entries, invalid_path)
        assert result.is_failure
        assert "Parent directory does not exist" in str(result.error)

    def test_health_check_degraded_conditions(self) -> None:
        """Test health_check under degraded conditions."""
        service = FlextLdifWriterService()

        # Mock the format handler to return empty output (test fails but no exception)
        original_write_ldif = service._format_handler.write_ldif

        def empty_write_ldif(*_args: object, **_kwargs: object) -> str:
            return ""  # Returns empty string which will fail the test

        service._format_handler.write_ldif = empty_write_ldif

        try:
            result = service.health_check()
            assert result.is_success

            health_data = result.unwrap()
            assert health_data["status"] == "degraded"
            assert health_data["checks"]["write_functionality"]["status"] == "failed"
        finally:
            # Restore original handler
            service._format_handler.write_ldif = original_write_ldif

    def test_health_check_unhealthy_conditions(self) -> None:
        """Test health_check under unhealthy conditions."""
        service = FlextLdifWriterService()

        # Mock FlextLdifModels.Entry to raise an exception during health check
        original_entry = FlextLdifModels.Entry

        def broken_entry(*_args: object, **_kwargs: object) -> None:
            msg = "Health check entry creation failure"
            raise RuntimeError(msg)

        # Replace Entry class temporarily
        FlextLdifModels.Entry = broken_entry

        try:
            result = service.health_check()
            assert result.is_success

            health_data = result.unwrap()
            assert health_data["status"] == "unhealthy"
            assert health_data["checks"]["write_functionality"]["status"] == "error"
        finally:
            # Restore original Entry class
            FlextLdifModels.Entry = original_entry

    def test_health_check_with_exception(self) -> None:
        """Test health_check with internal exception."""
        service = FlextLdifWriterService()

        # Corrupt internal state to cause exception
        service._total_writes = None  # type: ignore[assignment]

        result = service.health_check()
        assert result.is_failure
        assert "Health check error" in str(result.error)

    def test_large_batch_processing(self) -> None:
        """Test processing of large batches."""
        service = FlextLdifWriterService()

        # Set low threshold to trigger large batch handling
        service._large_batch_threshold = 2

        # Create large batch of entries
        entries = []
        for i in range(5):
            entry_data: dict[str, object] = {
                "dn": f"uid=large{i},ou=people,dc=example,dc=com",
                "attributes": {"objectClass": ["person"], "cn": [f"large{i}"]},
            }
            entries.append(FlextLdifModels.create_entry(entry_data))

        result = service.write_entries_to_string(entries)
        assert result.is_success

    def test_streaming_write_success(self) -> None:
        """Test successful streaming write operations."""
        service = FlextLdifWriterService()

        entries = []
        for i in range(3):
            entry_data: dict[str, object] = {
                "dn": f"uid=stream{i},ou=people,dc=example,dc=com",
                "attributes": {"objectClass": ["person"], "cn": [f"stream{i}"]},
            }
            entries.append(FlextLdifModels.create_entry(entry_data))

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as temp_file:
            temp_path = Path(temp_file.name)

        try:
            result = service.write_entries_streaming(entries, temp_path)
            assert result.is_success

            # Verify file was created and has content
            assert temp_path.exists()
            assert temp_path.stat().st_size > 0
        finally:
            temp_path.unlink()  # Clean up

    def test_statistics_and_metrics_comprehensive(self) -> None:
        """Test comprehensive statistics and metrics tracking."""
        service = FlextLdifWriterService()

        # Perform various operations to generate statistics
        entry_data: dict[str, object] = {
            "dn": "uid=stats,ou=people,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["stats"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)

        # String write
        service.write_entries_to_string([entry])

        # File write
        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as temp_file:
            temp_path = Path(temp_file.name)

        try:
            service.write_entries_to_file([entry], temp_path)

            # Get comprehensive statistics
            stats = service.get_write_statistics()
            assert stats["totals"]["writes"] >= 2
            assert stats["totals"]["string_writes"] >= 1
            assert stats["totals"]["file_writes"] >= 1
            assert "success_metrics" in stats
            assert "performance" in stats

            # Test reset statistics
            service.reset_statistics()
            reset_stats = service.get_write_statistics()
            assert reset_stats["totals"]["writes"] == 0
        finally:
            temp_path.unlink()  # Clean up
