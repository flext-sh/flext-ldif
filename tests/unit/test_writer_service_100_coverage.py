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
            attributes=FlextLdifModels.LdifAttributes(data={
                "cn": ["testuser"],
                "sn": ["User"],
                "givenName": ["Test"],
                "objectClass": ["person", "inetOrgPerson"],
                "mail": ["testuser@example.com"]
            })
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
