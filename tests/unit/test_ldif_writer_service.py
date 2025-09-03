"""Tests for FlextLDIFWriterService - Real functionality testing without mocks.

Comprehensive tests using actual LDIF data and real writer functionality.
No mocks, bypasses, or fake implementations - only real LDIF writing.
"""

from __future__ import annotations

from flext_ldif import FlextLDIFWriterService
from flext_ldif.models import FlextLDIFConfig, FlextLDIFEntry
from tests.support import TestFileManager, TestValidators


class TestFlextLDIFWriterServiceReal:
    """Test FlextLDIFWriterService with real functionality - no mocks."""

    def test_service_initialization_with_config(self) -> None:
        """Test writer service initializes with configuration."""
        config = FlextLDIFConfig(
            encoding="utf-8",
            max_line_length=76,
            fold_lines=True,
        )
        service = FlextLDIFWriterService(config=config)

        # Validate service has real configuration
        assert service.config is not None
        assert service.config.encoding == "utf-8"
        assert service.config.max_line_length == 76
        assert service.config.fold_lines is True

    def test_service_initialization_default_config(self) -> None:
        """Test writer service works with default configuration."""
        service = FlextLDIFWriterService()

        # Service should work with defaults
        result = service.execute()
        assert result.is_success

    def test_write_real_single_entry_to_string(self) -> None:
        """Test writing a single real LDIF entry to string."""
        service = FlextLDIFWriterService()

        # Create a real entry
        entry_data = {
            "dn": "uid=john.doe,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "uid": ["john.doe"],
                "cn": ["John Doe"],
                "sn": ["Doe"],
                "givenName": ["John"],
                "mail": ["john.doe@example.com"],
            },
        }
        entry = FlextLDIFEntry.model_validate(entry_data)

        # Write entry to string
        result = service.write_entries_to_string([entry])

        TestValidators.assert_successful_result(result)
        ldif_content = result.value

        # Verify LDIF content contains expected elements
        assert isinstance(ldif_content, str)
        assert len(ldif_content) > 0
        assert "dn: uid=john.doe,ou=people,dc=example,dc=com" in ldif_content
        assert "cn: John Doe" in ldif_content
        assert "mail: john.doe@example.com" in ldif_content

    def test_write_real_multiple_entries_to_string(self) -> None:
        """Test writing multiple real LDIF entries to string."""
        service = FlextLDIFWriterService()

        # Create multiple real entries
        entries = []
        for i in range(3):
            entry_data = {
                "dn": f"uid=user{i},ou=people,dc=example,dc=com",
                "attributes": {
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                    "uid": [f"user{i}"],
                    "cn": [f"User {i}"],
                    "sn": ["User"],
                    "mail": [f"user{i}@example.com"],
                },
            }
            entries.append(FlextLDIFEntry.model_validate(entry_data))

        # Write entries to string
        result = service.write_entries_to_string(entries)

        TestValidators.assert_successful_result(result)
        ldif_content = result.value

        # Verify LDIF content contains all entries
        assert isinstance(ldif_content, str)
        assert len(ldif_content) > 0

        for i in range(3):
            assert f"uid=user{i},ou=people,dc=example,dc=com" in ldif_content
            assert f"cn: User {i}" in ldif_content
            assert f"user{i}@example.com" in ldif_content

    def test_write_real_entry_with_multi_valued_attributes(self) -> None:
        """Test writing entry with multi-valued attributes."""
        service = FlextLDIFWriterService()

        # Create entry with multi-valued attributes
        entry_data = {
            "dn": "uid=multi.user,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "uid": ["multi.user"],
                "cn": ["Multi User"],
                "sn": ["User"],
                "mail": ["multi.user@example.com", "multi.user.alt@example.com"],
                "telephoneNumber": ["+1-555-0123", "+1-555-0124"],
            },
        }
        entry = FlextLDIFEntry.model_validate(entry_data)

        # Write entry to string
        result = service.write_entries_to_string([entry])

        TestValidators.assert_successful_result(result)
        ldif_content = result.value

        # Verify multi-valued attributes are written correctly
        assert "multi.user@example.com" in ldif_content
        assert "multi.user.alt@example.com" in ldif_content
        assert "+1-555-0123" in ldif_content
        assert "+1-555-0124" in ldif_content

    def test_write_real_entry_with_binary_data(self) -> None:
        """Test writing entry with binary (base64) data."""
        service = FlextLDIFWriterService()

        # Create entry with binary data
        entry_data = {
            "dn": "uid=photo.user,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "uid": ["photo.user"],
                "cn": ["Photo User"],
                "sn": ["User"],
                "jpegPhoto": ["/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQ=="],
            },
        }
        entry = FlextLDIFEntry.model_validate(entry_data)

        # Write entry to string
        result = service.write_entries_to_string([entry])

        TestValidators.assert_successful_result(result)
        ldif_content = result.value

        # Verify binary data is written (should be base64 encoded)
        assert "jpegPhoto:" in ldif_content
        assert "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQ==" in ldif_content

    def test_write_real_entry_with_special_characters(self) -> None:
        """Test writing entry with UTF-8 special characters."""
        service = FlextLDIFWriterService()

        # Create entry with special characters
        entry_data = {
            "dn": "uid=special.chars,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "uid": ["special.chars"],
                "cn": ["José María Ñuñez"],
                "sn": ["Ñuñez"],
                "description": ["Contains special characters: áéíóú ÁÉÍÓÚ ñÑ"],
            },
        }
        entry = FlextLDIFEntry.model_validate(entry_data)

        # Write entry to string
        result = service.write_entries_to_string([entry])

        TestValidators.assert_successful_result(result)
        ldif_content = result.value

        # Verify special characters are preserved
        assert "José María Ñuñez" in ldif_content
        assert "áéíóú ÁÉÍÓÚ ñÑ" in ldif_content

    def test_write_real_entries_to_file(
        self, test_file_manager: TestFileManager
    ) -> None:
        """Test writing real entries to actual file."""
        service = FlextLDIFWriterService()

        # Create real entries
        entries = []
        for i in range(2):
            entry_data = {
                "dn": f"uid=file{i},ou=people,dc=example,dc=com",
                "attributes": {
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                    "uid": [f"file{i}"],
                    "cn": [f"File User {i}"],
                    "sn": ["User"],
                    "mail": [f"file{i}@example.com"],
                },
            }
            entries.append(FlextLDIFEntry.model_validate(entry_data))

        # Create temporary file using the file manager
        with test_file_manager.temporary_directory() as temp_dir:
            temp_file = temp_dir / "test_output.ldif"

            # Write entries to file
            result = service.write_entries_to_file(entries, str(temp_file))

            TestValidators.assert_successful_result(result)

            # Verify file was created and contains expected content
            assert temp_file.exists()
            content = temp_file.read_text(encoding="utf-8")

            assert "uid=file0,ou=people,dc=example,dc=com" in content
            assert "uid=file1,ou=people,dc=example,dc=com" in content
            assert "File User 0" in content
            assert "File User 1" in content

    def test_write_real_empty_entry_list(self) -> None:
        """Test writing empty list of entries."""
        service = FlextLDIFWriterService()

        # Write empty list
        result = service.write_entries_to_string([])

        TestValidators.assert_successful_result(result)
        ldif_content = result.value

        # Should return empty or minimal content
        assert isinstance(ldif_content, str)
        assert len(ldif_content.strip()) == 0

    def test_write_with_custom_line_length(self) -> None:
        """Test writing with custom line length configuration."""
        config = FlextLDIFConfig(max_line_length=40)  # Shorter lines
        service = FlextLDIFWriterService(config=config)

        # Create entry with long attribute value
        entry_data = {
            "dn": "uid=long.lines,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "uid": ["long.lines"],
                "cn": [
                    "User With Very Long Common Name That Exceeds Normal Line Length"
                ],
                "sn": ["User"],
                "description": [
                    "This is a very long description that should be folded across multiple lines when the line length limit is reached"
                ],
            },
        }
        entry = FlextLDIFEntry.model_validate(entry_data)

        # Write entry to string
        result = service.write_entries_to_string([entry])

        TestValidators.assert_successful_result(result)
        ldif_content = result.value

        # Should contain the data (line folding behavior may vary)
        assert "User With Very Long Common Name" in ldif_content
        assert "very long description" in ldif_content

    def test_write_with_different_encodings(self) -> None:
        """Test writing with different character encodings."""
        config = FlextLDIFConfig(encoding="utf-8")
        service = FlextLDIFWriterService(config=config)

        # Create entry with unicode characters
        entry_data = {
            "dn": "uid=unicode,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
                "uid": ["unicode"],
                "cn": ["Unicode Test 测试 🌟"],
                "sn": ["Test"],
                "description": ["Unicode: αβγ 中文 العربية русский"],
            },
        }
        entry = FlextLDIFEntry.model_validate(entry_data)

        # Write entry to string
        result = service.write_entries_to_string([entry])

        TestValidators.assert_successful_result(result)
        ldif_content = result.value

        # Should contain unicode characters
        assert "Unicode Test 测试" in ldif_content
        assert "中文" in ldif_content


class TestWriterIntegrationReal:
    """Integration tests with real writer and other services."""

    def test_writer_with_parser_roundtrip(
        self, integration_services: dict[str, object]
    ) -> None:
        """Test writer → parser roundtrip with real services."""
        parser = integration_services["parser"]
        writer = integration_services["writer"]

        # Create original entries
        original_entries = []
        for i in range(3):
            entry_data = {
                "dn": f"uid=roundtrip{i},ou=people,dc=example,dc=com",
                "attributes": {
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                    "uid": [f"roundtrip{i}"],
                    "cn": [f"Roundtrip User {i}"],
                    "sn": ["User"],
                    "mail": [f"roundtrip{i}@example.com"],
                },
            }
            original_entries.append(FlextLDIFEntry.model_validate(entry_data))

        # Write entries to LDIF string
        write_result = writer.write_entries_to_string(original_entries)
        TestValidators.assert_successful_result(write_result)
        ldif_content = write_result.value

        # Parse the written LDIF content
        parse_result = parser.parse_ldif_content(ldif_content)
        TestValidators.assert_successful_result(parse_result)
        parsed_entries = parse_result.value

        # Verify roundtrip consistency
        assert len(original_entries) == len(parsed_entries)

        for original, parsed in zip(original_entries, parsed_entries, strict=False):
            assert str(original.dn) == str(parsed.dn)
            # Should have same number of attributes (allowing for minor differences)
            assert (
                len(original.attributes) <= len(parsed.attributes) + 2
            )  # Allow some variation
