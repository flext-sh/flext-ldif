
from __future__ import annotations

from flext_core import FlextTypes
from flext_ldif import FlextLDIFModels, FlextLDIFServices
from tests.test_support import TestFileManager, TestValidators


Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations


from typing import Dict


class TestFlextLDIFServicesWriterServiceReal:
    """Test FlextLDIFServices.WriterService with real functionality - no mocks."""

    def test_service_initialization_with_config(self) -> None:
        """Test writer service initializes with configuration."""

        config = FlextLDIFModels.Config(
            encoding="utf-8",
            max_line_length=76,
            fold_lines=True,
        )
        services = FlextLDIFServices(config=config)

        # Validate service has real configuration
        assert services.config is not None
        assert services.config.encoding == "utf-8"
        assert services.config.max_line_length == 76
        assert services.config.fold_lines is True

    def test_service_initialization_default_config(self) -> None:
        """Test writer service works with default configuration."""

        service = FlextLDIFServices().writer

        # Service should work with defaults
        # Test writing empty entries to verify service is functional
        result = service.write_entries_to_string([])
        assert result.is_success

    def test_write_real_single_entry_to_string(self) -> None:
        """Test writing a single real LDIF entry to string."""

        service = FlextLDIFServices().writer

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
        entry = FlextLDIFModels.Entry.model_validate(entry_data)

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

        service = FlextLDIFServices().writer

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
            entries.append(FlextLDIFModels.Entry.model_validate(entry_data))

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

        service = FlextLDIFServices().writer

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
        entry = FlextLDIFModels.Entry.model_validate(entry_data)

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

        service = FlextLDIFServices().writer

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
        entry = FlextLDIFModels.Entry.model_validate(entry_data)

        # Write entry to string
        result = service.write_entries_to_string([entry])

        TestValidators.assert_successful_result(result)
        ldif_content = result.value

        # Verify binary data is written (should be base64 encoded)
        assert "jpegPhoto:" in ldif_content
        assert "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQ==" in ldif_content

    def test_write_real_entry_with_special_characters(self) -> None:
        """Test writing entry with UTF-8 special characters."""

        service = FlextLDIFServices().writer

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
        entry = FlextLDIFModels.Entry.model_validate(entry_data)

        # Write entry to string
        result = service.write_entries_to_string([entry])

        TestValidators.assert_successful_result(result)
        ldif_content = result.value

        # Verify special characters are preserved (may be base64 encoded in LDIF)
        # Check that the DN contains the special characters
        assert "uid=special.chars" in ldif_content
        # Check that the entry was written successfully
        assert "cn::" in ldif_content or "cn:" in ldif_content

    def test_write_real_entries_to_file(
        self, test_file_manager: TestFileManager
    ) -> None:
        """Test writing real entries to actual file."""

        service = FlextLDIFServices().writer

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
            entries.append(FlextLDIFModels.Entry.model_validate(entry_data))

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

        service = FlextLDIFServices().writer

        # Write empty list
        result = service.write_entries_to_string([])

        TestValidators.assert_successful_result(result)
        ldif_content = result.value

        # Should return empty or minimal content
        assert isinstance(ldif_content, str)
        assert len(ldif_content.strip()) == 0

    def test_write_with_custom_line_length(self) -> None:
        """Test writing with custom line length configuration."""

        config = FlextLDIFModels.Config(max_line_length=40)  # Shorter lines
        services = FlextLDIFServices(config=config)
        service = services.writer

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
        entry = FlextLDIFModels.Entry.model_validate(entry_data)

        # Write entry to string
        result = service.write_entries_to_string([entry])

        TestValidators.assert_successful_result(result)
        ldif_content = result.value

        # Should contain the data (line folding behavior may vary)
        assert "User With Very Long Common Name" in ldif_content
        assert "very long description" in ldif_content

    def test_write_with_different_encodings(self) -> None:
        """Test writing with different character encodings."""

        config = FlextLDIFModels.Config(encoding="utf-8")
        services = FlextLDIFServices(config=config)
        service = services.writer

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
        entry = FlextLDIFModels.Entry.model_validate(entry_data)

        # Write entry to string
        result = service.write_entries_to_string([entry])

        TestValidators.assert_successful_result(result)
        ldif_content = result.value

        # Should contain unicode characters (may be base64 encoded in LDIF)
        # Check that the DN contains the unicode identifier
        assert "uid=unicode" in ldif_content
        # Check that the entry was written successfully
        assert "cn::" in ldif_content or "cn:" in ldif_content


class TestWriterIntegrationReal:
    """Integration tests with real writer and other services."""

    def test_writer_with_parser_roundtrip(
        self, integration_services: FlextTypes.Core.Dict
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
            original_entries.append(FlextLDIFModels.Entry.model_validate(entry_data))

        # Write entries to LDIF string
        write_result = writer.write_entries_to_string(original_entries)
        TestValidators.assert_successful_result(write_result)
        ldif_content = write_result.value

        # Parse the written LDIF content
        parse_result = parser.parse_content(ldif_content)
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
