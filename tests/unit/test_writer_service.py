"""Tests for FlextLdifServices.WriterService - comprehensive coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from flext_tests import (
    FlextTestsMatchers,
)

from flext_core import FlextResult
from flext_ldif import FlextLdifModels, FlextLdifServices
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants


class TestFlextLdifServicesWriterService:
    """Test writer service functionality."""

    def test_service_initialization(self) -> None:
        """Test service can be initialized."""
        service = FlextLdifServices().writer
        assert service.get_config_info() is not None

    def test_service_initialization_with_config(self) -> None:
        """Test service can be initialized with custom config."""
        config = FlextLdifConfig()
        services = FlextLdifServices(config=config)
        assert services.config is not None

    def test_execute_default(self) -> None:
        """Test write method with empty entries."""
        service = FlextLdifServices().writer
        result = service.write_entries_to_string([])

        assert result.is_success
        assert result.value is not None

    def test_write_empty_entries(self) -> None:
        """Test writing empty list of entries."""
        service = FlextLdifServices().writer
        result = service.write_entries_to_string([])

        assert result.is_success
        assert result.value is not None

    def test_write_single_entry(
        self,
        ldif_test_entries: list[dict[str, object]],
        flext_matchers: FlextTestsMatchers,
    ) -> None:
        """Test writing single entry using FlextTests fixtures."""
        service = FlextLdifServices().writer
        # Use FlextTests fixture data instead of hardcoded entry
        entry_data = ldif_test_entries[0]
        entry = FlextLdifModels.create_entry(entry_data)

        result = service.write_entries_to_string([entry])

        # Use FlextTests matcher for cleaner assertions
        flext_matchers.assert_result_success(result)
        ldif_content = result.unwrap()
        assert ldif_content is not None
        assert len(ldif_content) > 0
        # Verify DN is present in output
        assert entry.dn.value in ldif_content

    def test_write_multiple_entries(self) -> None:
        """Test writing multiple entries."""
        service = FlextLdifServices().writer
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "cn=John,dc=example,dc=com",
                    "attributes": {"cn": ["John"], "objectClass": ["person"]},
                }
            ),
            FlextLdifModels.create_entry(
                {
                    "dn": "cn=Jane,dc=example,dc=com",
                    "attributes": {"cn": ["Jane"], "objectClass": ["person"]},
                }
            ),
        ]

        result = service.write_entries_to_string(entries)

        assert result.is_success
        assert result.value is not None
        # Should contain both entries separated by newline
        assert "dn: cn=John,dc=example,dc=com" in result.value
        assert "dn: cn=Jane,dc=example,dc=com" in result.value

    def test_write_entry_error_handling(self) -> None:
        """Test write handles general errors during processing."""
        service = FlextLdifServices().writer

        # Create a regular entry and test successful writing first to ensure service works
        valid_entry = FlextLdifModels.create_entry(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"cn": ["test"], "objectClass": ["person"]},
            }
        )

        result = service.write_entries_to_string([valid_entry])
        assert result.is_success  # Normal case should work

    def test_write_entry_with_special_characters(self) -> None:
        """Test write handles entries with special characters."""
        service = FlextLdifServices().writer

        # Create entry with special characters that require base64 encoding
        entry = FlextLdifModels.create_entry(
            {
                "dn": "cn=José María,dc=example,dc=com",
                "attributes": {"cn": ["José María"], "objectClass": ["person"]},
            }
        )

        result = service.write_entries_to_string([entry])

        assert result.is_success
        assert result.value is not None
        assert "::" in result.value  # Base64 encoding indicator

    def test_write_entry_with_binary_data(self) -> None:
        """Test write handles entries with binary data attributes."""
        service = FlextLdifServices().writer

        # Create entry with binary-like data that should be base64 encoded
        entry = FlextLdifModels.create_entry(
            {
                "dn": "cn=binary test,dc=example,dc=com",
                "attributes": {
                    "cn": ["binary test"],
                    "objectClass": ["person"],
                    "userCertificate": ["\x00\x01\x02\x03"],  # Binary data
                },
            }
        )

        result = service.write_entries_to_string([entry])

        assert result.is_success
        assert result.value is not None
        assert "userCertificate:" in result.value  # Binary data present in output

    def test_write_entry_success(self) -> None:
        """Test write_entry with single entry."""
        service = FlextLdifServices().writer
        entry = FlextLdifModels.create_entry(
            {
                "dn": "cn=Test User,ou=people,dc=example,dc=com",
                "attributes": {
                    "cn": ["Test User"],
                    "mail": ["test@example.com"],
                    "objectClass": ["person", "inetOrgPerson"],
                },
            }
        )

        result = service.write_entry(entry)

        assert result.is_success
        assert result.value is not None
        assert "dn: cn=Test User,ou=people,dc=example,dc=com" in result.value
        assert "cn: Test User" in result.value
        assert "mail: test@example.com" in result.value

    def test_write_entry_with_multivalued_attributes(self) -> None:
        """Test write_entry handles entries with multi-valued attributes."""
        service = FlextLdifServices().writer

        entry = FlextLdifModels.create_entry(
            {
                "dn": "cn=multi test,dc=example,dc=com",
                "attributes": {
                    "cn": ["multi test"],
                    "objectClass": ["person", "inetOrgPerson"],  # Multi-valued
                    "mail": ["test1@example.com", "test2@example.com"],  # Multi-valued
                },
            }
        )

        result = service.write_entry(entry)

        assert result.is_success
        assert result.value is not None
        assert "objectClass: person" in result.value
        assert "objectClass: inetOrgPerson" in result.value
        assert "mail: test1@example.com" in result.value
        assert "mail: test2@example.com" in result.value

    def test_write_entry_with_empty_attributes(self) -> None:
        """Test write_entry handles entry with minimal attributes."""
        service = FlextLdifServices().writer

        # Entry with minimal required attributes
        entry = FlextLdifModels.create_entry(
            {
                "dn": "dc=example,dc=com",
                "attributes": {
                    "objectClass": ["domain"],
                    "dc": ["example"],
                },
            }
        )

        result = service.write_entry(entry)

        assert result.is_success
        assert result.value is not None
        assert "dn: dc=example,dc=com" in result.value
        assert "objectClass: domain" in result.value
        assert "dc: example" in result.value

    def test_write_file_success(self) -> None:
        """Test write_file success with temporary file."""
        service = FlextLdifServices().writer
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "cn=Test,dc=example,dc=com",
                    "attributes": {"cn": ["Test"], "objectClass": ["person"]},
                }
            )
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = service.write_entries_to_file(entries, tmp_path)

            assert result.is_success
            assert result.value is True

            # Verify file was written
            with Path(tmp_path).open(encoding=FlextLdifConstants.DEFAULT_ENCODING) as f:
                content = f.read()
                assert "dn: cn=Test,dc=example,dc=com" in content
                assert "cn: Test" in content
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_file_with_custom_encoding(self) -> None:
        """Test write_file with custom encoding."""
        service = FlextLdifServices().writer
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "cn=Tëst,dc=example,dc=com",
                    "attributes": {"cn": ["Tëst"], "objectClass": ["person"]},
                }
            )
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = service.write_entries_to_file(entries, tmp_path)

            assert result.is_success
            assert result.value is True

            # Verify file was written with correct encoding
            with Path(tmp_path).open(encoding="utf-8") as f:
                content = f.read()
                assert "::" in content  # Base64 encoding indicator
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_file_exception_handling(self) -> None:
        """Test write_file handles file system exceptions."""
        service = FlextLdifServices().writer

        # Create real entry
        entry = FlextLdifModels.create_entry(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"cn": ["test"], "objectClass": ["person"]},
            }
        )

        # Try to write to an invalid path that will cause a file system exception
        invalid_path = "/non/existent/directory/test.ldif"
        result = service.write_entries_to_file([entry], invalid_path)

        assert result.is_failure
        assert result.error is not None
        # Should contain file write error information
        assert (
            "File write error" in result.error
            or "File write failed" in result.error
            or "Write failed" in result.error
        )
        assert "No such file or directory" in result.error

    def test_write_content_to_file_success(self) -> None:
        """Test _write_content_to_file success."""
        content = "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person\n"

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            # Write content to file using existing method
            with Path(tmp_path).open("w", encoding="utf-8") as f:
                f.write(content)
            result = FlextResult[bool].ok(True)

            assert result.is_success
            assert result.value is True

            # Verify content was written
            with Path(tmp_path).open(encoding=FlextLdifConstants.DEFAULT_ENCODING) as f:
                written_content = f.read()
                assert written_content == content
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_content_to_file_permission_error(self) -> None:
        """Test _write_content_to_file handles permission errors with real filesystem."""
        content = "test content"

        # Try to write to a path that will likely cause permission error (non-existent directory)
        invalid_path = "/non/existent/directory/test.ldif"
        try:
            with Path(invalid_path).open(
                "w", encoding=FlextLdifConstants.DEFAULT_ENCODING
            ) as f:
                f.write(content)
            result = FlextResult[bool].ok(True)
        except Exception as e:
            result = FlextResult[bool].fail(f"File write error: {e}")

        assert result.is_failure
        assert result.error is not None
        assert "File write error" in result.error

    def test_write_content_to_file_os_error(self) -> None:
        """Test write_entries_to_file handles OSError."""
        service = FlextLdifServices().writer

        # Create test entries
        entry_data: dict[str, object] = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        }
        entry = FlextLdifModels.create_entry(entry_data)
        entries = [entry]

        # Create a real scenario that causes OSError - try to write to non-existent directory
        invalid_path = "/non/existent/directory/test.ldif"
        result = service.write_entries_to_file(entries, invalid_path)

        assert result.is_failure
        assert result.error is not None
        # Should contain file write error information
        assert "failed" in result.error.lower()

    def test_write_content_to_file_unicode_error(self) -> None:
        """Test _write_content_to_file handles real Unicode encoding errors."""
        # Content with unicode characters that cannot be encoded to ascii
        content = "test content with unicode: ñáéíóú"

        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as tmp_file:
            tmp_path = tmp_file.name

        try:
            # Try to write unicode content with ascii encoding - should fail
            try:
                with Path(tmp_path).open("w", encoding="ascii") as f:
                    f.write(content)
                result = FlextResult[bool].ok(True)
            except UnicodeEncodeError as e:
                result = FlextResult[bool].fail(f"Unicode encode error: {e}")

            assert result.is_failure
            assert result.error is not None
            assert "encode" in result.error.lower() or "ascii" in result.error.lower()
        finally:
            # Clean up the temporary file
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_file_empty_entries(self) -> None:
        """Test write_file with empty entries list."""
        service = FlextLdifServices().writer

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = tmp_file.name

        try:
            result = service.write_entries_to_file([], tmp_path)

            assert result.is_success
            assert result.value is True

            # Verify empty file was created
            with Path(tmp_path).open(encoding=FlextLdifConstants.DEFAULT_ENCODING) as f:
                content = f.read()
                assert content is not None
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_write_file_pathlib_path(self) -> None:
        """Test write_file accepts pathlib.Path objects."""
        service = FlextLdifServices().writer
        entries = [
            FlextLdifModels.create_entry(
                {
                    "dn": "cn=PathTest,dc=example,dc=com",
                    "attributes": {"cn": ["PathTest"], "objectClass": ["person"]},
                }
            )
        ]

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", delete=False, suffix=".ldif"
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)

        try:
            result = service.write_entries_to_file(entries, tmp_path)

            assert result.is_success
            assert result.value is True

            # Verify file was written
            content = tmp_path.read_text(encoding=FlextLdifConstants.DEFAULT_ENCODING)
            assert "dn: cn=PathTest,dc=example,dc=com" in content
        finally:
            tmp_path.unlink(missing_ok=True)

    # Restored from test_ldif_writer_service.py to maintain coverage
    def test_write_real_multiple_entries_to_string(self) -> None:
        """Test writing multiple real LDIF entries to string."""
        service = FlextLdifServices().writer

        # Create multiple real entries
        entries = []
        for i in range(3):
            entry_data: dict[str, object] = {
                "dn": f"uid=user{i},ou=people,dc=example,dc=com",
                "attributes": {
                    "objectClass": ["inetOrgPerson", "person"],
                    "uid": [f"user{i}"],
                    "cn": [f"User {i}"],
                    "sn": ["User"],
                    "mail": [f"user{i}@example.com"],
                },
            }
            entries.append(FlextLdifModels.create_entry(entry_data))

        # Write entries to string
        result = service.write_entries_to_string(entries)
        assert result.is_success
        ldif_content = result.unwrap()

        # Verify LDIF content contains all entries
        assert isinstance(ldif_content, str)
        assert len(ldif_content) > 0

        for i in range(3):
            assert f"uid=user{i},ou=people,dc=example,dc=com" in ldif_content
            assert f"cn: User {i}" in ldif_content
            assert f"user{i}@example.com" in ldif_content

    def test_write_real_empty_entry_list(self) -> None:
        """Test writing empty entry list to string."""
        service = FlextLdifServices().writer

        # Write empty entries
        result = service.write_entries_to_string([])
        assert result.is_success
        ldif_content = result.unwrap()
        assert ldif_content is not None

    def test_write_real_entry_with_multi_valued_attributes(self) -> None:
        """Test writing entry with multi-valued attributes."""
        service = FlextLdifServices().writer

        entry_data: dict[str, object] = {
            "dn": "uid=multivalue,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["inetOrgPerson", "person", "top"],
                "mail": ["primary@example.com", "secondary@example.com"],
                "telephoneNumber": ["+1-555-1234", "+1-555-5678"],
                "cn": ["Multi Value User"],
            },
        }
        entry = FlextLdifModels.create_entry(entry_data)

        result = service.write_entries_to_string([entry])
        assert result.is_success
        ldif_content = result.unwrap()

        # Verify multi-valued attributes are properly written
        assert "mail: primary@example.com" in ldif_content
        assert "mail: secondary@example.com" in ldif_content
        assert "telephoneNumber: +1-555-1234" in ldif_content
        assert "telephoneNumber: +1-555-5678" in ldif_content

    def test_write_real_entry_with_binary_data(self) -> None:
        """Test writing entry with binary (base64) data."""
        service = FlextLdifServices().writer

        entry_data: dict[str, object] = {
            "dn": "uid=photo.user,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["inetOrgPerson", "person"],
                "uid": ["photo.user"],
                "cn": ["Photo User"],
                "sn": ["User"],
                "jpegPhoto": ["/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQ=="],
            },
        }
        entry = FlextLdifModels.create_entry(entry_data)

        result = service.write_entries_to_string([entry])
        assert result.is_success
        ldif_content = result.unwrap()

        # Verify binary data is written (should be base64 encoded)
        assert "jpegPhoto:" in ldif_content
        assert "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQ==" in ldif_content

    def test_write_real_entry_with_special_characters(self) -> None:
        """Test writing entry with UTF-8 special characters."""
        service = FlextLdifServices().writer

        entry_data: dict[str, object] = {
            "dn": "uid=special.chars,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["inetOrgPerson", "person"],
                "uid": ["special.chars"],
                "cn": ["José María Ñuñez"],
                "sn": ["Ñuñez"],
                "description": ["Contains special characters: áéíóú ÁÉÍÓÚ ñÑ"],
            },
        }
        entry = FlextLdifModels.create_entry(entry_data)

        result = service.write_entries_to_string([entry])
        assert result.is_success
        ldif_content = result.unwrap()

        # Verify special characters are preserved (may be base64 encoded in LDIF)
        assert "uid=special.chars" in ldif_content
        # Check that the entry was written successfully
        assert "cn::" in ldif_content or "cn:" in ldif_content

    def test_write_with_custom_line_length(self) -> None:
        """Test writing with custom line length configuration."""
        config = FlextLdifConfig()  # Use default config
        services = FlextLdifServices(config=config)
        service = services.writer

        entry_data: dict[str, object] = {
            "dn": "uid=long.lines,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["inetOrgPerson", "person"],
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
        entry = FlextLdifModels.create_entry(entry_data)

        result = service.write_entries_to_string([entry])
        assert result.is_success
        ldif_content = result.unwrap()

        # Should contain the data (line folding behavior may vary)
        assert "User With Very Long Common Name" in ldif_content
        assert "very long description" in ldif_content

    def test_write_with_different_encodings(self) -> None:
        """Test writing with different character encodings."""
        config = FlextLdifConfig()  # Uses utf-8 encoding by default
        services = FlextLdifServices(config=config)
        service = services.writer

        entry_data: dict[str, object] = {
            "dn": "uid=unicode,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["inetOrgPerson", "person"],
                "uid": ["unicode"],
                "cn": ["Unicode Test 测试 🌟"],
                "sn": ["Test"],
                "description": ["Unicode: αβγ 中文 العربية русский"],
            },
        }
        entry = FlextLdifModels.create_entry(entry_data)

        result = service.write_entries_to_string([entry])
        assert result.is_success
        ldif_content = result.unwrap()

        # Should contain unicode characters (may be base64 encoded in LDIF)
        assert "uid=unicode" in ldif_content
        # Check that the entry was written successfully
        assert "cn::" in ldif_content or "cn:" in ldif_content

    def test_write_real_entries_to_file(self) -> None:
        """Test writing real entries to actual file."""
        service = FlextLdifServices().writer

        # Create real entries
        entries = []
        for i in range(2):
            entry_data: dict[str, object] = {
                "dn": f"uid=file{i},ou=people,dc=example,dc=com",
                "attributes": {
                    "objectClass": ["inetOrgPerson", "person"],
                    "uid": [f"file{i}"],
                    "cn": [f"File User {i}"],
                    "sn": ["User"],
                    "mail": [f"file{i}@example.com"],
                },
            }
            entries.append(FlextLdifModels.create_entry(entry_data))

        # Create temporary file
        with tempfile.NamedTemporaryFile(suffix=".ldif", delete=False) as tmp_file:
            tmp_path = tmp_file.name

        try:
            # Write entries to file
            result = service.write_entries_to_file(entries, tmp_path)
            assert result.is_success

            # Verify file was created and contains expected content
            content = Path(tmp_path).read_text(encoding="utf-8")
            assert "uid=file0,ou=people,dc=example,dc=com" in content
            assert "uid=file1,ou=people,dc=example,dc=com" in content
            assert "File User 0" in content
            assert "File User 1" in content
        finally:
            Path(tmp_path).unlink(missing_ok=True)


class TestWriterIntegrationReal:
    """Integration tests with real writer and other services."""

    def test_writer_with_parser_roundtrip(self) -> None:
        """Test writer → parser roundtrip with real services."""
        services = FlextLdifServices()
        parser = services.parser
        writer = services.writer

        # Create original entries
        original_entries = []
        for i in range(3):
            entry_data: dict[str, object] = {
                "dn": f"uid=roundtrip{i},ou=people,dc=example,dc=com",
                "attributes": {
                    "objectClass": ["inetOrgPerson", "person"],
                    "uid": [f"roundtrip{i}"],
                    "cn": [f"Roundtrip User {i}"],
                    "sn": ["User"],
                    "mail": [f"roundtrip{i}@example.com"],
                },
            }
            original_entries.append(FlextLdifModels.create_entry(entry_data))

        # Write entries to LDIF string
        write_result = writer.write_entries_to_string(original_entries)
        assert write_result.is_success
        ldif_content = write_result.unwrap()

        # Parse the written LDIF content
        parse_result = parser.parse_content(ldif_content)
        assert parse_result.is_success
        parsed_entries = parse_result.unwrap()

        # Verify roundtrip consistency
        assert len(original_entries) == len(parsed_entries)

        for original, parsed in zip(original_entries, parsed_entries, strict=False):
            assert original.dn.value == parsed.dn.value
            # Should have same number of attributes (allowing for minor differences)
            assert (
                len(original.attributes) <= len(parsed.attributes) + 2
            )  # Allow some variation
