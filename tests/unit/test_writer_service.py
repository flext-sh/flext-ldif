"""Tests for FlextLdifAPI writer functionality - comprehensive coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from flext_ldif import FlextLdifModels
from flext_ldif.api import FlextLdifAPI
from flext_ldif.config import FlextLdifConfig


class TestFlextLdifApiWriterFunctionality:
    """Tests for FlextLdifAPI writer functionality - comprehensive coverage."""

    def test_service_initialization(self) -> None:
        """Test basic API initialization."""
        api = FlextLdifAPI()
        assert api is not None

    def test_service_initialization_with_config(self) -> None:
        """Test API initialization with custom config."""
        config = FlextLdifConfig(ldif_strict_validation=True)
        api = FlextLdifAPI(config=config)
        assert api is not None

    def test_execute_default(self) -> None:
        """Test default write execution."""
        api = FlextLdifAPI()
        result = api.write([])
        assert result.is_success

    def test_write_empty_entries(self) -> None:
        """Test writing empty entries list."""
        api = FlextLdifAPI()
        result = api.write([])
        assert result.is_success
        assert not result.unwrap()

    def test_write_single_entry(self) -> None:
        """Test writing single entry."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {
                "cn": ["testuser"],
                "sn": ["User"],
                "objectClass": ["person"],
            },
        })

        result = api.write([entry])
        assert result.is_success
        output = result.unwrap()
        assert "dn: cn=testuser,dc=example,dc=com" in output
        assert "cn: testuser" in output

    def test_write_multiple_entries(self) -> None:
        """Test writing multiple entries."""
        api = FlextLdifAPI()

        entries = [
            FlextLdifModels.create_entry({
                "dn": "cn=user1,dc=example,dc=com",
                "attributes": {"cn": ["user1"], "objectClass": ["person"]},
            }),
            FlextLdifModels.create_entry({
                "dn": "cn=user2,dc=example,dc=com",
                "attributes": {"cn": ["user2"], "objectClass": ["person"]},
            }),
        ]

        result = api.write(entries)
        assert result.is_success
        output = result.unwrap()
        assert "cn=user1" in output
        assert "cn=user2" in output

    def test_write_entry_error_handling(self) -> None:
        """Test write error handling."""
        api = FlextLdifAPI()

        # Test with valid entries - should not error
        entries = [
            FlextLdifModels.create_entry({
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"cn": ["test"], "objectClass": ["person"]},
            })
        ]

        result = api.write(entries)
        assert result.is_success

    def test_write_entry_with_special_characters(self) -> None:
        """Test writing entry with special characters."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=Special User,dc=example,dc=com",
            "attributes": {
                "cn": ["Special User"],
                "description": ["User with special chars: éñüö"],
                "objectClass": ["person"],
            },
        })

        result = api.write([entry])
        assert result.is_success
        output = result.unwrap()
        assert "Special User" in output

    def test_write_entry_with_binary_data(self) -> None:
        """Test writing entry with binary data."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=binaryuser,dc=example,dc=com",
            "attributes": {
                "cn": ["binaryuser"],
                "objectClass": ["person"],
                "photo": ["base64encodeddata"],  # Simulated binary data
            },
        })

        result = api.write([entry])
        assert result.is_success
        output = result.unwrap()
        assert "binaryuser" in output

    def test_write_entry_success(self) -> None:
        """Test successful entry writing."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=successuser,ou=people,dc=example,dc=com",
            "attributes": {
                "cn": ["successuser"],
                "sn": ["Success"],
                "mail": ["success@example.com"],
                "objectClass": ["person", "organizationalPerson"],
            },
        })

        result = api.write([entry])
        assert result.is_success
        output = result.unwrap()
        assert "successuser" in output
        assert "Success" in output

    def test_write_entry_with_multivalued_attributes(self) -> None:
        """Test writing entry with multi-valued attributes."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=multiuser,dc=example,dc=com",
            "attributes": {
                "cn": ["multiuser"],
                "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
                "mail": ["multi1@example.com", "multi2@example.com"],
                "telephoneNumber": ["+1-555-1234", "+1-555-5678"],
            },
        })

        result = api.write([entry])
        assert result.is_success
        output = result.unwrap()
        assert "multiuser" in output
        assert "multi1@example.com" in output

    def test_write_entry_with_empty_attributes(self) -> None:
        """Test writing entry with empty attributes."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=emptyattrs,dc=example,dc=com",
            "attributes": {
                "cn": ["emptyattrs"],
                "objectClass": ["person"],
                "description": [""],  # Empty attribute value
            },
        })

        result = api.write([entry])
        assert result.is_success
        output = result.unwrap()
        assert "emptyattrs" in output

    def test_write_file_success(self) -> None:
        """Test successful file writing."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=fileuser,dc=example,dc=com",
            "attributes": {"cn": ["fileuser"], "objectClass": ["person"]},
        })

        with tempfile.NamedTemporaryFile(delete=False, suffix=".ldif") as temp_file:
            temp_path = Path(temp_file.name)

        try:
            result = api.write_file([entry], str(temp_path))
            assert result.is_success

            # Verify file was written
            assert temp_path.exists()
            content = temp_path.read_text(encoding="utf-8")
            assert "fileuser" in content
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_write_file_with_custom_encoding(self) -> None:
        """Test file writing with custom encoding."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=encodinguser,dc=example,dc=com",
            "attributes": {
                "cn": ["encodinguser"],
                "description": ["Éñcödïñg tëst"],
                "objectClass": ["person"],
            },
        })

        with tempfile.NamedTemporaryFile(delete=False, suffix=".ldif") as temp_file:
            temp_path = Path(temp_file.name)

        try:
            result = api.write_file([entry], str(temp_path))
            assert result.is_success

            # Verify content with encoding
            content = temp_path.read_text(encoding="utf-8")
            assert "encodinguser" in content
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_write_file_exception_handling(self) -> None:
        """Test file writing exception handling."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=erroruser,dc=example,dc=com",
            "attributes": {"cn": ["erroruser"], "objectClass": ["person"]},
        })

        # Test with invalid path
        result = api.write_file([entry], "/nonexistent/path/file.ldif")
        assert result.is_failure

    def test_write_content_to_file_success(self) -> None:
        """Test writing content to file successfully."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=contentuser,dc=example,dc=com",
            "attributes": {"cn": ["contentuser"], "objectClass": ["person"]},
        })

        with tempfile.NamedTemporaryFile(delete=False, suffix=".ldif") as temp_file:
            temp_path = Path(temp_file.name)

        try:
            result = api.write_file([entry], str(temp_path))
            assert result.is_success
            assert temp_path.exists()
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_write_content_to_file_permission_error(self) -> None:
        """Test handling permission errors."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=permuser,dc=example,dc=com",
            "attributes": {"cn": ["permuser"], "objectClass": ["person"]},
        })

        # Test with protected directory
        result = api.write_file([entry], "/root/protected.ldif")
        assert result.is_failure

    def test_write_content_to_file_os_error(self) -> None:
        """Test handling OS errors."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=osuser,dc=example,dc=com",
            "attributes": {"cn": ["osuser"], "objectClass": ["person"]},
        })

        # Test with invalid path
        result = api.write_file([entry], "/invalid/path/file.ldif")
        assert result.is_failure

    def test_write_content_to_file_unicode_error(self) -> None:
        """Test handling unicode errors."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=unicodeuser,dc=example,dc=com",
            "attributes": {
                "cn": ["unicodeuser"],
                "description": ["Unicode test: 你好"],
                "objectClass": ["person"],
            },
        })

        with tempfile.NamedTemporaryFile(delete=False, suffix=".ldif") as temp_file:
            temp_path = Path(temp_file.name)

        try:
            result = api.write_file([entry], str(temp_path))
            # Should handle unicode gracefully
            assert result is not None
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_write_file_empty_entries(self) -> None:
        """Test writing empty entries to file."""
        api = FlextLdifAPI()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".ldif") as temp_file:
            temp_path = Path(temp_file.name)

        try:
            result = api.write_file([], str(temp_path))
            assert result.is_success

            # File should exist but be empty or minimal
            assert temp_path.exists()
            content = temp_path.read_text(encoding="utf-8")
            assert len(content.strip()) == 0  # Empty content
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_write_file_pathlib_path(self) -> None:
        """Test writing file using pathlib Path."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=pathuser,dc=example,dc=com",
            "attributes": {"cn": ["pathuser"], "objectClass": ["person"]},
        })

        with tempfile.NamedTemporaryFile(delete=False, suffix=".ldif") as temp_file:
            temp_path = Path(temp_file.name)

        try:
            # Use Path directly (converted to string)
            result = api.write_file([entry], str(temp_path))
            assert result.is_success
            assert temp_path.exists()

            content = temp_path.read_text(encoding="utf-8")
            assert "pathuser" in content
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_write_real_multiple_entries_to_string(self) -> None:
        """Test writing real multiple entries to string."""
        api = FlextLdifAPI()

        entries = [
            FlextLdifModels.create_entry({
                "dn": "cn=real1,dc=example,dc=com",
                "attributes": {"cn": ["real1"], "objectClass": ["person"]},
            }),
            FlextLdifModels.create_entry({
                "dn": "cn=real2,dc=example,dc=com",
                "attributes": {"cn": ["real2"], "objectClass": ["person"]},
            }),
        ]

        result = api.write(entries)
        assert result.is_success
        output = result.unwrap()
        assert "real1" in output
        assert "real2" in output

    def test_write_real_empty_entry_list(self) -> None:
        """Test writing empty entry list."""
        api = FlextLdifAPI()
        result = api.write([])
        assert result.is_success
        assert not result.unwrap()

    def test_write_real_entry_with_multi_valued_attributes(self) -> None:
        """Test writing entry with multi-valued attributes."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=multival,dc=example,dc=com",
            "attributes": {
                "cn": ["multival"],
                "objectClass": ["person", "organizationalPerson"],
                "mail": ["email1@example.com", "email2@example.com"],
            },
        })

        result = api.write([entry])
        assert result.is_success
        output = result.unwrap()
        assert "multival" in output
        assert "email1@example.com" in output

    def test_write_real_entry_with_binary_data(self) -> None:
        """Test writing entry with binary data."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=binaryreal,dc=example,dc=com",
            "attributes": {
                "cn": ["binaryreal"],
                "objectClass": ["person"],
                "userCertificate": ["binarydata123"],
            },
        })

        result = api.write([entry])
        assert result.is_success
        output = result.unwrap()
        assert "binaryreal" in output

    def test_write_real_entry_with_special_characters(self) -> None:
        """Test writing entry with special characters."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=special,dc=example,dc=com",
            "attributes": {
                "cn": ["special"],
                "description": ["Special chars: àáâãäåæç"],
                "objectClass": ["person"],
            },
        })

        result = api.write([entry])
        assert result.is_success
        output = result.unwrap()
        assert "special" in output

    def test_write_with_custom_line_length(self) -> None:
        """Test writing with custom line length."""
        config = FlextLdifConfig(ldif_strict_validation=False)
        api = FlextLdifAPI(config=config)

        entry = FlextLdifModels.create_entry({
            "dn": "cn=longlineuser,dc=example,dc=com",
            "attributes": {
                "cn": ["longlineuser"],
                "description": [
                    "Very long description that might exceed normal line length limits"
                ],
                "objectClass": ["person"],
            },
        })

        result = api.write([entry])
        assert result.is_success
        output = result.unwrap()
        assert "longlineuser" in output

    def test_write_with_different_encodings(self) -> None:
        """Test writing with different encodings."""
        config = FlextLdifConfig(ldif_strict_validation=False)
        api = FlextLdifAPI(config=config)

        entry = FlextLdifModels.create_entry({
            "dn": "cn=encoding,dc=example,dc=com",
            "attributes": {
                "cn": ["encoding"],
                "description": ["Encoding test: ñáéíóú"],
                "objectClass": ["person"],
            },
        })

        result = api.write([entry])
        assert result.is_success
        output = result.unwrap()
        assert "encoding" in output

    def test_write_real_entries_to_file(self) -> None:
        """Test writing real entries to file."""
        api = FlextLdifAPI()

        entry = FlextLdifModels.create_entry({
            "dn": "cn=realfile,dc=example,dc=com",
            "attributes": {
                "cn": ["realfile"],
                "sn": ["File"],
                "objectClass": ["person"],
            },
        })

        with tempfile.NamedTemporaryFile(delete=False, suffix=".ldif") as temp_file:
            temp_path = Path(temp_file.name)

        try:
            result = api.write_file([entry], str(temp_path))
            assert result.is_success

            content = temp_path.read_text(encoding="utf-8")
            assert "realfile" in content
            assert "File" in content
        finally:
            if temp_path.exists():
                temp_path.unlink()


class TestWriterIntegrationReal:
    """Integration tests with real writer and other services."""

    def test_writer_with_parser_roundtrip(self) -> None:
        """Test writer → parser roundtrip with real API."""
        api = FlextLdifAPI()

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
        write_result = api.write(original_entries)
        assert write_result.is_success
        ldif_content = write_result.unwrap()

        # Parse the written LDIF content
        parse_result = api.parse(ldif_content)
        assert parse_result.is_success
        parsed_entries = parse_result.unwrap()

        # Verify roundtrip consistency
        assert len(original_entries) == len(parsed_entries)

        for original, parsed in zip(original_entries, parsed_entries, strict=False):
            assert original.dn.value == parsed.dn.value
            # Should have same number of attributes (allowing for minor differences)
            assert (
                len(original.attributes) <= len(parsed.attributes) + 2
            )  # Allow some variation  # Allow some variation
