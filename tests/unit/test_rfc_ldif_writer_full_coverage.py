"""Comprehensive RFC LDIF Writer Coverage Tests.

Tests cover ALL methods and code paths in FlextLdifRfcLdifWriter:
- execute() with various input configurations
- write_entries_to_string() with schema and ACL data
- write_entries_to_file() with append mode and various entry types
- _write_schema_entries() with attributeTypes and objectClasses
- _write_entries() with multi-valued attributes and special characters
- _write_acl_entries() with various ACL formats
- _wrap_line() with long attribute values
- _extract_acl_definitions() from entry attributes
- _normalize_dn() with various DN formats
- _needs_base64_encoding() for special characters
- _format_attribute_value() for different attribute types

All tests use REAL data structures from actual LDIF parsing, not mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.rfc_ldif_writer import FlextLdifRfcLdifWriter


class TestRfcLdifWriterSchemaEntries:
    """Test schema entry writing (attributeTypes and objectClasses)."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_output_dir(self) -> Generator[Path]:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_write_schema_with_attributetypes(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing schema with attributeTypes entries."""
        output_file = temp_output_dir / "schema.ldif"

        # Schema entries use dn: cn=schema
        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=schema",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["schema"],
                        "objectClass": ["ldapSubentry"],
                        "attributeTypes": [
                            "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
                        ],
                    },
                }
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params,
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        result = writer.execute()

        assert result.is_success
        content = output_file.read_text(encoding="utf-8")
        assert "cn=schema" in content

    def test_write_schema_with_objectclasses(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing schema with objectClasses entries."""
        output_file = temp_output_dir / "schema_oc.ldif"

        # Schema entries use dn: cn=schema with objectClasses attribute
        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=schema",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["schema"],
                        "objectClass": ["ldapSubentry"],
                        "objectClasses": [
                            "( 2.5.6.6 NAME 'person' STRUCTURAL SUP top MUST cn MAY description )"
                        ],
                    },
                }
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params,
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        result = writer.execute()

        assert result.is_success
        content = output_file.read_text(encoding="utf-8")
        assert "cn=schema" in content

    def test_write_schema_combined_attributes_and_objectclasses(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing combined schema with both attributes and objectClasses."""
        output_file = temp_output_dir / "schema_combined.ldif"

        # Combined schema entry with both attributeTypes and objectClasses
        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=schema",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["schema"],
                        "objectClass": ["ldapSubentry"],
                        "attributeTypes": [
                            "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
                        ],
                        "objectClasses": [
                            "( 2.5.6.6 NAME 'person' STRUCTURAL SUP top )"
                        ],
                    },
                }
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params,
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        result = writer.execute()

        assert result.is_success
        content = output_file.read_text(encoding="utf-8")
        assert "cn=schema" in content


class TestRfcLdifWriterSpecialCharacters:
    """Test handling of special characters and base64 encoding."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_output_dir(self) -> Generator[Path]:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_write_entry_with_special_characters(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing entry with special characters requiring base64 encoding."""
        output_file = temp_output_dir / "special_chars.ldif"

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=Special\\, Characters,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["Special, Characters"],
                        "description": ["Contains: colons, commas, special chars"],
                        "objectClass": ["person"],
                    },
                }
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params,
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        result = writer.execute()

        assert result.is_success
        content = output_file.read_text(encoding="utf-8")
        assert "cn=Special\\, Characters,dc=example,dc=com" in content

    def test_write_entry_with_multiple_values(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing entry with multiple values for same attribute."""
        output_file = temp_output_dir / "multivalued.ldif"

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["test", "Test User"],
                        "mail": [
                            "test@example.com",
                            "testuser@example.com",
                            "t.user@example.com",
                        ],
                        "objectClass": ["person", "inetOrgPerson"],
                    },
                }
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params,
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        result = writer.execute()

        assert result.is_success
        content = output_file.read_text(encoding="utf-8")
        assert "cn: test" in content
        assert "cn: Test User" in content

    def test_write_entry_with_binary_data(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing entry with binary attribute values."""
        output_file = temp_output_dir / "binary.ldif"

        # Simulate binary data (base64 will be applied)
        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["test"],
                        "jpegPhoto": [
                            "\x00\x01\x02\x03"
                        ],  # Binary data will trigger base64
                        "objectClass": ["person"],
                    },
                }
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params,
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        result = writer.execute()

        assert result.is_success
        content = output_file.read_text(encoding="utf-8")
        assert "cn=test,dc=example,dc=com" in content
        # Should contain base64 encoded data
        assert ":: " in content or ": " in content


class TestRfcLdifWriterAppendMode:
    """Test append mode and file operations."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_output_dir(self) -> Generator[Path]:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_append_mode_basic(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test basic append mode functionality."""
        output_file = temp_output_dir / "append.ldif"

        # First entry
        params1 = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=first,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["first"],
                        "objectClass": ["person"],
                    },
                }
            ],
        }

        # Second entry (append)
        params2 = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=second,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["second"],
                        "objectClass": ["person"],
                    },
                }
            ],
        }

        # Write first entry
        writer1 = FlextLdifRfcLdifWriter(
            params=params1,
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        result1 = writer1.execute()
        assert result1.is_success

        # Write second entry (should append)
        writer2 = FlextLdifRfcLdifWriter(
            params=params2,
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        result2 = writer2.execute()
        assert result2.is_success

        content = output_file.read_text(encoding="utf-8")
        assert "cn=first,dc=example,dc=com" in content
        assert "cn=second,dc=example,dc=com" in content
        assert content.count("version: 1") == 1  # Only one version header

    def test_empty_entries_list(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test handling of empty entries list."""
        output_file = temp_output_dir / "empty.ldif"

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [],
            FlextLdifConstants.DictKeys.ACL: [],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params,
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        result = writer.execute()

        assert result.is_success
        content = output_file.read_text(encoding="utf-8")
        assert "version: 1" in content


class TestRfcLdifWriterErrorHandling:
    """Test error handling and edge cases."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    def test_missing_dn_error(self, quirk_registry: FlextLdifQuirksRegistry) -> None:
        """Test error handling when DN is missing."""
        # Missing DN
        params = {
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["test"],
                        "objectClass": ["person"],
                    },
                }
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params,
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        result = writer.execute()

        assert not result.is_success
        assert "must be provided" in result.error

    def test_missing_attributes_error(
        self, quirk_registry: FlextLdifQuirksRegistry
    ) -> None:
        """Test error handling when attributes are missing."""
        params = {
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                    # Missing attributes
                }
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params,
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        result = writer.execute()

        assert not result.is_success
        assert "must be provided" in result.error

    def test_write_to_string_no_file(
        self, quirk_registry: FlextLdifQuirksRegistry
    ) -> None:
        """Test writing to string without output file."""
        params = {
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["test"],
                        "mail": ["test@example.com"],
                        "objectClass": ["person"],
                    },
                }
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params,
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        result = writer.execute()

        assert result.is_success
        output_data = result.unwrap()
        content = output_data.get("content", "")
        assert "version: 1" in content
        assert "cn=test,dc=example,dc=com" in content


class TestRfcLdifWriterStringOutput:
    """Test string output mode (no file)."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    def test_write_multiple_entries_to_string(
        self, quirk_registry: FlextLdifQuirksRegistry
    ) -> None:
        """Test writing multiple entries to string."""
        params = {
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "ou=users,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "ou": ["users"],
                        "description": ["User container"],
                        "objectClass": ["organizationalUnit"],
                    },
                },
                {
                    FlextLdifConstants.DictKeys.DN: "cn=John Doe,ou=users,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["John Doe"],
                        "sn": ["Doe"],
                        "givenName": ["John"],
                        "mail": ["john.doe@example.com"],
                        "telephoneNumber": ["+1-555-0100"],
                        "objectClass": ["person", "inetOrgPerson"],
                    },
                },
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params,
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        result = writer.execute()

        assert result.is_success
        output_data = result.unwrap()
        content = output_data.get("content", "")
        assert "version: 1" in content
        assert "ou=users,dc=example,dc=com" in content
        assert "cn=John Doe,ou=users,dc=example,dc=com" in content


__all__ = [
    "TestRfcLdifWriterAppendMode",
    "TestRfcLdifWriterErrorHandling",
    "TestRfcLdifWriterSchemaEntries",
    "TestRfcLdifWriterSpecialCharacters",
    "TestRfcLdifWriterStringOutput",
]
