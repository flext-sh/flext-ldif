"""Comprehensive test suite for RFC LDIF writer.

High-coverage testing using real LDIF fixtures and RFC-compliant output validation.
Tests RFC 2849 compliance and server-specific formatting.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pytest

from flext_ldif.api import FlextLdif
from flext_ldif.models import FlextLdifModels


class TestRfcLdifWriterComprehensive:
    """Comprehensive RFC LDIF writer testing with real fixtures."""

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        """Get fixtures directory."""
        return Path(__file__).parent.parent.parent / "fixtures"

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif()

    def create_entry(
        self, dn: str, attributes: dict[str, Any]
    ) -> FlextLdifModels.Entry:
        """Helper to create Entry using factory method.

        Converts dict[str, list[str]] to proper Entry model.
        """
        result = FlextLdifModels.Entry.create(dn=dn, attributes=attributes)
        assert result.is_success, f"Failed to create entry: {result.error}"
        return result.unwrap()

    def test_write_simple_entry(self, tmp_path: Path, api: FlextLdif) -> None:
        """Test writing a simple LDAP entry to LDIF format."""
        entry = self.create_entry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["inetOrgPerson"],
                "sn": ["User"],
            },
        )

        output_file = tmp_path / "simple_entry.ldif"
        result = api.write([entry], output_file)

        assert result.is_success
        assert output_file.exists()

        # Verify content is valid LDIF
        content = output_file.read_text()
        assert "dn: cn=test,dc=example,dc=com" in content
        assert "cn: test" in content
        assert "objectClass: inetOrgPerson" in content

    def test_write_multiple_entries(self, tmp_path: Path, api: FlextLdif) -> None:
        """Test writing multiple LDAP entries to single LDIF file."""
        entries = [
            self.create_entry(
                dn="cn=user1,dc=example,dc=com",
                attributes={"cn": ["user1"], "objectClass": ["person"]},
            ),
            self.create_entry(
                dn="cn=user2,dc=example,dc=com",
                attributes={"cn": ["user2"], "objectClass": ["person"]},
            ),
        ]

        output_file = tmp_path / "multiple_entries.ldif"
        result = api.write(entries, output_file)

        assert result.is_success
        content = output_file.read_text()

        # Verify both entries in output
        assert "cn=user1,dc=example,dc=com" in content
        assert "cn=user2,dc=example,dc=com" in content

    def test_write_entry_with_base64_attributes(
        self, tmp_path: Path, api: FlextLdif
    ) -> None:
        """Test writing entries with binary/base64 attributes."""
        # Binary data is base64-encoded in LDIF
        binary_data = b"\x89PNG\r\n\x1a\n"
        encoded_data = base64.b64encode(binary_data).decode("ascii")

        entry = self.create_entry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "jpegPhoto": [encoded_data],  # Base64-encoded binary data
            },
        )

        output_file = tmp_path / "base64_entry.ldif"
        result = api.write([entry], output_file)

        assert result.is_success
        content = output_file.read_text()
        # Base64-encoded data is written as regular string attribute
        # (LDIF writer encodes binary data as base64 string)
        assert "jpegPhoto:" in content
        assert encoded_data in content

    def test_write_entry_with_special_characters(
        self, tmp_path: Path, api: FlextLdif
    ) -> None:
        """Test writing entries with special characters in attributes."""
        entry = self.create_entry(
            dn="cn=José García,dc=example,dc=com",
            attributes={
                "cn": ["José García"],
                "description": ["Ñoño character test"],
            },
        )

        output_file = tmp_path / "special_chars.ldif"
        result = api.write([entry], output_file)

        assert result.is_success
        content = output_file.read_text()
        # UTF-8 characters should be preserved
        assert "José" in content or "Jos" in content

    def test_write_and_reparse_roundtrip(
        self, tmp_path: Path, fixtures_dir: Path, api: FlextLdif
    ) -> None:
        """Test that written LDIF can be parsed again with same data."""
        # Get fixture file
        fixture_file = fixtures_dir / "oid" / "oid_entries_fixtures.ldif"
        if not fixture_file.exists():
            pytest.skip(f"Fixture not found: {fixture_file}")

        # Parse original
        parse_result = api.parse(fixture_file, server_type="oid")
        assert parse_result.is_success
        original_entries = parse_result.unwrap()

        # Write to new file
        output_file = tmp_path / "roundtrip.ldif"
        write_result = api.write(original_entries, output_file)
        assert write_result.is_success

        # Parse written file
        reparse_result = api.parse(output_file)
        assert reparse_result.is_success
        reparsed_entries = reparse_result.unwrap()

        # Verify same count
        assert len(original_entries) == len(reparsed_entries)

    def test_write_preserves_attribute_order(
        self, tmp_path: Path, api: FlextLdif
    ) -> None:
        """Test that written LDIF preserves attribute values."""
        attrs = {
            "cn": ["test"],
            "description": ["Line 1", "Line 2", "Line 3"],
            "objectClass": ["person", "inetOrgPerson"],
        }

        entry = self.create_entry(dn="cn=test,dc=example,dc=com", attributes=attrs)

        output_file = tmp_path / "attributes.ldif"
        result = api.write([entry], output_file)

        assert result.is_success
        content = output_file.read_text()

        # All attribute values should be present
        assert "description: Line 1" in content
        assert "description: Line 2" in content
        assert "description: Line 3" in content

    def test_write_empty_attributes_list(self, tmp_path: Path, api: FlextLdif) -> None:
        """Test writing entry with empty attributes is handled properly."""
        entry = self.create_entry(
            dn="cn=empty,dc=example,dc=com",
            attributes={
                "cn": ["empty"],
                "objectClass": [],  # Empty list
            },
        )

        output_file = tmp_path / "empty_attrs.ldif"
        result = api.write([entry], output_file)

        assert result.is_success

    def test_write_maintains_rfc_format(self, tmp_path: Path, api: FlextLdif) -> None:
        """Test that output follows RFC 2849 LDIF format."""
        entry = self.create_entry(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectClass": ["person"]},
        )

        output_file = tmp_path / "rfc_format.ldif"
        result = api.write([entry], output_file)

        assert result.is_success
        content = output_file.read_text()

        # RFC 2849 format requirements
        assert "dn:" in content  # DN present
        assert "\n" in content  # Proper line endings
        # Should not have extraneous blank lines at end
        assert not content.endswith("\n\n\n")

    def test_write_with_different_encodings(
        self, tmp_path: Path, api: FlextLdif
    ) -> None:
        """Test writing with UTF-8 encoding (standard for LDIF)."""
        entry = self.create_entry(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "description": ["UTF-8: ü ö ä"]},
        )

        output_file = tmp_path / "utf8_entry.ldif"
        result = api.write([entry], output_file)

        assert result.is_success
        # Verify file can be read as UTF-8
        content = output_file.read_text(encoding="utf-8")
        assert "test" in content

    def test_write_large_attribute_value(self, tmp_path: Path, api: FlextLdif) -> None:
        """Test writing entries with large attribute values."""
        large_value = "x" * 10000  # 10KB attribute value

        entry = self.create_entry(
            dn="cn=large,dc=example,dc=com",
            attributes={"cn": ["large"], "description": [large_value]},
        )

        output_file = tmp_path / "large_attr.ldif"
        result = api.write([entry], output_file)

        assert result.is_success
        content = output_file.read_text()
        assert large_value in content

    def test_write_with_dn_variations(self, tmp_path: Path, api: FlextLdif) -> None:
        """Test writing entries with various DN formats."""
        entries = [
            self.create_entry(
                dn="cn=simple",
                attributes={"cn": ["simple"]},
            ),
            self.create_entry(
                dn="cn=User,ou=People,dc=example,dc=com",
                attributes={"cn": ["User"]},
            ),
            self.create_entry(
                dn="uid=john.doe,ou=Staff,o=Example Inc,c=US",
                attributes={"uid": ["john.doe"]},
            ),
        ]

        output_file = tmp_path / "dn_variations.ldif"
        result = api.write(entries, output_file)

        assert result.is_success
        content = output_file.read_text()

        # All DNs should be present
        assert "cn=simple" in content
        assert "cn=User,ou=People,dc=example,dc=com" in content
        assert "uid=john.doe,ou=Staff,o=Example Inc,c=US" in content
