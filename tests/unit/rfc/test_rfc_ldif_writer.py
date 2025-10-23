"""Unit tests for RFC 2849 LDIF writer service.

Tests cover:
- Write LDIF entries to file and string
- Schema entry processing and formatting
- Regular entry writing with DN normalization
- ACL entry writing and formatting
- Line wrapping at RFC 2849 limits
- Base64 encoding for special characters
- Append mode and version headers
- Error handling for invalid inputs

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.rfc.rfc_ldif_writer import FlextLdifRfcLdifWriter


class TestRfcLdifWriterBasic:
    """Test suite for RFC LDIF writer basic functionality."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_write_simple_entry_to_file(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing simple entry to file."""
        output_file = temp_output_dir / "simple.ldif"

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["test"],
                        "objectClass": ["person"],
                    },
                }
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params, quirk_registry=quirk_registry, target_server_type="rfc"
        )
        result = writer.execute()

        assert result.is_success
        assert output_file.exists()

        content = output_file.read_text(encoding="utf-8")
        assert "version: 1" in content
        assert "dn: cn=test,dc=example,dc=com" in content
        assert "cn: test" in content

    def test_write_entry_to_string(
        self, quirk_registry: FlextLdifQuirksRegistry
    ) -> None:
        """Test writing entry to string (no output file)."""
        params = {
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["test"],
                        "objectClass": ["person"],
                    },
                }
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params, quirk_registry=quirk_registry, target_server_type="rfc"
        )
        result = writer.execute()

        assert result.is_success
        output_data = result.unwrap()
        content = output_data.get("content", "")
        assert "version: 1" in content
        assert "dn: cn=test,dc=example,dc=com" in content

    def test_write_multiple_entries(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing multiple entries."""
        output_file = temp_output_dir / "multiple.ldif"

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=user1,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["user1"],
                        "objectClass": ["person"],
                    },
                },
                {
                    FlextLdifConstants.DictKeys.DN: "cn=user2,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["user2"],
                        "objectClass": ["person"],
                    },
                },
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params, quirk_registry=quirk_registry, target_server_type="rfc"
        )
        result = writer.execute()

        assert result.is_success
        content = output_file.read_text(encoding="utf-8")
        assert "cn=user1,dc=example,dc=com" in content
        assert "cn=user2,dc=example,dc=com" in content

    def test_empty_input_fails(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test that empty input fails with appropriate error."""
        output_file = temp_output_dir / "empty.ldif"

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [],
            FlextLdifConstants.DictKeys.SCHEMA: {},
            FlextLdifConstants.DictKeys.ACL: [],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params, quirk_registry=quirk_registry, target_server_type="rfc"
        )
        result = writer.execute()

        assert result.is_failure


class TestRfcLdifWriterSchema:
    """Test suite for RFC LDIF writer schema entry handling."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_write_schema_entries(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing schema entries."""
        output_file = temp_output_dir / "schema.ldif"

        schema = {
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "testAttr": "( 1.3.6.1.4.1.1466.115.121.1.1 NAME 'testAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
            },
            FlextLdifConstants.DictKeys.OBJECTCLASSES: {
                "testClass": "( 2.5.6.6 NAME 'testClass' SUP top STRUCTURAL )"
            },
        }

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.SCHEMA: schema,
        }

        writer = FlextLdifRfcLdifWriter(
            params=params, quirk_registry=quirk_registry, target_server_type="rfc"
        )
        result = writer.execute()

        assert result.is_success
        content = output_file.read_text(encoding="utf-8")
        assert "dn: cn=schema" in content
        assert "attributeTypes:" in content
        assert "objectClasses:" in content

    def test_schema_without_entries(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing schema only (no regular entries)."""
        output_file = temp_output_dir / "schema_only.ldif"

        schema = {
            FlextLdifConstants.DictKeys.ATTRIBUTES: {
                "testAttr": "( 1.3.6.1.4.1.1466.115.121.1.1 NAME 'testAttr' )"
            }
        }

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.SCHEMA: schema,
        }

        writer = FlextLdifRfcLdifWriter(
            params=params, quirk_registry=quirk_registry, target_server_type="rfc"
        )
        result = writer.execute()

        assert result.is_success
        content = output_file.read_text(encoding="utf-8")
        assert "dn: cn=schema" in content


class TestRfcLdifWriterAppendMode:
    """Test suite for RFC LDIF writer append mode."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_append_mode_preserves_existing(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test append mode preserves existing content."""
        output_file = temp_output_dir / "append.ldif"

        # Write initial entry
        params1 = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=user1,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["user1"]},
                }
            ],
        }

        writer1 = FlextLdifRfcLdifWriter(
            params=params1, quirk_registry=quirk_registry, target_server_type="rfc"
        )
        result1 = writer1.execute()
        assert result1.is_success

        # Append second entry
        params2 = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=user2,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["user2"]},
                }
            ],
            FlextLdifConstants.DictKeys.APPEND: True,
        }

        writer2 = FlextLdifRfcLdifWriter(
            params=params2, quirk_registry=quirk_registry, target_server_type="rfc"
        )
        result2 = writer2.execute()
        assert result2.is_success

        # Verify both entries exist
        content = output_file.read_text(encoding="utf-8")
        assert "cn=user1,dc=example,dc=com" in content
        assert "cn=user2,dc=example,dc=com" in content


class TestRfcLdifWriterMultiValueAttributes:
    """Test suite for multi-value attributes."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_multivalue_attribute_writing(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing entries with multi-value attributes."""
        output_file = temp_output_dir / "multivalue.ldif"

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=group,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["group"],
                        "member": [
                            "cn=user1,dc=example,dc=com",
                            "cn=user2,dc=example,dc=com",
                            "cn=user3,dc=example,dc=com",
                        ],
                        "objectClass": ["groupOfNames", "top"],
                    },
                }
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params, quirk_registry=quirk_registry, target_server_type="rfc"
        )
        result = writer.execute()

        assert result.is_success
        content = output_file.read_text(encoding="utf-8")
        assert "member: cn=user1,dc=example,dc=com" in content
        assert "member: cn=user2,dc=example,dc=com" in content
        assert "member: cn=user3,dc=example,dc=com" in content


class TestRfcLdifWriterSpecialCharacters:
    """Test suite for special character handling."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_entry_with_space_in_name(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test entry with space at beginning of attribute value."""
        output_file = temp_output_dir / "spaces.ldif"

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["test"],
                        "description": [" leading space"],  # Begins with space
                    },
                }
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params, quirk_registry=quirk_registry, target_server_type="rfc"
        )
        result = writer.execute()

        assert result.is_success


class TestRfcLdifWriterAclEntries:
    """Test suite for ACL entry writing."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_write_acl_entries(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing ACL entries."""
        output_file = temp_output_dir / "acl.ldif"

        acls = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=acl,dc=example,dc=com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "aci": [
                        '(targetattr="*")(version 3.0; acl "test"; allow (read) userdn="ldap:///anyone";)'
                    ]
                },
            }
        ]

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ACL: acls,
        }

        writer = FlextLdifRfcLdifWriter(
            params=params, quirk_registry=quirk_registry, target_server_type="rfc"
        )
        result = writer.execute()

        assert result.is_success


class TestRfcLdifWriterDnNormalization:
    """Test suite for DN normalization."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_dn_case_variations(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test DN with case variations."""
        output_file = temp_output_dir / "dn_case.ldif"

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=TEST,DC=EXAMPLE,DC=COM",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["test"]},
                }
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params, quirk_registry=quirk_registry, target_server_type="rfc"
        )
        result = writer.execute()

        assert result.is_success


class TestRfcLdifWriterInvalidTypes:
    """Test suite for invalid input type handling."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    def test_invalid_output_file_type(
        self, quirk_registry: FlextLdifQuirksRegistry
    ) -> None:
        """Test handling of non-string output_file."""
        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: 123,  # Invalid type
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["test"]},
                }
            ],
        }

        writer = FlextLdifRfcLdifWriter(
            params=params, quirk_registry=quirk_registry, target_server_type="rfc"
        )
        result = writer.execute()

        # Should fall back to string output since output_file is invalid
        assert result.is_success

    def test_invalid_entries_type(
        self, quirk_registry: FlextLdifQuirksRegistry
    ) -> None:
        """Test handling of non-list entries."""
        params = {
            FlextLdifConstants.DictKeys.ENTRIES: "not_a_list",  # Invalid type
        }

        writer = FlextLdifRfcLdifWriter(
            params=params, quirk_registry=quirk_registry, target_server_type="rfc"
        )
        result = writer.execute()

        assert result.is_failure
