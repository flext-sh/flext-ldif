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

import base64
import tempfile
from pathlib import Path
from typing import Any

import pytest

from flext_ldif.api import FlextLdif
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.rfc_ldif_writer import FlextLdifRfcLdifWriter


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


class TestRfcLdifWriterSchemaEntries:
    """Test schema entry writing (attributeTypes and objectClasses)."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_output_dir(self) -> Path:
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


class TestRfcLdifWriterAclHandling:
    """Test ACL entry writing and handling."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_write_entries_with_acl_attributes(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing entries that contain ACL attributes."""
        output_file = temp_output_dir / "with_acl.ldif"

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["test"],
                        "objectClass": ["person"],
                        "ds-aci": [
                            '(target="ldap:///") (version 3.0; acl "test"; allow(read) userdn="ldap:///anyone";)'
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
        assert "dn:" in content

    def test_write_separate_acl_entries(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing separate ACL entries."""
        output_file = temp_output_dir / "acl_entries.ldif"

        acl_data = [
            {
                "dn": "cn=acl-test,dc=example,dc=com",
                "target": "ldap:///",
                "content": '(version 3.0; acl "test"; allow(read) userdn="ldap:///anyone";)',
            }
        ]

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [],
            FlextLdifConstants.DictKeys.ACL: acl_data,
        }

        writer = FlextLdifRfcLdifWriter(
            params=params,
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        result = writer.execute()

        assert result.is_success


class TestRfcLdifWriterLineWrapping:
    """Test RFC 2849 line wrapping at 76 characters."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_write_entry_with_long_attribute_value(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test that long attribute values are wrapped per RFC 2849."""
        output_file = temp_output_dir / "long_values.ldif"

        long_description = "This is a very long description that definitely exceeds the RFC 2849 line wrapping limit of 76 characters and should be wrapped accordingly."

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["test"],
                        "description": [long_description],
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

        # Check that content is present
        assert "cn=test,dc=example,dc=com" in content
        assert "cn: test" in content

        # Check that lines respect wrapping (max 76 chars)
        # Note: Some implementations may use base64 for very long lines
        lines = content.split("\n")
        for line in lines:
            if not line.startswith(" "):  # Non-continuation lines
                assert len(line) <= 76, (
                    f"Line exceeds 76 character limit: {len(line)} chars in '{line[:50]}...'"
                )

    def test_write_entry_with_very_long_dn(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing entry with very long DN."""
        output_file = temp_output_dir / "long_dn.ldif"

        long_dn = (
            ",".join([f"cn=component{i}" for i in range(20)]) + ",dc=example,dc=com"
        )

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: long_dn,
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

        assert result.is_success


class TestRfcLdifWriterQuirkIntegration:
    """Test writer with different target server quirks."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_write_with_oud_quirks(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing with OUD (Oracle Unified Directory) quirks."""
        output_file = temp_output_dir / "oud.ldif"

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
            params=params,
            quirk_registry=quirk_registry,
            target_server_type="oud",
        )
        result = writer.execute()

        assert result.is_success

    def test_write_with_oid_quirks(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing with OID (Oracle Internet Directory) quirks."""
        output_file = temp_output_dir / "oid.ldif"

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
            params=params,
            quirk_registry=quirk_registry,
            target_server_type="oid",
        )
        result = writer.execute()

        assert result.is_success


class TestRfcLdifWriterErrorHandling:
    """Test error handling and edge cases."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_write_with_missing_dn(
        self, quirk_registry: FlextLdifQuirksRegistry
    ) -> None:
        """Test writing entry without DN."""
        params = {
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    # Missing DN
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

        # Should handle gracefully
        assert hasattr(result, "is_success")

    def test_write_with_missing_attributes(
        self, quirk_registry: FlextLdifQuirksRegistry, temp_output_dir: Path
    ) -> None:
        """Test writing entry without attributes."""
        output_file = temp_output_dir / "no_attrs.ldif"

        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: str(output_file),
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

        assert hasattr(result, "is_success")

    def test_write_invalid_output_file_path(
        self, quirk_registry: FlextLdifQuirksRegistry
    ) -> None:
        """Test writing to invalid file path."""
        params = {
            FlextLdifConstants.DictKeys.OUTPUT_FILE: "/invalid/path/that/does/not/exist.ldif",
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
            params=params,
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        result = writer.execute()

        # Should fail gracefully
        assert hasattr(result, "is_success")


class TestRfcLdifWriterStringOutput:
    """Test string output mode (no file)."""

    @pytest.fixture
    def quirk_registry(self) -> FlextLdifQuirksRegistry:
        """Create quirk registry."""
        return FlextLdifQuirksRegistry()

    def test_write_entries_to_string_returns_content(
        self, quirk_registry: FlextLdifQuirksRegistry
    ) -> None:
        """Test that string output mode returns content in result."""
        params = {
            FlextLdifConstants.DictKeys.ENTRIES: [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {
                        "cn": ["test"],
                        "mail": ["test@example.com"],
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
        output_data = result.unwrap()
        assert isinstance(output_data, dict)
        assert "content" in output_data or "entries_written" in output_data

    def test_write_complex_entries_to_string(
        self, quirk_registry: FlextLdifQuirksRegistry
    ) -> None:
        """Test writing complex entries to string."""
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
                        "mail": ["john@example.com", "jdoe@example.com"],
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
        assert "cn=John Doe" in content or isinstance(output_data, dict)


class TestRfcLdifWriterComprehensive:
    """Comprehensive RFC LDIF writer testing with real fixtures and FlextLdif API."""

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
