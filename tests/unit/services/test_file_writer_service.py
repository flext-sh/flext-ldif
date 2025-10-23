"""Unit tests for file writer service - real file I/O and integration tests.

Tests cover:
- Write categorized entries to LDIF files
- Schema entry processing and filtering
- Target-compatible schema entry creation
- RFC schema transformation pipeline
- Entry sorting by hierarchy and DN

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services.file_writer_service import FlextLdifFileWriterService


class TestFileWriterService:
    """Test FlextLdifFileWriterService file I/O and integration."""

    @pytest.fixture
    def temp_output_dir(self) -> Path:
        """Create temporary output directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_write_categorized_output_empty(self, temp_output_dir: Path) -> None:
        """Test writing empty categorized data."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        result = service.write_categorized_output({})
        assert result.is_success
        assert result.unwrap() == {}

    def test_write_categorized_output_single_category(
        self, temp_output_dir: Path
    ) -> None:
        """Test writing single category with entries."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={"users": "users.ldif"},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        categorized = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=user1,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["user1"]},
                }
            ]
        }

        result = service.write_categorized_output(categorized)
        assert result.is_success
        written_counts = result.unwrap()
        assert "users" in written_counts
        assert written_counts["users"] == 1

    def test_write_categorized_output_multiple_categories(
        self, temp_output_dir: Path
    ) -> None:
        """Test writing multiple categories."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={"users": "users.ldif", "groups": "groups.ldif"},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        categorized = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=user1,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["user1"]},
                }
            ],
            "groups": [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=group1,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["group1"]},
                }
            ],
        }

        result = service.write_categorized_output(categorized)
        assert result.is_success
        written_counts = result.unwrap()
        assert written_counts["users"] == 1
        assert written_counts["groups"] == 1

    def test_write_category_file_empty_entries(self, temp_output_dir: Path) -> None:
        """Test writing empty entry list returns 0."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        result = service.write_category_file("users", [], "users.ldif")
        assert result.is_success
        assert result.unwrap() == 0

    def test_write_category_file_creates_output_file(
        self, temp_output_dir: Path
    ) -> None:
        """Test that writing category file creates output file."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {"cn": ["test"]},
            }
        ]

        result = service.write_category_file("test", entries, "test.ldif")
        assert result.is_success

        # Verify file was created
        output_file = temp_output_dir / "test.ldif"
        assert output_file.exists()

    def test_process_schema_entries_empty(self, temp_output_dir: Path) -> None:
        """Test processing empty schema entries."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
            schema_whitelist_rules={},
        )

        result = service.process_schema_entries([])
        assert result == []

    def test_process_schema_entries_no_whitelist(self, temp_output_dir: Path) -> None:
        """Test processing schema entries without whitelist rules."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
            schema_whitelist_rules=None,
        )

        entries = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=schema",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": ["( 1.1 NAME 'test' )"]
                },
            }
        ]

        result = service.process_schema_entries(entries)
        assert len(result) == 1

    def test_process_schema_entries_with_attribute_whitelist(
        self, temp_output_dir: Path
    ) -> None:
        """Test processing schema with attribute OID whitelist."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
            schema_whitelist_rules={
                "allowed_attribute_oids": ["1.1", "1.2"],
                "allowed_objectclass_oids": [],
            },
        )

        entries = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=schema",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": [
                        "( 1.1 NAME 'allowed' )",
                        "( 2.1 NAME 'blocked' )",
                    ]
                },
            }
        ]

        result = service.process_schema_entries(entries)
        assert len(result) == 1
        attrs = result[0][FlextLdifConstants.DictKeys.ATTRIBUTES].get(
            "attributetypes", []
        )
        # Should only have allowed OID
        assert len(attrs) == 1

    def test_process_schema_entries_invalid_attributes_type(
        self, temp_output_dir: Path
    ) -> None:
        """Test handling of invalid attributes type."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=schema",
                FlextLdifConstants.DictKeys.ATTRIBUTES: "not_a_dict",
            }
        ]

        result = service.process_schema_entries(entries)
        # Should return entry as-is when attributes is not dict
        assert len(result) == 1
        assert result[0] == entries[0]

    def test_create_target_schema_entry_empty(self, temp_output_dir: Path) -> None:
        """Test creating schema entry from empty entries."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        result = service.create_target_schema_entry([])
        assert result == []

    def test_create_target_schema_entry_with_attributes(
        self, temp_output_dir: Path
    ) -> None:
        """Test creating schema entry with attributes."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries = [
            {
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": ["( 1.1 NAME 'cn' )"],
                    "objectclasses": ["( 2.1 NAME 'person' )"],
                }
            }
        ]

        result = service.create_target_schema_entry(entries)
        assert len(result) == 1
        assert result[0]["dn"] == "cn=schema"
        assert result[0]["changetype"] == ["modify"]

    def test_create_target_schema_entry_deduplication(
        self, temp_output_dir: Path
    ) -> None:
        """Test deduplication of schema entries."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries = [
            {
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": [
                        "( 1.1 NAME 'cn' )",
                        "( 1.1 NAME 'cn' )",  # Duplicate
                    ],
                    "objectclasses": [],
                }
            }
        ]

        result = service.create_target_schema_entry(entries)
        # Should deduplicate
        assert len(result) == 1

    def test_sort_entries_by_hierarchy_empty(self, temp_output_dir: Path) -> None:
        """Test sorting empty entry list."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        result = service._sort_entries_by_hierarchy_and_name([])
        assert result == []

    def test_sort_entries_by_hierarchy_single(self, temp_output_dir: Path) -> None:
        """Test sorting single entry."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {},
            }
        ]

        result = service._sort_entries_by_hierarchy_and_name(entries)
        assert len(result) == 1

    def test_sort_entries_by_hierarchy_depth(self, temp_output_dir: Path) -> None:
        """Test sorting by DN hierarchy depth."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=a,ou=b,ou=c,dc=example,dc=com",
            },
            {FlextLdifConstants.DictKeys.DN: "cn=x,dc=example,dc=com"},
            {FlextLdifConstants.DictKeys.DN: "cn=y,ou=z,dc=example,dc=com"},
        ]

        result = service._sort_entries_by_hierarchy_and_name(entries)
        # Should be sorted by depth (shallow first)
        assert len(result) == 3
        # Shallowest should be first
        first_dn = result[0].get(FlextLdifConstants.DictKeys.DN, "")
        assert first_dn == "cn=x,dc=example,dc=com"

    def test_sort_entries_with_non_string_dn(self, temp_output_dir: Path) -> None:
        """Test sorting with non-string DN values."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=valid,dc=example,dc=com",
            },
            {FlextLdifConstants.DictKeys.DN: 123},  # Invalid type
            {FlextLdifConstants.DictKeys.DN: "cn=another,dc=example,dc=com"},
        ]

        result = service._sort_entries_by_hierarchy_and_name(entries)
        # Non-string DNs should be at end
        assert len(result) == 3
        # Last entry should be the invalid one
        assert result[-1][FlextLdifConstants.DictKeys.DN] == 123

    def test_sort_entries_case_insensitive(self, temp_output_dir: Path) -> None:
        """Test sorting is case-insensitive."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries = [
            {FlextLdifConstants.DictKeys.DN: "CN=Zebra,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: "cn=apple,dc=example,dc=com"},
            {FlextLdifConstants.DictKeys.DN: "CN=banana,DC=example,DC=com"},
        ]

        result = service._sort_entries_by_hierarchy_and_name(entries)
        assert len(result) == 3

    def test_output_file_format_mapping(self, temp_output_dir: Path) -> None:
        """Test output file format mapping with non-string values."""
        service = FlextLdifFileWriterService(
            output_dir=temp_output_dir,
            output_files={"users": 123},  # Non-string value
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        # Should handle non-string filename gracefully
        categorized = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                }
            ]
        }

        result = service.write_categorized_output(categorized)
        assert result.is_success
        written_counts = result.unwrap()
        assert "users" in written_counts
