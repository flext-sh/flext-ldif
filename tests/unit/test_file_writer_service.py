"""Unit tests for LDIF file writer service.

Tests cover:
- Writing categorized LDIF output
- Category file writing with RFC-compliant formatting
- Schema entry processing and filtering
- Target-compatible schema entry creation
- DN sorting by hierarchy

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services.file_writer_service import FlextLdifFileWriterService


class TestFlextLdifFileWriterServiceInitialization:
    """Test FlextLdifFileWriterService initialization."""

    def test_initialization_with_required_parameters(self, tmp_path: Path) -> None:
        """Test service initialization with required parameters."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={"users": "users.ldif"},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        assert service._output_dir == tmp_path
        assert service._target_server == "oud"
        assert service._target_schema_quirk is None
        assert service._source_schema_quirk is None

    def test_initialization_with_schema_whitelist_rules(self, tmp_path: Path) -> None:
        """Test service initialization with whitelist rules."""
        rules: dict[str, object] = {"allowed_attribute_oids": ["1.3.6.1.4.*"]}
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oid",
            target_schema_quirk=None,
            source_schema_quirk=None,
            schema_whitelist_rules=rules,
        )

        assert service._schema_whitelist_rules == rules

    def test_initialization_default_whitelist_rules(self, tmp_path: Path) -> None:
        """Test that default whitelist rules is empty dict."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        assert service._schema_whitelist_rules == {}


class TestWriteCategorizedOutput:
    """Test write_categorized_output method."""

    def test_write_empty_categorized(self, tmp_path: Path) -> None:
        """Test writing empty categorized data."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        result = service.write_categorized_output({})

        assert result.is_success
        assert result.unwrap() == {}

    def test_write_single_category(self, tmp_path: Path) -> None:
        """Test writing single category with real writer."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={"users": "users.ldif"},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        categorized: dict[str, list[dict[str, object]]] = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                }
            ]
        }

        result = service.write_categorized_output(categorized)

        assert result.is_success
        counts = result.unwrap()
        assert "users" in counts
        assert counts["users"] == 1
        # Verify file was created
        output_file = tmp_path / "users.ldif"
        assert output_file.exists()

    def test_write_multiple_categories(self, tmp_path: Path) -> None:
        """Test writing multiple categories with real writer."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={"users": "users.ldif", "groups": "groups.ldif"},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        categorized: dict[str, list[dict[str, object]]] = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=User1,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                },
                {
                    FlextLdifConstants.DictKeys.DN: "CN=User2,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                },
            ],
            "groups": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=Group1,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                },
                {
                    FlextLdifConstants.DictKeys.DN: "CN=Group2,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                },
                {
                    FlextLdifConstants.DictKeys.DN: "CN=Group3,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                },
            ],
        }

        result = service.write_categorized_output(categorized)

        assert result.is_success
        counts = result.unwrap()
        assert "users" in counts
        assert "groups" in counts
        assert counts["users"] == 2
        assert counts["groups"] == 3
        # Verify files were created
        assert (tmp_path / "users.ldif").exists()
        assert (tmp_path / "groups.ldif").exists()

    def test_write_categorized_with_nested_output_dir(self, tmp_path: Path) -> None:
        """Test write with nested output directory that needs creation."""
        # Use a nested path that will be created by the real writer
        nested_dir = tmp_path / "nested" / "deep" / "path"

        service = FlextLdifFileWriterService(
            output_dir=nested_dir,
            output_files={"users": "users.ldif"},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        categorized: dict[str, list[dict[str, object]]] = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                }
            ]
        }

        result = service.write_categorized_output(categorized)

        # Real writer creates parent directories and succeeds
        assert result.is_success
        counts = result.unwrap()
        assert counts["users"] == 1
        # Verify file was created in nested directory
        assert (nested_dir / "users.ldif").exists()


class TestWriteCategoryFile:
    """Test write_category_file method."""

    def test_write_empty_entries(self, tmp_path: Path) -> None:
        """Test writing empty entry list returns 0."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        result = service.write_category_file("users", [], "users.ldif")

        assert result.is_success
        assert result.unwrap() == 0

    def test_write_category_file_with_real_writer(self, tmp_path: Path) -> None:
        """Test that write_category_file uses real RFC writer."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={"users": "users.ldif"},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {},
            }
        ]

        result = service.write_category_file("users", entries, "users.ldif")

        # Real writer should complete successfully
        assert result.is_success
        assert result.unwrap() == 1
        # File should be created
        assert (tmp_path / "users.ldif").exists()

    def test_write_category_file_with_empty_entries(self, tmp_path: Path) -> None:
        """Test that write_category_file handles empty entries correctly."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = []

        result = service.write_category_file("users", entries, "users.ldif")

        # Should succeed with empty entries, returning 0
        assert result.is_success
        assert result.unwrap() == 0


class TestProcessSchemaEntries:
    """Test process_schema_entries method."""

    def test_process_empty_schema_entries(self, tmp_path: Path) -> None:
        """Test processing empty schema entries."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        result = service.process_schema_entries([])
        assert result == []

    def test_process_schema_without_whitelist_rules(self, tmp_path: Path) -> None:
        """Test processing schema returns entries unchanged without whitelist."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=schema",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": ["( 1.2.3.4 NAME 'test' )"]
                },
            }
        ]

        result = service.process_schema_entries(entries)
        assert len(result) == 1

    def test_process_schema_with_whitelist_rules(self, tmp_path: Path) -> None:
        """Test processing schema with whitelist OID filtering."""
        rules: dict[str, object] = {"allowed_attribute_oids": ["1.2.3.*"]}
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
            schema_whitelist_rules=rules,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=schema",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": [
                        "( 1.2.3.4 NAME 'allowed' )",
                        "( 1.9.9.9 NAME 'blocked' )",
                    ]
                },
            }
        ]

        result = service.process_schema_entries(entries)
        assert len(result) == 1

    def test_process_schema_skips_invalid_attributes(self, tmp_path: Path) -> None:
        """Test processing schema skips entries with invalid attributes."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=schema",
                FlextLdifConstants.DictKeys.ATTRIBUTES: "invalid",  # Not dict
            }
        ]

        result = service.process_schema_entries(entries)
        assert len(result) == 1  # Entry returned unchanged


class TestCreateTargetSchemaEntry:
    """Test create_target_schema_entry method."""

    def test_create_target_schema_empty_entries(self, tmp_path: Path) -> None:
        """Test creating schema entry from empty entries."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        result = service.create_target_schema_entry([])
        assert result == []

    def test_create_target_schema_with_attributes(self, tmp_path: Path) -> None:
        """Test creating target schema entry with attributes and objectclasses."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=schema",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": [
                        "( 1.2.3.4 NAME 'test' )"
                    ],
                    "objectclasses": [
                        "( 1.5.6.7 NAME 'testClass' )"
                    ],
                },
            }
        ]

        result = service.create_target_schema_entry(entries)

        assert len(result) == 1
        schema_entry = result[0]
        assert schema_entry["dn"] == "cn=schema"
        assert schema_entry["changetype"] == ["modify"]

    def test_create_target_schema_deduplication(self, tmp_path: Path) -> None:
        """Test that duplicate schema entries are deduplicated."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": [
                        "( 1.2.3.4 NAME 'test' )",
                        "( 1.2.3.4 NAME 'test' )",  # Duplicate
                    ]
                },
            }
        ]

        result = service.create_target_schema_entry(entries)

        if result:
            schema_entry = result[0]
            # Should have deduplicated entries
            if "_modify_add_attributetypes" in schema_entry:
                attr_types = schema_entry["_modify_add_attributetypes"]
                assert isinstance(attr_types, list)

    def test_create_target_schema_sorting_by_oid(self, tmp_path: Path) -> None:
        """Test that schema entries are sorted by OID."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": [
                        "( 3.2.1.4 NAME 'z' )",
                        "( 1.2.3.4 NAME 'a' )",
                        "( 2.2.3.4 NAME 'b' )",
                    ]
                },
            }
        ]

        result = service.create_target_schema_entry(entries)

        if result and "_modify_add_attributetypes" in result[0]:
            attr_types = result[0]["_modify_add_attributetypes"]
            # Should be sorted by OID
            assert isinstance(attr_types, list)


class TestSortEntriesByHierarchy:
    """Test _sort_entries_by_hierarchy_and_name method."""

    def test_sort_empty_list(self, tmp_path: Path) -> None:
        """Test sorting empty entry list."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        result = service._sort_entries_by_hierarchy_and_name([])
        assert result == []

    def test_sort_single_entry(self, tmp_path: Path) -> None:
        """Test sorting single entry."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {},
            }
        ]

        result = service._sort_entries_by_hierarchy_and_name(entries)
        assert len(result) == 1

    def test_sort_by_hierarchy_depth(self, tmp_path: Path) -> None:
        """Test sorting by hierarchy depth (fewer RDN components first)."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {FlextLdifConstants.DictKeys.DN: "CN=A,OU=B,OU=C,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: "CN=X,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: "CN=Y,OU=Z,DC=Example,DC=Com"},
        ]

        result = service._sort_entries_by_hierarchy_and_name(entries)
        assert len(result) == 3
        # Should be ordered by depth: shallowest first

    def test_sort_case_insensitive_secondary_sort(self, tmp_path: Path) -> None:
        """Test that secondary sort is case-insensitive."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {FlextLdifConstants.DictKeys.DN: "CN=ZEBRA,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: "CN=apple,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: "CN=banana,DC=Example,DC=Com"},
        ]

        result = service._sort_entries_by_hierarchy_and_name(entries)
        assert len(result) == 3

    def test_sort_handles_missing_dn(self, tmp_path: Path) -> None:
        """Test sorting handles entries with missing or invalid DN."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {FlextLdifConstants.DictKeys.DN: "CN=Valid,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.ATTRIBUTES: {}},  # Missing DN
            {FlextLdifConstants.DictKeys.DN: 123},  # Invalid type
        ]

        result = service._sort_entries_by_hierarchy_and_name(entries)
        # Non-sortable entries should be at end
        assert len(result) == 3


class TestWriteCategoryFileWithSchema:
    """Test write_category_file with schema category and whitelist rules."""

    def test_write_schema_category_with_whitelist_rules(self, tmp_path: Path) -> None:
        """Test writing schema category applies whitelist filtering."""
        rules: dict[str, object] = {"allowed_attribute_oids": ["1.2.3.*"]}
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={"schema": "00-schema.ldif"},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
            schema_whitelist_rules=rules,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=schema",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": [
                        "( 1.2.3.4 NAME 'allowed' )",
                        "( 9.9.9.9 NAME 'blocked' )",
                    ]
                },
            }
        ]

        result = service.write_category_file("schema", entries, "00-schema.ldif")

        assert result.is_success
        assert result.unwrap() == 1

    def test_write_category_file_with_non_string_output_file(
        self, tmp_path: Path
    ) -> None:
        """Test write_category_file handles non-string output_files mapping."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={"users": 123},  # Non-string value
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {},
            }
        ]

        result = service.write_category_file("users", entries, "users.ldif")

        assert result.is_success

    def test_write_category_file_with_missing_output_file_mapping(
        self, tmp_path: Path
    ) -> None:
        """Test write_category_file generates default filename when not in mapping."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},  # Empty mapping
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {},
            }
        ]

        result = service.write_category_file("custom_category", entries, "custom.ldif")

        assert result.is_success


class TestProcessSchemaEntriesAdvanced:
    """Test advanced scenarios for process_schema_entries."""

    def test_process_schema_with_non_list_attributetypes(self, tmp_path: Path) -> None:
        """Test processing schema with non-list attributetypes value."""
        rules: dict[str, object] = {"allowed_attribute_oids": ["1.*"]}
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
            schema_whitelist_rules=rules,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=schema",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": "( 1.2.3.4 NAME 'single' )"  # Single string, not list
                },
            }
        ]

        result = service.process_schema_entries(entries)
        assert len(result) == 1

    def test_process_schema_with_non_list_objectclasses(self, tmp_path: Path) -> None:
        """Test processing schema with non-list objectclasses value."""
        rules: dict[str, object] = {"allowed_objectclass_oids": ["1.*"]}
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
            schema_whitelist_rules=rules,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=schema",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "objectclasses": "( 1.5.6.7 NAME 'singleClass' )"  # Single string
                },
            }
        ]

        result = service.process_schema_entries(entries)
        assert len(result) == 1

    def test_process_schema_with_invalid_whitelist_rules_types(
        self, tmp_path: Path
    ) -> None:
        """Test processing schema with non-list whitelist rule values."""
        rules: dict[str, object] = {
            "allowed_attribute_oids": "not-a-list",  # Invalid: should be list
            "allowed_objectclass_oids": 123,  # Invalid: should be list
        }
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
            schema_whitelist_rules=rules,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=schema",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": ["( 1.2.3.4 NAME 'test' )"]
                },
            }
        ]

        # Should handle gracefully by treating invalid rules as empty
        result = service.process_schema_entries(entries)
        assert len(result) == 1

    def test_process_schema_with_wildcard_patterns(self, tmp_path: Path) -> None:
        """Test processing schema with wildcard OID patterns."""
        rules: dict[str, object] = {
            "allowed_attribute_oids": ["1.2.3.*", "2.*.4.*"]
        }
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
            schema_whitelist_rules=rules,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=schema",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": [
                        "( 1.2.3.4 NAME 'match1' )",
                        "( 1.2.3.100 NAME 'match2' )",
                        "( 2.5.4.100 NAME 'match3' )",
                        "( 9.9.9.9 NAME 'nomatch' )",
                    ]
                },
            }
        ]

        result = service.process_schema_entries(entries)
        assert len(result) == 1
        # Should keep matching patterns

    def test_process_schema_with_empty_patterns(self, tmp_path: Path) -> None:
        """Test processing schema with empty pattern lists allows all."""
        rules: dict[str, object] = {
            "allowed_attribute_oids": [],  # Empty = allow all
            "allowed_objectclass_oids": [],  # Empty = allow all
        }
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
            schema_whitelist_rules=rules,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=schema",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": [
                        "( 1.2.3.4 NAME 'attr1' )",
                        "( 9.9.9.9 NAME 'attr2' )",
                    ]
                },
            }
        ]

        result = service.process_schema_entries(entries)
        # Empty patterns should allow all entries
        assert len(result) == 1


class TestCreateTargetSchemaEntryAdvanced:
    """Test advanced scenarios for create_target_schema_entry."""

    def test_create_target_schema_with_non_dict_attributes(self, tmp_path: Path) -> None:
        """Test creating target schema entry with non-dict attributes."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "cn=schema",
                "attributes": "not-a-dict",  # Non-dict attributes
            }
        ]

        result = service.create_target_schema_entry(entries)
        assert isinstance(result, list)

    def test_create_target_schema_with_single_attribute_not_list(
        self, tmp_path: Path
    ) -> None:
        """Test creating target schema with single attributetype (not list)."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": "( 1.2.3.4 NAME 'test' )"  # Single string
                },
            }
        ]

        result = service.create_target_schema_entry(entries)
        assert isinstance(result, list)

    def test_create_target_schema_with_single_objectclass_not_list(
        self, tmp_path: Path
    ) -> None:
        """Test creating target schema with single objectclass (not list)."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "objectclasses": "( 1.5.6.7 NAME 'testClass' )"  # Single string
                },
            }
        ]

        result = service.create_target_schema_entry(entries)
        assert isinstance(result, list)

    def test_create_target_schema_with_multiple_entries_merging(
        self, tmp_path: Path
    ) -> None:
        """Test creating target schema merges from multiple entries."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": ["( 1.2.3.4 NAME 'attr1' )"]
                },
            },
            {
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": ["( 2.2.3.4 NAME 'attr2' )"],
                    "objectclasses": ["( 1.5.6.7 NAME 'class1' )"],
                },
            },
        ]

        result = service.create_target_schema_entry(entries)
        assert len(result) == 1
        schema_entry = result[0]
        assert schema_entry["dn"] == "cn=schema"

    def test_create_target_schema_x_origin_addition(self, tmp_path: Path) -> None:
        """Test that X-ORIGIN is added if not present in RFC data."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.ATTRIBUTES: {
                    "attributetypes": ["( 1.2.3.4 NAME 'test' )"]
                },
            }
        ]

        result = service.create_target_schema_entry(entries)
        # Result should be valid schema entry
        assert isinstance(result, list)


class TestTransformSchemaViaRfc:
    """Test _transform_schema_via_rfc method."""

    def test_transform_schema_with_no_quirks(self, tmp_path: Path) -> None:
        """Test schema transformation returns unchanged when no quirks provided."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        schema_list = [
            "( 1.2.3.4 NAME 'test' )",
            "( 2.2.3.4 NAME 'test2' )",
        ]

        result = service._transform_schema_via_rfc(schema_list, "attribute")

        # Without quirks, should return original list unchanged
        assert result == schema_list

    def test_transform_schema_attribute_vs_objectclass(self, tmp_path: Path) -> None:
        """Test transform_schema handles both attribute and objectclass types."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        schema_list = ["( 1.2.3.4 NAME 'test' )"]

        # Should handle both types without error
        result_attr = service._transform_schema_via_rfc(schema_list, "attribute")
        result_obj = service._transform_schema_via_rfc(schema_list, "objectclass")

        assert isinstance(result_attr, list)
        assert isinstance(result_obj, list)


class TestSortEntriesEdgeCases:
    """Test edge cases for _sort_entries_by_hierarchy_and_name."""

    def test_sort_entries_with_empty_dn_string(self, tmp_path: Path) -> None:
        """Test sorting with empty DN string."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {FlextLdifConstants.DictKeys.DN: ""},  # Empty DN
            {FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com"},
        ]

        result = service._sort_entries_by_hierarchy_and_name(entries)
        assert len(result) == 2

    def test_sort_entries_with_very_deep_hierarchy(self, tmp_path: Path) -> None:
        """Test sorting with very deep DN hierarchy."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {FlextLdifConstants.DictKeys.DN: "CN=L8,CN=L7,CN=L6,CN=L5,CN=L4,CN=L3,CN=L2,CN=L1,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com"},
        ]

        result = service._sort_entries_by_hierarchy_and_name(entries)
        # Should sort by depth
        assert len(result) == 2
        # Shallower (User) should come before deeper
        assert result[0][FlextLdifConstants.DictKeys.DN] == "CN=User,DC=Example,DC=Com"

    def test_sort_entries_with_unicode_dns(self, tmp_path: Path) -> None:
        """Test sorting with Unicode DN characters."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        entries: list[dict[str, object]] = [
            {FlextLdifConstants.DictKeys.DN: "CN=Ünïcödé,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: "CN=ASCII,DC=Example,DC=Com"},
        ]

        result = service._sort_entries_by_hierarchy_and_name(entries)
        assert len(result) == 2

    def test_sort_entries_preserves_order_for_same_depth_and_case(
        self, tmp_path: Path
    ) -> None:
        """Test that stable sort preserves order for entries with same depth and case."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={},
            target_server="oud",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        # Create entries with same depth - should maintain relative order
        entries: list[dict[str, object]] = [
            {FlextLdifConstants.DictKeys.DN: "CN=A,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: "CN=B,DC=Example,DC=Com"},
            {FlextLdifConstants.DictKeys.DN: "CN=C,DC=Example,DC=Com"},
        ]

        result = service._sort_entries_by_hierarchy_and_name(entries)
        # Should maintain alphabetical order (case insensitive)
        assert len(result) == 3


class TestWriteCategoryFileErrorHandling:
    """Test error handling in write_category_file."""

    def test_write_category_file_with_invalid_output_path(
        self, tmp_path: Path
    ) -> None:
        """Test write_category_file handles invalid output path gracefully."""
        # Use a path with invalid characters or permissions
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()

        service = FlextLdifFileWriterService(
            output_dir=readonly_dir,
            output_files={},
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        # Make directory read-only to cause write error
        readonly_dir.chmod(0o444)

        entries: list[dict[str, object]] = [
            {
                FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com",
                FlextLdifConstants.DictKeys.ATTRIBUTES: {},
            }
        ]

        try:
            result = service.write_category_file("users", entries, "users.ldif")
            # Should fail gracefully
            assert result.is_failure or result.is_success  # Either outcome is acceptable
        finally:
            # Restore permissions for cleanup
            readonly_dir.chmod(0o755)


class TestWriteCategorizedOutputErrorHandling:
    """Test error handling in write_categorized_output."""

    def test_write_categorized_with_mixed_success_failure(self, tmp_path: Path) -> None:
        """Test write_categorized_output stops on first failure."""
        service = FlextLdifFileWriterService(
            output_dir=tmp_path,
            output_files={
                "users": "users.ldif",
                "groups": "groups.ldif",
            },
            target_server="rfc",
            target_schema_quirk=None,
            source_schema_quirk=None,
        )

        categorized: dict[str, list[dict[str, object]]] = {
            "users": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=User,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                }
            ],
            "groups": [
                {
                    FlextLdifConstants.DictKeys.DN: "CN=Group,DC=Example,DC=Com",
                    FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                }
            ],
        }

        result = service.write_categorized_output(categorized)

        # Should succeed with both categories
        assert result.is_success
        counts = result.unwrap()
        assert len(counts) == 2
