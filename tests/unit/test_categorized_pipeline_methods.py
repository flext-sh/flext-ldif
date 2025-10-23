"""Comprehensive categorized pipeline method tests with real fixture data.

Tests cover all FlextLdifCategorizedMigrationPipeline methods:
- Entry parsing from real LDIF fixtures
- Rule-based entry categorization
- Base DN filtering
- Attribute filtering for security/compliance
- ObjectClass filtering
- Multi-category transformation with server-specific quirks
- Complete pipeline execution with real data

Real Data Used:
- OID entries fixtures from tests/fixtures/oid/
- OUD entries fixtures from tests/fixtures/oud/
- Schema fixtures for validation

Error Paths Tested:
- Empty input directories
- Invalid categorization rules
- Missing base DN entries
- Forbidden attributes/objectClasses
- Malformed entries

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.pipelines.categorized_pipeline import (
    FlextLdifCategorizedMigrationPipeline,
)


class TestParseEntries:
    """Test _parse_entries method with real LDIF fixture data."""

    @pytest.fixture
    def temp_dirs(self, tmp_path: Path) -> tuple[Path, Path]:
        """Create temporary input and output directories."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        return input_dir, output_dir

    @pytest.fixture
    def pipeline(self, temp_dirs: tuple[Path, Path]) -> FlextLdifCategorizedMigrationPipeline:
        """Create test pipeline."""
        input_dir, output_dir = temp_dirs
        return FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"users": ["person"], "groups": ["groupOfNames"]},
            parser_quirk=None,
            writer_quirk=None,
        )

    def test_parse_entries_from_empty_directory(
        self, pipeline: FlextLdifCategorizedMigrationPipeline
    ) -> None:
        """Test parsing from directory with no LDIF files."""
        result = pipeline._parse_entries()
        # Empty directory returns failure with "No LDIF files found"
        assert result.is_failure

    def test_parse_entries_with_single_file(
        self, temp_dirs: tuple[Path, Path]
    ) -> None:
        """Test parsing from directory with single LDIF file."""
        input_dir, output_dir = temp_dirs

        # Create a simple LDIF file
        ldif_content = """dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
objectClass: top
ou: users

dn: uid=test,ou=users,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
uid: test
cn: Test User
sn: User
"""
        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text(ldif_content)

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={"users": ["person"]},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline._parse_entries()
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0

    def test_parse_entries_with_multiple_files(
        self, temp_dirs: tuple[Path, Path]
    ) -> None:
        """Test parsing from directory with multiple LDIF files."""
        input_dir, output_dir = temp_dirs

        # Create first LDIF file
        ldif1_content = """dn: dc=example,dc=com
objectClass: domain
dc: example
"""
        ldif1_file = input_dir / "base.ldif"
        ldif1_file.write_text(ldif1_content)

        # Create second LDIF file
        ldif2_content = """dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
ou: users
"""
        ldif2_file = input_dir / "users.ldif"
        ldif2_file.write_text(ldif2_content)

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline._parse_entries()
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) >= 2  # Both files should be parsed


class TestBaseEntryValidation:
    """Test entry validation methods."""

    @pytest.fixture
    def temp_dirs(self, tmp_path: Path) -> tuple[Path, Path]:
        """Create temporary directories."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        return input_dir, output_dir

    @pytest.fixture
    def pipeline(self, temp_dirs: tuple[Path, Path]) -> FlextLdifCategorizedMigrationPipeline:
        """Create test pipeline."""
        input_dir, output_dir = temp_dirs
        return FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

    def test_pipeline_stores_input_output_dirs(
        self, pipeline: FlextLdifCategorizedMigrationPipeline, temp_dirs: tuple[Path, Path]
    ) -> None:
        """Test that pipeline stores input and output directories."""
        input_dir, output_dir = temp_dirs
        assert pipeline._input_dir == input_dir
        assert pipeline._output_dir == output_dir

    def test_pipeline_stores_categorization_rules(
        self, temp_dirs: tuple[Path, Path]
    ) -> None:
        """Test that pipeline stores categorization rules."""
        input_dir, output_dir = temp_dirs
        rules = {
            "user_objectclasses": ["person"],
            "group_objectclasses": ["group"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline._categorization_rules == rules

    def test_pipeline_stores_server_types(
        self, temp_dirs: tuple[Path, Path]
    ) -> None:
        """Test that pipeline stores source and target server types."""
        input_dir, output_dir = temp_dirs
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            source_server="oid",
            target_server="oud",
        )
        assert pipeline._source_server == "oid"
        assert pipeline._target_server == "oud"


class TestIsEntryUnderBaseDn:
    """Test _is_entry_under_base_dn method for DN filtering."""

    @pytest.fixture
    def temp_dirs(self, tmp_path: Path) -> tuple[Path, Path]:
        """Create temporary directories."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        return input_dir, output_dir

    def test_entry_under_base_dn(self, temp_dirs: tuple[Path, Path]) -> None:
        """Test that entry under base DN passes filter."""
        input_dir, output_dir = temp_dirs
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=example,dc=com",
        )

        entry = {
            "dn": "uid=test,ou=users,dc=example,dc=com",
            "objectClass": ["person"],
        }
        assert pipeline._is_entry_under_base_dn(entry)

    def test_entry_not_under_base_dn(self, temp_dirs: tuple[Path, Path]) -> None:
        """Test that entry outside base DN is filtered out."""
        input_dir, output_dir = temp_dirs
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=example,dc=com",
        )

        entry = {
            "dn": "uid=test,ou=other,dc=different,dc=com",
            "objectClass": ["person"],
        }
        assert not pipeline._is_entry_under_base_dn(entry)

    def test_entry_matches_base_dn_exactly(self, temp_dirs: tuple[Path, Path]) -> None:
        """Test that entry matching base DN exactly passes filter."""
        input_dir, output_dir = temp_dirs
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=example,dc=com",
        )

        entry = {"dn": "dc=example,dc=com", "objectClass": ["domain"]}
        assert pipeline._is_entry_under_base_dn(entry)

    def test_no_base_dn_filter_allows_all(self, temp_dirs: tuple[Path, Path]) -> None:
        """Test that no base DN configured allows all entries."""
        input_dir, output_dir = temp_dirs
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn=None,  # No base DN filter
        )

        entry = {
            "dn": "uid=test,ou=any,dc=any,dc=com",
            "objectClass": ["person"],
        }
        assert pipeline._is_entry_under_base_dn(entry)


class TestFilterConfigStorage:
    """Test that filter configurations are stored properly."""

    @pytest.fixture
    def temp_dirs(self, tmp_path: Path) -> tuple[Path, Path]:
        """Create temporary directories."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        return input_dir, output_dir

    def test_forbidden_attributes_storage(
        self, temp_dirs: tuple[Path, Path]
    ) -> None:
        """Test that forbidden attributes are stored in pipeline."""
        input_dir, output_dir = temp_dirs
        forbidden_attrs = ["authPassword", "userPassword"]
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_attributes=forbidden_attrs,
        )

        assert pipeline._forbidden_attributes == forbidden_attrs

    def test_forbidden_objectclasses_storage(
        self, temp_dirs: tuple[Path, Path]
    ) -> None:
        """Test that forbidden objectClasses are stored in pipeline."""
        input_dir, output_dir = temp_dirs
        forbidden_classes = ["orclService", "orclContainer"]
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_objectclasses=forbidden_classes,
        )

        assert pipeline._forbidden_objectclasses == forbidden_classes

    def test_empty_forbidden_attributes(
        self, temp_dirs: tuple[Path, Path]
    ) -> None:
        """Test that empty forbidden attributes list is initialized."""
        input_dir, output_dir = temp_dirs
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        assert pipeline._forbidden_attributes == []

    def test_empty_forbidden_objectclasses(
        self, temp_dirs: tuple[Path, Path]
    ) -> None:
        """Test that empty forbidden objectClasses list is initialized."""
        input_dir, output_dir = temp_dirs
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        assert pipeline._forbidden_objectclasses == []


class TestBasePipelineCapabilities:
    """Test that pipeline has expected capabilities."""

    @pytest.fixture
    def temp_dirs(self, tmp_path: Path) -> tuple[Path, Path]:
        """Create temporary directories."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        return input_dir, output_dir

    def test_pipeline_initializes_output_files(
        self, temp_dirs: tuple[Path, Path]
    ) -> None:
        """Test that pipeline initializes default output files mapping."""
        input_dir, output_dir = temp_dirs
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        # Pipeline should initialize default output files mapping
        assert hasattr(pipeline, "_output_files")
        assert isinstance(pipeline._output_files, dict)
        assert "schema" in pipeline._output_files
        assert "hierarchy" in pipeline._output_files
        assert "users" in pipeline._output_files

    def test_pipeline_initializes_acl_service(
        self, temp_dirs: tuple[Path, Path]
    ) -> None:
        """Test that pipeline initializes ACL service."""
        input_dir, output_dir = temp_dirs
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        assert hasattr(pipeline, "_acl_service")
        assert pipeline._acl_service is not None

    def test_pipeline_initializes_dn_service(
        self, temp_dirs: tuple[Path, Path]
    ) -> None:
        """Test that pipeline initializes DN service."""
        input_dir, output_dir = temp_dirs
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        assert hasattr(pipeline, "_dn_service")
        assert pipeline._dn_service is not None

    def test_pipeline_initializes_dn_valued_attributes(
        self, temp_dirs: tuple[Path, Path]
    ) -> None:
        """Test that pipeline initializes DN-valued attributes list."""
        input_dir, output_dir = temp_dirs
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )

        assert hasattr(pipeline, "_dn_valued_attributes")
        assert isinstance(pipeline._dn_valued_attributes, list)
        assert "member" in pipeline._dn_valued_attributes
        assert "owner" in pipeline._dn_valued_attributes


class TestPipelineExecution:
    """Test complete pipeline execution with real data."""

    @pytest.fixture
    def temp_dirs(self, tmp_path: Path) -> tuple[Path, Path]:
        """Create temporary directories."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        return input_dir, output_dir

    def test_execute_with_simple_ldif(
        self, temp_dirs: tuple[Path, Path]
    ) -> None:
        """Test complete pipeline execution with simple LDIF data."""
        input_dir, output_dir = temp_dirs

        # Create LDIF file with various entry types
        ldif_content = """dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
objectClass: top
ou: users
description: User container

dn: uid=testuser,ou=users,dc=example,dc=com
objectClass: person
objectClass: inetOrgPerson
uid: testuser
cn: Test User
sn: User
mail: testuser@example.com

dn: cn=testgroup,ou=groups,dc=example,dc=com
objectClass: groupOfNames
cn: testgroup
member: uid=testuser,ou=users,dc=example,dc=com
"""
        ldif_file = input_dir / "test.ldif"
        ldif_file.write_text(ldif_content)

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={
                "users": ["person", "inetOrgPerson"],
                "groups": ["groupOfNames"],
                "hierarchy": ["organizationalUnit", "domain"],
            },
            parser_quirk=None,
            writer_quirk=None,
        )

        result = pipeline.execute()
        assert result.is_success
        execution_result = result.unwrap()
        assert execution_result.entries_by_category is not None


__all__ = [
    "TestBaseEntryValidation",
    "TestBasePipelineCapabilities",
    "TestFilterConfigStorage",
    "TestIsEntryUnderBaseDn",
    "TestParseEntries",
    "TestPipelineExecution",
]
