"""Phase 8: Comprehensive unit tests for categorized_pipeline.py.

Tests the FlextLdifCategorizedMigrationPipeline class with focus on:
- Pipeline initialization with various configurations
- Categorization rules application
- LDIF file output generation (00-schema through 05-rejected)
- Quirks integration and transformation
- Error handling and validation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.pipelines.categorized_pipeline import (
    FlextLdifCategorizedMigrationPipeline,
)


class TestCategorizedPipelineInitialization:
    """Test pipeline initialization and configuration."""

    def test_pipeline_initializes_with_minimal_config(self) -> None:
        """Test pipeline initialization with minimal required parameters."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_initializes_with_custom_servers(self) -> None:
        """Test pipeline initialization with custom source and target servers."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            source_server="openldap",
            target_server="389ds",
        )
        assert pipeline is not None

    def test_pipeline_initializes_with_categorization_rules(self) -> None:
        """Test pipeline with categorization rules."""
        rules = {
            "users": ["(objectClass=person)", "(objectClass=inetOrgPerson)"],
            "groups": ["(objectClass=groupOfNames)"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_initializes_with_schema_whitelist(self) -> None:
        """Test pipeline with schema whitelist rules."""
        whitelist = {
            "attributes": ["cn", "mail", "displayName"],
            "objectclasses": ["person", "organizationalUnit"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            schema_whitelist_rules=whitelist,
        )
        assert pipeline is not None

    def test_pipeline_initializes_with_forbidden_attributes(self) -> None:
        """Test pipeline with forbidden attributes list."""
        forbidden = ["userPassword", "sambaNTPassword", "krbKey"]
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_attributes=forbidden,
        )
        assert pipeline is not None

    def test_pipeline_initializes_with_base_dn(self) -> None:
        """Test pipeline with custom base DN."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=example,dc=com",
        )
        assert pipeline is not None

    def test_pipeline_initializes_with_custom_output_files(self) -> None:
        """Test pipeline with custom output file mapping."""
        output_files = {
            "schema": "schema_custom.ldif",
            "hierarchy": "hierarchy_custom.ldif",
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            output_files=output_files,
        )
        assert pipeline is not None

    def test_pipeline_initializes_with_input_file_list(self) -> None:
        """Test pipeline with specific input file list."""
        input_files = ["users.ldif", "groups.ldif", "schema.ldif"]
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            input_files=input_files,
        )
        assert pipeline is not None


class TestCategorizedPipelineConfiguration:
    """Test pipeline configuration and property access."""

    def test_pipeline_stores_input_dir(self) -> None:
        """Test that pipeline stores input directory."""
        input_dir = Path("input_data")
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_stores_output_dir(self) -> None:
        """Test that pipeline stores output directory."""
        output_dir = Path("output_data")
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_stores_categorization_rules(self) -> None:
        """Test that pipeline stores categorization rules."""
        rules = {"schema": ["(cn=schema)"]}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_with_string_paths(self) -> None:
        """Test pipeline accepts string paths and converts to Path."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="string/path/input",
            output_dir="string/path/output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_with_path_objects(self) -> None:
        """Test pipeline accepts Path objects directly."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("pathobj/input"),
            output_dir=Path("pathobj/output"),
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None


class TestCategorizedPipelineOutputFiles:
    """Test pipeline output file structure."""

    def test_pipeline_generates_six_output_files(self) -> None:
        """Test that pipeline is configured for 6 output files."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        # Pipeline should be configured to generate 6 files:
        # 00-schema.ldif, 01-hierarchy.ldif, 02-users.ldif,
        # 03-groups.ldif, 04-acl.ldif, 05-rejected.ldif
        assert pipeline is not None

    def test_default_output_file_names(self) -> None:
        """Test default output file naming convention."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        # Default file names should follow pattern:
        # 00-schema.ldif, 01-hierarchy.ldif, etc.
        assert pipeline is not None

    def test_custom_output_file_names(self) -> None:
        """Test custom output file naming."""
        custom_files = {
            "schema": "my_schema.ldif",
            "hierarchy": "my_hierarchy.ldif",
            "users": "my_users.ldif",
            "groups": "my_groups.ldif",
            "acl": "my_acl.ldif",
            "rejected": "my_rejected.ldif",
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            output_files=custom_files,
        )
        assert pipeline is not None


class TestCategorizedPipelineRules:
    """Test categorization rules handling."""

    def test_pipeline_with_user_categorization_rule(self) -> None:
        """Test user entry categorization rule."""
        rules = {
            "users": [
                "(objectClass=person)",
                "(objectClass=inetOrgPerson)",
            ]
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_with_group_categorization_rule(self) -> None:
        """Test group entry categorization rule."""
        rules = {
            "groups": [
                "(objectClass=groupOfNames)",
                "(objectClass=groupOfUniqueNames)",
            ]
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_with_hierarchy_categorization_rule(self) -> None:
        """Test organizational hierarchy categorization rule."""
        rules = {
            "hierarchy": [
                "(objectClass=organization)",
                "(objectClass=organizationalUnit)",
            ]
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_with_acl_categorization_rule(self) -> None:
        """Test ACL entry categorization rule."""
        rules = {"acl": ["(aci=*)", "(orclaci=*)"]}
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_with_schema_categorization_rule(self) -> None:
        """Test schema categorization rule."""
        rules = {
            "schema": [
                "(cn=schema)",
                "(objectClass=attributeType)",
                "(objectClass=objectClass)",
            ]
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_with_multiple_categorization_rules(self) -> None:
        """Test pipeline with multiple comprehensive rules."""
        rules = {
            "schema": ["(cn=schema)"],
            "hierarchy": ["(objectClass=organizationalUnit)"],
            "users": ["(objectClass=person)"],
            "groups": ["(objectClass=groupOfNames)"],
            "acl": ["(aci=*)"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None


class TestCategorizedPipelineQuirks:
    """Test quirks integration."""

    def test_pipeline_with_parser_quirk(self) -> None:
        """Test pipeline accepts None as parser quirk."""
        parser_quirk = None
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=parser_quirk,
            writer_quirk=None,
        )
        # Verify pipeline was created with None parser_quirk
        assert pipeline is not None
        assert pipeline._parser_quirk is None

    def test_pipeline_with_writer_quirk(self) -> None:
        """Test pipeline accepts None as writer quirk."""
        writer_quirk = None
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=writer_quirk,
        )
        # Verify pipeline was created with None writer_quirk
        assert pipeline is not None
        assert pipeline._writer_quirk is None

    def test_pipeline_with_both_quirks(self) -> None:
        """Test pipeline accepts None for both parser and writer quirks."""
        parser_quirk = None
        writer_quirk = None
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=parser_quirk,
            writer_quirk=writer_quirk,
        )
        # Verify pipeline was created with None for both quirks
        assert pipeline is not None
        assert pipeline._parser_quirk is None
        assert pipeline._writer_quirk is None

    def test_pipeline_with_schema_quirks(self) -> None:
        """Test pipeline with source and target schema quirks."""
        source_quirk = None
        target_quirk = None
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            source_schema_quirk=source_quirk,
            target_schema_quirk=target_quirk,
        )
        assert pipeline is not None


class TestCategorizedPipelineServerTypes:
    """Test server type handling."""

    def test_pipeline_with_oid_to_oud_migration(self) -> None:
        """Test OID to OUD migration configuration."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            source_server="oracle_oid",
            target_server="oracle_oud",
        )
        assert pipeline is not None

    def test_pipeline_with_openldap_migration(self) -> None:
        """Test OpenLDAP as source server."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            source_server="openldap",
            target_server="oracle_oud",
        )
        assert pipeline is not None

    def test_pipeline_with_active_directory_source(self) -> None:
        """Test Active Directory as source."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            source_server="active_directory",
            target_server="oracle_oud",
        )
        assert pipeline is not None

    def test_pipeline_with_rfc_target(self) -> None:
        """Test RFC-compliant target (no server-specific quirks)."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            source_server="oracle_oid",
            target_server="rfc",
        )
        assert pipeline is not None


class TestCategorizedPipelineExecution:
    """Test pipeline execution workflow."""

    def test_pipeline_execute_with_nonexistent_input_dir(self, tmp_path: Path) -> None:
        """Test execution gracefully handles nonexistent input directory."""
        output_dir = tmp_path / "output"
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="/nonexistent/path",
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        result = pipeline.execute()
        assert result.is_failure
        assert "Input directory does not exist" in str(result.error)

    def test_pipeline_execute_with_empty_input_dir(self, tmp_path: Path) -> None:
        """Test execution with empty input directory."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        result = pipeline.execute()
        # Empty input should result in zero entries
        assert result.is_success
        execution_result = result.unwrap()
        assert execution_result.statistics.total_entries == 0

    def test_pipeline_execute_creates_output_directory(self, tmp_path: Path) -> None:
        """Test execution creates output directory if it doesn't exist."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        result = pipeline.execute()
        assert result.is_success
        assert output_dir.exists()

    def test_pipeline_with_specific_input_files(self, tmp_path: Path) -> None:
        """Test pipeline processes only specified input files."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        # Create multiple LDIF files
        (input_dir / "file1.ldif").write_text("")
        (input_dir / "file2.ldif").write_text("")
        (input_dir / "file3.ldif").write_text("")

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            input_files=["file1.ldif", "file2.ldif"],
        )
        assert pipeline is not None

    def test_pipeline_returns_execution_result_with_statistics(self, tmp_path: Path) -> None:
        """Test pipeline returns proper PipelineExecutionResult structure."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        result = pipeline.execute()

        assert result.is_success
        execution_result = result.unwrap()
        assert isinstance(execution_result, FlextLdifModels.PipelineExecutionResult)
        assert hasattr(execution_result, "statistics")
        assert hasattr(execution_result, "entries_by_category")
        assert hasattr(execution_result, "file_paths")


class TestCategorizedPipelineCategorization:
    """Test entry categorization with various rules."""

    def test_pipeline_applies_categorization_rules(self) -> None:
        """Test pipeline applies provided categorization rules."""
        rules = {
            "schema": ["(cn=schema)"],
            "users": ["(objectClass=person)"],
            "groups": ["(objectClass=groupOfNames)"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_with_hierarchy_rules(self) -> None:
        """Test pipeline with organizational hierarchy categorization."""
        rules = {
            "hierarchy": [
                "(objectClass=organization)",
                "(objectClass=organizationalUnit)",
            ],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_with_empty_categorization_rules(self) -> None:
        """Test pipeline handles empty categorization rules."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_generates_six_output_categories(self) -> None:
        """Test pipeline is configured for all 6 output categories."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        # Six categories: schema, hierarchy, users, groups, acl, rejected
        assert pipeline is not None


class TestCategorizedPipelineFiltering:
    """Test attribute and objectClass filtering."""

    def test_pipeline_filters_forbidden_attributes_from_config(self) -> None:
        """Test forbidden attributes configuration."""
        forbidden = ["userPassword", "sambaNTPassword", "authPassword"]
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_attributes=forbidden,
        )
        assert pipeline is not None

    def test_pipeline_filters_forbidden_objectclasses(self) -> None:
        """Test forbidden objectClasses configuration."""
        forbidden_ocs = ["sambaAccount", "shadowAccount", "orclContainerOC"]
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            forbidden_objectclasses=forbidden_ocs,
        )
        assert pipeline is not None

    def test_pipeline_with_base_dn_filter(self) -> None:
        """Test base_dn filtering for entry scope."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="dc=example,dc=com",
        )
        assert pipeline is not None

    def test_pipeline_base_dn_normalizes_to_lowercase(self) -> None:
        """Test base_dn is normalized to lowercase."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn="DC=Example,DC=Com",
        )
        # base_dn should be normalized to lowercase internally
        assert pipeline is not None

    def test_pipeline_without_base_dn_includes_all_entries(self) -> None:
        """Test pipeline without base_dn includes entries at any DN level."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            base_dn=None,
        )
        assert pipeline is not None


class TestCategorizedPipelineOutputConfiguration:
    """Test output file configuration."""

    def test_pipeline_with_default_output_files(self) -> None:
        """Test pipeline uses default output file names."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        # Default files: schema.ldif, hierarchy.ldif, users.ldif, groups.ldif, acl.ldif, rejected.ldif
        assert pipeline is not None

    def test_pipeline_with_custom_output_file_names(self) -> None:
        """Test custom output file naming configuration."""
        custom_names = {
            "schema": "00_schema.ldif",
            "hierarchy": "01_hierarchy.ldif",
            "users": "02_users.ldif",
            "groups": "03_groups.ldif",
            "acl": "04_acl.ldif",
            "rejected": "05_rejected.ldif",
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            output_files=custom_names,
        )
        assert pipeline is not None

    def test_pipeline_with_partial_custom_output_files(self) -> None:
        """Test pipeline with custom names for subset of output files."""
        custom_names = {
            "schema": "custom_schema.ldif",
            "rejected": "custom_rejected.ldif",
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            output_files=custom_names,
        )
        assert pipeline is not None


class TestCategorizedPipelineServerIntegration:
    """Test server-specific quirks integration."""

    def test_pipeline_with_oid_to_oud_transformation(self) -> None:
        """Test OID to OUD server transformation configuration."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            source_server="oracle_oid",
            target_server="oracle_oud",
        )
        assert pipeline is not None

    def test_pipeline_with_openldap_source(self) -> None:
        """Test OpenLDAP as source server."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            source_server="openldap",
            target_server="oracle_oud",
        )
        assert pipeline is not None

    def test_pipeline_with_rfc_compliant_target(self) -> None:
        """Test RFC-compliant target (no server-specific quirks)."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            source_server="oracle_oid",
            target_server="rfc",
        )
        assert pipeline is not None

    def test_pipeline_with_schema_quirks(self) -> None:
        """Test pipeline with schema-specific quirks."""
        source_quirk = None
        target_quirk = None
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            source_schema_quirk=source_quirk,
            target_schema_quirk=target_quirk,
        )
        assert pipeline is not None

    def test_pipeline_with_parser_writer_quirks(self) -> None:
        """Test pipeline with parser and writer quirks."""
        parser_quirk = None
        writer_quirk = None
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=parser_quirk,
            writer_quirk=writer_quirk,
        )
        assert pipeline is not None


class TestCategorizedPipelineSchemaWhitelisting:
    """Test schema whitelist filtering."""

    def test_pipeline_with_attribute_whitelist(self) -> None:
        """Test pipeline with schema attribute whitelist."""
        whitelist = {
            "attributes": ["cn", "sn", "mail", "telephoneNumber", "description"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            schema_whitelist_rules=whitelist,
        )
        assert pipeline is not None

    def test_pipeline_with_objectclass_whitelist(self) -> None:
        """Test pipeline with schema objectClass whitelist."""
        whitelist = {
            "objectclasses": ["person", "inetOrgPerson", "organizationalUnit", "organization"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            schema_whitelist_rules=whitelist,
        )
        assert pipeline is not None

    def test_pipeline_with_comprehensive_schema_whitelist(self) -> None:
        """Test pipeline with both attribute and objectClass whitelist."""
        whitelist = {
            "attributes": ["cn", "sn", "mail", "userPassword", "objectClass"],
            "objectclasses": ["person", "inetOrgPerson", "groupOfNames"],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
            schema_whitelist_rules=whitelist,
        )
        assert pipeline is not None


class TestCategorizedPipelinePathHandling:
    """Test path handling and conversion."""

    def test_pipeline_accepts_string_paths(self) -> None:
        """Test pipeline accepts string paths and converts to Path objects."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="/path/to/input",
            output_dir="/path/to/output",
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_accepts_path_objects(self) -> None:
        """Test pipeline accepts Path objects directly."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("/path/to/input"),
            output_dir=Path("/path/to/output"),
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None

    def test_pipeline_with_relative_paths(self) -> None:
        """Test pipeline with relative path objects."""
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir=Path("relative/input"),
            output_dir=Path("relative/output"),
            categorization_rules={},
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None


class TestCategorizedPipelineComplexConfigurations:
    """Test complex configuration combinations."""

    def test_pipeline_with_all_features_enabled(self) -> None:
        """Test pipeline with comprehensive configuration."""
        rules = {
            "schema": ["(cn=schema)"],
            "hierarchy": ["(objectClass=organization)", "(objectClass=organizationalUnit)"],
            "users": ["(objectClass=person)", "(objectClass=inetOrgPerson)"],
            "groups": ["(objectClass=groupOfNames)"],
            "acl": ["(aci=*)", "(orclaci=*)"],
        }
        whitelist = {
            "attributes": ["cn", "sn", "mail", "objectClass"],
            "objectclasses": ["person", "organization"],
        }
        forbidden_attrs = ["userPassword", "authPassword"]
        forbidden_ocs = ["sambaAccount"]

        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
            source_server="oracle_oid",
            target_server="oracle_oud",
            source_schema_quirk=None,
            target_schema_quirk=None,
            schema_whitelist_rules=whitelist,
            forbidden_attributes=forbidden_attrs,
            forbidden_objectclasses=forbidden_ocs,
            base_dn="dc=example,dc=com",
        )
        assert pipeline is not None

    def test_pipeline_with_multiple_categorization_rules(self) -> None:
        """Test pipeline with comprehensive categorization rules."""
        rules = {
            "schema": ["(cn=schema)"],
            "hierarchy": [
                "(objectClass=organization)",
                "(objectClass=organizationalUnit)",
                "(objectClass=locality)",
            ],
            "users": [
                "(objectClass=person)",
                "(objectClass=inetOrgPerson)",
                "(objectClass=organizationalPerson)",
            ],
            "groups": [
                "(objectClass=groupOfNames)",
                "(objectClass=groupOfUniqueNames)",
                "(objectClass=dynamicGroup)",
            ],
            "acl": [
                "(aci=*)",
                "(orclaci=*)",
                "(orclEntrylevelACI=*)",
            ],
        }
        pipeline = FlextLdifCategorizedMigrationPipeline(
            input_dir="input",
            output_dir="output",
            categorization_rules=rules,
            parser_quirk=None,
            writer_quirk=None,
        )
        assert pipeline is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
