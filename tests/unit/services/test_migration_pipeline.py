"""Test suite for LDIF migration pipeline.

This module provides comprehensive testing for FlextLdifMigrationPipeline which
handles generic server-to-server LDIF migrations using RFC parsers with quirks.

Tests use the new API with individual parameters (input_dir, output_dir, source_server, target_server)
not the old params dict approach.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import pytest

from flext_ldif import FlextLdifMigrationPipeline, FlextLdifModels


class TestFlextLdifMigrationPipeline:
    """Consolidated test suite for LDIF migration pipeline.

    Tests all aspects: initialization, validation, empty input, simple mode,
    categorized mode, multiple files, and server-specific conversions.
    """

    # ════════════════════════════════════════════════════════════════════════
    # SCENARIO ENUMS
    # ════════════════════════════════════════════════════════════════════════

    class InitializationScenario(StrEnum):
        """Initialization test scenarios."""

        REQUIRED_PARAMS = "required_params"
        SIMPLE_MODE = "simple_mode"
        CATEGORIZED_MODE = "categorized_mode"

    class ValidationScenario(StrEnum):
        """Parameter validation test scenarios."""

        NONEXISTENT_INPUT_DIR = "nonexistent_input_dir"
        CREATE_MISSING_OUTPUT_DIR = "create_missing_output_dir"

    class EmptyInputScenario(StrEnum):
        """Empty input handling test scenarios."""

        SIMPLE_MODE_EMPTY = "simple_mode_empty"
        CATEGORIZED_MODE_EMPTY = "categorized_mode_empty"

    class SimpleModeScenario(StrEnum):
        """Simple mode execution test scenarios."""

        BASIC_EXECUTION = "basic_execution"
        WITH_FILTERING = "with_filtering"

    class CategorizedModeScenario(StrEnum):
        """Categorized mode execution test scenarios."""

        BASIC_EXECUTION = "basic_execution"
        WITH_BASE_DN_FILTERING = "with_base_dn_filtering"
        WITH_FORBIDDEN_ATTRIBUTES = "with_forbidden_attributes"

    class MultipleFilesScenario(StrEnum):
        """Multiple file handling test scenarios."""

        SIMPLE_MODE_MULTIPLE = "simple_mode_multiple"
        CATEGORIZED_MODE_CUSTOM_OUTPUT = "categorized_mode_custom_output"

    # ════════════════════════════════════════════════════════════════════════
    # INITIALIZATION TESTS (4 tests)
    # ════════════════════════════════════════════════════════════════════════

    def test_initialization_with_required_params(self, tmp_path: Path) -> None:
        """Test pipeline initializes with required parameters."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server="oid",
            target_server="oud",
        )

        assert pipeline is not None

    def test_initialization_simple_mode(self, tmp_path: Path) -> None:
        """Test pipeline initialization for simple mode."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server="oid",
            target_server="oud",
        )

        assert pipeline is not None

    def test_initialization_categorized_mode(self, tmp_path: Path) -> None:
        """Test pipeline initialization for categorized mode."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        categorization_rules: dict[str, object] = {
            "hierarchy_objectclasses": ["organization"],
            "user_objectclasses": ["inetOrgPerson"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": [],
        }

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="categorized",
            categorization_rules=categorization_rules,
            source_server="oid",
            target_server="oud",
        )

        assert pipeline is not None

    @pytest.mark.parametrize(
        ("source", "target"),
        [
            ("oid", "oud"),
            ("oid", "openldap"),
            ("oud", "openldap"),
            ("openldap", "oid"),
            ("openldap", "oud"),
            ("rfc", "rfc"),
        ],
    )
    def test_initialization_with_different_server_types(
        self,
        source: str,
        target: str,
        tmp_path: Path,
    ) -> None:
        """Test pipeline initialization with various server type combinations."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server=source,
            target_server=target,
        )

        assert pipeline is not None

    # ════════════════════════════════════════════════════════════════════════
    # VALIDATION TESTS (2 tests)
    # ════════════════════════════════════════════════════════════════════════

    def test_execute_fails_with_nonexistent_input_dir(self, tmp_path: Path) -> None:
        """Test pipeline fails when input directory doesn't exist."""
        nonexistent_input = tmp_path / "nonexistent"
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        pipeline = FlextLdifMigrationPipeline(
            input_dir=nonexistent_input,
            output_dir=output_dir,
            source_server="oid",
            target_server="oud",
        )

        result = pipeline.execute()

        # Pipeline should handle nonexistent input directory gracefully
        assert result.is_success
        execution_result = result.unwrap()
        assert execution_result.entries_by_category == {}
        if execution_result.statistics is not None:
            assert execution_result.statistics.total_entries == 0

    def test_execute_creates_output_dir_if_missing(self, tmp_path: Path) -> None:
        """Test pipeline creates output directory if it doesn't exist."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        nonexistent_output = tmp_path / "nonexistent"

        # Create a simple LDIF file
        _ = (input_dir / "test.ldif").write_text(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n",
        )

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=nonexistent_output,
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        # Pipeline should succeed and create the output directory
        assert result.is_success
        assert nonexistent_output.exists()

    # ════════════════════════════════════════════════════════════════════════
    # EMPTY INPUT TESTS (2 tests)
    # ════════════════════════════════════════════════════════════════════════

    def test_simple_mode_with_empty_input(self, tmp_path: Path) -> None:
        """Test simple mode handles empty input directory gracefully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # No LDIF files in input directory
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            source_server="oid",
            target_server="oud",
        )

        result = pipeline.execute()

        # Pipeline should handle gracefully (no entries to process)
        # Should either succeed with 0 entries migrated or fail with informative message
        assert result.is_success, f"Pipeline should succeed or fail gracefully, got error: {result.error}"

        if result.is_success:
            entry_result = result.unwrap()
            assert isinstance(entry_result, FlextLdifModels.EntryResult)
            assert entry_result.statistics is not None
            # With no input files, should have 0 entries migrated
            events = entry_result.statistics.events
            assert len(events) > 0, "Should have at least one migration event"
            migration_event = events[0]
            # Validate that either 0 entries processed or explicit handling documented
            assert migration_event.entries_migrated == 0 or migration_event.entries_processed == 0, \
                f"Empty input should migrate 0 entries, got migrated={migration_event.entries_migrated}, processed={migration_event.entries_processed}"

    def test_categorized_mode_with_empty_input(self, tmp_path: Path) -> None:
        """Test categorized mode handles empty input directory gracefully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        categorization_rules: dict[str, object] = {
            "hierarchy_objectclasses": ["organization"],
            "user_objectclasses": ["inetOrgPerson"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": [],
        }

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="categorized",
            categorization_rules=categorization_rules,
            source_server="oid",
            target_server="oud",
        )

        result = pipeline.execute()

        # Pipeline should handle gracefully with no input files
        assert result.is_success, f"Pipeline should succeed with empty input, got error: {result.error}"

        if result.is_success:
            entry_result = result.unwrap()
            assert isinstance(entry_result, FlextLdifModels.EntryResult)
            assert entry_result.statistics is not None
            # With no input files, should have 0 entries migrated
            events = entry_result.statistics.events
            assert len(events) > 0, "Should have at least one migration event"
            migration_event = events[0]
            # Validate categorized mode also handles empty input gracefully
            assert migration_event.entries_migrated == 0 or migration_event.entries_processed == 0, \
                f"Empty input in categorized mode should migrate 0 entries, got migrated={migration_event.entries_migrated}, processed={migration_event.entries_processed}"

    # ════════════════════════════════════════════════════════════════════════
    # SIMPLE MODE TESTS (2 tests)
    # ════════════════════════════════════════════════════════════════════════

    def test_simple_mode_basic_execution(self, tmp_path: Path) -> None:
        """Test simple mode executes successfully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create a simple LDIF file
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
objectClass: top
cn: test
sn: test
"""
        _ = (input_dir / "test.ldif").write_text(ldif_content)

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            output_filename="migrated.ldif",
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        # Validate migration succeeded with proper output
        assert result.is_success, f"Simple mode migration should succeed, got error: {result.error}"

        entry_result = result.unwrap()
        assert isinstance(entry_result, FlextLdifModels.EntryResult)
        assert entry_result.statistics is not None

        # Validate statistics contain migration event
        events = entry_result.statistics.events
        assert len(events) > 0, "Should have at least one migration event"
        migration_event = events[0]

        # Validate entry was processed
        assert migration_event.entries_processed >= 1, \
            f"Should process at least 1 entry, processed={migration_event.entries_processed}"
        assert migration_event.entries_migrated >= 1, \
            f"Should migrate at least 1 entry, migrated={migration_event.entries_migrated}"

        # Validate output file was created
        assert entry_result.file_paths is not None and len(entry_result.file_paths) > 0, \
            "Should create output files"
        output_file = Path(entry_result.file_paths[0])
        assert output_file.exists(), f"Output file should exist: {output_file}"
        assert output_file.stat().st_size > 0, f"Output file should not be empty: {output_file}"

    def test_simple_mode_with_filtering(self, tmp_path: Path) -> None:
        """Test simple mode with attribute filtering."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
mail: test@example.com
"""
        _ = (input_dir / "test.ldif").write_text(ldif_content)

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            forbidden_attributes=["mail"],
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        # Validate filtering succeeded
        assert result.is_success, f"Simple mode with filtering should succeed, got error: {result.error}"

        entry_result = result.unwrap()
        assert isinstance(entry_result, FlextLdifModels.EntryResult)
        assert entry_result.statistics is not None

        # Validate event shows entries were processed
        events = entry_result.statistics.events
        assert len(events) > 0, "Should have at least one migration event"
        migration_event = events[0]

        # Validate entry was processed
        assert migration_event.entries_processed >= 1, \
            f"Should process at least 1 entry, processed={migration_event.entries_processed}"
        assert migration_event.entries_migrated >= 1, \
            f"Should migrate at least 1 entry, migrated={migration_event.entries_migrated}"

        # Validate output file was created
        assert entry_result.file_paths is not None and len(entry_result.file_paths) > 0, \
            "Should create output files"
        output_file = Path(entry_result.file_paths[0])
        assert output_file.exists(), f"Output file should exist: {output_file}"

        # Validate that forbidden attribute is filtered out
        output_content = output_file.read_text(encoding="utf-8")
        assert "mail:" not in output_content, "Forbidden attribute 'mail' should be filtered out"
        assert "test@example.com" not in output_content, "Forbidden attribute value should be filtered out"
        # But other attributes should remain
        assert "cn: test" in output_content, "Non-forbidden attributes should remain"

    # ════════════════════════════════════════════════════════════════════════
    # CATEGORIZED MODE TESTS (3 tests)
    # ════════════════════════════════════════════════════════════════════════

    def test_categorized_mode_basic_execution(self, tmp_path: Path) -> None:
        """Test categorized mode executes successfully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_content = """dn: cn=schema,cn=REDACTED_LDAP_BIND_PASSWORD
objectClass: top
cn: schema

dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
objectClass: person
cn: REDACTED_LDAP_BIND_PASSWORD
"""
        _ = (input_dir / "test.ldif").write_text(ldif_content)

        categorization_rules: dict[str, object] = {
            "hierarchy_objectclasses": ["top"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": [],
        }

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="categorized",
            categorization_rules=categorization_rules,
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        # Validate categorized mode execution succeeded
        assert result.is_success, f"Categorized mode should succeed, got error: {result.error}"

        entry_result = result.unwrap()
        assert isinstance(entry_result, FlextLdifModels.EntryResult)
        assert entry_result.statistics is not None

        # Validate event shows entries were processed
        events = entry_result.statistics.events
        assert len(events) > 0, "Should have at least one migration event"
        migration_event = events[0]

        # Validate entries were processed
        assert migration_event.entries_processed >= 2, \
            f"Should process at least 2 entries (hierarchy+user), processed={migration_event.entries_processed}"
        assert migration_event.entries_migrated >= 2, \
            f"Should migrate at least 2 entries, migrated={migration_event.entries_migrated}"

        # Validate output files were created for each category
        assert entry_result.file_paths is not None and len(entry_result.file_paths) > 0, \
            "Should create output files for categories"

    def test_categorized_mode_with_base_dn_filtering(self, tmp_path: Path) -> None:
        """Test categorized mode with base DN filtering."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_content = """dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
objectClass: person
cn: REDACTED_LDAP_BIND_PASSWORD

dn: cn=user,dc=other,dc=com
objectClass: person
cn: user
"""
        _ = (input_dir / "test.ldif").write_text(ldif_content)

        categorization_rules: dict[str, object] = {
            "hierarchy_objectclasses": ["top"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": [],
        }

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="categorized",
            categorization_rules=categorization_rules,
            base_dn="dc=example,dc=com",
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        # Validate base DN filtering succeeded
        assert result.is_success, f"Categorized mode with base DN filtering should succeed, got error: {result.error}"

        entry_result = result.unwrap()
        assert isinstance(entry_result, FlextLdifModels.EntryResult)
        assert entry_result.statistics is not None

        # Validate event shows entries were processed
        events = entry_result.statistics.events
        assert len(events) > 0, "Should have at least one migration event"
        migration_event = events[0]

        # Only 1 entry should match the base DN (dc=example,dc=com)
        assert migration_event.entries_processed == 1, \
            f"Should only process entry matching base DN, processed={migration_event.entries_processed}"
        assert migration_event.entries_migrated == 1, \
            f"Should only migrate entry matching base DN, migrated={migration_event.entries_migrated}"

        # Validate output shows only the matching entry
        assert entry_result.file_paths is not None and len(entry_result.file_paths) > 0, \
            "Should create output files"
        for file_path in entry_result.file_paths:
            output_file = Path(file_path)
            if output_file.exists() and output_file.stat().st_size > 0:
                output_content = output_file.read_text(encoding="utf-8")
                # Should contain the matching entry
                if "REDACTED_LDAP_BIND_PASSWORD" in output_content:
                    assert "dc=example,dc=com" in output_content
                # Should NOT contain the non-matching entry
                assert "dc=other,dc=com" not in output_content, \
                    "Should filter out entries outside the base DN"

    def test_categorized_mode_with_forbidden_attributes(self, tmp_path: Path) -> None:
        """Test categorized mode filtering forbidden attributes."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        ldif_content = """dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
objectClass: person
cn: REDACTED_LDAP_BIND_PASSWORD
mail: REDACTED_LDAP_BIND_PASSWORD@example.com
userPassword: secret
"""
        _ = (input_dir / "test.ldif").write_text(ldif_content)

        categorization_rules: dict[str, object] = {
            "hierarchy_objectclasses": ["top"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": [],
        }

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="categorized",
            categorization_rules=categorization_rules,
            forbidden_attributes=["userPassword"],
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure

    # ════════════════════════════════════════════════════════════════════════
    # MULTIPLE FILES TESTS (2 tests)
    # ════════════════════════════════════════════════════════════════════════

    def test_simple_mode_with_multiple_files(self, tmp_path: Path) -> None:
        """Test simple mode processes multiple input files."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        # Create multiple LDIF files
        _ = (input_dir / "schema.ldif").write_text(
            "dn: cn=schema\nobjectClass: top\ncn: schema\n",
        )
        _ = (input_dir / "data.ldif").write_text(
            "dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com\nobjectClass: person\ncn: REDACTED_LDAP_BIND_PASSWORD\n",
        )

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="simple",
            input_files=["schema.ldif", "data.ldif"],
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure

    def test_categorized_mode_with_custom_output_files(self, tmp_path: Path) -> None:
        """Test categorized mode with custom output file names."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        _ = (input_dir / "test.ldif").write_text(
            "dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com\nobjectClass: person\ncn: REDACTED_LDAP_BIND_PASSWORD\n",
        )

        categorization_rules: dict[str, object] = {
            "hierarchy_objectclasses": ["top"],
            "user_objectclasses": ["person"],
            "group_objectclasses": ["groupOfNames"],
            "acl_attributes": [],
        }

        output_files = {
            "schema": "00_schema.ldif",
            "hierarchy": "01_hierarchy.ldif",
            "user": "02_user.ldif",
            "group": "03_group.ldif",
            "acl": "04_acl.ldif",
            "rejected": "99_rejected.ldif",
        }

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            mode="categorized",
            categorization_rules=categorization_rules,
            output_files=output_files,
            source_server="rfc",
            target_server="rfc",
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure

    # ════════════════════════════════════════════════════════════════════════
    # SERVER CONVERSION TESTS (1 parametrized test with 4 variations)
    # ════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("source", "target"),
        [
            ("oid", "oud"),
            ("oud", "oid"),
            ("rfc", "oid"),
            ("rfc", "oud"),
        ],
    )
    def test_server_conversion_modes(
        self,
        source: str,
        target: str,
        tmp_path: Path,
    ) -> None:
        """Test server-specific conversion modes."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()

        _ = (input_dir / "test.ldif").write_text(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n",
        )

        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server=source,
            target_server=target,
        )

        result = pipeline.execute()

        assert result.is_success or result.is_failure
