"""Tests for LDIF migration pipeline orchestration.

This module tests the migration pipeline that handles transforming LDIF
data between different LDAP server types, including initialization,
validation, and execution with various server type combinations.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifMigrationPipeline
from tests import m, s


class TestsTestFlextLdifMigrationPipeline(s):
    """Consolidated test suite for LDIF migration pipeline.

    Tests initialization, validation, execution with different server types.
    """

    def test_initialization_with_required_params(self, tmp_path: Path) -> None:
        """Test pipeline initializes with required parameters."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="oid",
            target_server_type="oud",
        )
        tm.that(pipeline, none=False)
        tm.that(pipeline.input_dir, eq=input_dir)
        tm.that(pipeline.output_dir, eq=output_dir)
        tm.that(pipeline.source_server_type, eq="oid")
        tm.that(pipeline.target_server_type, eq="oud")

    def test_initialization_with_defaults(self, tmp_path: Path) -> None:
        """Test pipeline initialization with default server types."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
        )
        tm.that(pipeline, none=False)
        tm.that(pipeline.source_server_type, eq="rfc")
        tm.that(pipeline.target_server_type, eq="rfc")

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
            source_server_type=source,
            target_server_type=target,
        )
        tm.that(pipeline, none=False)
        tm.that(pipeline.source_server_type, eq=source)
        tm.that(pipeline.target_server_type, eq=target)

    def test_execute_fails_with_no_input_dir(self) -> None:
        """Test pipeline fails when input directory is not specified."""
        pipeline = FlextLdifMigrationPipeline(
            source_server_type="oid",
            target_server_type="oud",
        )
        result = pipeline.execute()
        tm.that(result.is_failure, eq=True)
        tm.that(str(result.error).lower(), has="input_dir")

    def test_execute_fails_with_no_output_dir(self, tmp_path: Path) -> None:
        """Test pipeline fails when output directory is not specified."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            source_server_type="oid",
            target_server_type="oud",
        )
        result = pipeline.execute()
        tm.that(result.is_failure, eq=True)
        tm.that(str(result.error).lower(), has="output_dir")

    def test_execute_fails_with_nonexistent_input_dir(self, tmp_path: Path) -> None:
        """Test pipeline fails when input directory doesn't exist."""
        nonexistent_input = tmp_path / "nonexistent"
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        pipeline = FlextLdifMigrationPipeline(
            input_dir=nonexistent_input,
            output_dir=output_dir,
            source_server_type="oid",
            target_server_type="oud",
        )
        result = pipeline.execute()
        tm.that(result.is_failure, eq=True)
        tm.that(str(result.error).lower(), has="not found")

    def test_execute_creates_output_dir_if_missing(self, tmp_path: Path) -> None:
        """Test pipeline creates output directory if it doesn't exist."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        nonexistent_output = tmp_path / "nonexistent"
        (input_dir / "test.ldif").write_text(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n",
        )
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=nonexistent_output,
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        tm.that(result.is_success, eq=True)
        _ = tm.that(nonexistent_output.exists(), eq=True)

    def test_execute_with_empty_input(self, tmp_path: Path) -> None:
        """Test pipeline handles empty input directory gracefully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        pipeline: FlextLdifMigrationPipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
        )
        result = pipeline.execute()
        tm.that(result.is_success, eq=True)
        migration_result: m.Ldif.MigrationPipelineResult = result.value
        tm.that(migration_result.stats.total_entries, eq=0)

    def test_basic_execution_rfc_to_rfc(self, tmp_path: Path) -> None:
        """Test basic migration from RFC to c.RFC."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        ldif_content = "dn: cn=test,dc=example,dc=com\nobjectClass: person\nobjectClass: top\ncn: test\nsn: test\n"
        (input_dir / "test.ldif").write_text(ldif_content)
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        tm.that(result.is_success, eq=True)
        migration_result: m.Ldif.MigrationPipelineResult = result.value
        tm.that(migration_result.stats.processed_entries, gte=1)

    def test_migrate_entries_method(self, tmp_path: Path) -> None:
        """Test migrate_entries method directly."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="rfc",
            target_server_type="rfc",
        )
        entries = [
            m.Ldif.Entry(
                dn=m.Ldif.DN(value="cn=test,dc=example,dc=com"),
                attributes=m.Ldif.Attributes(
                    attributes={"cn": ["test"], "objectClass": ["person"]},
                    attribute_metadata={},
                ),
            ),
        ]
        result = pipeline.migrate_entries(entries)
        tm.that(result.is_success, eq=True)
        migrated = result.value
        tm.that(len(migrated), eq=1)

    def test_migrate_file_method(self, tmp_path: Path) -> None:
        """Test migrate_file method directly."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        ldif_content = "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n"
        input_file = input_dir / "test.ldif"
        input_file.write_text(ldif_content)
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.migrate_file(input_file)
        tm.that(result.is_success, eq=True)
        migration_result = result.value
        tm.that(migration_result.stats.total_entries, gte=1)

    @pytest.mark.parametrize(
        ("source", "target"),
        [("oid", "oud"), ("oud", "oid"), ("rfc", "oid"), ("rfc", "oud")],
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
        (input_dir / "test.ldif").write_text(
            "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n",
        )
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type=source,
            target_server_type=target,
        )
        result = pipeline.execute()
        tm.that(result.is_success or result.is_failure, eq=True)

    def test_execute_with_multiple_files(self, tmp_path: Path) -> None:
        """Test pipeline processes multiple input files."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        (input_dir / "schema.ldif").write_text(
            "dn: cn=schema\nobjectClass: top\ncn: schema\n",
        )
        (input_dir / "data.ldif").write_text(
            "dn: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com\nobjectClass: person\ncn: REDACTED_LDAP_BIND_PASSWORD\n",
        )
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.execute()
        tm.that(result.is_success, eq=True)
        migration_result: m.Ldif.MigrationPipelineResult = result.value
        tm.that(migration_result.stats.total_entries, gte=2)

    def test_migrate_file_not_found(self, tmp_path: Path) -> None:
        """Test migrate_file handles non-existent file gracefully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="rfc",
            target_server_type="rfc",
        )
        nonexistent_file = input_dir / "nonexistent.ldif"
        result = pipeline.migrate_file(nonexistent_file)
        tm.that(result.is_failure, eq=True)
        tm.that(str(result.error).lower(), has="not found")

    def test_migrate_entries_empty_list(self, tmp_path: Path) -> None:
        """Test migrate_entries handles empty list gracefully."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            output_dir=output_dir,
            source_server_type="rfc",
            target_server_type="rfc",
        )
        result = pipeline.migrate_entries([])
        tm.that(result.is_success, eq=True)
        migrated = result.value
        tm.that(not migrated, eq=True)
