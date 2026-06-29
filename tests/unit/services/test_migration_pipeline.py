"""Tests for LDIF migration pipeline orchestration.

This module tests the migration pipeline that handles transforming LDIF
data between different LDAP server types, including initialization,
validation, and execution with various server type combinations.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifMigrationPipeline, FlextLdifProcessingPipeline
from tests import c, m, t
from tests.utilities import TestsFlextLdifUtilities as u

if TYPE_CHECKING:
    from tests.unit.fixtures import _MigrationPipelineFactory


_BASIC_RFC_ENTRY_LDIF = "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n"


class TestsTestFlextLdifMigrationPipeline:
    """Consolidated test suite for LDIF migration pipeline.

    Tests initialization, validation, execution with different server types.
    """

    def test_initialization_with_required_params(
        self,
        migration_pipeline_factory: _MigrationPipelineFactory,
        migration_dirs: t.Pair[Path, Path],
    ) -> None:
        """Test pipeline initializes with required parameters."""
        input_dir, output_dir = migration_dirs
        pipeline = migration_pipeline_factory(
            source_server_type=c.Tests.OID, target_server_type=c.Tests.OUD
        )
        tm.that(pipeline, none=False)
        tm.that(pipeline.input_dir, eq=input_dir)
        tm.that(pipeline.output_dir, eq=output_dir)
        tm.that(pipeline.source_server_type, eq=c.Tests.OID)
        tm.that(pipeline.target_server_type, eq=c.Tests.OUD)

    def test_initialization_with_defaults(
        self, migration_pipeline_factory: _MigrationPipelineFactory
    ) -> None:
        """Test pipeline initialization with default server types."""
        pipeline = migration_pipeline_factory()
        tm.that(pipeline, none=False)
        tm.that(pipeline.source_server_type, eq=c.Tests.RFC)
        tm.that(pipeline.target_server_type, eq=c.Tests.RFC)

    @pytest.mark.parametrize(
        ("source", "target"),
        [
            (c.Tests.OID, c.Tests.OUD),
            (c.Tests.OID, c.Tests.OPENLDAP),
            (c.Tests.OUD, c.Tests.OPENLDAP),
            (c.Tests.OPENLDAP, c.Tests.OID),
            (c.Tests.OPENLDAP, c.Tests.OUD),
            (c.Tests.RFC, c.Tests.RFC),
        ],
    )
    def test_initialization_with_different_server_types(
        self,
        source: str,
        target: str,
        migration_pipeline_factory: _MigrationPipelineFactory,
    ) -> None:
        """Test pipeline initialization with various server type combinations."""
        pipeline = migration_pipeline_factory(
            source_server_type=source, target_server_type=target
        )
        tm.that(pipeline, none=False)
        tm.that(pipeline.source_server_type, eq=source)
        tm.that(pipeline.target_server_type, eq=target)

    def test_execute_fails_with_no_input_dir(self) -> None:
        """Test pipeline fails when input directory is not specified."""
        pipeline = FlextLdifMigrationPipeline(
            source_server_type=c.Tests.OID, target_server_type=c.Tests.OUD
        )
        tm.fail(pipeline.execute(), has="input_dir")

    def test_execute_fails_with_no_output_dir(
        self, migration_dirs: t.Pair[Path, Path]
    ) -> None:
        """Test pipeline fails when output directory is not specified."""
        input_dir, _ = migration_dirs
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            source_server_type=c.Tests.OID,
            target_server_type=c.Tests.OUD,
        )
        tm.fail(pipeline.execute(), has="output_dir")

    def test_execute_fails_with_nonexistent_input_dir(
        self,
        migration_pipeline_factory: _MigrationPipelineFactory,
        tmp_path: Path,
    ) -> None:
        """Test pipeline fails when input directory doesn't exist."""
        tm.fail(
            migration_pipeline_factory(
                input_dir=tmp_path / "nonexistent",
                source_server_type=c.Tests.OID,
                target_server_type=c.Tests.OUD,
            ).execute(),
            has="not found",
        )

    def test_execute_creates_output_dir_if_missing(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: _MigrationPipelineFactory,
        tmp_path: Path,
    ) -> None:
        """Test pipeline creates output directory if it doesn't exist."""
        input_dir, _ = migration_dirs
        nonexistent_output = tmp_path / "nonexistent"
        (input_dir / "test.ldif").write_text(_BASIC_RFC_ENTRY_LDIF)
        tm.ok(migration_pipeline_factory(output_dir=nonexistent_output).execute())
        tm.that(nonexistent_output.exists(), eq=True)

    def test_execute_with_empty_input(
        self, migration_pipeline_factory: _MigrationPipelineFactory
    ) -> None:
        """Test pipeline handles empty input directory gracefully."""
        migration_result = tm.ok(migration_pipeline_factory().execute())
        tm.that(migration_result.stats.total_entries, eq=0)

    def test_basic_execution_rfc_to_rfc(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: _MigrationPipelineFactory,
    ) -> None:
        """Test basic migration from RFC to RFC."""
        input_dir, _ = migration_dirs
        (input_dir / "test.ldif").write_text(c.Tests.RFC_SAMPLE_LDIF_BASIC)
        migration_result = tm.ok(migration_pipeline_factory().execute())
        tm.that(migration_result.stats.processed_entries, gte=1)

    def test_migrate_entries_method(
        self, migration_pipeline_factory: _MigrationPipelineFactory
    ) -> None:
        """Test migrate_entries method directly."""
        entries = [
            m.Ldif.Entry(
                dn=m.Ldif.DN(value=c.Tests.DN_TEST),
                attributes=m.Ldif.Attributes(
                    attributes={"cn": ["test"], "objectClass": ["person"]},
                    attribute_metadata={},
                ),
            ),
        ]
        migrated = tm.ok(migration_pipeline_factory().migrate_entries(entries))
        tm.that(len(migrated), eq=1)

    def test_migrate_file_method(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: _MigrationPipelineFactory,
    ) -> None:
        """Test migrate_file method directly."""
        input_dir, _ = migration_dirs
        input_file = input_dir / "test.ldif"
        input_file.write_text(c.Tests.CONFIG_BASIC_ENTRY)
        migration_result = tm.ok(migration_pipeline_factory().migrate_file(input_file))
        tm.that(migration_result.stats.total_entries, gte=1)

    def test_execute_with_multiple_files(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: _MigrationPipelineFactory,
    ) -> None:
        """Test pipeline processes multiple input files."""
        input_dir, _ = migration_dirs
        (input_dir / "schema.ldif").write_text(
            "dn: cn=schema\nobjectClass: top\ncn: schema\n"
        )
        (input_dir / "data.ldif").write_text(_BASIC_RFC_ENTRY_LDIF)
        migration_result = tm.ok(migration_pipeline_factory().execute())
        tm.that(migration_result.stats.total_entries, gte=2)

    def test_migrate_file_not_found(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: _MigrationPipelineFactory,
    ) -> None:
        """Test migrate_file handles non-existent file gracefully."""
        input_dir, _ = migration_dirs
        tm.fail(
            migration_pipeline_factory().migrate_file(input_dir / "nonexistent.ldif"),
            has="not found",
        )

    def test_migrate_entries_empty_list(
        self, migration_pipeline_factory: _MigrationPipelineFactory
    ) -> None:
        """Test migrate_entries handles empty list gracefully."""
        migrated = tm.ok(migration_pipeline_factory().migrate_entries([]))
        tm.that(migrated, empty=True)

    @pytest.mark.parametrize(
        ("raw_server", "expected_server"),
        list(c.Tests.MIGRATION_COERCE_CASES.values()),
        ids=list(c.Tests.MIGRATION_COERCE_CASES.keys()),
    )
    def test_coerce_server_type_cases(
        self, raw_server: str, expected_server: str
    ) -> None:
        """Lines 117-121: coercion keeps known values and falls back on unknown input."""
        result = FlextLdifMigrationPipeline._coerce_server_type(raw_server)
        if raw_server == c.Tests.MIGRATION_UNKNOWN_SERVER:
            tm.that(result, eq=FlextLdifMigrationPipeline._DEFAULT_SERVER)
            return
        tm.that(result, eq=c.Ldif.ServerTypes(expected_server))

    def test_execute_with_file_that_fails_parse(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: _MigrationPipelineFactory,
    ) -> None:
        """Line 185: migration file that fails logs warning and execute continues."""
        input_dir, _ = migration_dirs
        (input_dir / "bad.ldif").write_bytes(c.Tests.WRITER_INVALID_UTF8_BYTES)
        migration_result = tm.ok(migration_pipeline_factory().execute())
        tm.that(migration_result.stats.total_entries, eq=0)

    def test_migrate_file_returns_fail_when_writer_fails(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: _MigrationPipelineFactory,
    ) -> None:
        """Line 281: migrate_file returns fail when writer reports failure."""
        input_dir, output_dir = migration_dirs
        input_file = input_dir / c.Tests.MIGRATION_INPUT_FILENAME
        input_file.write_text(c.Tests.MIGRATION_SINGLE_ENTRY_LDIF)
        output_as_directory = output_dir / "existing_dir"
        output_as_directory.mkdir()
        tm.fail(
            migration_pipeline_factory().migrate_file(
                input_file, output_file=output_as_directory
            ),
            has="Write failed",
        )

    def test_migrate_file_returns_fail_when_read_raises(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: _MigrationPipelineFactory,
    ) -> None:
        """Lines 292-304: migrate_file catches decoding/type errors from IO stage."""
        input_dir, _ = migration_dirs
        input_file = input_dir / c.Tests.MIGRATION_INPUT_FILENAME
        input_file.write_bytes(c.Tests.WRITER_INVALID_UTF8_BYTES)
        tm.fail(
            migration_pipeline_factory().migrate_file(input_file),
            has="File migration failed",
        )

    def test_migrate_file_with_no_output_dir_or_file_fails(
        self, migration_dirs: t.Pair[Path, Path]
    ) -> None:
        """Line 269: migrate_file with no output_dir and no output_file fails."""
        input_dir, _ = migration_dirs
        input_file = input_dir / "test.ldif"
        input_file.write_text(c.Tests.RFC_SAMPLE_LDIF_BASIC)
        pipeline = FlextLdifMigrationPipeline(
            source_server_type=c.Tests.RFC, target_server_type=c.Tests.RFC
        )
        tm.fail(pipeline.migrate_file(input_file, output_file=None))


class TestsFlextLdifProcessingPipeline:
    """Tests for FlextLdifProcessingPipeline service."""

    def test_execute_without_entries_fails(self) -> None:
        """Line 93: execute with no entries and no entries_input fails."""
        tm.fail(
            FlextLdifProcessingPipeline(transform_config=None).execute(),
            has="No entries provided",
        )

    def test_execute_with_entries_succeeds(self) -> None:
        """Line 94-95: execute with entries returns success."""
        entry = m.Ldif.Entry(
            dn=c.Tests.ANALYSIS_DN_VALID,
            attributes=m.Ldif.Attributes(attributes={}),
        )
        tm.ok(
            FlextLdifProcessingPipeline(
                transform_config=None, entries_input=[entry]
            ).execute()
        )

    @pytest.mark.parametrize(
        "field",
        ["normalize_dns", "normalize_attrs"],
    )
    def test_build_pipeline_with_normalization_and_process_config(
        self, field: str
    ) -> None:
        """Normalization flags with process_config trigger dedicated transforms."""
        transform_config = m.Ldif.TransformConfig(
            **{field: True},
            process_config=m.Ldif.ProcessConfig(
                source_server=c.Tests.RFC, target_server=c.Tests.RFC
            ),
        )
        tm.ok(
            FlextLdifProcessingPipeline(
                transform_config=transform_config, entries_input=[]
            ).execute()
        )

    def test_migrate_entries_base_dn_filters_out_of_scope_acl_bind_dn(self) -> None:
        # FlextLdifMigrationPipeline.base_dn threads through to the OID→OUD ACL
        # scope filter via for_servers → TransformConfig → transformer.
        entry = u.Tests.create_real_entry(
            dn="cn=users,dc=ctbc",
            attributes={
                "objectClass": ["top"],
                "orclaci": [
                    (
                        'access to entry by group="cn=x,dc=other" (browse) '
                        'by group="cn=a,dc=ctbc" (browse)'
                    ),
                ],
            },
        )
        pipeline = FlextLdifMigrationPipeline(
            source_server_type="oid",
            target_server_type="oud",
            base_dn="dc=ctbc",
        )

        migrated: t.MutableSequenceOf[m.Ldif.Entry] = u.Tests.assert_success(
            pipeline.migrate_entries([entry]),
        )
        assert migrated[0].attributes is not None

        tm.that(
            migrated[0].attributes.attributes["aci"],
            eq=[
                (
                    '(targetattr="*")(version 3.0; acl "users Entry by x"; '
                    'allow (read, search) groupdn="ldap:///cn=a,dc=ctbc";)'
                ),
            ],
        )
