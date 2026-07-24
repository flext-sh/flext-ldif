"""Behavioral tests for LDIF migration pipeline orchestration.

These tests exercise only the public contract of the migration and processing
pipeline services: constructor-configured public fields, the ``r[T]`` outcome of
fallible operations (``execute`` / ``migrate_file`` / ``migrate_entries``), and
the public model state of the returned results. No private attributes, private
methods, or internal collaborators are touched.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from flext_ldif.services.migration import FlextLdifMigrationPipeline
from flext_ldif.services.pipeline import FlextLdifProcessingPipeline
from tests import TestsFlextLdifUtilities as u, c, m, p, t

if TYPE_CHECKING:
    from pathlib import Path

_BASIC_RFC_ENTRY_LDIF = "dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\n"

_KNOWN_COERCE_CASES = {
    key: case
    for key, case in c.Tests.MIGRATION_COERCE_CASES.items()
    if case[0] != c.Tests.MIGRATION_UNKNOWN_SERVER
}


class TestsFlextLdifMigrationPipeline:
    """Behavioral suite for the migration and processing pipeline services.

    Covers public initialization contract, fallible-operation ``r[T]`` outcomes,
    and public result model state for both ``FlextLdifMigrationPipeline`` and its
    delegate ``FlextLdifProcessingPipeline``.
    """

    # ── Initialization contract (public fields) ──────────────────────────

    def test_initialization_exposes_supplied_configuration(
        self,
        migration_pipeline_factory: p.Tests.MigrationPipelineFactory,
        migration_dirs: t.Pair[Path, Path],
    ) -> None:
        """Supplied directories and server types surface on public fields."""
        input_dir, output_dir = migration_dirs
        pipeline = migration_pipeline_factory(
            source_server_type=c.Tests.OID, target_server_type=c.Tests.OUD
        )
        assert pipeline is not None
        tm.that(pipeline.input_dir, eq=input_dir)
        tm.that(pipeline.output_dir, eq=output_dir)
        tm.that(pipeline.source_server_type, eq=c.Ldif.ServerTypes(c.Tests.OID))
        tm.that(pipeline.target_server_type, eq=c.Ldif.ServerTypes(c.Tests.OUD))

    def test_initialization_defaults_to_rfc_server_types(
        self, migration_pipeline_factory: p.Tests.MigrationPipelineFactory
    ) -> None:
        """Omitting server types yields the RFC default on both public fields."""
        pipeline = migration_pipeline_factory()
        assert pipeline is not None
        tm.that(pipeline.source_server_type, eq=c.Ldif.ServerTypes(c.Tests.RFC))
        tm.that(pipeline.target_server_type, eq=c.Ldif.ServerTypes(c.Tests.RFC))

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
    def test_initialization_preserves_server_type_pairs(
        self,
        source: str,
        target: str,
        migration_pipeline_factory: p.Tests.MigrationPipelineFactory,
    ) -> None:
        """Each known source/target pair round-trips onto the public fields."""
        pipeline = migration_pipeline_factory(
            source_server_type=source, target_server_type=target
        )
        tm.that(pipeline.source_server_type, eq=c.Ldif.ServerTypes(source))
        tm.that(pipeline.target_server_type, eq=c.Ldif.ServerTypes(target))

    @pytest.mark.parametrize(
        ("raw_server", "expected_server"),
        list(_KNOWN_COERCE_CASES.values()),
        ids=list(_KNOWN_COERCE_CASES.keys()),
    )
    def test_known_server_type_input_normalizes_on_public_fields(
        self,
        raw_server: str,
        expected_server: str,
        migration_pipeline_factory: p.Tests.MigrationPipelineFactory,
    ) -> None:
        """Case-insensitive known server input maps to its canonical member.

        Exercised purely through construction: the public ``source_server_type``
        / ``target_server_type`` fields expose the normalized ``ServerTypes``.
        """
        pipeline = migration_pipeline_factory(
            source_server_type=raw_server, target_server_type=raw_server
        )
        tm.that(pipeline.source_server_type, eq=c.Ldif.ServerTypes(expected_server))
        tm.that(pipeline.target_server_type, eq=c.Ldif.ServerTypes(expected_server))

    def test_unknown_server_type_input_is_rejected_at_construction(
        self, migration_pipeline_factory: p.Tests.MigrationPipelineFactory
    ) -> None:
        """An unrecognized server type is rejected when building the pipeline.

        Observable public behavior: construction with an unknown server type
        raises a validation error rather than silently producing an instance.
        (The RFC fallback in the coercion helper is not reachable through the
        public constructor, so this asserts the real contract, not the intent.)
        """
        with pytest.raises(ValueError, match="FlextLdifMigrationPipeline"):
            migration_pipeline_factory(
                source_server_type=c.Tests.MIGRATION_UNKNOWN_SERVER,
                target_server_type=c.Tests.MIGRATION_UNKNOWN_SERVER,
            )

    # ── execute() fallible outcomes ──────────────────────────────────────

    def test_execute_fails_without_input_dir(self) -> None:
        """execute() returns failure naming input_dir when none was configured."""
        pipeline = FlextLdifMigrationPipeline(
            source_server_type=c.Tests.OID, target_server_type=c.Tests.OUD
        )
        tm.fail(pipeline.execute(), has="input_dir")

    def test_execute_fails_without_output_dir(
        self, migration_dirs: t.Pair[Path, Path]
    ) -> None:
        """execute() returns failure naming output_dir when none was configured."""
        input_dir, _ = migration_dirs
        pipeline = FlextLdifMigrationPipeline(
            input_dir=input_dir,
            source_server_type=c.Tests.OID,
            target_server_type=c.Tests.OUD,
        )
        tm.fail(pipeline.execute(), has="output_dir")

    def test_execute_fails_when_input_dir_missing(
        self,
        migration_pipeline_factory: p.Tests.MigrationPipelineFactory,
        tmp_path: Path,
    ) -> None:
        """execute() reports 'not found' when the input directory is absent."""
        tm.fail(
            migration_pipeline_factory(
                input_dir=tmp_path / "nonexistent",
                source_server_type=c.Tests.OID,
                target_server_type=c.Tests.OUD,
            ).execute(),
            has="not found",
        )

    def test_execute_creates_missing_output_dir(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: p.Tests.MigrationPipelineFactory,
        tmp_path: Path,
    ) -> None:
        """A successful execute() materializes the configured output directory."""
        input_dir, _ = migration_dirs
        nonexistent_output = tmp_path / "nonexistent"
        (input_dir / "test.ldif").write_text(_BASIC_RFC_ENTRY_LDIF)
        tm.ok(migration_pipeline_factory(output_dir=nonexistent_output).execute())
        tm.that(nonexistent_output.exists(), eq=True)

    def test_execute_with_empty_input_reports_zero_entries(
        self, migration_pipeline_factory: p.Tests.MigrationPipelineFactory
    ) -> None:
        """An empty input directory succeeds with zero total entries."""
        migration_result = tm.ok(migration_pipeline_factory().execute())
        tm.that(migration_result.stats.total_entries, eq=0)

    def test_execute_rfc_to_rfc_processes_entries(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: p.Tests.MigrationPipelineFactory,
    ) -> None:
        """An RFC-to-RFC run reports at least one processed entry."""
        input_dir, _ = migration_dirs
        (input_dir / "test.ldif").write_text(c.Tests.RFC_SAMPLE_LDIF_BASIC)
        migration_result = tm.ok(migration_pipeline_factory().execute())
        tm.that(migration_result.stats.processed_entries, gte=1)

    def test_execute_aggregates_across_multiple_files(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: p.Tests.MigrationPipelineFactory,
    ) -> None:
        """execute() sums entries across every ``*.ldif`` input file."""
        input_dir, _ = migration_dirs
        (input_dir / "schema.ldif").write_text(
            "dn: cn=schema\nobjectClass: top\ncn: schema\n"
        )
        (input_dir / "data.ldif").write_text(_BASIC_RFC_ENTRY_LDIF)
        migration_result = tm.ok(migration_pipeline_factory().execute())
        tm.that(migration_result.stats.total_entries, gte=2)

    def test_execute_continues_when_a_file_fails_to_parse(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: p.Tests.MigrationPipelineFactory,
    ) -> None:
        """A single unparsable file is skipped; execute() still succeeds."""
        input_dir, _ = migration_dirs
        (input_dir / "bad.ldif").write_bytes(c.Tests.WRITER_INVALID_UTF8_BYTES)
        migration_result = tm.ok(migration_pipeline_factory().execute())
        tm.that(migration_result.stats.total_entries, eq=0)

    # ── migrate_entries() fallible outcomes ──────────────────────────────

    def test_migrate_entries_returns_migrated_entries(
        self, migration_pipeline_factory: p.Tests.MigrationPipelineFactory
    ) -> None:
        """migrate_entries() yields one output entry per input entry."""
        entries = [
            m.Ldif.Entry(
                dn=m.Ldif.DN(value=c.Tests.DN_TEST),
                attributes=m.Ldif.Attributes(
                    attributes={"cn": ["test"], "objectClass": ["person"]},
                    attribute_metadata={},
                ),
            )
        ]
        migrated = tm.ok(migration_pipeline_factory().migrate_entries(entries))
        tm.that(len(migrated), eq=1)

    def test_migrate_entries_with_empty_list_returns_empty(
        self, migration_pipeline_factory: p.Tests.MigrationPipelineFactory
    ) -> None:
        """migrate_entries([]) succeeds with an empty result."""
        migrated = tm.ok(migration_pipeline_factory().migrate_entries([]))
        tm.that(migrated, empty=True)

    def test_migrate_entries_base_dn_filters_out_of_scope_acl_bind_dn(self) -> None:
        """base_dn threads to the OID→OUD ACL scope filter, dropping out-of-scope binds.

        Observable contract: the migrated entry's public ``aci`` attribute retains
        only the in-scope ACL clause and is rewritten to OUD syntax.
        """
        entry = u.Tests.create_real_entry(
            dn="cn=users,dc=ctbc",
            attributes={
                "objectClass": ["top"],
                "orclaci": [
                    (
                        'access to entry by group="cn=x,dc=other" (browse) '
                        'by group="cn=a,dc=ctbc" (browse)'
                    )
                ],
            },
        )
        pipeline = FlextLdifMigrationPipeline(
            source_server_type="oid", target_server_type="oud", base_dn="dc=ctbc"
        )

        migrated: t.MutableSequenceOf[p.Ldif.Entry] = u.Tests.assert_success(
            pipeline.migrate_entries([entry])
        )
        assert migrated[0].attributes is not None
        tm.that(
            migrated[0].attributes.attributes["aci"],
            eq=[
                (
                    '(targetattr="*")(version 3.0; acl "users Entry by x"; '
                    'allow (read, search) groupdn="ldap:///cn=a,dc=ctbc";)'
                )
            ],
        )

    # ── migrate_file() fallible outcomes and result state ────────────────

    def test_migrate_file_reports_total_entries(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: p.Tests.MigrationPipelineFactory,
    ) -> None:
        """migrate_file() succeeds and reports the parsed entry count."""
        input_dir, _ = migration_dirs
        input_file = input_dir / "test.ldif"
        input_file.write_text(c.Tests.CONFIG_BASIC_ENTRY)
        migration_result = tm.ok(migration_pipeline_factory().migrate_file(input_file))
        tm.that(migration_result.stats.total_entries, gte=1)

    def test_migrate_file_fails_when_file_missing(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: p.Tests.MigrationPipelineFactory,
    ) -> None:
        """migrate_file() on an absent path returns a 'not found' failure."""
        input_dir, _ = migration_dirs
        tm.fail(
            migration_pipeline_factory().migrate_file(input_dir / "nonexistent.ldif"),
            has="not found",
        )

    def test_migrate_file_fails_when_write_target_is_a_directory(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: p.Tests.MigrationPipelineFactory,
    ) -> None:
        """A write that cannot complete surfaces as a 'Write failed' failure."""
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

    def test_migrate_file_fails_on_undecodable_input(
        self,
        migration_dirs: t.Pair[Path, Path],
        migration_pipeline_factory: p.Tests.MigrationPipelineFactory,
    ) -> None:
        """Undecodable bytes surface as a 'File migration failed' failure."""
        input_dir, _ = migration_dirs
        input_file = input_dir / c.Tests.MIGRATION_INPUT_FILENAME
        input_file.write_bytes(c.Tests.WRITER_INVALID_UTF8_BYTES)
        tm.fail(
            migration_pipeline_factory().migrate_file(input_file),
            has="File migration failed",
        )

    def test_migrate_file_fails_without_output_target(
        self, migration_dirs: t.Pair[Path, Path]
    ) -> None:
        """migrate_file() fails when neither output_dir nor output_file is given."""
        input_dir, _ = migration_dirs
        input_file = input_dir / "test.ldif"
        input_file.write_text(c.Tests.RFC_SAMPLE_LDIF_BASIC)
        pipeline = FlextLdifMigrationPipeline(
            source_server_type=c.Tests.RFC, target_server_type=c.Tests.RFC
        )
        tm.fail(pipeline.migrate_file(input_file, output_file=None))

    # ── FlextLdifProcessingPipeline (delegate) public contract ───────────

    def test_processing_execute_fails_without_entries(self) -> None:
        """Processing execute() fails when no entry batch was provided."""
        tm.fail(
            FlextLdifProcessingPipeline(transform_config=None).execute(),
            has="No entries provided",
        )

    def test_processing_execute_succeeds_with_entries(self) -> None:
        """Processing execute() succeeds when an entry batch is supplied."""
        entry = m.Ldif.Entry(
            dn=c.Tests.ANALYSIS_DN_VALID, attributes=m.Ldif.Attributes(attributes={})
        )
        tm.ok(
            FlextLdifProcessingPipeline(
                transform_config=None, entries_input=[entry]
            ).execute()
        )

    @pytest.mark.parametrize("field", ["normalize_dns", "normalize_attrs"])
    def test_processing_execute_succeeds_with_normalization_config(
        self, field: str
    ) -> None:
        """Normalization flags with a process_config execute successfully."""
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
