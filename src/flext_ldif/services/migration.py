"""Migration Pipeline Service - Server-to-Server LDIF Migration."""

from __future__ import annotations

import struct
from collections.abc import Sequence
from pathlib import Path
from typing import Final, override

from flext_core import FlextLogger
from pydantic import PrivateAttr

from flext_ldif import (
    FlextLdifParser,
    FlextLdifProcessingPipeline,
    FlextLdifProcessingPipelineService,
    FlextLdifWriter,
    c,
    m,
    r,
    s,
)

logger: Final = FlextLogger(__name__)


class FlextLdifMigrationPipeline(s[m.Ldif.MigrationPipelineResult]):
    """Migration Pipeline for Server-to-Server LDIF Migration."""

    _input_dir: Path | None = PrivateAttr(default=None)
    _output_dir: Path | None = PrivateAttr(default=None)
    _source_server: c.Ldif.ServerTypes = PrivateAttr(default=c.Ldif.ServerTypes.RFC)
    _target_server: c.Ldif.ServerTypes = PrivateAttr(default=c.Ldif.ServerTypes.RFC)
    _processing_pipeline_service: FlextLdifProcessingPipelineService = PrivateAttr()
    _output_filename: str | None = PrivateAttr(default=None)

    def __init__(
        self,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        source_server: str = "rfc",
        target_server: str = "rfc",
        source_server_type: str | None = None,
        target_server_type: str | None = None,
        output_filename: str | None = None,
        **_kwargs: str | float | bool | None,
    ) -> None:
        """Initialize migration pipeline."""
        super().__init__()
        effective_source_server = source_server_type or source_server
        effective_target_server = target_server_type or target_server
        object.__setattr__(self, "_input_dir", input_dir)
        object.__setattr__(self, "_output_dir", output_dir)
        object.__setattr__(self, "_source_server", effective_source_server)
        object.__setattr__(self, "_target_server", effective_target_server)
        object.__setattr__(self, "_output_filename", output_filename)
        object.__setattr__(
            self,
            "_processing_pipeline_service",
            FlextLdifProcessingPipelineService(),
        )

    @property
    def input_dir(self) -> Path | None:
        """Get input directory."""
        return getattr(self, "_input_dir", None)

    @property
    def output_dir(self) -> Path | None:
        """Get output directory."""
        return getattr(self, "_output_dir", None)

    @property
    def output_filename(self) -> str | None:
        """Get output filename override."""
        return getattr(self, "_output_filename", None)

    @property
    def source_server_type(self) -> c.Ldif.ServerTypes:
        """Get source server type."""
        val = getattr(self, "_source_server", c.Ldif.ServerTypes.RFC)
        if issubclass(val.__class__, c.Ldif.ServerTypes):
            return val
        try:
            return c.Ldif.ServerTypes(val)
        except ValueError:
            for member in c.Ldif.ServerTypes:
                if member.value == val.lower():
                    return member
            return c.Ldif.ServerTypes.RFC

    @property
    def target_server_type(self) -> c.Ldif.ServerTypes:
        """Get target server type."""
        val = getattr(self, "_target_server", c.Ldif.ServerTypes.RFC)
        if issubclass(val.__class__, c.Ldif.ServerTypes):
            return val
        try:
            return c.Ldif.ServerTypes(val)
        except ValueError:
            for member in c.Ldif.ServerTypes:
                if member.value == val.lower():
                    return member
            return c.Ldif.ServerTypes.RFC

    @override
    def execute(self) -> r[m.Ldif.MigrationPipelineResult]:
        """Execute migration pipeline for all files in input_dir."""
        in_dir = self.input_dir
        out_dir = self.output_dir
        if in_dir is None:
            return r[m.Ldif.MigrationPipelineResult].fail("No input_dir specified")
        if out_dir is None:
            return r[m.Ldif.MigrationPipelineResult].fail("No output_dir specified")
        if not in_dir.exists():
            return r[m.Ldif.MigrationPipelineResult].fail(
                f"Input directory not found: {in_dir}",
            )
        try:
            total_processed = 0
            total_migrated = 0
            all_entries: Sequence[m.Ldif.Entry] = []
            output_files: Sequence[str] = []
            for input_file in in_dir.glob("*.ldif"):
                logger.debug("Processing input file: %s", input_file)
                result = self.migrate_file(input_file)
                if result.is_success:
                    res = result.value
                    total_processed += res.stats.total_entries
                    total_migrated += res.stats.processed_entries
                    converted_res_entries: Sequence[m.Ldif.Entry] = list(res.entries)
                    all_entries.extend(converted_res_entries)
                    output_files.extend(res.output_files)
                else:
                    logger.warning(
                        "File migration failed",
                        file=str(input_file),
                        error=str(result.error),
                    )
            converted_all_entries: Sequence[m.Ldif.Entry] = list(all_entries)
            pipeline_result = m.Ldif.MigrationPipelineResult(
                migrated_schema=m.Ldif.SchemaContent.model_validate({}),
                entries=converted_all_entries,
                output_files=output_files,
                stats=m.Ldif.Statistics(
                    total_entries=total_processed,
                    processed_entries=total_migrated,
                    failed_entries=0,
                    schema_entries=0,
                    data_entries=0,
                    hierarchy_entries=0,
                    user_entries=0,
                    group_entries=0,
                    acl_entries=0,
                    rejected_entries=0,
                    schema_attributes=0,
                    schema_objectclasses=0,
                    acls_extracted=0,
                    acls_failed=0,
                    parse_errors=0,
                    entries_written=0,
                    file_size_bytes=0,
                    processing_duration=0.0,
                    rejection_reasons=m.Ldif.DynamicCounts(),
                    events=[],
                ),
            )
            return r[m.Ldif.MigrationPipelineResult].ok(pipeline_result)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.exception("Migration pipeline failed")
            return r[m.Ldif.MigrationPipelineResult].fail(
                f"Migration pipeline failed: {e}",
            )

    def migrate_entries(
        self, entries: Sequence[m.Ldif.Entry]
    ) -> r[Sequence[m.Ldif.Entry]]:
        """Migrate entries from source to target server format."""
        try:
            pipeline = self._get_processing_pipeline()
            return pipeline.execute(entries)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.exception(
                "Migration failed",
                source=self.source_server_type,
                target=self.target_server_type,
            )
            return r[Sequence[m.Ldif.Entry]].fail(f"Migration failed: {e}")

    def migrate_file(
        self,
        input_file: Path,
        output_file: Path | None = None,
    ) -> r[m.Ldif.MigrationPipelineResult]:
        """Migrate a single LDIF file."""
        try:
            if not input_file.exists():
                return r[m.Ldif.MigrationPipelineResult].fail(
                    f"Input file not found: {input_file}",
                )
            content = input_file.read_text(encoding="utf-8")
            parser = FlextLdifParser()
            parse_result = parser.parse_string(
                content,
                server_type=self.source_server_type,
            )
            if parse_result.is_failure:
                return r[m.Ldif.MigrationPipelineResult].fail(
                    f"Parse failed: {parse_result.error}",
                )
            response = parse_result.value
            entries_list: Sequence[m.Ldif.Entry] = list(response.entries)
            migrate_result = self.migrate_entries(entries_list)
            if migrate_result.is_failure:
                return r[m.Ldif.MigrationPipelineResult].fail(
                    f"Migration failed: {migrate_result.error}",
                )
            migrated = migrate_result.value
            if output_file is None:
                out_dir = self.output_dir
                if out_dir is None:
                    return r[m.Ldif.MigrationPipelineResult].fail(
                        "No output file or output_dir specified",
                    )
                filename = self.output_filename or input_file.name
                output_file = out_dir / filename
            writer = FlextLdifWriter()
            write_result = writer.write_to_string(
                migrated,
                server_type=self.target_server_type,
            )
            if write_result.is_failure:
                return r[m.Ldif.MigrationPipelineResult].fail(
                    f"Write failed: {write_result.error}",
                )
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(write_result.value, encoding="utf-8")
            logger.debug("Wrote migrated file to: %s", output_file)
            converted_entries: Sequence[m.Ldif.Entry] = list(migrated)
            result = m.Ldif.MigrationPipelineResult(
                migrated_schema=m.Ldif.SchemaContent.model_validate({}),
                entries=converted_entries,
                output_files=[str(output_file)],
                stats=m.Ldif.Statistics(
                    total_entries=len(entries_list),
                    processed_entries=len(migrated),
                    failed_entries=0,
                    schema_entries=0,
                    data_entries=0,
                    hierarchy_entries=0,
                    user_entries=0,
                    group_entries=0,
                    acl_entries=0,
                    rejected_entries=0,
                    schema_attributes=0,
                    schema_objectclasses=0,
                    acls_extracted=0,
                    acls_failed=0,
                    parse_errors=0,
                    entries_written=0,
                    file_size_bytes=0,
                    processing_duration=0.0,
                    rejection_reasons=m.Ldif.DynamicCounts(),
                    events=[],
                ),
            )
            return r[m.Ldif.MigrationPipelineResult].ok(result)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            logger.exception("File migration failed", input_file=str(input_file))
            return r[m.Ldif.MigrationPipelineResult].fail(f"File migration failed: {e}")

    def _get_processing_pipeline(self) -> FlextLdifProcessingPipeline:
        """Get or create processing pipeline instance."""
        service = getattr(self, "_processing_pipeline_service")
        return service.get_processing_pipeline(
            source_server_type=self.source_server_type,
            target_server_type=self.target_server_type,
        )


__all__ = ["FlextLdifMigrationPipeline"]
