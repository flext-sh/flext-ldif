"""Migration Pipeline Service - Server-to-Server LDIF Migration."""

from __future__ import annotations

from pathlib import Path
from typing import Final, override

from flext_core import FlextLogger, r
from pydantic import PrivateAttr

from flext_ldif._utilities.configs import ProcessConfig, TransformConfig
from flext_ldif.base import s
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.pipeline import ProcessingPipeline
from flext_ldif.services.writer import FlextLdifWriter

logger: Final = FlextLogger(__name__)


class FlextLdifMigrationPipeline(
    s[m.Ldif.LdifResults.MigrationPipelineResult],
):
    """Migration Pipeline for Server-to-Server LDIF Migration."""

    _input_dir: Path | None = PrivateAttr(default=None)
    _output_dir: Path | None = PrivateAttr(default=None)
    _source_server: c.Ldif.ServerTypes = PrivateAttr(default=c.Ldif.ServerTypes.RFC)
    _target_server: c.Ldif.ServerTypes = PrivateAttr(default=c.Ldif.ServerTypes.RFC)
    _processing_pipeline: ProcessingPipeline | None = PrivateAttr(default=None)

    _output_filename: str | None = PrivateAttr(default=None)

    def __init__(
        self,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        source_server: str = "rfc",
        target_server: str = "rfc",
        output_filename: str | None = None,
        **_kwargs: str | float | bool | None,
    ) -> None:
        """Initialize migration pipeline."""
        super().__init__()

        object.__setattr__(self, "_input_dir", input_dir)
        object.__setattr__(self, "_output_dir", output_dir)
        object.__setattr__(self, "_source_server", source_server)
        object.__setattr__(self, "_target_server", target_server)
        object.__setattr__(self, "_output_filename", output_filename)
        object.__setattr__(self, "_processing_pipeline", None)

    @property
    def input_dir(self) -> Path | None:
        """Get input directory."""
        return getattr(self, "_input_dir", None)

    @property
    def output_dir(self) -> Path | None:
        """Get output directory."""
        return getattr(self, "_output_dir", None)

    @property
    def source_server_type(self) -> c.Ldif.ServerTypes:
        """Get source server type."""
        val = getattr(self, "_source_server", c.Ldif.ServerTypes.RFC)
        # Ensure we return ServerTypes enum member
        if isinstance(val, c.Ldif.ServerTypes):
            return val
        # If it's a string, try to convert to enum
        try:
            return c.Ldif.ServerTypes(val)
        except ValueError:
            # Fallback or strict? Let's use RFC default if unknown string
            # Or try case-insensitive match
            for member in c.Ldif.ServerTypes:
                if member.value == val.lower():
                    return member
            return c.Ldif.ServerTypes.RFC

    @property
    def target_server_type(self) -> c.Ldif.ServerTypes:
        """Get target server type."""
        val = getattr(self, "_target_server", c.Ldif.ServerTypes.RFC)
        if isinstance(val, c.Ldif.ServerTypes):
            return val
        try:
            return c.Ldif.ServerTypes(val)
        except ValueError:
            for member in c.Ldif.ServerTypes:
                if member.value == val.lower():
                    return member
            return c.Ldif.ServerTypes.RFC

    @property
    def output_filename(self) -> str | None:
        """Get output filename override."""
        return getattr(self, "_output_filename", None)

    def _get_processing_pipeline(self) -> ProcessingPipeline:
        """Get or create processing pipeline instance."""
        pipeline = getattr(self, "_processing_pipeline", None)
        if pipeline is None:
            source_type = m.Ldif.ServerType(self.source_server_type)
            target_type = m.Ldif.ServerType(self.target_server_type)

            logger.debug(
                "Creating processing pipeline",
                source=source_type,
                target=target_type,
            )

            config_base = ProcessConfig()
            process_config = config_base.model_copy(
                update={
                    "source_server": source_type,
                    "target_server": target_type,
                },
            )

            config = TransformConfig(process_config=process_config)
            pipeline = ProcessingPipeline(config)
            object.__setattr__(self, "_processing_pipeline", pipeline)
        return pipeline

    def migrate_entries(
        self,
        entries: list[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Migrate entries from source to target server format."""
        try:
            pipeline = self._get_processing_pipeline()

            return pipeline.execute(entries)

        except Exception as e:
            logger.exception(
                "Migration failed",
                source=self.source_server_type,
                target=self.target_server_type,
            )
            return r[list[m.Ldif.Entry]].fail(f"Migration failed: {e}")

    def migrate_file(
        self,
        input_file: Path,
        output_file: Path | None = None,
    ) -> r[m.Ldif.LdifResults.MigrationPipelineResult]:
        """Migrate a single LDIF file."""
        try:
            if not input_file.exists():
                return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
                    f"Input file not found: {input_file}",
                )

            content = input_file.read_text(encoding="utf-8")

            parser = FlextLdifParser()
            parse_result = parser.parse_string(
                content,
                server_type=self.source_server_type,
            )

            if parse_result.is_failure:
                return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
                    f"Parse failed: {parse_result.error}",
                )

            response = parse_result.value

            entries_list: list[m.Ldif.Entry] = [
                m.Ldif.Entry.model_validate(e.model_dump(mode="json"))
                for e in response.entries
            ]

            migrate_result = self.migrate_entries(entries_list)
            if migrate_result.is_failure:
                return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
                    f"Migration failed: {migrate_result.error}",
                )

            migrated = migrate_result.value

            if output_file is None:
                out_dir = self.output_dir
                if out_dir is None:
                    return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
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
                return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
                    f"Write failed: {write_result.error}",
                )

            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(write_result.value, encoding="utf-8")
            logger.debug(f"Wrote migrated file to: {output_file}")

            converted_entries: list[m.Ldif.Entry] = [
                m.Ldif.Entry.model_validate(e.model_dump(mode="json")) for e in migrated
            ]

            result = m.Ldif.LdifResults.MigrationPipelineResult(
                entries=converted_entries,
                output_files=[str(output_file)],
                stats=m.Ldif.LdifResults.Statistics(
                    total_entries=len(entries_list),
                    processed_entries=len(migrated),
                ),
            )

            return r[m.Ldif.LdifResults.MigrationPipelineResult].ok(result)

        except Exception as e:
            logger.exception(
                "File migration failed",
                input_file=str(input_file),
            )
            return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
                f"File migration failed: {e}",
            )

    @override
    def execute(self) -> r[m.Ldif.LdifResults.MigrationPipelineResult]:
        """Execute migration pipeline for all files in input_dir."""
        in_dir = self.input_dir
        out_dir = self.output_dir

        if in_dir is None:
            return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
                "No input_dir specified",
            )

        if out_dir is None:
            return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
                "No output_dir specified",
            )

        if not in_dir.exists():
            return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
                f"Input directory not found: {in_dir}",
            )

        try:
            total_processed = 0
            total_migrated = 0
            all_entries: list[m.Ldif.Entry] = []
            output_files: list[str] = []

            for input_file in in_dir.glob("*.ldif"):
                logger.debug(f"Processing input file: {input_file}")
                result = self.migrate_file(input_file)
                if result.is_success:
                    res = result.value
                    total_processed += res.stats.total_entries
                    total_migrated += res.stats.processed_entries

                    converted_res_entries: list[m.Ldif.Entry] = [
                        m.Ldif.Entry.model_validate(e.model_dump(mode="json"))
                        for e in res.entries
                    ]
                    all_entries.extend(converted_res_entries)
                    output_files.extend(res.output_files)
                else:
                    logger.warning(
                        "File migration failed",
                        file=str(input_file),
                        error=str(result.error),
                    )

            converted_all_entries: list[m.Ldif.Entry] = [
                m.Ldif.Entry.model_validate(e.model_dump(mode="json"))
                for e in all_entries
            ]

            pipeline_result = m.Ldif.LdifResults.MigrationPipelineResult(
                entries=converted_all_entries,
                output_files=output_files,
                stats=m.Ldif.LdifResults.Statistics(
                    total_entries=total_processed,
                    processed_entries=total_migrated,
                ),
            )

            return r[m.Ldif.LdifResults.MigrationPipelineResult].ok(pipeline_result)

        except Exception as e:
            logger.exception("Migration pipeline failed")
            return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
                f"Migration pipeline failed: {e}",
            )


__all__ = ["FlextLdifMigrationPipeline"]
