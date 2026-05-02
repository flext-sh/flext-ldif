"""Migration Pipeline Service - Server-to-Server LDIF Migration."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Final, override

from flext_ldif import (
    FlextLdifParser,
    FlextLdifProcessingPipeline,
    FlextLdifWriter,
    c,
    m,
    p,
    r,
    s,
    t,
    u,
)


class FlextLdifMigrationPipeline(s[m.Ldif.MigrationPipelineResult]):
    """Migration Pipeline for Server-to-Server LDIF Migration."""

    _DEFAULT_SERVER: Final[c.Ldif.ServerTypes] = c.Ldif.ServerTypes.RFC

    input_dir: Annotated[
        Path | None,
        u.Field(
            default=None,
            exclude=True,
            description="Directory containing LDIF files to migrate.",
        ),
    ]
    output_dir: Annotated[
        Path | None,
        u.Field(
            default=None,
            exclude=True,
            description="Directory receiving migrated LDIF files.",
        ),
    ]
    output_filename: Annotated[
        str | None,
        u.Field(
            default=None,
            exclude=True,
            description="Optional output filename override used for single-file migration.",
        ),
    ]
    mode: Annotated[
        str | None,
        u.Field(
            default=None,
            exclude=True,
            description="Public migration mode input accepted by the pipeline DSL.",
        ),
    ]
    source_server: Annotated[
        str | c.Ldif.ServerTypes | None,
        u.Field(
            default=None,
            exclude=True,
            description="Legacy source server input accepted for compatibility.",
        ),
    ]
    target_server: Annotated[
        str | c.Ldif.ServerTypes | None,
        u.Field(
            default=None,
            exclude=True,
            description="Legacy target server input accepted for compatibility.",
        ),
    ]
    source_server_type: Annotated[
        str | c.Ldif.ServerTypes | None,
        u.Field(
            default=None,
            exclude=True,
            description="Canonical source server type used by the migration pipeline.",
        ),
    ]
    target_server_type: Annotated[
        str | c.Ldif.ServerTypes | None,
        u.Field(
            default=None,
            exclude=True,
            description="Canonical target server type used by the migration pipeline.",
        ),
    ]

    @override
    def model_post_init(self, __context: t.JsonMapping | None, /) -> None:
        """Normalize migration configuration after Pydantic initialization."""
        super().model_post_init(__context)
        self.source_server_type = self._coerce_server_type(
            self.source_server_type or self.source_server or self._DEFAULT_SERVER,
        )
        self.target_server_type = self._coerce_server_type(
            self.target_server_type or self.target_server or self._DEFAULT_SERVER,
        )

    @classmethod
    def _coerce_server_type(
        cls,
        value: str | c.Ldif.ServerTypes,
    ) -> c.Ldif.ServerTypes:
        """Coerce configured server type with stable behavior for explicit values."""
        if isinstance(value, c.Ldif.ServerTypes):
            return value
        lowered = value.lower().strip()
        try:
            return c.Ldif.ServerTypes(lowered)
        except ValueError:
            try:
                return c.Ldif.ServerTypes(u.Ldif.normalize_server_type(lowered))
            except ValueError:
                return cls._DEFAULT_SERVER

    @staticmethod
    def _build_stats(
        *,
        total_entries: int,
        processed_entries: int,
    ) -> m.Ldif.Statistics:
        """Create migration stats using model defaults for untouched counters."""
        return m.Ldif.Statistics(
            total_entries=total_entries,
            processed_entries=processed_entries,
        )

    @classmethod
    def _build_pipeline_result(
        cls,
        *,
        entries: t.MutableSequenceOf[m.Ldif.Entry],
        output_files: t.MutableSequenceOf[str],
        total_entries: int,
        processed_entries: int,
    ) -> m.Ldif.MigrationPipelineResult:
        """Build result with defaults, keeping service as pure orchestrator."""
        constructed: m.Ldif.MigrationPipelineResult = (
            m.Ldif.MigrationPipelineResult.model_construct(
                entries=entries,
                output_files=output_files,
                stats=cls._build_stats(
                    total_entries=total_entries,
                    processed_entries=processed_entries,
                ),
            )
        )
        return constructed

    @override
    def execute(self) -> p.Result[m.Ldif.MigrationPipelineResult]:
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
            all_entries: t.MutableSequenceOf[m.Ldif.Entry] = []
            output_files: t.MutableSequenceOf[str] = []
            for input_file in in_dir.glob("*.ldif"):
                self.logger.debug("Processing input file", input_file=str(input_file))
                result = self.migrate_file(input_file)
                if result.success:
                    res = result.value
                    total_processed += res.stats.total_entries
                    total_migrated += res.stats.processed_entries
                    all_entries.extend(res.entries)
                    output_files.extend(res.output_files)
                else:
                    self.logger.warning(
                        "File migration failed",
                        file=str(input_file),
                        error=str(result.error),
                    )
            pipeline_result = self._build_pipeline_result(
                entries=all_entries,
                output_files=output_files,
                total_entries=total_processed,
                processed_entries=total_migrated,
            )
            return r[m.Ldif.MigrationPipelineResult].ok(pipeline_result)
        except c.Ldif.EXC_LDIF_PARSE as e:
            self.logger.exception("Migration pipeline failed", error=str(e))
            return r[m.Ldif.MigrationPipelineResult].fail_op("Migration pipeline", e)

    def migrate_entries(
        self,
        entries: t.MutableSequenceOf[m.Ldif.Entry],
    ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Migrate entries from source to target server format."""
        source_server = self.source_server_type or self._DEFAULT_SERVER
        target_server = self.target_server_type or self._DEFAULT_SERVER
        try:
            pipeline = FlextLdifProcessingPipeline.for_servers(
                source_server=source_server,
                target_server=target_server,
            )
            return pipeline.model_copy(update={"entries_input": entries}).execute()
        except c.Ldif.EXC_LDIF_PARSE as e:
            self.logger.exception(
                "Migration failed",
                source=str(source_server),
                target=str(target_server),
                error=str(e),
            )
            return r[t.MutableSequenceOf[m.Ldif.Entry]].fail_op("Migration", e)

    def migrate_file(
        self,
        input_file: Path,
        output_file: Path | None = None,
    ) -> p.Result[m.Ldif.MigrationPipelineResult]:
        """Migrate a single LDIF file."""
        try:
            if not input_file.exists():
                return r[m.Ldif.MigrationPipelineResult].fail(
                    f"Input file not found: {input_file}",
                )
            content = input_file.read_text(encoding=c.Ldif.DEFAULT_ENCODING)
            parser = FlextLdifParser()
            parse_result = parser.parse_string(
                content,
                server_type=self.source_server_type,
            )
            if parse_result.failure:
                return r[m.Ldif.MigrationPipelineResult].fail_op(
                    "Parse", parse_result.error
                )
            response = parse_result.value
            entries_list: t.MutableSequenceOf[m.Ldif.Entry] = list(response.entries)
            migrate_result = self.migrate_entries(entries_list)
            if migrate_result.failure:
                return r[m.Ldif.MigrationPipelineResult].fail_op(
                    "Migration", migrate_result.error
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
            write_result = writer.write_ldif_file(
                migrated,
                output_file,
                server_type=self.target_server_type,
            )
            if write_result.failure:
                return r[m.Ldif.MigrationPipelineResult].fail_op(
                    "Write", write_result.error
                )
            self.logger.debug("Wrote migrated file", output_file=str(output_file))
            result = self._build_pipeline_result(
                entries=migrated,
                output_files=[str(output_file)],
                total_entries=len(entries_list),
                processed_entries=len(migrated),
            )
            return r[m.Ldif.MigrationPipelineResult].ok(result)
        except c.Ldif.EXC_LDIF_PARSE as e:
            self.logger.exception(
                "File migration failed",
                input_file=str(input_file),
                error=str(e),
            )
            return r[m.Ldif.MigrationPipelineResult].fail_op("File migration", e)


__all__: list[str] = ["FlextLdifMigrationPipeline"]
