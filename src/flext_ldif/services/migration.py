"""Server-to-server LDIF migration over explicit registry and value contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from os import PathLike
from pathlib import Path
from typing import Final, override

from flext_ldif import FlextLdifShared, c, m, p, r, s, t, u
from flext_ldif.services import (
    FlextLdifParser,
    FlextLdifProcessingPipeline,
    FlextLdifWriter,
)


class FlextLdifMigrationPipeline(
    s[p.Ldif.MigrationPipelineResult],
    m.Ldif.RegistryPortOptions,
    m.Ldif.MigrationPipelineOptions,
):
    """Migrate files and entry sequences through one explicitly supplied graph."""

    _DEFAULT_SERVER: Final[c.Ldif.ServerTypes] = c.Ldif.ServerTypes.RFC

    @override
    def model_post_init(self, __context: t.JsonMapping | None, /) -> None:
        """Normalize the model-owned source and target selectors."""
        super().model_post_init(__context)
        self.source_server_type = self._coerce_server_type(
            self.source_server_type or self.source_server or self._DEFAULT_SERVER,
        )
        self.target_server_type = self._coerce_server_type(
            self.target_server_type or self.target_server or self._DEFAULT_SERVER,
        )

    @staticmethod
    def _coerce_server_type(value: str | c.Ldif.ServerTypes) -> c.Ldif.ServerTypes:
        """Normalize known dialects and reject invalid explicit selectors.

        Returns:
            The normalized ``c.Ldif.ServerTypes`` selector.

        """
        if isinstance(value, c.Ldif.ServerTypes):
            return value
        lowered = value.lower().strip()
        try:
            return c.Ldif.ServerTypes(lowered)
        except ValueError:
            return FlextLdifShared.normalize_server_type(lowered)

    @override
    def execute(self) -> p.Result[p.Ldif.MigrationPipelineResult]:
        """Migrate the configured directory and aggregate its public outcomes.

        Returns:
            The resulting ``p.Result[p.Ldif.MigrationPipelineResult]`` with the
            aggregated outcome, a guard failure for missing or absent input and
            output directories, or ``fail_op`` metadata when aggregation raises.

        """
        in_dir = self.input_dir
        if in_dir is None:
            return r[p.Ldif.MigrationPipelineResult].fail("No input_dir specified")
        if self.output_dir is None:
            return r[p.Ldif.MigrationPipelineResult].fail("No output_dir specified")
        if not in_dir.exists():
            return r[p.Ldif.MigrationPipelineResult].fail(
                f"Input directory not found: {in_dir}",
            )
        try:
            outcome = self._collect_directory_outcomes(in_dir)
        except c.Ldif.EXC_LDIF_PARSE as exc:
            self.logger.exception("Migration pipeline failed", error=str(exc))
            return r[p.Ldif.MigrationPipelineResult].fail_op("Migration pipeline", exc)
        return r[p.Ldif.MigrationPipelineResult].ok(outcome)

    def _collect_directory_outcomes(
        self,
        in_dir: Path,
    ) -> m.Ldif.MigrationPipelineResult:
        """Migrate every LDIF file in the directory and aggregate the outcomes.

        Returns:
            The aggregated ``m.Ldif.MigrationPipelineResult`` over every
            successfully migrated file; per-file failures are logged as
            warnings and skipped.

        """
        all_entries: t.MutableSequenceOf[p.Ldif.Entry] = []
        output_files: t.MutableSequenceOf[str] = []
        total_processed = 0
        total_migrated = 0
        for input_file in in_dir.glob("*.ldif"):
            result = self.migrate_file(input_file)
            if result.failure:
                self.logger.warning(
                    "File migration failed",
                    file=str(input_file),
                    error=result.error,
                )
                continue
            outcome = result.value
            total_processed += outcome.stats.total_entries
            total_migrated += outcome.stats.processed_entries
            all_entries.extend(outcome.entries)
            output_files.extend(outcome.output_files)
        return m.Ldif.MigrationPipelineResult.model_validate({
            "entries": all_entries,
            "output_files": output_files,
            "stats": m.Ldif.Statistics(
                total_entries=total_processed,
                processed_entries=total_migrated,
            ),
        })

    def migrate_entries(
        self,
        entries: t.SequenceOf[p.Ldif.Entry],
    ) -> p.Result[t.SequenceOf[p.Ldif.Entry]]:
        """Migrate an ordered entry sequence without changing caller ownership.

        Returns:
            The resulting ``p.Result[t.SequenceOf[p.Ldif.Entry]]`` with the
            migrated sequence, the propagated pipeline failure metadata, or
            ``fail_op`` metadata when the migration raises.

        """
        source_server = self.source_server_type or self._DEFAULT_SERVER
        target_server = self.target_server_type or self._DEFAULT_SERVER
        try:
            configuration = m.Ldif.TransformConfig.servers(
                source_server=source_server,
                target_server=target_server,
                base_dn=self.base_dn or "",
            )
            pipeline = FlextLdifProcessingPipeline.model_validate({
                "transform_config": configuration,
                "entries_input": entries,
                "registry": self.registry,
                "runtime_settings": self.settings,
            })
            result = pipeline.execute()
            if result.failure:
                return r[t.SequenceOf[p.Ldif.Entry]].from_failure(result)
            return r[t.SequenceOf[p.Ldif.Entry]].ok(result.value)
        except c.Ldif.EXC_LDIF_PARSE as exc:
            self.logger.exception(
                "Migration failed",
                source=str(source_server),
                target=str(target_server),
                error=str(exc),
            )
            return r[t.SequenceOf[p.Ldif.Entry]].fail_op("Migration", exc)

    def migrate_file(
        self,
        input_file: PathLike[str],
        output_file: PathLike[str] | None = None,
    ) -> p.Result[p.Ldif.MigrationPipelineResult]:
        """Read, migrate and write one file through the public typed operations.

        Returns:
            The resulting ``p.Result[p.Ldif.MigrationPipelineResult]`` with the
            written outcome, a guard failure for a missing input file or output
            target, the propagated read/parse/migrate/write failure metadata, or
            ``fail_op`` metadata when the file migration raises.

        """
        try:
            return self._migrate_resolved_file(Path(input_file), output_file)
        except c.Ldif.EXC_LDIF_PARSE as exc:
            self.logger.exception(
                "File migration failed",
                input_file=str(input_file),
                error=str(exc),
            )
            return r[p.Ldif.MigrationPipelineResult].fail_op("File migration", exc)

    def _migrate_resolved_file(
        self,
        input_path: Path,
        output_file: PathLike[str] | None,
    ) -> p.Result[p.Ldif.MigrationPipelineResult]:
        """Run the guard chain for one resolved file and write its outcome.

        Returns:
            The resulting ``p.Result[p.Ldif.MigrationPipelineResult]`` with the
            written outcome, a guard failure for a missing input file or output
            target, or the propagated read/parse/migrate failure metadata.

        """
        if not input_path.exists():
            return r[p.Ldif.MigrationPipelineResult].fail(
                f"Input file not found: {input_path}",
            )
        parsed = self._read_and_parse(input_path)
        if parsed.failure:
            return r[p.Ldif.MigrationPipelineResult].from_failure(parsed)
        migrated = self.migrate_entries(parsed.value)
        if migrated.failure:
            return r[p.Ldif.MigrationPipelineResult].from_failure(migrated)
        output_path = self._resolve_output_path(output_file, input_path)
        if output_path is None:
            return r[p.Ldif.MigrationPipelineResult].fail(
                "No output file or output_dir specified",
            )
        return self._write_outcome(parsed.value, migrated.value, output_path)

    def _read_and_parse(
        self,
        input_path: Path,
    ) -> p.Result[t.SequenceOf[p.Ldif.Entry]]:
        """Read one file and parse its entries through the public parser.

        Returns:
            The resulting ``p.Result[t.SequenceOf[p.Ldif.Entry]]`` with the
            parsed entries or the propagated read and parse failure metadata.

        """
        read = u.Cli.files_read_text(input_path)
        if read.failure:
            return r[t.SequenceOf[p.Ldif.Entry]].from_failure(read)
        parsed = FlextLdifParser(
            registry=self.registry,
            runtime_settings=self.settings,
        ).parse_string(read.value, server_type=self.source_server_type)
        if parsed.failure:
            return r[t.SequenceOf[p.Ldif.Entry]].from_failure(parsed)
        return r[t.SequenceOf[p.Ldif.Entry]].ok(parsed.value.entries)

    def _resolve_output_path(
        self,
        output_file: PathLike[str] | None,
        input_path: Path,
    ) -> Path | None:
        """Resolve the explicit output file or the configured output directory.

        Returns:
            The resolved output ``Path``, or ``None`` when neither an explicit
            output file nor an output directory is configured.

        """
        output_path = None if output_file is None else Path(output_file)
        if output_path is None and self.output_dir is not None:
            return self.output_dir / (self.output_filename or input_path.name)
        return output_path

    def _write_outcome(
        self,
        entries: t.SequenceOf[p.Ldif.Entry],
        migrated: t.SequenceOf[p.Ldif.Entry],
        output_path: Path,
    ) -> p.Result[p.Ldif.MigrationPipelineResult]:
        """Build the outcome model and write the migrated entries to disk.

        Returns:
            The resulting ``p.Result[p.Ldif.MigrationPipelineResult]`` with the
            written outcome or the propagated write failure metadata.

        """
        outcome = m.Ldif.MigrationPipelineResult.model_validate({
            "entries": migrated,
            "output_files": [str(output_path)],
            "stats": m.Ldif.Statistics(
                total_entries=len(entries),
                processed_entries=len(migrated),
            ),
        })
        written = FlextLdifWriter(
            registry=self.registry,
            runtime_settings=self.settings,
        ).write_ldif_file(
            outcome.entries,
            output_path,
            server_type=self.target_server_type,
        )
        if written.failure:
            return r[p.Ldif.MigrationPipelineResult].from_failure(written)
        return r[p.Ldif.MigrationPipelineResult].ok(outcome)


__all__: list[str] = ["FlextLdifMigrationPipeline"]
