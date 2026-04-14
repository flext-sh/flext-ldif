"""Migration Pipeline Service - Server-to-Server LDIF Migration."""

from __future__ import annotations

import struct
from collections.abc import MutableSequence
from pathlib import Path
from typing import Final, override

from pydantic import PrivateAttr

from flext_ldif import (
    FlextLdifParser,
    FlextLdifProcessingPipelineService,
    FlextLdifWriter,
    c,
    m,
    r,
    s,
    u,
)

logger: Final = u.fetch_logger(__name__)


class FlextLdifMigrationPipeline(s[m.Ldif.MigrationPipelineResult]):
    """Migration Pipeline for Server-to-Server LDIF Migration."""

    _DEFAULT_SERVER: Final[c.Ldif.ServerTypes] = c.Ldif.ServerTypes.RFC
    _ENCODING_UTF8: Final[str] = c.Ldif.Encoding.UTF8.value

    _input_dir: Path | None = PrivateAttr(default=None)
    _output_dir: Path | None = PrivateAttr(default=None)
    _source_server: c.Ldif.ServerTypes = PrivateAttr(default=c.Ldif.ServerTypes.RFC)
    _target_server: c.Ldif.ServerTypes = PrivateAttr(default=c.Ldif.ServerTypes.RFC)
    _output_filename: str | None = PrivateAttr(default=None)

    def __init__(
        self,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        source_server: str = c.Ldif.ServerTypes.RFC.value,
        target_server: str = c.Ldif.ServerTypes.RFC.value,
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
        object.__setattr__(
            self,
            "_source_server",
            self._coerce_server_type(effective_source_server),
        )
        object.__setattr__(
            self,
            "_target_server",
            self._coerce_server_type(effective_target_server),
        )
        object.__setattr__(self, "_output_filename", output_filename)

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
        return getattr(self, "_source_server", self._DEFAULT_SERVER)

    @property
    def target_server_type(self) -> c.Ldif.ServerTypes:
        """Get target server type."""
        return getattr(self, "_target_server", self._DEFAULT_SERVER)

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
        entries: MutableSequence[m.Ldif.Entry],
        output_files: MutableSequence[str],
        total_entries: int,
        processed_entries: int,
    ) -> m.Ldif.MigrationPipelineResult:
        """Build result with defaults, keeping service as pure orchestrator."""
        payload: dict[str, object] = {
            "entries": entries,
            "output_files": output_files,
            "stats": cls._build_stats(
                total_entries=total_entries,
                processed_entries=processed_entries,
            ),
        }
        return m.Ldif.MigrationPipelineResult.model_validate(payload)

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
            all_entries: MutableSequence[m.Ldif.Entry] = []
            output_files: MutableSequence[str] = []
            for input_file in in_dir.glob("*.ldif"):
                logger.debug("Processing input file: %s", input_file)
                result = self.migrate_file(input_file)
                if result.success:
                    res = result.value
                    total_processed += res.stats.total_entries
                    total_migrated += res.stats.processed_entries
                    all_entries.extend(res.entries)
                    output_files.extend(res.output_files)
                else:
                    logger.warning(
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
        self,
        entries: MutableSequence[m.Ldif.Entry],
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Migrate entries from source to target server format."""
        try:
            pipeline = FlextLdifProcessingPipelineService.get_processing_pipeline(
                source_server_type=self.source_server_type,
                target_server_type=self.target_server_type,
            )
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
            return r[MutableSequence[m.Ldif.Entry]].fail(f"Migration failed: {e}")

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
            content = input_file.read_text(encoding=self._ENCODING_UTF8)
            parser = FlextLdifParser()
            parse_result = parser.parse_string(
                content,
                server_type=self.source_server_type,
            )
            if parse_result.failure:
                return r[m.Ldif.MigrationPipelineResult].fail(
                    f"Parse failed: {parse_result.error}",
                )
            response = parse_result.value
            entries_list: MutableSequence[m.Ldif.Entry] = list(response.entries)
            migrate_result = self.migrate_entries(entries_list)
            if migrate_result.failure:
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
            write_result = writer.write_ldif_file(
                migrated,
                output_file,
                server_type=self.target_server_type,
            )
            if write_result.failure:
                return r[m.Ldif.MigrationPipelineResult].fail(
                    f"Write failed: {write_result.error}",
                )
            logger.debug("Wrote migrated file to: %s", output_file)
            result = self._build_pipeline_result(
                entries=migrated,
                output_files=[str(output_file)],
                total_entries=len(entries_list),
                processed_entries=len(migrated),
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


__all__: list[str] = ["FlextLdifMigrationPipeline"]
