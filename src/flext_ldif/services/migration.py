"""Migration Pipeline Service - Server-to-Server LDIF Migration.

Provides FlextLdifMigrationPipeline for migrating LDIF data between different
LDAP server types (e.g., OID to OUD, OpenLDAP to 389DS).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import Final, cast, override

from flext_core import FlextLogger, r
from pydantic import BaseModel, PrivateAttr

from flext_ldif._utilities.pipeline import ProcessingPipeline
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import m
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.writer import FlextLdifWriter

logger: Final = FlextLogger(__name__)


class FlextLdifMigrationPipeline(
    FlextLdifServiceBase[m.Ldif.LdifResults.MigrationPipelineResult]
):
    """Migration Pipeline for Server-to-Server LDIF Migration.

    Orchestrates the migration of LDIF data between different LDAP server types.
    Uses the ProcessingPipeline from _utilities for entry transformation.

    Example:
        >>> pipeline = FlextLdifMigrationPipeline(
        ...     input_dir=Path("source_ldifs"),
        ...     output_dir=Path("target_ldifs"),
        ...     source_server_type="oid",
        ...     target_server_type="oud",
        ... )
        >>> result = pipeline.execute()

    """

    # Instance state (stored as PrivateAttr for frozen model compatibility)
    _input_dir: Path | None = PrivateAttr(default=None)
    _output_dir: Path | None = PrivateAttr(default=None)
    _source_type: str = PrivateAttr(default="rfc")
    _target_type: str = PrivateAttr(default="rfc")
    _processing_pipeline: ProcessingPipeline | None = PrivateAttr(default=None)

    def __init__(
        self,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        source_server_type: str = "rfc",
        target_server_type: str = "rfc",
        **_kwargs: str | float | bool | None,
    ) -> None:
        """Initialize migration pipeline.

        Args:
            input_dir: Directory containing source LDIF files.
            output_dir: Directory for output LDIF files.
            source_server_type: Source server type (e.g., "oid", "openldap").
            target_server_type: Target server type (e.g., "oud", "389ds").
            **kwargs: Additional kwargs for base class.

        """
        super().__init__()
        # Store as instance attributes via setattr for frozen Pydantic compatibility
        object.__setattr__(self, "_input_dir", input_dir)
        object.__setattr__(self, "_output_dir", output_dir)
        object.__setattr__(self, "_source_type", source_server_type)
        object.__setattr__(self, "_target_type", target_server_type)
        object.__setattr__(self, "_processing_pipeline", None)

    @property
    def input_dir(self) -> Path | None:
        """Get input directory."""
        # Type narrowing: _input_dir is Path | None (defined as PrivateAttr)
        return getattr(self, "_input_dir", None)

    @property
    def output_dir(self) -> Path | None:
        """Get output directory."""
        # Type narrowing: _output_dir is Path | None (defined as PrivateAttr)
        return getattr(self, "_output_dir", None)

    @property
    def source_server_type(self) -> str:
        """Get source server type."""
        # Type narrowing: _source_type is ServerTypeLiteral (defined as PrivateAttr)
        return getattr(self, "_source_type", "rfc")

    @property
    def target_server_type(self) -> str:
        """Get target server type."""
        # Type narrowing: _target_type is ServerTypeLiteral (defined as PrivateAttr)
        return getattr(self, "_target_type", "rfc")

    def _get_processing_pipeline(self) -> ProcessingPipeline:
        """Get or create processing pipeline instance."""
        # Type narrowing: _processing_pipeline is ProcessingPipeline | None (defined as PrivateAttr)
        pipeline = getattr(self, "_processing_pipeline", None)
        if pipeline is None:
            # Create TransformConfig with ProcessConfig inside
            # Convert str to ServerType enum
            source_type = m.Ldif.Config.ServerType(self.source_server_type)
            target_type = m.Ldif.Config.ServerType(self.target_server_type)
            # Use model_copy to update server types (Pydantic v2 pattern)

            config_base = m.Ldif.Config.ProcessConfig()
            config_base_model = cast("BaseModel", config_base)
            process_config = cast(
                "m.Ldif.Config.ProcessConfig",
                config_base_model.model_copy(
                    update={
                        "source_server": source_type,
                        "target_server": target_type,
                    }
                ),
            )
            # Create TransformConfig with ProcessConfig
            transform_config_base = m.Ldif.Config.TransformConfig()
            transform_config_base_model = cast("BaseModel", transform_config_base)
            config = cast(
                "m.Ldif.Config.TransformConfig",
                transform_config_base_model.model_copy(
                    update={"process_config": process_config}
                ),
            )
            pipeline = ProcessingPipeline(config)
            object.__setattr__(self, "_processing_pipeline", pipeline)
        return pipeline

    def migrate_entries(
        self,
        entries: list[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Migrate entries from source to target server format.

        Args:
            entries: Source entries to migrate.

        Returns:
            FlextResult with migrated entries.

        """
        try:
            pipeline = self._get_processing_pipeline()
            result = pipeline.execute(entries)
            if result.is_failure:
                return r[list[m.Ldif.Entry]].fail(str(result.error))

            # result.unwrap() already returns list[m.Ldif.Entry] - entries are already m.Ldif.Entry via inheritance
            # Business Rule: pipeline.execute returns FlextResult[list[m.Ldif.Entry]], so entries are already compatible
            migrated = result.unwrap()
            return r[list[m.Ldif.Entry]].ok(migrated)

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
        """Migrate a single LDIF file.

        Args:
            input_file: Source LDIF file.
            output_file: Target LDIF file (derived from input if not provided).

        Returns:
            FlextResult with migration result.

        """
        try:
            # Read input file
            if not input_file.exists():
                return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
                    f"Input file not found: {input_file}",
                )

            content = input_file.read_text(encoding="utf-8")

            # Parse entries
            parser = FlextLdifParser()  # Uses default server registry
            parse_result = parser.parse_string(
                content,
                server_type=self.source_server_type,
            )

            if parse_result.is_failure:
                return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
                    f"Parse failed: {parse_result.error}",
                )

            response = parse_result.unwrap()
            # response.entries is Sequence[m.Ldif.Entry] - entries are already m.Ldif.Entry
            # Type narrowing: response.entries contains m.Ldif.Entry
            # Convert to list and ensure type compatibility
            entries_list: list[m.Ldif.Entry] = [
                m.Ldif.Entry.model_validate(e.model_dump(mode="json"))
                for e in response.entries
            ]

            # Migrate entries
            migrate_result = self.migrate_entries(entries_list)
            if migrate_result.is_failure:
                return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
                    f"Migration failed: {migrate_result.error}",
                )

            migrated = migrate_result.unwrap()

            # Write output file
            if output_file is None:
                out_dir = self.output_dir
                if out_dir is None:
                    return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
                        "No output file or output_dir specified",
                    )
                output_file = out_dir / input_file.name

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
            output_file.write_text(write_result.unwrap(), encoding="utf-8")

            # Return result using public model classes via m alias
            # Convert m.Ldif.Entry to base Entry type for MigrationPipelineResult
            # m.Ldif.Entry is the same class as FlextLdifModelsDomains.Entry (public facade)
            # MigrationPipelineResult expects list[m.Ldif.Entry]
            # Convert using model_validate to ensure type compatibility
            converted_entries: list[m.Ldif.Entry] = [
                m.Ldif.Entry.model_validate(e.model_dump(mode="json")) for e in migrated
            ]
            # Create result using facade class which accepts base Entry type
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
                f"File migration failed: {e}"
            )

    @override
    def execute(self) -> r[m.Ldif.LdifResults.MigrationPipelineResult]:
        """Execute migration pipeline for all files in input_dir.

        Returns:
            FlextResult with migration result.

        """
        in_dir = self.input_dir
        out_dir = self.output_dir

        if in_dir is None:
            return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
                "No input_dir specified"
            )

        if out_dir is None:
            return r[m.Ldif.LdifResults.MigrationPipelineResult].fail(
                "No output_dir specified"
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
                result = self.migrate_file(input_file)
                if result.is_success:
                    res = result.unwrap()
                    total_processed += res.stats.total_entries
                    total_migrated += res.stats.processed_entries
                    # res.entries is list[m.Ldif.Entry] - convert to m.Ldif.Entry
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

            # Convert m.Ldif.Entry to base Entry type for MigrationPipelineResult
            # m.Ldif.Entry is the same class as FlextLdifModelsDomains.Entry (public facade)
            # MigrationPipelineResult expects list[m.Ldif.Entry]
            # Convert using model_validate to ensure type compatibility
            converted_all_entries: list[m.Ldif.Entry] = [
                m.Ldif.Entry.model_validate(e.model_dump(mode="json"))
                for e in all_entries
            ]
            # Create result using facade class which accepts base Entry type
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
