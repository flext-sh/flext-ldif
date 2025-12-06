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
from pydantic import PrivateAttr

from flext_ldif._utilities.configs import ProcessConfig, ServerType
from flext_ldif._utilities.pipeline import ProcessingPipeline
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.writer import FlextLdifWriter

logger: Final = FlextLogger(__name__)


class FlextLdifMigrationPipeline(FlextLdifServiceBase[m.MigrationPipelineResult]):
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
    _source_type: c.LiteralTypes.ServerTypeLiteral = PrivateAttr(default="rfc")
    _target_type: c.LiteralTypes.ServerTypeLiteral = PrivateAttr(default="rfc")
    _processing_pipeline: ProcessingPipeline | None = PrivateAttr(default=None)

    def __init__(
        self,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        source_server_type: c.LiteralTypes.ServerTypeLiteral = "rfc",
        target_server_type: c.LiteralTypes.ServerTypeLiteral = "rfc",
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize migration pipeline.

        Args:
            input_dir: Directory containing source LDIF files.
            output_dir: Directory for output LDIF files.
            source_server_type: Source server type (e.g., "oid", "openldap").
            target_server_type: Target server type (e.g., "oud", "389ds").
            **kwargs: Additional kwargs for base class.

        """
        super().__init__(**kwargs)
        # Store as instance attributes via setattr for frozen Pydantic compatibility
        object.__setattr__(self, "_input_dir", input_dir)
        object.__setattr__(self, "_output_dir", output_dir)
        object.__setattr__(self, "_source_type", source_server_type)
        object.__setattr__(self, "_target_type", target_server_type)
        object.__setattr__(self, "_processing_pipeline", None)

    @property
    def input_dir(self) -> Path | None:
        """Get input directory."""
        return cast("Path | None", getattr(self, "_input_dir", None))

    @property
    def output_dir(self) -> Path | None:
        """Get output directory."""
        return cast("Path | None", getattr(self, "_output_dir", None))

    @property
    def source_server_type(self) -> c.LiteralTypes.ServerTypeLiteral:
        """Get source server type."""
        return cast(
            "c.LiteralTypes.ServerTypeLiteral",
            getattr(self, "_source_type", "rfc"),
        )

    @property
    def target_server_type(self) -> c.LiteralTypes.ServerTypeLiteral:
        """Get target server type."""
        return cast(
            "c.LiteralTypes.ServerTypeLiteral",
            getattr(self, "_target_type", "rfc"),
        )

    def _get_processing_pipeline(self) -> ProcessingPipeline:
        """Get or create processing pipeline instance."""
        pipeline = cast(
            "ProcessingPipeline | None",
            getattr(self, "_processing_pipeline", None),
        )
        if pipeline is None:
            # ProcessConfig accepts ServerType - cast Literal types for compatibility
            config = ProcessConfig(
                source_server=cast("ServerType", self.source_server_type),
                target_server=cast("ServerType | None", self.target_server_type),
            )
            pipeline = ProcessingPipeline(config)
            object.__setattr__(self, "_processing_pipeline", pipeline)
        return pipeline

    def migrate_entries(
        self,
        entries: list[m.Entry],
    ) -> r[list[m.Entry]]:
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
                return r[list[m.Entry]].fail(str(result.error))

            # result.unwrap() already returns list[m.Entry] - entries are already m.Entry via inheritance
            # Business Rule: pipeline.execute returns FlextResult[list[m.Entry]], so entries are already compatible
            migrated = result.unwrap()
            return r[list[m.Entry]].ok(migrated)

        except Exception as e:
            logger.exception(
                "Migration failed",
                source=self.source_server_type,
                target=self.target_server_type,
            )
            return r[list[m.Entry]].fail(f"Migration failed: {e}")

    def migrate_file(
        self,
        input_file: Path,
        output_file: Path | None = None,
    ) -> r[m.MigrationPipelineResult]:
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
                return r[m.MigrationPipelineResult].fail(
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
                return r[m.MigrationPipelineResult].fail(
                    f"Parse failed: {parse_result.error}",
                )

            response = parse_result.unwrap()
            # response.entries is Sequence[m.Entry] - entries are already m.Entry via inheritance
            # Business Rule: m.Entry extends m.Entry, so entries are already compatible
            # Use cast for type checker - same model, public facade
            entries = [cast("m.Entry", e) for e in response.entries]

            # Migrate entries
            migrate_result = self.migrate_entries(entries)
            if migrate_result.is_failure:
                return r[m.MigrationPipelineResult].fail(
                    f"Migration failed: {migrate_result.error}",
                )

            migrated = migrate_result.unwrap()

            # Write output file
            if output_file is None:
                out_dir = self.output_dir
                if out_dir is None:
                    return r[m.MigrationPipelineResult].fail(
                        "No output file or output_dir specified",
                    )
                output_file = out_dir / input_file.name

            writer = FlextLdifWriter()
            write_result = writer.write_to_string(
                migrated,
                server_type=self.target_server_type,
            )

            if write_result.is_failure:
                return r[m.MigrationPipelineResult].fail(
                    f"Write failed: {write_result.error}",
                )

            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(write_result.unwrap(), encoding="utf-8")

            # Return result using public model classes via m alias
            # migrated is list[m.Entry] but MigrationPipelineResult.entries expects list[m.Entry]
            # Business Rule: m.Entry extends m.Entry, so entries are compatible via inheritance
            # Use cast for type checker - same model, public facade (using full module path to avoid import)
            result = m.MigrationPipelineResult(
                entries=cast("list[m.Entry]", migrated),
                output_files=[str(output_file)],
                stats=m.LdifResults.Statistics(
                    total_entries=len(entries),
                    processed_entries=len(migrated),
                ),
            )

            return r[m.MigrationPipelineResult].ok(result)

        except Exception as e:
            logger.exception(
                "File migration failed",
                input_file=str(input_file),
            )
            return r[m.MigrationPipelineResult].fail(f"File migration failed: {e}")

    @override
    def execute(
        self,
        **_kwargs: str | float | bool | None,
    ) -> r[m.MigrationPipelineResult]:
        """Execute migration pipeline for all files in input_dir.

        Returns:
            FlextResult with migration result.

        """
        in_dir = self.input_dir
        out_dir = self.output_dir

        if in_dir is None:
            return r[m.MigrationPipelineResult].fail("No input_dir specified")

        if out_dir is None:
            return r[m.MigrationPipelineResult].fail("No output_dir specified")

        if not in_dir.exists():
            return r[m.MigrationPipelineResult].fail(
                f"Input directory not found: {in_dir}",
            )

        try:
            total_processed = 0
            total_migrated = 0
            all_entries: list[m.Entry] = []
            output_files: list[str] = []

            for input_file in in_dir.glob("*.ldif"):
                result = self.migrate_file(input_file)
                if result.is_success:
                    res = result.unwrap()
                    total_processed += res.stats.total_entries
                    total_migrated += res.stats.processed_entries
                    # res.entries is list[m.Entry] but all_entries is list[m.Entry]
                    # Business Rule: m.Entry extends m.Entry, so entries are compatible via inheritance
                    # Use cast for type checker - same model, public facade
                    all_entries.extend(cast("list[m.Entry]", res.entries))
                    output_files.extend(res.output_files)
                else:
                    logger.warning(
                        "File migration failed",
                        file=str(input_file),
                        error=str(result.error),
                    )

            # all_entries is list[m.Entry] but MigrationPipelineResult.entries expects list[m.Entry]
            # Business Rule: m.Entry extends m.Entry, so entries are compatible via inheritance
            # Use cast for type checker - same model, public facade (using full module path to avoid import)
            pipeline_result = m.MigrationPipelineResult(
                entries=cast("list[m.Entry]", all_entries),
                output_files=output_files,
                stats=m.LdifResults.Statistics(
                    total_entries=total_processed,
                    processed_entries=total_migrated,
                ),
            )

            return r[m.MigrationPipelineResult].ok(pipeline_result)

        except Exception as e:
            logger.exception("Migration pipeline failed")
            return r[m.MigrationPipelineResult].fail(f"Migration pipeline failed: {e}")


__all__ = ["FlextLdifMigrationPipeline"]
