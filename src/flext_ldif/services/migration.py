"""LDIF Migration Pipeline - Direct Implementation.

Zero private methods - everything delegates to public services.
Pure railway-oriented programming with FlextResult chains.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Final

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.categorization import FlextLdifCategorization
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.sorting import FlextLdifSorting
from flext_ldif.services.writer import FlextLdifWriter
from flext_ldif.utilities import FlextLdifUtilities

logger: Final = FlextLogger(__name__)


class FlextLdifMigrationPipeline(FlextService[FlextLdifModels.EntryResult]):
    """LDIF Migration Pipeline - Direct Implementation.

    Zero private methods - pure service orchestration.
    All logic delegated to public service methods.

    Design:
    - FlextLdifParser: parse files
    - FlextLdifCategorization: validate, categorize, filter
    - FlextLdifSorting: sort entries
    - FlextLdifWriter: write outputs
    - FlextLdifUtilities: events

    Example:
        pipeline = FlextLdifMigrationPipeline(
            input_dir=Path("source"),
            output_dir=Path("target"),
            mode="categorized",
            categorization_rules={
                "hierarchy_objectclasses": ["organizationalUnit"],
                "user_objectclasses": ["inetOrgPerson"],
                "group_objectclasses": ["groupOfNames"],
                "acl_attributes": ["aci"],
            },
            source_server="oracle_oid",
            target_server="oracle_oud",
        )
        result = pipeline.execute()

    """

    def __init__(
        self,
        input_dir: str | Path,
        output_dir: str | Path,
        mode: FlextLdifConstants.LiteralTypes.MigrationMode = "simple",
        input_filename: str | None = None,
        output_filename: str = "migrated.ldif",
        categorization_rules: dict[str, list[str]] | None = None,
        input_files: list[str] | None = None,
        output_files: dict[str, str] | None = None,
        schema_whitelist_rules: dict[str, list[str]] | None = None,
        source_server: str = FlextLdifConstants.ServerTypes.RFC,
        target_server: str = FlextLdifConstants.ServerTypes.RFC,
        forbidden_attributes: list[str] | None = None,
        forbidden_objectclasses: list[str] | None = None,
        base_dn: str | None = None,
        *,
        sort_entries_hierarchically: bool = False,
        write_options: FlextLdifModels.WriteFormatOptions | None = None,
    ) -> None:
        """Initialize pipeline."""
        super().__init__()

        # Validate
        if mode not in {"simple", "categorized"}:
            msg = f"Invalid mode: {mode}"
            raise ValueError(msg)
        if mode == "categorized" and not categorization_rules:
            msg = "Categorized mode requires categorization_rules"
            raise ValueError(msg)

        # Store parameters as private instance attributes
        self._mode = mode
        self._input_dir = Path(input_dir)
        self._output_dir = Path(output_dir)
        self._input_filename = input_filename
        self._output_filename = output_filename
        self._input_files = input_files or []
        self._output_files = output_files or {
            FlextLdifConstants.Categories.SCHEMA: "00-schema.ldif",
            FlextLdifConstants.Categories.HIERARCHY: "01-hierarchy.ldif",
            FlextLdifConstants.Categories.USERS: "02-users.ldif",
            FlextLdifConstants.Categories.GROUPS: "03-groups.ldif",
            FlextLdifConstants.Categories.ACL: "04-acl.ldif",
            FlextLdifConstants.Categories.REJECTED: "05-rejected.ldif",
        }
        self._source_server = source_server
        self._target_server = target_server
        self._sort_hierarchically = sort_entries_hierarchically
        self._write_opts = write_options or FlextLdifModels.WriteFormatOptions()

        # Create service instances (all public APIs)
        self._categorization = FlextLdifCategorization(
            categorization_rules=categorization_rules,
            schema_whitelist_rules=schema_whitelist_rules,
            forbidden_attributes=forbidden_attributes,
            forbidden_objectclasses=forbidden_objectclasses,
            base_dn=base_dn,
        )
        self._parser = FlextLdifParser()
        self._writer = FlextLdifWriter()

    def execute(self) -> FlextResult[FlextLdifModels.EntryResult]:  # noqa: C901
        """Execute migration - pure railway pattern with public services."""
        start_time = time.time()

        # Create output directory
        try:
            self._output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return FlextResult[FlextLdifModels.EntryResult].fail(
                f"Failed to create output dir: {e}"
            )

        # Determine files to parse
        if self._mode == "simple":
            files = (
                [self._input_filename]
                if self._input_filename
                else sorted([f.name for f in self._input_dir.glob("*.ldif")])
            )
        else:
            files = self._input_files or sorted([
                f.name for f in self._input_dir.glob("*.ldif")
            ])

        # Parse all files using parser service
        all_entries: list[FlextLdifModels.Entry] = []
        for filename in files:
            file_path = self._input_dir / filename
            if not file_path.exists():
                logger.warning(f"File not found: {file_path}")
                continue

            parse_result = self._parser.parse_ldif_file(
                file_path, server_type=self._source_server
            )
            if parse_result.is_failure:
                return FlextResult[FlextLdifModels.EntryResult].fail(
                    f"Parse failed: {parse_result.error}"
                )

            parse_response = parse_result.unwrap()
            entries = (
                parse_response
                if isinstance(parse_response, list)
                else parse_response.entries
            )
            all_entries.extend(entries)
            logger.info(f"Parsed {len(entries)} from {filename}")

        logger.info(f"Total parsed: {len(all_entries)}")

        # Railway pattern: categorization service chain
        categorized_result = (
            FlextResult[list[FlextLdifModels.Entry]]
            .ok(all_entries)
            # Validate DNs (public method)
            .flat_map(self._categorization.validate_dns)
            # Categorize entries (public method)
            .flat_map(self._categorization.categorize_entries)
            # Filter by base DN (public method)
            .map(self._categorization.filter_by_base_dn)
            # Remove forbidden attributes (public method)
            .map(self._categorization.remove_forbidden_attributes)
            # Remove forbidden objectClasses (public method)
            .map(self._categorization.remove_forbidden_objectclasses)
        )

        if categorized_result.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(
                categorized_result.error
            )

        categories = categorized_result.unwrap()

        # Filter schema by OIDs if needed
        if FlextLdifConstants.Categories.SCHEMA in categories:
            schema_result = self._categorization.filter_schema_by_oids(
                categories[FlextLdifConstants.Categories.SCHEMA]
            )
            if schema_result.is_success:
                categories[FlextLdifConstants.Categories.SCHEMA] = (
                    schema_result.unwrap()
                )

        # Sort if configured (using sorting service builder)
        if self._sort_hierarchically:
            for cat in {
                FlextLdifConstants.Categories.HIERARCHY,
                FlextLdifConstants.Categories.USERS,
                FlextLdifConstants.Categories.GROUPS,
            }:
                cat_entries = categories.get(cat)
                if cat_entries:
                    # build() already executes and returns unwrapped result
                    sorted_entries = (
                        FlextLdifSorting.builder()
                        .with_entries(cat_entries)
                        .with_target("entries")
                        .with_strategy("hierarchy")
                        .build()
                    )
                    categories[cat] = sorted_entries
                    logger.info(f"Sorted '{cat}' hierarchically")

        # Write outputs using writer service
        file_paths: dict[str, str] = {}
        entry_counts: dict[str, int] = {}

        if self._mode == "simple":
            # Single file output
            output_path = self._output_dir / self._output_filename
            all_output_entries = [
                entry for entries in categories.values() for entry in entries
            ]

            write_result = self._writer.write(
                entries=all_output_entries,
                target_server_type=self._target_server,
                output_target="file",
                output_path=output_path,
                format_options=self._write_opts,
            )

            if write_result.is_failure:
                return FlextResult[FlextLdifModels.EntryResult].fail(
                    f"Write failed: {write_result.error}"
                )

            file_paths["output"] = str(output_path)
            entry_counts["output"] = len(all_output_entries)
            logger.info(f"Wrote {len(all_output_entries)} entries to {output_path}")

        else:
            # Categorized mode: 6 files
            for category, entries in categories.items():
                if not entries:
                    continue

                output_filename = self._output_files.get(category)
                if not output_filename:
                    continue

                output_path = self._output_dir / output_filename

                write_result = self._writer.write(
                    entries=entries,
                    target_server_type=self._target_server,
                    output_target="file",
                    output_path=output_path,
                    format_options=self._write_opts,
                )

                if write_result.is_failure:
                    return FlextResult[FlextLdifModels.EntryResult].fail(
                        f"Write {category} failed: {write_result.error}"
                    )

                file_paths[category] = str(output_path)
                entry_counts[category] = len(entries)
                logger.info(
                    f"Wrote {len(entries)} entries to {output_path} ({category})"
                )

        # Build statistics (inline, no private method)
        duration_ms = int((time.time() - start_time) * 1000)
        total_entries = sum(entry_counts.values())
        total_rejected = sum(
            len(v) for v in self._categorization.rejection_tracker.values()
        )
        total_processed = total_entries - entry_counts.get(
            FlextLdifConstants.Categories.REJECTED, 0
        )

        # Emit event using utilities service
        error_details = [
            {"reason": reason, "count": len(entries)}
            for reason, entries in self._categorization.rejection_tracker.items()
        ]
        event = FlextLdifUtilities.Events.log_and_emit_migration_event(
            logger=logger,
            migration_operation=f"pipeline_{self._mode}",
            source_server=self._source_server,
            target_server=self._target_server,
            entries_processed=total_entries + total_rejected,
            entries_migrated=total_processed,
            entries_failed=total_rejected,
            migration_duration_ms=duration_ms,
            error_details=error_details,
        )

        # Create statistics model
        statistics = FlextLdifModels.Statistics(events=[event])

        # Return EntryResult
        return FlextResult[FlextLdifModels.EntryResult].ok(
            FlextLdifModels.EntryResult(
                entries_by_category={},  # Empty - data in files
                statistics=statistics,
                file_paths=file_paths,
            )
        )
