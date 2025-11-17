"""LDIF Migration Pipeline - Direct Implementation.

Zero private methods - everything delegates to public services.
Pure railway-oriented programming with FlextResult chains.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Final, cast

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.categorization import FlextLdifCategorization
from flext_ldif.services.filters import FlextLdifFilters
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
            source_server="oid",
            target_server="oud",
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
        # Validate input_files - use empty list if None, but preserve actual list
        if input_files is None:
            self._input_files: list[str] = []
        else:
            self._input_files = input_files
        # Validate output_files - use defaults if None
        if output_files is None:
            self._output_files = {
                FlextLdifConstants.Categories.SCHEMA: "00-schema.ldif",
                FlextLdifConstants.Categories.HIERARCHY: "01-hierarchy.ldif",
                FlextLdifConstants.Categories.USERS: "02-users.ldif",
                FlextLdifConstants.Categories.GROUPS: "03-groups.ldif",
                FlextLdifConstants.Categories.ACL: "04-acl.ldif",
                FlextLdifConstants.Categories.REJECTED: "05-rejected.ldif",
            }
        else:
            self._output_files = output_files
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
            server_type=self._source_server,
        )
        self._parser = FlextLdifParser()
        self._writer = FlextLdifWriter()
        # Create DN registry for case normalization during migration
        self._dn_registry = FlextLdifModels.DnRegistry()

    def _create_output_directory(self) -> FlextResult[bool]:
        """Create output directory with proper error handling."""
        try:
            self._output_dir.mkdir(parents=True, exist_ok=True)
            return FlextResult[bool].ok(True)
        except OSError as e:
            return FlextResult[bool].fail(f"Failed to create output dir: {e}")

    def _determine_files(self) -> list[str]:
        """Determine which LDIF files to parse based on mode."""
        if self._mode == "simple":
            return (
                [self._input_filename]
                if self._input_filename
                else sorted([f.name for f in self._input_dir.glob("*.ldif")])
            )
        return self._input_files or sorted([
            f.name for f in self._input_dir.glob("*.ldif")
        ])

    def _parse_files(
        self,
        files: list[str],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse all input LDIF files using parser service."""
        all_entries: list[FlextLdifModels.Entry] = []

        for filename in files:
            file_path = self._input_dir / filename
            if not file_path.exists():
                logger.warning("File not found: %s", file_path)
                continue

            parse_result = self._parser.parse_ldif_file(
                file_path,
                server_type=self._source_server,
            )
            if parse_result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Parse failed: {parse_result.error}",
                )

            parse_response = parse_result.unwrap()
            entries = (
                parse_response
                if isinstance(parse_response, list)
                else parse_response.entries
            )
            # Register all DNs in registry for case normalization
            for entry in entries:
                if entry.dn and entry.dn.value:
                    _ = self._dn_registry.register_dn(entry.dn.value)
            all_entries.extend(cast("list[FlextLdifModels.Entry]", entries))
            logger.info(f"Parsed {len(entries)} from {filename}")

        logger.info(f"Total parsed: {len(all_entries)}")
        return FlextResult[list[FlextLdifModels.Entry]].ok(all_entries)

    def _apply_categorization(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[dict[str, list[FlextLdifModels.Entry]]]:
        """Apply categorization chain using railway pattern."""
        categorized_result = (
            FlextResult[list[FlextLdifModels.Entry]]
            .ok(entries)
            .flat_map(self._categorization.validate_dns)
            .flat_map(self._categorization.categorize_entries)
            .map(self._categorization.filter_by_base_dn)
        )

        if categorized_result.is_failure:
            return FlextResult[dict[str, list[FlextLdifModels.Entry]]].fail(
                categorized_result.error,
            )

        categories = categorized_result.unwrap()

        # Apply FlextLdifFilters directly - remove forbidden attributes/objectclasses
        forbidden_attrs = self._categorization.forbidden_attributes
        forbidden_ocs = self._categorization.forbidden_objectclasses

        if forbidden_attrs or forbidden_ocs:
            for category, cat_entries in categories.items():
                # Don't modify rejected entries (audit trail)
                if category != FlextLdifConstants.Categories.REJECTED:
                    filtered_entries = []
                    for entry in cat_entries:
                        filtered_entry = entry

                        # Apply attribute filtering
                        if forbidden_attrs:
                            attr_result = FlextLdifFilters.remove_attributes(
                                filtered_entry,
                                forbidden_attrs,
                            )
                            if attr_result.is_success:
                                filtered_entry = attr_result.unwrap()

                        # Apply objectClass filtering
                        if forbidden_ocs:
                            oc_result = FlextLdifFilters.remove_objectclasses(
                                filtered_entry,
                                forbidden_ocs,
                            )
                            if oc_result.is_success:
                                filtered_entry = oc_result.unwrap()

                        filtered_entries.append(filtered_entry)

                    # Replace category entries with filtered entries
                    categories[category] = filtered_entries

        # Filter schema by OIDs if needed
        if FlextLdifConstants.Categories.SCHEMA in categories:
            schema_result = self._categorization.filter_schema_by_oids(
                categories[FlextLdifConstants.Categories.SCHEMA],
            )
            if schema_result.is_success:
                categories[FlextLdifConstants.Categories.SCHEMA] = (
                    schema_result.unwrap()
                )

        # DUPLICATE entries with ACL attributes to ACL category
        # Entries categorized as hierarchy/users/groups that have ACL attributes
        # must appear in BOTH their primary category (without ACL) AND acl category (with ACL)
        acl_attr_names = {
            "aci",
        }  # Normalized ACL attribute names (orclaci→aci already transformed)
        for category in [
            FlextLdifConstants.Categories.HIERARCHY,
            FlextLdifConstants.Categories.USERS,
            FlextLdifConstants.Categories.GROUPS,
        ]:
            if category not in categories:
                continue

            for entry in categories[category]:
                # Check if entry has ACL attributes
                if entry.attributes:
                    attrs_dict = entry.attributes.attributes
                    has_acl = any(
                        attr_name.lower() in acl_attr_names for attr_name in attrs_dict
                    )

                    if has_acl:
                        # Duplicate entry to ACL category (deep copy to avoid shared references)
                        acl_copy = entry.model_copy(deep=True)
                        if FlextLdifConstants.Categories.ACL not in categories:
                            categories[FlextLdifConstants.Categories.ACL] = []
                        categories[FlextLdifConstants.Categories.ACL].append(acl_copy)

        return FlextResult[dict[str, list[FlextLdifModels.Entry]]].ok(categories)

    def _sort_categories(
        self,
        categories: dict[str, list[FlextLdifModels.Entry]],
    ) -> None:
        """Sort hierarchical categories in-place if configured."""
        if not self._sort_hierarchically:
            return

        for cat in {
            FlextLdifConstants.Categories.HIERARCHY,
            FlextLdifConstants.Categories.USERS,
            FlextLdifConstants.Categories.GROUPS,
        }:
            cat_entries = categories.get(cat)
            if cat_entries:
                sorted_entries = (
                    FlextLdifSorting.builder()
                    .with_entries(cat_entries)
                    .with_target("entries")
                    .with_strategy("hierarchy")
                    .build()
                )
                categories[cat] = sorted_entries
                logger.info("Sorted '%s' hierarchically", cat)

    def _write_categories(
        self,
        categories: dict[str, list[FlextLdifModels.Entry]],
    ) -> FlextResult[tuple[dict[str, str], dict[str, int]]]:
        """Write categorized entries to output files."""
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
                return FlextResult[tuple[dict[str, str], dict[str, int]]].fail(
                    f"Write failed: {write_result.error}",
                )

            file_paths["output"] = str(output_path)
            entry_counts["output"] = len(all_output_entries)
            logger.info(f"Wrote {len(all_output_entries)} entries to {output_path}")
        else:
            # Categorized mode: multiple files
            # Map categories to phase numbers for migration headers
            category_to_phase = {
                FlextLdifConstants.Categories.SCHEMA: 0,
                FlextLdifConstants.Categories.HIERARCHY: 1,
                FlextLdifConstants.Categories.USERS: 2,
                FlextLdifConstants.Categories.GROUPS: 3,
                FlextLdifConstants.Categories.ACL: 4,
                FlextLdifConstants.Categories.REJECTED: 5,
            }

            for category, entries in categories.items():
                if not entries:
                    continue

                output_filename = self._output_files.get(category)
                if not output_filename:
                    continue

                output_path = self._output_dir / output_filename

                # Build template_data for migration headers
                phase_num = category_to_phase.get(category, -1)
                # Validate base_dn - use empty string if None
                base_dn_value = self._categorization._base_dn  # noqa: SLF001
                if base_dn_value is None:
                    base_dn_value = ""
                elif not isinstance(base_dn_value, str):
                    base_dn_value = str(base_dn_value)

                template_data = {
                    "phase": phase_num,
                    "phase_name": category.upper(),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "source_server": self._source_server,
                    "target_server": self._target_server,
                    "base_dn": base_dn_value,
                    "total_entries": len(entries),
                    "processed_entries": len(entries),
                    "rejected_entries": 0,
                    "schema_whitelist_enabled": bool(
                        self._categorization._schema_whitelist_rules,  # noqa: SLF001
                    ),
                    "sort_entries_hierarchically": self._sort_hierarchically,
                    "server_type": self._target_server,
                }

                # Create category-specific WriteFormatOptions for phase-aware processing
                # This allows OUD quirks to apply different formatting based on output file category
                category_write_opts = self._write_opts.model_copy(
                    update={"entry_category": category},
                )

                # Initialize processed_entries with base entries
                # Will be updated for ACL category below
                processed_entries = entries

                # For ACL category: add base_dn and dn_registry to entry metadata
                if category == FlextLdifConstants.Categories.ACL:
                    base_dn = self._categorization._base_dn  # noqa: SLF001
                    # Add base_dn and dn_registry to entry metadata for ACL DN normalization
                    entries_with_metadata = []
                    for entry in entries:
                        # Create or update entry metadata
                        if not entry.entry_metadata:
                            entry.entry_metadata = {}
                        if "extensions" not in entry.entry_metadata:
                            entry.entry_metadata["extensions"] = {}
                        extensions = entry.entry_metadata["extensions"]
                        if not isinstance(extensions, dict):
                            extensions = {}
                            entry.entry_metadata["extensions"] = extensions
                        if base_dn:
                            extensions["base_dn"] = base_dn
                        # Add dn_registry for case normalization
                        extensions["dn_registry"] = self._dn_registry
                        entries_with_metadata.append(entry)
                    processed_entries = entries_with_metadata

                write_result = self._writer.write(
                    entries=processed_entries,
                    target_server_type=self._target_server,
                    output_target="file",
                    output_path=output_path,
                    format_options=category_write_opts,  # ← Category-specific options
                    template_data=template_data,
                )

                if write_result.is_failure:
                    return FlextResult[tuple[dict[str, str], dict[str, int]]].fail(
                        f"Write {category} failed: {write_result.error}",
                    )

                file_paths[category] = str(output_path)
                entry_counts[category] = len(entries)
                logger.info(
                    f"Wrote {len(entries)} entries to {output_path} ({category})",
                )

        return FlextResult[tuple[dict[str, str], dict[str, int]]].ok((
            file_paths,
            entry_counts,
        ))

    def execute(self) -> FlextResult[FlextLdifModels.EntryResult]:
        """Execute migration - pure railway pattern with public services."""
        start_time = time.time()

        # Step 1: Create output directory
        dir_result = self._create_output_directory()
        if dir_result.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(dir_result.error)

        # Step 2: Determine files to parse
        files = self._determine_files()

        # Step 3: Parse all input files
        entries_result = self._parse_files(files)
        if entries_result.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(entries_result.error)

        # Step 4: Apply categorization chain
        categories_result = self._apply_categorization(entries_result.unwrap())
        if categories_result.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(
                categories_result.error,
            )

        categories = categories_result.unwrap()

        # Step 5: Sort hierarchically if configured
        self._sort_categories(categories)

        # Step 6: Write output files
        write_result = self._write_categories(categories)
        if write_result.is_failure:
            return FlextResult[FlextLdifModels.EntryResult].fail(write_result.error)

        file_paths, entry_counts = write_result.unwrap()

        # Step 7: Build statistics and emit event
        duration_ms = int((time.time() - start_time) * 1000)
        total_entries = sum(entry_counts.values())
        total_rejected = sum(
            len(v) for v in self._categorization.rejection_tracker.values()
        )
        total_processed = total_entries - entry_counts.get(
            FlextLdifConstants.Categories.REJECTED,
            0,
        )

        error_details = [
            FlextLdifModels.ErrorDetail(
                item=f"rejected_{reason}",
                error=f"Rejected {len(entries)} entries: {reason}",
                context={"reason": reason, "count": len(entries)},
            )
            for reason, entries in self._categorization.rejection_tracker.items()
        ]
        # Create migration event config
        migration_config = FlextLdifModels.MigrationEventConfig(
            migration_operation=f"pipeline_{self._mode}",
            source_server=self._source_server,
            target_server=self._target_server,
            entries_processed=total_entries + total_rejected,
            entries_migrated=total_processed,
            entries_failed=total_rejected,
            migration_duration_ms=duration_ms,
            error_details=error_details,
        )
        event = FlextLdifUtilities.Events.log_and_emit_migration_event(
            logger=logger,
            config=migration_config,
        )

        # Create statistics model
        statistics = FlextLdifModels.Statistics(events=[event])

        # Return EntryResult
        return FlextResult[FlextLdifModels.EntryResult].ok(
            FlextLdifModels.EntryResult(
                entries_by_category={},  # Empty - data in files
                statistics=statistics,
                file_paths=file_paths,
            ),
        )
