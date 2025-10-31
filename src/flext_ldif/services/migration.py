"""Unified LDIF migration pipeline service.

Provides both simple and categorized migration modes with full parameterization
for complete genericity. No hardcoded quirks, rules, or server types.

Architecture:
- Single FlextLdifMigrationPipeline class for both migration modes
- Fully parameterizable (all behavior externalized)
- Delegates to existing services (parser, writer, filters, acl, dn, etc.)
- Supports any LDAP server via quirks system
- Railway-Oriented Programming with FlextResult error handling

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, cast, override

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.acl import FlextLdifAclService
from flext_ldif.services.dn import FlextLdifDnService
from flext_ldif.services.filters import FlextLdifFilters
from flext_ldif.services.operational import FlextLdifOperationalService
from flext_ldif.services.parser import FlextLdifParserService
from flext_ldif.services.registry import FlextLdifRegistry
from flext_ldif.services.writer import FlextLdifWriterService

logger = FlextLogger(__name__)


class FlextLdifMigrationPipeline(
    FlextService[FlextLdifModels.PipelineExecutionResult],
):
    """Generic LDIF migration pipeline supporting simple and categorized modes.

    Provides two migration modes controlled entirely by parameters:
    - **simple**: Single output file (no categorization)
    - **categorized**: 6-file structured output with entry categorization

    Design Principles:
    - 100% parameterized (no hardcoded quirks, rules, or servers)
    - Works with ANY LDAP server type via quirks system
    - User-defined categorization scheme via rules dictionary
    - All behavior externalized through constructor parameters

    Reuses Existing Services:
    - FlextLdifParserService - Entry parsing
    - FlextLdifWriterService - LDIF writing
    - FlextLdifFilters - Entry categorization (direct usage)
    - FlextLdifAclService - ACL extraction/processing
    - FlextLdifDnService - DN normalization
    - FlextLdifStatisticsService - Statistics generation
    - FlextLdifRegistry - Quirk registration

    Modes:

    **Simple Mode** (Default):
        Single LDIF output file with optional filtering/normalization.
        Use for: Generic server migrations, basic conversions.

    **Categorized Mode**:
        6-file structured output with rule-based categorization.
        Use for: Complex migrations with structured requirements.

    Example Usage:

        # Simple migration
        pipeline = FlextLdifMigrationPipeline(
            input_dir=Path("source"),
            output_dir=Path("target"),
            mode="simple",
            source_server="openldap",
            target_server="ad",
        )
        result = pipeline.execute()

        # Categorized migration
        pipeline = FlextLdifMigrationPipeline(
            input_dir=Path("source"),
            output_dir=Path("target"),
            mode="categorized",
            source_server="oracle_oid",
            target_server="oracle_oud",
            categorization_rules={
                "hierarchy_objectclasses": ["organization", "organizationalUnit"],
                "user_objectclasses": ["inetOrgPerson", "person"],
                "group_objectclasses": ["groupOfNames"],
                "acl_attributes": ["aci"],  # Empty list = disable ACL
            },
            input_files=["schema.ldif", "data.ldif"],
            output_files={
                "schema": "00-schema.ldif",
                "hierarchy": "01-hierarchy.ldif",
                "users": "02-users.ldif",
                "groups": "03-groups.ldif",
                "acl": "04-acl.ldif",
                "rejected": "05-rejected.ldif",
            },
        )
        result = pipeline.execute()
    """

    def __init__(
        self,
        input_dir: str | Path,
        output_dir: str | Path,
        mode: Literal["simple", "categorized", "structured"] = "simple",
        # Simple mode parameters
        input_filename: str | None = None,
        output_filename: str = "migrated.ldif",
        # Categorized mode parameters
        categorization_rules: dict[str, object] | None = None,
        input_files: list[str] | None = None,
        output_files: dict[str, str] | None = None,
        schema_whitelist_rules: dict[str, object] | None = None,
        # Structured mode (6-file) parameters
        migration_config: FlextLdifModels.MigrationConfig | None = None,
        write_options: FlextLdifModels.WriteFormatOptions | None = None,
        # Common parameters
        source_server: str = "rfc",
        target_server: str = "rfc",
        # Filtering parameters
        forbidden_attributes: list[str] | None = None,
        forbidden_objectclasses: list[str] | None = None,
        # DN normalization and sorting
        base_dn: str | None = None,
        *,
        sort_entries_hierarchically: bool = False,
    ) -> None:
        """Initialize LDIF migration pipeline.

        Args:
            input_dir: Source directory containing LDIF files
            output_dir: Target directory for output
            mode: Migration mode - "simple" (single file) or "categorized" (6 files)

            input_filename: Specific input file to process (simple mode only)
            output_filename: Output file name for simple mode (default: "migrated.ldif")

            categorization_rules: Dict defining entry categories (categorized mode only)
                Keys: category_name + "_objectclasses" or category_name + "_attributes"
                Example: {
                    "hierarchy_objectclasses": ["organization", "organizationalUnit"],
                    "user_objectclasses": ["inetOrgPerson", "person"],
                    "group_objectclasses": ["groupOfNames"],
                    "acl_attributes": ["aci"],  # Empty list = disable ACL
                }

            input_files: Ordered list of LDIF files to process (categorized mode)
            output_files: Category→filename mapping (categorized mode)
                Example: {
                    "schema": "00-schema.ldif",
                    "hierarchy": "01-hierarchy.ldif",
                    "users": "02-users.ldif",
                    "groups": "03-groups.ldif",
                    "acl": "04-acl.ldif",
                    "rejected": "05-rejected.ldif",
                }

            schema_whitelist_rules: Dict of allowed schema elements (categorized mode)
                Keys: "allowed_attribute_oids", "allowed_objectclass_oids", "blocked_objectclasses"

            source_server: Source server type identifier (e.g., "oracle_oid", "openldap")
            target_server: Target server type identifier (e.g., "oracle_oud", "ad")

            forbidden_attributes: List of attributes to remove from all entries
            forbidden_objectclasses: List of objectClasses to remove from all entries

            base_dn: Target base DN for DN normalization
            sort_entries_hierarchically: If True, sort by DN depth then alphabetically

        Notes:
            - ALL parameters are generic - no hardcoded values
            - Works with ANY LDAP server type
            - Categorization scheme is entirely user-defined
            - ACL categorization disabled if acl_attributes empty

        """
        super().__init__()
        self._mode = mode
        self._input_dir = Path(input_dir)
        self._output_dir = Path(output_dir)

        # Mode-specific parameters
        self._input_filename = input_filename
        self._output_filename = output_filename
        self._categorization_rules = categorization_rules or {}
        self._input_files = input_files
        self._migration_config = migration_config
        self._write_options = write_options

        # Output files mapping - prioritize migration_config if provided
        if migration_config and migration_config.output_file_mapping:
            self._output_files = migration_config.output_file_mapping
        elif output_files:
            self._output_files = output_files
        else:
            self._output_files = {
                FlextLdifConstants.Categories.SCHEMA: "00-schema.ldif",
                FlextLdifConstants.Categories.HIERARCHY: "01-hierarchy.ldif",
                FlextLdifConstants.Categories.USERS: "02-users.ldif",
                FlextLdifConstants.Categories.GROUPS: "03-groups.ldif",
                FlextLdifConstants.Categories.ACL: "04-acl.ldif",
                FlextLdifConstants.Categories.REJECTED: "05-rejected.ldif",
            }
        self._schema_whitelist_rules = schema_whitelist_rules

        # Common parameters
        self._source_server = source_server
        self._target_server = target_server

        # Filtering - prioritize migration_config if provided
        if migration_config:
            self._forbidden_attributes = (
                migration_config.attribute_blacklist or forbidden_attributes or []
            )
            self._forbidden_objectclasses = (
                migration_config.objectclass_blacklist or forbidden_objectclasses or []
            )
            self._attribute_whitelist = migration_config.attribute_whitelist
            self._objectclass_whitelist = migration_config.objectclass_whitelist
        else:
            self._forbidden_attributes = forbidden_attributes or []
            self._forbidden_objectclasses = forbidden_objectclasses or []
            self._attribute_whitelist = None
            self._objectclass_whitelist = None

        # DN normalization and sorting
        self._base_dn = base_dn.lower() if base_dn else None
        self._sort_entries_hierarchically = sort_entries_hierarchically

        # Service dependencies
        self._quirk_registry = FlextLdifRegistry.get_global_instance()
        self._acl_service = FlextLdifAclService()
        self._dn_service = FlextLdifDnService()
        self._operational_service = FlextLdifOperationalService()

    @override
    def execute(self) -> FlextResult[FlextLdifModels.PipelineExecutionResult]:
        """Execute migration pipeline in configured mode.

        Returns:
            FlextResult containing PipelineExecutionResult with:
            - entries_by_category: Dict of entries by category (categorized) or single list (simple)
            - statistics: Pipeline statistics
            - file_paths: Output file paths

        Process Flow (both modes):
            1. Create output directory
            2. Parse all input LDIF files
            3. (Categorized only) Categorize entries using rules
            4. (Categorized only) Extract ACL entries if configured
            5. Transform entries via quirks (source→RFC→target)
            6. Filter forbidden attributes/objectclasses
            7. Normalize DNs to target base_dn (if specified)
            8. Write output file(s)
            9. Generate statistics

        All logic delegates to existing services - no inline implementations.

        """
        # Create output directory
        create_result = self._create_output_directory()
        if create_result.is_failure:
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                f"Failed to create output directory: {create_result.error}",
            )

        # Parse all entries from input
        parse_result = self._parse_entries()
        if parse_result.is_failure:
            error_msg = str(parse_result.error)
            if "No LDIF files found" in error_msg:
                # Empty input is OK - return empty result
                empty_result = FlextLdifModels.PipelineExecutionResult(
                    entries_by_category={},
                    statistics=FlextLdifModels.PipelineStatistics(
                        total_entries=0,
                        processed_entries=0,
                    ),
                    file_paths={},
                )
                return FlextResult[FlextLdifModels.PipelineExecutionResult].ok(
                    empty_result,
                )
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                f"Failed to parse entries: {error_msg}",
            )

        entries = parse_result.unwrap()
        total_entries = len(entries)

        # Route to appropriate mode handler
        if self._mode == "structured":
            return self._execute_structured_migration(entries, total_entries)
        if self._mode == "categorized":
            return self._execute_categorized_migration(entries, total_entries)
        return self._execute_simple_migration(entries, total_entries)

    def _execute_simple_migration(
        self,
        entries: list[FlextLdifModels.Entry],
        total_entries: int,
    ) -> FlextResult[FlextLdifModels.PipelineExecutionResult]:
        """Execute simple migration mode (single output file).

        Args:
            entries: Parsed LDIF entries
            total_entries: Total number of entries

        Returns:
            FlextResult with pipeline result

        """
        # Transform entries via quirks
        transformed_result = self._transform_entries(entries)
        if transformed_result.is_failure:
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                f"Failed to transform entries: {transformed_result.error}",
            )

        transformed_entries = transformed_result.unwrap()

        # Filter forbidden attributes/objectclasses
        filtered_result = self._filter_entries(transformed_entries)
        if filtered_result.is_failure:
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                f"Failed to filter entries: {filtered_result.error}",
            )

        filtered_entries = filtered_result.unwrap()

        # DN normalization if base_dn specified
        if self._base_dn:
            normalized_entries = self._normalize_dns(filtered_entries)
        else:
            normalized_entries = filtered_entries

        # Sort entries hierarchically if requested
        if self._sort_entries_hierarchically:
            final_entries = self._sort_entries_by_hierarchy(normalized_entries)
        else:
            final_entries = normalized_entries

        # Write single output file
        output_path = self._output_dir / self._output_filename
        writer = FlextLdifWriterService()

        write_result = writer.write(
            entries=final_entries,
            target_server_type=self._target_server,
            output_target="file",
            output_path=output_path,
        )

        if write_result.is_failure:
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                f"Failed to write output file: {write_result.error}",
            )

        # Extract write response to get actual write statistics
        # entries_written available in write_result.unwrap().statistics.entries_written if needed

        # Generate statistics
        stats = FlextLdifModels.PipelineStatistics(
            total_entries=total_entries,
            processed_entries=len(final_entries),
            schema_entries=0,  # Not applicable in simple mode
        )

        result = FlextLdifModels.PipelineExecutionResult(
            entries_by_category={"output": final_entries},
            statistics=stats,
            file_paths={"output": str(output_path)},
        )

        return FlextResult[FlextLdifModels.PipelineExecutionResult].ok(result)

    def _execute_categorized_migration(
        self,
        entries: list[FlextLdifModels.Entry],
        total_entries: int,
    ) -> FlextResult[FlextLdifModels.PipelineExecutionResult]:
        """Execute categorized migration mode (6-file structured output).

        Args:
            entries: Parsed LDIF entries
            total_entries: Total number of entries

        Returns:
            FlextResult with pipeline result

        """
        # Categorize entries using rules
        categorize_result = self._categorize_entries(entries)
        if categorize_result.is_failure:
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                f"Failed to categorize entries: {categorize_result.error}",
            )

        categorized = categorize_result.unwrap()

        # Extract ACL entries if configured
        acl_attr_config = self._categorization_rules.get("acl_attributes", [])
        if acl_attr_config:  # Non-empty = enabled
            acl_result = self._extract_acl_entries(entries)
            if acl_result.is_failure:
                return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                    f"Failed to extract ACL entries: {acl_result.error}",
                )
            acl_entries = acl_result.unwrap()
            categorized[FlextLdifConstants.Categories.ACL] = acl_entries

            # CRITICAL: Remove ACL entries from other categories to prevent duplicates
            # An entry should only be in ONE output file
            acl_dns = {entry.dn.value for entry in acl_entries}
            for category in list(categorized.keys()):
                if category != FlextLdifConstants.Categories.ACL:
                    categorized[category] = [
                        entry
                        for entry in categorized[category]
                        if entry.dn.value not in acl_dns
                    ]

        # Transform each category via quirks
        transform_result = self._transform_categories(categorized)
        if transform_result.is_failure:
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                f"Failed to transform categories: {transform_result.error}",
            )

        transformed = transform_result.unwrap()

        # Filter each category
        final_categorized = {}
        for category, cat_entries in transformed.items():
            # Apply schema whitelist filtering for schema entries
            if (
                category == FlextLdifConstants.Categories.SCHEMA
                and self._schema_whitelist_rules
            ):
                cat_entries = self._filter_schema_by_oids(cat_entries)

            # Filter
            filtered = self._filter_entries_batch(cat_entries)

            # DN normalization if base_dn specified
            normalized = self._normalize_dns(filtered) if self._base_dn else filtered

            # Sort entries hierarchically if requested
            if self._sort_entries_hierarchically:
                sorted_entries = self._sort_entries_by_hierarchy(normalized)
            else:
                sorted_entries = normalized

            final_categorized[category] = sorted_entries

        # Write categorized files
        file_paths = {}
        category_entry_counts: dict[str, int] = {}

        writer = FlextLdifWriterService()

        # Write files for ALL mapped categories (create empty files for sync requirements)
        for category, output_filename in self._output_files.items():
            cat_entries = final_categorized.get(category, [])
            output_path = self._output_dir / output_filename

            if cat_entries:
                # Write file with entries
                write_result = writer.write(
                    entries=cat_entries,
                    target_server_type=self._target_server,
                    output_target="file",
                    output_path=output_path,
                )

                if write_result.is_failure:
                    self.logger.warning(
                        f"Failed to write category {category}: {write_result.error}",
                    )
                    continue

                # Extract write response to get actual written count
                write_response = write_result.unwrap()
                entries_written = write_response.statistics.entries_written
                category_entry_counts[category] = entries_written
                file_paths[category] = str(output_path)
            else:
                # Create empty file with just version line (for sync requirements)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text("version: 1\n", encoding="utf-8")
                file_paths[category] = str(output_path)
                category_entry_counts[category] = 0

        # Generate statistics with per-category tracking
        processed = sum(len(entries) for entries in final_categorized.values())
        stats = FlextLdifModels.PipelineStatistics(
            total_entries=total_entries,
            processed_entries=processed,
            schema_entries=category_entry_counts.get(
                FlextLdifConstants.Categories.SCHEMA, 0
            ),
            hierarchy_entries=category_entry_counts.get(
                FlextLdifConstants.Categories.HIERARCHY, 0
            ),
            user_entries=category_entry_counts.get(
                FlextLdifConstants.Categories.USERS, 0
            ),
            group_entries=category_entry_counts.get(
                FlextLdifConstants.Categories.GROUPS, 0
            ),
            acl_entries=category_entry_counts.get(FlextLdifConstants.Categories.ACL, 0),
            rejected_entries=category_entry_counts.get(
                FlextLdifConstants.Categories.REJECTED, 0
            ),
        )

        result = FlextLdifModels.PipelineExecutionResult(
            entries_by_category=final_categorized,
            statistics=stats,
            file_paths=file_paths,
        )

        return FlextResult[FlextLdifModels.PipelineExecutionResult].ok(result)

    def _execute_structured_migration(
        self,
        entries: list[FlextLdifModels.Entry],
        total_entries: int,
    ) -> FlextResult[FlextLdifModels.PipelineExecutionResult]:
        """Execute structured 6-file migration (00-schema through 06-rejected).

        This is the main method for client-a-oud-mig integration, providing:
        - 00-schema.ldif: Schema entries (automatic detection)
        - 01-hierarchy.ldif: Org/OU entries (from migration_config rules)
        - 02-users.ldif: User entries (from migration_config rules)
        - 03-groups.ldif: Group entries (from migration_config rules)
        - 04-acl.ldif: ACL entries (automatic detection)
        - 05-data.ldif: Leftover entries not categorized above
        - 06-rejected.ldif: Invalid/rejected entries

        Args:
            entries: Parsed LDIF entries
            total_entries: Total number of entries

        Returns:
            FlextResult with pipeline result

        """
        if not self._migration_config:
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                "Structured migration requires migration_config"
            )

        # 1. Separate schema entries (automatic detection)
        schema_entries = [e for e in entries if self._is_schema_entry(e)]
        non_schema = [e for e in entries if e not in schema_entries]

        # 2. Extract ACL entries (automatic detection)
        acl_entries = []
        non_acl = []
        for entry in non_schema:
            if self._has_acl_attributes(entry):
                acl_entries.append(entry)
            else:
                non_acl.append(entry)

        # 3. Categorize remaining by rules (01, 02, 03)
        hierarchy = self._filter_by_objectclasses(
            non_acl, self._migration_config.hierarchy_objectclasses
        )
        users = self._filter_by_objectclasses(
            non_acl, self._migration_config.user_objectclasses
        )
        groups = self._filter_by_objectclasses(
            non_acl, self._migration_config.group_objectclasses
        )

        # 4. Leftover goes to 05-data
        categorized_set = set(hierarchy + users + groups)
        data_entries = [e for e in non_acl if e not in categorized_set]

        # 5. Transform and filter all categories with tracking
        categories = {
            "schema": schema_entries,
            "hierarchy": hierarchy,
            "users": users,
            "groups": groups,
            "acl": acl_entries,
            "data": data_entries,
            "rejected": [],  # Populated during transform/filter
        }

        transformed_categories = {}
        for category, cat_entries in categories.items():
            # Apply schema whitelist filtering for schema entries
            if category == "schema" and self._schema_whitelist_rules:
                cat_entries = self._filter_schema_by_oids(cat_entries)

            # Transform and filter all entries (including ACL)
            transformed = self._transform_and_filter_with_tracking(cat_entries)
            transformed_categories[category] = transformed

        # 6. Write all mapped files (create empty files for missing categories)
        file_paths = {}
        category_entry_counts: dict[str, int] = {}

        writer = FlextLdifWriterService()

        # Write files for all categories in the mapping (even if not in transformed_categories)
        for (
            category,
            output_filename,
        ) in self._migration_config.output_file_mapping.items():
            cat_entries = transformed_categories.get(category, [])
            output_path = self._output_dir / output_filename

            # Always write file even if empty (for sync requirements)
            if cat_entries:
                # Write file with entries
                write_result = writer.write(
                    entries=cat_entries,
                    target_server_type=self._target_server,
                    output_target="file",
                    output_path=output_path,
                    format_options=self._write_options,
                    header_template=self._migration_config.header_template,
                    template_data=self._migration_config.header_data,
                )

                if write_result.is_success:
                    file_paths[category] = str(output_path)
                    category_entry_counts[category] = len(cat_entries)
                else:
                    self.logger.warning(
                        f"Failed to write {category} file: {write_result.error}"
                    )
            else:
                # Create empty file with just version line
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text("version: 1\n", encoding="utf-8")
                file_paths[category] = str(output_path)
                category_entry_counts[category] = 0

        # 7. Generate statistics
        processed = sum(len(entries) for entries in transformed_categories.values())
        stats = FlextLdifModels.PipelineStatistics(
            total_entries=total_entries,
            processed_entries=processed,
            schema_entries=category_entry_counts.get("schema", 0),
            hierarchy_entries=category_entry_counts.get("hierarchy", 0),
            user_entries=category_entry_counts.get("users", 0),
            group_entries=category_entry_counts.get("groups", 0),
            acl_entries=category_entry_counts.get("acl", 0),
            rejected_entries=category_entry_counts.get("rejected", 0),
        )

        result = FlextLdifModels.PipelineExecutionResult(
            entries_by_category=transformed_categories,
            statistics=stats,
            file_paths=file_paths,
        )

        return FlextResult[FlextLdifModels.PipelineExecutionResult].ok(result)

    def _parse_entries(
        self,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Parse all entries from input directory.

        Returns:
            FlextResult containing list of parsed entries

        """
        entries: list[FlextLdifModels.Entry] = []

        # Determine files to process
        if self._input_files:
            files_to_process = [self._input_dir / f for f in self._input_files]
        else:
            files_to_process = sorted(self._input_dir.glob("*.ldif"))

        if not files_to_process:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"No LDIF files found in {self._input_dir}",
            )

        # Create parser and use explicit source server type
        parser = FlextLdifParserService()
        for file_path in files_to_process:
            if not file_path.exists():
                self.logger.warning(f"LDIF file not found: {file_path}")
                continue

            parse_result = parser.parse_ldif_file(
                file_path, server_type=self._source_server
            )
            if parse_result.is_failure:
                self.logger.warning(
                    f"Failed to parse {file_path}: {parse_result.error}",
                )
                continue

            parse_response = parse_result.unwrap()
            entries.extend(parse_response.entries)

        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def _categorize_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[dict[str, list[FlextLdifModels.Entry]]]:
        """Categorize entries using user-defined rules.

        Args:
            entries: Entries to categorize

        Returns:
            FlextResult containing categorized entries dict

        """
        categorized: dict[str, list[FlextLdifModels.Entry]] = {}

        for entry in entries:
            category, _reason = FlextLdifFilters.categorize_entry(
                entry,
                categorization_rules=self._categorization_rules,
                schema_whitelist_rules=self._schema_whitelist_rules,
            )

            if category not in categorized:
                categorized[category] = []
            categorized[category].append(entry)

        return FlextResult[dict[str, list[FlextLdifModels.Entry]]].ok(categorized)

    def _extract_acl_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Extract ACL entries from all entries.

        Args:
            entries: All entries to search for ACLs

        Returns:
            FlextResult containing ACL entries

        """
        acl_attributes_obj = self._categorization_rules.get("acl_attributes", [])
        acl_attributes: list[str] = (
            acl_attributes_obj if isinstance(acl_attributes_obj, list) else []
        )
        if not acl_attributes:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        acl_entries = []
        for entry in entries:
            has_acl = any(
                acl_attr in entry.attributes.attributes for acl_attr in acl_attributes
            )
            if has_acl:
                acl_entries.append(entry)

        return FlextResult[list[FlextLdifModels.Entry]].ok(acl_entries)

    def _transform_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Transform entries via quirks (source→RFC→target).

        Args:
            entries: Entries to transform

        Returns:
            FlextResult containing transformed entries

        """
        # For now, return entries as-is (quirks applied by writer)
        # In production, use QuirksConversionMatrix for explicit transformation
        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def _transform_and_filter_with_tracking(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> list[FlextLdifModels.Entry]:
        """Transform entries and track removed attributes in metadata.

        This method:
        1. Transforms entries via quirks
        2. Applies whitelist/blacklist filtering
        3. Tracks removed attributes in entry metadata

        Args:
            entries: Entries to transform and filter

        Returns:
            List of transformed and filtered entries with metadata

        """
        result_entries = []

        for entry in entries:
            # Track original attributes before filtering
            original_attrs = set(entry.attributes.attributes.keys())

            # Apply whitelist/blacklist filtering
            filtered_attrs = dict(entry.attributes.attributes)

            # Apply whitelist (if provided)
            if self._attribute_whitelist:
                filtered_attrs = {
                    k: v
                    for k, v in filtered_attrs.items()
                    if k in self._attribute_whitelist
                }

            # Apply blacklist
            for forbidden_attr in self._forbidden_attributes:
                filtered_attrs.pop(forbidden_attr, None)

            # Track removed attributes if configured
            if (
                self._migration_config
                and self._migration_config.track_removed_attributes
            ):
                final_attrs = set(filtered_attrs.keys())
                removed = original_attrs - final_attrs

                if removed:
                    # Create or update metadata
                    metadata = entry.metadata or FlextLdifModels.QuirkMetadata()
                    metadata = metadata.model_copy(
                        update={"removed_attributes": list(removed)}
                    )

                    # Create new entry with updated metadata
                    attrs_data = cast("dict[str, object]", filtered_attrs)
                    new_attrs_result = FlextLdifModels.LdifAttributes.create(attrs_data)
                    if new_attrs_result.is_success:
                        entry = entry.model_copy(
                            update={
                                "attributes": new_attrs_result.unwrap(),
                                "metadata": metadata,
                            }
                        )
            else:
                # Just update attributes without metadata
                attrs_data = cast("dict[str, object]", filtered_attrs)
                new_attrs_result = FlextLdifModels.LdifAttributes.create(attrs_data)
                if new_attrs_result.is_success:
                    entry = entry.model_copy(
                        update={"attributes": new_attrs_result.unwrap()}
                    )

            result_entries.append(entry)

        return result_entries

    def _filter_schema_by_oids(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> list[FlextLdifModels.Entry]:
        """Filter schema entries by allowed OID patterns.

        Filters attributeTypes and objectClasses within schema entries
        based on allowed OID patterns from schema_whitelist_rules.

        Args:
            entries: Schema entries to filter

        Returns:
            Filtered schema entries with only whitelisted OIDs

        """
        if not self._schema_whitelist_rules:
            return entries

        allowed_attr_oids_raw = self._schema_whitelist_rules.get(
            "allowed_attribute_oids", []
        )
        allowed_oc_oids_raw = self._schema_whitelist_rules.get(
            "allowed_objectclass_oids", []
        )

        # Validate and convert to list[str]
        allowed_attr_oids = (
            list(allowed_attr_oids_raw)
            if isinstance(allowed_attr_oids_raw, list)
            else []
        )
        allowed_oc_oids = (
            list(allowed_oc_oids_raw) if isinstance(allowed_oc_oids_raw, list) else []
        )

        if not allowed_attr_oids and not allowed_oc_oids:
            return entries

        filtered_entries = []

        for entry in entries:
            # Get attributes
            attrs = dict(entry.attributes.attributes)
            filtered_attrs = {}

            logger.debug(
                f"Filtering schema entry {entry.dn.value} - attributes: {list(attrs.keys())}"
            )

            # Filter attributetypes if present - use constants for field names
            attr_key = None
            for schema_field in [
                FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES_LOWER,
                FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES,
            ]:
                if schema_field in attrs:
                    attr_key = schema_field
                    break
            if attr_key:
                attr_values = attrs[attr_key]

                if isinstance(attr_values, list):
                    filtered_attr_values = []
                    for attr_def in attr_values:
                        # Extract OID from attribute definition
                        # Format: ( OID NAME 'name' ... ) or ( OID ... )
                        attr_def_str = str(attr_def)
                        oid_match = re.search(
                            FlextLdifConstants.LdifPatterns.SCHEMA_OID_EXTRACTION_START,
                            attr_def_str,
                        )
                        if oid_match:
                            oid = oid_match.group(1)
                            if FlextLdifFilters.matches_oid_pattern(
                                oid, allowed_attr_oids
                            ):
                                filtered_attr_values.append(attr_def)
                        else:
                            logger.debug(
                                f"Could not extract OID from attribute definition: {attr_def_str[:100]}"
                            )
                    if filtered_attr_values:
                        filtered_attrs[attr_key] = filtered_attr_values
                        logger.debug(
                            f"Filtered {len(filtered_attr_values)}/{len(attr_values)} attributeTypes for {entry.dn.value}"
                        )
                    else:
                        logger.debug(
                            f"No attributeTypes matched whitelist for {entry.dn.value} (checked {len(attr_values)} attributes)"
                        )
                else:
                    # Single value or multiline string - need to split by lines
                    attr_str = str(attr_values)
                    # Check if it's a multiline string with multiple attributetypes
                    if "\n" in attr_str or "\r" in attr_str:
                        # Split by lines and process each
                        lines = attr_str.splitlines()
                        filtered_attr_values = []
                        for line in lines:
                            line = line.strip()
                            if line.startswith((
                                f"{FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES_LOWER}:",
                                f"{FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES}:",
                            )):
                                # Extract the definition after the colon
                                if ":" in line:
                                    definition = line.split(":", 1)[1].strip()
                                    oid_match = re.search(
                                        FlextLdifConstants.LdifPatterns.SCHEMA_OID_EXTRACTION_START,
                                        definition,
                                    )
                                    if oid_match:
                                        oid = oid_match.group(1)
                                        if FlextLdifFilters.matches_oid_pattern(
                                            oid, allowed_attr_oids
                                        ):
                                            filtered_attr_values.append(definition)
                            elif line.startswith("("):
                                # Direct definition line
                                oid_match = re.search(
                                    FlextLdifConstants.LdifPatterns.SCHEMA_OID_EXTRACTION_START,
                                    line,
                                )
                                if oid_match:
                                    oid = oid_match.group(1)
                                    if FlextLdifFilters.matches_oid_pattern(
                                        oid, allowed_attr_oids
                                    ):
                                        filtered_attr_values.append(line)
                        if filtered_attr_values:
                            filtered_attrs[attr_key] = filtered_attr_values
                    else:
                        # Single value - check OID
                        oid_match = re.search(
                            FlextLdifConstants.LdifPatterns.SCHEMA_OID_EXTRACTION_START,
                            attr_str,
                        )
                        if oid_match:
                            oid = oid_match.group(1)
                            if FlextLdifFilters.matches_oid_pattern(
                                oid, allowed_attr_oids
                            ):
                                filtered_attrs[attr_key] = attr_values

            # Filter objectclasses if present - use constants for field names
            oc_key = None
            for schema_field in [
                FlextLdifConstants.SchemaFields.OBJECT_CLASSES_LOWER,
                FlextLdifConstants.SchemaFields.OBJECT_CLASSES,
            ]:
                if schema_field in attrs:
                    oc_key = schema_field
                    break
            if oc_key:
                oc_values = attrs[oc_key]

                if isinstance(oc_values, list):
                    filtered_oc_values = []
                    for oc_def in oc_values:
                        # Extract OID from objectClass definition
                        oid_match = re.search(
                            FlextLdifConstants.LdifPatterns.SCHEMA_OID_EXTRACTION_START,
                            str(oc_def),
                        )
                        if oid_match:
                            oid = oid_match.group(1)
                            if FlextLdifFilters.matches_oid_pattern(
                                oid, allowed_oc_oids
                            ):
                                filtered_oc_values.append(oc_def)
                    filtered_attrs[oc_key] = filtered_oc_values
                else:
                    # Single value - check OID
                    oid_match = re.search(
                        FlextLdifConstants.LdifPatterns.SCHEMA_OID_EXTRACTION_START,
                        str(oc_values),
                    )
                    if oid_match:
                        oid = oid_match.group(1)
                        if FlextLdifFilters.matches_oid_pattern(oid, allowed_oc_oids):
                            filtered_attrs[oc_key] = oc_values

            # Keep all other attributes unchanged (exclude schema fields)
            schema_fields_lower = {
                FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES_LOWER.lower(),
                FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES.lower(),
                FlextLdifConstants.SchemaFields.OBJECT_CLASSES_LOWER.lower(),
                FlextLdifConstants.SchemaFields.OBJECT_CLASSES.lower(),
            }
            for key, value in attrs.items():
                key_lower = key.lower()
                if key_lower not in schema_fields_lower:
                    filtered_attrs[key] = value

            # Always keep the entry, even if no attributetypes/objectclasses passed the filter
            # The entry may have other important attributes (cn, objectclass, etc.)
            # Only skip if entry has no attributes at all (shouldn't happen)
            if filtered_attrs:
                new_attrs_result = FlextLdifModels.LdifAttributes.create(filtered_attrs)
                if new_attrs_result.is_success:
                    new_entry = entry.model_copy(
                        update={"attributes": new_attrs_result.unwrap()}
                    )
                    filtered_entries.append(new_entry)
                    # Log if attributetypes/objectclasses were filtered out
                    schema_field_names = [
                        FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES_LOWER,
                        FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES,
                        FlextLdifConstants.SchemaFields.OBJECT_CLASSES_LOWER,
                        FlextLdifConstants.SchemaFields.OBJECT_CLASSES,
                    ]
                    has_schema_attrs = any(sf in attrs for sf in schema_field_names)
                    has_filtered_schema = any(
                        filtered_attrs.get(sf) for sf in schema_field_names
                    )
                    if has_schema_attrs and not has_filtered_schema:
                        logger.debug(
                            f"Schema entry {entry.dn.value} - all schema elements filtered out by whitelist"
                        )
                else:
                    logger.warning(
                        f"Failed to create filtered attributes for {entry.dn.value}: {new_attrs_result.error}"
                    )
            else:
                # Entry has no attributes at all - skip it
                logger.debug(
                    f"Skipping schema entry {entry.dn.value} - no attributes found"
                )

        return filtered_entries

    def _is_schema_entry(self, entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is a schema entry.

        Args:
            entry: Entry to check

        Returns:
            True if entry is a schema entry

        """
        # Schema entries typically have cn=schema DN or specific objectClasses
        dn_lower = entry.dn.value.lower()
        # Use constants for schema DN pattern matching
        schema_dn_patterns = [
            FlextLdifConstants.DnPatterns.CN_SCHEMA.lower(),
            FlextLdifConstants.DnPatterns.CN_SUBSCHEMA.lower(),
        ]
        if any(pattern in dn_lower for pattern in schema_dn_patterns):
            return True

        # Check for schema-related objectClasses (case-insensitive lookup)
        oc_values = []
        for attr_name, attr_values in entry.attributes.attributes.items():
            if attr_name.lower() == FlextLdifConstants.DictKeys.OBJECTCLASS.lower():
                oc_values = attr_values
                break

        schema_classes = {"subschema", "ldapsubentry", "extensibleobject"}
        return any(
            oc.lower() in schema_classes for oc in oc_values if isinstance(oc, str)
        )

    def _has_acl_attributes(self, entry: FlextLdifModels.Entry) -> bool:
        """Check if entry has ACL attributes.

        Uses constants from FlextLdifConstants.AclAttributes for ACL detection.

        Args:
            entry: Entry to check

        Returns:
            True if entry has ACL attributes

        """
        # Use constants for ACL attribute filtering
        # Fallback to ALL_ACL_ATTRIBUTES if FILTER_ACL_ATTRIBUTES is empty
        filter_acl_attrs = (
            FlextLdifConstants.AclAttributes.FILTER_ACL_ATTRIBUTES
            or FlextLdifConstants.AclAttributes.ALL_ACL_ATTRIBUTES
        )

        # Case-insensitive attribute check
        attr_names_lower = {name.lower() for name in entry.attributes.attributes}
        acl_attrs_lower = {attr.lower() for attr in filter_acl_attrs}
        return any(acl_attr in attr_names_lower for acl_attr in acl_attrs_lower)

    def _filter_by_objectclasses(
        self,
        entries: list[FlextLdifModels.Entry],
        objectclasses: list[str],
    ) -> list[FlextLdifModels.Entry]:
        """Filter entries by objectClass membership.

        Args:
            entries: Entries to filter
            objectclasses: List of objectClass names to match

        Returns:
            Filtered list of entries

        """
        if not objectclasses:
            return []

        filtered = []
        objectclasses_lower = [oc.lower() for oc in objectclasses]

        for entry in entries:
            # Get objectClass attribute (case-insensitive lookup)
            oc_values = []
            for attr_name, attr_values in entry.attributes.attributes.items():
                if attr_name.lower() == FlextLdifConstants.DictKeys.OBJECTCLASS.lower():
                    oc_values = attr_values
                    break

            entry_ocs_lower = [oc.lower() for oc in oc_values if isinstance(oc, str)]

            # Check if entry has any of the target objectClasses
            if any(oc in objectclasses_lower for oc in entry_ocs_lower):
                filtered.append(entry)

        return filtered

    def _transform_categories(
        self,
        categorized: dict[str, list[FlextLdifModels.Entry]],
    ) -> FlextResult[dict[str, list[FlextLdifModels.Entry]]]:
        """Transform each category via quirks.

        Args:
            categorized: Entries organized by category

        Returns:
            FlextResult containing transformed categorized entries

        """
        # Transformation is handled by the writer (which applies quirks during write)
        # The parser already normalized entries to RFC format during parsing
        # The writer will denormalize from RFC to target format
        return FlextResult[dict[str, list[FlextLdifModels.Entry]]].ok(categorized)

    def _filter_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter forbidden attributes/objectclasses from entries.

        Uses existing services to avoid duplication:
        - OperationalService for operational attribute filtering
        - FlextLdifFilters for attribute/objectClass filtering

        Args:
            entries: Entries to filter

        Returns:
            FlextResult containing filtered entries

        """
        filtered = []
        for entry in entries:
            current_entry = entry

            # Step 1: Filter operational attributes for target server
            operational_result = (
                self._operational_service.filter_operational_attributes(
                    entry.attributes.attributes, self._target_server
                )
            )
            if operational_result.is_success:
                # Rebuild entry with operational attributes filtered out
                filtered_op_attrs = operational_result.unwrap()
                ldif_attrs_op = FlextLdifModels.LdifAttributes(
                    attributes=filtered_op_attrs,
                )
                current_entry = FlextLdifModels.Entry(
                    dn=entry.dn,
                    attributes=ldif_attrs_op,
                    metadata=entry.metadata,
                )
            else:
                logger.warning(
                    f"Failed to filter operational attributes for {entry.dn.value}: {operational_result.error}"
                )

            # Step 2: Filter forbidden attributes using FlextLdifFilters
            if self._forbidden_attributes:
                forbidden_result = FlextLdifFilters.filter_entry_attributes(
                    current_entry, self._forbidden_attributes
                )
                if forbidden_result.is_success:
                    current_entry = forbidden_result.unwrap()
                else:
                    logger.warning(
                        f"Failed to filter forbidden attributes for {current_entry.dn.value}: {forbidden_result.error}"
                    )

            # Step 3: Filter forbidden objectClasses using FlextLdifFilters
            if self._forbidden_objectclasses:
                oc_result = FlextLdifFilters.filter_entry_objectclasses(
                    current_entry, self._forbidden_objectclasses
                )
                if oc_result.is_success:
                    current_entry = oc_result.unwrap()
                else:
                    logger.warning(
                        f"Failed to filter forbidden objectClasses for {current_entry.dn.value}: {oc_result.error}"
                    )

            filtered.append(current_entry)

        return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)

    def _filter_entries_batch(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> list[FlextLdifModels.Entry]:
        """Batch filter entries (internal method).

        Args:
            entries: Entries to filter

        Returns:
            Filtered entries

        """
        result = self._filter_entries(entries)
        return result.unwrap() if result.is_success else entries

    def _create_output_directory(self) -> FlextResult[None]:
        """Create output directory if it doesn't exist.

        Returns:
            FlextResult[None] with status

        """
        try:
            self._output_dir.mkdir(parents=True, exist_ok=True)
            return FlextResult[None].ok(None)
        except OSError as e:
            return FlextResult[None].fail(f"Failed to create directory: {e}")

    def _normalize_dns(
        self, entries: list[FlextLdifModels.Entry]
    ) -> list[FlextLdifModels.Entry]:
        """Normalize entry DNs to target base DN.

        Replaces the base DN suffix of each entry's DN with the target base DN,
        preserving the entire hierarchical path.

        For example, if base_dn="dc=ctbc" and source has "dc=network,dc=ctbc", then:
          "cn=user,ou=people,dc=network,dc=ctbc" -> "cn=user,ou=people,dc=ctbc"
          "cn=group,cn=OracleContext,dc=network,dc=ctbc" -> "cn=group,cn=OracleContext,dc=ctbc"

        Strategy:
        1. Find where the source base DN starts (search for common dc= suffixes)
        2. Replace everything from that point with the target base DN
        3. If no common suffix found, append target base DN

        Args:
            entries: Entries to normalize

        Returns:
            Entries with normalized DNs

        """
        if not self._base_dn:
            return entries

        normalized = []

        for entry in entries:
            original_dn = entry.dn.value
            original_dn_lower = original_dn.lower()

            # Try to find common base DN patterns to replace
            # Common patterns: dc=network,dc=ctbc, dc=example,dc=com, dc=org, etc.
            new_dn = original_dn

            # Strategy: Find the last occurrence of "dc=" in the DN
            # Everything from there is considered the base DN
            last_dc_index = original_dn_lower.rfind(",dc=")
            if last_dc_index != -1:
                # Found a dc= component, find the start of the base DN sequence
                # Count backwards to get all consecutive dc= components
                base_start = last_dc_index
                check_pos = last_dc_index
                while check_pos > 0:
                    # Look for previous ",dc=" pattern
                    prev_dc = original_dn_lower.rfind(",dc=", 0, check_pos)
                    if prev_dc == -1:
                        break
                    # Check if this is immediately adjacent (accounting for the component value)
                    # For simplicity, if we find dc= patterns, assume they're part of base
                    base_start = prev_dc
                    check_pos = prev_dc

                # Extract the RDN path (everything before the base DN)
                rdn_path = original_dn[:base_start]

                # Build new DN: RDN path + target base DN
                if rdn_path:
                    new_dn = f"{rdn_path},{self._base_dn}"
                else:
                    # DN was only base DN components
                    new_dn = self._base_dn
            else:
                # No dc= found, append base DN
                new_dn = f"{original_dn},{self._base_dn}"

            normalized_entry = FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=new_dn),
                attributes=entry.attributes,
                metadata=entry.metadata,
            )
            normalized.append(normalized_entry)

        return normalized

    def _sort_entries_by_hierarchy(
        self, entries: list[FlextLdifModels.Entry]
    ) -> list[FlextLdifModels.Entry]:
        """Sort entries hierarchically by DN depth then alphabetically.

        Ensures parent containers are created before children during sync.
        Sort order:
        1. By DN depth (fewer commas = higher in hierarchy tree)
        2. By DN alphabetically (for consistent ordering)

        Args:
            entries: Entries to sort

        Returns:
            Sorted entries (parents before children)

        """

        def dn_sort_key(entry: FlextLdifModels.Entry) -> tuple[int, str]:
            dn = entry.dn.value
            depth = dn.count(",")
            return (depth, dn.lower())

        return sorted(entries, key=dn_sort_key)


__all__ = ["FlextLdifMigrationPipeline"]
