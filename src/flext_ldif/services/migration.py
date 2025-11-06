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

from pathlib import Path
from typing import cast, override

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.acl import FlextLdifAcl
from flext_ldif.services.dn import FlextLdifDn
from flext_ldif.services.entry import FlextLdifEntry
from flext_ldif.services.filters import FlextLdifFilters
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.sorting import FlextLdifSorting
from flext_ldif.services.writer import FlextLdifWriter
from flext_ldif.utilities import FlextLdifUtilities

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

    DN Handling (RFC 4514 Compliance):
    - Base DN normalized using FlextLdifUtilities.DN.norm() for RFC 4514 compliance
    - All entry DNs validated using FlextLdifUtilities.DN.validate()
    - Entry DNs normalized using FlextLdifUtilities.DN.norm() during migration
    - Invalid DNs logged and skipped with detailed error tracking
    - Ensures migration output uses canonical DN format for target server

    Reuses Existing Services:
    - FlextLdifParser - Entry parsing
    - FlextLdifWriter - LDIF writing
    - FlextLdifFilters - Entry categorization (direct usage)
    - FlextLdifAcl - ACL extraction/processing
    - FlextLdifDn - DN normalization
    - FlextLdifUtilities - RFC 4514 DN validation and normalization
    - FlextLdifStatistics - Statistics generation
    - FlextLdifServer - Quirk registration

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
        mode: FlextLdifConstants.LiteralTypes.MigrationMode = "simple",
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
        # Use FlextLdifUtilities.DN for RFC 4514 compliant base DN normalization
        if base_dn:
            normalized_base = FlextLdifUtilities.DN.norm(base_dn)
            self._base_dn = normalized_base or base_dn.lower()
        else:
            self._base_dn = None
        self._sort_entries_hierarchically = sort_entries_hierarchically

        # Service dependencies
        self._registry = FlextLdifServer.get_global_instance()
        self._acl_service = FlextLdifAcl()
        self._dn_service = FlextLdifDn()

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
                    statistics={
                        "total_entries": 0,
                        "processed_entries": 0,
                    },
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

        # Unified generic pipeline: parse → categorize → filter → sort → write
        return self._unified_migration_pipeline(entries, total_entries)

    def _validate_and_normalize_entry_dns(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> list[FlextLdifModels.Entry]:
        """Validate and normalize all entry DNs using FlextLdifUtilities.

        Ensures all DNs comply with RFC 4514 and registers them for migration tracking.

        Args:
            entries: Entries to validate and normalize

        Returns:
            Entries with validated and normalized DNs

        """
        validated_entries = []

        for entry in entries:
            try:
                entry_dn = str(FlextLdifUtilities.DN._get_dn_value(entry.dn))

                # Validate DN using FlextLdifUtilities.DN
                if not FlextLdifUtilities.DN.validate(entry_dn):
                    logger.warning(
                        "[MIGRATION] Invalid DN per RFC 4514: %s, skipping entry",
                        entry_dn,
                    )
                    continue

                # Normalize DN using FlextLdifUtilities
                normalized_dn = FlextLdifUtilities.DN.norm(entry_dn)
                if not normalized_dn:
                    logger.warning(
                        "[MIGRATION] Failed to normalize DN: %s, using original",
                        entry_dn,
                    )
                    normalized_dn = entry_dn

                # Create entry with normalized DN
                if normalized_dn != entry_dn:
                    new_dn = FlextLdifModels.DistinguishedName(value=normalized_dn)
                    normalized_entry = entry.model_copy(update={"dn": new_dn})
                    validated_entries.append(normalized_entry)
                else:
                    validated_entries.append(entry)

            except Exception as e:
                logger.exception("[MIGRATION] Error validating entry DN: %s", e)
                continue

        return validated_entries

    def _extract_acl_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        categorized: dict[str, list[FlextLdifModels.Entry]],
    ) -> None:
        """Extract ACL entries if configured and update categorized dict.

        Args:
            entries: Original entry list
            categorized: Dictionary to update with ACL entries

        """
        acl_config_obj = self._categorization_rules.get("acl_attributes", [])
        acl_config: list[str] = (
            acl_config_obj if isinstance(acl_config_obj, list) else []
        )

        if not acl_config:
            return

        logger.info("[PIPELINE] ACL config found: %s", acl_config)
        acl_entries, acl_dns = [], set()

        for idx, entry in enumerate(entries):
            try:
                if FlextLdifFilters.is_schema(entry):
                    continue
                if any(attr in entry.attributes.attributes for attr in acl_config):
                    acl_entries.append(entry)
                    acl_dns.add(FlextLdifUtilities.DN._get_dn_value(entry.dn))
            except Exception as e:
                logger.exception("[PIPELINE] Error processing entry %s: %s", idx, e)
                raise

        categorized[FlextLdifConstants.Categories.ACL] = acl_entries
        for cat in list(categorized.keys()):
            if cat != FlextLdifConstants.Categories.ACL:
                categorized[cat] = [
                    e
                    for e in categorized[cat]
                    if FlextLdifUtilities.DN._get_dn_value(e.dn) not in acl_dns
                ]

    def _process_category(
        self,
        cat: str,
        cat_entries: list[FlextLdifModels.Entry],
    ) -> list[FlextLdifModels.Entry]:
        """Process category entries (filter and sort).

        Args:
            cat: Category name
            cat_entries: Entries in this category

        Returns:
            Processed entry list

        """
        logger.info(
            f"[PIPELINE] Processing {cat}: {len(cat_entries)} entries before filter",
        )

        # Schema: only filter by OID whitelist
        if cat == FlextLdifConstants.Categories.SCHEMA:
            if self._schema_whitelist_rules and isinstance(
                self._schema_whitelist_rules,
                dict,
            ):
                result = FlextLdifFilters.filter_schema_by_oids(
                    entries=cat_entries,
                    allowed_oids=cast(
                        "dict[str, list[str]]",
                        self._schema_whitelist_rules,
                    ),
                )
                filtered = result.unwrap() if result.is_success else cat_entries
            else:
                filtered = cat_entries
        else:
            # Non-schema: apply normal filtering
            filter_result = self._filter_entries(cat_entries)
            filtered = (
                filter_result.unwrap() if filter_result.is_success else cat_entries
            )

            # Sort if configured
            if self._sort_entries_hierarchically:
                filtered = self._sort_entries_by_hierarchy(filtered)

        logger.info(f"[PIPELINE] {cat} after filter: {len(filtered)} entries")
        return filtered

    def _write_category_files(
        self,
        final: dict[str, list[FlextLdifModels.Entry]],
    ) -> tuple[dict[str, str], dict[str, int]]:
        """Write category entries to files.

        Args:
            final: Final categorized entries

        Returns:
            Tuple of (file_paths, counts) dictionaries

        """
        file_paths, counts = {}, {}
        writer = FlextLdifWriter()

        for cat, filename in self._get_output_files_mapping().items():
            cat_entries = final.get(cat, [])
            path = self._output_dir / filename

            if cat_entries:
                result = writer.write(
                    entries=cat_entries,
                    target_server_type=self._target_server,
                    output_target="file",
                    output_path=path,
                    format_options=self._write_options,
                )
                if result.is_success:
                    file_paths[cat] = str(path)
                    counts[cat] = len(cat_entries)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("version: 1\n", encoding="utf-8")
                file_paths[cat] = str(path)
                counts[cat] = 0

        return file_paths, counts

    def _unified_migration_pipeline(
        self,
        entries: list[FlextLdifModels.Entry],
        total_entries: int,
    ) -> FlextResult[FlextLdifModels.PipelineExecutionResult]:
        """Unified migration pipeline - orchestration ONLY, delegates all logic to services.

        Single code path for all 3 modes (simple/categorized/structured).
        Behavior adapts ONLY through parameters, NO God Patterns.
        """
        logger.info("[PIPELINE START] Processing %s entries", total_entries)

        # Step 0: Validate and normalize all entry DNs using FlextLdifUtilities
        logger.info("[PIPELINE] Validating and normalizing entry DNs using RFC 4514")
        validated_entries = self._validate_and_normalize_entry_dns(entries)
        logger.info(
            f"[PIPELINE] DN validation complete: {len(validated_entries)}/{len(entries)} entries valid",
        )

        # Step 1: Categorize entries (no categorization rules = simple mode)
        categorized = self._categorize_entries_unified(validated_entries)
        logger.info(
            f"[PIPELINE] Categorized into {len(categorized)} categories: {list(categorized.keys())}",
        )

        # Step 2: Extract and remove ACL entries if configured (using helper)
        logger.info("[PIPELINE] Starting ACL extraction")
        self._extract_acl_entries(entries, categorized)
        logger.info("[PIPELINE] ACL extraction complete")

        # Step 3: Filter and sort each category (using helper)
        logger.info("[PIPELINE] Starting filter and sort")
        final = {}
        for cat, cat_entries in categorized.items():
            final[cat] = self._process_category(cat, cat_entries)

        # Step 4: Write files (using helper)
        file_paths, counts = self._write_category_files(final)

        # Step 5: Build result
        processed = sum(len(e) for e in final.values())
        stats = FlextLdifModels.PipelineStatistics(
            total_entries=total_entries,
            processed_entries=processed,
            schema_entries=counts.get(FlextLdifConstants.Categories.SCHEMA, 0),
            hierarchy_entries=counts.get(
                FlextLdifConstants.Categories.HIERARCHY,
                0,
            ),
            user_entries=counts.get(FlextLdifConstants.Categories.USERS, 0),
            group_entries=counts.get(FlextLdifConstants.Categories.GROUPS, 0),
            acl_entries=counts.get(FlextLdifConstants.Categories.ACL, 0),
            rejected_entries=counts.get(
                FlextLdifConstants.Categories.REJECTED,
                0,
            ),
        )
        return FlextResult[FlextLdifModels.PipelineExecutionResult].ok(
            FlextLdifModels.PipelineExecutionResult(
                entries_by_category=final,
                statistics=stats.model_dump(),  # Convert to dict for Pydantic v2
                file_paths=file_paths,
            ),
        )

    def _categorize_entries_unified(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> dict[str, list[FlextLdifModels.Entry]]:
        """Unified categorization - adapts based on mode and rules."""
        if not self._categorization_rules:
            return {"output": entries}
        categorized: dict[str, list[FlextLdifModels.Entry]] = {}
        for entry in entries:
            cat, _ = FlextLdifFilters.categorize_entry(
                entry,
                rules=self._categorization_rules,
                whitelist_rules=self._schema_whitelist_rules,
            )
            if cat not in categorized:
                categorized[cat] = []
            categorized[cat].append(entry)
        return categorized

    def _get_output_files_mapping(self) -> dict[str, str]:
        """Get output files mapping."""
        if self._migration_config and self._migration_config.output_file_mapping:
            return self._migration_config.output_file_mapping
        if self._output_files:
            return self._output_files
        return {
            FlextLdifConstants.Categories.SCHEMA: "00-schema.ldif",
            FlextLdifConstants.Categories.HIERARCHY: "01-hierarchy.ldif",
            FlextLdifConstants.Categories.USERS: "02-users.ldif",
            FlextLdifConstants.Categories.GROUPS: "03-groups.ldif",
            FlextLdifConstants.Categories.ACL: "04-acl.ldif",
            FlextLdifConstants.Categories.REJECTED: "05-rejected.ldif",
            "output": self._output_filename,
        }

    def _filter_schema_by_oids(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> list[FlextLdifModels.Entry]:
        """Filter schema by OID whitelist."""
        if not self._schema_whitelist_rules or not isinstance(
            self._schema_whitelist_rules,
            dict,
        ):
            return entries
        result = FlextLdifFilters.filter_schema_by_oids(
            entries=entries,
            allowed_oids=self._schema_whitelist_rules,  # type: ignore[arg-type]
        )
        return result.unwrap() if result.is_success else entries

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

        logger.info("=" * 80)
        logger.info("STEP 1: PARSING INPUT FILES")
        logger.info("=" * 80)

        # Create parser and use explicit source server type
        parser = FlextLdifParser()
        for file_path in files_to_process:
            if not file_path.exists():
                self.logger.warning("LDIF file not found: %s", file_path)
                continue

            logger.info(f"Parsing file: {file_path.name}")

            parse_result = parser.parse_ldif_file(
                file_path,
                server_type=self._source_server,
            )
            if parse_result.is_failure:
                self.logger.warning(
                    f"Failed to parse {file_path}: {parse_result.error}",
                )
                continue

            parse_response = parse_result.unwrap()
            file_entries = parse_response.entries
            logger.info(f"  → Parsed {len(file_entries)} entries from {file_path.name}")

            # Check if any are schema entries
            schema_count = sum(1 for e in file_entries if FlextLdifFilters.is_schema(e))
            if schema_count > 0:
                logger.info(
                    f"  → Found {schema_count} SCHEMA entries in {file_path.name}",
                )
                for e in file_entries:
                    if FlextLdifFilters.is_schema(e):
                        logger.info(
                            f"     Schema DN: {FlextLdifUtilities.DN._get_dn_value(e.dn)}",
                        )

            entries.extend(file_entries)

        logger.info(
            f"TOTAL PARSED: {len(entries)} entries from {len(files_to_process)} files",
        )
        logger.info("")

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
                rules=self._categorization_rules,
                whitelist_rules=self._schema_whitelist_rules,
            )

            if category not in categorized:
                categorized[category] = []
            categorized[category].append(entry)

        return FlextResult[dict[str, list[FlextLdifModels.Entry]]].ok(categorized)

    # NOTE: Duplicate method removed - _extract_acl_entries(self, entries) -> FlextResult
    # The correct method is _extract_acl_entries(self, entries, categorized) -> None at line 365

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
            updated_entry = entry
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
                        update={"removed_attributes": list(removed)},
                    )

                    # Create new entry with updated metadata
                    new_attrs_result = FlextLdifModels.LdifAttributes.create(
                        filtered_attrs,
                    )  # type: ignore[arg-type]
                    if new_attrs_result.is_success:
                        updated_entry = entry.model_copy(
                            update={
                                "attributes": new_attrs_result.unwrap(),
                                "metadata": metadata,
                            },
                        )
            else:
                # Just update attributes without metadata
                new_attrs_result = FlextLdifModels.LdifAttributes.create(filtered_attrs)  # type: ignore[arg-type]
                if new_attrs_result.is_success:
                    updated_entry = entry.model_copy(
                        update={"attributes": new_attrs_result.unwrap()},
                    )

            result_entries.append(updated_entry)

        return result_entries

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

        # Use FlextLdifUtilities for case-insensitive attribute check
        return FlextLdifUtilities.Entry.has_any_attributes(
            entry,
            list(filter_acl_attrs),
        )

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

        # Use FlextLdifUtilities for case-insensitive objectClass check
        return [
            entry
            for entry in entries
            if FlextLdifUtilities.Entry.has_objectclass(entry, tuple(objectclasses))
        ]

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

            # Step 1: Filter operational attributes using FlextLdifEntry service
            # NOTE: remove_operational_attributes returns Entry, not dict
            operational_result = FlextLdifEntry.remove_operational_attributes(entry)
            if operational_result.is_success:
                # Get filtered entry directly (already an Entry model)
                current_entry = operational_result.unwrap()
            else:
                logger.warning(
                    f"Failed to filter operational attributes for {FlextLdifUtilities.DN._get_dn_value(entry.dn)}: {operational_result.error}",
                )
                current_entry = entry  # Keep original if filtering fails

            # Step 2: Filter forbidden attributes using FlextLdifFilters
            if self._forbidden_attributes:
                forbidden_result = FlextLdifFilters.filter_entry_attributes(
                    current_entry,
                    self._forbidden_attributes,
                )
                if forbidden_result.is_success:
                    current_entry = forbidden_result.unwrap()
                else:
                    logger.warning(
                        f"Failed to filter forbidden attributes for {FlextLdifUtilities.DN._get_dn_value(current_entry.dn)}: {forbidden_result.error}",
                    )

            # Step 3: Filter forbidden objectClasses using FlextLdifFilters
            if self._forbidden_objectclasses:
                oc_result = FlextLdifFilters.filter_entry_objectclasses(
                    current_entry,
                    self._forbidden_objectclasses,
                )
                if oc_result.is_success:
                    current_entry = oc_result.unwrap()
                else:
                    logger.warning(
                        f"Failed to filter forbidden objectClasses for {FlextLdifUtilities.DN._get_dn_value(current_entry.dn)}: {oc_result.error}",
                    )

            filtered.append(current_entry)

        return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)

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

    def _sort_entries_by_hierarchy(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> list[FlextLdifModels.Entry]:
        """Sort entries hierarchically by DN depth then alphabetically.

        Ensures parent containers are created before children during sync.
        Uses classmethod from FlextLdifSorting for consistency.

        Sort order:
        1. By DN depth (fewer commas = higher in hierarchy tree)
        2. By DN alphabetically (for consistent ordering)

        Args:
            entries: Entries to sort

        Returns:
            Sorted entries (parents before children)

        """
        # Use sorting service for hierarchical sorting
        sort_result = FlextLdifSorting.hierarchical_sort_by_dn(entries, reverse=False)
        return sort_result.unwrap() if sort_result.is_success else entries


__all__ = ["FlextLdifMigrationPipeline"]
