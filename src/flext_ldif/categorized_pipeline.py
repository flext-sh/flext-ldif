"""Categorized LDIF migration pipeline.

Provides rule-based entry categorization with structured LDIF file output.
Generates 6 LDIF files: 00-schema.ldif through 05-rejected.ldif.

Architecture:
- Phase 2 of MIGRATION_ENHANCEMENT_PLAN.md
- Uses FlextLdifFilters for rule-based categorization
- Integrates with quirks system for transformation
- Follows Railway-Oriented Programming pattern

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import cast, override

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif import FlextLdifModels
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.filters import FlextLdifFilters
from flext_ldif.quirks.base import BaseAclQuirk, BaseSchemaQuirk
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.rfc_ldif_parser import FlextLdifRfcLdifParser
from flext_ldif.services.acl import FlextLdifAclService
from flext_ldif.services.dn import FlextLdifDnService
from flext_ldif.services.file_writer import FlextLdifFileWriterService
from flext_ldif.services.statistics import FlextLdifStatisticsService

logger = FlextLogger(__name__)


class FlextLdifCategorizedMigrationPipeline(
    FlextService[FlextLdifModels.PipelineExecutionResult]
):
    """LDIF migration pipeline with rule-based entry categorization.

    Processes LDIF entries and categorizes them into separate output files
    based on configurable rules. Generates structured output across 6 files
    (00-schema.ldif through 05-rejected.ldif).

    Capabilities:
    - Rule-based entry categorization using regex patterns
    - Multi-file structured output
    - Server-specific quirks transformation per category
    - Schema whitelist filtering
    - Attribute filtering for security and compliance
    - Statistics and rejection tracking

    Implementation:
    - Uses FlextLdifRfcLdifParser for RFC-compliant parsing
    - Uses DnService for DN validation
    - Uses FlextLdifEntryQuirks for entry-level transformations
    - Uses categorization rules for intelligent classification
    - Generates structured LDIF files with proper ordering and naming

    Output Structure (6 LDIF files in execution order):
    - 00-schema.ldif: Schema definitions (attributeTypes, objectClasses)
    Loaded first.
    - 01-hierarchy.ldif: Organizational structure (organization, ou, domain)
    Directory foundation.
    - 02-users.ldif: User entries (person, inetOrgPerson, organizationalPerson)
    User accounts.
    - 03-groups.ldif: Group entries (groupOfNames, groupOfUniqueNames)
    Group memberships.
    - 04-acl.ldif: Access Control Lists (entries with aci attributes)
    Security policies.
    - 05-rejected.ldif: Rejected entries with detailed reasons
    Review and remediation.

    Each output file contains properly formatted LDIF entries with server-specific
    transformations applied according to the target server's quirks.
    """

    def __init__(
        self,
        input_dir: str | Path,
        output_dir: str | Path,
        categorization_rules: dict[str, list[str]],
        parser_quirk: object | None,
        writer_quirk: object | None,
        *,
        source_server: str = "oracle_oid",
        target_server: str = "oracle_oud",
        source_schema_quirk: BaseSchemaQuirk | None = None,
        target_schema_quirk: BaseSchemaQuirk | None = None,
        schema_whitelist_rules: dict[str, list[str]] | None = None,
        input_files: list[str] | None = None,
        output_files: dict[str, str] | None = None,
        forbidden_attributes: list[str] | None = None,
        forbidden_objectclasses: list[str] | None = None,
        base_dn: str | None = None,
    ) -> None:
        """Initialize categorized migration pipeline.

        Args:
            input_dir: Input directory containing LDIF files
            output_dir: Output directory for categorized LDIF files
            categorization_rules: Dictionary containing categorization rules
            parser_quirk: Quirk for parsing source server format
            writer_quirk: Quirk for writing target server format
            source_server: Source LDAP server type (optional)
            target_server: Target LDAP server type (optional)
            source_schema_quirk: Schema quirk for SOURCE server format (REQUIRED for schema transformation)
            target_schema_quirk: Schema quirk for TARGET server format (REQUIRED for schema transformation)
            schema_whitelist_rules: Optional schema whitelist rules
            input_files: Optional list of specific input files to process
            output_files: Optional mapping of category names to output filenames
            forbidden_attributes: List of attribute names (with optional subtypes) to filter out during transformation. Examples: ['authPassword', 'authpassword;orclcommonpwd', 'authpassword;oid']
            forbidden_objectclasses: List of objectClass names to filter out during transformation. Examples: ['orclContainerOC', 'orclService']
            base_dn: Optional base DN to filter entries. Only entries under this base DN will be included in output files 01-04. Schema (00) is not filtered. Example: 'dc=ctbc'

        Note:
            Uses STRATEGY PATTERN - business rules from client application.

        """
        super().__init__()
        self._input_dir = Path(input_dir)
        self._output_dir = Path(output_dir)
        self._categorization_rules = categorization_rules
        self._parser_quirk = parser_quirk
        self._writer_quirk = writer_quirk
        self._source_server = source_server
        self._target_server = target_server
        self._source_schema_quirk = source_schema_quirk
        self._target_schema_quirk = target_schema_quirk
        self._schema_whitelist_rules = schema_whitelist_rules
        self._input_files = input_files
        self._forbidden_attributes = forbidden_attributes or []
        self._forbidden_objectclasses = forbidden_objectclasses or []
        self._base_dn = base_dn.lower() if base_dn else None

        # Initialize service dependencies (inject via container if needed)
        self._acl_service = FlextLdifAclService()
        self._dn_service = FlextLdifDnService()

        # DN-valued attributes that need case normalization
        self._dn_valued_attributes = [
            "member",
            "uniqueMember",
            "owner",
            "seeAlso",
            "manager",
            "secretary",
            "target",
        ]

        # Use provided output filenames or generic defaults
        self._output_files: dict[str, str] = output_files or {
            FlextLdifConstants.Categories.SCHEMA: "schema.ldif",
            FlextLdifConstants.Categories.HIERARCHY: "hierarchy.ldif",
            FlextLdifConstants.Categories.USERS: "users.ldif",
            FlextLdifConstants.Categories.GROUPS: "groups.ldif",
            "acl": "acl.ldif",
            "rejected": "rejected.ldif",
        }

    @override
    def execute(self) -> FlextResult[FlextLdifModels.PipelineExecutionResult]:
        """Execute categorized migration pipeline.

        Returns:
        FlextResult containing categorized migration statistics

        Workflow:
        1. Parse all entries from input directory
        2. Categorize entries using rules
        3. Transform entries per category (quirks)
        4. Write to structured LDIF file output
        5. Return complete statistics

        """
        # Step 1: Create output directory (base directory only)
        create_result = self._create_output_directory()
        if create_result.is_failure:
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                f"Failed to create output directory: {create_result.error}"
            )

        # Step 2: Parse all entries from input directory
        parse_result = self._parse_entries()
        if parse_result.is_failure:
            # Return empty result with error for empty input (not a failure case)
            if "No LDIF files found" in str(parse_result.error):
                empty_result = FlextLdifModels.PipelineExecutionResult(
                    entries_by_category={},
                    statistics=FlextLdifModels.PipelineStatistics(
                        total_entries=0,
                        processed_entries=0,
                    ),
                    file_paths={},
                )
                return FlextResult[FlextLdifModels.PipelineExecutionResult].ok(
                    empty_result
                )
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                f"Failed to parse entries: {parse_result.error}"
            )

        entries = parse_result.unwrap()

        # Step 3: Categorize entries using rules
        categorize_result = self._categorize_entries(entries)
        if categorize_result.is_failure:
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                f"Failed to categorize entries: {categorize_result.error}"
            )

        categorized = categorize_result.unwrap()

        # Step 3.5: Extract ACL entries as separate dedicated phase
        # This runs AFTER categorization but uses ALL parsed entries as input
        acl_extract_result = self._extract_acl_entries_final_phase(entries)
        if acl_extract_result.is_failure:
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                f"Failed to extract ACL entries: {acl_extract_result.error}"
            )

        # Replace ACL category with extracted ACL entries
        extracted_acl_entries = acl_extract_result.unwrap()
        categorized["acl"] = extracted_acl_entries

        # Log ACL extraction results
        self.logger.info(
            f"ACL extraction phase: Populated 'acl' category with "
            f"{len(extracted_acl_entries)} entries"
        )

        # Step 4: Transform entries per category (quirks)
        transform_result = self._transform_categories(categorized)
        if transform_result.is_failure:
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                f"Failed to transform categories: {transform_result.error}"
            )

        transformed_categorized = transform_result.unwrap()

        # Step 5: Write to structured output directories
        file_writer = FlextLdifFileWriterService(
            output_dir=self._output_dir,
            output_files=cast("dict[str, object]", self._output_files),
            target_server=self._target_server,
            target_schema_quirk=self._target_schema_quirk,
            source_schema_quirk=self._source_schema_quirk,
            schema_whitelist_rules=cast(
                "dict[str, object] | None", self._schema_whitelist_rules
            ),
        )
        write_result = file_writer.write_categorized_output(transformed_categorized)
        if write_result.is_failure:
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                f"Failed to write output: {write_result.error}"
            )

        written_counts = write_result.unwrap()

        # Step 6: Generate complete statistics
        stats_service = FlextLdifStatisticsService()
        stats_result = stats_service.generate_statistics(
            transformed_categorized,
            written_counts,
            self._output_dir,
            cast("dict[str, object]", self._output_files),
        )
        if stats_result.is_failure:
            return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                f"Failed to generate statistics: {stats_result.error}"
            )
        stats_dict = stats_result.unwrap()
        # Add server and input dir info from instance
        stats_dict.update({
            "source_server": self._source_server,
            "target_server": self._target_server,
            "input_dir": str(self._input_dir),
            "output_dir": str(self._output_dir),
        })

        # Convert statistics dict to PipelineStatistics model
        total_entries_val = stats_dict.get("total_entries") or 0
        pipeline_stats = FlextLdifModels.PipelineStatistics(
            total_entries=(
                int(total_entries_val)
                if isinstance(total_entries_val, (int, str))
                else 0
            ),
            processed_entries=sum(
                len(entries) for entries in transformed_categorized.values()
            ),
            schema_entries=len(
                transformed_categorized.get(FlextLdifConstants.Categories.SCHEMA, [])
            ),
            hierarchy_entries=len(
                transformed_categorized.get(FlextLdifConstants.Categories.HIERARCHY, [])
            ),
            user_entries=len(
                transformed_categorized.get(FlextLdifConstants.Categories.USERS, [])
            ),
            group_entries=len(
                transformed_categorized.get(FlextLdifConstants.Categories.GROUPS, [])
            ),
            acl_entries=len(transformed_categorized.get("acl", [])),
            rejected_entries=len(transformed_categorized.get("rejected", [])),
            rejected_reasons={},  # Will be populated from stats_dict if needed
            processing_duration=0.0,  # Will be tracked if needed
        )

        # Convert dictionaries to proper Entry objects for the model
        entries_by_category: dict[str, list[FlextLdifModels.Entry]] = {}
        self.logger.debug(
            f"Converting entries for categories: {list(transformed_categorized.keys())}"
        )

        for category, entries in transformed_categorized.items():
            self.logger.debug(
                f"Processing category: {category}, entries: {len(entries)}"
            )
            entry_objects = []
            for i, entry_dict in enumerate(entries):
                # Debug first entry in each category
                if i == 0:
                    self.logger.info(
                        f"First entry in {category}: DN={entry_dict.get('dn')}, keys={list(entry_dict.keys())}"
                    )
                # Initialize dn and dn_value outside try block for exception handler
                dn: FlextLdifModels.DistinguishedName | None = None
                dn_value: object = entry_dict.get("dn", "")
                try:
                    # Convert dictionary to proper Entry object
                    if isinstance(dn_value, str):
                        dn = FlextLdifModels.DistinguishedName(value=dn_value)
                    elif isinstance(dn_value, FlextLdifModels.DistinguishedName):
                        # If it's already a DistinguishedName object, use it
                        dn = dn_value
                    else:
                        # Convert to string and then to DistinguishedName
                        dn = FlextLdifModels.DistinguishedName(value=str(dn_value))

                    # Handle schema entries specially (cn=schema or cn=subschemasubentry)
                    schema_attrs: dict[str, list[str]] = {}
                    dn_str = str(dn_value).lower()
                    is_schema_entry = dn_str in {"cn=schema", "cn=subschemasubentry"}

                    # Debug all entries to understand the structure
                    self.logger.debug(
                        f"Processing entry with DN: {dn_value}, keys: {list(entry_dict.keys())}"
                    )

                    if is_schema_entry:
                        self.logger.info(f"Processing schema entry with DN: {dn_value}")
                        self.logger.info(
                            f"Schema entry keys: {list(entry_dict.keys())}"
                        )
                        attrs = entry_dict.get("attributes", {})
                        attrs_keys: list[str] | str = (
                            list(attrs.keys())
                            if isinstance(attrs, dict)
                            else "attributes is not dict"
                        )
                        self.logger.info(f"Schema entry attributes keys: {attrs_keys}")
                        # For schema entries, handle special attributes as proper AttributeValues
                        # Extract schema-specific attributes as proper AttributeValues
                        # Check both direct entry_dict and entry_dict['attributes']
                        attributes_source = entry_dict.get("attributes", entry_dict)

                        # Process ALL attributes from attributes_source
                        # Each attribute should be a SINGLE AttributeValues object containing all values
                        if isinstance(attributes_source, dict):
                            for key, value in attributes_source.items():
                                if key in {
                                    FlextLdifConstants.DictKeys.DN,
                                    FlextLdifConstants.DictKeys.OBJECTCLASS,
                                    FlextLdifConstants.DictKeys.METADATA,
                                }:
                                    continue

                                # Convert value to list of strings
                                if isinstance(value, list):
                                    string_values = [str(item) for item in value]
                                else:
                                    string_values = [str(value)]

                                # Store values directly (no AttributeValues wrapper)
                                schema_attrs[key] = string_values
                    else:
                        # For regular entries, extract attributes normally
                        attrs_value = entry_dict.get("attributes", entry_dict)
                        # Type narrow to dict[str, object]
                        if isinstance(attrs_value, dict):
                            attributes_dict: dict[str, object] = attrs_value
                        else:
                            attributes_dict = entry_dict.copy()

                        # Remove non-attribute fields
                        for key in [
                            FlextLdifConstants.DictKeys.DN,
                            FlextLdifConstants.DictKeys.OBJECTCLASS,
                            FlextLdifConstants.DictKeys.METADATA,
                        ]:
                            if isinstance(attributes_dict, dict):
                                attributes_dict.pop(key, None)

                        # Convert all attribute values to proper list format
                        # Each attribute is stored as a list of strings directly
                        converted_attributes: dict[str, list[str]] = {}
                        if isinstance(attributes_dict, dict):
                            for key, value in attributes_dict.items():
                                # Ensure value is a list of strings
                                if isinstance(value, list):
                                    # Flatten if nested lists exist
                                    string_values = [str(item) for item in value]
                                else:
                                    string_values = [str(value)]

                                # Store values directly (no AttributeValues wrapper)
                                converted_attributes[key] = string_values

                        schema_attrs = converted_attributes

                    # Extract objectClass and add it to schema_attrs BEFORE creating LdifAttributes
                    # ObjectClass is stored as an attribute, not a separate Entry field
                    objectclass_value = entry_dict.get(
                        FlextLdifConstants.DictKeys.OBJECTCLASS, []
                    )
                    if not isinstance(objectclass_value, list):
                        objectclass_value = (
                            [objectclass_value] if objectclass_value else []
                        )
                    # Convert to list of strings
                    objectclass_list = [str(oc) for oc in objectclass_value]

                    # Add objectClass to schema_attrs if present
                    if objectclass_list:
                        schema_attrs["objectClass"] = objectclass_list

                    # Create attributes with objectClass included
                    attributes = FlextLdifModels.LdifAttributes(attributes=schema_attrs)

                    # Extract metadata if present
                    metadata_value = entry_dict.get("metadata")
                    metadata = None
                    if metadata_value is not None and isinstance(
                        metadata_value, FlextLdifModels.QuirkMetadata
                    ):
                        metadata = metadata_value

                    entry_obj = FlextLdifModels.Entry(
                        dn=dn, attributes=attributes, metadata=metadata
                    )
                    entry_objects.append(entry_obj)
                except (ValueError, TypeError, AttributeError) as e:
                    # ABORT on conversion failure - do not continue with invalid data
                    dn_for_error: str = dn.value if dn else str(dn_value)
                    error_msg = f"Failed to convert entry to Entry object (DN: {dn_for_error}): {e}"
                    self.logger.exception(error_msg)
                    return FlextResult[FlextLdifModels.PipelineExecutionResult].fail(
                        error_msg
                    )

            entries_by_category[category] = entry_objects

        # Build PipelineExecutionResult with proper Entry objects
        result = FlextLdifModels.PipelineExecutionResult(
            entries_by_category=entries_by_category,
            statistics=pipeline_stats,
            file_paths=self._output_files,
        )
        return FlextResult[FlextLdifModels.PipelineExecutionResult].ok(result)

    def _create_output_directory(self) -> FlextResult[None]:
        """Create base output directory for LDIF files.

        Returns:
        FlextResult indicating success or failure

        """
        try:
            # Create base output directory only (files will be written directly here)
            self._output_dir.mkdir(parents=True, exist_ok=True)
            return FlextResult[None].ok(None)
        except (OSError, PermissionError) as e:
            return FlextResult[None].fail(f"Failed to create output directory: {e}")

    class _LdifFileParsingChain:
        """LDIF file parsing helper methods using railway pattern."""

        @staticmethod
        def parse_ldif_file(
            ldif_file: Path,
            quirk_registry: FlextLdifQuirksRegistry,
        ) -> FlextResult[list[dict[str, object]]]:
            """Parse single LDIF file and convert entries to dictionaries.

            Args:
            ldif_file: Path to LDIF file to parse
            quirk_registry: Registry for RFC parser quirks

            Returns:
            FlextResult containing list of entry dictionaries from file

            """
            try:
                # Use RFC parser for standards-compliant parsing
                parser_params: dict[str, object] = {
                    "file_path": str(ldif_file),
                    "parse_changes": False,
                    "encoding": "utf-8",
                }
                parser = FlextLdifRfcLdifParser(
                    params=parser_params, quirk_registry=quirk_registry
                )
                parse_result = parser.execute()

                if parse_result.is_failure:
                    return FlextResult[list[dict[str, object]]].fail(
                        f"Failed to parse {ldif_file}: {parse_result.error}"
                    )

                # Convert Entry models to dictionaries
                parsed_data_raw = parse_result.unwrap()
                entries_raw = parsed_data_raw.get("entries", [])
                if not isinstance(entries_raw, list):
                    return FlextResult[list[dict[str, object]]].ok([])

                # 🔍 DEBUG POINT 0: Check Entry MODELS for ACL attributes (BEFORE dict conversion)
                acl_count_models = sum(
                    1
                    for e in entries_raw
                    if hasattr(e, "attributes")
                    and hasattr(e.attributes, "attributes")
                    and any(
                        k.lower() in {"orclaci", "orclentrylevelaci"}
                        for k in e.attributes.attributes
                    )
                )
                if acl_count_models > 0:
                    logger.info(
                        f"🔍 DEBUG POINT 0: Entry MODELS with ACL attributes in {ldif_file.name}: {acl_count_models}/{len(entries_raw)}"
                    )
                else:
                    logger.warning(
                        f"🔍 DEBUG POINT 0: NO Entry MODELS with ACL attributes in {ldif_file.name} (checked {len(entries_raw)} models)!"
                    )

                file_entries: list[dict[str, object]] = []
                for entry_model in entries_raw:
                    # Extract data from Entry model
                    entry_dict: dict[str, object] = {
                        FlextLdifConstants.DictKeys.DN: entry_model.dn.value,
                        FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                        FlextLdifConstants.DictKeys.OBJECTCLASS: [],
                    }

                    # Type narrow attributes dict
                    attrs_dict: dict[str, object] = {}

                    # Extract objectClass from attributes
                    for (
                        attr_name,
                        attr_values,
                    ) in entry_model.attributes.attributes.items():
                        # Handle both object with .values attribute and direct list
                        values_list = (
                            attr_values.values
                            if hasattr(attr_values, "values")
                            else attr_values
                        )
                        if attr_name.lower() == FlextLdifConstants.DictKeys.OBJECTCLASS:
                            # Add to objectClass list
                            entry_dict[FlextLdifConstants.DictKeys.OBJECTCLASS] = (
                                values_list
                            )
                        # Add to attributes dict
                        # (multi-valued attributes stored as list or single value)
                        elif len(values_list) == 1:
                            attrs_dict[attr_name] = values_list[0]
                        else:
                            attrs_dict[attr_name] = values_list

                    # Set attributes after building the dict
                    entry_dict[FlextLdifConstants.DictKeys.ATTRIBUTES] = attrs_dict

                    file_entries.append(entry_dict)

                # DEBUG: Count entries with ACL attributes after parsing
                acl_count = sum(
                    1
                    for e in file_entries
                    if any(
                        k.lower() in {"orclaci", "orclentrylevelaci"}
                        for k in cast(
                            "dict[str, object]",
                            e.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {}),
                        )
                    )
                )
                if acl_count > 0:
                    logger.info(
                        f"🔍 DEBUG POINT 1: Entries with ACL attributes after parsing {ldif_file.name}: {acl_count}/{len(file_entries)}"
                    )

                return FlextResult[list[dict[str, object]]].ok(file_entries)

            except (OSError, UnicodeDecodeError) as e:
                return FlextResult[list[dict[str, object]]].fail(
                    f"Failed to parse {ldif_file}: {e}"
                )

    def _parse_entries(self) -> FlextResult[list[dict[str, object]]]:
        """Parse all LDIF entries from input directory using RFC parser.

        Returns:
        FlextResult containing list of parsed entry dictionaries

        Note:
        Uses FlextLdifRfcLdifParser for RFC 2849 compliant parsing.
        Consolidates file parsing with batch_process for functional composition.

        """
        try:
            # Get all LDIF files from input directory
            if not self._input_dir.exists():
                return FlextResult[list[dict[str, object]]].fail(
                    f"Input directory does not exist: {self._input_dir}"
                )

            # Apply input file filter if provided
            # (generic feature for selective processing)
            if self._input_files:
                # Process only specified files
                ldif_files = [
                    self._input_dir / filename
                    for filename in self._input_files
                    if (self._input_dir / filename).exists()
                ]
                if not ldif_files:
                    return FlextResult[list[dict[str, object]]].fail(
                        f"None of the specified input files found: {self._input_files}"
                    )
            else:
                # Process all LDIF files (default behavior)
                ldif_files = list(self._input_dir.glob("*.ldif"))
                if not ldif_files:
                    return FlextResult[list[dict[str, object]]].fail(
                        "No LDIF files found in input directory"
                    )

            # Initialize quirk registry for RFC parser
            quirk_registry = FlextLdifQuirksRegistry()

            # Define processor function for batch_process composition
            def parse_ldif_file_processor(
                ldif_file: Path,
            ) -> FlextResult[list[dict[str, object]]]:
                """Process single LDIF file with railway pattern."""
                return self._LdifFileParsingChain.parse_ldif_file(
                    ldif_file, quirk_registry
                )

            # Use batch_process to parse all files and flatten results
            # Returns (successes, failures) tuple for statistics tracking
            parsed_file_results, file_failures = FlextResult.batch_process(
                ldif_files, parse_ldif_file_processor
            )

            # Log failures if any (non-fatal, continue with successful files)
            if file_failures:
                self.logger.debug(
                    f"LDIF file parsing: {len(file_failures)} files failed to parse"
                )

            # Flatten list of lists (each file returns list of entries)
            # parsed_file_results is list[list[dict[str, object]]]
            entries: list[dict[str, object]] = []
            for file_entries in parsed_file_results:
                if isinstance(file_entries, list):
                    entries.extend(file_entries)

            return FlextResult[list[dict[str, object]]].ok(entries)

        except (OSError, UnicodeDecodeError) as e:
            return FlextResult[list[dict[str, object]]].fail(
                f"Failed to parse entries: {e}"
            )

    def _categorize_entry(self, entry: dict[str, object]) -> tuple[str, str | None]:
        """Delegate to FlextLdifFilters for 6-category entry categorization.

        Args:
            entry: Entry dictionary to categorize

        Returns:
            Tuple of (category, rejection_reason)
            Category is one of: schema, hierarchy, users, groups, acl, rejected

        """
        return FlextLdifFilters.categorize_entry(
            entry,
            categorization_rules=cast("dict[str, object]", self._categorization_rules),
            schema_whitelist_rules=cast(
                "dict[str, object] | None", self._schema_whitelist_rules
            ),
        )

    def _is_entry_under_base_dn(self, entry: dict[str, object]) -> bool:
        """Check if entry's DN is under the configured base_dn.

        Args:
            entry: Entry dictionary with 'dn' attribute
                   Can be either simple string or Pydantic Entry dict with {'value': ...}

        Returns:
            True if entry is under base_dn or no base_dn is configured,
            False otherwise

        """
        # If no base_dn filter configured, include all entries
        if not self._base_dn:
            return True

        # Extract DN from entry
        # Handle both simple string format and Pydantic Entry format
        dn_value: object = entry.get("dn")
        dn: str = ""

        if isinstance(dn_value, str):
            # Simple string format
            dn = dn_value
        elif isinstance(dn_value, dict):
            # Pydantic Entry format with {'value': ..., 'metadata': ..., 'components': ...}
            dn_extracted: object = dn_value.get('value')
            if isinstance(dn_extracted, str):
                dn = dn_extracted

        if not dn:
            return False

        # Normalize DN to lowercase for comparison
        dn_lower = dn.lower()

        # Check if DN ends with base_dn (is under base_dn in LDAP hierarchy)
        # Example: "ou=users,dc=ctbc" ends with "dc=ctbc"
        return dn_lower.endswith(self._base_dn) or dn_lower == self._base_dn

    def _categorize_entries(
        self, entries: list[dict[str, object]]
    ) -> FlextResult[dict[str, list[dict[str, object]]]]:
        """Categorize all entries into structured categories.

        Args:
        entries: List of parsed entry dictionaries

        Returns:
        FlextResult containing dictionary mapping category to entry list

        """
        try:
            # Define processor function for batch_process composition
            def categorize_entry_processor(
                entry: dict[str, object],
            ) -> FlextResult[dict[str, object]]:
                """Process and categorize single entry with railway pattern."""
                return self._EntryCategorizationChain.categorize_and_track(entry, self)

            # Use batch_process to categorize all entries and extract results
            # Returns (successes, failures) tuple for statistics tracking
            categorization_results, categorization_failures = FlextResult.batch_process(
                entries, categorize_entry_processor
            )

            # Log failures if any (non-fatal, continue processing)
            if categorization_failures:
                self.logger.debug(
                    f"Entry categorization: {len(categorization_failures)} entries "
                    f"failed categorization"
                )

            # Build categorized dictionary from results
            categorized: dict[str, list[dict[str, object]]] = {
                FlextLdifConstants.Categories.SCHEMA: [],
                FlextLdifConstants.Categories.HIERARCHY: [],
                FlextLdifConstants.Categories.USERS: [],
                FlextLdifConstants.Categories.GROUPS: [],
                "acl": [],
                "rejected": [],
            }

            rejection_reasons_map: dict[str, str] = {}

            for result_item in categorization_results:
                # Type narrow result to ensure it has required structure
                if not isinstance(result_item, dict):
                    continue

                category = result_item.get("category")
                processed_entry = result_item.get("entry")
                rejection_reason = result_item.get("rejection_reason")

                # Type narrow category
                if not isinstance(category, str) or category not in categorized:
                    continue

                # Add entry to appropriate category
                if isinstance(processed_entry, dict):
                    # Apply base_dn filter for non-schema categories
                    # Schema entries (00) are never filtered by base_dn
                    is_under_base_dn = self._is_entry_under_base_dn(processed_entry)
                    if (
                        category != FlextLdifConstants.Categories.SCHEMA
                        and not is_under_base_dn
                    ):
                        # Reject entry if not under base_dn
                        dn_value = processed_entry.get(
                            FlextLdifConstants.DictKeys.DN, "unknown"
                        )
                        base_dn_rejection = (
                            f"Entry DN not under base_dn '{self._base_dn}'"
                        )
                        categorized["rejected"].append(processed_entry)
                        if isinstance(dn_value, str):
                            rejection_reasons_map[dn_value] = base_dn_rejection
                        self.logger.debug(
                            f"Filtered out entry not under base_dn: {dn_value}"
                        )
                        continue

                    categorized[category].append(processed_entry)

                    # Track rejection reason if present
                    if isinstance(rejection_reason, str) and rejection_reason:
                        dn_value = processed_entry.get(FlextLdifConstants.DictKeys.DN)
                        if isinstance(dn_value, str):
                            rejection_reasons_map[dn_value] = rejection_reason

            # Step 2: Inject rejection reasons into rejected entries using batch_process
            rejected_entries = categorized.get("rejected", [])
            if rejected_entries and rejection_reasons_map:
                # Define processor for rejection reason injection
                def inject_rejection_reason_processor(
                    entry: dict[str, object],
                ) -> FlextResult[dict[str, object]]:
                    """Inject rejection reason into rejected entry."""
                    return self._EntryCategorizationChain.inject_rejection_reason(
                        entry, rejection_reasons_map
                    )

                # Use batch_process to inject rejection reasons
                injected_entries, injection_failures = FlextResult.batch_process(
                    rejected_entries, inject_rejection_reason_processor
                )

                # Log failures if any (non-fatal)
                if injection_failures:
                    self.logger.debug(
                        f"Rejection reason injection: {len(injection_failures)} "
                        f"entries failed injection"
                    )

                # Replace rejected entries with injected versions
                categorized["rejected"] = injected_entries

            # DEBUG: Log ACL category details after categorization
            acl_count = len(categorized.get("acl", []))
            if acl_count > 0:
                self.logger.info(
                    f"🔍 DEBUG POINT 3: ACL category has {acl_count} entries after categorization"
                )
                first_acl = categorized["acl"][0]
                dn = first_acl.get(FlextLdifConstants.DictKeys.DN, "unknown")
                attrs = first_acl.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
                if isinstance(attrs, dict):
                    self.logger.info(
                        f"🔍 DEBUG: First ACL entry DN={dn}, attributes={list(attrs.keys())[:5]}"
                    )
            else:
                self.logger.warning(
                    "🔍 DEBUG POINT 3: ACL category is EMPTY after categorization! (Expected 2,302+ entries)"
                )

            return FlextResult[dict[str, list[dict[str, object]]]].ok(categorized)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[dict[str, list[dict[str, object]]]].fail(
                f"Entry categorization failed: {e}"
            )

    def _filter_forbidden_attributes(
        self, attributes: dict[str, object]
    ) -> dict[str, object]:
        """Filter out forbidden attributes from entry.

        STRATEGY PATTERN: Business rules from client application (e.g., algar-oud-mig)
        determine which attributes to filter.

        Delegates to FlextLdifFilters for filtering logic.

        Args:
            attributes: Dictionary of attributes to filter

        Returns:
            Filtered attributes dictionary without forbidden attributes

        """
        if not self._forbidden_attributes:
            return attributes

        # Create case-insensitive set of forbidden attributes
        forbidden_lower = {attr.lower() for attr in self._forbidden_attributes}

        # Filter attributes using case-insensitive comparison
        filtered: dict[str, object] = {
            attr_name: attr_value
            for attr_name, attr_value in attributes.items()
            if attr_name.lower() not in forbidden_lower
        }

        return filtered

    def _filter_forbidden_objectclasses(self, entry: object) -> FlextResult[object]:
        """Filter forbidden objectClasses from entry.

        STRATEGY PATTERN: Business rules from client application (e.g., algar-oud-mig)
        determine which objectClasses to filter. This method provides generic filtering.

        Args:
        entry: FlextLdifModels.Entry object to filter

        Returns:
        FlextResult containing filtered Entry or error

        Example forbidden_objectclasses:
        ['orclContainerOC', 'orclService', 'orclcontextaux82']

        Note:
        Uses FlextLdifFilters.filter_entry_objectclasses for actual filtering.
        Maintains entry metadata and DN during transformation.

        """
        if not self._forbidden_objectclasses:
            # No filtering needed - return entry as-is
            return FlextResult[object].ok(entry)

        # Type guard - ensure we have an Entry object
        if not isinstance(entry, FlextLdifModels.Entry):
            return FlextResult[object].fail(
                f"Expected FlextLdifModels.Entry, got {type(entry).__name__}"
            )

        # Delegate to FlextLdifFilters for actual filtering
        # Type cast result to match return type
        filter_result = FlextLdifFilters.filter_entry_objectclasses(
            entry, self._forbidden_objectclasses
        )

        # Map FlextResult[FlextLdifModels.Entry] to FlextResult[object]
        if filter_result.is_success:
            return FlextResult[object].ok(filter_result.unwrap())
        return FlextResult[object].fail(filter_result.error)

    class _AclTransformationChain:
        """ACL transformation helper methods using railway pattern."""

        @staticmethod
        def transform_acl_entry(
            entry: dict[str, object],
            parser_acl_quirk: BaseAclQuirk | None,
            writer_acl_quirk: BaseAclQuirk | None,
        ) -> FlextResult[dict[str, object]]:
            """Transform single ACL entry using server-specific quirks.

            GENERIC: Works with ANY server combination via provided quirks.

            Args:
            entry: ACL entry dictionary to transform
            parser_acl_quirk: Source server ACL quirk for parsing (or None)
            writer_acl_quirk: Target server ACL quirk for writing (or None)

            Returns:
            FlextResult with transformed entry

            """
            try:
                transformed_entry = entry.copy()
                attributes = transformed_entry.get(
                    FlextLdifConstants.DictKeys.ATTRIBUTES, {}
                )
                if not isinstance(attributes, dict):
                    return FlextResult[dict[str, object]].ok(transformed_entry)

                # If no quirks provided, return entry as-is (no ACL transformation)
                if parser_acl_quirk is None or writer_acl_quirk is None:
                    return FlextResult[dict[str, object]].ok(transformed_entry)

                new_attributes: dict[str, object] = {}

                for attr_name, attr_value in attributes.items():
                    if attr_name.lower() in {"orclaci", "orclentrylevelaci"}:
                        values_to_process = (
                            attr_value if isinstance(attr_value, list) else [attr_value]
                        )

                        transformed_acis = []
                        for single_value in values_to_process:
                            acl_line = f"{attr_name}: {single_value}"
                            parse_result = parser_acl_quirk.parse_acl(acl_line)

                            if parse_result.is_failure:
                                continue

                            acl_data = parse_result.unwrap()

                            rfc_result = parser_acl_quirk.convert_acl_to_rfc(acl_data)
                            if rfc_result.is_failure:
                                continue

                            rfc_data = rfc_result.unwrap()

                            oud_result = writer_acl_quirk.convert_acl_from_rfc(rfc_data)
                            if oud_result.is_failure:
                                continue

                            oud_data = oud_result.unwrap()

                            write_result = writer_acl_quirk.write_acl_to_rfc(oud_data)
                            if write_result.is_failure:
                                continue

                            aci_line = write_result.unwrap()

                            if aci_line.startswith("aci:"):
                                transformed_acis.append(
                                    aci_line.split(":", 1)[1].strip()
                                )
                            else:
                                transformed_acis.append(aci_line)

                        if transformed_acis:
                            if len(transformed_acis) == 1:
                                new_attributes["aci"] = transformed_acis[0]
                            else:
                                new_attributes["aci"] = transformed_acis

                    else:
                        new_attributes[attr_name] = attr_value

                transformed_entry[FlextLdifConstants.DictKeys.ATTRIBUTES] = (
                    new_attributes
                )
                return FlextResult[dict[str, object]].ok(transformed_entry)

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[dict[str, object]].fail(
                    f"ACL transformation failed: {e}"
                )

    class _EntryCategorizationChain:
        """Entry categorization helper methods using railway pattern."""

        @staticmethod
        def categorize_and_track(
            entry: dict[str, object],
            pipeline: object,  # FlextLdifCategorizedMigrationPipeline
        ) -> FlextResult[dict[str, object]]:
            """Categorize single entry with ACL metadata extraction and tracking.

            Args:
            entry: Entry dictionary to categorize
            pipeline: Reference to pipeline instance for categorization access

            Returns:
            FlextResult containing result dict with category, entry, rejection_reason

            """
            try:
                # Type narrow pipeline to access _categorize_entry
                if not hasattr(pipeline, "_categorize_entry"):
                    return FlextResult[dict[str, object]].fail(
                        "Pipeline missing _categorize_entry method"
                    )

                # Check if entry is valid dictionary
                if not isinstance(entry, dict):
                    return FlextResult[dict[str, object]].fail(
                        "Entry is not a dictionary"
                    )

                # Categorize the entry (accessing private method intentionally)
                categorize_func = pipeline._categorize_entry  # noqa: SLF001
                category, rejection_reason = categorize_func(entry)

                # Type narrow category and rejection_reason
                if not isinstance(category, str):
                    return FlextResult[dict[str, object]].fail(
                        f"Invalid category type: {type(category)}"
                    )

                # Build result dictionary with tracking information
                result_dict: dict[str, object] = {
                    "category": category,
                    "entry": entry,
                    "rejection_reason": rejection_reason,
                }

                return FlextResult[dict[str, object]].ok(result_dict)

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[dict[str, object]].fail(
                    f"Entry categorization and tracking failed: {e}"
                )

        @staticmethod
        def inject_rejection_reason(
            entry: dict[str, object],
            rejection_reasons_map: dict[str, str],
        ) -> FlextResult[dict[str, object]]:
            """Inject rejection reason into rejected entry if available.

            Args:
            entry: Entry dictionary to inject rejection reason into
            rejection_reasons_map: Dictionary mapping DN to rejection reason

            Returns:
            FlextResult containing updated entry

            """
            try:
                # Type narrow entry to dict
                if not isinstance(entry, dict):
                    return FlextResult[dict[str, object]].ok(entry)

                # Get DN value for lookup
                dn_value = entry.get(FlextLdifConstants.DictKeys.DN)

                # Type narrow DN to string
                if not isinstance(dn_value, str):
                    return FlextResult[dict[str, object]].ok(entry)

                # Check if rejection reason exists for this DN
                if dn_value not in rejection_reasons_map:
                    return FlextResult[dict[str, object]].ok(entry)

                # Make copy of entry and inject rejection reason
                updated_entry = entry.copy()
                attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})

                # Type narrow attributes to dict
                if not isinstance(attrs, dict):
                    return FlextResult[dict[str, object]].ok(updated_entry)

                # Create new attributes dict with rejection reason
                new_attrs = attrs.copy()
                new_attrs["rejectionReason"] = rejection_reasons_map[dn_value]

                # Update entry with new attributes
                updated_entry[FlextLdifConstants.DictKeys.ATTRIBUTES] = new_attrs

                return FlextResult[dict[str, object]].ok(updated_entry)

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[dict[str, object]].fail(
                    f"Rejection reason injection failed: {e}"
                )

    def _extract_acl_entries_final_phase(
        self, all_entries: list[dict[str, object]]
    ) -> FlextResult[list[dict[str, object]]]:
        """Extract ACL entries as final separate phase.

        Scans all parsed entries and creates minimal ACL entries containing:
        - DN from original entry
        - ONLY ACL attributes (orclaci, orclentrylevelaci, aci)
        - Applies quirks: OID → RFC → OUD conversion
        - FILTERS by base_dn (Phase 04 must respect baseDN filtering)

        This is a DEDICATED ACL processing phase that runs AFTER categorization
        but BEFORE transformation. It ensures ACL attributes are properly
        extracted and converted using the quirks system.

        Args:
            all_entries: All parsed entry dictionaries from input

        Returns:
            FlextResult containing list of converted ACL entries

        """
        try:
            acl_entries: list[dict[str, object]] = []
            acl_attribute_names = {"orclaci", "orclentrylevelaci", "aci"}

            # Step 1: Scan all entries for ACL attributes
            for entry in all_entries:
                if not isinstance(entry, dict):
                    continue

                # Get entry DN with type narrowing
                # DN can be either a simple string or a dict with 'value' key (from Pydantic model)
                dn_value: object = entry.get(FlextLdifConstants.DictKeys.DN)
                dn: str = ""

                if isinstance(dn_value, str):
                    # Simple string format (legacy dict format)
                    dn = dn_value
                elif isinstance(dn_value, dict):
                    # Pydantic Entry model format with {'value': ..., 'metadata': ..., 'components': ...}
                    dn_extracted: object = dn_value.get('value')
                    if isinstance(dn_extracted, str):
                        dn = dn_extracted

                if not dn:
                    # No valid DN found, skip entry
                    continue

                # Get entry attributes with type narrowing
                # Attributes can be either flat dict or nested dict with 'attributes' key (from Pydantic model)
                attributes_value: object = entry.get(
                    FlextLdifConstants.DictKeys.ATTRIBUTES
                )
                if not isinstance(attributes_value, dict):
                    continue

                # Extract actual attributes dict
                # If Pydantic Entry format, attributes are under 'attributes' key
                # Otherwise use attributes_value directly
                attributes_container: dict[str, object] = attributes_value
                if 'attributes' in attributes_container:
                    # Pydantic Entry model format
                    inner_attrs: object = attributes_container.get('attributes')
                    if isinstance(inner_attrs, dict):
                        attributes: dict[str, object] = inner_attrs
                    else:
                        continue
                else:
                    # Legacy dict format - use attributes directly
                    attributes = attributes_container

                # Check if entry has any ACL attributes
                has_acl = any(
                    attr_name.lower() in acl_attribute_names for attr_name in attributes
                )

                if not has_acl:
                    continue

                # CRITICAL: Filter ACL entries by base_dn (Phase 04 filtering)
                # ACL entries MUST match target baseDN, just like phases 01-03
                is_under_base_dn = self._is_entry_under_base_dn(entry)
                if not is_under_base_dn:
                    # Skip ACL entries not under base_dn
                    self.logger.debug(
                        f"Phase 04 - Filtering out-of-scope ACL entry: {dn}"
                    )
                    continue

                # Step 2: Extract ACL definition strings from raw attributes
                # Raw attributes have structure: {'orclaci': {'values': [...], 'single_value': ...}, ...}
                # RFC writer's _extract_acl_definitions expects ACL items as dicts with 'DEFINITION' key
                acl_items: list[object] = []

                for attr_name, attr_value in attributes.items():
                    if attr_name.lower() not in acl_attribute_names:
                        continue

                    # Extract ACL values from attribute
                    # Attribute value can be:
                    # 1. Dict with 'values' key (from parsed LDIF): {'values': [...], 'single_value': ...}
                    # 2. List of strings (legacy format)
                    # 3. String (single value)
                    acl_definitions: list[str] = []

                    if isinstance(attr_value, dict):
                        # Pydantic Entry model format
                        if 'values' in attr_value:
                            values_list: object = attr_value.get('values')
                            if isinstance(values_list, list):
                                acl_definitions.extend([
                                    val for val in values_list if isinstance(val, str)
                                ])
                        elif 'single_value' in attr_value:
                            single_val: object = attr_value.get('single_value')
                            if isinstance(single_val, str):
                                acl_definitions.append(single_val)
                    elif isinstance(attr_value, list):
                        # Legacy list format
                        acl_definitions.extend([
                            val for val in attr_value if isinstance(val, str)
                        ])
                    elif isinstance(attr_value, str):
                        # Single value (string)
                        acl_definitions.append(attr_value)

                    # Convert ACL definitions to format expected by RFC writer
                    # Wrap each definition in a dict with 'DEFINITION' key for compatibility
                    acl_items.extend([
                        {FlextLdifConstants.DictKeys.DEFINITION: acl_def}
                        for acl_def in acl_definitions
                    ])

                # Build minimal ACL entry with wrapped ACL definitions
                # DN can be either simple string or dict with 'value' key
                # ACL is a list of dicts with 'DEFINITION' key for RFC writer to process
                acl_entry: dict[str, object] = {
                    FlextLdifConstants.DictKeys.DN: entry.get(FlextLdifConstants.DictKeys.DN, dn),
                    FlextLdifConstants.DictKeys.ACL: acl_items,
                }

                # Step 3: Apply parser quirk (OID → RFC)
                # Get parser's ACL quirk if available
                parser_acl_quirk = None
                if self._parser_quirk is not None and hasattr(
                    self._parser_quirk, "acl_quirk"
                ):
                    parser_acl_quirk = self._parser_quirk.acl_quirk

                # Step 4: Apply writer quirk (RFC → OUD: aci)
                # Get writer's ACL quirk if available
                writer_acl_quirk = None
                if self._writer_quirk is not None and hasattr(
                    self._writer_quirk, "acl_quirk"
                ):
                    writer_acl_quirk = self._writer_quirk.acl_quirk

                # Step 5: Transform ACL entry using quirks system
                if parser_acl_quirk is not None and writer_acl_quirk is not None:
                    transform_result = self._AclTransformationChain.transform_acl_entry(
                        acl_entry, parser_acl_quirk, writer_acl_quirk
                    )

                    if transform_result.is_success:
                        transformed_entry = transform_result.unwrap()
                        acl_entries.append(transformed_entry)
                    else:
                        # Log transformation failure but continue
                        self.logger.debug(
                            f"ACL transformation failed for DN={dn}: {transform_result.error}"
                        )
                        # Add untransformed entry as fallback
                        acl_entries.append(acl_entry)
                else:
                    # No quirks available, add untransformed entry
                    acl_entries.append(acl_entry)

            # Log extraction statistics
            self.logger.info(
                f"ACL extraction: Found {len(acl_entries)} ACL entries from "
                f"{len(all_entries)} total entries"
            )

            return FlextResult[list[dict[str, object]]].ok(acl_entries)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[dict[str, object]]].fail(
                f"ACL extraction failed: {e}"
            )

    def _transform_categories(
        self, categorized: dict[str, list[dict[str, object]]]
    ) -> FlextResult[dict[str, list[dict[str, object]]]]:
        """Apply per-category transformations using quirks system.

        Implements proper OID→RFC→OUD transformation using quirks:
        1. Parse ACL attributes with source quirks (OID format)
        2. Convert to RFC generic intermediate format (preserves metadata)
        3. Convert from RFC to target quirks (OUD format)
        4. Write transformed ACL in target format
        5. Filter forbidden attributes (business rules from client)

        Args:
        categorized: Dictionary mapping category to entry list

        Returns:
        FlextResult containing transformed categorized entries

        """
        try:
            # Get ACL quirks from provided parser/writer quirks
            # Generic approach - works with ANY server combination
            # Parser quirk handles source server ACL format
            # Writer quirk handles target server ACL format
            parser_acl_quirk: BaseAclQuirk | None = None
            writer_acl_quirk: BaseAclQuirk | None = None

            # Try to get ACL quirk from parser (source server)
            if self._parser_quirk is not None and hasattr(
                self._parser_quirk, "AclQuirk"
            ):
                acl_quirk_cls = getattr(self._parser_quirk, "AclQuirk", None)
                if acl_quirk_cls is not None:
                    parser_acl_quirk = acl_quirk_cls()

            # Try to get ACL quirk from writer (target server)
            if self._writer_quirk is not None and hasattr(
                self._writer_quirk, "AclQuirk"
            ):
                acl_quirk_cls = getattr(self._writer_quirk, "AclQuirk", None)
                if acl_quirk_cls is not None:
                    writer_acl_quirk = acl_quirk_cls()

            # Transform ACL entries (category "acl" ONLY) using batch processing
            # CRITICAL: User requirement: "aci must only be migrated in 04, only, only, only"
            # Phases 01-03 must NOT have aci attributes - only phase 04 (acl category)
            # Delegates to helper method for railway-oriented error handling
            acl_entries = categorized.get("acl", [])
            if acl_entries:
                # Define processor function for batch_process composition
                def transform_acl_entry_processor(
                    entry: dict[str, object],
                ) -> FlextResult[dict[str, object]]:
                    """Process single ACL entry with railway pattern."""
                    return self._AclTransformationChain.transform_acl_entry(
                        entry, parser_acl_quirk, writer_acl_quirk
                    )

                # Use batch_process for functional composition
                # Returns (successes, failures) tuple for statistics tracking
                transformed_acl, acl_failures = FlextResult.batch_process(
                    acl_entries, transform_acl_entry_processor
                )

                # Log failures if any (non-fatal, continue processing)
                if acl_failures:
                    self.logger.debug(
                        f"ACL transformation: {len(acl_failures)} entries "
                        f"failed transformation"
                    )

                # Replace ACL entries with successfully transformed versions
                categorized["acl"] = transformed_acl

            # Step 1.5: Apply EntryQuirk conversion (OID→RFC normalization for ALL entries)
            # Convert boolean attributes "0"/"1" → "TRUE"/"FALSE" per RFC 4517
            parser_entry_quirk = None
            if self._parser_quirk is not None and hasattr(
                self._parser_quirk, "EntryQuirk"
            ):
                entry_quirk_cls = getattr(self._parser_quirk, "EntryQuirk", None)
                if entry_quirk_cls is not None:
                    parser_entry_quirk = entry_quirk_cls()

            if parser_entry_quirk is not None:
                for category, entries in categorized.items():
                    transformed_entries = []
                    for entry in entries:
                        # Apply OID→RFC conversion to normalize non-RFC values
                        entry_result = parser_entry_quirk.convert_entry_to_rfc(entry)
                        if entry_result.is_success:
                            transformed_entries.append(entry_result.unwrap())
                        else:
                            # Log warning but keep original entry
                            self.logger.debug(
                                f"Entry conversion failed for {entry.get('dn', 'unknown')}: "
                                f"{entry_result.error}"
                            )
                            transformed_entries.append(entry)
                    categorized[category] = transformed_entries

            # Step 2: Filter forbidden attributes and objectClasses from all categories
            # STRATEGY PATTERN: Business rules from client application
            if self._forbidden_attributes or self._forbidden_objectclasses:
                # Define processor function for filtering single entry
                def filter_entry_processor(
                    entry: dict[str, object],
                ) -> FlextResult[dict[str, object]]:
                    """Filter forbidden attributes and objectClasses from single entry."""
                    try:
                        # Check if entry is valid dictionary
                        if not isinstance(entry, dict):
                            return FlextResult[dict[str, object]].ok(entry)

                        # Check if entry has attributes key
                        if FlextLdifConstants.DictKeys.ATTRIBUTES not in entry:
                            return FlextResult[dict[str, object]].ok(entry)

                        # Make copy of entry
                        filtered_entry = entry.copy()
                        attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES)

                        # Type narrow attributes to dict
                        if not isinstance(attrs, dict):
                            return FlextResult[dict[str, object]].ok(filtered_entry)

                        # Step 1: Filter forbidden attributes
                        filtered_attrs = self._filter_forbidden_attributes(attrs)

                        # Step 2: Filter forbidden objectClasses
                        if self._forbidden_objectclasses:
                            oc_attr = FlextLdifConstants.DictKeys.OBJECTCLASS
                            if oc_attr in filtered_attrs:
                                oc_values = filtered_attrs[oc_attr]
                                if isinstance(oc_values, list):
                                    forbidden_lower = {
                                        oc.lower()
                                        for oc in self._forbidden_objectclasses
                                    }
                                    filtered_ocs = [
                                        oc
                                        for oc in oc_values
                                        if oc.lower() not in forbidden_lower
                                    ]

                                    if not filtered_ocs:
                                        return FlextResult[dict[str, object]].fail(
                                            f"Entry {entry.get('dn', 'unknown')}: "
                                            "All objectClasses would be removed"
                                        )

                                    filtered_attrs[oc_attr] = filtered_ocs

                        # Update entry with filtered attributes
                        filtered_entry[FlextLdifConstants.DictKeys.ATTRIBUTES] = (
                            filtered_attrs
                        )

                        return FlextResult[dict[str, object]].ok(filtered_entry)

                    except (ValueError, TypeError, AttributeError) as e:
                        return FlextResult[dict[str, object]].fail(
                            f"Forbidden filtering failed: {e}"
                        )

                # Apply filtering to each category using batch_process
                for category, entries in categorized.items():
                    # Use batch_process for functional composition
                    filtered_entries, filter_failures = FlextResult.batch_process(
                        entries, filter_entry_processor
                    )

                    # Log failures if any (non-fatal, continue processing)
                    if filter_failures:
                        self.logger.debug(
                            f"Forbidden filtering for '{category}': "
                            f"{len(filter_failures)} entries failed filtering"
                        )

                    # Replace entries with successfully filtered versions
                    categorized[category] = filtered_entries

            # Step 3: Normalize DN references (groups and ACLs) using batch_process
            try:
                dn_service = FlextLdifDnService()
                dn_map_result = dn_service.build_canonical_dn_map(categorized)
                if dn_map_result.is_failure:
                    return FlextResult[dict[str, list[dict[str, object]]]].fail(
                        f"Failed to build DN map: {dn_map_result.error}"
                    )
                dn_map = dn_map_result.unwrap()
                ref_attrs = self._categorization_rules.get(
                    "dn_reference_attributes",
                    [
                        FlextLdifConstants.DictKeys.MEMBER,
                        "uniqueMember",
                        "owner",
                        "manager",
                        "seeAlso",
                        "roleOccupant",
                        "memberOf",
                    ],
                )
                ref_attrs_lower = {a.lower() for a in ref_attrs if isinstance(a, str)}

                # Define processor function for DN normalization
                def normalize_dn_processor(
                    entry: dict[str, object],
                ) -> FlextResult[dict[str, object]]:
                    """Normalize DN references in single entry."""
                    normalized_result = dn_service.normalize_dn_references_for_entry(
                        entry, dn_map, ref_attrs_lower
                    )
                    if normalized_result.is_failure:
                        return FlextResult[dict[str, object]].fail(
                            f"Failed to normalize DN references: {normalized_result.error}"
                        )
                    normalized_entry = normalized_result.unwrap()
                    return FlextResult[dict[str, object]].ok(normalized_entry)

                # Apply DN normalization to each category using batch_process
                for category, entries in categorized.items():
                    # Skip schema entries
                    if category == FlextLdifConstants.Categories.SCHEMA:
                        continue

                    # Use batch_process for functional composition
                    # Returns (successes, failures) tuple for statistics tracking
                    normalized_entries, normalization_failures = (
                        FlextResult.batch_process(entries, normalize_dn_processor)
                    )

                    # Log failures if any (non-fatal, continue processing)
                    if normalization_failures:
                        self.logger.debug(
                            f"DN reference normalization for '{category}': "
                            f"{len(normalization_failures)} entries failed normalization"
                        )

                    # Replace entries with successfully normalized versions
                    categorized[category] = normalized_entries

            except (
                Exception
            ) as e:  # Safety net: do not fail migration if normalization fails
                self.logger.debug(f"DN reference normalization skipped: {e}")

            return FlextResult[dict[str, list[dict[str, object]]]].ok(categorized)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[dict[str, list[dict[str, object]]]].fail(
                f"ACL transformation failed: {e}"
            )


__all__ = ["FlextLdifCategorizedMigrationPipeline"]
