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

import re
from pathlib import Path
from typing import override

from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.entry_quirks import FlextLdifEntryQuirks
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.quirks.servers import (
    FlextLdifQuirksServersOid,
    FlextLdifQuirksServersOud,
)
from flext_ldif.rfc.rfc_ldif_parser import FlextLdifRfcLdifParser
from flext_ldif.services.dn_service import DnService


class FlextLdifCategorizedMigrationPipeline(FlextService[dict[str, object]]):
    """Categorized LDIF migration with structured LDIF file output.

    Enterprise-grade categorized LDIF migration with rule-based entry classification
    and structured multi-file output for complex directory transformations.

    Features:
    - Rule-based entry categorization with regex pattern matching
    - 6-file structured LDIF output (00-schema.ldif through 05-rejected.ldif)
    - Per-category server-specific quirks transformation
    - Schema whitelist filtering for controlled migrations
    - Forbidden attributes filtering for security compliance
    - Comprehensive statistics and rejection tracking
    - Railway-Oriented Programming with FlextResult error handling
    - Memory-efficient batch processing with configurable parameters

    Architecture:
    - Uses FlextLdifRfcLdifParser for RFC-compliant entry parsing
    - Uses DnService for DN validation and case consistency
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
        schema_whitelist_rules: dict[str, list[str]] | None = None,
        input_files: list[str] | None = None,
        output_files: dict[str, str] | None = None,
        entry_quirks: FlextLdifEntryQuirks | None = None,
        forbidden_attributes: list[str] | None = None,
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
            schema_whitelist_rules: Optional schema whitelist rules
            input_files: Optional list of specific input files to process
            output_files: Optional mapping of category names to output filenames
            entry_quirks: Service for handling entry-level quirks
            forbidden_attributes: List of attribute names (with optional subtypes)
                to filter out during transformation. Examples: ['authPassword',
                'authpassword;orclcommonpwd', 'authpassword;oid']

        """
        super().__init__()
        self._input_dir = Path(input_dir)
        self._output_dir = Path(output_dir)
        self._categorization_rules = categorization_rules
        self._parser_quirk = parser_quirk
        self._writer_quirk = writer_quirk
        self._source_server = source_server
        self._target_server = target_server
        self._schema_whitelist_rules = schema_whitelist_rules
        self._input_files = input_files
        self._entry_quirks = entry_quirks or FlextLdifEntryQuirks()
        self._forbidden_attributes = forbidden_attributes or []

        # DN-valued attributes that need case normalization
        # Phase 4: Attributes that contain DN references needing case normalization
        self._dn_valued_attributes = [
            "member",
            "uniqueMember",
            "owner",
            "seeAlso",
            "manager",
            "secretary",
            "target",  # ACL target attribute
        ]

        # Use provided output filenames or generic defaults
        self._output_files: dict[str, str] = output_files or {
            "schema": "schema.ldif",
            "hierarchy": "hierarchy.ldif",
            "users": "users.ldif",
            "groups": "groups.ldif",
            "acl": "acl.ldif",
            "rejected": "rejected.ldif",
        }

    @override
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute categorized migration pipeline.

        Returns:
            FlextResult containing categorized migration statistics

        Workflow:
            1. Parse all entries from input directory
            2. Categorize entries using rules
            3. Transform entries per category (quirks)
            4. Write to structured LDIF file output
            5. Return comprehensive statistics

        """
        # Step 1: Create output directory (base directory only)
        create_result = self._create_output_directory()
        if create_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"Failed to create output directory: {create_result.error}"
            )

        # Step 2: Parse all entries from input directory
        parse_result = self._parse_entries()
        if parse_result.is_failure:
            # Return empty result with error for empty input (not a failure case)
            if "No LDIF files found" in str(parse_result.error):
                result_dict: dict[str, object] = {
                    "total_entries": 0,
                    "categorized_counts": {},
                    "written_counts": {},
                    "rejection_count": 0,
                    "rejection_rate": 0.0,
                    "rejection_reasons": [],
                    "output_directories": {},
                    "source_server": self._source_server,
                    "target_server": self._target_server,
                }
                return FlextResult[dict[str, object]].ok(result_dict)
            return FlextResult[dict[str, object]].fail(
                f"Failed to parse entries: {parse_result.error}"
            )

        entries = parse_result.unwrap()

        # Step 3: Categorize entries using rules
        categorize_result = self._categorize_entries(entries)
        if categorize_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"Failed to categorize entries: {categorize_result.error}"
            )

        categorized = categorize_result.unwrap()

        # Step 4: Transform entries per category (quirks)
        transform_result = self._transform_categories(categorized)
        if transform_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"Failed to transform categories: {transform_result.error}"
            )

        transformed_categorized = transform_result.unwrap()

        # Step 5: Write to structured output directories
        write_result = self._write_categorized_output(transformed_categorized)
        if write_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"Failed to write output: {write_result.error}"
            )

        written_counts = write_result.unwrap()

        # Step 6: Generate comprehensive statistics
        statistics = self._generate_statistics(transformed_categorized, written_counts)

        return FlextResult[dict[str, object]].ok(statistics)

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
                        if attr_name.lower() == FlextLdifConstants.DictKeys.OBJECTCLASS:
                            # Add to objectClass list
                            entry_dict[FlextLdifConstants.DictKeys.OBJECTCLASS] = (
                                attr_values.values
                            )
                        # Add to attributes dict
                        # (multi-valued attributes stored as list or single value)
                        elif len(attr_values.values) == 1:
                            attrs_dict[attr_name] = attr_values.values[0]
                        else:
                            attrs_dict[attr_name] = attr_values.values

                    # Set attributes after building the dict
                    entry_dict[FlextLdifConstants.DictKeys.ATTRIBUTES] = attrs_dict

                    file_entries.append(entry_dict)

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
                self.logger.warning(
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

    def _matches_dn_pattern(self, dn: str, patterns: list[str]) -> bool:
        """Check if DN matches any of the provided regex patterns.

        Args:
            dn: Distinguished Name to check
            patterns: List of regex patterns to match against

        Returns:
            True if DN matches any pattern, False otherwise

        """
        for pattern in patterns:
            try:
                if re.search(pattern, dn, re.IGNORECASE):
                    return True
            except re.error:
                # Invalid regex pattern - skip
                continue

        return False

    def _has_acl_attributes(self, entry: dict[str, object]) -> bool:
        """Check if entry has ACL-related attributes.

        Args:
            entry: Entry dictionary to check

        Returns:
            True if entry has ACL attributes, False otherwise

        """
        acl_attributes = self._categorization_rules.get("acl_attributes", [])
        if not isinstance(acl_attributes, list):
            return False

        entry_attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
        if not isinstance(entry_attrs, dict):
            return False

        # Case-insensitive attribute lookup (LDIF RFC compliance)
        entry_attrs_lower = {k.lower(): v for k, v in entry_attrs.items()}
        acl_attributes_lower = [attr.lower() for attr in acl_attributes]

        return any(acl_attr in entry_attrs_lower for acl_attr in acl_attributes_lower)

    def _categorize_entry(self, entry: dict[str, object]) -> tuple[str, str | None]:
        """Categorize a single entry based on rules.

        Args:
            entry: Entry dictionary to categorize

        Returns:
            Tuple of (category, rejection_reason)
            Category is one of: schema, hierarchy, users, groups, acl, rejected
            Rejection reason is None unless category is 'rejected'

        Categorization Logic:
            0. Check for blocked objectClasses → rejected (ALGAR business rule)
            1. Check for schema entries (attributeTypes, objectClasses)
            2. Check for hierarchy objectClasses → hierarchy (BEFORE ACL!)
            3. Check for user objectClasses → users
            4. Check for group objectClasses → groups
            5. Check for ACL attributes → acl (AFTER hierarchy/users/groups)
            6. Otherwise → rejected

        CRITICAL: Hierarchy check has HIGHER priority than ACL check. This ensures
        Oracle containers (orclcontainer, orclprivilegegroup) with ACL attributes go
        to hierarchy file for proper parent-child sync order.

        """
        # Get entry DN and objectClasses with proper type narrowing
        dn_value = entry.get(FlextLdifConstants.DictKeys.DN, "")
        dn = dn_value if isinstance(dn_value, str) else ""

        object_classes = entry.get(FlextLdifConstants.DictKeys.OBJECTCLASS, [])
        if not isinstance(object_classes, list):
            object_classes = []

        # Convert objectClasses to lowercase for case-insensitive matching
        # LDAP objectClasses are case-insensitive per RFC 4512
        object_classes_lower = [
            oc.lower() if isinstance(oc, str) else oc for oc in object_classes
        ]

        # 0. Check for blocked objectClasses (ALGAR business rule)
        # Reject entries with OID-specific objectClasses that don't exist in OUD
        if self._schema_whitelist_rules:
            blocked_ocs = self._schema_whitelist_rules.get("blocked_objectclasses", [])
            if isinstance(blocked_ocs, list) and blocked_ocs:
                blocked_ocs_lower = {
                    oc.lower() for oc in blocked_ocs if isinstance(oc, str)
                }
                for obj_class_lower in object_classes_lower:
                    if obj_class_lower in blocked_ocs_lower:
                        msg_fmt = (
                            "Entry has blocked objectClass matching '{}' "
                            "(OID-specific, not in OUD schema)"
                        )
                        return ("rejected", msg_fmt.format(obj_class_lower))

        # 1. Schema entries (cn=schema, subschemasubentry, or has schema attributes)
        # Check DN patterns
        if "cn=schema" in dn.lower() or "subschemasubentry" in dn.lower():
            return ("schema", None)

        # Check for schema attributes (attributetypes, objectclasses as attributes)
        # Not DN-based schema entries
        entry_attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
        if isinstance(entry_attrs, dict):
            attrs_lower = {k.lower() for k in entry_attrs}
            if "attributetypes" in attrs_lower or "objectclasses" in attrs_lower:
                return ("schema", None)

        # Get categorization rules
        # Convert to lowercase for case-insensitive matching
        # LDAP objectClasses are case-insensitive per RFC 4512
        hierarchy_classes = self._categorization_rules.get(
            "hierarchy_objectclasses", []
        )
        user_classes = self._categorization_rules.get("user_objectclasses", [])
        group_classes = self._categorization_rules.get("group_objectclasses", [])
        user_dn_patterns = self._categorization_rules.get("user_dn_patterns", [])

        if not isinstance(hierarchy_classes, list):
            hierarchy_classes = []
        if not isinstance(user_classes, list):
            user_classes = []
        if not isinstance(group_classes, list):
            group_classes = []
        if not isinstance(user_dn_patterns, list):
            user_dn_patterns = []

        # Convert rule objectClasses to lowercase sets
        # for efficient case-insensitive lookup
        hierarchy_classes_lower = {
            oc.lower() for oc in hierarchy_classes if isinstance(oc, str)
        }
        user_classes_lower = {oc.lower() for oc in user_classes if isinstance(oc, str)}
        group_classes_lower = {
            oc.lower() for oc in group_classes if isinstance(oc, str)
        }

        # 2. Hierarchy entries
        # (organization, organizationalUnit, domain, Oracle containers)
        # CRITICAL: Check hierarchy BEFORE ACL so Oracle containers go to hierarchy file
        # Oracle containers (orclcontainer, orclprivilegegroup) are structural parents
        # They may have ACL attributes but must be synced before children
        for obj_class_lower in object_classes_lower:
            if obj_class_lower in hierarchy_classes_lower:
                return ("hierarchy", None)

        # 3. User entries (person, inetOrgPerson, etc.)
        for obj_class_lower in object_classes_lower:
            if obj_class_lower in user_classes_lower:
                # Validate with DN patterns if provided
                if user_dn_patterns and not self._matches_dn_pattern(
                    dn, user_dn_patterns
                ):
                    return (
                        "rejected",
                        f"User entry DN does not match expected patterns: {dn}",
                    )
                return ("users", None)

        # 4. Group entries (groupOfNames, etc.)
        for obj_class_lower in object_classes_lower:
            if obj_class_lower in group_classes_lower:
                return ("groups", None)

        # 5. ACL entries (have ACL attributes but no hierarchy/user/group objectClasses)
        # NOTE: ACL check moved AFTER hierarchy/users/groups
        # This gives priority to structural entries
        if self._has_acl_attributes(entry):
            return ("acl", None)

        # 6. Rejected entries (no matching category)
        # Use original objectClasses (not lowercase) for error message clarity
        return ("rejected", f"No matching category for objectClasses: {object_classes}")

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
                self.logger.warning(
                    f"Entry categorization: {len(categorization_failures)} entries "
                    f"failed categorization"
                )

            # Build categorized dictionary from results
            categorized: dict[str, list[dict[str, object]]] = {
                "schema": [],
                "hierarchy": [],
                "users": [],
                "groups": [],
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
                has_acl_metadata = result_item.get("has_acl_metadata", False)

                # Type narrow category
                if not isinstance(category, str) or category not in categorized:
                    continue

                # Add entry to appropriate category
                if isinstance(processed_entry, dict):
                    categorized[category].append(processed_entry)

                    # Track rejection reason if present
                    if isinstance(rejection_reason, str) and rejection_reason:
                        dn_value = processed_entry.get(FlextLdifConstants.DictKeys.DN)
                        if isinstance(dn_value, str):
                            rejection_reasons_map[dn_value] = rejection_reason

                # If entry has ACL metadata, create separate ACL entry
                if has_acl_metadata and isinstance(processed_entry, dict):
                    acl_metadata = result_item.get("acl_metadata")
                    if isinstance(acl_metadata, dict):
                        acl_entry = {
                            FlextLdifConstants.DictKeys.DN: processed_entry.get(
                                FlextLdifConstants.DictKeys.DN
                            ),
                            FlextLdifConstants.DictKeys.ATTRIBUTES: acl_metadata,
                            "_from_metadata": True,
                        }
                        categorized["acl"].append(acl_entry)

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
                    self.logger.warning(
                        f"Rejection reason injection: {len(injection_failures)} "
                        f"entries failed injection"
                    )

                # Replace rejected entries with injected versions
                categorized["rejected"] = injected_entries

            return FlextResult[dict[str, list[dict[str, object]]]].ok(categorized)

        except Exception as e:
            return FlextResult[dict[str, list[dict[str, object]]]].fail(
                f"Entry categorization failed: {e}"
            )

    def _filter_forbidden_attributes(
        self, attributes: dict[str, object]
    ) -> dict[str, object]:
        """Filter out forbidden attributes from entry.

        STRATEGY PATTERN: Business rules from client application (e.g., algar-oud-mig)
        determine which attributes to filter. This method provides generic filtering.

        Args:
            attributes: Dictionary of attributes to filter

        Returns:
            Filtered attributes dictionary without forbidden attributes

        Example forbidden_attributes:
            ['authPassword', 'authpassword;orclcommonpwd', 'authpassword;oid']

        """
        if not self._forbidden_attributes:
            return attributes

        # Create case-insensitive set of forbidden attributes
        forbidden_lower = {attr.lower() for attr in self._forbidden_attributes}

        # Filter attributes
        # Check both exact match and case-insensitive match
        filtered: dict[str, object] = {
            attr_name: attr_value
            for attr_name, attr_value in attributes.items()
            if attr_name.lower() not in forbidden_lower
        }

        return filtered

    class _AclTransformationChain:
        """ACL transformation helper methods using railway pattern."""

        @staticmethod
        def transform_acl_entry(
            entry: dict[str, object],
            oid_acl_quirk: FlextLdifQuirksServersOid.AclQuirk,
            oud_acl_quirk: FlextLdifQuirksServersOud.AclQuirk,
        ) -> FlextResult[dict[str, object]]:
            """Transform single ACL entry from OID to OUD format.

            Args:
                entry: ACL entry dictionary to transform
                oid_acl_quirk: OID ACL quirk for parsing
                oud_acl_quirk: OUD ACL quirk for writing

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

                new_attributes: dict[str, object] = {}

                for attr_name, attr_value in attributes.items():
                    if attr_name.lower() in {"orclaci", "orclentrylevelaci"}:
                        values_to_process = (
                            attr_value if isinstance(attr_value, list) else [attr_value]
                        )

                        transformed_acis = []
                        for single_value in values_to_process:
                            acl_line = f"{attr_name}: {single_value}"
                            parse_result = oid_acl_quirk.parse_acl(acl_line)

                            if parse_result.is_failure:
                                continue

                            acl_data = parse_result.unwrap()

                            rfc_result = oid_acl_quirk.convert_acl_to_rfc(acl_data)
                            if rfc_result.is_failure:
                                continue

                            rfc_data = rfc_result.unwrap()

                            oud_result = oud_acl_quirk.convert_acl_from_rfc(rfc_data)
                            if oud_result.is_failure:
                                continue

                            oud_data = oud_result.unwrap()

                            write_result = oud_acl_quirk.write_acl_to_rfc(oud_data)
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

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"ACL transformation failed: {e}"
                )

    class _ForbiddenAttributesFilteringChain:
        """Forbidden attributes filtering helper methods using railway pattern."""

        @staticmethod
        def filter_entry(
            entry: dict[str, object],
            pipeline: object,  # FlextLdifCategorizedMigrationPipeline
        ) -> FlextResult[dict[str, object]]:
            """Filter forbidden attributes from single entry.

            Args:
                entry: Entry dictionary to filter
                pipeline: Reference to pipeline instance for forbidden_attributes access

            Returns:
                FlextResult containing filtered entry

            """
            try:
                # Type narrow pipeline to access forbidden_attributes
                if not hasattr(pipeline, "_filter_forbidden_attributes"):
                    return FlextResult[dict[str, object]].ok(entry)

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

                # Filter forbidden attributes using pipeline method
                filter_func = getattr(pipeline, "_filter_forbidden_attributes")
                filtered_attrs = filter_func(attrs)

                # Update entry with filtered attributes
                filtered_entry[FlextLdifConstants.DictKeys.ATTRIBUTES] = filtered_attrs

                return FlextResult[dict[str, object]].ok(filtered_entry)

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"Forbidden attributes filtering failed: {e}"
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

                # STRATEGY PATTERN: Check if entry has ACL attributes in metadata
                # (set by OID quirk during RFC conversion)
                acl_attrs = entry.get("_acl_attributes")
                processed_entry = entry
                has_acl_metadata = False
                acl_metadata: dict[str, object] = {}

                if acl_attrs and isinstance(acl_attrs, dict):
                    # Mark that entry has ACL metadata
                    has_acl_metadata = True
                    acl_metadata = acl_attrs.copy()

                    # Remove ACL metadata from original entry (already extracted)
                    processed_entry = entry.copy()
                    processed_entry.pop("_acl_attributes", None)

                # Categorize the entry
                categorize_func = getattr(pipeline, "_categorize_entry")
                category, rejection_reason = categorize_func(processed_entry)

                # Type narrow category and rejection_reason
                if not isinstance(category, str):
                    return FlextResult[dict[str, object]].fail(
                        f"Invalid category type: {type(category)}"
                    )

                # Build result dictionary with all tracking information
                result_dict: dict[str, object] = {
                    "category": category,
                    "entry": processed_entry,
                    "rejection_reason": rejection_reason,
                    "has_acl_metadata": has_acl_metadata,
                }

                if has_acl_metadata:
                    result_dict["acl_metadata"] = acl_metadata

                return FlextResult[dict[str, object]].ok(result_dict)

            except Exception as e:
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

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"Rejection reason injection failed: {e}"
                )

    class _DnNormalizationChain:
        """DN reference normalization helper methods using railway pattern."""

        @staticmethod
        def normalize_dn_references(
            entry: dict[str, object],
            dn_map: dict[str, str],
            ref_attrs_lower: set[str],
            pipeline: object,  # FlextLdifCategorizedMigrationPipeline
        ) -> FlextResult[dict[str, object]]:
            """Normalize DN references in single entry with dual normalization.

            Performs two sequential normalizations:
            1. Normalize DN-valued attributes using dn_map
            2. Normalize DNs embedded in ACI attribute strings

            Args:
                entry: Entry dictionary to normalize
                dn_map: Map of normalized DN values for lookup
                ref_attrs_lower: Set of lowercase DN reference attribute names
                pipeline: Reference to pipeline instance for method access

            Returns:
                FlextResult containing normalized entry

            """
            try:
                # Type narrow entry to dict
                if not isinstance(entry, dict):
                    return FlextResult[dict[str, object]].ok(entry)

                # Step 1: Normalize DN-valued attributes
                normalize_dn_func = getattr(
                    pipeline, "_normalize_dn_references_for_entry", None
                )
                if normalize_dn_func:
                    normalized_entry = normalize_dn_func(entry, dn_map, ref_attrs_lower)
                else:
                    normalized_entry = entry

                # Step 2: Normalize DNs inside ACI strings
                normalize_aci_func = getattr(
                    pipeline, "_normalize_aci_dn_references", None
                )
                if normalize_aci_func:
                    normalized_entry = normalize_aci_func(normalized_entry, dn_map)

                return FlextResult[dict[str, object]].ok(normalized_entry)

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"DN reference normalization failed: {e}"
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
            # Initialize source and target quirks
            oid_acl_quirk = FlextLdifQuirksServersOid.AclQuirk()
            oud_acl_quirk = FlextLdifQuirksServersOud.AclQuirk()

            # Transform ACL entries (category "acl") using batch processing
            # Delegates to helper method for railway-oriented error handling
            acl_entries = categorized.get("acl", [])
            if acl_entries:
                # Define processor function for batch_process composition
                def transform_acl_entry_processor(
                    entry: dict[str, object],
                ) -> FlextResult[dict[str, object]]:
                    """Process single ACL entry with railway pattern."""
                    return self._AclTransformationChain.transform_acl_entry(
                        entry, oid_acl_quirk, oud_acl_quirk
                    )

                # Use batch_process for functional composition
                # Returns (successes, failures) tuple for statistics tracking
                transformed_acl, acl_failures = FlextResult.batch_process(
                    acl_entries, transform_acl_entry_processor
                )

                # Log failures if any (non-fatal, continue processing)
                if acl_failures:
                    self.logger.warning(
                        f"ACL transformation: {len(acl_failures)} entries "
                        f"failed transformation"
                    )

                # Replace ACL entries with successfully transformed versions
                categorized["acl"] = transformed_acl

            # Step 2: Filter forbidden attributes from all categories using batch_process
            # STRATEGY PATTERN: Business rules from client application
            if self._forbidden_attributes:
                # Define processor function for filtering single entry
                def filter_entry_processor(
                    entry: dict[str, object],
                ) -> FlextResult[dict[str, object]]:
                    """Filter forbidden attributes from single entry."""
                    return self._ForbiddenAttributesFilteringChain.filter_entry(
                        entry, self
                    )

                # Apply filtering to each category using batch_process
                for category, entries in categorized.items():
                    # Use batch_process for functional composition
                    # Returns (successes, failures) tuple for statistics tracking
                    filtered_entries, filter_failures = FlextResult.batch_process(
                        entries, filter_entry_processor
                    )

                    # Log failures if any (non-fatal, continue processing)
                    if filter_failures:
                        self.logger.warning(
                            f"Forbidden attributes filtering for '{category}': "
                            f"{len(filter_failures)} entries failed filtering"
                        )

                    # Replace entries with successfully filtered versions
                    categorized[category] = filtered_entries

            # Step 3: Normalize DN references (groups and ACLs) using batch_process
            try:
                dn_map = self._build_canonical_dn_map(categorized)
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
                    return self._DnNormalizationChain.normalize_dn_references(
                        entry, dn_map, ref_attrs_lower, self
                    )

                # Apply DN normalization to each category using batch_process
                for category, entries in categorized.items():
                    # Skip schema entries
                    if category == "schema":
                        continue

                    # Use batch_process for functional composition
                    # Returns (successes, failures) tuple for statistics tracking
                    normalized_entries, normalization_failures = (
                        FlextResult.batch_process(entries, normalize_dn_processor)
                    )

                    # Log failures if any (non-fatal, continue processing)
                    if normalization_failures:
                        self.logger.warning(
                            f"DN reference normalization for '{category}': "
                            f"{len(normalization_failures)} entries failed normalization"
                        )

                    # Replace entries with successfully normalized versions
                    categorized[category] = normalized_entries

            except (
                Exception
            ) as e:  # Safety net: do not fail migration if normalization fails
                self.logger.warning(f"DN reference normalization skipped: {e}")

            return FlextResult[dict[str, list[dict[str, object]]]].ok(categorized)

        except Exception as e:
            return FlextResult[dict[str, list[dict[str, object]]]].fail(
                f"ACL transformation failed: {e}"
            )

    def _build_canonical_dn_map(
        self, categorized: dict[str, list[dict[str, object]]]
    ) -> dict[str, str]:
        """Build a mapping of lowercase(cleaned DN) -> canonical cleaned DN.

        Uses DnService.clean_dn to normalize formatting and ensures
        case-consistent canonical values based on parsed entries.
        """
        dn_map: dict[str, str] = {}
        for entries in categorized.values():
            for entry in entries:
                if isinstance(entry, dict):
                    dn_value = entry.get(FlextLdifConstants.DictKeys.DN)
                    if isinstance(dn_value, str) and dn_value:
                        cleaned = DnService.clean_dn(dn_value)
                        if cleaned:
                            dn_map[cleaned.lower()] = cleaned
        return dn_map

    def _normalize_dn_value(self, value: str, dn_map: dict[str, str]) -> str:
        """Normalize a single DN value using canonical map, fallback to cleaned DN."""
        cleaned = DnService.clean_dn(value)
        return dn_map.get(cleaned.lower(), cleaned)

    def _normalize_dn_references_for_entry(
        self,
        entry: dict[str, object],
        dn_map: dict[str, str],
        ref_attrs_lower: set[str],
    ) -> dict[str, object]:
        """Normalize DN-valued attributes in an entry according to dn_map.

        Handles both str and list[str] attribute values.
        """
        normalized = entry.copy()
        attrs = normalized.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
        if not isinstance(attrs, dict):
            return normalized

        new_attrs: dict[str, object] = {}
        for attr_name, attr_value in attrs.items():
            if attr_name.lower() in ref_attrs_lower:
                if isinstance(attr_value, list):
                    new_attrs[attr_name] = [
                        self._normalize_dn_value(v, dn_map) if isinstance(v, str) else v
                        for v in attr_value
                    ]
                elif isinstance(attr_value, str):
                    new_attrs[attr_name] = self._normalize_dn_value(attr_value, dn_map)
                else:
                    new_attrs[attr_name] = attr_value
            else:
                new_attrs[attr_name] = attr_value

        normalized[FlextLdifConstants.DictKeys.ATTRIBUTES] = new_attrs
        return normalized

    def _normalize_aci_dn_references(
        self, entry: dict[str, object], dn_map: dict[str, str]
    ) -> dict[str, object]:
        """Normalize DNs embedded in ACI attribute strings using dn_map.

        Attempts to detect DN substrings in common OUD ACI patterns and
        replace them with canonical DNs.
        """
        try:
            attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
            if not isinstance(attrs, dict):
                return entry

            def normalize_in_text(text: str) -> str:
                # Fast path: replace occurrences after ldap:/// and within quotes
                # Identify candidate DN segments and canonicalize

                def repl_ldap(m: re.Match[str]) -> str:
                    dn_part = m.group(1)
                    norm = self._normalize_dn_value(dn_part, dn_map)
                    return f"ldap:///{norm}"

                text2 = re.sub(r"ldap:///([^\"]+?)", repl_ldap, text)

                # Also handle bare quoted DN-like sequences (best-effort)
                def repl_quoted(m: re.Match[str]) -> str:
                    dn_part = m.group(1)
                    norm = self._normalize_dn_value(dn_part, dn_map)
                    return f'"{norm}"'

                return re.sub(
                    r'"((?:[a-zA-Z]+=[^,\";\)]+)(?:,[a-zA-Z]+=[^,\";\)]+)*)"',
                    repl_quoted,
                    text2,
                )

            aci_value = attrs.get("aci")
            if isinstance(aci_value, list):
                attrs["aci"] = [
                    normalize_in_text(v) if isinstance(v, str) else v for v in aci_value
                ]
            elif isinstance(aci_value, str):
                attrs["aci"] = normalize_in_text(aci_value)

            entry_out = entry.copy()
            entry_out[FlextLdifConstants.DictKeys.ATTRIBUTES] = attrs
            return entry_out
        except Exception:
            return entry

    def _process_schema_entries(
        self, entries: list[dict[str, object]]
    ) -> list[dict[str, object]]:
        """Process schema entries: apply whitelist filtering and sort by OID.

        RFC-COMPLIANT: Works with RFC 4512 schema format (attributetypes/objectclasses).
        Applies OID pattern matching from whitelist rules.

        Args:
            entries: List of RFC format schema entries

        Returns:
            Filtered and sorted schema entries

        """
        if not entries or not self._schema_whitelist_rules:
            return entries

        # Get whitelist rules for OID patterns
        allowed_attr_oids = self._schema_whitelist_rules.get(
            "allowed_attribute_oids", []
        )
        allowed_obj_oids = self._schema_whitelist_rules.get(
            "allowed_objectclass_oids", []
        )

        if not isinstance(allowed_attr_oids, list):
            allowed_attr_oids = []
        if not isinstance(allowed_obj_oids, list):
            allowed_obj_oids = []

        processed_entries = []

        for entry in entries:
            attributes = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
            if not isinstance(attributes, dict):
                processed_entries.append(entry)
                continue

            # Get attributetypes and objectclasses
            attr_types = attributes.get("attributetypes", [])
            obj_classes = attributes.get("objectclasses", [])

            if not isinstance(attr_types, list):
                attr_types = [attr_types] if attr_types else []
            if not isinstance(obj_classes, list):
                obj_classes = [obj_classes] if obj_classes else []

            def extract_oid(schema_line: str) -> str:
                """Extract OID from RFC 4512 schema definition."""
                match = re.match(r"\(\s*([0-9.]+)", str(schema_line))
                return match.group(1) if match else ""

            def matches_pattern(oid: str, patterns: list[str]) -> bool:
                """Check if OID matches any whitelist pattern (supports wildcards)."""
                if not patterns:
                    return True  # No restrictions

                for pattern in patterns:
                    pattern_str = str(pattern).replace("*", ".*")
                    if re.match(f"^{pattern_str}$", oid):
                        return True
                return False

            # Filter and sort attributetypes
            filtered_attr_types = [
                line
                for line in attr_types
                if matches_pattern(extract_oid(line), allowed_attr_oids)
            ]
            sorted_attr_types = sorted(filtered_attr_types, key=extract_oid)

            # Filter and sort objectclasses
            filtered_obj_classes = [
                line
                for line in obj_classes
                if matches_pattern(extract_oid(line), allowed_obj_oids)
            ]
            sorted_obj_classes = sorted(filtered_obj_classes, key=extract_oid)

            # Rebuild entry with filtered and sorted schema
            new_attributes = {}
            if sorted_attr_types:
                new_attributes["attributetypes"] = sorted_attr_types
            if sorted_obj_classes:
                new_attributes["objectclasses"] = sorted_obj_classes

            # Keep other attributes unchanged
            new_attributes.update({
                key: value
                for key, value in attributes.items()
                if key not in {"attributetypes", "objectclasses"}
            })

            processed_entry = entry.copy()
            processed_entry[FlextLdifConstants.DictKeys.ATTRIBUTES] = new_attributes
            processed_entries.append(processed_entry)

        return processed_entries

    def _create_oud_schema_entry(
        self, processed_entries: list[dict[str, object]]
    ) -> list[dict[str, object]]:
        """Create OUD-compatible schema entry from processed schema entries.

        OUD requires schema in a specific format:
        - dn: cn=schema
        - changetype: add
        - objectclass: top, ldapSubentry, subschema
        - attributetypes: (sorted by OID)
        - objectclasses: (sorted by OID)

        Args:
            processed_entries: List of processed schema entries

        Returns:
            List containing single OUD-compatible schema entry

        """
        if not processed_entries:
            return []

        # Collect all attributetypes and objectclasses from processed entries
        all_attributetypes: list[str] = []
        all_objectclasses: list[str] = []

        for entry in processed_entries:
            attributes = entry.get("attributes", {})
            if not isinstance(attributes, dict):
                continue

            # Get attributetypes
            attr_types = attributes.get("attributetypes", [])
            if isinstance(attr_types, list):
                all_attributetypes.extend(attr_types)
            elif attr_types:
                all_attributetypes.append(str(attr_types))

            # Get objectclasses
            obj_classes = attributes.get("objectclasses", [])
            if isinstance(obj_classes, list):
                all_objectclasses.extend(obj_classes)
            elif obj_classes:
                all_objectclasses.append(str(obj_classes))

        # Remove duplicates while preserving order
        seen_attributetypes = set()
        unique_attributetypes = []
        for attr_type in all_attributetypes:
            if attr_type not in seen_attributetypes:
                unique_attributetypes.append(attr_type)
                seen_attributetypes.add(attr_type)

        seen_objectclasses = set()
        unique_objectclasses = []
        for obj_class in all_objectclasses:
            if obj_class not in seen_objectclasses:
                unique_objectclasses.append(obj_class)
                seen_objectclasses.add(obj_class)

        # Sort by OID
        def extract_oid(schema_line: str) -> str:
            """Extract OID from RFC 4512 schema definition."""
            match = re.match(r"\(\s*([0-9.]+)", str(schema_line))
            return match.group(1) if match else ""

        sorted_attributetypes = sorted(unique_attributetypes, key=extract_oid)
        sorted_objectclasses = sorted(unique_objectclasses, key=extract_oid)

        # Create OUD schema entry
        attributes_dict: dict[str, list[str]] = {
            "changetype": ["add"],
            "objectClass": ["top", "ldapSubentry", "subschema"],
        }

        # Add sorted attributetypes if any
        if sorted_attributetypes:
            attributes_dict["attributetypes"] = sorted_attributetypes

        # Add sorted objectclasses if any
        if sorted_objectclasses:
            attributes_dict["objectclasses"] = sorted_objectclasses

        schema_entry: dict[str, object] = {
            "dn": "cn=schema",
            "attributes": attributes_dict,
        }

        return [schema_entry]

    def _sort_entries_by_hierarchy_and_name(
        self, entries: list[dict[str, object]]
    ) -> list[dict[str, object]]:
        """Sort entries by DN hierarchy depth, then case-insensitive DN.

        Ordering rules:
        - First key: DN depth (fewer RDN components first)
        - Second key: Case-insensitive DN string for stable ordering

        This ensures deterministic ordering across 01-05 categories.
        """

        def sort_key(entry: dict[str, object]) -> tuple[int, str]:
            dn_value = entry.get(FlextLdifConstants.DictKeys.DN, "")
            dn = dn_value if isinstance(dn_value, str) else ""
            dn_clean = DnService.clean_dn(dn)
            depth = dn_clean.count(",") + (1 if dn_clean else 0)
            return (depth, dn_clean.lower())

        # Filter only entries with a DN string to avoid exceptions during sort
        sortable = [
            e
            for e in entries
            if isinstance(e.get(FlextLdifConstants.DictKeys.DN, ""), str)
        ]
        nonsortable = [
            e
            for e in entries
            if not isinstance(e.get(FlextLdifConstants.DictKeys.DN, ""), str)
        ]

        # Sort sortable entries and keep any non-sortable at the end in original order
        return sorted(sortable, key=sort_key) + nonsortable

    def _write_category_file(
        self, category: str, entries: list[dict[str, object]], category_filename: str
    ) -> FlextResult[int]:
        """Write entries for a single category to LDIF file.

        Args:
            category: Category name (schema, hierarchy, users, groups, acl, rejected)
            entries: List of entries to write
            category_filename: LDIF filename (e.g., "00-schema.ldif")

        Returns:
            FlextResult containing count of entries written

        Note:
            For rejected entries, rejection reasons are written as LDIF comments
            (lines starting with #) above the entry, not as attributes.
            For schema entries, applies whitelist filtering and OID sorting.

        """
        if not entries:
            return FlextResult[int].ok(0)

        try:
            # Special handling for schema category
            if category == "schema" and self._schema_whitelist_rules:
                # Apply whitelist filtering and sorting to schema entries
                processed_entries = self._process_schema_entries(entries)
                if processed_entries:
                    # Create OUD-compatible schema entry format
                    entries = self._create_oud_schema_entry(processed_entries)
                else:
                    entries = []
            else:
                # Apply hierarchy + name sorting for all non-schema categories (01-05)
                entries = self._sort_entries_by_hierarchy_and_name(entries)
            # Write directly to output directory (not subdirectory)
            output_file = self._output_dir / category_filename

            # Generate LDIF content
            ldif_content: list[str] = []
            is_rejected_category = category == "rejected"

            for entry in entries:
                # Get DN with proper type narrowing
                dn_value = entry.get(FlextLdifConstants.DictKeys.DN, "")
                if isinstance(dn_value, str) and dn_value:
                    dn = dn_value
                else:
                    continue

                # For rejected entries, write rejection reason as LDIF comment
                if is_rejected_category:
                    attributes = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
                    if isinstance(attributes, dict) and "rejectionReason" in attributes:
                        rejection_reason = attributes.get("rejectionReason", "")
                        if isinstance(rejection_reason, str):
                            # Write rejection reason as LDIF comment
                            ldif_content.append(f"# Rejection: {rejection_reason}")

                # Write DN
                ldif_content.append(f"dn: {dn}")

                # Write objectClasses
                object_classes = entry.get(FlextLdifConstants.DictKeys.OBJECTCLASS, [])
                if isinstance(object_classes, list):
                    ldif_content.extend(
                        f"objectClass: {obj_class}" for obj_class in object_classes
                    )

                # Write attributes (exclude rejectionReason for rejected entries)
                attributes = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
                if isinstance(attributes, dict):
                    for attr_name, attr_value in attributes.items():
                        # Skip rejectionReason attribute for rejected entries
                        # (already written as comment)
                        if is_rejected_category and attr_name == "rejectionReason":
                            continue

                        # Handle multi-valued attributes (lists)
                        if isinstance(attr_value, list):
                            # Write each value on its own line
                            ldif_content.extend(
                                f"{attr_name}: {value}" for value in attr_value
                            )
                        else:
                            # Single value
                            ldif_content.append(f"{attr_name}: {attr_value}")

                # Add blank line between entries
                ldif_content.append("")

            # Write to file
            with output_file.open("w", encoding="utf-8") as f:
                f.write("\n".join(ldif_content))

            return FlextResult[int].ok(len(entries))

        except (OSError, UnicodeEncodeError) as e:
            return FlextResult[int].fail(f"Failed to write {category} file: {e}")

    def _write_categorized_output(
        self, categorized: dict[str, list[dict[str, object]]]
    ) -> FlextResult[dict[str, int]]:
        """Write categorized entries to structured LDIF files.

        Args:
            categorized: Dictionary mapping category to entry list

        Returns:
            FlextResult containing dict[str, object] of category to count written

        """
        written_counts: dict[str, int] = {}

        # Write each category to its LDIF file (using provided output_files mapping)
        for category, entries in categorized.items():
            filename_obj = self._output_files.get(category, f"{category}.ldif")
            category_filename = (
                filename_obj if isinstance(filename_obj, str) else f"{category}.ldif"
            )

            write_result = self._write_category_file(
                category, entries, category_filename
            )

            if write_result.is_failure:
                return FlextResult[dict[str, int]].fail(
                    f"Failed to write {category}: {write_result.error}"
                )

            written_counts[category] = write_result.unwrap()

        return FlextResult[dict[str, int]].ok(written_counts)

    def _generate_statistics(
        self,
        categorized: dict[str, list[dict[str, object]]],
        written_counts: dict[str, int],
    ) -> dict[str, object]:
        """Generate comprehensive statistics for categorized migration.

        Args:
            categorized: Dictionary mapping category to entry list
            written_counts: Dictionary mapping category to count written

        Returns:
            Statistics dictionary with counts, rejection info, and metadata

        """
        # Calculate total entries
        total_entries = sum(len(entries) for entries in categorized.values())

        # Build categorized counts
        categorized_counts: dict[str, object] = {}
        for category, entries in categorized.items():
            categorized_counts[category] = len(entries)

        # Count rejections and gather reasons
        rejected_entries = categorized.get("rejected", [])
        rejection_count = len(rejected_entries)
        rejection_reasons: list[str] = []

        for entry in rejected_entries:
            attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
            if isinstance(attrs, dict) and "rejectionReason" in attrs:
                reason_value = attrs["rejectionReason"]
                if (
                    isinstance(reason_value, str)
                    and reason_value not in rejection_reasons
                ):
                    rejection_reasons.append(reason_value)

        # Calculate rejection rate
        rejection_rate = rejection_count / total_entries if total_entries > 0 else 0.0

        # Build output files info (LDIF files, not directories)
        output_files: dict[str, object] = {}
        for category in written_counts:
            filename_obj = self._output_files.get(category, f"{category}.ldif")
            category_filename = (
                filename_obj if isinstance(filename_obj, str) else f"{category}.ldif"
            )
            output_path = self._output_dir / category_filename
            output_files[category] = str(output_path)

        # Build comprehensive statistics
        stats: dict[str, object] = {
            "total_entries": total_entries,
            "categorized_counts": categorized_counts,
            "written_counts": written_counts,
            "rejection_count": rejection_count,
            "rejection_rate": rejection_rate,
            "rejection_reasons": rejection_reasons,
            "output_files": output_files,
            "source_server": self._source_server,
            "target_server": self._target_server,
            "input_dir": str(self._input_dir),
            "output_dir": str(self._output_dir),
        }

        return stats


__all__ = ["FlextLdifCategorizedMigrationPipeline"]
