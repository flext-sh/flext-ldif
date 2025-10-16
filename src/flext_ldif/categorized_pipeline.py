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

from flext_core import FlextResult, FlextService, FlextTypes

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.entry_quirks import FlextLdifEntryQuirks
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.quirks.servers import (
    FlextLdifQuirksServersOid,
    FlextLdifQuirksServersOud,
)
from flext_ldif.rfc.rfc_ldif_parser import FlextLdifRfcLdifParser
from flext_ldif.services.dn_service import DnService


class FlextLdifCategorizedMigrationPipeline(FlextService[FlextTypes.Dict]):
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
    - 00-schema.ldif: Schema definitions (attributeTypes, objectClasses) - loaded first
    - 01-hierarchy.ldif: Organizational structure (organization, ou, domain) - directory foundation
    - 02-users.ldif: User entries (person, inetOrgPerson, organizationalPerson) - user accounts
    - 03-groups.ldif: Group entries (groupOfNames, groupOfUniqueNames) - group memberships
    - 04-acl.ldif: Access Control Lists (entries with aci attributes) - security policies
    - 05-rejected.ldif: Rejected entries with detailed reasons - review and remediation

    Each output file contains properly formatted LDIF entries with server-specific
    transformations applied according to the target server's quirks.
    """

    def __init__(
        self,
        input_dir: str | Path,
        output_dir: str | Path,
        categorization_rules: dict[str, list[str]],
        parser_quirk: object,
        writer_quirk: object,
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
    def execute(self) -> FlextResult[FlextTypes.Dict]:
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
            return FlextResult[FlextTypes.Dict].fail(
                f"Failed to create output directory: {create_result.error}"
            )

        # Step 2: Parse all entries from input directory
        parse_result = self._parse_entries()
        if parse_result.is_failure:
            # Return empty result with error for empty input (not a failure case)
            if "No LDIF files found" in str(parse_result.error):
                result_dict: FlextTypes.Dict = {
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
                return FlextResult[FlextTypes.Dict].ok(result_dict)
            return FlextResult[FlextTypes.Dict].fail(
                f"Failed to parse entries: {parse_result.error}"
            )

        entries = parse_result.unwrap()

        # Step 3: Categorize entries using rules
        categorize_result = self._categorize_entries(entries)
        if categorize_result.is_failure:
            return FlextResult[FlextTypes.Dict].fail(
                f"Failed to categorize entries: {categorize_result.error}"
            )

        categorized = categorize_result.unwrap()

        # Step 4: Transform entries per category (quirks)
        transform_result = self._transform_categories(categorized)
        if transform_result.is_failure:
            return FlextResult[FlextTypes.Dict].fail(
                f"Failed to transform categories: {transform_result.error}"
            )

        transformed_categorized = transform_result.unwrap()

        # Step 5: Write to structured output directories
        write_result = self._write_categorized_output(transformed_categorized)
        if write_result.is_failure:
            return FlextResult[FlextTypes.Dict].fail(
                f"Failed to write output: {write_result.error}"
            )

        written_counts = write_result.unwrap()

        # Step 6: Generate comprehensive statistics
        statistics = self._generate_statistics(transformed_categorized, written_counts)

        return FlextResult[FlextTypes.Dict].ok(statistics)

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

    def _parse_entries(self) -> FlextResult[list[FlextTypes.Dict]]:
        """Parse all LDIF entries from input directory using RFC parser.

        Returns:
            FlextResult containing list of parsed entry dictionaries

        Note:
            Uses FlextLdifRfcLdifParser for RFC 2849 compliant parsing.
            Replaces 116 lines of custom parsing with battle-tested ldif3 library.

        """
        entries: list[FlextTypes.Dict] = []

        try:
            # Get all LDIF files from input directory
            if not self._input_dir.exists():
                return FlextResult[list[FlextTypes.Dict]].fail(
                    f"Input directory does not exist: {self._input_dir}"
                )

            # Apply input file filter if provided (generic feature for selective processing)
            if self._input_files:
                # Process only specified files
                ldif_files = [
                    self._input_dir / filename
                    for filename in self._input_files
                    if (self._input_dir / filename).exists()
                ]
                if not ldif_files:
                    return FlextResult[list[FlextTypes.Dict]].fail(
                        f"None of the specified input files found: {self._input_files}"
                    )
            else:
                # Process all LDIF files (default behavior)
                ldif_files = list(self._input_dir.glob("*.ldif"))
                if not ldif_files:
                    return FlextResult[list[FlextTypes.Dict]].fail(
                        "No LDIF files found in input directory"
                    )

            # Initialize quirk registry for RFC parser
            quirk_registry = FlextLdifQuirksRegistry()

            # Parse each LDIF file using RFC parser
            for ldif_file in ldif_files:
                # Use RFC parser for standards-compliant parsing
                parser_params: FlextTypes.Dict = {
                    "file_path": str(ldif_file),
                    "parse_changes": False,
                    "encoding": "utf-8",
                }
                parser = FlextLdifRfcLdifParser(
                    params=parser_params, quirk_registry=quirk_registry
                )
                parse_result = parser.execute()

                if parse_result.is_failure:
                    return FlextResult[list[FlextTypes.Dict]].fail(
                        f"Failed to parse {ldif_file}: {parse_result.error}"
                    )

                # Convert Entry models to dictionaries
                parsed_data_raw = parse_result.unwrap()
                # Type narrow parsed_data to access entries list
                entries_raw = parsed_data_raw.get("entries", [])
                if not isinstance(entries_raw, list):
                    continue

                for entry_model in entries_raw:
                    # Extract data from Entry model
                    entry_dict: FlextTypes.Dict = {
                        FlextLdifConstants.DictKeys.DN: entry_model.dn.value,  # Get string value from DistinguishedName
                        FlextLdifConstants.DictKeys.ATTRIBUTES: {},
                        FlextLdifConstants.DictKeys.OBJECTCLASS: [],
                    }

                    # Type narrow attributes dict
                    attrs_dict: FlextTypes.Dict = {}

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
                        # Add to attributes dict (multi-valued attributes stored as list or single value)
                        elif len(attr_values.values) == 1:
                            attrs_dict[attr_name] = attr_values.values[0]
                        else:
                            attrs_dict[attr_name] = attr_values.values

                    # Set attributes after building the dict
                    entry_dict[FlextLdifConstants.DictKeys.ATTRIBUTES] = attrs_dict

                    entries.append(entry_dict)

            return FlextResult[list[FlextTypes.Dict]].ok(entries)

        except (OSError, UnicodeDecodeError) as e:
            return FlextResult[list[FlextTypes.Dict]].fail(
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

    def _has_acl_attributes(self, entry: FlextTypes.Dict) -> bool:
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

    def _categorize_entry(self, entry: FlextTypes.Dict) -> tuple[str, str | None]:
        """Categorize a single entry based on rules.

        Args:
            entry: Entry dictionary to categorize

        Returns:
            Tuple of (category, rejection_reason)
            Category is one of: schema, hierarchy, users, groups, acl, rejected
            Rejection reason is None unless category is 'rejected'

        Categorization Logic:
            0. Check for blocked objectClasses → rejected (client-a business rule)
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

        # 0. Check for blocked objectClasses (client-a business rule)
        # Reject entries with OID-specific objectClasses that don't exist in OUD
        if self._schema_whitelist_rules:
            blocked_ocs = self._schema_whitelist_rules.get("blocked_objectclasses", [])
            if isinstance(blocked_ocs, list) and blocked_ocs:
                blocked_ocs_lower = {
                    oc.lower() for oc in blocked_ocs if isinstance(oc, str)
                }
                for obj_class_lower in object_classes_lower:
                    if obj_class_lower in blocked_ocs_lower:
                        return (
                            "rejected",
                            f"Entry has blocked objectClass matching '{obj_class_lower}' (OID-specific, not in OUD schema)",
                        )

        # 1. Schema entries (cn=schema, subschemasubentry, or has schema attributes)
        # Check DN patterns
        if "cn=schema" in dn.lower() or "subschemasubentry" in dn.lower():
            return ("schema", None)

        # Check for schema attributes (attributetypes, objectclasses as attributes, not DN)
        entry_attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
        if isinstance(entry_attrs, dict):
            attrs_lower = {k.lower() for k in entry_attrs}
            if "attributetypes" in attrs_lower or "objectclasses" in attrs_lower:
                return ("schema", None)

        # Get categorization rules and convert to lowercase for case-insensitive matching
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

        # Convert rule objectClasses to lowercase sets for efficient case-insensitive lookup
        hierarchy_classes_lower = {
            oc.lower() for oc in hierarchy_classes if isinstance(oc, str)
        }
        user_classes_lower = {oc.lower() for oc in user_classes if isinstance(oc, str)}
        group_classes_lower = {
            oc.lower() for oc in group_classes if isinstance(oc, str)
        }

        # 2. Hierarchy entries (organization, organizationalUnit, domain, Oracle containers)
        # CRITICAL: Check hierarchy BEFORE ACL so Oracle containers go to hierarchy file
        # Oracle containers (orclcontainer, orclprivilegegroup) are structural parent
        # containers that may have ACL attributes, but they must be synced before children
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
        # NOTE: ACL check moved AFTER hierarchy/users/groups to give priority to structural entries
        if self._has_acl_attributes(entry):
            return ("acl", None)

        # 6. Rejected entries (no matching category)
        # Use original objectClasses (not lowercase) for error message clarity
        return ("rejected", f"No matching category for objectClasses: {object_classes}")

    def _categorize_entries(
        self, entries: list[FlextTypes.Dict]
    ) -> FlextResult[dict[str, list[FlextTypes.Dict]]]:
        """Categorize all entries into structured categories.

        Args:
            entries: List of parsed entry dictionaries

        Returns:
            FlextResult containing dictionary mapping category to entry list

        """
        categorized: dict[str, list[FlextTypes.Dict]] = {
            "schema": [],
            "hierarchy": [],
            "users": [],
            "groups": [],
            "acl": [],
            "rejected": [],
        }

        rejection_reasons: dict[str, str] = {}

        for entry in entries:
            # STRATEGY PATTERN: Check if entry has ACL attributes in metadata
            # (set by OID quirk during RFC conversion)
            acl_attrs = entry.get("_acl_attributes")
            processed_entry = entry
            if acl_attrs and isinstance(acl_attrs, dict):
                # Create separate ACL entry with same DN but only ACL attributes
                acl_entry = {
                    FlextLdifConstants.DictKeys.DN: entry.get(
                        FlextLdifConstants.DictKeys.DN
                    ),
                    FlextLdifConstants.DictKeys.ATTRIBUTES: acl_attrs,
                    "_from_metadata": True,  # Mark as coming from metadata
                }
                acl_list = categorized.get("acl", [])
                if isinstance(acl_list, list):
                    acl_list.append(acl_entry)
                    categorized["acl"] = acl_list

                # Remove ACL metadata from original entry (already extracted)
                processed_entry = entry.copy()
                processed_entry.pop("_acl_attributes", None)

            category, reason = self._categorize_entry(processed_entry)

            # Add entry to appropriate category (without ACL attrs)
            category_list = categorized.get(category, [])
            if isinstance(category_list, list):
                category_list.append(processed_entry)
                categorized[category] = category_list

            # Track rejection reasons with proper type narrowing
            if reason:
                dn_value = processed_entry.get(FlextLdifConstants.DictKeys.DN)
                if isinstance(dn_value, str):
                    rejection_reasons[dn_value] = reason

        # Add rejection reasons to rejected entries
        for entry in categorized.get("rejected", []):
            dn_value = entry.get(FlextLdifConstants.DictKeys.DN)
            if isinstance(dn_value, str) and dn_value in rejection_reasons:
                attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
                if isinstance(attrs, dict):
                    attrs["rejectionReason"] = rejection_reasons[dn_value]
                    entry[FlextLdifConstants.DictKeys.ATTRIBUTES] = attrs

        return FlextResult[dict[str, list[FlextTypes.Dict]]].ok(categorized)

    def _filter_forbidden_attributes(
        self, attributes: FlextTypes.Dict
    ) -> FlextTypes.Dict:
        """Filter out forbidden attributes from entry.

        STRATEGY PATTERN: Business rules from client application (e.g., client-a-oud-mig)
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
        filtered: FlextTypes.Dict = {
            attr_name: attr_value
            for attr_name, attr_value in attributes.items()
            if attr_name.lower() not in forbidden_lower
        }

        return filtered

    def _transform_categories(
        self, categorized: dict[str, list[FlextTypes.Dict]]
    ) -> FlextResult[dict[str, list[FlextTypes.Dict]]]:
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

            # Transform ACL entries (category "acl")
            acl_entries = categorized.get("acl", [])
            if acl_entries:
                transformed_acl = []

                for entry in acl_entries:
                    transformed_entry = entry.copy()
                    attributes = transformed_entry.get(
                        FlextLdifConstants.DictKeys.ATTRIBUTES, {}
                    )
                    if not isinstance(attributes, dict):
                        transformed_acl.append(transformed_entry)
                        continue

                    # Create new attributes dict for transformed entry
                    new_attributes: FlextTypes.Dict = {}

                    # Process each attribute
                    for attr_name, attr_value in attributes.items():
                        # Check if this is an OID ACL attribute (using set for efficiency)
                        if attr_name.lower() in {"orclaci", "orclentrylevelaci"}:
                            # Handle multi-valued attributes (stored as list)
                            values_to_process = (
                                attr_value
                                if isinstance(attr_value, list)
                                else [attr_value]
                            )

                            # Transform each ACL value (entries can have multiple orclaci lines)
                            transformed_acis = []
                            for single_value in values_to_process:
                                # STEP 1: Parse OID format with OID quirks
                                acl_line = f"{attr_name}: {single_value}"
                                parse_result = oid_acl_quirk.parse_acl(acl_line)

                                if parse_result.is_failure:
                                    # Keep original if parsing fails
                                    continue

                                acl_data = parse_result.unwrap()

                                # STEP 2: Convert OID → RFC generic (intermediate)
                                rfc_result = oid_acl_quirk.convert_acl_to_rfc(acl_data)
                                if rfc_result.is_failure:
                                    continue

                                rfc_data = rfc_result.unwrap()

                                # STEP 3: Convert RFC generic → OUD format
                                oud_result = oud_acl_quirk.convert_acl_from_rfc(
                                    rfc_data
                                )
                                if oud_result.is_failure:
                                    continue

                                oud_data = oud_result.unwrap()

                                # STEP 4: Write OUD ACI format string
                                write_result = oud_acl_quirk.write_acl_to_rfc(oud_data)
                                if write_result.is_failure:
                                    continue

                                aci_line = write_result.unwrap()

                                # Remove "aci:" prefix and collect transformed value
                                if aci_line.startswith("aci:"):
                                    transformed_acis.append(
                                        aci_line.split(":", 1)[1].strip()
                                    )
                                else:
                                    transformed_acis.append(aci_line)

                            # Store transformed ACIs (single value or list depending on count)
                            if transformed_acis:
                                if len(transformed_acis) == 1:
                                    new_attributes["aci"] = transformed_acis[0]
                                else:
                                    new_attributes["aci"] = transformed_acis

                        else:
                            # Non-ACL attribute: keep as-is
                            new_attributes[attr_name] = attr_value

                    # Update entry with transformed attributes
                    transformed_entry[FlextLdifConstants.DictKeys.ATTRIBUTES] = (
                        new_attributes
                    )
                    transformed_acl.append(transformed_entry)

                # Replace ACL entries with transformed versions
                categorized["acl"] = transformed_acl

            # Step 2: Filter forbidden attributes from all categories
            # STRATEGY PATTERN: Business rules from client application
            if self._forbidden_attributes:
                for category, entries in categorized.items():
                    filtered_entries = []
                    for entry in entries:
                        if (
                            isinstance(entry, dict)
                            and FlextLdifConstants.DictKeys.ATTRIBUTES in entry
                        ):
                            filtered_entry = entry.copy()
                            attrs = entry[FlextLdifConstants.DictKeys.ATTRIBUTES]
                            if isinstance(attrs, dict):
                                filtered_entry[
                                    FlextLdifConstants.DictKeys.ATTRIBUTES
                                ] = self._filter_forbidden_attributes(attrs)
                            filtered_entries.append(filtered_entry)
                        else:
                            filtered_entries.append(entry)
                    categorized[category] = filtered_entries

            # Step 3: Normalize DN references (groups and ACLs) using canonical DN map
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

                for category, entries in categorized.items():
                    if category == "schema":
                        continue
                    normalized_entries: list[FlextTypes.Dict] = []
                    for entry in entries:
                        if not isinstance(entry, dict):
                            normalized_entries.append(entry)
                            continue
                        normalized_entry = self._normalize_dn_references_for_entry(
                            entry, dn_map, ref_attrs_lower
                        )
                        # Additionally normalize DNs inside ACI strings
                        normalized_entry = self._normalize_aci_dn_references(
                            normalized_entry, dn_map
                        )
                        normalized_entries.append(normalized_entry)
                    categorized[category] = normalized_entries
            except (
                Exception
            ) as e:  # Safety net: do not fail migration if normalization fails
                self.logger.warning(f"DN reference normalization skipped: {e}")

            return FlextResult[dict[str, list[FlextTypes.Dict]]].ok(categorized)

        except Exception as e:
            return FlextResult[dict[str, list[FlextTypes.Dict]]].fail(
                f"ACL transformation failed: {e}"
            )

    def _build_canonical_dn_map(
        self, categorized: dict[str, list[FlextTypes.Dict]]
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
        entry: FlextTypes.Dict,
        dn_map: dict[str, str],
        ref_attrs_lower: set[str],
    ) -> FlextTypes.Dict:
        """Normalize DN-valued attributes in an entry according to dn_map.

        Handles both str and list[str] attribute values.
        """
        normalized = entry.copy()
        attrs = normalized.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
        if not isinstance(attrs, dict):
            return normalized

        new_attrs: FlextTypes.Dict = {}
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
        self, entry: FlextTypes.Dict, dn_map: dict[str, str]
    ) -> FlextTypes.Dict:
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
        self, entries: list[FlextTypes.Dict]
    ) -> list[FlextTypes.Dict]:
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

    def _sort_entries_by_hierarchy_and_name(
        self, entries: list[FlextTypes.Dict]
    ) -> list[FlextTypes.Dict]:
        """Sort entries by DN hierarchy depth, then case-insensitive DN.

        Ordering rules:
        - First key: DN depth (fewer RDN components first)
        - Second key: Case-insensitive DN string for stable ordering

        This ensures deterministic ordering across 01-05 categories.
        """

        def sort_key(entry: FlextTypes.Dict) -> tuple[int, str]:
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
        self, category: str, entries: list[FlextTypes.Dict], category_filename: str
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
                    entries = processed_entries
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
                        # Skip rejectionReason attribute for rejected entries (already written as comment)
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
        self, categorized: dict[str, list[FlextTypes.Dict]]
    ) -> FlextResult[dict[str, int]]:
        """Write categorized entries to structured LDIF files.

        Args:
            categorized: Dictionary mapping category to entry list

        Returns:
            FlextResult containing FlextTypes.Dict of category to count written

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
        categorized: dict[str, list[FlextTypes.Dict]],
        written_counts: dict[str, int],
    ) -> FlextTypes.Dict:
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
        categorized_counts: FlextTypes.Dict = {}
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
        output_files: FlextTypes.Dict = {}
        for category in written_counts:
            filename_obj = self._output_files.get(category, f"{category}.ldif")
            category_filename = (
                filename_obj if isinstance(filename_obj, str) else f"{category}.ldif"
            )
            output_path = self._output_dir / category_filename
            output_files[category] = str(output_path)

        # Build comprehensive statistics
        stats: FlextTypes.Dict = {
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
