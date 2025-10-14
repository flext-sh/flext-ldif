"""Categorized LDIF migration pipeline.

Provides rule-based entry categorization with structured output directories.
Generates 6-phase output structure: 00-schema through 05-rejected.

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

from flext_core import FlextCore


class FlextLdifCategorizedMigrationPipeline(FlextCore.Service[FlextCore.Types.Dict]):
    """Categorized LDIF migration with structured output directories.

    Features:
    - Rule-based entry categorization
    - 6-directory structured output (00-schema through 05-rejected)
    - Per-category quirks transformation
    - Statistics and reporting
    - Railway-Oriented Programming

    Architecture:
    - Uses FlextLdifParser for entry parsing
    - Uses categorization rules for classification
    - Uses FlextLdifQuirksManager for transformations
    - Generates structured output directories

    Output Structure:
    - 00-schema: Schema definitions (attributeTypes, objectClasses)
    - 01-hierarchy: Organizational structure (organization, ou, domain)
    - 02-users: User entries (person, inetOrgPerson, etc.)
    - 03-groups: Group entries (groupOfNames, etc.)
    - 04-acl: Access Control Lists (entries with aci attributes)
    - 05-rejected: Rejected entries with reasons
    """

    @override
    def __init__(
        self,
        input_dir: Path,
        output_dir: Path,
        categorization_rules: FlextCore.Types.Dict,
        source_server: str = "oracle_oid",
        target_server: str = "oracle_oud",
    ) -> None:
        """Initialize categorized migration pipeline.

        Args:
            input_dir: Input directory with LDIF files
            output_dir: Output directory for categorized results
            categorization_rules: Rules dictionary for categorization
            source_server: Source LDAP server type
            target_server: Target LDAP server type

        """
        super().__init__()
        self._input_dir = Path(input_dir)
        self._output_dir = Path(output_dir)
        self._rules = categorization_rules
        self._source_server = source_server
        self._target_server = target_server

    @override
    def execute(self) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Execute categorized migration pipeline.

        Returns:
            FlextCore.Result containing categorized migration statistics

        Workflow:
            1. Parse all entries from input directory
            2. Categorize entries using rules
            3. Transform entries per category (quirks)
            4. Write to structured output directories
            5. Return comprehensive statistics

        """
        # Phase 2: Implementation will be completed incrementally
        # For now, placeholder that validates structure

        # Create output directories
        create_result = self._create_output_directories()
        if create_result.is_failure:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Failed to create output directories: {create_result.error}"
            )

        # Placeholder result
        result_dict: FlextCore.Types.Dict = {
            "total_entries": 0,
            "categorized_counts": {},
            "output_directories": {},
            "source_server": self._source_server,
            "target_server": self._target_server,
        }

        return FlextCore.Result[FlextCore.Types.Dict].ok(result_dict)

    def _create_output_directories(self) -> FlextCore.Result[None]:
        """Create structured output directories.

        Returns:
            FlextCore.Result indicating success or failure

        """
        try:
            # Create base output directory
            self._output_dir.mkdir(parents=True, exist_ok=True)

            # Create category subdirectories
            for category_dir in [
                "00-schema",
                "01-hierarchy",
                "02-users",
                "03-groups",
                "04-acl",
                "05-rejected",
            ]:
                category_path = self._output_dir / category_dir
                category_path.mkdir(parents=True, exist_ok=True)

            return FlextCore.Result[None].ok(None)
        except (OSError, PermissionError) as e:
            return FlextCore.Result[None].fail(f"Failed to create directories: {e}")

    def _parse_entries(self) -> FlextCore.Result[list[FlextCore.Types.Dict]]:
        """Parse all LDIF entries from input directory.

        Returns:
            FlextCore.Result containing list of parsed entry dictionaries

        Note:
            Phase 2 Day 2: Basic parsing implementation.
            Will be enhanced with FlextLdifParser integration in later phases.

        """
        entries: list[FlextCore.Types.Dict] = []

        try:
            # Get all LDIF files from input directory
            if not self._input_dir.exists():
                return FlextCore.Result[list[FlextCore.Types.Dict]].fail(
                    f"Input directory does not exist: {self._input_dir}"
                )

            ldif_files = list(self._input_dir.glob("*.ldif"))
            if not ldif_files:
                return FlextCore.Result[list[FlextCore.Types.Dict]].fail(
                    "No LDIF files found in input directory"
                )

            # Parse each LDIF file
            for ldif_file in ldif_files:
                with ldif_file.open("r", encoding="utf-8") as f:
                    content = f.read()

                # Simple LDIF parsing (will be replaced with FlextLdifParser)
                for entry_block in content.split("\n\n"):
                    if not entry_block.strip():
                        continue

                    entry: FlextCore.Types.Dict = {
                        "dn": "",
                        "attributes": {},
                        "objectClass": [],
                    }

                    for line in entry_block.split("\n"):
                        if not line.strip() or line.startswith("#"):
                            continue

                        if ":" not in line:
                            continue

                        key, value = line.split(":", 1)
                        key = key.strip()
                        value = value.strip()

                        if key == "dn":
                            entry["dn"] = value
                        elif key == "objectClass":
                            obj_classes = entry.get("objectClass", [])
                            if isinstance(obj_classes, list):
                                obj_classes.append(value)
                                entry["objectClass"] = obj_classes
                        else:
                            attrs = entry.get("attributes", {})
                            if isinstance(attrs, dict):
                                attrs[key] = value
                                entry["attributes"] = attrs

                    if entry["dn"]:
                        entries.append(entry)

            return FlextCore.Result[list[FlextCore.Types.Dict]].ok(entries)

        except (OSError, UnicodeDecodeError) as e:
            return FlextCore.Result[list[FlextCore.Types.Dict]].fail(
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

    def _has_acl_attributes(self, entry: FlextCore.Types.Dict) -> bool:
        """Check if entry has ACL-related attributes.

        Args:
            entry: Entry dictionary to check

        Returns:
            True if entry has ACL attributes, False otherwise

        """
        acl_attributes = self._rules.get("acl_attributes", [])
        if not isinstance(acl_attributes, list):
            return False

        entry_attrs = entry.get("attributes", {})
        if not isinstance(entry_attrs, dict):
            return False

        return any(acl_attr in entry_attrs for acl_attr in acl_attributes)

    def _categorize_entry(self, entry: FlextCore.Types.Dict) -> tuple[str, str | None]:
        """Categorize a single entry based on rules.

        Args:
            entry: Entry dictionary to categorize

        Returns:
            Tuple of (category, rejection_reason)
            Category is one of: schema, hierarchy, users, groups, acl, rejected
            Rejection reason is None unless category is 'rejected'

        Categorization Logic:
            1. Check for schema entries (attributeTypes, objectClasses)
            2. Check for ACL attributes → acl
            3. Check for hierarchy objectClasses → hierarchy
            4. Check for user objectClasses → users
            5. Check for group objectClasses → groups
            6. Otherwise → rejected

        """
        # Get entry DN and objectClasses with proper type narrowing
        dn_value = entry.get("dn", "")
        dn = dn_value if isinstance(dn_value, str) else ""

        object_classes = entry.get("objectClass", [])
        if not isinstance(object_classes, list):
            object_classes = []

        # 1. Schema entries (cn=schema or schema-related DNs)
        if "cn=schema" in dn.lower() or "attributeTypes" in dn or "objectClasses" in dn:
            return ("schema", None)

        # 2. ACL entries (have ACL attributes)
        if self._has_acl_attributes(entry):
            return ("acl", None)

        # Get categorization rules
        hierarchy_classes = self._rules.get("hierarchy_objectclasses", [])
        user_classes = self._rules.get("user_objectclasses", [])
        group_classes = self._rules.get("group_objectclasses", [])
        user_dn_patterns = self._rules.get("user_dn_patterns", [])

        if not isinstance(hierarchy_classes, list):
            hierarchy_classes = []
        if not isinstance(user_classes, list):
            user_classes = []
        if not isinstance(group_classes, list):
            group_classes = []
        if not isinstance(user_dn_patterns, list):
            user_dn_patterns = []

        # 3. Hierarchy entries (organization, organizationalUnit, domain)
        for obj_class in object_classes:
            if obj_class in hierarchy_classes:
                return ("hierarchy", None)

        # 4. User entries (person, inetOrgPerson, etc.)
        for obj_class in object_classes:
            if obj_class in user_classes:
                # Validate with DN patterns if provided
                if user_dn_patterns and not self._matches_dn_pattern(
                    dn, user_dn_patterns
                ):
                    return (
                        "rejected",
                        f"User entry DN does not match expected patterns: {dn}",
                    )
                return ("users", None)

        # 5. Group entries (groupOfNames, etc.)
        for obj_class in object_classes:
            if obj_class in group_classes:
                return ("groups", None)

        # 6. Rejected entries (no matching category)
        return ("rejected", f"No matching category for objectClasses: {object_classes}")

    def _categorize_entries(
        self, entries: list[FlextCore.Types.Dict]
    ) -> FlextCore.Result[dict[str, list[FlextCore.Types.Dict]]]:
        """Categorize all entries into structured categories.

        Args:
            entries: List of parsed entry dictionaries

        Returns:
            FlextCore.Result containing dictionary mapping category to entry list

        """
        categorized: dict[str, list[FlextCore.Types.Dict]] = {
            "schema": [],
            "hierarchy": [],
            "users": [],
            "groups": [],
            "acl": [],
            "rejected": [],
        }

        rejection_reasons: dict[str, str] = {}

        for entry in entries:
            category, reason = self._categorize_entry(entry)

            # Add entry to appropriate category
            category_list = categorized.get(category, [])
            if isinstance(category_list, list):
                category_list.append(entry)
                categorized[category] = category_list

            # Track rejection reasons with proper type narrowing
            if reason:
                dn_value = entry.get("dn")
                if isinstance(dn_value, str):
                    rejection_reasons[dn_value] = reason

        # Add rejection reasons to rejected entries
        for entry in categorized.get("rejected", []):
            dn_value = entry.get("dn")
            if isinstance(dn_value, str) and dn_value in rejection_reasons:
                attrs = entry.get("attributes", {})
                if isinstance(attrs, dict):
                    attrs["rejectionReason"] = rejection_reasons[dn_value]
                    entry["attributes"] = attrs

        return FlextCore.Result[dict[str, list[FlextCore.Types.Dict]]].ok(categorized)

    def _transform_categories(
        self, categorized: dict[str, list[FlextCore.Types.Dict]]
    ) -> FlextCore.Result[dict[str, list[FlextCore.Types.Dict]]]:
        """Apply per-category transformations using quirks system.

        Args:
            categorized: Dictionary mapping category to entry list

        Returns:
            FlextCore.Result containing transformed categorized entries

        Note:
            Phase 2 Day 2: Placeholder for quirks integration.
            Will be enhanced with FlextLdifQuirksManager in later phases.

        """
        # Phase 2 Day 2: Placeholder - no transformations yet
        # Phase 3 TODO: Integrate with FlextLdifQuirksManager
        # Example:
        #   quirks_manager = FlextLdifQuirksManager(
        #       source_server=self._source_server,
        #       target_server=self._target_server
        #   )
        #   for category, entries in categorized.items():
        #       transformed = quirks_manager.transform_entries(entries, category)
        #       categorized[category] = transformed

        return FlextCore.Result[dict[str, list[FlextCore.Types.Dict]]].ok(categorized)

    def _write_category_file(
        self, category: str, entries: list[FlextCore.Types.Dict], category_dir: str
    ) -> FlextCore.Result[int]:
        """Write entries for a single category to LDIF file.

        Args:
            category: Category name (schema, hierarchy, users, groups, acl, rejected)
            entries: List of entries to write
            category_dir: Category directory name (e.g., "00-schema")

        Returns:
            FlextCore.Result containing count of entries written

        """
        if not entries:
            return FlextCore.Result[int].ok(0)

        try:
            # Create output file path
            category_path = self._output_dir / category_dir
            output_file = category_path / f"{category}.ldif"

            # Generate LDIF content
            ldif_content: list[str] = []

            for entry in entries:
                # Get DN with proper type narrowing
                dn_value = entry.get("dn", "")
                if isinstance(dn_value, str) and dn_value:
                    dn = dn_value
                else:
                    continue

                ldif_content.append(f"dn: {dn}")

                # Write objectClasses
                object_classes = entry.get("objectClass", [])
                if isinstance(object_classes, list):
                    ldif_content.extend(
                        f"objectClass: {obj_class}" for obj_class in object_classes
                    )

                # Write attributes
                attributes = entry.get("attributes", {})
                if isinstance(attributes, dict):
                    for attr_name, attr_value in attributes.items():
                        ldif_content.append(f"{attr_name}: {attr_value}")

                # Add blank line between entries
                ldif_content.append("")

            # Write to file
            with output_file.open("w", encoding="utf-8") as f:
                f.write("\n".join(ldif_content))

            return FlextCore.Result[int].ok(len(entries))

        except (OSError, UnicodeEncodeError) as e:
            return FlextCore.Result[int].fail(f"Failed to write {category} file: {e}")

    def _write_categorized_output(
        self, categorized: dict[str, list[FlextCore.Types.Dict]]
    ) -> FlextCore.Result[dict[str, int]]:
        """Write categorized entries to structured output directories.

        Args:
            categorized: Dictionary mapping category to entry list

        Returns:
            FlextCore.Result containing dict of category to count written

        """
        written_counts: dict[str, int] = {}

        # Category to directory mapping
        category_dirs = {
            "schema": "00-schema",
            "hierarchy": "01-hierarchy",
            "users": "02-users",
            "groups": "03-groups",
            "acl": "04-acl",
            "rejected": "05-rejected",
        }

        # Write each category
        for category, entries in categorized.items():
            category_dir = category_dirs.get(category, category)

            write_result = self._write_category_file(category, entries, category_dir)

            if write_result.is_failure:
                return FlextCore.Result[dict[str, int]].fail(
                    f"Failed to write {category}: {write_result.error}"
                )

            written_counts[category] = write_result.unwrap()

        return FlextCore.Result[dict[str, int]].ok(written_counts)

    def _generate_statistics(
        self,
        categorized: dict[str, list[FlextCore.Types.Dict]],
        written_counts: dict[str, int],
    ) -> FlextCore.Types.Dict:
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
        categorized_counts: FlextCore.Types.Dict = {}
        for category, entries in categorized.items():
            categorized_counts[category] = len(entries)

        # Count rejections and gather reasons
        rejected_entries = categorized.get("rejected", [])
        rejection_count = len(rejected_entries)
        rejection_reasons: list[str] = []

        for entry in rejected_entries:
            attrs = entry.get("attributes", {})
            if isinstance(attrs, dict) and "rejectionReason" in attrs:
                reason_value = attrs["rejectionReason"]
                if (
                    isinstance(reason_value, str)
                    and reason_value not in rejection_reasons
                ):
                    rejection_reasons.append(reason_value)

        # Calculate rejection rate
        rejection_rate = rejection_count / total_entries if total_entries > 0 else 0.0

        # Build output directories info
        output_directories: FlextCore.Types.Dict = {}
        category_dirs = {
            "schema": "00-schema",
            "hierarchy": "01-hierarchy",
            "users": "02-users",
            "groups": "03-groups",
            "acl": "04-acl",
            "rejected": "05-rejected",
        }
        for category in written_counts:
            category_dir = category_dirs.get(category, category)
            output_path = self._output_dir / category_dir
            output_directories[category] = str(output_path)

        # Build comprehensive statistics
        stats: FlextCore.Types.Dict = {
            "total_entries": total_entries,
            "categorized_counts": categorized_counts,
            "written_counts": written_counts,
            "rejection_count": rejection_count,
            "rejection_rate": rejection_rate,
            "rejection_reasons": rejection_reasons,
            "output_directories": output_directories,
            "source_server": self._source_server,
            "target_server": self._target_server,
            "input_dir": str(self._input_dir),
            "output_dir": str(self._output_dir),
        }

        return stats


__all__ = ["FlextLdifCategorizedMigrationPipeline"]
