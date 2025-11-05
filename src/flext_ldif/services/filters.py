"""FLEXT LDIF Filters Service - Universal Entry Filtering and Categorization Engine.

╔══════════════════════════════════════════════════════════════════════════════╗
║  COMPREHENSIVE ENTRY FILTERING, CATEGORIZATION & TRANSFORMATION ENGINE      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ✅ DN pattern matching (wildcard/fnmatch syntax)                           ║
║  ✅ ObjectClass-based filtering with required attributes                    ║
║  ✅ Attribute presence/absence filtering                                    ║
║  ✅ Attribute and objectClass removal (entry transformation)                ║
║  ✅ Entry categorization (6-category: users/groups/hierarchy/schema/ACL)   ║
║  ✅ Schema entry detection and filtering by OID patterns                    ║
║  ✅ ACL attribute detection and extraction                                  ║
║  ✅ Exclusion metadata marking with reason tracking                         ║
║  ✅ Fluent builder pattern for complex multi-condition filtering            ║
║  ✅ Multiple API patterns (static, classmethod, builder, helpers)           ║
║  ✅ 100% server-agnostic design (works with any LDAP server)               ║
╚══════════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════════
REAL USAGE EXAMPLES
═══════════════════════════════════════════════════════════════════════════════

# PATTERN 1: Static Method API (Direct & Simple)
────────────────────────────────────────────────
# Filter entries by DN pattern
result = FlextLdifFilter.filter_by_dn(
    entries=my_entries,
    pattern="*,ou=users,dc=example,dc=com",
    mode="include"
)
filtered = result.unwrap()

# Filter by objectClass
result = FlextLdifFilter.filter_by_objectclass(
    entries=my_entries,
    objectclass=("person", "inetOrgPerson"),
    required_attributes=["cn", "mail"]
)

# Filter by attribute presence
result = FlextLdifFilter.filter_by_attributes(
    entries=my_entries,
    attributes=["mail"],
    match_all=False,  # Has ANY attribute
    mode="include"
)

# PATTERN 2: Classmethod for Composable/Chainable Operations
──────────────────────────────────────────────────────────────
result = (
    FlextLdifFilter.filter(
        entries=my_entries,
        criteria="dn",
        pattern="*,ou=users,*"
    )
    .map(lambda e: e[:10])  # Take first 10
    .and_then(lambda e: FlextLdifFilter.filter(e, criteria="objectclass", objectclass="person"))
)

# PATTERN 3: Fluent Builder Pattern
───────────────────────────────────
filtered_result = (
    FlextLdifFilter.builder()
    .with_entries(my_entries)
    .with_dn_pattern("*,ou=users,dc=example,dc=com")
    .with_objectclass("person")
    .with_required_attributes(["cn", "mail"])
    .build()  # Returns list[Entry] directly
)

# PATTERN 4: Public Classmethod Helpers (Most Direct)
────────────────────────────────────────────────────
# Filter by DN pattern
result = FlextLdifFilter.by_dn(entries, "*,ou=users,*")
filtered = result.unwrap()

# Filter by objectClass
result = FlextLdifFilter.by_objectclass(
    entries, ("person", "inetOrgPerson")
)

# Filter by attributes
result = FlextLdifFilter.by_attributes(
    entries, ["mail"], match_all=False
)

# Filter by base DN
included, excluded = FlextLdifFilter.by_base_dn(
    entries, "dc=example,dc=com"
)

# Extract ACL entries
result = FlextLdifFilter.extract_acl_entries(entries)

# Categorize entry
category, reason = FlextLdifFilter.categorize(entry, rules)

# PATTERN 5: Transformation (Remove Attributes/ObjectClasses)
──────────────────────────────────────────────────────────────
# Remove temporary attributes
result = FlextLdifFilter.remove_attributes(
    entry=my_entry,
    attributes=["tempAttribute", "debugInfo"]
)

# Remove unwanted objectClasses
result = FlextLdifFilter.remove_objectclasses(
    entry=my_entry,
    objectclasses=["temporaryClass"]
)

# PATTERN 6: Schema & Advanced Operations
───────────────────────────────────────────
# Check if entry is schema
is_schema = FlextLdifFilter.is_schema(entry)

# Filter schema by OID whitelist
result = FlextLdifFilter.filter_schema_by_oids(
    entries=schema_entries,
    allowed_oids={
        "attributes": ["2.5.4.*"],
        "objectclasses": ["2.5.6.*"]
    }
)

═══════════════════════════════════════════════════════════════════════════════
QUICK REFERENCE
═══════════════════════════════════════════════════════════════════════════════

Most Common Use Cases:

# Filter entries by DN pattern
result = FlextLdifFilter.by_dn(entries, "*,ou=users,*")
filtered = result.unwrap()

# Filter by objectClass
result = FlextLdifFilter.by_objectclass(
    entries, ("person", "inetOrgPerson")
)

# Combine multiple conditions (builder)
filtered_result = (
    FlextLdifFilter.builder()
    .with_entries(entries)
    .with_dn_pattern("*,ou=users,*")
    .with_objectclass("person")
    .build()
)

# Check if schema entry
is_schema = FlextLdifFilter.is_schema(entry)

# Extract ACL entries
result = FlextLdifFilter.extract_acl_entries(entries)
acl_entries = result.unwrap()

# Categorize entry
category, reason = FlextLdifFilter.categorize(entry, rules)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import fnmatch
import re
from datetime import UTC, datetime
from typing import Any

from flext_core import FlextResult, FlextService
from pydantic import Field, field_validator

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifFilter(FlextService[list[FlextLdifModels.Entry]]):
    """Universal LDIF Entry Filtering and Categorization Service.

    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  FLEXIBLE FILTERING FOR LDIF ENTRIES: DN, OBJECTCLASS, ATTRIBUTES, ACL  ║
    ╠══════════════════════════════════════════════════════════════════════════╣
    ║  ✅ Filter entries by DN pattern (wildcard: *, ?, [seq])                ║
    ║  ✅ Filter by objectClass with required attributes                      ║
    ║  ✅ Filter by attribute presence (ANY or ALL)                           ║
    ║  ✅ Filter by base DN (hierarchy)                                       ║
    ║  ✅ Categorize entries (users, groups, hierarchy, schema, ACL, rejected)║
    ║  ✅ Schema detection and OID-based filtering                            ║
    ║  ✅ ACL attribute detection and extraction                              ║
    ║  ✅ Remove attributes/objectClasses from entries                        ║
    ║  ✅ 100% type-safe with Pydantic v2 validation                          ║
    ║  ✅ Multiple API patterns: execute(), filter(), builder(), helpers()    ║
    ╚══════════════════════════════════════════════════════════════════════════╝

    FILTER CRITERIA:
    - "dn"           Filter by DN pattern
    - "objectclass"  Filter by objectClass
    - "attributes"   Filter by attribute presence
    - "base_dn"      Filter by base DN (returns tuple)

    MODES (for all criteria):
    - "include"      Keep matching entries (default)
    - "exclude"      Remove matching entries (opposite of include)

    ATTRIBUTE MATCHING:
    - match_all=True   Entry must have ALL attributes (AND logic)
    - match_all=False  Entry must have ANY attribute (OR logic)

    """

    # ════════════════════════════════════════════════════════════════════════
    # NESTED CLASSES - SRP COMPLIANT COMPONENTS
    # ════════════════════════════════════════════════════════════════════════

    class Filter:
        """Handles basic DN, objectClass, and attribute filtering operations.

        Responsibility (SRP):
        - Filter entries by DN pattern matching
        - Filter entries by objectClass presence
        - Filter entries by attribute presence
        - Filter entries by base DN (hierarchy)
        """

        @staticmethod
        def _filter_by_dn(
            entries: list[FlextLdifModels.Entry],
            dn_pattern: str,
            mode: str,
            mark_excluded: bool,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Filter entries by DN pattern."""
            try:
                pattern = dn_pattern  # Type narrowing
                filtered = []
                for entry in entries:
                    # Use DN utility to get string value (supports both DN model and str)
                    entry_dn_str = FlextLdifUtilities.DN._get_dn_value(entry.dn)
                    matches = fnmatch.fnmatch(entry_dn_str.lower(), pattern.lower())
                    include = (
                        mode == FlextLdifConstants.Modes.INCLUDE and matches
                    ) or (mode == FlextLdifConstants.Modes.EXCLUDE and not matches)

                    if include:
                        filtered.append(entry)
                    elif mark_excluded:
                        filtered.append(
                            FlextLdifFilter.Exclusion._mark_excluded(
                                entry, f"DN pattern: {dn_pattern}"
                            )
                        )

                return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
            except Exception as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"DN filter failed: {e}"
                )

        @staticmethod
        def _filter_by_objectclass(
            entries: list[FlextLdifModels.Entry],
            objectclass: str | tuple[str, ...],
            required_attributes: list[str] | None,
            mode: str,
            mark_excluded: bool,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Filter by objectClass."""
            try:
                oc_tuple = (
                    objectclass if isinstance(objectclass, tuple) else (objectclass,)
                )

                filtered = []
                for entry in entries:
                    has_oc = FlextLdifFilter.Filter._has_objectclass(entry, oc_tuple)
                    has_attrs = True

                    if has_oc and required_attributes:
                        has_attrs = FlextLdifFilter.Filter._has_attributes(
                            entry, required_attributes, match_any=False
                        )

                    matches = has_oc and has_attrs
                    include = (
                        mode == FlextLdifConstants.Modes.INCLUDE and matches
                    ) or (mode == FlextLdifConstants.Modes.EXCLUDE and not matches)

                    if include:
                        filtered.append(entry)
                    elif mark_excluded:
                        filtered.append(
                            FlextLdifFilter.Exclusion._mark_excluded(
                                entry, f"ObjectClass filter: {oc_tuple}"
                            )
                        )

                return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
            except Exception as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"ObjectClass filter failed: {e}"
                )

        @staticmethod
        def _filter_by_attributes(
            entries: list[FlextLdifModels.Entry],
            attributes: list[str],
            match_all: bool,
            mode: str,
            mark_excluded: bool,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Filter by attribute presence."""
            try:
                attrs = attributes  # Type narrowing
                filtered = []
                for entry in entries:
                    matches = FlextLdifFilter.Filter._has_attributes(
                        entry, attrs, match_any=not match_all
                    )
                    include = (
                        mode == FlextLdifConstants.Modes.INCLUDE and matches
                    ) or (mode == FlextLdifConstants.Modes.EXCLUDE and not matches)

                    if include:
                        filtered.append(entry)
                    elif mark_excluded:
                        filtered.append(
                            FlextLdifFilter.Exclusion._mark_excluded(
                                entry, f"Attribute filter: {attributes}"
                            )
                        )

                return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
            except Exception as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Attribute filter failed: {e}"
                )

        @staticmethod
        def _filter_by_base_dn(
            entries: list[FlextLdifModels.Entry],
            base_dn: str,
            mark_excluded: bool,
        ) -> tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]:
            """Filter by base DN.

            Uses FlextLdifUtilities.DN.is_under_base() for DN hierarchy check.
            """
            included = []
            excluded = []

            for entry in entries:
                # Use utility for consistent DN comparison (now supports DN models)
                if FlextLdifUtilities.DN.is_under_base(entry.dn, base_dn):
                    included.append(entry)
                elif mark_excluded:
                    excluded.append(
                        FlextLdifFilter.Exclusion._mark_excluded(
                            entry, f"Base DN: {base_dn}"
                        )
                    )
                else:
                    excluded.append(entry)

            return (included, excluded)

        @staticmethod
        def _has_objectclass(
            entry: FlextLdifModels.Entry, objectclasses: tuple[str, ...]
        ) -> bool:
            """Check if entry has any of the objectClasses.

            Uses FlextLdifUtilities.Entry.has_objectclass() for consistent logic.
            """
            return FlextLdifUtilities.Entry.has_objectclass(entry, objectclasses)

        @staticmethod
        def _has_attributes(
            entry: FlextLdifModels.Entry,
            attributes: list[str],
            *,
            match_any: bool = True,
        ) -> bool:
            """Check if entry has attributes (ANY or ALL).

            Uses FlextLdifUtilities.Entry helpers for consistent logic.
            """
            if match_any:
                return FlextLdifUtilities.Entry.has_any_attributes(entry, attributes)
            return FlextLdifUtilities.Entry.has_all_attributes(entry, attributes)

    class Categorizer:
        """Handles entry categorization into 6 categories.

        Responsibility (SRP):
        - Categorize entries into: schema, hierarchy, users, groups, acl, rejected
        - Validate DN patterns for specific categories
        - Check for blocked objectClasses
        """

        @staticmethod
        def _check_blocked_objectclasses(
            entry: FlextLdifModels.Entry,
            whitelist_rules: dict[str, Any] | None,
        ) -> tuple[bool, str | None]:
            """Check if entry has blocked objectClasses."""
            if not whitelist_rules:
                return (False, None)

            blocked_ocs = whitelist_rules.get("blocked_objectclasses", [])
            if not blocked_ocs:
                return (False, None)

            entry_ocs = entry.get_attribute_values("objectClass")
            if not entry_ocs:
                return (False, None)

            blocked_ocs_lower = {oc.lower() for oc in blocked_ocs}
            for oc in entry_ocs:
                if oc.lower() in blocked_ocs_lower:
                    return (True, f"Blocked objectClass: {oc}")

            return (False, None)

        @staticmethod
        def _validate_category_dn_pattern(
            entry: FlextLdifModels.Entry,
            category: str,
            rules: dict[str, Any],
        ) -> tuple[bool, str | None]:
            """Validate DN pattern for specific category."""
            pattern_key = f"{category[:-1]}_dn_patterns"  # users -> user_dn_patterns
            dn_patterns = rules.get(pattern_key, [])

            if not dn_patterns:
                return (False, None)

            try:
                if not FlextLdifFilter.Exclusion._matches_dn_pattern(
                    entry.dn, dn_patterns
                ):
                    return (True, f"DN pattern does not match {category} rules")
            except ValueError:
                # Invalid patterns - just let it through
                pass

            return (False, None)

    class Transformer:
        """Handles entry transformation (removing attributes/objectClasses).

        Responsibility (SRP):
        - Remove attributes from entries
        - Remove objectClasses from entries
        - Filter entry attributes
        - Filter entry objectClasses
        """

        @staticmethod
        def remove_attributes(
            entry: FlextLdifModels.Entry,
            attributes: list[str],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Remove attributes from entry."""
            try:
                blocked_lower = {attr.lower() for attr in attributes}
                filtered_attrs_dict = {
                    key: value
                    for key, value in entry.attributes.attributes.items()
                    if key.lower() not in blocked_lower
                }

                new_attributes = FlextLdifModels.LdifAttributes(
                    attributes=filtered_attrs_dict,
                    metadata=entry.attributes.metadata,
                )

                # Entry.create() already returns FlextResult, return directly
                return FlextLdifModels.Entry.create(
                    dn=entry.dn,
                    attributes=new_attributes,
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to remove attributes: {e}"
                )

        @staticmethod
        def remove_objectclasses(
            entry: FlextLdifModels.Entry,
            objectclasses: list[str],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Remove objectClasses from entry."""
            try:
                blocked_lower = {oc.lower() for oc in objectclasses}

                oc_values = entry.get_attribute_values(
                    FlextLdifConstants.DictKeys.OBJECTCLASS
                )
                if not oc_values:
                    return FlextResult[FlextLdifModels.Entry].ok(entry)

                filtered_ocs = [
                    oc for oc in oc_values if oc.lower() not in blocked_lower
                ]
                if not filtered_ocs:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        "All objectClasses would be removed"
                    )

                new_attrs_dict = dict(entry.attributes.attributes)
                new_attrs_dict[FlextLdifConstants.DictKeys.OBJECTCLASS] = filtered_ocs

                new_attributes = FlextLdifModels.LdifAttributes(
                    attributes=new_attrs_dict,
                    metadata=entry.attributes.metadata,
                )

                # Entry.create() already returns FlextResult, return directly
                return FlextLdifModels.Entry.create(
                    dn=entry.dn,
                    attributes=new_attributes,
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to remove objectClasses: {e}"
                )

        @staticmethod
        def filter_entry_attributes(
            entry: FlextLdifModels.Entry,
            attributes_to_remove: list[str],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Remove specified attributes from entry."""
            try:
                if not attributes_to_remove:
                    return FlextResult[FlextLdifModels.Entry].ok(entry)

                # Create filtered attributes dict
                attrs_lower = {attr.lower() for attr in attributes_to_remove}

                filtered_attrs = {
                    key: values
                    for key, values in entry.attributes.items()
                    if key.lower() not in attrs_lower
                }

                # Create new LdifAttributes
                attrs_result = FlextLdifModels.LdifAttributes.create(filtered_attrs)
                if not attrs_result.is_success:
                    return FlextResult[FlextLdifModels.Entry].fail(attrs_result.error)

                new_entry = entry.model_copy(
                    update={"attributes": attrs_result.unwrap()}
                )
                return FlextResult[FlextLdifModels.Entry].ok(new_entry)

            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Filter attributes failed: {e}"
                )

        @staticmethod
        def filter_entry_objectclasses(
            entry: FlextLdifModels.Entry,
            objectclasses_to_remove: list[str],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Remove specified objectClasses from entry."""
            try:
                oc_to_remove_lower = {oc.lower() for oc in objectclasses_to_remove}
                current_ocs = entry.get_attribute_values("objectClass")

                if not current_ocs:
                    return FlextResult[FlextLdifModels.Entry].ok(entry)

                # Filter objectClasses
                filtered_ocs = [
                    oc for oc in current_ocs if oc.lower() not in oc_to_remove_lower
                ]

                # Check if all objectClasses would be removed
                if not filtered_ocs:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        "All objectClasses would be removed"
                    )

                # Create filtered attributes dict
                filtered_attrs = dict(entry.attributes.attributes)
                filtered_attrs["objectClass"] = filtered_ocs

                # Create new LdifAttributes
                attrs_result = FlextLdifModels.LdifAttributes.create(filtered_attrs)
                if not attrs_result.is_success:
                    return FlextResult[FlextLdifModels.Entry].fail(attrs_result.error)

                new_entry = entry.model_copy(
                    update={"attributes": attrs_result.unwrap()}
                )
                return FlextResult[FlextLdifModels.Entry].ok(new_entry)

            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Filter objectClasses failed: {e}"
                )

    class AclDetector:
        """Handles ACL detection and schema entry operations.

        Responsibility (SRP):
        - Detect schema entries
        - Detect ACL attributes
        - Extract ACL entries
        - Filter schema by OID patterns
        """

        @staticmethod
        def is_schema(entry: FlextLdifModels.Entry) -> bool:
            """Check if entry is a REAL schema entry with schema definitions.

            Uses FlextLdifUtilities.Entry.is_schema_entry() with strict mode.

            CRITICAL: This method detects ONLY real LDAP schema entries that
            contain attributetypes or objectclasses definitions. Entries with
            "cn=schema" in DN but NO schema attributes (like ODIP config
            entries) are NOT schema.

            Priority order (AND logic):
            1. MUST have attributetypes OR objectclasses attributes (PRIMARY)
            2. AND DN pattern check (cn=subschemasubentry or similar)

            This prevents false positives from entries like:
            - cn=Schema,cn=Directory Integration Platform (ODIP config, NOT
            schema)
            """
            return FlextLdifUtilities.Entry.is_schema_entry(entry, strict=True)

        @staticmethod
        def _has_acl_attributes(
            entry: FlextLdifModels.Entry, attributes: list[str]
        ) -> bool:
            """Check if entry has any of the specified ACL attributes."""
            if not attributes:
                return False

            entry_attrs_lower = {attr.lower() for attr in entry.attributes}
            return any(attr.lower() in entry_attrs_lower for attr in attributes)

        @staticmethod
        def _matches_oid_pattern(
            attributes: dict[str, Any],
            attribute_keys: list[str],
            allowed_oids: list[str],
        ) -> bool:
            """Check if entry attributes contain OID matching allowed patterns."""
            for key in attribute_keys:
                if key not in attributes:
                    continue

                values = attributes[key]
                if not isinstance(values, list):
                    continue

                for val in values:
                    oid_match = re.search(r"\(\s*(\d+(?:\.\d+)*)", str(val))
                    if not oid_match:
                        continue

                    oid = oid_match.group(1)
                    pattern = "|".join(allowed_oids) if allowed_oids else "*"
                    if fnmatch.fnmatch(oid, pattern):
                        return True

            return False

    class Exclusion:
        """Handles entry exclusion management and metadata.

        Responsibility (SRP):
        - Mark entries as excluded
        - Track exclusion reasons
        - Virtual delete operations
        - Restore virtually deleted entries
        - Match DN patterns
        """

        @staticmethod
        def _mark_excluded(
            entry: FlextLdifModels.Entry, reason: str
        ) -> FlextLdifModels.Entry:
            """Mark entry as excluded."""
            exclusion_info = FlextLdifModels.ExclusionInfo(
                excluded=True,
                exclusion_reason=reason,
                timestamp=datetime.now(UTC).isoformat(),
            )

            if entry.metadata is None:
                new_metadata = FlextLdifModels.QuirkMetadata(
                    extensions={"exclusion_info": exclusion_info.model_dump()},
                )
            else:
                new_extensions = {**entry.metadata.extensions}
                new_extensions["exclusion_info"] = exclusion_info.model_dump()
                new_metadata = FlextLdifModels.QuirkMetadata(
                    original_format=entry.metadata.original_format,
                    quirk_type=entry.metadata.quirk_type,
                    parsed_timestamp=entry.metadata.parsed_timestamp,
                    extensions=new_extensions,
                    custom_data=entry.metadata.custom_data,
                )

            return entry.model_copy(update={"metadata": new_metadata})

        @staticmethod
        def is_entry_excluded(entry: FlextLdifModels.Entry) -> bool:
            """Check if entry is marked as excluded in metadata."""
            if entry.metadata is None:
                return False

            exclusion_info = entry.metadata.extensions.get("exclusion_info")
            if not isinstance(exclusion_info, dict):
                return False

            excluded = exclusion_info.get("excluded")
            return isinstance(excluded, bool) and excluded

        @staticmethod
        def get_exclusion_reason(entry: FlextLdifModels.Entry) -> str | None:
            """Get exclusion reason from entry metadata."""
            if entry.metadata is None:
                return None

            exclusion_info = entry.metadata.extensions.get("exclusion_info")
            if not isinstance(exclusion_info, dict):
                return None

            # Only return reason if entry is actually marked as excluded
            if not FlextLdifFilter.Exclusion.is_entry_excluded(entry):
                return None

            reason = exclusion_info.get("exclusion_reason")
            return reason if isinstance(reason, str) else None

        @staticmethod
        def _matches_dn_pattern(dn: str | Any, patterns: list[str]) -> bool:
            """Check if DN matches any of the regex patterns.

            Args:
                dn: DN string or FlextLdifModels.DistinguishedName object
                patterns: List of regex patterns to match against

            Returns:
                True if DN matches any pattern, False otherwise

            """
            if not patterns:
                return False

            # Extract DN string (supports both DN model and str)
            dn_str = FlextLdifUtilities.DN._get_dn_value(dn)

            # First validate ALL patterns before matching
            invalid_patterns = []
            for pattern in patterns:
                try:
                    re.compile(pattern)
                except re.error:
                    invalid_patterns.append(pattern)

            if invalid_patterns:
                msg = f"Invalid regex patterns: {invalid_patterns}"
                raise ValueError(msg)

            # Now do the matching
            dn_lower = dn_str.lower()
            for pattern in patterns:
                try:
                    pattern_lower = pattern.lower()
                    if re.search(pattern_lower, dn_lower):
                        return True
                except re.error:
                    # This shouldn't happen since we already validated,
                    # but skip if it does
                    continue

            return False

        @staticmethod
        def virtual_delete(
            entries: list[FlextLdifModels.Entry],
            filter_criteria: str | None = None,
            dn_pattern: str | None = None,
        ) -> FlextResult[dict[str, list[FlextLdifModels.Entry]]]:
            """Perform virtual (soft) delete.

            Non-destructive operation that marks entries for deletion by
            adding a 'deleted' metadata marker. Original data remains intact
            for recovery.

            Returns:
                FlextResult with dict containing:
                    - "active": List of entries that were NOT deleted
                    - "virtual_deleted": List of entries marked as deleted
                    - "archive": Copy of deleted entries for archival

            """
            try:
                if not entries:
                    return FlextResult[dict[str, list[FlextLdifModels.Entry]]].ok({
                        "active": [],
                        "virtual_deleted": [],
                        "archive": [],
                    })

                active_entries: list[FlextLdifModels.Entry] = []
                deleted_entries: list[FlextLdifModels.Entry] = []

                for entry in entries:
                    should_delete = True

                    # Check DN pattern if provided
                    if dn_pattern:
                        should_delete = FlextLdifFilter.Exclusion._matches_dn_pattern(
                            entry.dn, [dn_pattern]
                        )

                    if should_delete:
                        # Mark as virtually deleted (non-destructive)
                        entry_dict = entry.model_dump()
                        entry_dict["metadata"] = entry_dict.get("metadata", {})
                        if isinstance(entry_dict["metadata"], dict):
                            from datetime import datetime

                            entry_dict["metadata"]["virtual_deleted"] = True
                            entry_dict["metadata"]["deletion_timestamp"] = datetime.now(
                                UTC
                            ).isoformat()

                        deleted_entry = FlextLdifModels.Entry.model_validate(entry_dict)
                        deleted_entries.append(deleted_entry)
                    else:
                        active_entries.append(entry)

                return FlextResult[dict[str, list[FlextLdifModels.Entry]]].ok({
                    "active": active_entries,
                    "virtual_deleted": deleted_entries,
                    "archive": deleted_entries,  # Archive copy for recovery
                })

            except Exception as e:
                return FlextResult[dict[str, list[FlextLdifModels.Entry]]].fail(
                    f"Virtual delete failed: {e}"
                )

        @staticmethod
        def restore_virtual_deleted(
            entries: list[FlextLdifModels.Entry],
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Restore virtually deleted entries back to active state.

            Removes virtual delete markers and restores entries to active
            state. No data is ever lost - this is purely metadata
            manipulation.

            """
            try:
                restored_entries: list[FlextLdifModels.Entry] = []

                for entry in entries:
                    entry_dict = entry.model_dump()
                    metadata = entry_dict.get("metadata", {})

                    # Remove virtual delete markers
                    if isinstance(metadata, dict):
                        metadata.pop("virtual_deleted", None)
                        metadata.pop("deletion_timestamp", None)
                        entry_dict["metadata"] = metadata

                    restored_entry = FlextLdifModels.Entry.model_validate(entry_dict)
                    restored_entries.append(restored_entry)

                return FlextResult[list[FlextLdifModels.Entry]].ok(restored_entries)

            except Exception as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Restore virtual deleted failed: {e}"
                )

    # ════════════════════════════════════════════════════════════════════════
    # PYDANTIC FIELDS
    # ════════════════════════════════════════════════════════════════════════

    entries: list[FlextLdifModels.Entry] = Field(
        default_factory=list,
        description="LDIF entries to filter.",
    )

    filter_criteria: str = Field(
        default="dn",
        description="Filter type: dn|objectclass|attributes|base_dn|exclude",
    )

    dn_pattern: str | None = Field(
        default=None,
        description="DN wildcard pattern for filtering.",
    )

    objectclass: str | tuple[str, ...] | None = Field(
        default=None,
        description="ObjectClass name(s) to filter by.",
    )

    required_attributes: list[str] | None = Field(
        default=None,
        description="Required attributes for objectClass filter.",
    )

    attributes: list[str] | None = Field(
        default=None,
        description="Attributes to filter by presence.",
    )

    base_dn: str | None = Field(
        default=None,
        description="Base DN for hierarchy filtering.",
    )

    mode: str = Field(
        default=FlextLdifConstants.Modes.INCLUDE,
        description="Filter mode: include|exclude",
    )

    match_all: bool = Field(
        default=False,
        description="For attribute filtering: ALL (True) or ANY (False)",
    )

    mark_excluded: bool = Field(
        default=False,
        description="Mark excluded entries in metadata (returns both matched + marked excluded). Default: False (returns only matched).",
    )

    # ════════════════════════════════════════════════════════════════════════
    # PYDANTIC VALIDATORS
    # ════════════════════════════════════════════════════════════════════════

    @field_validator("filter_criteria")
    @classmethod
    def validate_filter_criteria(cls, v: str) -> str:
        """Validate filter_criteria is valid."""
        valid = {"dn", "objectclass", "attributes", "base_dn"}
        if v not in valid:
            msg = f"Invalid filter_criteria: {v!r}. Valid: {', '.join(sorted(valid))}"
            raise ValueError(msg)
        return v

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        """Validate mode is valid."""
        valid = {
            FlextLdifConstants.Modes.INCLUDE,
            FlextLdifConstants.Modes.EXCLUDE,
        }
        if v not in valid:
            msg = f"Invalid mode: {v!r}. Valid: {', '.join(sorted(valid))}"
            raise ValueError(msg)
        return v

    # ════════════════════════════════════════════════════════════════════════
    # CORE EXECUTION (V2 Universal Engine)
    # ════════════════════════════════════════════════════════════════════════

    def execute(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute filtering based on filter_criteria and mode."""
        if not self.entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        try:
            match self.filter_criteria:
                case "dn":
                    return self._filter_by_dn()
                case "objectclass":
                    return self._filter_by_objectclass()
                case "attributes":
                    return self._filter_by_attributes()
                case "base_dn":
                    # base_dn returns tuple, wrap in Result
                    included, _excluded = self._filter_by_base_dn()
                    return FlextResult[list[FlextLdifModels.Entry]].ok(included)
                case _:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Unknown filter_criteria: {self.filter_criteria}"
                    )
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Filter failed: {e}")

    # ════════════════════════════════════════════════════════════════════════
    # PUBLIC API - MINIMAL ESSENTIALS
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def filter(
        cls,
        entries: list[FlextLdifModels.Entry],
        *,
        criteria: str = "dn",
        pattern: str | None = None,
        objectclass: str | tuple[str, ...] | None = None,
        required_attributes: list[str] | None = None,
        attributes: list[str] | None = None,
        base_dn: str | None = None,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        match_all: bool = False,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Quick filter with FlextResult for composable/chainable operations."""
        return cls(
            entries=entries,
            filter_criteria=criteria,
            dn_pattern=pattern,
            objectclass=objectclass,
            required_attributes=required_attributes,
            attributes=attributes,
            base_dn=base_dn,
            mode=mode,
            match_all=match_all,
            mark_excluded=mark_excluded,
        ).execute()

    @classmethod
    def builder(cls) -> FlextLdifFilter:
        """Create fluent builder instance."""
        return cls(entries=[])

    def with_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextLdifFilter:
        """Set entries to filter (fluent builder)."""
        self.entries = entries
        return self

    def with_dn_pattern(self, pattern: str) -> FlextLdifFilter:
        """Set DN pattern filter (fluent builder)."""
        self.filter_criteria = "dn"
        self.dn_pattern = pattern
        return self

    def with_objectclass(self, *classes: str) -> FlextLdifFilter:
        """Set objectClass filter (fluent builder)."""
        self.filter_criteria = "objectclass"
        self.objectclass = classes or None
        return self

    def with_required_attributes(self, attributes: list[str]) -> FlextLdifFilter:
        """Set required attributes (fluent builder)."""
        self.required_attributes = attributes
        return self

    def with_attributes(self, attributes: list[str]) -> FlextLdifFilter:
        """Set attribute filter (fluent builder)."""
        self.filter_criteria = "attributes"
        self.attributes = attributes
        return self

    def with_base_dn(self, base_dn: str) -> FlextLdifFilter:
        """Set base DN filter (fluent builder)."""
        self.filter_criteria = "base_dn"
        self.base_dn = base_dn
        return self

    def with_mode(self, mode: str) -> FlextLdifFilter:
        """Set filter mode: include|exclude (fluent builder)."""
        self.mode = mode
        return self

    def with_match_all(self, *, match_all: bool = True) -> FlextLdifFilter:
        """Set attribute matching: ALL (True) or ANY (False) (fluent builder)."""
        self.match_all = match_all
        return self

    def exclude_matching(self) -> FlextLdifFilter:
        """Invert filter to exclude matching entries (fluent builder)."""
        self.mode = FlextLdifConstants.Modes.EXCLUDE
        return self

    def build(self) -> list[FlextLdifModels.Entry]:
        """Execute and return unwrapped result (fluent terminal)."""
        return self.execute().unwrap()

    # ════════════════════════════════════════════════════════════════════════
    # PUBLIC CLASSMETHOD HELPERS (Direct Entry Points)
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def filter_by_dn(
        cls,
        entries: list[FlextLdifModels.Entry],
        pattern: str,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        *,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by DN pattern."""
        # Delegate to nested Filter class
        return cls.Filter._filter_by_dn(entries, pattern, mode, mark_excluded)

    @classmethod
    def by_dn(
        cls,
        entries: list[FlextLdifModels.Entry],
        pattern: str,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        *,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by DN pattern (alias for filter_by_dn)."""
        return cls.filter_by_dn(entries, pattern, mode, mark_excluded=mark_excluded)

    @classmethod
    def by_objectclass(
        cls,
        entries: list[FlextLdifModels.Entry],
        objectclass: str | tuple[str, ...],
        required_attributes: list[str] | None = None,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        *,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by objectClass."""
        return cls.Filter._filter_by_objectclass(
            entries,
            objectclass,
            required_attributes,
            mode,
            mark_excluded,
        )

    @classmethod
    def by_attributes(
        cls,
        entries: list[FlextLdifModels.Entry],
        attributes: list[str],
        *,
        match_all: bool = False,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by attribute presence."""
        return cls.Filter._filter_by_attributes(
            entries,
            attributes,
            match_all,
            mode,
            mark_excluded,
        )

    @classmethod
    def by_base_dn(
        cls,
        entries: list[FlextLdifModels.Entry],
        base_dn: str,
        *,
        mark_excluded: bool = False,
    ) -> tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]:
        """Filter entries by base DN (hierarchy)."""
        return cls.Filter._filter_by_base_dn(entries, base_dn, mark_excluded)

    @classmethod
    def is_schema(cls, entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is a REAL schema entry with schema definitions."""
        return cls.AclDetector.is_schema(entry)

    @classmethod
    def extract_acl_entries(
        cls,
        entries: list[FlextLdifModels.Entry],
        acl_attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Extract entries with ACL attributes."""
        filter_acl_attrs = acl_attributes or ["acl", "aci", "olcAccess"]

        # Exclude schema entries first
        non_schema_entries = [e for e in entries if not cls.is_schema(e)]

        return cls.by_attributes(
            non_schema_entries,
            filter_acl_attrs,
            match_all=False,
            mode=FlextLdifConstants.Modes.INCLUDE,
            mark_excluded=False,
        )

    @classmethod
    def remove_attributes(
        cls,
        entry: FlextLdifModels.Entry,
        attributes: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove attributes from entry."""
        return cls.Transformer.remove_attributes(entry, attributes)

    @classmethod
    def remove_objectclasses(
        cls,
        entry: FlextLdifModels.Entry,
        objectclasses: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove objectClasses from entry."""
        return cls.Transformer.remove_objectclasses(entry, objectclasses)

    @classmethod
    def categorize(
        cls,
        entry: FlextLdifModels.Entry,
        rules: dict[str, Any],
    ) -> tuple[str, str | None]:
        """Categorize entry into 6 categories.

        Categories (in priority order):
        - schema: Has attributeTypes/objectClasses
        - hierarchy: Containers (organizationalUnit, etc)
        - users: User accounts
        - groups: Group entries
        - acl: Entries with ACL attributes
        - rejected: No match

        Returns:
            Tuple of (category, rejection_reason)

        """
        # Check schema first
        if cls.is_schema(entry):
            return ("schema", None)

        # Parse rules
        hierarchy_classes = tuple(rules.get("hierarchy_objectclasses", []))
        user_classes = tuple(rules.get("user_objectclasses", []))
        group_classes = tuple(rules.get("group_objectclasses", []))
        acl_attributes = rules.get("acl_attributes", ["acl", "aci", "olcAccess"])

        # Check objectClass hierarchy BEFORE ACL (important!)
        if hierarchy_classes and cls.Filter._has_objectclass(entry, hierarchy_classes):
            return ("hierarchy", None)

        # Check users
        if user_classes and cls.Filter._has_objectclass(entry, user_classes):
            return ("users", None)

        # Check groups
        if group_classes and cls.Filter._has_objectclass(entry, group_classes):
            return ("groups", None)

        # Check ACL
        if cls.Filter._has_attributes(entry, acl_attributes, match_any=True):
            return ("acl", None)

        # Rejected
        return ("rejected", "No category match")

    def filter_schema_by_oids(
        self,
        entries: list[FlextLdifModels.Entry],
        allowed_oids: dict[str, list[str]],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter schema entries by allowed OID patterns."""
        if not entries or not allowed_oids:
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        allowed_attr_oids = allowed_oids.get("attributes", [])
        allowed_oc_oids = allowed_oids.get("objectclasses", [])

        filtered = []
        for entry in entries:
            attrs = dict(entry.attributes.attributes)

            # Check attributeTypes using helper
            attr_keys = ["attributeTypes", "attributetypes"]
            has_attr_match = self.AclDetector._matches_oid_pattern(
                attrs, attr_keys, allowed_attr_oids
            )

            # Check objectClasses using helper
            oc_keys = ["objectClasses", "objectclasses"]
            has_oc_match = self.AclDetector._matches_oid_pattern(
                attrs, oc_keys, allowed_oc_oids
            )

            # Keep entry if any pattern matched
            if has_attr_match or has_oc_match:
                filtered.append(entry)

        return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)

    # ════════════════════════════════════════════════════════════════════════
    # PRIVATE IMPLEMENTATION (DRY Core)
    # ════════════════════════════════════════════════════════════════════════

    def _filter_by_dn(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter by DN pattern."""
        if not self.dn_pattern:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "dn_pattern required for dn filter"
            )
        return self.Filter._filter_by_dn(
            self.entries, self.dn_pattern, self.mode, self.mark_excluded
        )

    def _filter_by_objectclass(
        self,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter by objectClass."""
        if not self.objectclass:
            return FlextResult[list[FlextLdifModels.Entry]].fail("objectclass required")
        return self.Filter._filter_by_objectclass(
            self.entries,
            self.objectclass,
            self.required_attributes,
            self.mode,
            self.mark_excluded,
        )

    def _filter_by_attributes(
        self,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter by attribute presence."""
        if not self.attributes:
            return FlextResult[list[FlextLdifModels.Entry]].fail("attributes required")
        return self.Filter._filter_by_attributes(
            self.entries,
            self.attributes,
            self.match_all,
            self.mode,
            self.mark_excluded,
        )

    def _filter_by_base_dn(
        self,
    ) -> tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]:
        """Filter by base DN."""
        if not self.base_dn:
            return (self.entries, [])
        return self.Filter._filter_by_base_dn(
            self.entries, self.base_dn, self.mark_excluded
        )

    def _apply_exclude_filter(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Apply invert/exclude filter logic."""
        try:
            # Store original mode and invert
            original_mode = self.mode
            self.mode = (
                FlextLdifConstants.Modes.EXCLUDE
                if original_mode == FlextLdifConstants.Modes.INCLUDE
                else FlextLdifConstants.Modes.INCLUDE
            )

            # Apply the appropriate filter
            match self.filter_criteria:
                case "dn":
                    result = self._filter_by_dn()
                case "objectclass":
                    result = self._filter_by_objectclass()
                case "attributes":
                    result = self._filter_by_attributes()
                case _:
                    result = FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Cannot exclude with criteria: {self.filter_criteria}"
                    )

            # Restore original mode
            self.mode = original_mode
            return result
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Exclude failed: {e}")


class FlextLdifFilters:
    """Static utility class for backward compatibility and advanced operations.

    This class provides backward-compatible interfaces that delegate to the
    nested classes within FlextLdifFilter. Methods here maintain the same
    signatures as before for compatibility with existing code.

    """

    @staticmethod
    def is_entry_excluded(entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is marked as excluded in metadata."""
        return FlextLdifFilter.Exclusion.is_entry_excluded(entry)

    @staticmethod
    def get_exclusion_reason(entry: FlextLdifModels.Entry) -> str | None:
        """Get exclusion reason from entry metadata."""
        return FlextLdifFilter.Exclusion.get_exclusion_reason(entry)

    @staticmethod
    def _matches_dn_pattern(dn: str, patterns: list[str]) -> bool:
        """Check if DN matches any of the regex patterns."""
        return FlextLdifFilter.Exclusion._matches_dn_pattern(dn, patterns)

    @staticmethod
    def _has_acl_attributes(
        entry: FlextLdifModels.Entry, attributes: list[str]
    ) -> bool:
        """Check if entry has any of the specified ACL attributes."""
        return FlextLdifFilter.AclDetector._has_acl_attributes(entry, attributes)

    @staticmethod
    def _check_blocked_objectclasses(
        entry: FlextLdifModels.Entry,
        whitelist_rules: dict[str, Any] | None,
    ) -> tuple[bool, str | None]:
        """Check if entry has blocked objectClasses."""
        return FlextLdifFilter.Categorizer._check_blocked_objectclasses(
            entry, whitelist_rules
        )

    @staticmethod
    def _validate_category_dn_pattern(
        entry: FlextLdifModels.Entry,
        category: str,
        rules: dict[str, Any],
    ) -> tuple[bool, str | None]:
        """Validate DN pattern for specific category."""
        return FlextLdifFilter.Categorizer._validate_category_dn_pattern(
            entry, category, rules
        )

    @staticmethod
    def categorize_entry(
        entry: FlextLdifModels.Entry,
        rules: dict[str, Any],
        whitelist_rules: dict[str, Any] | None = None,
    ) -> tuple[str, str | None]:
        """Categorize entry into 6 categories.

        Delegates to FlextLdifFilter.categorize, with optional whitelist
        validation.

        """
        # Check for blocked objectClasses first using helper
        is_blocked, reason = FlextLdifFilter.Categorizer._check_blocked_objectclasses(
            entry, whitelist_rules
        )
        if is_blocked:
            return ("rejected", reason)

        # Delegate to FilterService for main categorization
        category, reason = FlextLdifFilter.categorize(entry, rules)

        # Validate DN patterns for category-specific matching using helper
        if category in {"users", "groups"}:
            is_rejected, reject_reason = (
                FlextLdifFilter.Categorizer._validate_category_dn_pattern(
                    entry, category, rules
                )
            )
            if is_rejected:
                return ("rejected", reject_reason)

        return (category, reason)

    @staticmethod
    def filter_entries_by_dn(
        entries: list[FlextLdifModels.Entry],
        pattern: str,
        mode: str = "include",
        *,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by DN pattern."""
        return FlextLdifFilter.filter_by_dn(
            entries, pattern, mode, mark_excluded=mark_excluded
        )

    @staticmethod
    def filter_entries_by_objectclass(
        entries: list[FlextLdifModels.Entry],
        objectclass: str | tuple[str, ...],
        required_attributes: list[str] | None = None,
        mode: str = "include",
        *,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by objectClass."""
        return FlextLdifFilter.by_objectclass(
            entries,
            objectclass,
            required_attributes,
            mode,
            mark_excluded=mark_excluded,
        )

    @staticmethod
    def filter_entries_by_attributes(
        entries: list[FlextLdifModels.Entry],
        attributes: list[str],
        *,
        match_all: bool = False,
        mode: str = "include",
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by attribute presence."""
        return FlextLdifFilter.by_attributes(
            entries,
            attributes,
            match_all=match_all,
            mode=mode,
            mark_excluded=mark_excluded,
        )

    @staticmethod
    def filter_entry_attributes(
        entry: FlextLdifModels.Entry,
        attributes_to_remove: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove specified attributes from entry."""
        return FlextLdifFilter.Transformer.filter_entry_attributes(
            entry, attributes_to_remove
        )

    @staticmethod
    def filter_entry_objectclasses(
        entry: FlextLdifModels.Entry,
        objectclasses_to_remove: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove specified objectClasses from entry."""
        return FlextLdifFilter.Transformer.filter_entry_objectclasses(
            entry, objectclasses_to_remove
        )

    @staticmethod
    def virtual_delete(
        entries: list[FlextLdifModels.Entry],
        filter_criteria: str | None = None,
        dn_pattern: str | None = None,
    ) -> FlextResult[dict[str, list[FlextLdifModels.Entry]]]:
        """Perform virtual (soft) delete - marks entries as deleted."""
        return FlextLdifFilter.Exclusion.virtual_delete(
            entries, filter_criteria, dn_pattern
        )

    @staticmethod
    def restore_virtual_deleted(
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Restore virtually deleted entries back to active state."""
        return FlextLdifFilter.Exclusion.restore_virtual_deleted(entries)


__all__ = ["FlextLdifFilter", "FlextLdifFilters"]
