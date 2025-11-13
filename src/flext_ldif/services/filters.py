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
result = FlextLdifFilters.filter_by_dn(
    entries=my_entries,
    pattern="*,ou=users,dc=example,dc=com",
    mode="include"
)
filtered = result.unwrap()

# Filter by objectClass
result = FlextLdifFilters.filter_by_objectclass(
    entries=my_entries,
    objectclass=("person", "inetOrgPerson"),
    required_attributes=["cn", "mail"]
)

# Filter by attribute presence
result = FlextLdifFilters.filter_by_attributes(
    entries=my_entries,
    attributes=["mail"],
    match_all=False,  # Has ANY attribute
    mode="include"
)

# PATTERN 2: Classmethod for Composable/Chainable Operations
──────────────────────────────────────────────────────────────
result = (
    FlextLdifFilters.filter(
        entries=my_entries,
        criteria="dn",
        pattern="*,ou=users,*"
    )
    .map(lambda e: e[:10])  # Take first 10
    .and_then(lambda e: FlextLdifFilters.filter(e, criteria="objectclass", objectclass="person"))
)

# PATTERN 3: Fluent Builder Pattern
───────────────────────────────────
filtered_result = (
    FlextLdifFilters.builder()
    .with_entries(my_entries)
    .with_dn_pattern("*,ou=users,dc=example,dc=com")
    .with_objectclass("person")
    .with_required_attributes(["cn", "mail"])
    .build()  # Returns list[Entry] directly
)

# PATTERN 4: Public Classmethod Helpers (Most Direct)
────────────────────────────────────────────────────
# Filter by DN pattern
result = FlextLdifFilters.by_dn(entries, "*,ou=users,*")
filtered = result.unwrap()

# Filter by objectClass
result = FlextLdifFilters.by_objectclass(
    entries, ("person", "inetOrgPerson")
)

# Filter by attributes
result = FlextLdifFilters.by_attributes(
    entries, ["mail"], match_all=False
)

# Filter by base DN
included, excluded = FlextLdifFilters.by_base_dn(
    entries, "dc=example,dc=com"
)

# Extract ACL entries
result = FlextLdifFilters.extract_acl_entries(entries)

# Categorize entry
category, reason = FlextLdifFilters.categorize(entry, rules)

# PATTERN 5: Transformation (Remove Attributes/ObjectClasses)
──────────────────────────────────────────────────────────────
# Remove temporary attributes
result = FlextLdifFilters.remove_attributes(
    entry=my_entry,
    attributes=["tempAttribute", "debugInfo"]
)

# Remove unwanted objectClasses
result = FlextLdifFilters.remove_objectclasses(
    entry=my_entry,
    objectclasses=["temporaryClass"]
)

# PATTERN 6: Schema & Advanced Operations
───────────────────────────────────────────
# Check if entry is schema
is_schema = FlextLdifFilters.is_schema(entry)

# Filter schema by OID whitelist
result = FlextLdifFilters.filter_schema_by_oids(
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
result = FlextLdifFilters.by_dn(entries, "*,ou=users,*")
filtered = result.unwrap()

# Filter by objectClass
result = FlextLdifFilters.by_objectclass(
    entries, ("person", "inetOrgPerson")
)

# Combine multiple conditions (builder)
filtered_result = (
    FlextLdifFilters.builder()
    .with_entries(entries)
    .with_dn_pattern("*,ou=users,*")
    .with_objectclass("person")
    .build()
)

# Check if schema entry
is_schema = FlextLdifFilters.is_schema(entry)

# Extract ACL entries
result = FlextLdifFilters.extract_acl_entries(entries)
acl_entries = result.unwrap()

# Categorize entry
category, reason = FlextLdifFilters.categorize(entry, rules)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import fnmatch
import re
import time
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, cast

from flext_core import FlextResult, FlextService
from pydantic import Field, PrivateAttr, ValidationError, field_validator

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifFilters(FlextService[FlextLdifModels.EntryResult]):
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
    # INTERNAL NORMALIZATION HELPERS
    # ════════════════════════════════════════════════════════════════════════
    @staticmethod
    def _ensure_str_list(value: object) -> list[str]:
        """Ensure configuration values are normalized to list[str]."""
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            return [item for item in value if isinstance(item, str)]
        return []

    @staticmethod
    def _normalize_category_rules(
        rules: FlextLdifModels.CategoryRules | Mapping[str, object] | None,
    ) -> FlextResult[FlextLdifModels.CategoryRules]:
        """Coerce dict inputs into CategoryRules models (backwards compatibility)."""
        if isinstance(rules, FlextLdifModels.CategoryRules):
            return FlextResult.ok(rules)

        if rules is None:
            return FlextResult.ok(FlextLdifModels.CategoryRules())

        if not isinstance(rules, Mapping):
            return FlextResult.fail(
                "Category rules must be a mapping or CategoryRules model"
            )

        normalized: dict[str, list[str]] = {}

        # Consolidate field normalization into loop (reduces cyclomatic complexity)
        fields = [
            "user_dn_patterns",
            "group_dn_patterns",
            "hierarchy_dn_patterns",
            "schema_dn_patterns",
            "user_objectclasses",
            "group_objectclasses",
            "hierarchy_objectclasses",
        ]
        for field in fields:
            if field in rules:
                normalized[field] = FlextLdifFilters._ensure_str_list(
                    rules.get(field),
                )

        try:
            return FlextResult.ok(
                FlextLdifModels.CategoryRules.model_validate(
                    normalized,
                ),
            )
        except ValidationError as exc:
            return FlextResult.fail(
                f"Invalid category rules: {exc.errors(include_context=False)}"
            )

    @staticmethod
    def _normalize_whitelist_rules(
        rules: FlextLdifModels.WhitelistRules | Mapping[str, object] | None,
    ) -> FlextResult[FlextLdifModels.WhitelistRules]:
        """Coerce dict inputs into WhitelistRules models (backwards compatibility)."""
        if isinstance(rules, FlextLdifModels.WhitelistRules):
            return FlextResult.ok(rules)

        if rules is None:
            return FlextResult.ok(FlextLdifModels.WhitelistRules())

        if not isinstance(rules, Mapping):
            return FlextResult.fail(
                "Whitelist rules must be a mapping or WhitelistRules model"
            )

        normalized = {
            "blocked_objectclasses": FlextLdifFilters._ensure_str_list(
                rules.get("blocked_objectclasses"),
            ),
            "allowed_objectclasses": FlextLdifFilters._ensure_str_list(
                rules.get("allowed_objectclasses"),
            ),
        }

        try:
            return FlextResult.ok(
                FlextLdifModels.WhitelistRules.model_validate(normalized),
            )
        except ValidationError as exc:
            return FlextResult.fail(
                f"Invalid whitelist rules: {exc.errors(include_context=False)}"
            )

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
        def filter_by_dn(
            entries: list[FlextLdifModels.Entry],
            dn_pattern: str,
            mode: str,
            *,
            mark_excluded: bool,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Filter entries by DN pattern."""
            try:
                pattern = dn_pattern  # Type narrowing
                filtered = []
                for entry in entries:
                    # Use DN utility to get string value (supports both DN model and str)
                    entry_dn_str = FlextLdifUtilities.DN.get_dn_value(entry.dn)
                    matches = fnmatch.fnmatch(entry_dn_str.lower(), pattern.lower())
                    include = (
                        mode == FlextLdifConstants.Modes.INCLUDE and matches
                    ) or (mode == FlextLdifConstants.Modes.EXCLUDE and not matches)

                    if include:
                        filtered.append(entry)
                    elif mark_excluded:
                        filtered.append(
                            FlextLdifFilters.Exclusion.mark_excluded(
                                entry,
                                f"DN pattern: {dn_pattern}",
                            ),
                        )

                return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
            except Exception as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"DN filter failed: {e}",
                )

        @staticmethod
        def filter_by_objectclass(
            entries: list[FlextLdifModels.Entry],
            objectclass: str | tuple[str, ...],
            required_attributes: list[str] | None,
            mode: str,
            *,
            mark_excluded: bool,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Filter by objectClass using functional composition."""

            def normalize_objectclass(oc: str | tuple[str, ...]) -> tuple[str, ...]:
                """Normalize objectclass to tuple."""
                return oc if isinstance(oc, tuple) else (oc,)

            def matches_entry(
                entry: FlextLdifModels.Entry, oc_tuple: tuple[str, ...]
            ) -> bool:
                """Check if entry matches objectclass filter."""
                has_oc = FlextLdifFilters.Filter.has_objectclass(entry, oc_tuple)
                if not has_oc or not required_attributes:
                    return has_oc

                has_attrs = FlextLdifFilters.Filter.has_attributes(
                    entry, required_attributes, match_any=False
                )
                return has_oc and has_attrs

            def should_include(*, matches: bool, filter_mode: str) -> bool:
                """Determine if entry should be included based on mode."""
                return (
                    filter_mode == FlextLdifConstants.Modes.INCLUDE and matches
                ) or (filter_mode == FlextLdifConstants.Modes.EXCLUDE and not matches)

            def process_entry(
                entry: FlextLdifModels.Entry,
                oc_tuple: tuple[str, ...],
                filter_mode: str,
            ) -> FlextLdifModels.Entry | None:
                """Process single entry with filtering logic."""
                entry_matches = matches_entry(entry, oc_tuple)
                if should_include(matches=entry_matches, filter_mode=filter_mode):
                    return entry
                if mark_excluded:
                    return FlextLdifFilters.Exclusion.mark_excluded(
                        entry, f"ObjectClass filter: {oc_tuple}"
                    )
                # Return None to indicate exclusion (will be filtered out)
                return None

            try:
                # Functional composition: normalize -> filter -> clean
                oc_tuple = normalize_objectclass(objectclass)

                filtered_entries = [
                    processed
                    for entry in entries
                    if (processed := process_entry(entry, oc_tuple, mode)) is not None
                ]

                return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

            except Exception as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"ObjectClass filter failed: {e}",
                )

        @staticmethod
        def filter_by_attributes(
            entries: list[FlextLdifModels.Entry],
            attributes: list[str],
            *,
            match_all: bool,
            mode: str,
            mark_excluded: bool,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Filter by attribute presence using functional composition."""

            def matches_attributes(
                entry: FlextLdifModels.Entry, attrs: list[str]
            ) -> bool:
                """Check if entry matches attribute filter."""
                return FlextLdifFilters.Filter.has_attributes(
                    entry, attrs, match_any=not match_all
                )

            def should_include_attribute(*, matches: bool, filter_mode: str) -> bool:
                """Determine inclusion based on mode."""
                return (
                    filter_mode == FlextLdifConstants.Modes.INCLUDE and matches
                ) or (filter_mode == FlextLdifConstants.Modes.EXCLUDE and not matches)

            def process_attribute_entry(
                entry: FlextLdifModels.Entry, attrs: list[str], filter_mode: str
            ) -> FlextLdifModels.Entry | None:
                """Process single entry for attribute filtering."""
                entry_matches = matches_attributes(entry, attrs)
                if should_include_attribute(
                    matches=entry_matches, filter_mode=filter_mode
                ):
                    return entry
                if mark_excluded:
                    return FlextLdifFilters.Exclusion.mark_excluded(
                        entry, f"Attribute filter: {attributes}"
                    )
                return None

            try:
                # Functional composition with list comprehension
                filtered_entries = [
                    processed
                    for entry in entries
                    if (processed := process_attribute_entry(entry, attributes, mode))
                    is not None
                ]

                return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

            except Exception as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Attribute filter failed: {e}",
                )

        @staticmethod
        def filter_by_base_dn(
            entries: list[FlextLdifModels.Entry],
            base_dn: str,
            *,
            mark_excluded: bool,
        ) -> tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]:
            """Filter by base DN.

            Uses FlextLdifUtilities.DN.is_under_base() for DN hierarchy check.
            """
            included = []
            excluded = []

            for entry in entries:
                # Use utility for consistent DN comparison (now supports DN models)
                dn_str = entry.dn.value if entry.dn else None
                if FlextLdifUtilities.DN.is_under_base(dn_str, base_dn):
                    included.append(entry)
                elif mark_excluded:
                    excluded.append(
                        FlextLdifFilters.Exclusion.mark_excluded(
                            entry,
                            f"Base DN: {base_dn}",
                        ),
                    )
                else:
                    excluded.append(entry)

            return (included, excluded)

        @staticmethod
        def has_objectclass(
            entry: FlextLdifModels.Entry,
            objectclasses: tuple[str, ...],
        ) -> bool:
            """Check if entry has any of the objectClasses.

            Uses FlextLdifUtilities.Entry.has_objectclass() for consistent logic.
            """
            return FlextLdifUtilities.Entry.has_objectclass(entry, objectclasses)

        @staticmethod
        def has_attributes(
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
        def check_blocked_objectclasses(
            entry: FlextLdifModels.Entry,
            whitelist_rules: FlextLdifModels.WhitelistRules
            | Mapping[str, object]
            | None,
        ) -> tuple[bool, str | None]:
            """Check if entry has blocked objectClasses.

            Uses type-safe WhitelistRules model instead of dict[str, Any].
            """
            rules_result = FlextLdifFilters._normalize_whitelist_rules(whitelist_rules)
            if rules_result.is_failure:
                return (True, rules_result.error)

            rules_model = rules_result.unwrap()

            blocked_ocs = rules_model.blocked_objectclasses
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
        def validate_category_dn_pattern(
            entry: FlextLdifModels.Entry,
            category: str,
            rules: FlextLdifModels.CategoryRules | Mapping[str, object] | None,
        ) -> tuple[bool, str | None]:
            """Validate DN pattern for specific category.

            Uses type-safe CategoryRules model instead of dict[str, Any].
            """
            rules_result = FlextLdifFilters._normalize_category_rules(rules)
            if rules_result.is_failure:
                return (True, rules_result.error)
            normalized_rules = rules_result.unwrap()

            # Map category to pattern attribute
            pattern_map = {
                "users": normalized_rules.user_dn_patterns,
                "groups": normalized_rules.group_dn_patterns,
                "hierarchy": normalized_rules.hierarchy_dn_patterns,
                "schema": normalized_rules.schema_dn_patterns,
            }

            dn_patterns = pattern_map.get(category, [])
            if not dn_patterns:
                return (False, None)

            try:
                if not FlextLdifFilters.Exclusion.matches_dn_pattern(
                    entry.dn,
                    dn_patterns,
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
                ).map(lambda e: cast("FlextLdifModels.Entry", e))
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to remove attributes: {e}",
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
                    FlextLdifConstants.DictKeys.OBJECTCLASS,
                )
                if not oc_values:
                    return FlextResult[FlextLdifModels.Entry].ok(entry)

                filtered_ocs = [
                    oc for oc in oc_values if oc.lower() not in blocked_lower
                ]
                if not filtered_ocs:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        "All objectClasses would be removed",
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
                ).map(lambda e: cast("FlextLdifModels.Entry", e))
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to remove objectClasses: {e}",
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
                attrs_result = FlextLdifModels.LdifAttributes.create(
                    cast("dict[str, object]", filtered_attrs),
                )
                if not attrs_result.is_success:
                    return FlextResult[FlextLdifModels.Entry].fail(attrs_result.error)

                new_entry = entry.model_copy(
                    update={"attributes": attrs_result.unwrap()},
                )
                return FlextResult[FlextLdifModels.Entry].ok(new_entry)

            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Filter attributes failed: {e}",
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
                        "All objectClasses would be removed",
                    )

                # Create filtered attributes dict
                filtered_attrs = dict(entry.attributes.attributes)
                filtered_attrs["objectClass"] = filtered_ocs

                # Create new LdifAttributes
                attrs_result = FlextLdifModels.LdifAttributes.create(
                    cast("dict[str, object]", filtered_attrs),
                )
                if not attrs_result.is_success:
                    return FlextResult[FlextLdifModels.Entry].fail(attrs_result.error)

                new_entry = entry.model_copy(
                    update={"attributes": attrs_result.unwrap()},
                )
                return FlextResult[FlextLdifModels.Entry].ok(new_entry)

            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Filter objectClasses failed: {e}",
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
            return FlextLdifUtilities.Entry.is_schema_entry(entry, strict=False)

        @staticmethod
        def has_acl_attributes(
            entry: FlextLdifModels.Entry,
            attributes: list[str],
        ) -> bool:
            """Check if entry has any of the specified ACL attributes."""
            if not attributes:
                return False

            # Type annotation to help pyrefly understand attr is str
            attrs_keys: list[str] = entry.attributes.keys()
            entry_attrs_lower = {attr.lower() for attr in attrs_keys}
            return any(attr.lower() in entry_attrs_lower for attr in attributes)

        @staticmethod
        def matches_oid_pattern(
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
                    # Test each pattern individually (fnmatch doesn't understand |)
                    for pattern in allowed_oids:
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
        def mark_excluded(
            entry: FlextLdifModels.Entry,
            reason: str,
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
            if not FlextLdifFilters.Exclusion.is_entry_excluded(entry):
                return None

            reason = exclusion_info.get("exclusion_reason")
            return reason if isinstance(reason, str) else None

        @staticmethod
        def matches_dn_pattern(dn: str | object, patterns: list[str]) -> bool:
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
            dn_str = (
                FlextLdifUtilities.DN.get_dn_value(dn)
                if isinstance(dn, (str, FlextLdifModels.DistinguishedName))
                else str(dn)
            )

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
                        should_delete = FlextLdifFilters.Exclusion.matches_dn_pattern(
                            entry.dn,
                            [dn_pattern],
                        )

                    if should_delete:
                        # Mark as virtually deleted (non-destructive)
                        entry_dict = entry.model_dump()
                        entry_dict["metadata"] = entry_dict.get("metadata", {})
                        if isinstance(entry_dict["metadata"], dict):
                            entry_dict["metadata"]["virtual_deleted"] = True
                            entry_dict["metadata"]["deletion_timestamp"] = datetime.now(
                                UTC,
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
                    f"Virtual delete failed: {e}",
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
                    f"Restore virtual deleted failed: {e}",
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

    # Private attributes (Pydantic v2 PrivateAttr for internal state)
    _last_event: FlextLdifModels.FilterEvent | None = PrivateAttr(default=None)

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

    def _execute_dn_filter(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute DN pattern filter."""
        if self.dn_pattern is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "dn_pattern is required for dn filter"
            )
        return self.filter_by_dn(
            self.entries,
            self.dn_pattern,
            self.mode,
            mark_excluded=self.mark_excluded,
        )

    def _execute_objectclass_filter(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute objectClass filter."""
        if self.objectclass is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "objectclass is required for objectclass filter"
            )
        return self.filter_by_objectclass(
            self.entries,
            self.objectclass,
            self.required_attributes,
            self.mode,
            mark_excluded=self.mark_excluded,
        )

    def _execute_attributes_filter(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute attributes filter."""
        if self.attributes is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "attributes is required for attributes filter"
            )
        return self.filter_by_attributes(
            self.entries,
            self.attributes,
            match_all=self.match_all,
            mode=self.mode,
            mark_excluded=self.mark_excluded,
        )

    def _execute_base_dn_filter(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute base DN filter."""
        if self.base_dn is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "base_dn is required for base_dn filter"
            )
        included, _excluded = self.filter_by_base_dn(
            self.entries,
            self.base_dn,
        )
        return FlextResult[list[FlextLdifModels.Entry]].ok(included)

    def execute(self) -> FlextResult[FlextLdifModels.EntryResult]:
        """Execute filtering based on filter_criteria and mode."""
        if not self.entries:
            return FlextResult[FlextLdifModels.EntryResult].ok(
                cast("FlextLdifModels.EntryResult", FlextLdifModels.EntryResult.empty())
            )

        # Track filtering metrics (MANDATORY - eventos obrigatórios)
        start_time = time.perf_counter()
        entries_before = len(self.entries)

        try:
            match self.filter_criteria:
                case "dn":
                    result = self._execute_dn_filter()
                case "objectclass":
                    result = self._execute_objectclass_filter()
                case "attributes":
                    result = self._execute_attributes_filter()
                case "base_dn":
                    result = self._execute_base_dn_filter()
                case _:
                    return FlextResult[FlextLdifModels.EntryResult].fail(
                        f"Unknown filter_criteria: {self.filter_criteria}",
                    )

            # Emit FilterEvent ALWAYS when filtering succeeded (MANDATORY - eventos obrigatórios)
            if result.is_success:
                filtered_entries = result.unwrap()
                filter_duration_ms = (time.perf_counter() - start_time) * 1000.0
                entries_after = len(filtered_entries)

                filter_event = FlextLdifModels.FilterEvent(
                    unique_id=f"filter_{uuid.uuid4().hex[:8]}",
                    event_type="ldif.filter",
                    aggregate_id=f"filter_{uuid.uuid4().hex[:8]}",
                    created_at=datetime.now(UTC),
                    filter_operation=f"filter_by_{self.filter_criteria}",
                    entries_before=entries_before,
                    entries_after=entries_after,
                    filter_criteria=[
                        {
                            "type": self.filter_criteria,
                            "pattern": self.dn_pattern,
                            "objectclass": str(self.objectclass)
                            if self.objectclass
                            else None,
                            "attributes": self.attributes,
                            "base_dn": self.base_dn,
                            "mode": self.mode,
                        }
                    ],
                    filter_duration_ms=filter_duration_ms,
                )
                # Store event for retrieval via get_last_event()
                self._last_event = filter_event

                # Wrap filtered entries in EntryResult for API consistency
                # Cast public Entry type to internal domain Entry type
                entry_result = FlextLdifModels.EntryResult.from_entries(
                    cast(
                        "list[FlextLdifModelsDomains.Entry]",
                        filtered_entries,
                    )
                )
                return FlextResult[FlextLdifModels.EntryResult].ok(
                    cast("FlextLdifModels.EntryResult", entry_result)
                )

            # If result is failure, propagate the error
            return FlextResult[FlextLdifModels.EntryResult].fail(result.error)

        except Exception as e:
            return FlextResult[FlextLdifModels.EntryResult].fail(f"Filter failed: {e}")

    def get_last_event(self) -> FlextLdifModels.FilterEvent | None:
        """Retrieve last emitted FilterEvent.

        Returns:
            Last FilterEvent if enable_events=True and execute() was called, None otherwise.

        Note:
            This is a workaround for current architecture limitations.
            Prefer using EntryResult-based APIs when available.

        """
        return self._last_event

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
    ) -> FlextResult[FlextLdifModels.EntryResult]:
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
    def builder(cls) -> FlextLdifFilters:
        """Create fluent builder instance."""
        return cls(entries=[])

    def with_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextLdifFilters:
        """Set entries to filter (fluent builder)."""
        self.entries = entries
        return self

    def with_dn_pattern(self, pattern: str) -> FlextLdifFilters:
        """Set DN pattern filter (fluent builder)."""
        self.filter_criteria = "dn"
        self.dn_pattern = pattern
        return self

    def with_objectclass(self, *classes: str) -> FlextLdifFilters:
        """Set objectClass filter (fluent builder)."""
        self.filter_criteria = "objectclass"
        self.objectclass = classes or None
        return self

    def with_required_attributes(self, attributes: list[str]) -> FlextLdifFilters:
        """Set required attributes (fluent builder)."""
        self.required_attributes = attributes
        return self

    def with_attributes(self, attributes: list[str]) -> FlextLdifFilters:
        """Set attribute filter (fluent builder)."""
        self.filter_criteria = "attributes"
        self.attributes = attributes
        return self

    def with_base_dn(self, base_dn: str) -> FlextLdifFilters:
        """Set base DN filter (fluent builder)."""
        self.filter_criteria = "base_dn"
        self.base_dn = base_dn
        return self

    def with_mode(self, mode: str) -> FlextLdifFilters:
        """Set filter mode: include|exclude (fluent builder)."""
        self.mode = mode
        return self

    def with_match_all(self, *, match_all: bool = True) -> FlextLdifFilters:
        """Set attribute matching: ALL (True) or ANY (False) (fluent builder)."""
        self.match_all = match_all
        return self

    def exclude_matching(self) -> FlextLdifFilters:
        """Invert filter to exclude matching entries (fluent builder)."""
        self.mode = FlextLdifConstants.Modes.EXCLUDE
        return self

    def build(self) -> FlextLdifModels.EntryResult:
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
        return cls.Filter.filter_by_dn(
            entries, pattern, mode, mark_excluded=mark_excluded
        )

    @classmethod
    def filter_by_objectclass(
        cls,
        entries: list[FlextLdifModels.Entry],
        objectclass: str | tuple[str, ...],
        required_attributes: list[str] | None = None,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        *,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by objectClass."""
        return cls.Filter.filter_by_objectclass(
            entries,
            objectclass,
            required_attributes,
            mode,
            mark_excluded=mark_excluded,
        )

    @classmethod
    def filter_by_attributes(
        cls,
        entries: list[FlextLdifModels.Entry],
        attributes: list[str],
        *,
        match_all: bool = False,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by attribute presence."""
        return cls.Filter.filter_by_attributes(
            entries,
            attributes,
            match_all=match_all,
            mode=mode,
            mark_excluded=mark_excluded,
        )

    @classmethod
    def filter_by_base_dn(
        cls,
        entries: list[FlextLdifModels.Entry],
        base_dn: str,
        *,
        mark_excluded: bool = False,
    ) -> tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]:
        """Filter entries by base DN (hierarchy)."""
        return cls.Filter.filter_by_base_dn(
            entries, base_dn, mark_excluded=mark_excluded
        )

    @classmethod
    def by_dn(
        cls,
        entries: list[FlextLdifModels.Entry],
        pattern: str,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        *,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by DN pattern (alias for filter_entries_by_dn)."""
        return cls.filter_entries_by_dn(
            entries, pattern, mode, mark_excluded=mark_excluded
        )

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
        return cls.Filter.filter_by_objectclass(
            entries,
            objectclass,
            required_attributes,
            mode,
            mark_excluded=mark_excluded,
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
        return cls.Filter.filter_by_attributes(
            entries,
            attributes,
            match_all=match_all,
            mode=mode,
            mark_excluded=mark_excluded,
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
        return cls.Filter.filter_by_base_dn(
            entries, base_dn, mark_excluded=mark_excluded
        )

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
        rules: FlextLdifModels.CategoryRules | Mapping[str, object] | None,
    ) -> tuple[str, str | None]:
        """Categorize entry into 6 categories.

        Uses type-safe CategoryRules model instead of dict[str, Any].

        Categories (in priority order):
        - schema: Has attributeTypes/objectClasses
        - users: User accounts (person, inetOrgPerson, orcluser)
        - groups: Group entries (groupOfUniqueNames, orclgroup)
        - hierarchy: Containers (organizationalUnit, etc)
        - acl: Entries with ACL attributes
        - rejected: No match

        Returns:
            Tuple of (category, rejection_reason)

        """
        rules_result = cls._normalize_category_rules(rules)
        if rules_result.is_failure:
            return ("rejected", rules_result.error)
        normalized_rules = rules_result.unwrap()

        # Check schema first
        if cls.is_schema(entry):
            return ("schema", None)

        # Get objectClasses from CategoryRules model
        hierarchy_classes = tuple(normalized_rules.hierarchy_objectclasses)
        user_classes = tuple(normalized_rules.user_objectclasses)
        group_classes = tuple(normalized_rules.group_objectclasses)

        # Check users FIRST
        if user_classes and cls.Filter.has_objectclass(entry, user_classes):
            return ("users", None)

        # Check groups SECOND (BEFORE hierarchy - prevents misclassification)
        if group_classes and cls.Filter.has_objectclass(entry, group_classes):
            return ("groups", None)

        # Check hierarchy AFTER groups
        if hierarchy_classes and cls.Filter.has_objectclass(entry, hierarchy_classes):
            return ("hierarchy", None)

        # Check ACL (default ACL attributes - can be made configurable later)
        acl_attributes = ["acl", "aci", "olcAccess"]
        if cls.Filter.has_attributes(entry, acl_attributes, match_any=True):
            return ("acl", None)

        # Rejected
        return ("rejected", "No category match")

    @staticmethod
    def _extract_allowed_oids(
        allowed_oids: dict[str, list[str]],
    ) -> tuple[list[str], ...]:
        """Extract allowed OIDs for each schema type from config dict."""
        allowed_attr_oids = (
            allowed_oids.get("allowed_attribute_oids")
            or allowed_oids.get("attributes")
            or []
        )
        allowed_oc_oids = (
            allowed_oids.get("allowed_objectclass_oids")
            or allowed_oids.get("objectclasses")
            or []
        )
        allowed_mr_oids = (
            allowed_oids.get("allowed_matchingrule_oids")
            or allowed_oids.get("matchingrules")
            or []
        )
        allowed_mru_oids = (
            allowed_oids.get("allowed_matchingruleuse_oids")
            or allowed_oids.get("matchingruleuse")
            or []
        )
        return allowed_attr_oids, allowed_oc_oids, allowed_mr_oids, allowed_mru_oids

    @classmethod
    def _filter_schema_attribute(
        cls,
        attrs_copy: dict[str, list[str]],
        attr_names: tuple[str, str],
        allowed_oids: list[str],
    ) -> None:
        """Filter a single schema attribute type in-place.

        Args:
            attrs_copy: Dictionary of attributes to modify
            attr_names: Tuple of (capitalized_name, lowercase_name)
            allowed_oids: List of allowed OID patterns

        """
        cap_name, low_name = attr_names
        if cap_name in attrs_copy or low_name in attrs_copy:
            key = cap_name if cap_name in attrs_copy else low_name
            filtered = cls._filter_definitions(attrs_copy[key], allowed_oids)
            attrs_copy[key] = filtered

    @staticmethod
    def _has_remaining_definitions(attrs_copy: dict[str, list[str]]) -> bool:
        """Check if entry has any schema definitions remaining after filtering."""
        return any([
            attrs_copy.get("attributeTypes") or attrs_copy.get("attributetypes"),
            attrs_copy.get("objectClasses") or attrs_copy.get("objectclasses"),
            attrs_copy.get("matchingRules") or attrs_copy.get("matchingrules"),
            attrs_copy.get("matchingRuleUse") or attrs_copy.get("matchingruleuse"),
        ])

    @classmethod
    def filter_schema_by_oids(
        cls,
        entries: list[FlextLdifModels.Entry],
        allowed_oids: dict[str, list[str]],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter schema entries by allowed OID patterns.

        Filters INDIVIDUAL DEFINITIONS within schema attributes (attributeTypes,
        objectClasses, matchingRules, matchingRuleUse) to keep only those with
        OIDs matching the allowed patterns.

        Key improvement: Instead of filtering entire entries based on whether they
        contain ANY whitelisted OID, this method filters the DEFINITIONS WITHIN
        each attribute to keep only whitelisted ones.
        """
        if not entries or not allowed_oids:
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        # Extract allowed OIDs for each schema type
        allowed_attr_oids, allowed_oc_oids, allowed_mr_oids, allowed_mru_oids = (
            cls._extract_allowed_oids(allowed_oids)
        )

        filtered = []
        for entry in entries:
            attrs_copy = dict(entry.attributes.attributes)

            # Filter each schema type
            cls._filter_schema_attribute(
                attrs_copy, ("attributeTypes", "attributetypes"), allowed_attr_oids
            )
            cls._filter_schema_attribute(
                attrs_copy, ("objectClasses", "objectclasses"), allowed_oc_oids
            )
            cls._filter_schema_attribute(
                attrs_copy, ("matchingRules", "matchingrules"), allowed_mr_oids
            )
            cls._filter_schema_attribute(
                attrs_copy, ("matchingRuleUse", "matchingruleuse"), allowed_mru_oids
            )

            # Only keep entry if it has definitions remaining after filtering
            if cls._has_remaining_definitions(attrs_copy):
                # Create new entry with filtered attributes
                # Cast attrs_copy to match Entry.create signature
                attributes_typed = cast("dict[str, list[str] | str]", attrs_copy)
                filtered_entry_result = FlextLdifModels.Entry.create(
                    dn=entry.dn.value,
                    attributes=attributes_typed,
                    entry_metadata=entry.entry_metadata
                    if hasattr(entry, "entry_metadata")
                    else None,
                )
                if filtered_entry_result.is_success:
                    filtered.append(
                        cast("FlextLdifModels.Entry", filtered_entry_result.unwrap())
                    )

        return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)

    @staticmethod
    def _filter_definitions(
        definitions: list[str] | str,
        allowed_oids: list[str],
    ) -> list[str]:
        """Filter individual schema definitions by OID patterns and sort by OID.

        Keeps only definitions whose OIDs match one of the allowed patterns.
        Results are sorted by OID for consistent output.

        Args:
            definitions: List of schema definitions or single definition string
            allowed_oids: List of allowed OID patterns (supports wildcards like "99.*")
                         Empty list means NO definitions are allowed (strict filtering)

        Returns:
            List of filtered definitions matching allowed OIDs, sorted by OID.
            Returns empty list if allowed_oids is empty.

        """
        if isinstance(definitions, str):
            definitions = [definitions]

        # If no allowed OIDs, return empty list (nothing is allowed)
        if not allowed_oids:
            return []

        if not definitions:
            return []

        filtered = []
        for definition in definitions:
            # Extract OID from definition (first OID in parentheses)
            oid = (
                FlextLdifUtilities.OID.extract_from_definition(definition) or definition
            )

            # Check if OID matches any allowed pattern
            for pattern in allowed_oids:
                if fnmatch.fnmatch(oid, pattern):
                    filtered.append(definition)
                    break  # Found a match, no need to check other patterns

        # Sort filtered results by OID
        return sorted(
            filtered,
            key=lambda d: FlextLdifUtilities.OID.extract_from_definition(d) or d,
        )

    # ════════════════════════════════════════════════════════════════════════
    # PRIVATE IMPLEMENTATION (DRY Core)
    # ════════════════════════════════════════════════════════════════════════

    def _execute_filter_by_dn(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter by DN pattern."""
        if not self.dn_pattern:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "dn_pattern required for dn filter",
            )
        return self.Filter.filter_by_dn(
            self.entries,
            self.dn_pattern,
            self.mode,
            mark_excluded=self.mark_excluded,
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
                    if self.dn_pattern is None:
                        result = FlextResult[list[FlextLdifModels.Entry]].fail(
                            "dn_pattern is required"
                        )
                    else:
                        result = self.filter_by_dn(
                            self.entries,
                            self.dn_pattern,
                            self.mode,
                            mark_excluded=self.mark_excluded,
                        )
                case "objectclass":
                    if self.objectclass is None:
                        result = FlextResult[list[FlextLdifModels.Entry]].fail(
                            "objectclass is required"
                        )
                    else:
                        result = self.filter_by_objectclass(
                            self.entries,
                            self.objectclass,
                            self.required_attributes,
                            self.mode,
                            mark_excluded=self.mark_excluded,
                        )
                case "attributes":
                    if self.attributes is None:
                        result = FlextResult[list[FlextLdifModels.Entry]].fail(
                            "attributes is required"
                        )
                    else:
                        result = self.filter_by_attributes(
                            self.entries,
                            self.attributes,
                            match_all=self.match_all,
                            mode=self.mode,
                            mark_excluded=self.mark_excluded,
                        )
                case _:
                    result = FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Cannot exclude with criteria: {self.filter_criteria}",
                    )

            # Restore original mode
            self.mode = original_mode
            return result
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Exclude failed: {e}")

    @staticmethod
    def is_entry_excluded(entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is marked as excluded in metadata."""
        return FlextLdifFilters.Exclusion.is_entry_excluded(entry)

    @staticmethod
    def get_exclusion_reason(entry: FlextLdifModels.Entry) -> str | None:
        """Get exclusion reason from entry metadata."""
        return FlextLdifFilters.Exclusion.get_exclusion_reason(entry)

    @staticmethod
    def matches_dn_pattern(dn: str, patterns: list[str]) -> bool:
        """Check if DN matches any of the regex patterns."""
        return FlextLdifFilters.Exclusion.matches_dn_pattern(dn, patterns)

    @staticmethod
    def has_acl_attributes(
        entry: FlextLdifModels.Entry,
        attributes: list[str],
    ) -> bool:
        """Check if entry has any of the specified ACL attributes."""
        return FlextLdifFilters.AclDetector.has_acl_attributes(entry, attributes)

    @staticmethod
    def check_blocked_objectclasses(
        entry: FlextLdifModels.Entry,
        whitelist_rules: FlextLdifModels.WhitelistRules | dict[str, list[str]] | None,
    ) -> tuple[bool, str | None]:
        """Check if entry has blocked objectClasses.

        Accepts WhitelistRules model or dict for backward compatibility.
        """
        # Convert dict to model if needed
        if isinstance(whitelist_rules, dict):
            rules_model = FlextLdifModels.WhitelistRules(**whitelist_rules)
        elif whitelist_rules is None:
            rules_model = None
        else:
            rules_model = whitelist_rules

        return FlextLdifFilters.Categorizer.check_blocked_objectclasses(
            entry,
            rules_model,
        )

    @staticmethod
    def validate_category_dn_pattern(
        entry: FlextLdifModels.Entry,
        category: str,
        rules: FlextLdifModels.CategoryRules | dict[str, list[str]],
    ) -> tuple[bool, str | None]:
        """Validate DN pattern for specific category.

        Accepts CategoryRules model or dict for backward compatibility.
        """
        # Convert dict to model if needed
        if isinstance(rules, dict):
            rules_model = FlextLdifModels.CategoryRules(**rules)
        else:
            rules_model = rules

        return FlextLdifFilters.Categorizer.validate_category_dn_pattern(
            entry,
            category,
            rules_model,
        )

    @staticmethod
    def categorize_entry(
        entry: FlextLdifModels.Entry,
        rules: FlextLdifModels.CategoryRules | Mapping[str, object] | None,
        whitelist_rules: FlextLdifModels.WhitelistRules
        | Mapping[str, object]
        | None = None,
    ) -> tuple[str, str | None]:
        """Categorize entry into 6 categories.

        Uses type-safe Pydantic models instead of dict[str, Any].
        Delegates to FlextLdifFilters.categorize, with optional whitelist validation.
        """
        rules_result = FlextLdifFilters._normalize_category_rules(rules)
        if rules_result.is_failure:
            return ("rejected", rules_result.error)
        normalized_rules = rules_result.unwrap()

        # Check for blocked objectClasses first using helper
        is_blocked, reason = FlextLdifFilters.Categorizer.check_blocked_objectclasses(
            entry,
            whitelist_rules,
        )
        if is_blocked:
            return ("rejected", reason)

        # Delegate to FilterService for main categorization
        category, reason = FlextLdifFilters.categorize(entry, normalized_rules)

        # Validate DN patterns for category-specific matching using helper
        if category in {"users", "groups"}:
            is_rejected, reject_reason = (
                FlextLdifFilters.Categorizer.validate_category_dn_pattern(
                    entry,
                    category,
                    normalized_rules,
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
        return FlextLdifFilters.Filter.filter_by_dn(
            entries,
            pattern,
            mode,
            mark_excluded=mark_excluded,
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
        return FlextLdifFilters.by_objectclass(
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
        return FlextLdifFilters.by_attributes(
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
        return FlextLdifFilters.Transformer.filter_entry_attributes(
            entry,
            attributes_to_remove,
        )

    @staticmethod
    def filter_entry_objectclasses(
        entry: FlextLdifModels.Entry,
        objectclasses_to_remove: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove specified objectClasses from entry."""
        return FlextLdifFilters.Transformer.filter_entry_objectclasses(
            entry,
            objectclasses_to_remove,
        )

    @staticmethod
    def virtual_delete(
        entries: list[FlextLdifModels.Entry],
        _filter_criteria: str | None = None,  # Reserved for future use
        _dn_pattern: str | None = None,
    ) -> FlextResult[dict[str, list[FlextLdifModels.Entry]]]:
        """Perform virtual (soft) delete - marks entries as deleted."""
        return FlextLdifFilters.Exclusion.virtual_delete(entries)

    @staticmethod
    def restore_virtual_deleted(
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Restore virtually deleted entries back to active state."""
        return FlextLdifFilters.Exclusion.restore_virtual_deleted(entries)


__all__ = ["FlextLdifFilters"]
