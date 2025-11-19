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

# PATTERN 1: Direct Classmethod API (Simplified)
────────────────────────────────────────────────
# Filter entries by DN pattern
result = FlextLdifFilters.by_dn(
    entries=my_entries,
    pattern="*,ou=users,dc=example,dc=com",
    mode="include"
)
filtered = result.unwrap()

# Filter by objectClass
result = FlextLdifFilters.by_objectclass(
    entries=my_entries,
    objectclass=("person", "inetOrgPerson"),
    required_attributes=["cn", "mail"]
)

# Filter by attribute presence
result = FlextLdifFilters.by_attributes(
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
from typing import TYPE_CHECKING, cast

from flext_core import FlextResult, FlextService
from pydantic import Field, PrivateAttr, ValidationError, field_validator

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels

# Import specialized services for delegation (SRP compliance)
from flext_ldif.services.acl_extractor import FlextLdifAclExtractor
from flext_ldif.services.categorizer import FlextLdifCategorizer
from flext_ldif.services.entry_transformer import FlextLdifEntryTransformer
from flext_ldif.services.schema_detector import FlextLdifSchemaDetector
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

# Type alias to avoid Pydantic v2 forward reference resolution issues
# FlextLdifTypes.Models is a namespace, not an importable module
if TYPE_CHECKING:
    _ServiceResponseType = FlextLdifTypes.Models.ServiceResponseTypes
else:
    _ServiceResponseType = object  # type: ignore[misc]


class FlextLdifFilters(FlextService[_ServiceResponseType]):
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
                "Category rules must be a mapping or CategoryRules model",
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
                f"Invalid category rules: {exc.errors(include_context=False)}",
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
                "Whitelist rules must be a mapping or WhitelistRules model",
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
                f"Invalid whitelist rules: {exc.errors(include_context=False)}",
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
        def _normalize_objectclass_tuple(oc: str | tuple[str, ...]) -> tuple[str, ...]:
            """Normalize objectclass to tuple."""
            return oc if isinstance(oc, tuple) else (oc,)

        @staticmethod
        def _matches_objectclass_entry(
            entry: FlextLdifModels.Entry,
            oc_tuple: tuple[str, ...],
            required_attributes: list[str] | None,
        ) -> bool:
            """Check if entry matches objectclass filter."""
            has_oc = FlextLdifUtilities.Entry.has_objectclass(entry, oc_tuple)
            if not has_oc or not required_attributes:
                return has_oc

            has_attrs = FlextLdifUtilities.Entry.has_all_attributes(
                entry,
                required_attributes,
            )
            return has_oc and has_attrs

        @staticmethod
        def _should_include_entry(*, matches: bool, filter_mode: str) -> bool:
            """Determine if entry should be included based on mode."""
            return (filter_mode == FlextLdifConstants.Modes.INCLUDE and matches) or (
                filter_mode == FlextLdifConstants.Modes.EXCLUDE and not matches
            )

        @staticmethod
        def _process_objectclass_entry(
            entry: FlextLdifModels.Entry,
            oc_tuple: tuple[str, ...],
            required_attributes: list[str] | None,
            filter_mode: str,
            *,
            mark_excluded: bool,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Process single entry with filtering logic."""
            # Access private methods within same class (acceptable pattern)
            entry_matches = FlextLdifFilters.Filter._matches_objectclass_entry(
                entry,
                oc_tuple,
                required_attributes,
            )
            if FlextLdifFilters.Filter._should_include_entry(
                matches=entry_matches,
                filter_mode=filter_mode,
            ):
                return FlextResult[FlextLdifModels.Entry].ok(entry)
            if mark_excluded:
                excluded_entry = FlextLdifFilters.Exclusion.mark_excluded(
                    entry,
                    f"ObjectClass filter: {oc_tuple}",
                )
                return FlextResult[FlextLdifModels.Entry].ok(excluded_entry)
            return FlextResult[FlextLdifModels.Entry].fail("Entry excluded by filter")

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
            try:
                # Normalize objectclass to tuple
                oc_tuple = FlextLdifFilters.Filter._normalize_objectclass_tuple(
                    objectclass,
                )

                # Process all entries
                filtered_entries: list[FlextLdifModels.Entry] = []
                for entry in entries:
                    result = FlextLdifFilters.Filter._process_objectclass_entry(
                        entry,
                        oc_tuple,
                        required_attributes,
                        mode,
                        mark_excluded=mark_excluded,
                    )
                    if result.is_success:
                        filtered_entries.append(result.unwrap())

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
                entry: FlextLdifModels.Entry,
                attrs: list[str],
            ) -> bool:
                """Check if entry matches attribute filter."""
                # Use direct utility method - no helper wrapper
                if match_all:
                    return FlextLdifUtilities.Entry.has_all_attributes(entry, attrs)
                return FlextLdifUtilities.Entry.has_any_attributes(entry, attrs)

            def should_include_attribute(*, matches: bool, filter_mode: str) -> bool:
                """Determine inclusion based on mode."""
                return (
                    filter_mode == FlextLdifConstants.Modes.INCLUDE and matches
                ) or (filter_mode == FlextLdifConstants.Modes.EXCLUDE and not matches)

            def process_attribute_entry(
                entry: FlextLdifModels.Entry,
                attrs: list[str],
                filter_mode: str,
            ) -> FlextResult[FlextLdifModels.Entry]:
                """Process single entry for attribute filtering."""
                entry_matches = matches_attributes(entry, attrs)
                if should_include_attribute(
                    matches=entry_matches,
                    filter_mode=filter_mode,
                ):
                    return FlextResult[FlextLdifModels.Entry].ok(entry)
                if mark_excluded:
                    excluded_entry = FlextLdifFilters.Exclusion.mark_excluded(
                        entry,
                        f"Attribute filter: {attributes}",
                    )
                    return FlextResult[FlextLdifModels.Entry].ok(excluded_entry)
                # Entry excluded - return failure to indicate filtering out
                return FlextResult[FlextLdifModels.Entry].fail(
                    "Entry excluded by filter",
                )

            try:
                # Functional composition - collect successful results
                filtered_entries: list[FlextLdifModels.Entry] = []
                for entry in entries:
                    result = process_attribute_entry(entry, attributes, mode)
                    if result.is_success:
                        filtered_entries.append(result.unwrap())

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

        # Removed has_objectclass and has_attributes helpers - use FlextLdifUtilities.Entry directly
        # These were just wrappers without added functionality

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
        """Handles entry attribute and objectClass filtering.

        Responsibility (SRP):
        - Filter entry attributes (internal use only)
        - Filter entry objectClasses (internal use only)

        NOTE: Public remove_attributes() and remove_objectclasses() are delegated
        to FlextLdifEntryTransformer service. See classmethod implementations below.
        """

        @staticmethod
        def filter_entry_attributes(
            entry: FlextLdifModels.Entry,
            attributes_to_remove: list[str],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Remove specified attributes from entry."""
            try:
                if not attributes_to_remove:
                    return FlextResult[FlextLdifModels.Entry].ok(entry)

                if entry.attributes is None:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        f"Entry {FlextLdifUtilities.DN.get_dn_value(entry.dn)} has no attributes",
                    )

                # Create filtered attributes dict
                attrs_lower = {attr.lower() for attr in attributes_to_remove}

                filtered_attrs = {
                    key: values
                    for key, values in entry.attributes.items()
                    if key.lower() not in attrs_lower
                }

                # Create new LdifAttributes
                attrs_result = FlextLdifModels.LdifAttributes.create(
                    filtered_attrs,
                )
                if not attrs_result.is_success:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        attrs_result.error or "Unknown error",
                    )

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

                # Check if entry has attributes
                if not entry.attributes:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        "Entry has no attributes",
                    )

                # Create filtered attributes dict
                filtered_attrs = dict(entry.attributes.attributes)
                filtered_attrs["objectClass"] = filtered_ocs

                # Create new LdifAttributes
                attrs_result = FlextLdifModels.LdifAttributes.create(
                    filtered_attrs,
                )
                if not attrs_result.is_success:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        attrs_result.error or "Unknown error",
                    )

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

            if not entry.attributes:
                return False

            # Type annotation to help pyrefly understand attr is str
            attrs_keys: list[str] = entry.attributes.keys()
            entry_attrs_lower = {attr.lower() for attr in attrs_keys}
            return any(attr.lower() in entry_attrs_lower for attr in attributes)

        @staticmethod
        def matches_oid_pattern(
            attributes: dict[str, list[str] | str],
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
                    quirk_type="filter_excluded",
                    extensions={"exclusion_info": exclusion_info},
                )
            else:
                new_extensions = {**entry.metadata.extensions}
                new_extensions["exclusion_info"] = exclusion_info
                new_metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type=entry.metadata.quirk_type,
                    extensions=new_extensions,
                )

            return entry.model_copy(update={"metadata": new_metadata})

        @staticmethod
        def is_entry_excluded(entry: FlextLdifModels.Entry) -> bool:
            """Check if entry is marked as excluded in metadata."""
            if entry.metadata is None:
                return False

            exclusion_info = entry.metadata.extensions.get("exclusion_info")
            if exclusion_info is None:
                return False

            # Handle both model and dict formats
            if isinstance(exclusion_info, FlextLdifModels.ExclusionInfo):
                return exclusion_info.excluded
            if isinstance(exclusion_info, dict):
                excluded = exclusion_info.get("excluded")
                return isinstance(excluded, bool) and excluded

            return False

        @staticmethod
        def get_exclusion_reason(entry: FlextLdifModels.Entry) -> str | None:
            """Get exclusion reason from entry metadata."""
            if entry.metadata is None:
                return None

            exclusion_info = entry.metadata.extensions.get("exclusion_info")
            if exclusion_info is None:
                return None

            # Only return reason if entry is actually marked as excluded
            if not FlextLdifFilters.Exclusion.is_entry_excluded(entry):
                return None

            # Handle both model and dict formats
            if isinstance(exclusion_info, FlextLdifModels.ExclusionInfo):
                return exclusion_info.exclusion_reason
            if isinstance(exclusion_info, dict):
                reason = exclusion_info.get("exclusion_reason")
                return reason if isinstance(reason, str) else None

            return None

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
                        existing_metadata = entry.metadata
                        if existing_metadata is None:
                            new_metadata = FlextLdifModels.QuirkMetadata(
                                quirk_type="virtual_deleted",
                                extensions={
                                    "virtual_deleted": True,
                                    "deletion_timestamp": datetime.now(UTC).isoformat(),
                                },
                            )
                        else:
                            new_extensions = {**existing_metadata.extensions}
                            new_extensions["virtual_deleted"] = True
                            new_extensions["deletion_timestamp"] = datetime.now(
                                UTC,
                            ).isoformat()
                            new_metadata = existing_metadata.model_copy(
                                update={"extensions": new_extensions},
                            )

                        deleted_entry = entry.model_copy(
                            update={"metadata": new_metadata},
                        )
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
                    # Remove virtual delete markers from metadata
                    if entry.metadata is None:
                        restored_entries.append(entry)
                        continue

                    new_extensions = {**entry.metadata.extensions}
                    new_extensions.pop("virtual_deleted", None)
                    new_extensions.pop("deletion_timestamp", None)

                    new_metadata = entry.metadata.model_copy(
                        update={"extensions": new_extensions},
                    )

                    restored_entry = entry.model_copy(update={"metadata": new_metadata})
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
                "dn_pattern is required for dn filter",
            )
        return self.Filter.filter_by_dn(
            self.entries,
            self.dn_pattern,
            self.mode,
            mark_excluded=self.mark_excluded,
        )

    def _execute_objectclass_filter(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute objectClass filter."""
        if self.objectclass is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "objectclass is required for objectclass filter",
            )
        return self.Filter.filter_by_objectclass(
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
                "attributes is required for attributes filter",
            )
        return self.Filter.filter_by_attributes(
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
                "base_dn is required for base_dn filter",
            )
        included, _excluded = self.filter_by_base_dn(
            self.entries,
            self.base_dn,
        )
        return FlextResult[list[FlextLdifModels.Entry]].ok(included)

    def execute(
        self,
        **_kwargs: object,
    ) -> FlextResult[FlextLdifTypes.Models.ServiceResponseTypes]:
        """Execute filtering based on filter_criteria and mode.

        Args:
            **_kwargs: Unused keyword arguments for FlextService compatibility.

        """
        if not self.entries:
            return FlextResult[FlextLdifTypes.Models.ServiceResponseTypes].ok(
                FlextLdifModels.EntryResult.empty(),
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
                    return FlextResult[FlextLdifTypes.Models.ServiceResponseTypes].fail(
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
                        },
                    ],
                    filter_duration_ms=filter_duration_ms,
                )
                # Store event for retrieval via get_last_event()
                self._last_event = filter_event

                # Wrap filtered entries in EntryResult for API consistency
                entry_result = FlextLdifModels.EntryResult.from_entries(
                    filtered_entries,
                )
                return FlextResult[FlextLdifTypes.Models.ServiceResponseTypes].ok(
                    entry_result,
                )

            # If result is failure, propagate the error
            return FlextResult[FlextLdifTypes.Models.ServiceResponseTypes].fail(
                result.error or "Filter operation failed",
            )

        except Exception as e:
            return FlextResult[FlextLdifTypes.Models.ServiceResponseTypes].fail(
                f"Filter failed: {e}",
            )

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
    ) -> FlextResult[FlextLdifTypes.Models.ServiceResponseTypes]:
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
        # Use tuple if classes provided, None if empty
        self.objectclass = tuple(classes) if classes else None
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
        # execute() returns ServiceResponseTypes but we know it's always EntryResult for FlextLdifFilters
        result = self.execute().unwrap()
        # Fix: Use type directly instead of string to avoid Pydantic v2 forward reference issues
        return cast("FlextLdifModels.EntryResult", result)

    # ════════════════════════════════════════════════════════════════════════
    # PUBLIC CLASSMETHOD HELPERS (Direct Entry Points)
    # ════════════════════════════════════════════════════════════════════════

    # Removed filter_by_dn, filter_by_objectclass, filter_by_attributes helpers
    # Use Filter.filter_by_* directly or by_* methods

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
            entries,
            base_dn,
            mark_excluded=mark_excluded,
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
        """Filter entries by DN pattern."""
        # Use Filter directly - no intermediate helper
        return cls.Filter.filter_by_dn(
            entries,
            pattern,
            mode,
            mark_excluded=mark_excluded,
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
        # Use Filter directly - no intermediate helper
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
        # Use Filter directly - no intermediate helper
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
            entries,
            base_dn,
            mark_excluded=mark_excluded,
        )

    # ════════════════════════════════════════════════════════════════════════
    # STATIC METHODS FOR TEST COMPATIBILITY
    # ════════════════════════════════════════════════════════════════════════

    @staticmethod
    def filter_by_dn(
        entries: list[FlextLdifModels.Entry],
        dn_pattern: str,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        *,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by DN pattern (static method for test compatibility)."""
        return FlextLdifFilters.Filter.filter_by_dn(
            entries,
            dn_pattern,
            mode,
            mark_excluded=mark_excluded,
        )

    @staticmethod
    def filter_by_objectclass(
        entries: list[FlextLdifModels.Entry],
        objectclass: str | tuple[str, ...],
        required_attributes: list[str] | None = None,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        *,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by objectClass (static method for test compatibility)."""
        return FlextLdifFilters.Filter.filter_by_objectclass(
            entries,
            objectclass,
            required_attributes,
            mode,
            mark_excluded=mark_excluded,
        )

    @staticmethod
    def filter_by_attributes(
        entries: list[FlextLdifModels.Entry],
        attributes: list[str],
        *,
        match_all: bool = False,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by attribute presence (static method for test compatibility)."""
        return FlextLdifFilters.Filter.filter_by_attributes(
            entries,
            attributes,
            match_all=match_all,
            mode=mode,
            mark_excluded=mark_excluded,
        )

    @staticmethod
    def filter_entries_by_dn(
        entries: list[FlextLdifModels.Entry],
        dn_pattern: str,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        *,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by DN pattern (alias for filter_by_dn)."""
        return FlextLdifFilters.filter_by_dn(
            entries,
            dn_pattern,
            mode,
            mark_excluded=mark_excluded,
        )

    @staticmethod
    def filter_entries_by_objectclass(
        entries: list[FlextLdifModels.Entry],
        objectclass: str | tuple[str, ...],
        required_attributes: list[str] | None = None,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        *,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by objectClass (alias for filter_by_objectclass)."""
        return FlextLdifFilters.filter_by_objectclass(
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
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by attribute presence (alias for filter_by_attributes)."""
        return FlextLdifFilters.filter_by_attributes(
            entries,
            attributes,
            match_all=match_all,
            mode=mode,
            mark_excluded=mark_excluded,
        )

    @classmethod
    def is_schema(cls, entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is a REAL schema entry with schema definitions.

        DELEGATED TO: FlextLdifSchemaDetector.is_schema()
        """
        return FlextLdifSchemaDetector.is_schema(entry)

    @classmethod
    def extract_acl_entries(
        cls,
        entries: list[FlextLdifModels.Entry],
        acl_attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Extract entries with ACL attributes.

        DELEGATED TO: FlextLdifAclExtractor.extract_acl_entries()
        """
        extractor = FlextLdifAclExtractor()
        return extractor.extract_acl_entries(entries, acl_attributes)

    @classmethod
    def remove_attributes(
        cls,
        entry: FlextLdifModels.Entry,
        attributes: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove attributes from entry.

        DELEGATED TO: FlextLdifEntryTransformer.remove_attributes()
        """
        transformer = FlextLdifEntryTransformer()
        return transformer.remove_attributes(entry, attributes)

    @classmethod
    def remove_objectclasses(
        cls,
        entry: FlextLdifModels.Entry,
        objectclasses: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove objectClasses from entry.

        DELEGATED TO: FlextLdifEntryTransformer.remove_objectclasses()
        """
        transformer = FlextLdifEntryTransformer()
        return transformer.remove_objectclasses(entry, objectclasses)

    @classmethod
    def _check_hierarchy_priority(
        cls,
        entry: FlextLdifModels.Entry,
        constants: type,
    ) -> bool:
        """Check if entry matches HIERARCHY_PRIORITY_OBJECTCLASSES.

        Args:
            entry: Entry to check
            constants: Server Constants class

        Returns:
            True if entry has priority hierarchy objectClass

        """
        if not hasattr(constants, "HIERARCHY_PRIORITY_OBJECTCLASSES"):
            return False

        priority_classes = constants.HIERARCHY_PRIORITY_OBJECTCLASSES
        entry_ocs = {oc.lower() for oc in entry.get_objectclass_names()}
        return any(oc.lower() in entry_ocs for oc in priority_classes)

    @classmethod
    def _get_server_constants(cls, server_type: str) -> FlextResult[type]:
        """Get and validate server constants via FlextLdifServer registry.

        Args:
            server_type: Server type identifier

        Returns:
            FlextResult with constants class or error message

        """
        try:
            # Import here to avoid circular dependency (services -> servers -> services)
            from flext_ldif.services.server import FlextLdifServer

            registry = FlextLdifServer.get_global_instance()
            server_quirk = registry.quirk(server_type)

            if not server_quirk:
                return FlextResult[type].fail(f"Unknown server type: {server_type}")

            quirk_class = type(server_quirk)
            if not hasattr(quirk_class, "Constants"):
                return FlextResult[type].fail(
                    f"Server type {server_type} missing Constants class",
                )

            constants = quirk_class.Constants

            if not hasattr(constants, "CATEGORIZATION_PRIORITY"):
                return FlextResult[type].fail(
                    f"Server {server_type} missing CATEGORIZATION_PRIORITY",
                )
            if not hasattr(constants, "CATEGORY_OBJECTCLASSES"):
                return FlextResult[type].fail(
                    f"Server {server_type} missing CATEGORY_OBJECTCLASSES",
                )

            return FlextResult[type].ok(constants)
        except (ImportError, ValueError) as e:
            return FlextResult[type].fail(f"Failed to get server constants: {e}")

    @classmethod
    def _categorize_by_priority(
        cls,
        entry: FlextLdifModels.Entry,
        constants: type,
        priority_order: list[str],
        category_map: dict[str, frozenset[str]],
    ) -> tuple[str, str | None]:
        """Categorize entry by iterating through priority order.

        Args:
            entry: Entry to categorize
            constants: Server Constants class
            priority_order: Category priority order
            category_map: Category to objectClasses mapping

        Returns:
            Tuple of (category, rejection_reason)

        """
        for category in priority_order:
            if category == "acl":
                if hasattr(constants, "CATEGORIZATION_ACL_ATTRIBUTES"):
                    acl_attributes = list(constants.CATEGORIZATION_ACL_ATTRIBUTES)
                    # Use direct utility method - no helper wrapper
                    if FlextLdifUtilities.Entry.has_any_attributes(
                        entry,
                        acl_attributes,
                    ):
                        return ("acl", None)
                continue

            category_objectclasses = category_map.get(category)
            if not category_objectclasses:
                continue

            # Use direct utility method - no helper wrapper
            if FlextLdifUtilities.Entry.has_objectclass(
                entry,
                tuple(category_objectclasses),
            ):
                return (category, None)

        return ("rejected", "No category match")

    @classmethod
    def categorize(
        cls,
        entry: FlextLdifModels.Entry,
        rules: FlextLdifModels.CategoryRules | Mapping[str, object] | None,
        server_type: str = "rfc",
    ) -> tuple[str, str | None]:
        """Categorize entry using SERVER-SPECIFIC rules.

        DELEGATED TO: FlextLdifCategorizer.categorize_entry()

        Uses server-specific constants from servers/oid.py, servers/oud.py, etc.
        for objectClass prioritization and ACL detection.

        Categories (server-specific priority):
        - schema: Has attributeTypes/objectClasses
        - users: User accounts (person, inetOrgPerson, orcluser for OID)
        - hierarchy: Containers (organizationalUnit, orclContainer for OID)
        - groups: Group entries (groupOfNames, orclGroup for OID)
        - acl: Entries with ACL attributes (orclaci for OID, aci for OUD)
        - rejected: No match

        Args:
            entry: LDIF entry to categorize
            rules: Category rules (can override server defaults)
            server_type: Server type ("oid", "oud", "rfc") determines constants

        Returns:
            Tuple of (category, rejection_reason)

        """
        categorizer = FlextLdifCategorizer()
        return categorizer.categorize_entry(entry, rules, server_type)

    @staticmethod
    def _extract_allowed_oids(
        allowed_oids: dict[str, list[str]],
    ) -> tuple[list[str], ...]:
        """Extract allowed OIDs for each schema type from config dict."""
        attr_oids = allowed_oids.get("allowed_attribute_oids")
        if attr_oids is None:
            attr_oids = allowed_oids.get("attributes")
        allowed_attr_oids = attr_oids if attr_oids is not None else []

        oc_oids = allowed_oids.get("allowed_objectclass_oids")
        if oc_oids is None:
            oc_oids = allowed_oids.get("objectclasses")
        allowed_oc_oids = oc_oids if oc_oids is not None else []

        mr_oids = allowed_oids.get("allowed_matchingrule_oids")
        if mr_oids is None:
            mr_oids = allowed_oids.get("matchingrules")
        allowed_mr_oids = mr_oids if mr_oids is not None else []

        mru_oids = allowed_oids.get("allowed_matchingruleuse_oids")
        if mru_oids is None:
            mru_oids = allowed_oids.get("matchingruleuse")
        allowed_mru_oids = mru_oids if mru_oids is not None else []
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
            # Skip entries without attributes or DN
            if not entry.attributes or not entry.dn:
                continue

            attrs_copy = dict(entry.attributes.attributes)

            # Filter each schema type
            cls._filter_schema_attribute(
                attrs_copy,
                ("attributeTypes", "attributetypes"),
                allowed_attr_oids,
            )
            cls._filter_schema_attribute(
                attrs_copy,
                ("objectClasses", "objectclasses"),
                allowed_oc_oids,
            )
            cls._filter_schema_attribute(
                attrs_copy,
                ("matchingRules", "matchingrules"),
                allowed_mr_oids,
            )
            cls._filter_schema_attribute(
                attrs_copy,
                ("matchingRuleUse", "matchingruleuse"),
                allowed_mru_oids,
            )

            # Only keep entry if it has definitions remaining after filtering
            if cls._has_remaining_definitions(attrs_copy):
                # Create new entry with filtered attributes
                # Type cast: attrs_copy is dict[str, list[str]] but Entry.create() accepts dict[str, list[str] | str]
                attrs_typed = cast("dict[str, list[str] | str]", attrs_copy)

                filtered_entry_result = FlextLdifModels.Entry.create(
                    dn=entry.dn.value,
                    attributes=attrs_typed,
                    entry_metadata=entry.entry_metadata
                    if hasattr(entry, "entry_metadata")
                    else None,
                )
                if filtered_entry_result.is_success:
                    # Entry.create() returns Domain.Entry, which is compatible with Models.Entry
                    # Models.Entry extends Domain.Entry, so this cast is safe
                    new_entry = filtered_entry_result.unwrap()
                    if isinstance(new_entry, FlextLdifModels.Entry):
                        filtered.append(new_entry)

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
                            "dn_pattern is required",
                        )
                    # Use static method if available (allows monkeypatch in tests), otherwise use Filter
                    elif hasattr(FlextLdifFilters, "filter_by_dn") and callable(
                        getattr(FlextLdifFilters, "filter_by_dn", None),
                    ):
                        result = FlextLdifFilters.filter_by_dn(
                            self.entries,
                            self.dn_pattern,
                            self.mode,
                            mark_excluded=self.mark_excluded,
                        )
                    else:
                        # Use Filter directly - no intermediate helper
                        result = self.Filter.filter_by_dn(
                            self.entries,
                            self.dn_pattern,
                            self.mode,
                            mark_excluded=self.mark_excluded,
                        )
                case "objectclass":
                    if self.objectclass is None:
                        result = FlextResult[list[FlextLdifModels.Entry]].fail(
                            "objectclass is required",
                        )
                    else:
                        # Use Filter directly - no intermediate helper
                        result = self.Filter.filter_by_objectclass(
                            self.entries,
                            self.objectclass,
                            self.required_attributes,
                            self.mode,
                            mark_excluded=self.mark_excluded,
                        )
                case "attributes":
                    if self.attributes is None:
                        result = FlextResult[list[FlextLdifModels.Entry]].fail(
                            "attributes is required",
                        )
                    else:
                        # Use Filter directly - no intermediate helper
                        result = self.Filter.filter_by_attributes(
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
        server_type: str = "rfc",
    ) -> tuple[str, str | None]:
        """Categorize entry into 6 categories.

        Uses type-safe Pydantic models instead of dict[str, Any].
        Delegates to FlextLdifFilters.categorize, with optional whitelist validation.

        Args:
            entry: Entry to categorize
            rules: Categorization rules (model or dict)
            whitelist_rules: Schema whitelist rules (optional)
            server_type: LDAP server type (oid, oud, rfc, etc.) - defaults to "rfc"

        Returns:
            Tuple of (category, reason) where category is one of:
                schema, hierarchy, users, groups, acl, rejected

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

        # Use server_type parameter (passed from migration service) instead of
        # extracting from entry metadata. This ensures correct server-specific
        # constants are used even if entries don't have metadata set.
        # Priority: parameter > entry.metadata.quirk_type > "rfc" fallback
        effective_server_type = server_type
        if (
            entry.metadata
            and hasattr(entry.metadata, "quirk_type")
            and entry.metadata.quirk_type
        ):
            effective_server_type = entry.metadata.quirk_type

        # Delegate to FilterService for main categorization with server_type
        category, reason = FlextLdifFilters.categorize(
            entry,
            normalized_rules,
            effective_server_type,
        )

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

    # Removed filter_entries_by_* static methods - use by_* classmethods or Filter.filter_by_* directly

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
