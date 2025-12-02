"""FLEXT LDIF Filters Service - Universal Entry Filtering and Categorization Engine.

Provides DN pattern matching, objectClass filtering, attribute filtering,
entry transformation, and categorization for LDIF entries.

For detailed usage examples and API documentation, see docs/FILTERS.md.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import fnmatch
import re
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

from flext_core import (
    FlextLogger,
    FlextResult,
    FlextRuntime,
    FlextUtilities,
)
from pydantic import Field, PrivateAttr, ValidationError, field_validator

from flext_ldif._models.config import FlextLdifModelsConfig
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.events import FlextLdifModelsEvents
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.services.acl import FlextLdifAcl
from flext_ldif.services.entries import FlextLdifEntries
from flext_ldif.services.registry import FlextLdifServiceRegistry
from flext_ldif.services.schema import FlextLdifSchema
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifFilters(
    FlextLdifServiceBase[FlextLdifTypes.Models.ServiceResponseTypes],
):
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
    def _get_or_create_metadata(
        entry: FlextLdifModels.Entry,
        quirk_type: str,
    ) -> FlextLdifModels.QuirkMetadata | FlextLdifModelsDomains.QuirkMetadata:
        """Get or create metadata for entry using FlextLdifUtilities pattern.

        Reduces code duplication across metadata operations.
        Uses Entry + Metadata pattern consistently.

        Args:
            entry: Entry to get/create metadata for
            quirk_type: Quirk type identifier for new metadata

        Returns:
            QuirkMetadata instance (existing or newly created)

        """
        if entry.metadata is not None:
            return entry.metadata
        return FlextLdifModels.QuirkMetadata(quirk_type=quirk_type)

    @staticmethod
    def _ensure_str_list(value: str | list[str] | None) -> list[str]:
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
        rules: FlextLdifModels.CategoryRules | Mapping[str, list[str] | str] | None,
    ) -> FlextResult[FlextLdifModels.CategoryRules]:
        """Coerce dict inputs into CategoryRules models (backwards compatibility)."""
        if isinstance(rules, FlextLdifModels.CategoryRules):
            return FlextResult.ok(rules)

        if rules is None:
            return FlextResult.ok(FlextLdifModels.CategoryRules())

        # Type narrowing: at this point rules must be Mapping[str, list[str] | str]
        # Validate for runtime safety
        if not isinstance(rules, Mapping):
            return FlextResult[FlextLdifModels.CategoryRules].fail(
                "Category rules must be a mapping or CategoryRules model",
            )
        # Type narrowing: rules is now guaranteed to be Mapping[str, list[str] | str]

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
        rules: FlextLdifModels.WhitelistRules | Mapping[str, list[str] | str] | None,
    ) -> FlextResult[FlextLdifModels.WhitelistRules]:
        """Coerce dict inputs into WhitelistRules models (backwards compatibility)."""
        if isinstance(rules, FlextLdifModels.WhitelistRules):
            return FlextResult.ok(rules)

        if rules is None:
            return FlextResult.ok(FlextLdifModels.WhitelistRules())

        # Type narrowing: at this point rules must be Mapping[str, list[str] | str]
        # Validate for runtime safety
        if not isinstance(rules, Mapping):
            return FlextResult[FlextLdifModels.WhitelistRules].fail(
                "Whitelist rules must be a mapping or WhitelistRules model",
            )
        # Type narrowing: rules is now guaranteed to be Mapping[str, list[str] | str]

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
            # Validate mode
            valid_modes = (
                FlextLdifConstants.Modes.INCLUDE,
                FlextLdifConstants.Modes.EXCLUDE,
            )
            if mode not in valid_modes:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Invalid filter mode '{mode}'. Must be one of: {valid_modes}",
                )
            try:
                pattern = dn_pattern  # Type narrowing
                filtered = []
                for entry in entries:
                    # Use DN utility to get string value (supports DN model and str)
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
        def normalize_objectclass_tuple(oc: str | tuple[str, ...]) -> tuple[str, ...]:
            """Normalize objectclass to tuple."""
            return oc if isinstance(oc, tuple) else (oc,)

        @staticmethod
        def matches_objectclass_entry(
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
        def should_include_entry(*, matches: bool, filter_mode: str) -> bool:
            """Determine if entry should be included based on mode."""
            return (filter_mode == FlextLdifConstants.Modes.INCLUDE and matches) or (
                filter_mode == FlextLdifConstants.Modes.EXCLUDE and not matches
            )

        @staticmethod
        def process_objectclass_entry(
            entry: FlextLdifModels.Entry,
            oc_tuple: tuple[str, ...],
            required_attributes: list[str] | None,
            filter_mode: str,
            *,
            mark_excluded: bool,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Process single entry with filtering logic."""
            # Call static methods within same nested class (private access ok)
            entry_matches = FlextLdifFilters.Filter.matches_objectclass_entry(
                entry,
                oc_tuple,
                required_attributes,
            )
            if FlextLdifFilters.Filter.should_include_entry(
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
                oc_tuple = FlextLdifFilters.Filter.normalize_objectclass_tuple(
                    objectclass,
                )

                # Process all entries
                filtered_entries: list[FlextLdifModels.Entry] = []
                for entry in entries:
                    result = FlextLdifFilters.Filter.process_objectclass_entry(
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

        # Removed has_objectclass/has_attributes helpers - use FlextLdifUtilities.Entry
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
            | Mapping[str, list[str] | str]
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
            category: FlextLdifConstants.LiteralTypes.CategoryLiteral | str,
            rules: FlextLdifModels.CategoryRules | Mapping[str, list[str] | str] | None,
        ) -> tuple[bool, str | None]:
            """Validate DN pattern for specific category.

            Uses type-safe CategoryRules model instead of dict[str, Any].
            """
            rules_result = FlextLdifFilters._normalize_category_rules(rules)
            if rules_result.is_failure:
                return (True, rules_result.error)
            normalized_rules = rules_result.unwrap()

            # Map category to pattern attribute (supports both enum and string)
            pattern_map: dict[str, list[str]] = {
                "users": normalized_rules.user_dn_patterns,
                "groups": normalized_rules.group_dn_patterns,
                "hierarchy": normalized_rules.hierarchy_dn_patterns,
                "schema": normalized_rules.schema_dn_patterns,
            }

            # Normalize category to string for lookup
            category_str = (
                str(category.value) if hasattr(category, "value") else str(category)
            )
            dn_patterns = pattern_map.get(category_str, [])
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
        to FlextLdifEntries service. See classmethod implementations below.
        """

        @staticmethod
        def mark_attributes_for_removal(
            entry: FlextLdifModels.Entry,
            attributes_to_mark: set[str],
            status: str = FlextLdifConstants.AttributeMarkerStatus.MARKED_FOR_REMOVAL,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Mark attributes in metadata without removing from entry.attributes.

            SRP: Filters MARK only, entry service REMOVES.

            Uses FlextLdifUtilities.Metadata and Entry + Metadata patterns.
            Marks attributes using removed_attributes field in QuirkMetadata.

            Args:
                entry: Entry to mark attributes in
                attributes_to_mark: Set of attribute names to mark
                status: Marker status (default: MARKED_FOR_REMOVAL)

            Returns:
                FlextResult[Entry] with marked attributes in metadata

            """
            try:
                if not attributes_to_mark:
                    return FlextResult[FlextLdifModels.Entry].ok(entry)

                # Entry.attributes is required by model, but we check for safety
                if not hasattr(entry, "attributes") or entry.attributes is None:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        f"Entry {FlextLdifUtilities.DN.get_dn_value(entry.dn)} has no attributes",
                    )

                # Get or create metadata using FlextLdifUtilities pattern
                current_metadata = entry.metadata
                if current_metadata is None:
                    current_metadata = FlextLdifModels.QuirkMetadata(
                        quirk_type="filter_marked",
                    )

                # Build marked attributes dict with original values
                attrs_lower = {attr.lower() for attr in attributes_to_mark}
                marked_attributes: dict[str, list[str]] = {}
                marked_for_tracking: dict[str, list[str]] = {}
                marked_with_status: dict[str, dict[str, str]] = {}

                for attr_name, attr_values in entry.attributes.items():
                    if attr_name.lower() in attrs_lower:
                        # Store original values for recovery with explicit str conversion
                        # Normalize to list[str] regardless of input type
                        values_list: list[str]
                        if isinstance(attr_values, (list, tuple)):
                            values_list = [str(v) for v in attr_values]
                        else:
                            values_list = [str(attr_values)]
                        marked_attributes[attr_name] = values_list
                        marked_for_tracking[attr_name] = values_list
                        # Build status dict for extensions
                        marked_with_status[attr_name] = {"status": status}

                if not marked_attributes:
                    return FlextResult[FlextLdifModels.Entry].ok(entry)

                # Update removed_attributes in metadata (standard field)
                # Use model_dump() for DynamicMetadata → dict conversion
                updated_removed = current_metadata.removed_attributes.model_dump()
                updated_removed.update(marked_attributes)

                # Update extensions with marked_attributes
                updated_extensions = current_metadata.extensions.model_dump()
                updated_extensions["marked_attributes"] = marked_with_status

                # Track transformation for each marked attribute using FlextLdifUtilities.Metadata
                updated_metadata = current_metadata.model_copy(
                    update={
                        "removed_attributes": updated_removed,
                        "extensions": updated_extensions,
                    },
                )

                for attr_name, original_values in marked_for_tracking.items():
                    FlextLdifUtilities.Metadata.track_transformation(
                        metadata=updated_metadata,
                        original_name=attr_name,
                        target_name=None,
                        original_values=original_values,
                        target_values=None,
                        transformation_type="removed",
                        reason=f"Marked for removal with status: {status}",
                    )

                new_entry = entry.model_copy(update={"metadata": updated_metadata})

                # Log marking operation
                FlextLogger.get_logger().debug(
                    "Marked attributes for removal in metadata",
                    action_taken="mark_attributes_for_removal",
                    entry_dn=FlextLdifUtilities.DN.get_dn_value(entry.dn),
                    marked_attributes=list(marked_attributes.keys()),
                    marked_count=len(marked_attributes),
                    status=status,
                )

                return FlextResult[FlextLdifModels.Entry].ok(new_entry)

            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Mark attributes for removal failed: {e}",
                )

        @staticmethod
        def mark_objectclasses_for_removal(
            entry: FlextLdifModels.Entry,
            objectclasses_to_mark: set[str],
            status: str = FlextLdifConstants.AttributeMarkerStatus.MARKED_FOR_REMOVAL,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Mark objectClasses in metadata without removing from entry.attributes.

            SRP: Filters MARK only, entry service REMOVES.

            Uses FlextLdifUtilities.Metadata and Entry + Metadata patterns.
            Marks objectClasses using removed_attributes field in QuirkMetadata.

            Args:
                entry: Entry to mark objectClasses in
                objectclasses_to_mark: Set of objectClass values to mark
                status: Marker status (default: MARKED_FOR_REMOVAL)

            Returns:
                FlextResult[Entry] with marked objectClasses in metadata

            """
            try:
                if not objectclasses_to_mark:
                    return FlextResult[FlextLdifModels.Entry].ok(entry)

                current_ocs = entry.get_attribute_values("objectClass")
                if not current_ocs:
                    return FlextResult[FlextLdifModels.Entry].ok(entry)

                # Build marked objectclasses (case-insensitive)
                ocs_lower = {oc.lower() for oc in objectclasses_to_mark}
                marked_ocs = [
                    oc_value
                    for oc_value in current_ocs
                    if oc_value.lower() in ocs_lower
                ]

                if not marked_ocs:
                    return FlextResult[FlextLdifModels.Entry].ok(entry)

                # Get or create metadata using FlextLdifUtilities pattern
                current_metadata = FlextLdifFilters._get_or_create_metadata(
                    entry,
                    "filter_marked",
                )

                # Store marked objectClasses in removed_attributes using objectClass key
                updated_removed = current_metadata.removed_attributes.model_dump()
                objectclass_key = FlextLdifConstants.DictKeys.OBJECTCLASS
                existing_ocs = updated_removed.get(objectclass_key, [])
                if not isinstance(existing_ocs, list):
                    existing_ocs = []
                # Merge marked objectClasses (avoid duplicates)
                merged_ocs = list(set(existing_ocs + marked_ocs))
                updated_removed[objectclass_key] = merged_ocs

                # Build marked_with_status for extensions (like attributes)
                marked_with_status: dict[str, dict[str, str]] = {}
                for oc_name in marked_ocs:
                    marked_with_status[oc_name] = {"status": status}

                # Update extensions with marked_objectclasses
                updated_extensions = current_metadata.extensions.model_dump()
                updated_extensions["marked_objectclasses"] = marked_with_status

                # Update metadata with both removed_attributes and extensions
                updated_metadata = current_metadata.model_copy(
                    update={
                        "removed_attributes": updated_removed,
                        "extensions": updated_extensions,
                    },
                )

                # Track transformation for objectClass using FlextLdifUtilities.Metadata
                FlextLdifUtilities.Metadata.track_transformation(
                    metadata=updated_metadata,
                    original_name=objectclass_key,
                    target_name=None,
                    original_values=marked_ocs,
                    target_values=None,
                    transformation_type="removed",
                    reason=f"Marked objectClasses for removal with status: {status}",
                )

                new_entry = entry.model_copy(update={"metadata": updated_metadata})

                # Log marking operation
                FlextLogger.get_logger().debug(
                    "Marked objectClasses for removal in metadata",
                    action_taken="mark_objectclasses_for_removal",
                    entry_dn=FlextLdifUtilities.DN.get_dn_value(entry.dn),
                    marked_objectclasses=marked_ocs,
                    marked_count=len(marked_ocs),
                    status=status,
                )

                return FlextResult[FlextLdifModels.Entry].ok(new_entry)

            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Mark objectClasses for removal failed: {e}",
                )

        @staticmethod
        def filter_entry_attributes(
            entry: FlextLdifModels.Entry,
            attributes_to_remove: list[str],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Mark attributes for removal in entry metadata (SRP - never removes).

            This method follows Single Responsibility Principle:
            - filters.py: MARKS attributes in metadata (this method)
            - entry.py: REMOVES attributes based on markers
            - writer.py: Decides output visibility based on WriteOutputOptions

            Args:
                entry: Entry to mark attributes for removal
                attributes_to_remove: List of attribute names to mark

            Returns:
                FlextResult[Entry] with marked attributes in metadata

            """
            if not attributes_to_remove:
                return FlextResult[FlextLdifModels.Entry].ok(entry)

            return FlextLdifFilters.Transformer.mark_attributes_for_removal(
                entry,
                set(attributes_to_remove),
                FlextLdifConstants.AttributeMarkerStatus.FILTERED,
            )

        @staticmethod
        def filter_entry_objectclasses(
            entry: FlextLdifModels.Entry,
            objectclasses_to_remove: list[str],
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Mark objectClasses for removal in entry metadata (SRP - never removes).

            This method follows Single Responsibility Principle:
            - filters.py: MARKS objectClasses in metadata (this method)
            - entry.py: REMOVES objectClasses based on markers
            - writer.py: Decides output visibility based on WriteOutputOptions

            Args:
                entry: Entry to mark objectClasses for removal
                objectclasses_to_remove: List of objectClass names to mark

            Returns:
                FlextResult[Entry] with marked objectClasses in metadata

            """
            if not objectclasses_to_remove:
                return FlextResult[FlextLdifModels.Entry].ok(entry)

            # Mark "objectClass" attribute as having filtered values
            # Store which specific objectClasses are marked in metadata
            return FlextLdifFilters.Transformer.mark_objectclasses_for_removal(
                entry,
                set(objectclasses_to_remove),
                FlextLdifConstants.AttributeMarkerStatus.FILTERED,
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

            # Convert keys to list for type compatibility
            attrs_keys: list[str] = list(entry.attributes.keys())
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
                if not FlextRuntime.is_list_like(values):
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
            """Mark entry as excluded using Entry + Metadata pattern.

            Uses FlextLdifUtilities.Metadata and standard ExclusionInfo model.
            Stores exclusion info in metadata.extensions using standard pattern.

            Args:
                entry: Entry to mark as excluded
                reason: Exclusion reason

            Returns:
                Entry with exclusion metadata

            """
            exclusion_info = FlextLdifModels.ExclusionInfo(
                excluded=True,
                exclusion_reason=reason,
                timestamp=FlextUtilities.Generators.generate_iso_timestamp(),
            )

            # Get or create metadata using FlextLdifUtilities pattern
            current_metadata = entry.metadata
            if current_metadata is None:
                current_metadata = FlextLdifModels.QuirkMetadata(
                    quirk_type="filter_excluded",
                )

            # Update extensions with exclusion info
            updated_extensions = current_metadata.extensions.model_dump()
            updated_extensions["exclusion_info"] = exclusion_info

            updated_metadata = current_metadata.model_copy(
                update={"extensions": updated_extensions},
            )

            return entry.model_copy(update={"metadata": updated_metadata})

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
            if FlextRuntime.is_dict_like(exclusion_info):
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
            if FlextRuntime.is_dict_like(exclusion_info):
                reason = exclusion_info.get("exclusion_reason")
                return reason if isinstance(reason, str) else None

            return None

        @staticmethod
        def matches_dn_pattern(
            dn: str
            | FlextLdifModels.DistinguishedName
            | FlextLdifModelsDomains.DistinguishedName,
            patterns: list[str],
        ) -> bool:
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
                    return FlextResult[dict[str, list[FlextLdifModels.Entry]]].ok(
                        {
                            "active": [],
                            "virtual_deleted": [],
                            "archive": [],
                        },
                    )

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
                        # Mark as virtually deleted using Entry + Metadata pattern
                        current_metadata = entry.metadata
                        if current_metadata is None:
                            current_metadata = FlextLdifModels.QuirkMetadata(
                                quirk_type="virtual_deleted",
                            )

                        # Update extensions with virtual delete markers
                        updated_extensions = current_metadata.extensions.model_dump()
                        updated_extensions["virtual_deleted"] = True
                        updated_extensions["deletion_timestamp"] = (
                            FlextUtilities.Generators.generate_iso_timestamp()
                        )

                        updated_metadata = current_metadata.model_copy(
                            update={"extensions": updated_extensions},
                        )

                        deleted_entry = entry.model_copy(
                            update={"metadata": updated_metadata},
                        )
                        deleted_entries.append(deleted_entry)
                    else:
                        active_entries.append(entry)

                return FlextResult[dict[str, list[FlextLdifModels.Entry]]].ok(
                    {
                        "active": active_entries,
                        "virtual_deleted": deleted_entries,
                        "archive": deleted_entries,  # Archive copy for recovery
                    },
                )

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

                    new_extensions = entry.metadata.extensions.model_dump()
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
    _last_event: FlextLdifModelsEvents.FilterEvent | None = PrivateAttr(default=None)

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
    ) -> FlextResult[FlextLdifTypes.Models.ServiceResponseTypes]:
        """Execute filtering based on filter_criteria and mode."""
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

                # Build filter criteria dict with only valid FilterCriteria fields
                criteria_dict: dict[str, object] = {
                    "filter_type": self.filter_criteria,
                    "mode": self.mode,
                }
                if self.dn_pattern:
                    criteria_dict["pattern"] = self.dn_pattern
                # FilterCriteria doesn't have objectclass, attributes, or base_dn fields
                # These are stored in the filter service itself, not in FilterCriteria
                filter_event = FlextLdifModelsEvents.FilterEvent(
                    unique_id=f"filter_{FlextUtilities.Generators.generate_short_id(8)}",
                    event_type="ldif.filter",
                    aggregate_id=f"filter_{FlextUtilities.Generators.generate_short_id(8)}",
                    created_at=datetime.now(UTC),
                    filter_operation=f"filter_by_{self.filter_criteria}",
                    entries_before=entries_before,
                    entries_after=entries_after,
                    filter_criteria=[
                        FlextLdifModelsConfig.FilterCriteria(**criteria_dict),
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

    def get_last_event(self) -> FlextLdifModelsEvents.FilterEvent | None:
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
        instance = cls.model_validate({
            "entries": entries,
            "filter_criteria": criteria,
            "dn_pattern": pattern,
            "objectclass": objectclass,
            "required_attributes": required_attributes,
            "attributes": attributes,
            "base_dn": base_dn,
            "mode": mode,
            "match_all": match_all,
            "mark_excluded": mark_excluded,
        })
        return instance.execute()

    @classmethod
    def builder(cls) -> FlextLdifFilters:
        """Create fluent builder instance."""
        return cls.model_validate({"entries": []})

    def with_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextLdifFilters:
        """Set entries to filter (fluent builder)."""
        return self.model_copy(update={"entries": entries})

    def with_dn_pattern(self, pattern: str) -> FlextLdifFilters:
        """Set DN pattern filter (fluent builder)."""
        return self.model_copy(update={"filter_criteria": "dn", "dn_pattern": pattern})

    def with_objectclass(self, *classes: str) -> FlextLdifFilters:
        """Set objectClass filter (fluent builder)."""
        # Use tuple if classes provided, None if empty
        objectclass_value = tuple(classes) if classes else None
        return self.model_copy(update={"filter_criteria": "objectclass", "objectclass": objectclass_value})

    def with_required_attributes(self, attributes: list[str]) -> FlextLdifFilters:
        """Set required attributes (fluent builder)."""
        return self.model_copy(update={"required_attributes": attributes})

    def with_attributes(self, attributes: list[str]) -> FlextLdifFilters:
        """Set attribute filter (fluent builder)."""
        return self.model_copy(update={"filter_criteria": "attributes", "attributes": attributes})

    def with_base_dn(self, base_dn: str) -> FlextLdifFilters:
        """Set base DN filter (fluent builder)."""
        return self.model_copy(update={"filter_criteria": "base_dn", "base_dn": base_dn})

    def with_mode(self, mode: str) -> FlextLdifFilters:
        """Set filter mode: include|exclude (fluent builder)."""
        return self.model_copy(update={"mode": mode})

    def with_match_all(self, *, match_all: bool = True) -> FlextLdifFilters:
        """Set attribute matching: ALL (True) or ANY (False) (fluent builder)."""
        return self.model_copy(update={"match_all": match_all})

    def exclude_matching(self) -> FlextLdifFilters:
        """Invert filter to exclude matching entries (fluent builder)."""
        return self.model_copy(update={"mode": FlextLdifConstants.Modes.EXCLUDE})

    def build(self) -> FlextLdifModels.EntryResult:
        """Execute and return unwrapped result (fluent terminal)."""
        # execute() returns ServiceResponseTypes but we know it's always EntryResult for FlextLdifFilters
        result = self.execute().unwrap()
        # Type narrowing: result is EntryResult for FlextLdifFilters
        if isinstance(result, FlextLdifModels.EntryResult):
            return result
        msg = f"Expected EntryResult but got {type(result).__name__}"
        raise TypeError(msg)

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
    # STATIC METHODS - Direct access to Filter nested class
    # ════════════════════════════════════════════════════════════════════════

    @staticmethod
    def filter_by_dn(
        entries: list[FlextLdifModels.Entry],
        dn_pattern: str,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        *,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by DN pattern.

        Prefer using by_dn() classmethod for consistency.
        """
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
        """Filter entries by objectClass.

        Prefer using by_objectclass() classmethod for consistency.
        """
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
        """Filter entries by attribute presence.

        Prefer using by_attributes() classmethod for consistency.
        """
        return FlextLdifFilters.Filter.filter_by_attributes(
            entries,
            attributes,
            match_all=match_all,
            mode=mode,
            mark_excluded=mark_excluded,
        )

    @classmethod
    def is_schema(cls, entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is a REAL schema entry with schema definitions.

        DELEGATED TO: FlextLdifSchema.is_schema()
        """
        return FlextLdifSchema.is_schema(entry)

    @classmethod
    def extract_acl_entries(
        cls,
        entries: list[FlextLdifModels.Entry],
        acl_attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Extract entries with ACL attributes.

        DELEGATED TO: FlextLdifAcl.extract_acl_entries()
        """
        acl_service = FlextLdifAcl()
        return acl_service.extract_acl_entries(entries, acl_attributes)

    @classmethod
    def remove_attributes(
        cls,
        entry: FlextLdifModels.Entry,
        attributes: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove attributes from entry.

        DELEGATED TO: FlextLdifEntries.remove_attributes()
        """
        entries_service = FlextLdifEntries()
        return entries_service.remove_attributes(entry, attributes)

    @classmethod
    def remove_objectclasses(
        cls,
        entry: FlextLdifModels.Entry,
        objectclasses: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove objectClasses from entry.

        DELEGATED TO: FlextLdifEntries.remove_objectclasses()
        """
        entries_service = FlextLdifEntries()
        return entries_service.remove_objectclasses(entry, objectclasses)

    @classmethod
    def remove_attributes_with_tracking(
        cls,
        entry: FlextLdifModels.Entry,
        attributes: list[str],
        *,
        reason: str = "",
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove attributes and record transformation tracking in metadata.

        Combines attribute removal with metadata tracking for transformation comments.
        Useful for migrations where you need to record which attributes were removed
        and why (for documentation/audit purposes).

        Args:
            entry: Entry to modify
            attributes: List of attribute names to remove
            reason: Human-readable reason for removal (tracked in metadata)

        Returns:
            FlextResult with updated entry (attributes removed + transformation tracked)

        Example:
            result = FlextLdif.filters.remove_attributes_with_tracking(
                entry,
                ["nsds5ReplicaId", "nsslapd-maxbersize"],
                reason="Removed server-specific attributes"
            )

        """
        if not attributes:
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        # Track each attribute removal in metadata for transformation comments
        # Ensure metadata exists before tracking
        current_metadata = entry.metadata
        if current_metadata is None:
            current_metadata = FlextLdifModels.QuirkMetadata(
                quirk_type="filter_tracking",
            )

        updated_entry = entry
        for attr_name in attributes:
            # Get original values before removal (for metadata tracking)
            attr_lower = attr_name.lower()
            matching_attr = None
            original_values: list[str] = []

            for key, values in updated_entry.attributes.items():
                if key.lower() == attr_lower:
                    matching_attr = key
                    original_values = (
                        list(values)
                        if isinstance(values, (list, tuple))
                        else [str(values)]
                    )
                    break

            if matching_attr:
                # Track the transformation using FlextLdifUtilities.Metadata
                FlextLdifUtilities.Metadata.track_transformation(
                    metadata=current_metadata,
                    original_name=matching_attr,
                    target_name=None,
                    original_values=original_values,
                    target_values=None,
                    transformation_type="removed",
                    reason=reason,
                )

            # Remove the attribute using standard removal
            remove_result = cls.remove_attributes(updated_entry, [attr_name])
            if remove_result.is_success:
                updated_entry = remove_result.unwrap()
                # Update metadata reference for next iteration
                if updated_entry.metadata:
                    current_metadata = updated_entry.metadata

        # Ensure final entry has updated metadata
        if current_metadata and updated_entry.metadata != current_metadata:
            updated_entry = updated_entry.model_copy(
                update={"metadata": current_metadata},
            )

        return FlextResult[FlextLdifModels.Entry].ok(updated_entry)

    @classmethod
    def filter_entry(
        cls,
        entry: FlextLdifModels.Entry,
        forbidden_attributes: list[str] | None = None,
        forbidden_objectclasses: list[str] | None = None,
        *,
        track_removed: bool = False,
        removal_reason: str = "",
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Unified entry filtering for both attributes and objectClasses.

        Convenience method that removes forbidden attributes and objectClasses
        in a single operation, optionally tracking transformations for comments.

        Args:
            entry: Entry to filter
            forbidden_attributes: List of attribute names to remove
            forbidden_objectclasses: List of objectClass names to remove
            track_removed: If True, track removed attributes in metadata
            removal_reason: Reason for removal (used in metadata tracking)

        Returns:
            FlextResult with filtered entry

        Example:
            result = FlextLdif.filters.filter_entry(
                entry,
                forbidden_attributes=["nsds5ReplicaId"],
                forbidden_objectclasses=["top"],
                track_removed=True,
                removal_reason="Blocked by policy"
            )

        """
        filtered_entry = entry

        # Remove attributes
        if forbidden_attributes:
            if track_removed:
                remove_result = cls.remove_attributes_with_tracking(
                    filtered_entry,
                    forbidden_attributes,
                    reason=removal_reason,
                )
            else:
                remove_result = cls.remove_attributes(
                    filtered_entry,
                    forbidden_attributes,
                )
            if not remove_result.is_success:
                return remove_result
            filtered_entry = remove_result.unwrap()

        # Remove objectClasses
        if forbidden_objectclasses:
            oc_result = cls.remove_objectclasses(
                filtered_entry,
                forbidden_objectclasses,
            )
            if not oc_result.is_success:
                return oc_result
            filtered_entry = oc_result.unwrap()

        return FlextResult[FlextLdifModels.Entry].ok(filtered_entry)

    @classmethod
    def filter_acls_by_base_dn(
        cls,
        acl_entries: list[FlextLdifModels.Entry],
        base_dn: str,
    ) -> tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]:
        """Filter ACL entries with special handling for system ACLs.

        ACLs have special filtering rules:
        - ACLs WITH base DN in DN → filter by base DN using by_base_dn()
        - ACLs WITHOUT base DN in DN → keep all (system ACLs)

        This is a specialized filter method for LDAP migrations where system ACLs
        (those not tied to a specific base DN) must be preserved.

        Args:
            acl_entries: List of ACL entries to filter
            base_dn: Base DN to filter by (e.g., "dc=example,dc=com")

        Returns:
            Tuple of (included_acls, excluded_acls) where:
            - included_acls = ACLs with base DN + all ACLs without base DN (system ACLs)
            - excluded_acls = ACLs with base DN outside filter

        Example:
            included, excluded = FlextLdif.filters.filter_acls_by_base_dn(
                acl_entries,
                "dc=example,dc=com"
            )

        """
        if not base_dn:
            # No base DN filter - return all as included
            return (acl_entries, [])

        # Separate ACLs based on whether they have the base DN in their DN
        acls_with_basedn: list[FlextLdifModels.Entry] = []
        acls_without_basedn: list[FlextLdifModels.Entry] = []

        base_dn_norm_result = FlextLdifUtilities.DN.norm(base_dn)
        base_dn_norm = (
            base_dn_norm_result.unwrap()
            if base_dn_norm_result.is_success
            else base_dn.lower()
        )

        for acl_entry in acl_entries:
            if acl_entry.dn:
                # Get DN value (handle both DistinguishedName model and string)
                dn_value = (
                    acl_entry.dn.value
                    if hasattr(acl_entry.dn, "value")
                    else str(acl_entry.dn)
                )
                entry_dn_norm_result = FlextLdifUtilities.DN.norm(dn_value)
                entry_dn_norm = (
                    entry_dn_norm_result.unwrap()
                    if entry_dn_norm_result.is_success
                    else dn_value.lower()
                )
                (
                    acls_with_basedn
                    if base_dn_norm in entry_dn_norm
                    else acls_without_basedn
                ).append(acl_entry)
            else:
                acls_without_basedn.append(acl_entry)

        # Filter ACLs that have base DN
        if not acls_with_basedn:
            # No ACLs to filter - return all system ACLs as included
            return (acls_without_basedn, [])

        # Filter by base DN (returns tuple of included, excluded)
        included_acls, excluded_acls = cls.by_base_dn(
            acls_with_basedn,
            base_dn,
            mark_excluded=True,
        )

        # Mark excluded ACLs as rejected in metadata using FlextLdifUtilities.Metadata
        updated_excluded: list[FlextLdifModels.Entry] = []
        for entry in excluded_acls:
            if entry.metadata and entry.metadata.processing_stats:
                updated_entry = FlextLdifUtilities.Metadata.update_entry_statistics(
                    entry,
                    mark_rejected=(
                        FlextLdifConstants.RejectionCategory.BASE_DN_FILTER,
                        f"ACL DN outside base DN: {entry.dn}",
                    ),
                )
                updated_excluded.append(updated_entry)
            else:
                updated_excluded.append(entry)
        excluded_acls = updated_excluded

        # Combine: filtered ACLs + all system ACLs (kept because they're not base DN specific)
        return (included_acls + acls_without_basedn, excluded_acls)

    @classmethod
    def categorize(
        cls,
        entry: FlextLdifModels.Entry,
        rules: FlextLdifModels.CategoryRules | Mapping[str, list[str]] | None,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral
        | str
        | None = None,
        *,
        server_registry: FlextLdifServer | None = None,
        categorization_service: FlextLdifProtocols.Services.CategorizationServiceProtocol
        | None = None,
    ) -> tuple[FlextLdifConstants.LiteralTypes.CategoryLiteral, str | None]:
        """Categorize entry using SERVER-SPECIFIC rules.

        DELEGATED TO: FlextLdifCategorization.categorize_entry()

        Uses server-specific constants from FlextLdifServer registry via DI.
        No direct knowledge of OID, OUD, etc. - all via server registry.

        Uses Entry + Metadata pattern: determines server_type from entry.metadata.quirk_type
        if not provided, falling back to FlextLdifServer registry defaults.

        Categories (server-specific priority via FlextLdifServer):
        - schema: Has attributeTypes/objectClasses
        - users: User accounts (server-specific objectClasses from registry)
        - hierarchy: Containers (server-specific objectClasses from registry)
        - groups: Group entries (server-specific objectClasses from registry)
        - acl: Entries with ACL attributes (server-specific attributes from registry)
        - rejected: No match

        Args:
            entry: LDIF entry to categorize
            rules: Category rules (can override server defaults)
            server_type: Server type (FlextLdifConstants.ServerTypes.*) - if None, uses entry.metadata.quirk_type
            server_registry: FlextLdifServer instance for DI (defaults to global instance)

        Returns:
            Tuple of (category, rejection_reason)

        """
        # Determine effective server_type using Entry + Metadata pattern
        effective_server_type = server_type
        if (
            effective_server_type is None
            and entry.metadata
            and entry.metadata.quirk_type
        ):
            effective_server_type = entry.metadata.quirk_type
        if effective_server_type is None:
            # Fallback to global registry default (first registered server or RFC)
            registry = server_registry or FlextLdifServer.get_global_instance()
            registered = registry.list_registered_servers()
            effective_server_type = (
                registered[0] if registered else FlextLdifConstants.ServerTypes.RFC
            )

        # Use categorization service via protocol (dependency injection via registry)
        if categorization_service is None:
            # Get categorization service from registry (breaks circular dependency)
            categorization_service = (
                FlextLdifServiceRegistry.get_categorization_service(
                    effective_server_type,
                )
            )

        return categorization_service.categorize_entry(
            entry,
            rules,
            effective_server_type,
        )

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

        ls_oids = allowed_oids.get("allowed_ldapsyntaxes_oids")
        if ls_oids is None:
            ls_oids = allowed_oids.get("ldapsyntaxes")
        allowed_ls_oids = ls_oids if ls_oids is not None else []

        return (
            allowed_attr_oids,
            allowed_oc_oids,
            allowed_mr_oids,
            allowed_mru_oids,
            allowed_ls_oids,
        )

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
        return any(
            [
                attrs_copy.get("attributeTypes") or attrs_copy.get("attributetypes"),
                attrs_copy.get("objectClasses") or attrs_copy.get("objectclasses"),
                attrs_copy.get("matchingRules") or attrs_copy.get("matchingrules"),
                attrs_copy.get("matchingRuleUse") or attrs_copy.get("matchingruleuse"),
                attrs_copy.get("ldapSyntaxes") or attrs_copy.get("ldapsyntaxes"),
            ],
        )

    @classmethod
    def filter_schema_by_oids(
        cls,
        entries: list[FlextLdifModels.Entry],
        allowed_oids: dict[str, list[str]],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter schema entries by allowed OID patterns.

        Filters INDIVIDUAL DEFINITIONS within schema attributes (attributeTypes,
        objectClasses, matchingRules, matchingRuleUse, ldapSyntaxes) to keep only those with
        OIDs matching the allowed patterns.

        Key improvement: Instead of filtering entire entries based on whether they
        contain ANY whitelisted OID, this method filters the DEFINITIONS WITHIN
        each attribute to keep only whitelisted ones.
        """
        if not entries or not allowed_oids:
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        # Extract allowed OIDs for each schema type (all 4 types: attributetypes, objectclasses, matchingrules, ldapsyntaxes)
        (
            allowed_attr_oids,
            allowed_oc_oids,
            allowed_mr_oids,
            allowed_mru_oids,
            allowed_ls_oids,
        ) = cls._extract_allowed_oids(allowed_oids)

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
            cls._filter_schema_attribute(
                attrs_copy,
                ("ldapSyntaxes", "ldapsyntaxes"),
                allowed_ls_oids,
            )

            # Only keep entry if it has definitions remaining after filtering
            if cls._has_remaining_definitions(attrs_copy):
                # Create new entry with filtered attributes
                # Convert dict[str, list[str]] to dict[str, list[str] | str] explicitly
                attrs_typed: dict[str, list[str] | str] = dict(attrs_copy)
                filtered_entry_result = FlextLdifModels.Entry.create(
                    dn=entry.dn.value,
                    attributes=attrs_typed,
                    entry_metadata=getattr(entry, "entry_metadata", None),
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
                    else:
                        # Use Filter directly
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
        if FlextRuntime.is_dict_like(whitelist_rules) and isinstance(
            whitelist_rules,
            dict,
        ):
            # Type narrowing: use Mapping protocol for safe access
            blocked_objectclasses = whitelist_rules.get("blocked_objectclasses")
            rules_model = FlextLdifModels.WhitelistRules(
                blocked_objectclasses=[str(v) for v in blocked_objectclasses]
                if isinstance(blocked_objectclasses, list)
                else [],
            )
        elif whitelist_rules is None:
            rules_model = None
        elif isinstance(whitelist_rules, FlextLdifModels.WhitelistRules):
            rules_model = whitelist_rules
        else:
            # Fallback: create empty WhitelistRules
            rules_model = FlextLdifModels.WhitelistRules()

        return FlextLdifFilters.Categorizer.check_blocked_objectclasses(
            entry,
            rules_model,
        )

    @staticmethod
    def validate_category_dn_pattern(
        entry: FlextLdifModels.Entry,
        category: FlextLdifConstants.LiteralTypes.CategoryLiteral | str,
        rules: FlextLdifModels.CategoryRules | dict[str, list[str]],
    ) -> tuple[bool, str | None]:
        """Validate DN pattern for specific category.

        Accepts CategoryRules model or dict for backward compatibility.
        """
        # Convert dict to model if needed
        if FlextRuntime.is_dict_like(rules) and isinstance(rules, dict):
            # Type narrowing with isinstance for safe access
            user_dn_patterns = rules.get("user_dn_patterns") or rules.get(
                "users",
            )
            group_dn_patterns = rules.get("group_dn_patterns") or rules.get(
                "groups",
            )
            hierarchy_dn_patterns = rules.get(
                "hierarchy_dn_patterns",
            ) or rules.get("hierarchy")
            schema_dn_patterns = rules.get("schema_dn_patterns") or rules.get(
                "schema",
            )
            user_objectclasses = rules.get("user_objectclasses", [])
            group_objectclasses = rules.get("group_objectclasses", [])
            hierarchy_objectclasses = rules.get("hierarchy_objectclasses", [])
            acl_attributes = rules.get("acl_attributes") or rules.get("acl")
            rules_model = FlextLdifModels.CategoryRules(
                user_dn_patterns=list(user_dn_patterns)
                if isinstance(user_dn_patterns, list)
                else [],
                group_dn_patterns=list(group_dn_patterns)
                if isinstance(group_dn_patterns, list)
                else [],
                hierarchy_dn_patterns=list(hierarchy_dn_patterns)
                if isinstance(hierarchy_dn_patterns, list)
                else [],
                schema_dn_patterns=list(schema_dn_patterns)
                if isinstance(schema_dn_patterns, list)
                else [],
                user_objectclasses=list(user_objectclasses)
                if isinstance(user_objectclasses, list)
                else [],
                group_objectclasses=list(group_objectclasses)
                if isinstance(group_objectclasses, list)
                else [],
                hierarchy_objectclasses=list(hierarchy_objectclasses)
                if isinstance(hierarchy_objectclasses, list)
                else [],
                acl_attributes=list(acl_attributes)
                if isinstance(acl_attributes, list)
                else [],
            )
        elif isinstance(rules, FlextLdifModels.CategoryRules):
            rules_model = rules
        else:
            # Fallback: create empty CategoryRules
            rules_model = FlextLdifModels.CategoryRules()

        return FlextLdifFilters.Categorizer.validate_category_dn_pattern(
            entry,
            category,
            rules_model,
        )

    @staticmethod
    def categorize_entry(
        entry: FlextLdifModels.Entry,
        rules: FlextLdifModels.CategoryRules | Mapping[str, list[str] | str] | None,
        whitelist_rules: FlextLdifModels.WhitelistRules
        | Mapping[str, list[str] | str]
        | None = None,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral
        | str
        | None = None,
        *,
        server_registry: FlextLdifServer | None = None,
        categorization_service: FlextLdifProtocols.Services.CategorizationServiceProtocol
        | None = None,
    ) -> tuple[FlextLdifConstants.LiteralTypes.CategoryLiteral, str | None]:
        """Categorize entry into 6 categories.

        Uses type-safe Pydantic models instead of dict[str, Any].
        Delegates to FlextLdifFilters.categorize, with optional whitelist validation.

        Uses Entry + Metadata pattern: determines server_type from entry.metadata.quirk_type
        if not provided, falling back to FlextLdifServer registry defaults.

        Args:
            entry: Entry to categorize
            rules: Categorization rules (model or dict)
            whitelist_rules: Schema whitelist rules (optional)
            server_type: LDAP server type (oid, oud, rfc, etc.) - if None, uses entry.metadata.quirk_type
            server_registry: FlextLdifServer instance for DI (defaults to global instance)

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

        # Determine effective server_type using Entry + Metadata pattern
        # Priority: parameter > entry.metadata.quirk_type > registry default
        effective_server_type = server_type
        if (
            effective_server_type is None
            and entry.metadata
            and entry.metadata.quirk_type
        ):
            effective_server_type = entry.metadata.quirk_type
        if effective_server_type is None:
            # Fallback to global registry default (first registered server or RFC)
            registry = server_registry or FlextLdifServer.get_global_instance()
            registered = registry.list_registered_servers()
            effective_server_type = (
                registered[0] if registered else FlextLdifConstants.ServerTypes.RFC
            )

        # Use categorization service via protocol (dependency injection via registry)
        if categorization_service is None:
            # Get categorization service from registry (breaks circular dependency)
            categorization_service = (
                FlextLdifServiceRegistry.get_categorization_service(
                    effective_server_type,
                )
            )

        category, reason = categorization_service.categorize_entry(
            entry,
            normalized_rules,
            effective_server_type,
        )

        # Validate DN patterns for category-specific matching using helper
        if category in {
            FlextLdifConstants.Categories.USERS,
            FlextLdifConstants.Categories.GROUPS,
        }:
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
    def filter_entry_attributes(
        entry: FlextLdifModels.Entry,
        attributes_to_remove: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Mark attributes for removal in entry metadata (SRP - never removes)."""
        return FlextLdifFilters.Transformer.filter_entry_attributes(
            entry,
            attributes_to_remove,
        )

    @staticmethod
    def filter_entry_objectclasses(
        entry: FlextLdifModels.Entry,
        objectclasses_to_remove: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Mark objectClasses for removal in entry metadata (SRP - never removes)."""
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

    @staticmethod
    def apply_standard_filters(
        entries: list[FlextLdifModels.Entry],
        objectclass: str | None = None,
        dn_pattern: str | None = None,
        attributes: dict[str, str | None] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Apply standard filters (objectclass, DN pattern, attributes) to entries.

        Internal helper method to reduce complexity in filter() method.

        Args:
            entries: List of entries to filter
            objectclass: Optional objectclass filter
            dn_pattern: Optional DN pattern filter
            attributes: Optional attributes filter

        Returns:
            FlextResult containing filtered entries

        """
        # Apply objectclass filter if provided
        if objectclass is not None:
            filter_result = FlextLdifFilters.by_objectclass(
                entries,
                objectclass,
                mark_excluded=False,
            )
            if not filter_result.is_success:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Objectclass filter failed: {filter_result.error}",
                )
            entries = filter_result.unwrap()

        # Apply dn_pattern filter if provided
        if dn_pattern is not None:
            # Convert simple substring pattern to fnmatch pattern
            fnmatch_pattern = f"*{dn_pattern}*" if "*" not in dn_pattern else dn_pattern
            filter_result = FlextLdifFilters.by_dn(
                entries,
                fnmatch_pattern,
                mark_excluded=False,
            )
            if not filter_result.is_success:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"DN pattern filter failed: {filter_result.error}",
                )
            entries = filter_result.unwrap()

        # Apply attributes filter if provided
        if attributes is not None:
            attr_list = list(attributes.keys())
            filter_result = FlextLdifFilters.by_attributes(
                entries,
                attr_list,
                mark_excluded=False,
            )
            if not filter_result.is_success:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Attributes filter failed: {filter_result.error}",
                )
            entries = filter_result.unwrap()

        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)


__all__ = ["FlextLdifFilters"]
