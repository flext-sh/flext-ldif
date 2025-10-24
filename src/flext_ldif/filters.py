"""FLEXT LDIF Filters - Filtering and Categorization Utilities.

This module provides utilities for filtering and categorizing LDIF entries:
- DN pattern matching with wildcards
- OID pattern matching for schema filtering
- ObjectClass-based filtering with attribute validation
- Attribute-based filtering
- Entry categorization (users, groups, containers)
- Exclusion metadata marking

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import fnmatch
import re
from datetime import UTC, datetime

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifFilters:
    """Utility class for LDIF filtering and categorization operations.

    Provides static methods for:
    - Pattern matching (DN wildcards, OID patterns)
    - Exclusion metadata management
    - Entry categorization by objectClass
    - Attribute presence/absence filtering

    All methods use fnmatch for wildcard pattern matching, supporting:
    - * (matches any sequence of characters)
    - ? (matches any single character)
    - [seq] (matches any character in seq)
    - [!seq] (matches any character not in seq)
    """

    @staticmethod
    def matches_dn_pattern(dn: str, pattern: str) -> bool:
        """Check if DN matches wildcard pattern.

        Uses fnmatch for pattern matching. Case-insensitive comparison.

        Args:
            dn: Distinguished name to check
            pattern: Wildcard pattern (e.g., "*,ou=users,dc=example,dc=com")

        Returns:
            True if DN matches pattern, False otherwise

        Example:
            >>> FlextLdifFilters.matches_dn_pattern(
            ...     "cn=john,ou=users,dc=example,dc=com", "*,ou=users,dc=example,dc=com"
            ... )
            True

        """
        return fnmatch.fnmatch(dn.lower(), pattern.lower())

    @staticmethod
    def matches_oid_pattern(oid: str, patterns: list[str]) -> bool:
        """Check if OID matches any pattern in list.

        Uses fnmatch for pattern matching. Supports wildcards in OID patterns.

        Args:
            oid: OID string to check (e.g., "1.3.6.1.4.1.111.2.3")
            patterns: List of OID patterns (e.g., ["1.3.6.1.4.1.111.*", "2.16.840.1.113894.*"])

        Returns:
            True if OID matches any pattern, False otherwise

        Example:
            >>> FlextLdifFilters.matches_oid_pattern(
            ...     "1.3.6.1.4.1.111.2.3.4", ["1.3.6.1.4.1.111.*"]
            ... )
            True

        """
        return any(fnmatch.fnmatch(oid, pattern) for pattern in patterns)

    @staticmethod
    def mark_entry_excluded(
        entry: FlextLdifModels.Entry,
        reason: str,
        filter_criteria: FlextLdifModels.FilterCriteria | None = None,
    ) -> FlextLdifModels.Entry:
        """Mark entry as excluded by adding exclusion metadata.

        Creates or updates QuirkMetadata with ExclusionInfo in extensions.
        Returns a new Entry instance with updated metadata (entries are frozen).

        Args:
            entry: Entry to mark as excluded
            reason: Human-readable exclusion reason
            filter_criteria: Optional filter criteria that caused exclusion

        Returns:
            New Entry instance with updated metadata

        Example:
            >>> entry = Entry(...)
            >>> marked = FlextLdifFilters.mark_entry_excluded(
            ...     entry,
            ...     "DN outside base context",
            ...     FilterCriteria(filter_type="dn_pattern", pattern="*,dc=old,dc=com"),
            ... )

        """
        # Create exclusion info
        exclusion_info = FlextLdifModels.ExclusionInfo(
            excluded=True,
            exclusion_reason=reason,
            filter_criteria=filter_criteria,
            timestamp=datetime.now(UTC).isoformat(),
        )

        # Create new metadata with exclusion info
        if entry.metadata is None:
            new_metadata = FlextLdifModels.QuirkMetadata(
                extensions={"exclusion_info": exclusion_info.model_dump()}
            )
        else:
            # Preserve existing extensions and add exclusion_info
            new_extensions: dict[str, object] = {**entry.metadata.extensions}
            # model_dump() returns dict[str, object] which is compatible with dict[str, object]
            new_extensions["exclusion_info"] = exclusion_info.model_dump()
            updated_metadata: FlextLdifModels.QuirkMetadata = (
                FlextLdifModels.QuirkMetadata(
                    original_format=entry.metadata.original_format,
                    quirk_type=entry.metadata.quirk_type,
                    parsed_timestamp=entry.metadata.parsed_timestamp,
                    extensions=new_extensions,
                    custom_data=entry.metadata.custom_data,
                )
            )
            new_metadata = updated_metadata

        # Return new entry with updated metadata (models are frozen)
        return entry.model_copy(update={"metadata": new_metadata})

    @staticmethod
    def is_entry_excluded(entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is marked as excluded.

        Args:
        entry: Entry to check

        Returns:
        True if entry has exclusion metadata, False otherwise

        """
        if entry.metadata is None:
            return False

        # Type guard: entry.metadata is not None (pyrefly compliant)
        if entry.metadata is None:
            return False

        # Get exclusion_info dict[str, object] from extensions (stored via model_dump())
        exclusion_info_raw: object = entry.metadata.extensions.get("exclusion_info")
        if exclusion_info_raw is None:
            return False

        # Type narrowing: exclusion_info is a dict[str, object] from model_dump()
        if not isinstance(exclusion_info_raw, dict):
            return False

        exclusion_info: dict[str, object] = exclusion_info_raw

        # Get excluded field from dict[str, object] (type-safe access)
        excluded_value: object = exclusion_info.get("excluded")
        if excluded_value is None:
            return False

        # Type narrowing: excluded must be bool
        if not isinstance(excluded_value, bool):
            return False

        return excluded_value

    @staticmethod
    def get_exclusion_reason(entry: FlextLdifModels.Entry) -> str | None:
        """Get exclusion reason from entry metadata.

        Args:
        entry: Entry to check

        Returns:
        Exclusion reason string or None if not excluded

        """
        if entry.metadata is None:
            return None

        # Type guard: entry.metadata is not None (pyrefly compliant)
        if entry.metadata is None:
            return None

        # Get exclusion_info dict[str, object] from extensions (stored via model_dump())
        exclusion_info_raw: object = entry.metadata.extensions.get("exclusion_info")
        if exclusion_info_raw is None:
            return None

        # Type narrowing: exclusion_info is a dict[str, object] from model_dump()
        if not isinstance(exclusion_info_raw, dict):
            return None

        exclusion_info: dict[str, object] = exclusion_info_raw

        # Get exclusion_reason field from dict[str, object] (type-safe access)
        reason_value: object = exclusion_info.get("exclusion_reason")
        if reason_value is None:
            return None

        # Type narrowing: reason must be str
        if not isinstance(reason_value, str):
            return None

        return reason_value

    @staticmethod
    def has_objectclass(
        entry: FlextLdifModels.Entry, objectclasses: tuple[str, ...]
    ) -> bool:
        """Check if entry has any of the specified objectClasses.

        Case-insensitive comparison.

        Args:
        entry: Entry to check
        objectclasses: Tuple of objectClass names to check

        Returns:
        True if entry has any of the objectClasses, False otherwise

        """
        entry_classes = entry.get_attribute_values(
            FlextLdifConstants.DictKeys.OBJECTCLASS
        )
        if not entry_classes:
            return False

        entry_classes_lower = [cls.lower() for cls in entry_classes]
        objectclasses_lower = [cls.lower() for cls in objectclasses]

        return any(cls in entry_classes_lower for cls in objectclasses_lower)

    @staticmethod
    def has_required_attributes(
        entry: FlextLdifModels.Entry, required_attributes: list[str]
    ) -> bool:
        """Check if entry has all required attributes.

        Args:
        entry: Entry to check
        required_attributes: List of required attribute names

        Returns:
        True if entry has all required attributes, False otherwise

        """
        return all(entry.has_attribute(attr) for attr in required_attributes)

    @staticmethod
    def _matches_dn_pattern(dn: str, patterns: list[str]) -> bool:
        """Check if DN matches any of the provided regex patterns.

        Args:
            dn: Distinguished Name to check
            patterns: List of regex patterns to match against

        Returns:
            True if DN matches any pattern, False otherwise

        Raises:
            ValueError: If any pattern is invalid regex

        """
        invalid_patterns = []
        for pattern in patterns:
            try:
                if re.search(pattern, dn, re.IGNORECASE):
                    return True
            except re.error as e:
                # Collect invalid patterns - do NOT skip silently
                invalid_patterns.append(f"'{pattern}' ({e!s})")

        # If invalid patterns were found, raise error (fail fast, not silent)
        if invalid_patterns:
            error_msg = (
                f"Invalid regex patterns in DN filter: {', '.join(invalid_patterns)}"
            )
            raise ValueError(error_msg)

        return False

    @staticmethod
    def _has_acl_attributes(
        entry: dict[str, object],
        acl_attributes: list[str],
    ) -> bool:
        """Check if entry has ACL-related attributes.

        Args:
            entry: Entry dictionary to check
            acl_attributes: List of ACL attribute names to look for

        Returns:
            True if entry has ACL attributes, False otherwise

        """
        if not acl_attributes:
            return False

        entry_attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
        if not isinstance(entry_attrs, dict):
            return False

        # Case-insensitive attribute lookup (LDIF RFC compliance)
        entry_attrs_lower = {k.lower(): v for k, v in entry_attrs.items()}
        acl_attributes_lower = [attr.lower() for attr in acl_attributes]

        return any(acl_attr in entry_attrs_lower for acl_attr in acl_attributes_lower)

    @staticmethod
    def categorize_entry(
        entry: dict[str, object],
        categorization_rules: dict[
            str, object
        ],  # Contains: hierarchy_objectclasses, user_objectclasses, group_objectclasses, acl_attributes, user_dn_patterns
        schema_whitelist_rules: (
            dict[str, object] | None
        ) = None,  # Contains: blocked_objectclasses, allowed_attribute_oids, allowed_objectclass_oids
    ) -> tuple[str, str | None]:
        """Categorize entry with 6-category support (schema, hierarchy, users, groups, acl, rejected).

        Categorization logic:
        0. Check for blocked objectClasses (ALGAR business rule)
        1. Check for schema entries (attributeTypes, objectClasses)
        2. Check for hierarchy objectClasses → hierarchy (BEFORE ACL!)
        3. Check for user objectClasses → users
        4. Check for group objectClasses → groups
        5. Check for ACL attributes → acl (AFTER hierarchy/users/groups)
        6. Otherwise → rejected

        CRITICAL: Hierarchy check has HIGHER priority than ACL check. This ensures
        Oracle containers (orclcontainer, orclprivilegegroup) with ACL attributes go
        to hierarchy file for proper parent-child sync order.

        Args:
            entry: Entry dictionary to categorize
            categorization_rules: Dictionary with categorization configuration:
                - hierarchy_objectclasses: list of hierarchy objectClass names
                - user_objectclasses: list of user objectClass names
                - group_objectclasses: list of group objectClass names
                - user_dn_patterns: list of regex patterns for user DN validation
                - acl_attributes: list of ACL attribute names to check
            schema_whitelist_rules: Optional dictionary with schema whitelist configuration:
                - blocked_objectclasses: list of objectClasses to reject (ALGAR rule)

        Returns:
            Tuple of (category, rejection_reason):
            - category: one of "schema", "hierarchy", "users", "groups", "acl", "rejected"
            - rejection_reason: None unless category is "rejected"

        """
        if schema_whitelist_rules is None:
            schema_whitelist_rules = {}

        # Get entry DN and objectClasses with proper type narrowing
        dn_value = entry.get(FlextLdifConstants.DictKeys.DN, "")
        dn = dn_value if isinstance(dn_value, str) else ""

        object_classes = entry.get(FlextLdifConstants.DictKeys.OBJECTCLASS, [])
        if not isinstance(object_classes, list):
            object_classes = []

        # Convert objectClasses to lowercase for case-insensitive matching per RFC 4512
        object_classes_lower = [
            oc.lower() if isinstance(oc, str) else oc for oc in object_classes
        ]

        # 0. Check for blocked objectClasses (ALGAR business rule)
        blocked_ocs = schema_whitelist_rules.get("blocked_objectclasses", [])
        if isinstance(blocked_ocs, list) and blocked_ocs:
            blocked_ocs_lower = {
                oc.lower() for oc in blocked_ocs if isinstance(oc, str)
            }
            for obj_class_lower in object_classes_lower:
                if obj_class_lower in blocked_ocs_lower:
                    return (
                        "rejected",
                        f"Blocked objectClass: {obj_class_lower} (OID-specific)",
                    )

        # 1. Schema entries (cn=schema, subschemasubentry, or has schema attributes)
        if "cn=schema" in dn.lower() or "subschemasubentry" in dn.lower():
            return ("schema", None)

        entry_attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
        if isinstance(entry_attrs, dict):
            attrs_lower = {k.lower() for k in entry_attrs}
            if "attributetypes" in attrs_lower or "objectclasses" in attrs_lower:
                return ("schema", None)

        # Get categorization rules with type validation
        hierarchy_classes = categorization_rules.get("hierarchy_objectclasses", [])
        user_classes = categorization_rules.get("user_objectclasses", [])
        group_classes = categorization_rules.get("group_objectclasses", [])
        user_dn_patterns = categorization_rules.get("user_dn_patterns", [])
        acl_attributes = categorization_rules.get("acl_attributes", [])

        if not isinstance(hierarchy_classes, list):
            hierarchy_classes = []
        if not isinstance(user_classes, list):
            user_classes = []
        if not isinstance(group_classes, list):
            group_classes = []
        if not isinstance(user_dn_patterns, list):
            user_dn_patterns = []
        if not isinstance(acl_attributes, list):
            acl_attributes = []

        # Convert to lowercase sets for efficient lookup
        hierarchy_classes_lower = {
            oc.lower() for oc in hierarchy_classes if isinstance(oc, str)
        }
        user_classes_lower = {oc.lower() for oc in user_classes if isinstance(oc, str)}
        group_classes_lower = {
            oc.lower() for oc in group_classes if isinstance(oc, str)
        }

        # 2. Hierarchy entries (BEFORE ACL - critical for Oracle containers)
        for obj_class_lower in object_classes_lower:
            if obj_class_lower in hierarchy_classes_lower:
                return ("hierarchy", None)

        # 3. User entries (with optional DN pattern validation)
        for obj_class_lower in object_classes_lower:
            if obj_class_lower in user_classes_lower:
                if user_dn_patterns and not FlextLdifFilters._matches_dn_pattern(
                    dn, user_dn_patterns
                ):
                    return (
                        "rejected",
                        f"User DN pattern mismatch: {dn}",
                    )
                return ("users", None)

        # 4. Group entries
        for obj_class_lower in object_classes_lower:
            if obj_class_lower in group_classes_lower:
                return ("groups", None)

        # 5. ACL entries (AFTER hierarchy/users/groups)
        if FlextLdifFilters._has_acl_attributes(entry, acl_attributes):
            return ("acl", None)

        # 6. Rejected entries
        return ("rejected", f"No category match for: {object_classes}")

    @staticmethod
    def filter_entries_by_dn(
        entries: list[FlextLdifModels.Entry],
        pattern: str,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        *,
        mark_excluded: bool = True,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by DN pattern.

        Args:
            entries: List of entries to filter
            pattern: DN wildcard pattern
            mode: "include" to keep matches, "exclude" to remove matches
            mark_excluded: If True, mark excluded entries in metadata (keyword-only)

        Returns:
            FlextResult containing filtered entry list

        """
        try:
            filtered: list[FlextLdifModels.Entry] = []

            for entry in entries:
                dn = entry.dn.value
                matches = FlextLdifFilters.matches_dn_pattern(dn, pattern)

                # Determine if entry should be included
                include = (mode == FlextLdifConstants.Modes.INCLUDE and matches) or (
                    mode == FlextLdifConstants.Modes.EXCLUDE and not matches
                )

                if include:
                    filtered.append(entry)
                elif mark_excluded:
                    # Mark as excluded and include in results
                    criteria = FlextLdifModels.FilterCriteria(
                        filter_type=FlextLdifConstants.FilterTypes.DN_PATTERN,
                        pattern=pattern,
                        mode=mode,
                    )
                    marked_entry = FlextLdifFilters.mark_entry_excluded(
                        entry,
                        f"DN pattern {mode} filter: {pattern}",
                        criteria,
                    )
                    filtered.append(marked_entry)

            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)

        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Failed to filter entries by DN: {e}"
            )

    @staticmethod
    def filter_entries_by_objectclass(
        entries: list[FlextLdifModels.Entry],
        objectclass: str | tuple[str, ...],
        required_attributes: list[str] | None = None,
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        *,
        mark_excluded: bool = True,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by objectClass with optional required attributes.

        Args:
            entries: List of entries to filter
            objectclass: Single objectClass or tuple of objectClasses
            required_attributes: Optional list of required attributes
            mode: "include" to keep matches, "exclude" to remove matches
            mark_excluded: If True, mark excluded entries in metadata (keyword-only)

        Returns:
            FlextResult containing filtered entry list

        """
        try:
            # Normalize objectclass to tuple
            if isinstance(objectclass, str):
                objectclass = (objectclass,)

            filtered: list[FlextLdifModels.Entry] = []

            for entry in entries:
                has_class = FlextLdifFilters.has_objectclass(entry, objectclass)

                # Check required attributes if specified
                has_attrs = True
                if required_attributes and has_class:
                    has_attrs = FlextLdifFilters.has_required_attributes(
                        entry, required_attributes
                    )

                matches = has_class and has_attrs

                # Determine if entry should be included
                include = (mode == FlextLdifConstants.Modes.INCLUDE and matches) or (
                    mode == FlextLdifConstants.Modes.EXCLUDE and not matches
                )

                if include:
                    filtered.append(entry)
                elif mark_excluded:
                    # Mark as excluded and include in results
                    criteria = FlextLdifModels.FilterCriteria(
                        filter_type=FlextLdifConstants.DictKeys.OBJECTCLASS,
                        pattern=",".join(objectclass),
                        required_attributes=required_attributes,
                        mode=mode,
                    )
                    reason = f"ObjectClass {mode} filter: {','.join(objectclass)}"
                    if required_attributes:
                        reason += (
                            f" (required attributes: {','.join(required_attributes)})"
                        )
                    marked_entry = FlextLdifFilters.mark_entry_excluded(
                        entry,
                        reason,
                        criteria,
                    )
                    filtered.append(marked_entry)

            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)

        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Failed to filter entries by objectClass: {e}"
            )

    @staticmethod
    def filter_entries_by_attributes(
        entries: list[FlextLdifModels.Entry],
        attributes: list[str],
        mode: str = FlextLdifConstants.Modes.INCLUDE,
        *,
        match_all: bool = False,
        mark_excluded: bool = True,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by attribute presence.

        Args:
            entries: List of entries to filter
            attributes: List of attribute names to check
            mode: "include" to keep entries with attributes, "exclude" to remove them
            match_all: If True, entry must have ALL attributes; if False, ANY attribute (keyword-only)
            mark_excluded: If True, mark excluded entries in metadata (keyword-only)

        Returns:
            FlextResult containing filtered entry list

        """
        try:
            filtered: list[FlextLdifModels.Entry] = []

            for entry in entries:
                if match_all:
                    matches = all(entry.has_attribute(attr) for attr in attributes)
                else:
                    matches = any(entry.has_attribute(attr) for attr in attributes)

                # Determine if entry should be included
                include = (mode == FlextLdifConstants.Modes.INCLUDE and matches) or (
                    mode == FlextLdifConstants.Modes.EXCLUDE and not matches
                )

                if include:
                    filtered.append(entry)
                elif mark_excluded:
                    # Mark as excluded and include in results
                    criteria = FlextLdifModels.FilterCriteria(
                        filter_type=FlextLdifConstants.FilterTypes.ATTRIBUTE,
                        pattern=",".join(attributes),
                        mode=mode,
                    )
                    match_type = (
                        FlextLdifConstants.MatchTypes.ALL
                        if match_all
                        else FlextLdifConstants.MatchTypes.ANY
                    )
                    marked_entry = FlextLdifFilters.mark_entry_excluded(
                        entry,
                        f"Attribute {mode} filter ({match_type}): {','.join(attributes)}",
                        criteria,
                    )
                    filtered.append(marked_entry)

            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)

        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Failed to filter entries by attributes: {e}"
            )

    @staticmethod
    def filter_entry_attributes(
        entry: FlextLdifModels.Entry,
        blocked_attributes: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove specified attributes from entry.

        Creates new Entry with blocked attributes removed. Entry objects are frozen,
        so this returns a new instance.

        Args:
            entry: Entry to filter
            blocked_attributes: List of attribute names to remove (case-insensitive)

        Returns:
            FlextResult with new Entry instance without blocked attributes

        Example:
            >>> entry = FlextLdifModels.Entry(
            ...     dn="cn=test,dc=example",
            ...     attributes={"cn": ["test"], "orclaci": ["access rule"]},
            ... )
            >>> result = FlextLdifFilters.filter_entry_attributes(
            ...     entry, ["orclaci", "orclentrylevelaci"]
            ... )
            >>> filtered_entry = result.unwrap()
            >>> "orclaci" in filtered_entry.attributes
            False

        """
        try:
            # Case-insensitive blocked attribute set
            blocked_lower = {attr.lower() for attr in blocked_attributes}

            # Filter attributes (keep only non-blocked)
            # Note: entry.attributes is LdifAttributes, access underlying dict via .attributes
            filtered_attrs_dict = {
                key: value
                for key, value in entry.attributes.attributes.items()
                if key.lower() not in blocked_lower
            }

            # Create new LdifAttributes container
            new_attributes = FlextLdifModels.LdifAttributes(
                attributes=filtered_attrs_dict,
                metadata=entry.attributes.metadata,
            )

            # Create new Entry (entries are frozen)
            filtered_entry = FlextLdifModels.Entry(
                dn=entry.dn,
                attributes=new_attributes,
                metadata=entry.metadata,  # Preserve metadata
            )

            return FlextResult[FlextLdifModels.Entry].ok(filtered_entry)

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to filter entry attributes: {e}"
            )

    @staticmethod
    def filter_entry_objectclasses(
        entry: FlextLdifModels.Entry,
        blocked_objectclasses: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove specified objectClasses from entry.

        Filters objectClass attribute values, removing blocked classes.
        Creates new Entry with filtered objectClass values.

        Args:
            entry: Entry to filter
            blocked_objectclasses: List of objectClass names to remove (case-insensitive)

        Returns:
            FlextResult with new Entry instance without blocked objectClasses

        Example:
            >>> entry = FlextLdifModels.Entry(
            ...     dn="cn=test,dc=example",
            ...     attributes={"objectClass": ["top", "person", "orclContainerOC"]},
            ... )
            >>> result = FlextLdifFilters.filter_entry_objectclasses(
            ...     entry, ["orclContainerOC", "orclService"]
            ... )
            >>> filtered_entry = result.unwrap()
            >>> "orclContainerOC" in filtered_entry.get_attribute_values("objectClass")
            False

        """
        try:
            # Case-insensitive blocked objectClass set
            blocked_lower = {oc.lower() for oc in blocked_objectclasses}

            # Get objectClass values
            oc_values = entry.get_attribute_values(
                FlextLdifConstants.DictKeys.OBJECTCLASS
            )
            if not oc_values:
                # No objectClass attribute - return entry unchanged
                return FlextResult[FlextLdifModels.Entry].ok(entry)

            # Filter objectClasses (keep only non-blocked)
            filtered_ocs = [oc for oc in oc_values if oc.lower() not in blocked_lower]

            # If no objectClasses remain, fail
            if not filtered_ocs:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Entry {entry.dn}: All objectClasses would be removed"
                )

            # Create new attributes dict with filtered objectClasses
            # Note: entry.attributes is LdifAttributes, access underlying dict via .attributes
            new_attrs_dict = dict(entry.attributes.attributes)
            # Update objectClass attribute with filtered values
            if FlextLdifConstants.DictKeys.OBJECTCLASS in new_attrs_dict:
                new_attrs_dict[
                    FlextLdifConstants.DictKeys.OBJECTCLASS
                ].values = filtered_ocs

            # Create new LdifAttributes container
            new_attributes = FlextLdifModels.LdifAttributes(
                attributes=new_attrs_dict,
                metadata=entry.attributes.metadata,
            )

            # Create new Entry (entries are frozen)
            filtered_entry = FlextLdifModels.Entry(
                dn=entry.dn,
                attributes=new_attributes,
                metadata=entry.metadata,  # Preserve metadata
            )

            return FlextResult[FlextLdifModels.Entry].ok(filtered_entry)

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to filter entry objectClasses: {e}"
            )


__all__ = ["FlextLdifFilters"]
