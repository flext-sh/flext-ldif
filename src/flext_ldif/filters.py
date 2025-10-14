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
from datetime import UTC, datetime

from flext_core import FlextCore

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
    def matches_oid_pattern(oid: str, patterns: FlextCore.Types.StringList) -> bool:
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
            new_extensions["exclusion_info"] = exclusion_info.model_dump()
            new_metadata: FlextLdifModels.QuirkMetadata = FlextLdifModels.QuirkMetadata(
                original_format=entry.metadata.original_format,
                quirk_type=entry.metadata.quirk_type,
                parsed_timestamp=entry.metadata.parsed_timestamp,
                extensions=new_extensions,
                custom_data=entry.metadata.custom_data,
            )

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

        # Get exclusion_info dict from extensions (stored via model_dump())
        exclusion_info_raw: object | None = entry.metadata.extensions.get(
            "exclusion_info"
        )
        if exclusion_info_raw is None:
            return False

        # Type narrowing: exclusion_info is a dict from model_dump()
        if not isinstance(exclusion_info_raw, dict):
            return False

        exclusion_info: dict[str, object] = exclusion_info_raw

        # Get excluded field from dict (type-safe access)
        excluded_value: object | None = exclusion_info.get("excluded")
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

        # Get exclusion_info dict from extensions (stored via model_dump())
        exclusion_info_raw: object | None = entry.metadata.extensions.get(
            "exclusion_info"
        )
        if exclusion_info_raw is None:
            return None

        # Type narrowing: exclusion_info is a dict from model_dump()
        if not isinstance(exclusion_info_raw, dict):
            return None

        exclusion_info: dict[str, object] = exclusion_info_raw

        # Get exclusion_reason field from dict (type-safe access)
        reason_value: object | None = exclusion_info.get("exclusion_reason")
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
        entry_classes = entry.get_attribute_values("objectClass")
        if not entry_classes:
            return False

        entry_classes_lower = [cls.lower() for cls in entry_classes]
        objectclasses_lower = [cls.lower() for cls in objectclasses]

        return any(cls in entry_classes_lower for cls in objectclasses_lower)

    @staticmethod
    def has_required_attributes(
        entry: FlextLdifModels.Entry, required_attributes: FlextCore.Types.StringList
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
    def categorize_entry(
        entry: FlextLdifModels.Entry,
        user_objectclasses: tuple[str, ...],
        group_objectclasses: tuple[str, ...],
        container_objectclasses: tuple[str, ...],
    ) -> str:
        """Categorize entry based on objectClass.

        Checks objectClasses in priority order: users, groups, containers, uncategorized.

        Args:
            entry: Entry to categorize
            user_objectclasses: Tuple of user objectClass names
            group_objectclasses: Tuple of group objectClass names
            container_objectclasses: Tuple of container objectClass names

        Returns:
            Category string: "user", "group", "container", or "uncategorized"

        """
        if FlextLdifFilters.has_objectclass(entry, user_objectclasses):
            return "user"
        if FlextLdifFilters.has_objectclass(entry, group_objectclasses):
            return "group"
        if FlextLdifFilters.has_objectclass(entry, container_objectclasses):
            return "container"
        return "uncategorized"

    @staticmethod
    def filter_entries_by_dn(
        entries: list[FlextLdifModels.Entry],
        pattern: str,
        mode: str = "include",
        *,
        mark_excluded: bool = True,
    ) -> FlextCore.Result[list[FlextLdifModels.Entry]]:
        """Filter entries by DN pattern.

        Args:
            entries: List of entries to filter
            pattern: DN wildcard pattern
            mode: "include" to keep matches, "exclude" to remove matches
            mark_excluded: If True, mark excluded entries in metadata (keyword-only)

        Returns:
            FlextCore.Result containing filtered entry list

        """
        try:
            filtered: list[FlextLdifModels.Entry] = []

            for entry in entries:
                dn = entry.dn.value
                matches = FlextLdifFilters.matches_dn_pattern(dn, pattern)

                # Determine if entry should be included
                include = (mode == "include" and matches) or (
                    mode == "exclude" and not matches
                )

                if include:
                    filtered.append(entry)
                elif mark_excluded:
                    # Mark as excluded and include in results
                    criteria = FlextLdifModels.FilterCriteria(
                        filter_type="dn_pattern",
                        pattern=pattern,
                        mode=mode,
                    )
                    marked_entry = FlextLdifFilters.mark_entry_excluded(
                        entry,
                        f"DN pattern {mode} filter: {pattern}",
                        criteria,
                    )
                    filtered.append(marked_entry)

            return FlextCore.Result[list[FlextLdifModels.Entry]].ok(filtered)

        except Exception as e:
            return FlextCore.Result[list[FlextLdifModels.Entry]].fail(
                f"Failed to filter entries by DN: {e}"
            )

    @staticmethod
    def filter_entries_by_objectclass(
        entries: list[FlextLdifModels.Entry],
        objectclass: str | tuple[str, ...],
        required_attributes: FlextCore.Types.StringList | None = None,
        mode: str = "include",
        *,
        mark_excluded: bool = True,
    ) -> FlextCore.Result[list[FlextLdifModels.Entry]]:
        """Filter entries by objectClass with optional required attributes.

        Args:
            entries: List of entries to filter
            objectclass: Single objectClass or tuple of objectClasses
            required_attributes: Optional list of required attributes
            mode: "include" to keep matches, "exclude" to remove matches
            mark_excluded: If True, mark excluded entries in metadata (keyword-only)

        Returns:
            FlextCore.Result containing filtered entry list

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
                include = (mode == "include" and matches) or (
                    mode == "exclude" and not matches
                )

                if include:
                    filtered.append(entry)
                elif mark_excluded:
                    # Mark as excluded and include in results
                    criteria = FlextLdifModels.FilterCriteria(
                        filter_type="objectclass",
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

            return FlextCore.Result[list[FlextLdifModels.Entry]].ok(filtered)

        except Exception as e:
            return FlextCore.Result[list[FlextLdifModels.Entry]].fail(
                f"Failed to filter entries by objectClass: {e}"
            )

    @staticmethod
    def filter_entries_by_attributes(
        entries: list[FlextLdifModels.Entry],
        attributes: FlextCore.Types.StringList,
        mode: str = "include",
        *,
        match_all: bool = False,
        mark_excluded: bool = True,
    ) -> FlextCore.Result[list[FlextLdifModels.Entry]]:
        """Filter entries by attribute presence.

        Args:
            entries: List of entries to filter
            attributes: List of attribute names to check
            mode: "include" to keep entries with attributes, "exclude" to remove them
            match_all: If True, entry must have ALL attributes; if False, ANY attribute (keyword-only)
            mark_excluded: If True, mark excluded entries in metadata (keyword-only)

        Returns:
            FlextCore.Result containing filtered entry list

        """
        try:
            filtered: list[FlextLdifModels.Entry] = []

            for entry in entries:
                if match_all:
                    matches = all(entry.has_attribute(attr) for attr in attributes)
                else:
                    matches = any(entry.has_attribute(attr) for attr in attributes)

                # Determine if entry should be included
                include = (mode == "include" and matches) or (
                    mode == "exclude" and not matches
                )

                if include:
                    filtered.append(entry)
                elif mark_excluded:
                    # Mark as excluded and include in results
                    criteria = FlextLdifModels.FilterCriteria(
                        filter_type="attribute",
                        pattern=",".join(attributes),
                        mode=mode,
                    )
                    match_type = "all" if match_all else "any"
                    marked_entry = FlextLdifFilters.mark_entry_excluded(
                        entry,
                        f"Attribute {mode} filter ({match_type}): {','.join(attributes)}",
                        criteria,
                    )
                    filtered.append(marked_entry)

            return FlextCore.Result[list[FlextLdifModels.Entry]].ok(filtered)

        except Exception as e:
            return FlextCore.Result[list[FlextLdifModels.Entry]].fail(
                f"Failed to filter entries by attributes: {e}"
            )


__all__ = ["FlextLdifFilters"]
