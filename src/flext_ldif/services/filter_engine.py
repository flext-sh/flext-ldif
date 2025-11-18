"""FLEXT-LDIF Filter Engine Service - Core entry filtering logic.

This service handles all core filtering operations:
- DN pattern matching (wildcards)
- ObjectClass filtering with required attributes
- Attribute presence filtering (match ALL or ANY)
- Base DN filtering (hierarchy)

Extracted from FlextLdifFilters to follow Single Responsibility Principle.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import fnmatch
from datetime import UTC, datetime

from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifFilterEngine(FlextService[FlextLdifTypes.Models.ServiceResponseTypes]):
    """Service for core entry filtering operations.

    Provides methods for:
    - Filtering by DN pattern (wildcard matching)
    - Filtering by objectClass (with optional required attributes)
    - Filtering by attribute presence (match ALL or ANY)
    - Filtering by base DN (hierarchy filtering)

    All methods support include/exclude modes and optional exclusion marking.

    Example:
        engine = FlextLdifFilterEngine()

        # Filter by DN pattern
        result = engine.filter_by_dn(
            entries,
            dn_pattern="*,ou=users,dc=example,dc=com",
            mode="include"
        )

        # Filter by objectClass with required attributes
        result = engine.filter_by_objectclass(
            entries,
            objectclass=("person", "inetOrgPerson"),
            required_attributes=["cn", "mail"],
            mode="include"
        )

        # Filter by attribute presence (match ANY)
        result = engine.filter_by_attributes(
            entries,
            attributes=["mail", "telephoneNumber"],
            match_all=False,  # Has ANY attribute
            mode="include"
        )

    """

    def execute(
        self, **_kwargs: object
    ) -> FlextResult[FlextLdifTypes.Models.ServiceResponseTypes]:
        """Execute method required by FlextService abstract base class.

        This service provides specific methods (filter_by_dn, etc.)
        rather than a generic execute operation.

        Args:
            **_kwargs: Ignored parameters for FlextService protocol compatibility

        Returns:
            FlextResult with not implemented error

        """
        return FlextResult.fail(
            "FlextLdifFilterEngine does not support generic execute(). Use specific methods instead."
        )

    def filter_by_dn(
        self,
        entries: list[FlextLdifModels.Entry],
        dn_pattern: str,
        mode: str = "include",
        *,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by DN pattern using wildcards.

        Uses fnmatch for pattern matching (*, ?, [seq]).
        Case-insensitive matching.

        Args:
            entries: List of entries to filter
            dn_pattern: DN pattern with wildcards (e.g., "*,ou=users,dc=*")
            mode: "include" (keep matches) or "exclude" (remove matches)
            mark_excluded: If True, add excluded entries with exclusion metadata

        Returns:
            FlextResult with filtered entry list

        """
        try:
            pattern = dn_pattern  # Type narrowing
            filtered = []
            for entry in entries:
                # Use DN utility to get string value (supports both DN model and str)
                entry_dn_str = FlextLdifUtilities.DN.get_dn_value(entry.dn)
                matches = fnmatch.fnmatch(entry_dn_str.lower(), pattern.lower())
                include = (mode == FlextLdifConstants.Modes.INCLUDE and matches) or (
                    mode == FlextLdifConstants.Modes.EXCLUDE and not matches
                )

                if include:
                    filtered.append(entry)
                elif mark_excluded:
                    # Mark as excluded with reason using ExclusionInfo pattern
                    exclusion_info = FlextLdifModels.ExclusionInfo(
                        excluded=True,
                        exclusion_reason=f"DN pattern: {dn_pattern}",
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

                    entry_copy = entry.model_copy(update={"metadata": new_metadata})
                    filtered.append(entry_copy)

            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
        except (ValueError, TypeError, AttributeError) as e:
            error_msg = f"DN filter failed: {e}"
            return FlextResult[list[FlextLdifModels.Entry]].fail(error_msg)

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

    def filter_by_objectclass(
        self,
        entries: list[FlextLdifModels.Entry],
        objectclass: str | tuple[str, ...],
        required_attributes: list[str] | None = None,
        mode: str = "include",
        *,
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by objectClass with optional required attributes.

        Args:
            entries: List of entries to filter
            objectclass: Single objectClass or tuple of objectClasses (OR logic)
            required_attributes: Optional list of required attributes (AND logic)
            mode: "include" (keep matches) or "exclude" (remove matches)
            mark_excluded: If True, add excluded entries with exclusion metadata

        Returns:
            FlextResult with filtered entry list

        """
        try:
            # Normalize objectclass to tuple
            oc_tuple = self._normalize_objectclass_tuple(objectclass)

            # Process all entries
            filtered_entries: list[FlextLdifModels.Entry] = []
            for entry in entries:
                matches = self._matches_objectclass_entry(
                    entry, oc_tuple, required_attributes
                )
                include = (mode == FlextLdifConstants.Modes.INCLUDE and matches) or (
                    mode == FlextLdifConstants.Modes.EXCLUDE and not matches
                )

                if include:
                    filtered_entries.append(entry)
                elif mark_excluded:
                    # Mark as excluded with reason using ExclusionInfo pattern
                    exclusion_info = FlextLdifModels.ExclusionInfo(
                        excluded=True,
                        exclusion_reason=f"ObjectClass filter: {oc_tuple}",
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

                    entry_copy = entry.model_copy(update={"metadata": new_metadata})
                    filtered_entries.append(entry_copy)

            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

        except (ValueError, TypeError, AttributeError) as e:
            error_msg = f"ObjectClass filter failed: {e}"
            return FlextResult[list[FlextLdifModels.Entry]].fail(error_msg)

    def filter_by_attributes(
        self,
        entries: list[FlextLdifModels.Entry],
        attributes: list[str],
        *,
        match_all: bool = True,
        mode: str = "include",
        mark_excluded: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by attribute presence.

        Args:
            entries: List of entries to filter
            attributes: List of attribute names to check
            match_all: If True, entry must have ALL attributes (AND logic)
                      If False, entry must have ANY attribute (OR logic)
            mode: "include" (keep matches) or "exclude" (remove matches)
            mark_excluded: If True, add excluded entries with exclusion metadata

        Returns:
            FlextResult with filtered entry list

        """
        try:
            filtered_entries: list[FlextLdifModels.Entry] = []
            for entry in entries:
                if match_all:
                    matches = FlextLdifUtilities.Entry.has_all_attributes(
                        entry, attributes
                    )
                else:
                    matches = FlextLdifUtilities.Entry.has_any_attributes(
                        entry, attributes
                    )

                include = (mode == FlextLdifConstants.Modes.INCLUDE and matches) or (
                    mode == FlextLdifConstants.Modes.EXCLUDE and not matches
                )

                if include:
                    filtered_entries.append(entry)
                elif mark_excluded:
                    # Mark as excluded with reason using ExclusionInfo pattern
                    match_type = "ALL" if match_all else "ANY"
                    exclusion_info = FlextLdifModels.ExclusionInfo(
                        excluded=True,
                        exclusion_reason=f"Attributes ({match_type}): {attributes}",
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

                    entry_copy = entry.model_copy(update={"metadata": new_metadata})
                    filtered_entries.append(entry_copy)

            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

        except (ValueError, TypeError, AttributeError) as e:
            error_msg = f"Attributes filter failed: {e}"
            return FlextResult[list[FlextLdifModels.Entry]].fail(error_msg)

    def filter_by_base_dn(
        self,
        entries: list[FlextLdifModels.Entry],
        base_dn: str,
    ) -> tuple[list[FlextLdifModels.Entry], list[FlextLdifModels.Entry]]:
        """Filter entries by base DN (hierarchy filtering).

        Returns tuple of (included, excluded) entries.

        Args:
            entries: List of entries to filter
            base_dn: Base DN to match (entries under this DN are included)

        Returns:
            Tuple of (included_entries, excluded_entries)

        """
        included: list[FlextLdifModels.Entry] = []
        excluded: list[FlextLdifModels.Entry] = []

        base_dn_lower = base_dn.lower()

        for entry in entries:
            entry_dn_str = FlextLdifUtilities.DN.get_dn_value(entry.dn)
            # Entry matches if it IS the base DN or is UNDER the base DN
            if entry_dn_str.lower().endswith(base_dn_lower):
                included.append(entry)
            else:
                excluded.append(entry)

        return included, excluded


__all__ = ["FlextLdifFilterEngine"]
