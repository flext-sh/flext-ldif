"""LDIF Entry Adaptation Service - Entry Transformation and Cleanup.

╔══════════════════════════════════════════════════════════════════════════╗
║  UNIVERSAL ENTRY TRANSFORMATION & CLEANUP ENGINE                         ║
╠══════════════════════════════════════════════════════════════════════════╣
║  ✅ DN string cleaning (RFC 4514 compliant)                             ║
║  ✅ Operational attribute removal (server-agnostic)                      ║
║  ✅ Attribute stripping (selective removal)                              ║
║  ✅ Entry adaptation for server compatibility                            ║
║  ✅ Entry portability (makes entries work across servers)               ║
║  ✅ Multiple API patterns (classmethod, builder, direct)                ║
║  ✅ 100% server-agnostic design                                         ║
║  ✅ FlextResult railway-oriented programming                            ║
╚══════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════
RESPONSIBILITY (SRP)

This service handles ENTRY TRANSFORMATION ONLY:
- Cleaning DN strings to RFC 4514 compliance
- Removing operational attributes for portability
- Removing unwanted attributes from entries
- Adapting entries for specific server targets

What it does NOT do:
- Filter entries (use FlextLdifFilters)
- Sort entries (use FlextLdifSorting)
- Validate schema (use FlextLdifValidation)

═══════════════════════════════════════════════════════════════════════════
REAL USAGE EXAMPLES

# PATTERN 1: Direct Classmethod API (Most Common)
────────────────────────────────────────────────
# Clean DN strings
cleaned_dn = FlextLdifUtilities.DN.clean_dn("cn = John , dc = example , dc = com")
# Result: "cn=John,dc=example,dc=com"

# Remove operational attributes from entry
result = FlextLdifEntry.remove_operational_attributes(entry)
adapted_entry = result.unwrap()

# Remove specific attributes
result = FlextLdifEntry.remove_attributes(
    entry=my_entry,
    attributes=["tempAttribute", "debugInfo"]
)
cleaned_entry = result.unwrap()

# Clean all DNs in multiple entries
result = FlextLdifEntry.clean_all_dns(entries)
cleaned_entries = result.unwrap()

# PATTERN 2: Execute Method (V1 FlextService Style)
────────────────────────────────────────────────────
result = FlextLdifEntry(
    entries=my_entries,
    operation="remove_operational_attributes"
).execute()

if result.is_success:
    adapted_entries = result.unwrap()

# PATTERN 3: Fluent Builder Pattern
───────────────────────────────────
adapted_entries = (
    FlextLdifEntry.builder()
    .with_entries(my_entries)
    .with_operation("remove_operational_attributes")
    .build()
)

# PATTERN 4: Transformation Pipeline
─────────────────────────────────────
result = (
    FlextLdifEntry.remove_operational_attributes(entries)
    .and_then(lambda e: FlextLdifEntry.remove_attributes(
        e,
        attributes=["tempAttr"]
    ))
)

═══════════════════════════════════════════════════════════════════════════
OPERATIONAL ATTRIBUTES

COMMON (removed by default):
- createTimestamp, modifyTimestamp
- createTimestamp, modifyTimestamp
- creatorsName, modifiersName
- entryCSN, entryUUID
- contextCSN

SPECIFIC (server-specific, not removed):
- creatorsName (might be needed for auditing)
- modifiersName (might be needed for auditing)

═══════════════════════════════════════════════════════════════════════════
QUICK REFERENCE

Most Common Use Cases:

# Clean a DN string
cleaned = FlextLdifEntry.clean_dn(messy_dn)

# Remove operational attributes (for portability)
result = FlextLdifEntry.remove_operational_attributes(entry)
portable_entry = result.unwrap()

# Remove specific attributes (cleanup)
result = FlextLdifEntry.remove_attributes(
    entry,
    attributes=["tempAttribute", "debugInfo"]
)

# Remove operational attributes from multiple entries
result = FlextLdifEntry.remove_operational_attributes_batch(entries)
portable_entries = result.unwrap()

# Copyright (c) 2025 FLEXT Team. All rights reserved.
# SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import FlextResult
from pydantic import Field

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.base import LdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifEntry(LdifServiceBase):
    """Universal entry transformation and cleanup service.

    Handles entry adaptation, DN cleaning, and attribute removal for
    making LDIF entries compatible across different LDAP servers.

    Responsibility (SRP):
    - Clean DN strings to RFC 4514 compliance
    - Remove operational attributes for portability
    - Remove unwanted attributes
    - Adapt entries for server compatibility

    Does NOT handle:
    - Filtering entries (use FlextLdifFilters)
    - Sorting entries (use FlextLdifSorting)
    - Validating schema (use FlextLdifValidation)
    """

    # ════════════════════════════════════════════════════════════════════════
    # PYDANTIC FIELDS
    # ════════════════════════════════════════════════════════════════════════

    entries: list[FlextLdifModels.Entry] = Field(default_factory=list)
    operation: str = "remove_operational_attributes"
    attributes_to_remove: list[str] = Field(default_factory=list)

    # ════════════════════════════════════════════════════════════════════════
    # EXECUTE PATTERN (V1 FlextService)
    # ════════════════════════════════════════════════════════════════════════

    @override
    def execute(self, **_kwargs: object) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute entry transformation operation.

        Args:
            **kwargs: Ignored parameters for FlextService protocol compatibility

        Supported operations:
        - "remove_operational_attributes": Strip COMMON operational attrs
        - "remove_attributes": Strip specific attributes

        Returns:
            FlextResult with transformed entries

        """
        try:
            if self.operation == "remove_operational_attributes":
                return self._remove_operational_attributes_batch()
            if self.operation == "remove_attributes":
                return self._remove_attributes_batch()
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Unknown operation: {self.operation}",
            )
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(str(e))

    # ════════════════════════════════════════════════════════════════════════
    # PUBLIC CLASSMETHOD API (Direct Entry Points)
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def remove_operational_attributes(
        cls,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove operational attributes from a single entry.

        Removes COMMON operational attributes (createTimestamp, modifyTimestamp, etc.)
        making the entry portable across different LDAP servers.

        Args:
            entry: Entry to adapt

        Returns:
            FlextResult with adapted entry (operational attrs removed)

        Example:
            result = FlextLdifEntry.remove_operational_attributes(entry)
            portable_entry = result.unwrap()

        """
        return cls().remove_operational_attributes_single(entry)

    @classmethod
    def remove_operational_attributes_batch(
        cls,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Remove operational attributes from multiple entries.

        Args:
            entries: Entries to adapt

        Returns:
            FlextResult with adapted entries

        Example:
            result = FlextLdifEntry.remove_operational_attributes_batch(entries)
            portable_entries = result.unwrap()

        """
        return cls(entries=entries, operation="remove_operational_attributes").execute()

    @classmethod
    def remove_attributes(
        cls,
        entry: FlextLdifModels.Entry,
        attributes: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove specific attributes from a single entry.

        Args:
            entry: Entry to clean
            attributes: List of attribute names to remove (case-insensitive)

        Returns:
            FlextResult with cleaned entry

        Example:
            result = FlextLdifEntry.remove_attributes(
                entry,
                attributes=["tempAttribute", "debugInfo"]
            )
            cleaned_entry = result.unwrap()

        """
        return cls().remove_attributes_single(entry, attributes)

    @classmethod
    def remove_attributes_batch(
        cls,
        entries: list[FlextLdifModels.Entry],
        attributes: list[str],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Remove specific attributes from multiple entries.

        Args:
            entries: Entries to clean
            attributes: List of attribute names to remove

        Returns:
            FlextResult with cleaned entries

        Example:
            result = FlextLdifEntry.remove_attributes_batch(
                entries,
                attributes=["tempAttribute", "debugInfo"]
            )
            cleaned_entries = result.unwrap()

        """
        return cls(
            entries=entries,
            operation="remove_attributes",
            attributes_to_remove=attributes,
        ).execute()

    @classmethod
    def filter_entry_attributes(
        cls,
        entry: FlextLdifModels.Entry,
        attributes_to_remove: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove specified attributes from entry (alias for remove_attributes).

        This method provides a filtering interface for attribute removal,
        consolidating all attribute removal logic in the entry service
        rather than in the filters service (SRP principle).

        Args:
            entry: Entry to filter
            attributes_to_remove: List of attribute names to remove (case-insensitive)

        Returns:
            FlextResult with filtered entry

        """
        return cls.remove_attributes(entry, attributes_to_remove)

    # ════════════════════════════════════════════════════════════════════════
    # FLUENT BUILDER PATTERN
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def builder(cls) -> FlextLdifEntry:
        """Create fluent builder for complex entry transformations.

        Returns:
            Service instance for method chaining

        Example:
            result = (FlextLdifEntry.builder()
                .with_entries(entries)
                .with_operation("remove_operational_attributes")
                .build())

        """
        return cls(entries=[])

    def with_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextLdifEntry:
        """Set entries to transform (fluent builder)."""
        self.entries = entries
        return self

    def with_operation(self, operation: str) -> FlextLdifEntry:
        """Set transformation operation (fluent builder)."""
        self.operation = operation
        return self

    def with_attributes_to_remove(self, attributes: list[str]) -> FlextLdifEntry:
        """Set attributes to remove (fluent builder)."""
        self.attributes_to_remove = attributes
        return self

    def build(self) -> list[FlextLdifModels.Entry]:
        """Execute and return unwrapped result (fluent terminal)."""
        return self.execute().unwrap()

    # ════════════════════════════════════════════════════════════════════════
    # PRIVATE IMPLEMENTATION (DRY Core)
    # ════════════════════════════════════════════════════════════════════════

    def _remove_operational_attributes_batch(
        self,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Remove operational attributes from all entries."""
        adapted_entries: list[FlextLdifModels.Entry] = []

        for entry in self.entries:
            result = self.remove_operational_attributes_single(entry)
            if result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    result.error or "Unknown error",
                )
            adapted_entries.append(result.unwrap())

        return FlextResult[list[FlextLdifModels.Entry]].ok(adapted_entries)

    def remove_operational_attributes_single(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove operational attributes from single entry."""
        if entry.attributes is None:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Entry {FlextLdifUtilities.DN.get_dn_value(entry.dn)} has no attributes",
            )

        operational_attrs = set(FlextLdifConstants.OperationalAttributes.COMMON)
        operational_attrs_lower = {attr.lower() for attr in operational_attrs}

        adapted_attrs: dict[str, list[str]] = {}

        for attr_name, attr_values in entry.attributes.attributes.items():
            # Skip operational attributes (case-insensitive check)
            if attr_name.lower() in operational_attrs_lower:
                if self.logger is not None:
                    self.logger.debug(
                        "Removed operational attribute",
                        attribute_name=attr_name,
                        entry_dn=FlextLdifUtilities.DN.get_dn_value(entry.dn),
                    )
                continue

            # Keep attribute as-is
            adapted_attrs[attr_name] = attr_values.copy()

        # Create adapted entry
        ldif_attributes = FlextLdifModels.LdifAttributes(attributes=adapted_attrs)

        # Check DN is not None before creating entry
        if not entry.dn:
            return FlextResult[FlextLdifModels.Entry].fail("Entry has no DN")

        create_result = FlextLdifModels.Entry.create(
            dn=entry.dn,
            attributes=ldif_attributes,
        )
        if create_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                create_result.error or "Unknown error",
            )
        # Entry.create() already returns FlextLdifModels.Entry
        # Convert domain Entry to public Entry if needed
        internal_entry = create_result.unwrap()
        if isinstance(internal_entry, FlextLdifModelsDomains.Entry) and not isinstance(
            internal_entry, FlextLdifModels.Entry
        ):
            entry_public = FlextLdifModels.Entry.model_validate(
                internal_entry.model_dump()
            )
        else:
            entry_public = internal_entry
        adapted_entry_result = FlextResult[FlextLdifModels.Entry].ok(entry_public)

        if adapted_entry_result.is_failure:
            error_msg = f"Failed to adapt entry {FlextLdifUtilities.DN.get_dn_value(entry.dn)}: {adapted_entry_result.error}"
            if self.logger is not None:
                self.logger.error(
                    "Failed to create adapted entry",
                    entry_dn=FlextLdifUtilities.DN.get_dn_value(entry.dn),
                    error=str(adapted_entry_result.error),
                )
            return FlextResult[FlextLdifModels.Entry].fail(error_msg or "Unknown error")

        return adapted_entry_result

    def _remove_attributes_batch(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Remove specific attributes from all entries."""
        adapted_entries: list[FlextLdifModels.Entry] = []

        for entry in self.entries:
            result = self.remove_attributes_single(entry, self.attributes_to_remove)
            if result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    result.error or "Unknown error",
                )
            adapted_entries.append(result.unwrap())

        return FlextResult[list[FlextLdifModels.Entry]].ok(adapted_entries)

    def remove_attributes_single(
        self,
        entry: FlextLdifModels.Entry,
        attributes: list[str],
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Remove specific attributes from single entry.

        Uses FlextLdifUtilities.Entry.remove_attributes() for core logic.
        """
        # Check if entry has attributes
        if not entry.attributes:
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        # Log attributes being removed
        if self.logger is not None:
            attrs_to_remove_lower = {attr.lower() for attr in attributes}
            for attr_name in entry.attributes.attributes:
                if attr_name.lower() in attrs_to_remove_lower:
                    self.logger.debug(
                        "Removed attribute",
                        attribute_name=attr_name,
                        entry_dn=FlextLdifUtilities.DN.get_dn_value(entry.dn),
                    )

        # Use utility for core removal logic
        try:
            cleaned_entry = FlextLdifUtilities.Entry.remove_attributes(
                entry,
                attributes,
            )
            return FlextResult[FlextLdifModels.Entry].ok(cleaned_entry)
        except Exception as e:
            error_msg = f"Failed to clean entry {FlextLdifUtilities.DN.get_dn_value(entry.dn)}: {e}"
            if self.logger is not None:
                self.logger.exception(
                    "Failed to remove attributes",
                    entry_dn=FlextLdifUtilities.DN.get_dn_value(entry.dn),
                    error=str(e),
                )
            return FlextResult[FlextLdifModels.Entry].fail(error_msg or "Unknown error")

    @classmethod
    def apply_marked_removals(
        cls,
        entry: FlextLdifModels.Entry,
    ) -> FlextLdifModels.Entry:
        """Remove attributes that were marked for removal by filters.

        SRP: Entry service performs actual removal based on metadata markers.

        Reads: entry.metadata.extensions["marked_attributes"]
        Removes: Attributes with status == "marked_for_removal" or "filtered"
        Preserves: Removal info in metadata for writer to show as comments

        Args:
            entry: Entry to process

        Returns:
            Entry with marked attributes removed

        Example:
            # Filter marks attributes
            marked_entry = filter_service.mark_attributes(entry, attrs_to_remove)

            # Entry service removes marked attributes
            cleaned_entry = FlextLdifEntry.apply_marked_removals(marked_entry)

        """
        # Check if entry has metadata and marked attributes
        if not entry.metadata:
            return entry

        # Get marked_attributes from metadata extensions (narrowed type)
        marked_attrs_raw = entry.metadata.extensions.get("marked_attributes", {})
        if not isinstance(marked_attrs_raw, dict):
            return entry

        marked_attrs: dict[str, dict[str, object]] = marked_attrs_raw
        if not marked_attrs:
            return entry

        # Collect attributes to remove - extracted to reduce complexity
        attrs_to_remove = cls._collect_attributes_to_remove(marked_attrs)
        if not attrs_to_remove or not entry.attributes:
            return entry

        # Remove marked attributes and update metadata
        return cls._create_cleaned_entry(entry, attrs_to_remove, marked_attrs)

    @staticmethod
    def _collect_attributes_to_remove(
        marked_attrs: dict[str, dict[str, object]],
    ) -> list[str]:
        """Collect attribute names marked for removal (extracted to reduce complexity)."""
        attrs_to_remove: list[str] = []
        removal_statuses = {
            FlextLdifConstants.AttributeMarkerStatus.MARKED_FOR_REMOVAL,
            FlextLdifConstants.AttributeMarkerStatus.FILTERED,
        }

        for attr_name, attr_info in marked_attrs.items():
            status = attr_info.get("status")
            if status in removal_statuses:
                attrs_to_remove.append(attr_name)

        return attrs_to_remove

    @staticmethod
    def _create_cleaned_entry(
        entry: FlextLdifModels.Entry,
        attrs_to_remove: list[str],
        marked_attrs: dict[str, dict[str, object]],
    ) -> FlextLdifModels.Entry:
        """Create entry with removed attributes (extracted to reduce complexity)."""
        # Remove marked attributes from entry.attributes
        cleaned_attrs: dict[str, list[str]] = {}
        if entry.attributes:
            for attr_name, attr_values in entry.attributes.attributes.items():
                if attr_name not in attrs_to_remove:
                    cleaned_attrs[attr_name] = attr_values.copy()

        # Create new attributes object
        new_attributes = FlextLdifModels.LdifAttributes(attributes=cleaned_attrs)

        # Store removed attributes in metadata for writer to show as comments
        removed_attributes: dict[str, object] = {}
        for attr_name in attrs_to_remove:
            if attr_name in marked_attrs:
                removed_attributes[attr_name] = marked_attrs[attr_name]

        # Update metadata extensions with removed_attributes
        if not entry.metadata:
            return entry

        new_extensions = entry.metadata.extensions.copy()
        new_extensions["removed_attributes"] = removed_attributes

        # Create new metadata with updated extensions
        new_metadata = FlextLdifModels.QuirkMetadata(
            quirk_type=entry.metadata.quirk_type,
            extensions=new_extensions,
            rfc_violations=entry.metadata.rfc_violations,
            rfc_warnings=entry.metadata.rfc_warnings,
        )

        # Return entry with cleaned attributes and updated metadata
        result = FlextLdifModels.Entry.create(
            dn=entry.dn,
            attributes=new_attributes,
            metadata=new_metadata,
        )

        # Type narrowing: create returns Entry, unwrap() returns Entry when is_success
        if result.is_success:
            entry_unwrapped = result.unwrap()
            if not isinstance(entry_unwrapped, FlextLdifModels.Entry):
                msg = f"Expected Entry, got {type(entry_unwrapped)}"
                raise TypeError(msg)
            return entry_unwrapped
        return entry


__all__ = ["FlextLdifEntry"]
