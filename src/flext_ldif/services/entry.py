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

from typing import cast, override

from flext_core import FlextResult, FlextService
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifEntry(FlextService[list[FlextLdifModels.Entry]]):
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
    def execute(self, **kwargs: object) -> FlextResult[list[FlextLdifModels.Entry]]:
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
                return cast("FlextResult[list[FlextLdifModels.Entry]]", result)
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

        adapted_entry_result: FlextResult[FlextLdifModels.Entry] = (
            FlextLdifModels.Entry.create(
                dn=entry.dn,
                attributes=ldif_attributes,
            ).map(lambda e: cast("FlextLdifModels.Entry", e))
        )

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
                return cast("FlextResult[list[FlextLdifModels.Entry]]", result)
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


__all__ = ["FlextLdifEntry"]
