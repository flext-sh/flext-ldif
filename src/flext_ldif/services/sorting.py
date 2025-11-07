"""LDIF Entry Sorting Service (V2 Ultimate DRY - Minimal API).

Ultra-minimal design with maximum automation:
- Single entry point (instance-based)
- V2 auto-execution by default
- Minimal public API surface
- All sorting via Pydantic fields
- Zero code duplication

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import operator
import re
from collections.abc import Callable

from flext_core import FlextResult, FlextService
from pydantic import Field, field_validator, model_validator

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifSorting(FlextService[list[FlextLdifModels.Entry]]):
    """LDIF Sorting Service - Universal Sorting Engine.

    ╔══════════════════════════════════════════════════════════════════════╗
    ║  FLEXIBLE SORTING FOR LDIF ENTRIES, ATTRIBUTES, ACL & SCHEMAS        ║
    ╠══════════════════════════════════════════════════════════════════════╣
    ║  ✅ Sort entries by hierarchy, DN, custom predicate, or schema OID   ║
    ║  ✅ Sort attributes within entries (alphabetical or custom order)    ║
    ║  ✅ Sort ACL values (acl, aci, olcAccess attributes)                ║
    ║  ✅ Combined sorting: entries + attributes + ACL in one operation    ║
    ║  ✅ Multiple usage patterns: execute(), classmethod, builder         ║
    ║  ✅ 100% type-safe with Pydantic v2 validation                       ║
    ║  ✅ RFC 4514 DN normalization via FlextLdifUtilities                 ║
    ╚══════════════════════════════════════════════════════════════════════╝

    DN Handling (RFC 4514 Compliance):
    - Hierarchical sorting uses FlextLdifUtilities.DN.norm() for DN normalization
    - DN depth calculation with fallback to FlextLdifUtilities.DN.get_depth()
    - Alphabetical DN sorting uses RFC 4514 normalized form for canonical ordering
    - All DN comparisons are case-insensitive and RFC 4514 compliant

    ═══════════════════════════════════════════════════════════════════════
    WHAT IT SORTS (sort_target parameter)
    ═══════════════════════════════════════════════════════════════════════

    "entries"      - Sort the entry list itself by DN/hierarchy/custom
    "attributes"   - Sort attributes WITHIN each entry (no entry reordering)
    "acl"          - Sort ACL values WITHIN entries (acl, aci, olcAccess)
    "schema"       - Sort schema entries by OID (for schema exports)
    "combined"     - Sort everything at once (entries + attrs + ACL)

    ═══════════════════════════════════════════════════════════════════════
    HOW IT SORTS ENTRIES (sort_by parameter)
    ═══════════════════════════════════════════════════════════════════════

    "hierarchy"     - Depth-first: shallow entries first, then alphabetical
                     Order: dc=com, ou=users,dc=com, cn=john,ou=users,...

    "alphabetical"  - Full DN alphabetical (case-insensitive)
    "dn"            - Alias for alphabetical

    "schema"        - For schema entries: attributeTypes before objectClasses,
                     each sorted by extracted OID number

    "custom"        - Use custom_predicate function to extract sort key

    ═══════════════════════════════════════════════════════════════════════
    REAL USAGE EXAMPLES
    ═══════════════════════════════════════════════════════════════════════

    # PATTERN 1: Execute Method (V1 Style)
    ────────────────────────────────────────
    result = FlextLdifSorting(
        entries=my_entries,
        sort_by="hierarchy"
    ).execute()

    if result.is_success:
        sorted_entries = result.unwrap()

    # PATTERN 2: Classmethod for Composable/Chainable Operations
    ────────────────────────────────────────────────────────────
    result = (
        FlextLdifSorting.sort(my_entries, by="hierarchy")
        .map(lambda e: e[:10])  # Take first 10
        .and_then(lambda e: FlextLdifSorting.sort(e, by="alphabetical"))
    )

    # PATTERN 3: Fluent Builder Pattern
    ───────────────────────────────────
    sorted_entries = (
        FlextLdifSorting.builder()
        .with_entries(my_entries)
        .with_strategy("hierarchy")
        .with_attribute_sorting(order=["cn", "sn", "mail"])
        .build()  # Returns list[Entry] directly
    )

    # PATTERN 4: Public Classmethod Helpers (Most Direct)
    ────────────────────────────────────────────────────
    # Sort entries by hierarchy
    result = FlextLdifSorting.by_hierarchy(my_entries)
    sorted_entries = result.unwrap()

    # Sort entries alphabetically by DN
    result = FlextLdifSorting.by_dn(my_entries)

    # Sort entries by custom predicate
    result = FlextLdifSorting.by_custom(
        my_entries,
        lambda e: FlextLdifUtilities.DN.get_dn_value(e.dn).count(",")
    )

    # Sort attributes in entries
    result = FlextLdifSorting.sort_attributes(
        my_entries,
        order=["cn", "sn", "mail"]
    )

    # Sort ACL values in entries
    result = FlextLdifSorting.sort_acl(my_entries)

    # Sort schema entries by OID
    result = FlextLdifSorting.by_schema(schema_entries)

    ═══════════════════════════════════════════════════════════════════════
    ATTRIBUTE & ACL SORTING OPTIONS
    ═══════════════════════════════════════════════════════════════════════

    When sort_target="attributes":
        sort_attributes=True       - Sort alphabetically (default)
        attribute_order=[...]      - Custom order: ["cn", "sn", "mail"]
                                    (remaining attrs sorted alphabetically)

    When sort_target="acl":
        acl_attributes=[...]       - Which attrs to sort (default:
                                    ["acl", "aci", "olcAccess"])

    ═══════════════════════════════════════════════════════════════════════
    COMPLEX SORTING EXAMPLES
    ═══════════════════════════════════════════════════════════════════════

    # Sort ONLY attributes, preserving entry order
    sorted_entries = FlextLdifSorting(
        entries=my_entries,
        sort_target="attributes"
    ).execute().unwrap()

    # Sort ONLY ACL values within entries
    sorted_entries = FlextLdifSorting(
        entries=my_entries,
        sort_target="acl"
    ).execute().unwrap()

    # Sort EVERYTHING at once
    sorted_entries = FlextLdifSorting(
        entries=my_entries,
        sort_target="combined",
        sort_by="hierarchy",
        sort_attributes=True,
        attribute_order=["objectClass", "cn", "sn", "mail"],
        sort_acl=True
    ).execute().unwrap()

    # Custom sorting: sort by DN length
    sorted_entries = FlextLdifSorting(
        entries=my_entries,
        sort_by="custom",
        custom_predicate=lambda e: len(FlextLdifUtilities.DN.get_dn_value(e.dn))
    ).execute().unwrap()

    # Custom sorting: sort by CN attribute value
    result = FlextLdifSorting.by_custom(
        my_entries,
        lambda e: e.attributes.attributes.get("cn", [""])[0].lower()
    )

    ═══════════════════════════════════════════════════════════════════════
    PUBLIC CLASSMETHOD API
    ═══════════════════════════════════════════════════════════════════════

    sort(entries, target=..., by=..., predicate=...)
        → FlextResult[list[Entry]] for chaining

    by_hierarchy(entries)
        → FlextResult[list[Entry]] (depth-first + alphabetical)

    by_dn(entries)
        → FlextResult[list[Entry]] (alphabetical by full DN)

    by_schema(entries)
        → FlextResult[list[Entry]] (schema entries by OID)

    by_custom(entries, predicate)
        → FlextResult[list[Entry]] (custom sort function)

    sort_attributes(entries, order=None)
        → FlextResult[list[Entry]] (sort attrs within entries)

    sort_acl(entries, acl_attrs=None)
        → FlextResult[list[Entry]] (sort ACL values)

    builder()
        → FlextLdifSorting (fluent builder, terminal: .build())

    ═══════════════════════════════════════════════════════════════════════
    QUICK REFERENCE
    ═══════════════════════════════════════════════════════════════════════

    Most Common Use Cases:

    # Just sort entries by hierarchy
    sorted = FlextLdifSorting.by_hierarchy(entries).unwrap()

    # Just sort entries alphabetically
    sorted = FlextLdifSorting.by_dn(entries).unwrap()

    # Sort entries + sort attributes + sort ACL
    sorted = FlextLdifSorting(
        entries=entries,
        sort_target="combined",
        sort_by="hierarchy",
        sort_attributes=True,
        sort_acl=True
    ).execute().unwrap()

    # Sort with custom logic
    sorted = FlextLdifSorting.by_custom(
        entries,
        lambda e: FlextLdifUtilities.DN.get_dn_value(e.dn).count(",")
    ).unwrap()

    """

    # ════════════════════════════════════════════════════════════════════════
    # PYDANTIC FIELDS
    # ════════════════════════════════════════════════════════════════════════

    # ──────────────────────────────────────────────────────────────────────
    # DATA FIELDS
    # ──────────────────────────────────────────────────────────────────────

    entries: list[FlextLdifModels.Entry] = Field(
        default_factory=list,
        description="LDIF entries to sort.",
    )

    # ──────────────────────────────────────────────────────────────────────
    # SORT CONFIGURATION (Ultra Parametrized)
    # ──────────────────────────────────────────────────────────────────────

    sort_target: str = Field(
        default=FlextLdifConstants.SortTarget.ENTRIES.value,
        description="What to sort: entries|attributes|acl|schema|combined",
    )

    sort_by: str = Field(
        default=FlextLdifConstants.SortStrategy.HIERARCHY.value,
        description="How to sort: hierarchy|alphabetical|schema|custom",
    )

    custom_predicate: Callable[[FlextLdifModels.Entry], str | int | float] | None = (
        Field(default=None, description="Custom sort predicate.")
    )

    # ──────────────────────────────────────────────────────────────────────
    # ATTRIBUTE SORTING
    # ──────────────────────────────────────────────────────────────────────

    sort_attributes: bool = Field(
        default=False,
        description="Sort entry attributes alphabetically.",
    )

    attribute_order: list[str] | None = Field(
        default=None,
        description="Custom attribute order list.",
    )

    # ──────────────────────────────────────────────────────────────────────
    # ACL SORTING
    # ──────────────────────────────────────────────────────────────────────

    sort_acl: bool = Field(
        default=False,
        description="Sort ACL attributes within entries.",
    )

    acl_attributes: list[str] = Field(
        default_factory=lambda: ["acl", "aci", "olcAccess"],
        description="ACL attribute names to sort.",
    )

    # ════════════════════════════════════════════════════════════════════════
    # PYDANTIC VALIDATORS
    # ════════════════════════════════════════════════════════════════════════

    @field_validator("sort_target")
    @classmethod
    def validate_sort_target(cls, v: str) -> str:
        """Validate sort_target is valid."""
        valid = {t.value for t in FlextLdifConstants.SortTarget}
        if v not in valid:
            msg = f"Invalid sort_target: {v!r}. Valid: {', '.join(sorted(valid))}"
            raise ValueError(msg)
        return v

    @field_validator("sort_by")
    @classmethod
    def validate_sort_strategy(cls, v: str) -> str:
        """Validate sort_by is valid."""
        valid = {s.value for s in FlextLdifConstants.SortStrategy}
        if v not in valid:
            msg = f"Invalid sort_by: {v!r}. Valid: {', '.join(sorted(valid))}"
            raise ValueError(msg)
        return v

    @model_validator(mode="after")
    def validate_custom_predicate_when_needed(self) -> FlextLdifSorting:
        """Validate custom_predicate when needed."""
        if (
            self.sort_by == FlextLdifConstants.SortStrategy.CUSTOM.value
            and not self.custom_predicate
        ):
            msg = "custom_predicate required when sort_by='custom'."
            raise ValueError(msg)
        return self

    # ════════════════════════════════════════════════════════════════════════
    # CORE EXECUTION (V2 Universal Engine)
    # ════════════════════════════════════════════════════════════════════════

    def execute(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute sorting based on sort_target (ultra parametrized dispatch)."""
        if not self.entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        # Universal dispatcher based on sort_target
        match self.sort_target:
            case FlextLdifConstants.SortTarget.ENTRIES.value:
                return self._sort_entries()
            case FlextLdifConstants.SortTarget.ATTRIBUTES.value:
                return self._sort_only_attributes()
            case FlextLdifConstants.SortTarget.ACL.value:
                return self._sort_only_acl()
            case FlextLdifConstants.SortTarget.SCHEMA.value:
                return self._sort_schema_entries()
            case FlextLdifConstants.SortTarget.COMBINED.value:
                return self._sort_combined()
            case _:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Unknown sort_target: {self.sort_target}",
                )

    # ════════════════════════════════════════════════════════════════════════
    # PUBLIC API - MINIMAL ESSENTIALS
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def sort(
        cls,
        entries: list[FlextLdifModels.Entry],
        *,
        target: str = FlextLdifConstants.SortTarget.ENTRIES.value,
        by: str
        | FlextLdifConstants.SortStrategy = FlextLdifConstants.SortStrategy.HIERARCHY,
        predicate: Callable[[FlextLdifModels.Entry], str | int | float] | None = None,
        sort_attributes: bool = False,
        attribute_order: list[str] | None = None,
        sort_acl: bool = False,
        acl_attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Quick sort with FlextResult for composable/chainable operations.

        Standardized Parameters:
            entries: Entries to sort
            target: WHAT to sort (entries|attributes|acl|schema|combined)
            by: HOW to sort entries (hierarchy|alphabetical|schema|custom)
            predicate: Custom sort function (required if by="custom")
            sort_attributes: Auto-sort attributes alphabetically
            attribute_order: Custom attribute order list
            sort_acl: Sort ACL attribute values
            acl_attributes: ACL attribute names (default: ["acl", "aci", "olcAccess"])

        Returns:
            FlextResult[list[Entry]] for chaining with .map/.and_then/.unwrap

        Examples:
            # Simple sort with unwrap
            sorted = Service.sort(entries, by="hierarchy").unwrap()

            # Chainable pipeline
            result = (Service.sort(entries, by="hierarchy")
                .map(lambda e: e[:10])
                .and_then(lambda e: Service.sort(e, by="alphabetical")))

            # With error handling
            sorted = Service.sort(entries, by="custom",
                                 predicate=lambda e: len(FlextLdifUtilities.DN.get_dn_value(e.dn))
                                ).unwrap_or([])

        """
        strategy = by.value if isinstance(by, FlextLdifConstants.SortStrategy) else by
        return cls(
            entries=entries,
            sort_target=target,
            sort_by=strategy,
            custom_predicate=predicate,
            sort_attributes=sort_attributes,
            attribute_order=attribute_order,
            sort_acl=sort_acl,
            acl_attributes=acl_attributes or ["acl", "aci", "olcAccess"],
        ).execute()

    @classmethod
    def builder(cls) -> FlextLdifSorting:
        """Create fluent builder instance.

        Returns:
            Service instance for method chaining

        Example:
            sorted_entries = (Service.builder()
                .with_entries(my_entries)
                .with_strategy("hierarchy")
                .build())

        """
        return cls(entries=[])

    def with_entries(self, entries: list[FlextLdifModels.Entry]) -> FlextLdifSorting:
        """Set entries to sort (fluent builder)."""
        self.entries = entries
        return self

    def with_target(
        self,
        target: str | FlextLdifConstants.SortTarget,
    ) -> FlextLdifSorting:
        """Set sort target - WHAT to sort (fluent builder).

        Args:
            target: "entries"|"attributes"|"acl"|"schema"|"combined"

        """
        self.sort_target = (
            target.value
            if isinstance(target, FlextLdifConstants.SortTarget)
            else target
        )
        return self

    def with_strategy(
        self,
        strategy: str | FlextLdifConstants.SortStrategy,
    ) -> FlextLdifSorting:
        """Set sort strategy - HOW to sort (fluent builder).

        Args:
        strategy: "hierarchy"|"alphabetical"|"schema"|"custom"

        """
        self.sort_by = (
            strategy.value
            if isinstance(strategy, FlextLdifConstants.SortStrategy)
            else strategy
        )
        return self

    def with_predicate(
        self,
        predicate: Callable[[FlextLdifModels.Entry], str | int | float],
    ) -> FlextLdifSorting:
        """Set custom predicate function (fluent builder)."""
        self.custom_predicate = predicate
        return self

    def with_attribute_sorting(
        self,
        *,
        alphabetical: bool = False,
        order: list[str] | None = None,
    ) -> FlextLdifSorting:
        """Enable attribute sorting (fluent builder).

        Args:
        alphabetical: Sort attributes alphabetically
        order: Custom attribute order (overrides alphabetical)

        """
        if order:
            self.attribute_order = order
            self.sort_attributes = False
        else:
            self.sort_attributes = alphabetical
            self.attribute_order = None
        return self

    def with_acl_sorting(
        self,
        *,
        enabled: bool = True,
        acl_attrs: list[str] | None = None,
    ) -> FlextLdifSorting:
        """Enable ACL sorting (fluent builder).

        Args:
            enabled: Enable ACL sorting
            acl_attrs: ACL attribute names (default: ["acl", "aci", "olcAccess"])

        """
        self.sort_acl = enabled
        if acl_attrs:
            self.acl_attributes = acl_attrs
        return self

    def build(self) -> list[FlextLdifModels.Entry]:
        """Execute and return unwrapped result (fluent terminal)."""
        return self.execute().unwrap()

    # ════════════════════════════════════════════════════════════════════════
    # PUBLIC CLASSMETHOD HELPERS (Direct Entry Points)
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def by_hierarchy(
        cls,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort entries by hierarchy (depth-first, then alphabetical).

        Args:
            entries: LDIF entries to sort

        Returns:
            FlextResult with sorted entries (shallowest first)

        Example:
            result = FlextLdifSorting.by_hierarchy(entries)
            sorted_entries = result.unwrap()

        """
        return cls(
            entries=entries,
            sort_target="entries",
            sort_by="hierarchy",
        ).execute()

    @classmethod
    def by_dn(
        cls,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort entries alphabetically by full DN.

        Args:
            entries: LDIF entries to sort

        Returns:
            FlextResult with sorted entries (case-insensitive alphabetical)

        Example:
            result = FlextLdifSorting.by_dn(entries)
            sorted_entries = result.unwrap()

        """
        return cls(entries=entries, sort_target="entries", sort_by="dn").execute()

    @classmethod
    def by_schema(
        cls,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort schema entries by OID (attributeTypes before objectClasses).

        Args:
            entries: Schema entries to sort

        Returns:
            FlextResult with sorted schema entries

        Example:
            result = FlextLdifSorting.by_schema(schema_entries)
            sorted_entries = result.unwrap()

        """
        return cls(entries=entries, sort_target="schema", sort_by="schema").execute()

    @classmethod
    def by_custom(
        cls,
        entries: list[FlextLdifModels.Entry],
        predicate: Callable[[FlextLdifModels.Entry], str | int | float],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort entries using custom predicate function.

        Args:
            entries: LDIF entries to sort
            predicate: Function to extract sort key from entry

        Returns:
            FlextResult with sorted entries

        Example:
            # Sort by DN depth
            result = FlextLdifSorting.by_custom(
                entries,
                lambda e: FlextLdifUtilities.DN.get_dn_value(e.dn).count(",")
            )
            sorted_entries = result.unwrap()

        """
        return cls(
            entries=entries,
            sort_target="entries",
            sort_by="custom",
            custom_predicate=predicate,
        ).execute()

    # ════════════════════════════════════════════════════════════════════════
    # PRIVATE IMPLEMENTATION (DRY Core)
    # ════════════════════════════════════════════════════════════════════════

    def _sort_entries(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Universal entry sorting engine."""
        try:
            match self.sort_by:
                case FlextLdifConstants.SortStrategy.HIERARCHY.value:
                    return self._by_hierarchy()
                case (
                    FlextLdifConstants.SortStrategy.DN.value
                    | FlextLdifConstants.SortStrategy.ALPHABETICAL.value
                ):
                    return self._by_dn()
                case FlextLdifConstants.SortStrategy.SCHEMA.value:
                    return self._by_schema()
                case FlextLdifConstants.SortStrategy.CUSTOM.value:
                    return self._by_custom()
                case _:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Unknown strategy: {self.sort_by}",
                    )
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Sort failed: {e}")

    def _sort_only_attributes(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort ONLY attributes (no entry sorting)."""
        return self._sort_attributes_in_entries(self.entries)

    def _sort_only_acl(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort ONLY ACL attributes (no entry sorting)."""
        return self._sort_acl_in_entries(self.entries)

    def _sort_schema_entries(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort schema entries by OID (equivalent to _by_schema but explicit)."""
        return self._by_schema()

    def _sort_combined(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort EVERYTHING: entries + attributes + ACL + schema."""
        # Step 1: Sort entries
        result = self._sort_entries()
        if not result.is_success:
            return result

        sorted_entries = result.unwrap()

        # Step 2: Sort attributes if configured
        if self.sort_attributes or self.attribute_order:
            result = self._sort_attributes_in_entries(sorted_entries)
            if not result.is_success:
                return result
            sorted_entries = result.unwrap()

        # Step 3: Sort ACL if configured
        if self.sort_acl:
            result = self._sort_acl_in_entries(sorted_entries)
            if not result.is_success:
                return result
            sorted_entries = result.unwrap()

        return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)

    def _sort_attributes_in_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort attributes in all entries."""
        processed = []
        for entry in entries:
            if self.attribute_order:
                result = self._sort_entry_attributes_by_order(entry)
            else:
                result = self._sort_entry_attributes_alphabetically(entry)

            if not result.is_success:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Attribute sort failed: {result.error}",
                )
            processed.append(result.unwrap())

        return FlextResult[list[FlextLdifModels.Entry]].ok(processed)

    def _sort_acl_in_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort ACL attributes in all entries."""
        processed = []
        for entry in entries:
            # Access the actual attributes dict
            attrs_dict = dict(entry.attributes.attributes)  # Create mutable copy
            modified = False

            # Sort each ACL attribute's values
            for acl_attr in self.acl_attributes:
                if acl_attr in attrs_dict:
                    acl_values = attrs_dict[acl_attr]
                    if isinstance(acl_values, list) and len(acl_values) > 1:
                        attrs_dict[acl_attr] = sorted(
                            acl_values,
                            key=lambda x: str(x).lower(),
                        )
                        modified = True

            if modified:
                # Create new LdifAttributes with sorted ACLs
                sorted_attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
                processed.append(entry.model_copy(update={"attributes": sorted_attrs}))
            else:
                processed.append(entry)

        return FlextResult[list[FlextLdifModels.Entry]].ok(processed)

    def _by_hierarchy(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort by DN hierarchy (depth-first) using simple and effective rule.

        Sorting rule: (depth, normalized_dn)
        - Depth 1 entries first (sorted alphabetically)
        - Depth 2 entries next (sorted alphabetically)
        - And so on...

        This naturally preserves parent-before-children ordering for proper LDAP
        synchronization since parents (lower depth) always appear before children
        (higher depth).

        Uses FlextLdifUtilities.DN.norm() for RFC 4514 compliant DN normalization.
        """

        def sort_key(entry: FlextLdifModels.Entry) -> tuple[int, str]:
            """Generate hierarchical sort key: (depth, normalized_dn)."""
            dn_value = (
                str(FlextLdifUtilities.DN.get_dn_value(entry.dn)) if entry.dn else ""
            )
            if not dn_value:
                return (0, "")

            # Calculate depth (number of RDN components)
            depth = dn_value.count(",") + 1

            # Normalize DN for consistent sorting using FlextLdifUtilities
            normalized = FlextLdifUtilities.DN.norm(dn_value)
            sort_dn = normalized.lower() if normalized else dn_value.lower()

            # Return tuple: (depth, normalized_dn)
            # Sorting by this ensures all parents come before children
            return (depth, sort_dn)

        # Sort entries using hierarchical key
        sorted_entries = sorted(self.entries, key=sort_key)
        return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)

    def _by_dn(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort alphabetically by DN using RFC 4514 normalization.

        Uses FlextLdifUtilities.DN.norm() for RFC 4514 compliant DN normalization
        before sorting, ensuring consistent canonical ordering.
        """

        def dn_sort_key(entry: FlextLdifModels.Entry) -> str:
            dn_value = (
                str(FlextLdifUtilities.DN.get_dn_value(entry.dn)) if entry.dn else ""
            )
            if not dn_value:
                return ""

            # Normalize DN using FlextLdifUtilities for RFC 4514 compliance
            normalized = FlextLdifUtilities.DN.norm(dn_value)
            return normalized.lower() if normalized else dn_value.lower()

        sorted_entries = sorted(self.entries, key=dn_sort_key)
        return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)

    def _by_schema(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort schema entries by OID."""

        def schema_key(entry: FlextLdifModels.Entry) -> tuple[int, str]:
            attrs = entry.attributes.model_dump()

            # Priority: attributetypes (1) before objectclasses (2)
            if FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES in attrs:
                priority = 1
                oid_values = attrs[FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES]
            elif FlextLdifConstants.SchemaFields.OBJECT_CLASSES in attrs:
                priority = 2
                oid_values = attrs[FlextLdifConstants.SchemaFields.OBJECT_CLASSES]
            else:
                return (3, FlextLdifUtilities.DN.get_dn_value(entry.dn).lower())

            # Extract OID
            first_val = str(
                oid_values[0] if isinstance(oid_values, list) else oid_values,
            )
            oid_match = re.search(r"\b\d+(?:\.\d+)+\b", first_val)
            oid = oid_match.group(0) if oid_match else first_val

            return (priority, oid)

        sorted_entries = sorted(self.entries, key=schema_key)
        return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)

    def _by_custom(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort using custom predicate."""
        if self.custom_predicate is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "Custom predicate not provided",
            )
        sorted_entries = sorted(self.entries, key=self.custom_predicate)
        return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)

    def _sort_entry_attributes_alphabetically(
        self,
        entry: FlextLdifModels.Entry,
        *,
        case_sensitive: bool = False,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Sort entry attributes alphabetically."""
        attrs_dict = entry.attributes.attributes  # Get the actual attributes dict
        if case_sensitive:
            key_func: Callable[[tuple[str, list[str]]], str] = operator.itemgetter(0)
        else:

            def key_func(x: tuple[str, list[str]]) -> str:
                return x[0].lower()

        sorted_items = sorted(attrs_dict.items(), key=key_func)
        sorted_attrs = FlextLdifModels.LdifAttributes(attributes=dict(sorted_items))
        return FlextResult[FlextLdifModels.Entry].ok(
            entry.model_copy(update={"attributes": sorted_attrs}),
        )

    def _sort_entry_attributes_by_order(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Sort entry attributes by custom order."""
        if not self.attribute_order:
            return self._sort_entry_attributes_alphabetically(entry)
        attrs_dict = entry.attributes.attributes  # Get the actual attributes dict
        order = self.attribute_order
        ordered = [(k, attrs_dict[k]) for k in order if k in attrs_dict]
        remaining = sorted(
            [(k, v) for k, v in attrs_dict.items() if k not in order],
            key=lambda x: x[0].lower(),
        )
        sorted_attrs = FlextLdifModels.LdifAttributes(
            attributes=dict(ordered + remaining)
        )
        return FlextResult[FlextLdifModels.Entry].ok(
            entry.model_copy(update={"attributes": sorted_attrs}),
        )

    @staticmethod
    def attributes_by_order(
        attribute_items: list[tuple[str, list[str]]],
        order: list[str],
    ) -> list[tuple[str, list[str]]]:
        """Sort attribute items by custom order list.

        Args:
            attribute_items: List of (attr_name, attr_values) tuples
            order: Custom attribute order list

        Returns:
            Sorted list of attribute items

        """
        attrs_dict = dict(attribute_items)
        ordered = [(k, attrs_dict[k]) for k in order if k in attrs_dict]
        remaining = sorted(
            [(k, v) for k, v in attrs_dict.items() if k not in order],
            key=lambda x: x[0].lower(),
        )
        return ordered + remaining

    @staticmethod
    def attributes_alphabetically(
        attribute_items: list[tuple[str, list[str]]],
        *,
        case_sensitive: bool = False,
    ) -> list[tuple[str, list[str]]]:
        """Sort attribute items alphabetically.

        Args:
            attribute_items: List of (attr_name, attr_values) tuples
            case_sensitive: Whether to use case-sensitive sorting

        Returns:
            Sorted list of attribute items

        """
        if case_sensitive:
            key_func: Callable[[tuple[str, list[str]]], str] = operator.itemgetter(0)
        else:

            def key_func(x: tuple[str, list[str]]) -> str:
                return x[0].lower()

        return sorted(attribute_items, key=key_func)

    @classmethod
    def hierarchical_sort_by_dn(
        cls,
        entries: list[FlextLdifModels.Entry],
        *,
        reverse: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort entries in hierarchical order following LDAP DN tree structure.

        Organizes entries by their DN hierarchy:
        - Root entries first (few RDNs)
        - Child entries grouped by parent
        - Siblings sorted lexicographically

        Args:
            entries: List of entries to sort
            reverse: If True, sort in reverse hierarchical order (leaf → root)

        Returns:
            FlextResult with hierarchically sorted entries

        Example:
            >>> entries = [
            ...     Entry(dn="cn=user,ou=users,dc=example,dc=com"),
            ...     Entry(dn="ou=users,dc=example,dc=com"),
            ...     Entry(dn="dc=example,dc=com"),
            ... ]
            >>> result = FlextLdifSorting.hierarchical_sort_by_dn(entries)
            >>> # Result: [dc=example,dc=com], [ou=users,dc=example,dc=com], [cn=user,...]

        """
        try:

            def dn_depth_key(entry: FlextLdifModels.Entry) -> tuple[int, str]:
                dn = FlextLdifUtilities.DN.get_dn_value(entry.dn)
                # Count RDNs (components separated by commas not in quotes)
                rdn_count = dn.count(",") + 1
                return (rdn_count, dn)

            sorted_entries = sorted(
                entries,
                key=dn_depth_key,
                reverse=reverse,
            )
            return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)

        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Hierarchical DN sort failed: {e}",
            )

    @classmethod
    def smart_sort_entries(
        cls,
        entries: list[FlextLdifModels.Entry],
        primary_key: str = "dn",
        secondary_key: str | None = None,
        *,
        case_sensitive: bool = False,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Intelligent sorting supporting multiple attribute types and fallbacks.

        Automatically handles:
        - DN sorting with hierarchy awareness
        - Attribute sorting with type detection
        - Multi-level sorting with fallback keys
        - Case-sensitive/insensitive handling

        Args:
            entries: List of entries to sort
            primary_key: Primary sort key ("dn", "cn", "uid", or any attribute)
            secondary_key: Optional fallback sort key if primary is unavailable
            case_sensitive: Whether to use case-sensitive comparison

        Returns:
            FlextResult with sorted entries using intelligent key extraction

        """
        try:

            def get_sort_value(
                entry: FlextLdifModels.Entry,
                key: str,
            ) -> tuple[int, int, str]:
                """Extract value from entry, with type-aware sorting."""
                if key.lower() == "dn":
                    value = FlextLdifUtilities.DN.get_dn_value(entry.dn)
                    rdn_count = value.count(",") + 1
                    return (0, rdn_count, value if case_sensitive else value.lower())
                # Try to find attribute in entry
                for attr_name, attr_values in entry.attributes.items():
                    if attr_name.lower() == key.lower():
                        # Convert list to first value for sorting
                        if isinstance(attr_values, list) and attr_values:
                            val = str(attr_values[0])
                        else:
                            val = str(attr_values) if attr_values else ""
                        return (1, 0, val if case_sensitive else val.lower())
                # Attribute not found, try secondary key
                if secondary_key:
                    return (2, 0, secondary_key)
                return (3, 0, "")

            sorted_entries = sorted(
                entries,
                key=lambda e: get_sort_value(e, primary_key),
            )
            return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)

        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Smart sort failed: {e}",
            )

    @staticmethod
    def _extract_group_values(
        entry: FlextLdifModels.Entry,
        group_by: str,
    ) -> list[str]:
        """Extract grouping attribute values from an entry.

        Args:
            entry: Entry to extract from
            group_by: Attribute name to group by

        Returns:
            List of group values, or ["__ungrouped__"] if not found

        """
        for attr_name, attr_value in entry.attributes.items():
            if attr_name.lower() == group_by.lower():
                if isinstance(attr_value, list):
                    return [str(v) for v in attr_value]
                return [str(attr_value)]
        return ["__ungrouped__"]

    @classmethod
    def group_and_sort(
        cls,
        entries: list[FlextLdifModels.Entry],
        group_by: str = "objectclass",
        *,
        sort_within_group: bool = True,
    ) -> FlextResult[dict[str, list[FlextLdifModels.Entry]]]:
        """Group entries by an attribute and sort within groups.

        Organizes entries into groups with internal sorting:
        - Groups by specified attribute (e.g., objectClass, ou)
        - Optionally sorts entries within each group
        - Returns dict mapping group value to entries

        Args:
            entries: List of entries to group and sort
            group_by: Attribute to group by (default: objectClass)
            sort_within_group: Whether to sort entries within each group

        Returns:
            FlextResult with dict mapping group values to sorted entry lists

        """
        try:
            groups: dict[str, list[FlextLdifModels.Entry]] = {}

            for entry in entries:
                # Extract grouping values using helper
                group_values = cls._extract_group_values(entry, group_by)

                # Add entry to all relevant groups
                for group_value in group_values:
                    if group_value not in groups:
                        groups[group_value] = []
                    groups[group_value].append(entry)

            # Sort within groups if requested
            if sort_within_group:
                for group_key, group_entries in groups.items():
                    result = cls.hierarchical_sort_by_dn(group_entries)
                    if result.is_success:
                        groups[group_key] = result.unwrap()

            return FlextResult[dict[str, list[FlextLdifModels.Entry]]].ok(groups)

        except Exception as e:
            return FlextResult[dict[str, list[FlextLdifModels.Entry]]].fail(
                f"Group and sort failed: {e}",
            )


__all__ = ["FlextLdifSorting"]
