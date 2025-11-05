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


class FlextLdifSortingService(FlextService[list[FlextLdifModels.Entry]]):
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
    ╚══════════════════════════════════════════════════════════════════════╝

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
    result = FlextLdifSortingService(
        entries=my_entries,
        sort_by="hierarchy"
    ).execute()

    if result.is_success:
        sorted_entries = result.unwrap()

    # PATTERN 2: Classmethod for Composable/Chainable Operations
    ────────────────────────────────────────────────────────────
    result = (
        FlextLdifSortingService.sort(my_entries, by="hierarchy")
        .map(lambda e: e[:10])  # Take first 10
        .and_then(lambda e: FlextLdifSortingService.sort(e, by="alphabetical"))
    )

    # PATTERN 3: Fluent Builder Pattern
    ───────────────────────────────────
    sorted_entries = (
        FlextLdifSortingService.builder()
        .with_entries(my_entries)
        .with_strategy("hierarchy")
        .with_attribute_sorting(order=["cn", "sn", "mail"])
        .build()  # Returns list[Entry] directly
    )

    # PATTERN 4: Public Classmethod Helpers (Most Direct)
    ────────────────────────────────────────────────────
    # Sort entries by hierarchy
    result = FlextLdifSortingService.by_hierarchy(my_entries)
    sorted_entries = result.unwrap()

    # Sort entries alphabetically by DN
    result = FlextLdifSortingService.by_dn(my_entries)

    # Sort entries by custom predicate
    result = FlextLdifSortingService.by_custom(
        my_entries,
        lambda e: e.dn.value.count(",")  # By depth
    )

    # Sort attributes in entries
    result = FlextLdifSortingService.sort_attributes(
        my_entries,
        order=["cn", "sn", "mail"]
    )

    # Sort ACL values in entries
    result = FlextLdifSortingService.sort_acl(my_entries)

    # Sort schema entries by OID
    result = FlextLdifSortingService.by_schema(schema_entries)

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
    sorted_entries = FlextLdifSortingService(
        entries=my_entries,
        sort_target="attributes"
    ).execute().unwrap()

    # Sort ONLY ACL values within entries
    sorted_entries = FlextLdifSortingService(
        entries=my_entries,
        sort_target="acl"
    ).execute().unwrap()

    # Sort EVERYTHING at once
    sorted_entries = FlextLdifSortingService(
        entries=my_entries,
        sort_target="combined",
        sort_by="hierarchy",
        sort_attributes=True,
        attribute_order=["objectClass", "cn", "sn", "mail"],
        sort_acl=True
    ).execute().unwrap()

    # Custom sorting: sort by DN length
    sorted_entries = FlextLdifSortingService(
        entries=my_entries,
        sort_by="custom",
        custom_predicate=lambda e: len(e.dn.value)
    ).execute().unwrap()

    # Custom sorting: sort by CN attribute value
    result = FlextLdifSortingService.by_custom(
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
        → FlextLdifSortingService (fluent builder, terminal: .build())

    ═══════════════════════════════════════════════════════════════════════
    QUICK REFERENCE
    ═══════════════════════════════════════════════════════════════════════

    Most Common Use Cases:

    # Just sort entries by hierarchy
    sorted = FlextLdifSortingService.by_hierarchy(entries).unwrap()

    # Just sort entries alphabetically
    sorted = FlextLdifSortingService.by_dn(entries).unwrap()

    # Sort entries + sort attributes + sort ACL
    sorted = FlextLdifSortingService(
        entries=entries,
        sort_target="combined",
        sort_by="hierarchy",
        sort_attributes=True,
        sort_acl=True
    ).execute().unwrap()

    # Sort with custom logic
    sorted = FlextLdifSortingService.by_custom(
        entries,
        lambda e: e.dn.value.count(",")  # By depth
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
    def validate_custom_predicate_when_needed(self) -> FlextLdifSortingService:
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
                    f"Unknown sort_target: {self.sort_target}"
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
                                 predicate=lambda e: len(e.dn.value)
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
    def builder(cls) -> FlextLdifSortingService:
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

    def with_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextLdifSortingService:
        """Set entries to sort (fluent builder)."""
        self.entries = entries
        return self

    def with_target(
        self, target: str | FlextLdifConstants.SortTarget
    ) -> FlextLdifSortingService:
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
        self, strategy: str | FlextLdifConstants.SortStrategy
    ) -> FlextLdifSortingService:
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
        self, predicate: Callable[[FlextLdifModels.Entry], str | int | float]
    ) -> FlextLdifSortingService:
        """Set custom predicate function (fluent builder)."""
        self.custom_predicate = predicate
        return self

    def with_attribute_sorting(
        self, *, alphabetical: bool = False, order: list[str] | None = None
    ) -> FlextLdifSortingService:
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
        self, enabled: bool = True, acl_attrs: list[str] | None = None
    ) -> FlextLdifSortingService:
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
        cls, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort entries by hierarchy (depth-first, then alphabetical).

        Args:
            entries: LDIF entries to sort

        Returns:
            FlextResult with sorted entries (shallowest first)

        Example:
            result = FlextLdifSortingService.by_hierarchy(entries)
            sorted_entries = result.unwrap()

        """
        return cls(
            entries=entries, sort_target="entries", sort_by="hierarchy"
        ).execute()

    @classmethod
    def by_dn(
        cls, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort entries alphabetically by full DN.

        Args:
            entries: LDIF entries to sort

        Returns:
            FlextResult with sorted entries (case-insensitive alphabetical)

        Example:
            result = FlextLdifSortingService.by_dn(entries)
            sorted_entries = result.unwrap()

        """
        return cls(entries=entries, sort_target="entries", sort_by="dn").execute()

    @classmethod
    def by_schema(
        cls, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort schema entries by OID (attributeTypes before objectClasses).

        Args:
            entries: Schema entries to sort

        Returns:
            FlextResult with sorted schema entries

        Example:
            result = FlextLdifSortingService.by_schema(schema_entries)
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
            result = FlextLdifSortingService.by_custom(
                entries,
                lambda e: e.dn.value.count(",")
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
                        f"Unknown strategy: {self.sort_by}"
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
        self, entries: list[FlextLdifModels.Entry]
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
                    f"Attribute sort failed: {result.error}"
                )
            processed.append(result.unwrap())

        return FlextResult[list[FlextLdifModels.Entry]].ok(processed)

    def _sort_acl_in_entries(
        self, entries: list[FlextLdifModels.Entry]
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
                            acl_values, key=lambda x: str(x).lower()
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
        """Sort by DN hierarchy (depth-first)."""
        sorted_entries = sorted(
            self.entries,
            key=lambda e: (
                e.dn.value.count(",") + 1 if e.dn.value else 0,
                e.dn.value.lower(),
            ),
        )
        return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)

    def _by_dn(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort alphabetically by DN."""
        sorted_entries = sorted(self.entries, key=lambda e: e.dn.value.lower())
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
                return (3, entry.dn.value.lower())

            # Extract OID
            first_val = str(
                oid_values[0] if isinstance(oid_values, list) else oid_values
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
                "Custom predicate not provided"
            )
        sorted_entries = sorted(self.entries, key=self.custom_predicate)
        return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)

    def _sort_entry_attributes_alphabetically(
        self, entry: FlextLdifModels.Entry, case_sensitive: bool = False
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Sort entry attributes alphabetically."""
        attrs_dict = entry.attributes.model_dump()
        if case_sensitive:
            key_func: Callable[[tuple[str, list[str]]], str] = operator.itemgetter(0)
        else:
            key_func = lambda x: x[0].lower()
        sorted_items = sorted(attrs_dict.items(), key=key_func)
        sorted_attrs = FlextLdifModels.LdifAttributes(**dict(sorted_items))
        return FlextResult[FlextLdifModels.Entry].ok(
            entry.model_copy(update={"attributes": sorted_attrs})
        )

    def _sort_entry_attributes_by_order(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Sort entry attributes by custom order."""
        if not self.attribute_order:
            return self._sort_entry_attributes_alphabetically(entry)
        attrs_dict = entry.attributes.model_dump()
        order = self.attribute_order
        ordered = [(k, attrs_dict[k]) for k in order if k in attrs_dict]
        remaining = sorted(
            [(k, v) for k, v in attrs_dict.items() if k not in order],
            key=lambda x: x[0].lower(),
        )
        sorted_attrs = FlextLdifModels.LdifAttributes(**dict(ordered + remaining))
        return FlextResult[FlextLdifModels.Entry].ok(
            entry.model_copy(update={"attributes": sorted_attrs})
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
            key_func = lambda x: x[0].lower()
        return sorted(attribute_items, key=key_func)


__all__ = ["FlextLdifSortingService"]
