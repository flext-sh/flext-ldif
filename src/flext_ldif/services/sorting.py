"""Sorting Service - LDIF Entry and Attribute Sorting Operations.

Provides comprehensive sorting capabilities for LDIF entries including hierarchical
DN sorting (depth-first, level-order), attribute sorting (alphabetical, custom order),
ACL sorting, schema sorting, and custom predicate sorting.

Scope: Entry sorting (hierarchical, DN, schema, custom), attribute sorting
(alphabetical, custom order), ACL sorting, combined sorting, grouping and sorting.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import operator
from collections.abc import Callable
from typing import ClassVar, Self, override

from flext_core import FlextResult, FlextRuntime
from pydantic import Field, field_validator, model_validator

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifSorting(
    FlextLdifServiceBase[list[FlextLdifModels.Entry]],
):
    """LDIF Sorting Service - Universal Sorting Engine."""

    auto_execute: ClassVar[bool] = False

    @classmethod
    def builder(cls) -> Self:
        """Create a new sorting service instance for builder pattern."""
        return cls()

    entries: list[FlextLdifModels.Entry] = Field(default_factory=list)
    sort_target: FlextLdifConstants.LiteralTypes.SortTargetLiteral = Field(
        default="entries",
    )
    sort_by: FlextLdifConstants.LiteralTypes.SortStrategyLiteral = Field(
        default="hierarchy",
    )
    custom_predicate: Callable[[FlextLdifModels.Entry], str | int | float] | None = (
        Field(default=None)
    )
    sort_attributes: bool = Field(default=False)
    attribute_order: list[str] | None = Field(default=None)
    sort_acl: bool = Field(default=False)
    acl_attributes: list[str] = Field(
        default_factory=lambda: list(
            FlextLdifConstants.AclAttributes.DEFAULT_ACL_ATTRIBUTES,
        ),
    )
    traversal: str = Field(default="depth-first")

    def with_entries(self, entries: list[FlextLdifModels.Entry]) -> Self:
        """Set entries to sort."""
        self.entries = entries
        return self

    def with_strategy(
        self,
        strategy: FlextLdifConstants.LiteralTypes.SortStrategyLiteral,
    ) -> Self:
        """Set sorting strategy."""
        self.sort_by = strategy
        return self

    def with_attribute_sorting(
        self,
        *,
        alphabetical: bool | None = None,
        order: list[str] | None = None,
    ) -> Self:
        """Configure attribute sorting.

        Args:
            alphabetical: Enable alphabetical sorting (mutually exclusive with order)
            order: Custom attribute order (mutually exclusive with alphabetical)

        """
        if alphabetical is not None:
            self.sort_attributes = alphabetical
            self.attribute_order = None
        if order is not None:
            self.attribute_order = order
            self.sort_attributes = False
        return self

    def with_target(
        self,
        target: FlextLdifConstants.LiteralTypes.SortTargetLiteral,
    ) -> Self:
        """Set sorting target (entries, attributes, acl, schema, combined)."""
        self.sort_target = target
        return self

    @field_validator("sort_target")
    @classmethod
    def validate_sort_target(
        cls,
        v: FlextLdifConstants.LiteralTypes.SortTargetLiteral | str,
    ) -> FlextLdifConstants.LiteralTypes.SortTargetLiteral:
        """Validate sort_target parameter.

        Args:
            v: The sort target value to validate

        Returns:
            The validated sort target value

        Raises:
            ValueError: If the sort target is not valid

        """
        # Use TypeGuard for proper type narrowing
        if FlextLdifConstants.is_valid_sort_target_literal(v):
            return v
        valid = {t.value for t in FlextLdifConstants.SortTarget.__members__.values()}
        msg = f"Invalid sort_target: {v!r}. Valid: {', '.join(sorted(valid))}"
        raise ValueError(msg)

    @field_validator("sort_by")
    @classmethod
    def validate_sort_strategy(
        cls,
        v: FlextLdifConstants.LiteralTypes.SortStrategyLiteral | str,
    ) -> FlextLdifConstants.LiteralTypes.SortStrategyLiteral:
        """Validate sort_by parameter.

        Args:
            v: The sort strategy value to validate

        Returns:
            The validated sort strategy value

        Raises:
            ValueError: If the sort strategy is not valid

        """
        # Use TypeGuard for proper type narrowing
        if FlextLdifConstants.is_valid_sort_strategy_literal(v):
            return v
        valid = {s.value for s in FlextLdifConstants.SortStrategy.__members__.values()}
        msg = f"Invalid sort_by: {v!r}. Valid: {', '.join(sorted(valid))}"
        raise ValueError(msg)

    @field_validator("traversal")
    @classmethod
    def validate_traversal(cls, v: str) -> str:
        """Validate traversal parameter.

        Args:
            v: The traversal value to validate

        Returns:
            The validated traversal value

        Raises:
            ValueError: If the traversal is not valid

        """
        if v not in {"depth-first", "level-order"}:
            msg = f"Invalid traversal: {v!r}"
            raise ValueError(msg)
        return v

    @model_validator(mode="after")
    def validate_custom_predicate(self) -> Self:
        """Validate custom predicate requirements."""
        if (
            self.sort_by == FlextLdifConstants.SortStrategy.CUSTOM.value
            and not self.custom_predicate
        ):
            msg = "custom_predicate required when sort_by='custom'"
            raise ValueError(msg)
        return self

    @override
    def execute(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute sorting based on sort_target."""
        if not self.entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        dispatch = {
            FlextLdifConstants.SortTarget.ENTRIES.value: self._sort_entries,
            FlextLdifConstants.SortTarget.ATTRIBUTES.value: self._sort_only_attributes,
            FlextLdifConstants.SortTarget.ACL.value: self._sort_only_acl,
            FlextLdifConstants.SortTarget.SCHEMA.value: self._sort_schema_entries,
            FlextLdifConstants.SortTarget.COMBINED.value: self._sort_combined,
        }
        method = dispatch.get(self.sort_target)
        return (
            method()
            if method
            else FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Unknown sort_target: {self.sort_target}",
            )
        )

    @classmethod
    def sort(
        cls,
        entries: list[FlextLdifModels.Entry],
        *,
        target: str = FlextLdifConstants.SortTarget.ENTRIES.value,
        by: str
        | FlextLdifConstants.SortStrategy = FlextLdifConstants.SortStrategy.HIERARCHY,
        traversal: str = "depth-first",
        predicate: Callable[[FlextLdifModels.Entry], str | int | float] | None = None,
        sort_attributes: bool = False,
        attribute_order: list[str] | None = None,
        sort_acl: bool = False,
        acl_attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort entries with FlextResult for composable operations."""
        strategy = by.value if isinstance(by, FlextLdifConstants.SortStrategy) else by
        default_acl_attrs = list(
            FlextLdifConstants.AclAttributes.DEFAULT_ACL_ATTRIBUTES,
        )
        from typing import cast
        return cls(
            entries=entries,
            sort_target=cast("FlextLdifConstants.LiteralTypes.SortTargetLiteral", target),
            sort_by=cast("FlextLdifConstants.LiteralTypes.SortStrategyLiteral", strategy),
            traversal=traversal,
            custom_predicate=predicate,
            sort_attributes=sort_attributes,
            attribute_order=attribute_order,
            sort_acl=sort_acl,
            acl_attributes=acl_attributes or default_acl_attrs,
        ).execute()

    # PUBLIC CLASSMETHOD HELPERS (Direct Entry Points)

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
        sorting_instance = cls(
            entries=entries,
            sort_target=FlextLdifConstants.SortTarget.ENTRIES.value,
            sort_by=FlextLdifConstants.SortStrategy.HIERARCHY.value,
        )
        return sorting_instance.execute()

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
        sorting_instance = cls(
            entries=entries,
            sort_target=FlextLdifConstants.SortTarget.ENTRIES.value,
            sort_by=FlextLdifConstants.SortStrategy.DN.value,
        )
        return sorting_instance.execute()

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
        sorting_instance = cls(
            entries=entries,
            sort_target=FlextLdifConstants.SortTarget.SCHEMA.value,
            sort_by=FlextLdifConstants.SortStrategy.SCHEMA.value,
        )
        return sorting_instance.execute()

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
        sorting_instance = cls(
            entries=entries,
            sort_target=FlextLdifConstants.SortTarget.ENTRIES.value,
            sort_by=FlextLdifConstants.SortStrategy.CUSTOM.value,
            custom_predicate=predicate,
        )
        return sorting_instance.execute()

    @classmethod
    def sort_attributes_in_entries(
        cls,
        entries: list[FlextLdifModels.Entry],
        order: list[str] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort attributes within entries.

        Args:
            entries: LDIF entries to process
            order: Custom attribute order list (optional)

        Returns:
            FlextResult with entries having sorted attributes

        Example:
            result = FlextLdifSorting.sort_attributes_in_entries(
                entries,
                order=["cn", "sn", "mail"]
            )
            sorted_entries = result.unwrap()

        """
        sorting_instance = cls(
            entries=entries,
            sort_target=FlextLdifConstants.SortTarget.ATTRIBUTES.value,
            attribute_order=order,
        )
        return sorting_instance.execute()

    @classmethod
    def sort_acl_in_entries(
        cls,
        entries: list[FlextLdifModels.Entry],
        acl_attrs: list[str] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort ACL attribute values within entries.

        Args:
            entries: LDIF entries to process
            acl_attrs: ACL attribute names to sort (default: ["acl", "aci", "olcAccess"])

        Returns:
            FlextResult with entries having sorted ACL values

        Example:
            result = FlextLdifSorting.sort_acl_in_entries(entries)
            sorted_entries = result.unwrap()

        """
        sorting_instance = cls(
            entries=entries,
            sort_target=FlextLdifConstants.SortTarget.ACL.value,
            acl_attributes=acl_attrs if acl_attrs is not None else [],
        )
        return sorting_instance.execute()

    def _sort_entries(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Universal entry sorting engine."""
        strategies = {
            FlextLdifConstants.SortStrategy.HIERARCHY.value: self._by_hierarchy,
            FlextLdifConstants.SortStrategy.DN.value: self._by_dn,
            FlextLdifConstants.SortStrategy.ALPHABETICAL.value: self._by_dn,
            FlextLdifConstants.SortStrategy.SCHEMA.value: self._by_schema,
            FlextLdifConstants.SortStrategy.CUSTOM.value: self._by_custom,
        }
        method = strategies.get(self.sort_by)
        if not method:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Unknown strategy: {self.sort_by}",
            )
        return method()

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
        processed: list[FlextLdifModels.Entry] = []
        for entry in entries:
            if self.attribute_order:
                result = self._sort_entry_attributes_by_order(entry)
            else:
                result = self._sort_entry_attributes_alphabetically(entry)

            if not result.is_success:
                error_msg = result.error or "Unknown error"
                original_attrs = (
                    list(entry.attributes.attributes.keys()) if entry.attributes else []
                )
                self.logger.error(
                    "Failed to sort entry attributes",
                    action_attempted="sort_entry_attributes",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    entry_index=len(processed) + 1,
                    total_entries=len(entries),
                    error=str(error_msg),
                    error_type=type(result.error).__name__ if result.error else None,
                    attributes_count=len(original_attrs),
                    consequence="Entry attributes were not sorted",
                )
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Attribute sort failed: {error_msg}",
                )
            processed.append(result.unwrap())

        return FlextResult[list[FlextLdifModels.Entry]].ok(processed)

    @staticmethod
    def _ensure_metadata_extensions(
        entry: FlextLdifModels.Entry,
    ) -> FlextLdifModels.Entry:
        """Ensure entry metadata has extensions initialized using Entry Model + Metadata pattern."""
        # Use QuirkMetadata.create_for() factory method which handles defaults
        if entry.metadata is None:
            return entry.model_copy(
                update={"metadata": FlextLdifModels.QuirkMetadata.create_for()},
            )
        if entry.metadata.extensions is None:
            # Initialize with empty DynamicMetadata via immutable model_copy
            new_metadata = entry.metadata.model_copy(
                update={"extensions": FlextLdifModels.DynamicMetadata()},
            )
            return entry.model_copy(update={"metadata": new_metadata})
        return entry

    def _track_acl_sorting_metadata(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextLdifModels.Entry:
        """Track ACL sorting transformation in metadata using Entry Model + Metadata pattern."""
        new_entry = FlextLdifSorting._ensure_metadata_extensions(entry)
        mk = FlextLdifConstants.MetadataKeys
        # After _ensure_metadata_extensions, metadata is guaranteed non-None
        if new_entry.metadata is not None:
            extensions = new_entry.metadata.extensions
            # DynamicMetadata supports __setitem__ for extra fields
            extensions[mk.SORTING_ACL_ATTRIBUTES] = self.acl_attributes
            extensions[mk.SORTING_ACL_SORTED] = True
        return new_entry

    def _sort_acl_in_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort ACL attributes in all entries."""
        processed = []
        for entry in entries:
            if not entry.attributes:
                processed.append(entry)
                continue

            attrs_dict: dict[str, list[str]] = {
                str(k): (
                    [str(v) for v in vals]
                    if FlextRuntime.is_list_like(vals)
                    else [str(vals)]
                )
                for k, vals in entry.attributes.attributes.items()
            }
            modified = False

            for acl_attr in self.acl_attributes:
                if acl_attr in attrs_dict:
                    acl_values_raw = attrs_dict[acl_attr]
                    acl_values = (
                        acl_values_raw
                        if FlextRuntime.is_list_like(acl_values_raw)
                        else [str(acl_values_raw)]
                    )
                    if len(acl_values) > 1:
                        sorted_acl: list[str] = [
                            str(item)
                            for item in sorted(acl_values, key=lambda x: str(x).lower())
                        ]
                        attrs_dict[acl_attr] = sorted_acl
                        modified = True

            if modified:
                sorted_attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
                new_entry = entry.model_copy(update={"attributes": sorted_attrs})
                processed.append(self._track_acl_sorting_metadata(new_entry))
            else:
                processed.append(entry)

        return FlextResult[list[FlextLdifModels.Entry]].ok(processed)

    @staticmethod
    def _build_dn_tree(
        entries: list[FlextLdifModels.Entry],
    ) -> tuple[dict[str, list[str]], dict[str, list[FlextLdifModels.Entry]], list[str]]:
        """Build DN tree structure for depth-first traversal.

        Returns:
            Tuple of (parent_to_children, dn_to_entries, root_dns)
            - parent_to_children: Dict mapping parent DN to list of child DNs
            - dn_to_entries: Dict mapping DN to list of Entry objects (supports duplicates)
            - root_dns: List of root DNs (depth 1-2)

        """
        parent_to_children: dict[str, list[str]] = {}
        dn_to_entries: dict[str, list[FlextLdifModels.Entry]] = {}

        # First pass: build dn_to_entries and parent_to_children mappings
        for entry in entries:
            dn_value = (
                str(FlextLdifUtilities.DN.get_dn_value(entry.dn)) if entry.dn else ""
            )
            if not dn_value:
                continue

            # Normalize DN for consistent handling
            norm_result = FlextLdifUtilities.DN.norm(dn_value)
            normalized_dn = norm_result.unwrap() if norm_result.is_success else None
            dn_key = normalized_dn.lower() if normalized_dn else dn_value.lower()

            # Store entry (append to list to support duplicates)
            if dn_key not in dn_to_entries:
                dn_to_entries[dn_key] = []
            dn_to_entries[dn_key].append(entry)

            # Extract parent DN (everything after first comma)
            if "," in dn_value:
                parent_dn = dn_value.split(",", 1)[1]
                parent_norm_result = FlextLdifUtilities.DN.norm(parent_dn)
                parent_normalized = (
                    parent_norm_result.unwrap()
                    if parent_norm_result.is_success
                    else None
                )
                parent_key = (
                    parent_normalized.lower()
                    if parent_normalized
                    else parent_dn.lower()
                )

                # Add to parent's children (only once per unique DN)
                if parent_key not in parent_to_children:
                    parent_to_children[parent_key] = []
                if dn_key not in parent_to_children[parent_key]:
                    parent_to_children[parent_key].append(dn_key)

        # Sort children alphabetically for consistent ordering
        for children in parent_to_children.values():
            children.sort()

        # Identify root DNs using helper method
        root_dns = FlextLdifSorting._identify_root_dns(dn_to_entries)

        return parent_to_children, dn_to_entries, root_dns

    @staticmethod
    def _dfs_traverse(
        dn: str,
        parent_to_children: dict[str, list[str]],
        dn_to_entries: dict[str, list[FlextLdifModels.Entry]],
        visited: set[str],
    ) -> list[FlextLdifModels.Entry]:
        """Depth-first traversal of DN tree.

        Visits parent, then recursively visits all children before moving to siblings.
        This ensures proper LDAP sync order (parents before children).
        Preserves duplicate DNs by including all entries for each DN.

        Args:
            dn: Current DN to visit
            parent_to_children: Tree structure mapping parent->children
            dn_to_entries: Mapping DN->list of Entry objects (supports duplicates)
            visited: Set of already visited DNs (prevents infinite loops)

        Returns:
            List of entries in depth-first order

        """
        if dn in visited or dn not in dn_to_entries:
            return []

        visited.add(dn)
        # Include ALL entries with this DN (preserves duplicates)
        result = list(dn_to_entries[dn])

        # Recursively visit all children (already sorted alphabetically)
        for child_dn in parent_to_children.get(dn, []):
            result.extend(
                FlextLdifSorting._dfs_traverse(
                    child_dn,
                    parent_to_children,
                    dn_to_entries,
                    visited,
                ),
            )

        return result

    @staticmethod
    def _identify_root_dns(
        dn_to_entries: dict[str, list[FlextLdifModels.Entry]],
    ) -> list[str]:
        """Identify root DNs (entries whose parents are not in the list).

        Args:
            dn_to_entries: Mapping DN->list of Entry objects

        Returns:
            List of root DNs sorted by depth (shallowest first), then alphabetically

        """
        root_dns: list[str] = []

        for dn_key, entry_list in dn_to_entries.items():
            # Use first entry to check root status (all duplicates have same DN)
            entry = entry_list[0]
            dn_value = (
                str(FlextLdifUtilities.DN.get_dn_value(entry.dn)) if entry.dn else ""
            )

            if "," not in dn_value:
                # True root (no parent)
                root_dns.append(dn_key)
            else:
                # Check if parent exists in entry list
                parent_dn = dn_value.split(",", 1)[1]
                parent_norm_result = FlextLdifUtilities.DN.norm(parent_dn)
                parent_normalized = (
                    parent_norm_result.unwrap()
                    if parent_norm_result.is_success
                    else None
                )
                parent_key = (
                    parent_normalized.lower()
                    if parent_normalized
                    else parent_dn.lower()
                )

                if parent_key not in dn_to_entries:
                    # Parent not in list, so this is a root
                    root_dns.append(dn_key)

        # Sort roots by depth (shallowest first), then alphabetically
        root_dns.sort(key=lambda dn_key: (dn_key.count(","), dn_key))

        return root_dns

    @staticmethod
    def _levelorder_traverse(
        entries: list[FlextLdifModels.Entry],
    ) -> list[FlextLdifModels.Entry]:
        """Level-order traversal (original behavior for backward compatibility).

        Sorts by (depth, normalized_dn) - all depth=1, then all depth=2, etc.
        This is NOT proper depth-first but provided for backward compatibility.

        Args:
            entries: Entries to sort

        Returns:
            List of entries in level-order (grouped by depth)

        """

        def sort_key(entry: FlextLdifModels.Entry) -> tuple[int, str]:
            dn_value = (
                str(FlextLdifUtilities.DN.get_dn_value(entry.dn)) if entry.dn else ""
            )
            if not dn_value:
                return (0, "")

            depth = dn_value.count(",") + 1
            norm_result = FlextLdifUtilities.DN.norm(dn_value)
            normalized = norm_result.unwrap() if norm_result.is_success else None
            sort_dn = normalized.lower() if normalized else dn_value.lower()

            return (depth, sort_dn)

        return sorted(entries, key=sort_key)

    def _by_hierarchy(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort by DN hierarchy using configurable traversal strategy.

        Traversal Modes:
            depth-first (default):
                - Proper parent->child ordering
                - Each parent immediately followed by ALL its descendants
                - Ensures LDAP sync works (parents added before children)
                - Example order: dc=com, ou=users,dc=com, cn=john,ou=users,dc=com

            level-order (backward compatibility):
                - Groups entries by depth level
                - All depth=1, then all depth=2, etc.
                - May fail LDAP sync if children span many levels
                - Example order: dc=com, ou=users,dc=com, ou=groups,dc=com, cn=john,...

        Uses FlextLdifUtilities.DN.norm() for RFC 4514 compliant DN normalization.
        Preserves duplicate DNs (same DN but different attributes).
        """
        if not self.entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        # Choose traversal strategy based on self.traversal
        if self.traversal == "depth-first":
            # Build DN tree structure
            parent_to_children, dn_to_entries, root_dns = self._build_dn_tree(
                self.entries,
            )

            # DFS traverse from each root
            sorted_entries: list[FlextLdifModels.Entry] = []
            visited: set[str] = set()
            for root_dn in root_dns:
                sorted_entries.extend(
                    self._dfs_traverse(
                        root_dn,
                        parent_to_children,
                        dn_to_entries,
                        visited,
                    ),
                )

            # Handle any orphaned entries (entries whose parents weren't in the list)
            # Note: All entries with same DN share the same dn_key, so if dn_key is
            # visited, all duplicate entries are already included
            for entry in self.entries:
                dn_value = (
                    str(FlextLdifUtilities.DN.get_dn_value(entry.dn))
                    if entry.dn
                    else ""
                )
                if dn_value:
                    norm_result = FlextLdifUtilities.DN.norm(dn_value)
                    normalized = (
                        norm_result.unwrap() if norm_result.is_success else None
                    )
                    dn_key = normalized.lower() if normalized else dn_value.lower()
                    if dn_key not in visited:
                        # Add all entries with this DN
                        sorted_entries.extend(dn_to_entries.get(dn_key, []))
                        visited.add(dn_key)

            return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)

        if self.traversal == "level-order":
            # Use level-order traversal (original behavior)
            sorted_entries = self._levelorder_traverse(self.entries)
            return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)

        # Should never happen due to validator, but handle gracefully
        return FlextResult[list[FlextLdifModels.Entry]].fail(
            f"Unknown traversal mode: {self.traversal}",
        )

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
            norm_result = FlextLdifUtilities.DN.norm(dn_value)
            normalized = norm_result.unwrap() if norm_result.is_success else None
            return normalized.lower() if normalized else dn_value.lower()

        sorted_entries = sorted(self.entries, key=dn_sort_key)
        return FlextResult[list[FlextLdifModels.Entry]].ok(sorted_entries)

    def _by_schema(self) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort schema entries by OID."""

        def schema_key(entry: FlextLdifModels.Entry) -> tuple[int, str]:
            if not entry.attributes:
                # Entries without attributes go to the end
                return (3, FlextLdifUtilities.DN.get_dn_value(entry.dn).lower())

            attrs = entry.attributes.attributes

            # Priority: attributetypes (1) before objectclasses (2)
            if FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES in attrs:
                priority = 1
                oid_values = attrs[FlextLdifConstants.SchemaFields.ATTRIBUTE_TYPES]
            elif FlextLdifConstants.SchemaFields.OBJECT_CLASSES in attrs:
                priority = 2
                oid_values = attrs[FlextLdifConstants.SchemaFields.OBJECT_CLASSES]
            else:
                return (3, FlextLdifUtilities.DN.get_dn_value(entry.dn).lower())

            # Extract OID using FlextLdifUtilities.OID for consistency
            first_val = str(
                oid_values[0] if FlextRuntime.is_list_like(oid_values) else oid_values,
            )
            oid = FlextLdifUtilities.OID.extract_from_definition(first_val) or first_val

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
        """Sort entry attributes alphabetically using Entry Model + Metadata pattern."""
        if not entry.attributes:
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        attrs_dict = entry.attributes.attributes
        sorted_items = (
            sorted(attrs_dict.items(), key=operator.itemgetter(0))
            if case_sensitive
            else sorted(attrs_dict.items(), key=lambda x: x[0].lower())
        )

        original_attr_order = list(attrs_dict.keys())
        sorted_dict: dict[str, list[str]] = dict(sorted_items)
        sorted_attrs = FlextLdifModels.LdifAttributes(attributes=sorted_dict)
        new_entry = entry.model_copy(update={"attributes": sorted_attrs})

        # Track sorting transformation in metadata if order changed using Entry Model + Metadata pattern
        new_attr_order = list(sorted_dict.keys())
        if original_attr_order != new_attr_order:
            # Ensure metadata extensions are initialized
            new_entry = FlextLdifSorting._ensure_metadata_extensions(new_entry)
            # After _ensure_metadata_extensions, metadata is guaranteed non-None
            if new_entry.metadata is not None:
                extensions = new_entry.metadata.extensions
                # Track attribute order transformation in metadata extensions using constants
                mk = FlextLdifConstants.MetadataKeys
                strategy_type = (
                    FlextLdifConstants.SortingStrategyType.ALPHABETICAL_CASE_SENSITIVE
                    if case_sensitive
                    else FlextLdifConstants.SortingStrategyType.ALPHABETICAL_CASE_INSENSITIVE
                )
                # DynamicMetadata supports __setitem__ for extra fields
                extensions[mk.ATTRIBUTE_ORDER] = original_attr_order
                extensions[mk.SORTING_NEW_ATTRIBUTE_ORDER] = new_attr_order
                extensions[mk.SORTING_STRATEGY] = strategy_type.value

                self.logger.debug(
                    "Sorted entry attributes",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    attributes_count=len(original_attr_order),
                )

        return FlextResult[FlextLdifModels.Entry].ok(new_entry)

    def _sort_entry_attributes_by_order(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Sort entry attributes by custom order using Entry Model + Metadata pattern."""
        if not self.attribute_order:
            return self._sort_entry_attributes_alphabetically(entry)

        if not entry.attributes:
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        attrs_dict = entry.attributes.attributes
        order = self.attribute_order
        original_attr_order = list(attrs_dict.keys())
        ordered = [(k, attrs_dict[k]) for k in order if k in attrs_dict]
        remaining = sorted(
            [(k, v) for k, v in attrs_dict.items() if k not in order],
            key=lambda x: x[0].lower(),
        )
        sorted_dict = dict(ordered + remaining)
        sorted_attrs = FlextLdifModels.LdifAttributes(attributes=sorted_dict)
        new_entry = entry.model_copy(update={"attributes": sorted_attrs})

        # Track sorting transformation in metadata if order changed using Entry Model + Metadata pattern
        new_attr_order = list(sorted_dict.keys())
        if original_attr_order != new_attr_order:
            # Ensure metadata extensions are initialized
            new_entry = FlextLdifSorting._ensure_metadata_extensions(new_entry)
            # After _ensure_metadata_extensions, metadata is guaranteed non-None
            if new_entry.metadata is not None:
                extensions = new_entry.metadata.extensions
                # Track custom order transformation in metadata extensions using constants
                mk = FlextLdifConstants.MetadataKeys
                ordered_attrs = [k for k, _ in ordered]
                remaining_attrs = [k for k, _ in remaining]
                # DynamicMetadata supports __setitem__ for extra fields
                extensions[mk.ATTRIBUTE_ORDER] = original_attr_order
                extensions[mk.SORTING_NEW_ATTRIBUTE_ORDER] = new_attr_order
                extensions[mk.SORTING_STRATEGY] = (
                    FlextLdifConstants.SortingStrategyType.CUSTOM_ORDER.value
                )
                extensions[mk.SORTING_CUSTOM_ORDER] = order
                extensions[mk.SORTING_ORDERED_ATTRIBUTES] = ordered_attrs
                extensions[mk.SORTING_REMAINING_ATTRIBUTES] = remaining_attrs

                self.logger.debug(
                    "Sorted entry attributes by custom order",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    attributes_count=len(original_attr_order),
                    ordered_count=len(ordered_attrs),
                    remaining_count=len(remaining_attrs),
                )

        return FlextResult[FlextLdifModels.Entry].ok(new_entry)
