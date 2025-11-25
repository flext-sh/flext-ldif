"""LDIF Entry Sorting Service - Advanced hierarchical and attribute sorting.

Provides comprehensive sorting capabilities for LDIF entries including:
- Hierarchical DN sorting (depth-first, level-order)
- Attribute sorting (alphabetical, custom order)
- ACL sorting
- Schema sorting
- Custom predicate sorting

Scope: Sorting operations for flext-ldif entries and attributes.
Modules: flext_ldif.services.sorting

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import operator
import re
from collections.abc import Callable
from typing import ClassVar, Self, cast

from flext_core import FlextResult, FlextRuntime
from pydantic import Field, field_validator, model_validator

from flext_ldif.base import LdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifSorting(LdifServiceBase):
    """LDIF Sorting Service - Universal Sorting Engine."""

    auto_execute: ClassVar[bool] = False

    @classmethod
    def builder(cls) -> Self:
        """Create a new sorting service instance for builder pattern."""
        return cls()

    entries: list[FlextLdifModels.Entry] = Field(default_factory=list)
    sort_target: str = Field(default=FlextLdifConstants.SortTarget.ENTRIES.value)
    sort_by: str = Field(default=FlextLdifConstants.SortStrategy.HIERARCHY.value)
    custom_predicate: Callable[[FlextLdifModels.Entry], str | int | float] | None = (
        Field(default=None)
    )
    sort_attributes: bool = Field(default=False)
    attribute_order: list[str] | None = Field(default=None)
    sort_acl: bool = Field(default=False)
    acl_attributes: list[str] = Field(
        default_factory=lambda: ["acl", "aci", "olcAccess"]
    )
    traversal: str = Field(default="depth-first")

    def with_entries(self, entries: list[FlextLdifModels.Entry]) -> Self:
        """Set entries to sort."""
        self.entries = entries
        return self

    def with_strategy(self, strategy: str) -> Self:
        """Set sorting strategy."""
        self.sort_by = strategy
        return self

    def with_attribute_sorting(
        self, *, alphabetical: bool | None = None, order: list[str] | None = None
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

    def with_target(self, target: str) -> Self:
        """Set sorting target (entries, attributes, acl, schema, combined)."""
        self.sort_target = target
        return self

    @field_validator("sort_target")
    @classmethod
    def validate_sort_target(cls, v: str) -> str:
        """Validate sort_target parameter.

        Args:
            v: The sort target value to validate

        Returns:
            The validated sort target value

        Raises:
            ValueError: If the sort target is not valid

        """
        valid = {t.value for t in FlextLdifConstants.SortTarget.__members__.values()}
        if v not in valid:
            msg = "Invalid sort_target: {!r}. Valid: {}".format(
                v, ", ".join(sorted(valid))
            )
            raise ValueError(msg)
        return v

    @field_validator("sort_by")
    @classmethod
    def validate_sort_strategy(cls, v: str) -> str:
        """Validate sort_by parameter.

        Args:
            v: The sort strategy value to validate

        Returns:
            The validated sort strategy value

        Raises:
            ValueError: If the sort strategy is not valid

        """
        valid = {s.value for s in FlextLdifConstants.SortStrategy.__members__.values()}
        if v not in valid:
            msg = "Invalid sort_by: {!r}. Valid: {}".format(v, ", ".join(sorted(valid)))
            raise ValueError(msg)
        return v

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

    def execute(self, **_kwargs: object) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute sorting based on sort_target."""
        if not self.entries:
            return FlextResult.ok([])

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
            else FlextResult.fail(f"Unknown sort_target: {self.sort_target}")
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
        kwargs = {
            "entries": entries,
            "sort_target": target,
            "sort_by": strategy,
            "traversal": traversal,
            "custom_predicate": predicate,
            "sort_attributes": sort_attributes,
            "attribute_order": attribute_order,
            "sort_acl": sort_acl,
        }
        if acl_attributes:
            kwargs["acl_attributes"] = acl_attributes
        return cls(
            entries=entries,
            sort_target=target,
            sort_by=strategy,
            traversal=traversal,
            custom_predicate=predicate,
            sort_attributes=sort_attributes,
            attribute_order=attribute_order,
            sort_acl=sort_acl,
            acl_attributes=acl_attributes or ["acl", "aci", "olcAccess"],
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
            sort_target="entries",
            sort_by="hierarchy",
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
        sorting_instance = cls(entries=entries, sort_target="entries", sort_by="dn")
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
        sorting_instance = cls(entries=entries, sort_target="schema", sort_by="schema")
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
            sort_target="entries",
            sort_by="custom",
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
            sort_target="attributes",
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
        # Build instance with explicit parameters
        sorting_instance = cls(
            entries=entries,
            sort_target="acl",
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
            return FlextResult.fail(f"Unknown strategy: {self.sort_by}")
        try:
            return method()
        except Exception as e:
            return FlextResult.fail(f"Sort failed: {e}")

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

    def _sort_acl_in_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Sort ACL attributes in all entries."""
        processed = []
        for entry in entries:
            # Skip entries without attributes
            if not entry.attributes:
                processed.append(entry)
                continue

            # Access the actual attributes dict
            # entry.attributes.attributes is dict[str, list[str]], ensure correct type
            attrs_dict_raw = entry.attributes.attributes
            attrs_dict: dict[str, list[str]] = {}
            for key, value in attrs_dict_raw.items():
                # Ensure value is list[str] (LdifAttributes.attributes is dict[str, list[str]])
                if FlextRuntime.is_list_like(value):
                    # Type narrowing: cast list[object] to list[str]
                    attrs_dict[key] = cast("list[str]", value)
                else:
                    attrs_dict[key] = [str(value)]
            modified = False

            # Sort each ACL attribute's values
            for acl_attr in self.acl_attributes:
                if acl_attr in attrs_dict:
                    acl_values_raw = attrs_dict[acl_attr]
                    # Ensure acl_values is a list
                    if FlextRuntime.is_list_like(acl_values_raw):
                        acl_values = acl_values_raw
                    else:
                        acl_values = [str(acl_values_raw)]
                    if len(acl_values) > 1:
                        # Type narrowing: sorted returns list[object], cast to list[str]
                        attrs_dict[acl_attr] = cast(
                            "list[str]",
                            sorted(
                                acl_values,
                                key=lambda x: str(x).lower(),
                            ),
                        )
                        modified = True

            if modified:
                # Create new LdifAttributes with sorted ACLs
                sorted_attrs = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
                processed.append(entry.model_copy(update={"attributes": sorted_attrs}))
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

            # Extract OID
            first_val = str(
                oid_values[0] if FlextRuntime.is_list_like(oid_values) else oid_values,
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
        if not entry.attributes:
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        attrs_dict = entry.attributes.attributes  # Get the actual attributes dict
        if case_sensitive:
            sorted_items = sorted(attrs_dict.items(), key=operator.itemgetter(0))
        else:
            sorted_items = sorted(attrs_dict.items(), key=lambda x: x[0].lower())

        # Create dict with correct type - attrs_dict is dict[str, list[str]]
        original_attr_order = list(attrs_dict.keys())
        sorted_dict: dict[str, list[str]] = dict(sorted_items)
        sorted_attrs = FlextLdifModels.LdifAttributes(
            attributes=sorted_dict,
        )
        new_entry = entry.model_copy(update={"attributes": sorted_attrs})

        # Log detailed sorting information if attributes were reordered
        new_attr_order = list(sorted_dict.keys())
        if original_attr_order != new_attr_order:
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
        """Sort entry attributes by custom order."""
        if not self.attribute_order:
            return self._sort_entry_attributes_alphabetically(entry)

        if not entry.attributes:
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        attrs_dict = entry.attributes.attributes  # Get the actual attributes dict
        order = self.attribute_order
        original_attr_order = list(attrs_dict.keys())
        ordered = [(k, attrs_dict[k]) for k in order if k in attrs_dict]
        remaining = sorted(
            [(k, v) for k, v in attrs_dict.items() if k not in order],
            key=lambda x: x[0].lower(),
        )
        sorted_dict = dict(ordered + remaining)
        sorted_attrs = FlextLdifModels.LdifAttributes(
            attributes=sorted_dict,
        )
        new_entry = entry.model_copy(update={"attributes": sorted_attrs})

        # Log detailed sorting information if attributes were reordered
        new_attr_order = list(sorted_dict.keys())
        if original_attr_order != new_attr_order:
            ordered_attrs = [k for k, _ in ordered]
            remaining_attrs = [k for k, _ in remaining]
            self.logger.debug(
                "Sorted entry attributes by custom order",
                entry_dn=str(entry.dn) if entry.dn else None,
                attributes_count=len(original_attr_order),
                ordered_count=len(ordered_attrs),
                remaining_count=len(remaining_attrs),
            )

        return FlextResult[FlextLdifModels.Entry].ok(new_entry)

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
            return sorted(attribute_items, key=operator.itemgetter(0))
        return sorted(attribute_items, key=lambda x: x[0].lower())

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
            reverse: If True, sort in reverse hierarchical order (leaf -> root)

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

    @staticmethod
    def _get_dn_sort_value(
        entry: FlextLdifModels.Entry,
        *,
        case_sensitive: bool = False,
    ) -> tuple[int, int, str]:
        """Extract DN value for sorting with hierarchy awareness.

        Args:
            entry: Entry to extract DN from
            case_sensitive: Whether to preserve case

        Returns:
            Tuple of (priority=0, rdn_count, dn_value) for DN sorting

        """
        value = FlextLdifUtilities.DN.get_dn_value(entry.dn)
        rdn_count = value.count(",") + 1
        return (0, rdn_count, value if case_sensitive else value.lower())

    @staticmethod
    def _find_attribute_sort_value(
        entry: FlextLdifModels.Entry,
        key: str,
        *,
        case_sensitive: bool = False,
    ) -> tuple[int, int, str]:
        """Find and extract attribute value for sorting.

        Args:
            entry: Entry to search in
            key: Attribute name to find
            case_sensitive: Whether to preserve case

        Returns:
            Tuple of (priority=1, 0, attr_value) if found, (priority=0, 0, "") if not found

        """
        if not entry.attributes:
            return (0, 0, "")  # Not found - use priority 0 to indicate missing

        for attr_name, attr_values in entry.attributes.items():
            if attr_name.lower() == key.lower():
                # Convert list to first value for sorting
                val = str(attr_values[0]) if attr_values else ""
                return (1, 0, val if case_sensitive else val.lower())
        return (0, 0, "")  # Not found - use priority 0 to indicate missing

    @staticmethod
    def _get_smart_sort_key(
        entry: FlextLdifModels.Entry,
        primary_key: str,
        secondary_key: str | None,
        *,
        case_sensitive: bool = False,
    ) -> tuple[int, int, str]:
        """Extract sort key from entry with fallback logic.

        Handles DN sorting, attribute sorting, and secondary key fallback
        with reduced complexity via helper methods.

        Args:
            entry: Entry to extract key from
            primary_key: Primary attribute to sort by
            secondary_key: Fallback key if primary not found
            case_sensitive: Whether to use case-sensitive comparison

        Returns:
            Tuple of (priority, rdn_count, value) for sorting

        """
        # DN sorting
        if primary_key.lower() == "dn":
            return FlextLdifSorting._get_dn_sort_value(
                entry,
                case_sensitive=case_sensitive,
            )

        # Attribute sorting
        attr_result = FlextLdifSorting._find_attribute_sort_value(
            entry,
            primary_key,
            case_sensitive=case_sensitive,
        )
        # Priority 1 means attribute was found
        if attr_result[0] == 1:
            return attr_result

        # Fallback to secondary key or empty
        if secondary_key:
            return (2, 0, secondary_key)
        return (3, 0, "")

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
            sorted_entries = sorted(
                entries,
                key=lambda e: cls._get_smart_sort_key(
                    e,
                    primary_key,
                    secondary_key,
                    case_sensitive=case_sensitive,
                ),
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
        if not entry.attributes:
            return ["__ungrouped__"]

        for attr_name, attr_value in entry.attributes.items():
            if attr_name.lower() == group_by.lower():
                return [str(v) for v in attr_value]
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
