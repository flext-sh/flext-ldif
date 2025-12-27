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
from collections.abc import Callable, Sequence
from typing import ClassVar, Self, override

from flext_core import FlextTypes as t, r
from pydantic import Field, field_validator, model_validator

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.utilities import u


class FlextLdifSorting(
    FlextLdifServiceBase[list[m.Ldif.Entry]],
):
    """LDIF Sorting Service - Universal Sorting Engine.

    Business Rule: Sorting service provides comprehensive entry and attribute sorting
    capabilities including hierarchical DN sorting (depth-first, level-order), attribute
    sorting (alphabetical, custom order), ACL sorting, and schema sorting. Sorting strategies
    enable data organization for migration, export, and analysis.

    Implication: Sorting maintains RFC compliance while enabling server-specific ordering
    requirements. Builder pattern enables fluent API for complex sorting configurations.
    All sorting operations are immutable - return new sorted entry lists.

    """

    auto_execute: ClassVar[bool] = False

    @classmethod
    def builder(cls) -> Self:
        """Create a new sorting service instance for builder pattern."""
        return cls()

    entries: list[m.Ldif.Entry] = Field(default_factory=list)
    sort_target: str = Field(
        default="entries",
    )
    sort_by: str = Field(
        default="hierarchy",
    )
    custom_predicate: Callable[[m.Ldif.Entry], str | int | float] | None = Field(
        default=None,
    )
    sort_attributes: bool = Field(default=False)
    attribute_order: list[str] | None = Field(default=None)
    sort_acl: bool = Field(default=False)
    acl_attributes: list[str] = Field(
        default_factory=lambda: list(c.Ldif.AclAttributes.DEFAULT_ACL_ATTRIBUTES),
    )
    traversal: str = Field(default="depth-first")

    def with_entries(self, entries: list[m.Ldif.Entry]) -> Self:
        """Set entries to sort."""
        # Use model_copy to update frozen model
        return self.model_copy(update={"entries": entries})

    def with_strategy(
        self,
        strategy: str,
    ) -> Self:
        """Set sorting strategy."""
        # Use model_copy to update frozen model
        return self.model_copy(update={"sort_by": strategy})

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
        # Use model_copy to update frozen model
        update_dict: dict[str, t.GeneralValueType] = {}
        if alphabetical is not None:
            update_dict["sort_attributes"] = alphabetical
            update_dict["attribute_order"] = None
        if order is not None:
            update_dict["attribute_order"] = order
            update_dict["sort_attributes"] = False
        return self.model_copy(update=update_dict) if update_dict else self

    def with_target(
        self,
        target: str,
    ) -> Self:
        """Set sorting target (entries, attributes, acl, schema, combined)."""
        # Use model_copy to update frozen model
        return self.model_copy(update={"sort_target": target})

    @field_validator("sort_target")
    @classmethod
    def validate_sort_target(
        cls,
        v: str,
    ) -> str:
        """Validate sort_target parameter.

        Args:
            v: The sort target value to validate

        Returns:
            The validated sort target value

        Raises:
            ValueError: If the sort target is not valid

        """
        # Type narrowing: check if v is a valid SortTarget literal
        valid_values = {
            c.Ldif.SortTarget.ENTRIES.value,
            c.Ldif.SortTarget.ATTRIBUTES.value,
            c.Ldif.SortTarget.ACL.value,
            c.Ldif.SortTarget.SCHEMA.value,
            c.Ldif.SortTarget.COMBINED.value,
        }
        if isinstance(v, str) and v in valid_values:
            # Type narrowing: v is a valid SortTarget literal value
            return v
        msg = f"Invalid sort_target: {v!r}. Valid: {', '.join(sorted(valid_values))}"
        raise ValueError(msg)

    @field_validator("sort_by")
    @classmethod
    def validate_sort_strategy(
        cls,
        v: str,
    ) -> str:
        """Validate sort_by parameter.

        Args:
            v: The sort strategy value to validate

        Returns:
            The validated sort strategy value

        Raises:
            ValueError: If the sort strategy is not valid

        """
        # Type narrowing: check if v is a valid SortStrategy literal
        valid_values = {
            c.Ldif.SortStrategy.HIERARCHY.value,
            c.Ldif.SortStrategy.DN.value,
            c.Ldif.SortStrategy.ALPHABETICAL.value,
            c.Ldif.SortStrategy.SCHEMA.value,
            c.Ldif.SortStrategy.CUSTOM.value,
        }
        if isinstance(v, str) and v in valid_values:
            # Type narrowing: v is a valid SortStrategy literal value
            return v
        msg = f"Invalid sort_by: {v!r}. Valid: {', '.join(sorted(valid_values))}"
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
            self.sort_by == c.Ldif.SortStrategy.CUSTOM.value
            and not self.custom_predicate
        ):
            msg = "custom_predicate required when sort_by='custom'"
            raise ValueError(msg)
        return self

    @override
    def execute(self) -> r[list[m.Ldif.Entry]]:
        """Execute sorting based on sort_target.

        Business Rule: Sorting execution routes to appropriate sorting method based on
        sort_target configuration (entries, attributes, acl, schema, combined). Empty
        entry lists return empty results (valid per RFC 2849). Sorting operations are
        immutable - return new sorted entry lists.

        Implication: Builder pattern enables fluent API for complex sorting configurations.
        Multiple sorting strategies can be combined for comprehensive data organization.

        Returns:
            FlextResult containing sorted entries (immutable - new list instances)

        """
        if not self.entries:
            return r[list[m.Ldif.Entry]].ok([])

        dispatch = {
            c.Ldif.SortTarget.ENTRIES.value: self._sort_entries,
            c.Ldif.SortTarget.ATTRIBUTES.value: self._sort_only_attributes,
            c.Ldif.SortTarget.ACL.value: self._sort_only_acl,
            c.Ldif.SortTarget.SCHEMA.value: self._sort_schema_entries,
            c.Ldif.SortTarget.COMBINED.value: self._sort_combined,
        }
        method = dispatch.get(self.sort_target)
        return (
            method()
            if method
            else r[list[m.Ldif.Entry]].fail(
                f"Unknown sort_target: {self.sort_target}",
            )
        )

    @classmethod
    def sort(
        cls,
        config: m.Ldif.LdifResults.SortConfig | None = None,
        entries: Sequence[m.Ldif.Entry] | None = None,
        target: str | None = None,
        by: str | None = None,
        traversal: str = "depth-first",
        predicate: Callable[[m.Ldif.Entry], str | int | float] | None = None,
        attribute_order: list[str] | None = None,
        acl_attributes: list[str] | None = None,
        *,
        sort_attributes: bool = False,
        sort_acl: bool = False,
    ) -> r[list[m.Ldif.Entry]]:
        """Sort entries with FlextResult for composable operations.

        Args:
            config: SortConfig model (if provided, other params are ignored)
            entries: LDIF entries to sort
            target: Sort target (entries, attributes, acl, schema, combined)
            by: Sort strategy (hierarchy, dn, schema, custom)
            traversal: Traversal order (depth-first, level-order)
            predicate: Custom predicate function for custom sorting
            sort_attributes: Whether to sort attributes within entries
            attribute_order: Custom attribute order list
            sort_acl: Whether to sort ACL attributes
            acl_attributes: List of ACL attribute names to sort

        Returns:
            FlextResult with sorted entries

        """
        default_target = c.Ldif.SortTarget.ENTRIES.value
        default_by = c.Ldif.SortStrategy.HIERARCHY.value
        default_acl_attrs = list(c.Ldif.AclAttributes.DEFAULT_ACL_ATTRIBUTES)

        if config is not None:
            # Use config model - extract values with proper type narrowing
            strategy = config.by if isinstance(config.by, str) else str(config.by)
            # Type narrowing via list comprehension with isinstance
            entries_final = [e for e in config.entries if isinstance(e, m.Ldif.Entry)]
            acl_attrs_final = config.acl_attributes or []
            return cls(
                entries=entries_final,
                sort_target=config.target,
                sort_by=strategy,
                traversal=config.traversal,
                custom_predicate=config.predicate,
                sort_attributes=config.sort_attributes,
                attribute_order=config.attribute_order,
                sort_acl=config.sort_acl,
                acl_attributes=acl_attrs_final,
            ).execute()

        # Direct parameter path - all params are properly typed
        entries_list = list(entries) if entries is not None else []
        target_str = target if target is not None else default_target
        by_str = by if by is not None else default_by
        acl_attrs_list = (
            acl_attributes if acl_attributes is not None else default_acl_attrs
        )

        return cls(
            entries=entries_list,
            sort_target=target_str,
            sort_by=by_str,
            traversal=traversal,
            custom_predicate=predicate,
            sort_attributes=sort_attributes,
            attribute_order=attribute_order,
            sort_acl=sort_acl,
            acl_attributes=acl_attrs_list,
        ).execute()

    # PUBLIC CLASSMETHOD HELPERS (Direct Entry Points)

    @classmethod
    def by_hierarchy(
        cls,
        entries: Sequence[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Sort entries by hierarchy (depth-first, then alphabetical).

        Args:
            entries: LDIF entries to sort

        Returns:
            FlextResult with sorted entries (shallowest first)

        Example:
            result = FlextLdifSorting.by_hierarchy(entries)
            sorted_entries = result.value

        """
        sorting_instance = cls(
            entries=list(entries),
            sort_target=c.Ldif.SortTarget.ENTRIES.value,
            sort_by=c.Ldif.SortStrategy.HIERARCHY.value,
        )
        return sorting_instance.execute()

    @classmethod
    def by_dn(
        cls,
        entries: Sequence[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Sort entries alphabetically by full DN.

        Args:
            entries: LDIF entries to sort

        Returns:
            FlextResult with sorted entries (case-insensitive alphabetical)

        Example:
            result = FlextLdifSorting.by_dn(entries)
            sorted_entries = result.value

        """
        sorting_instance = cls(
            entries=list(entries),
            sort_target=c.Ldif.SortTarget.ENTRIES.value,
            sort_by=c.Ldif.SortStrategy.DN.value,
        )
        return sorting_instance.execute()

    @classmethod
    def by_schema(
        cls,
        entries: Sequence[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Sort schema entries by OID (attributeTypes before objectClasses).

        Args:
            entries: Schema entries to sort

        Returns:
            FlextResult with sorted schema entries

        Example:
            result = FlextLdifSorting.by_schema(schema_entries)
            sorted_entries = result.value

        """
        sorting_instance = cls(
            entries=list(entries),
            sort_target=c.Ldif.SortTarget.SCHEMA.value,
            sort_by=c.Ldif.SortStrategy.SCHEMA.value,
        )
        return sorting_instance.execute()

    @classmethod
    def by_custom(
        cls,
        entries: Sequence[m.Ldif.Entry],
        predicate: Callable[[m.Ldif.Entry], str | int | float],
    ) -> r[list[m.Ldif.Entry]]:
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
                lambda e: u.Ldif.DN.get_dn_value(e.dn).count(",")
            )
            sorted_entries = result.value

        """
        sorting_instance = cls(
            entries=list(entries),
            sort_target=c.Ldif.SortTarget.ENTRIES.value,
            sort_by=c.Ldif.SortStrategy.CUSTOM.value,
            custom_predicate=predicate,
        )
        return sorting_instance.execute()

    @classmethod
    def sort_attributes_in_entries(
        cls,
        entries: Sequence[m.Ldif.Entry],
        order: list[str] | None = None,
    ) -> r[list[m.Ldif.Entry]]:
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
            sorted_entries = result.value

        """
        sorting_instance = cls(
            entries=list(entries),
            sort_target=c.Ldif.SortTarget.ATTRIBUTES.value,
            attribute_order=order,
        )
        return sorting_instance.execute()

    @classmethod
    def sort_acl_in_entries(
        cls,
        entries: Sequence[m.Ldif.Entry],
        acl_attrs: list[str] | None = None,
    ) -> r[list[m.Ldif.Entry]]:
        """Sort ACL attribute values within entries.

        Args:
            entries: LDIF entries to process
            acl_attrs: ACL attribute names to sort
                (default: ["acl", "aci", "olcAccess"])

        Returns:
            FlextResult with entries having sorted ACL values

        Example:
            result = FlextLdifSorting.sort_acl_in_entries(entries)
            sorted_entries = result.value

        """
        sorting_instance = cls(
            entries=list(entries),
            sort_target=c.Ldif.SortTarget.ACL.value,
            acl_attributes=acl_attrs if acl_attrs is not None else [],
        )
        return sorting_instance.execute()

    def _sort_entries(self) -> r[list[m.Ldif.Entry]]:
        """Universal entry sorting engine."""
        strategies = {
            c.Ldif.SortStrategy.HIERARCHY.value: self._by_hierarchy,
            c.Ldif.SortStrategy.DN.value: self._by_dn,
            c.Ldif.SortStrategy.ALPHABETICAL.value: self._by_dn,
            c.Ldif.SortStrategy.SCHEMA.value: self._by_schema,
            c.Ldif.SortStrategy.CUSTOM.value: self._by_custom,
        }
        method = strategies.get(self.sort_by)
        if not method:
            return r[list[m.Ldif.Entry]].fail(
                f"Unknown strategy: {self.sort_by}",
            )
        return method()

    def _sort_only_attributes(self) -> r[list[m.Ldif.Entry]]:
        """Sort ONLY attributes (no entry sorting)."""
        return self._sort_attributes_in_entries(self.entries)

    def _sort_only_acl(self) -> r[list[m.Ldif.Entry]]:
        """Sort ONLY ACL attributes (no entry sorting)."""
        return self._sort_acl_in_entries(self.entries)

    def _sort_schema_entries(self) -> r[list[m.Ldif.Entry]]:
        """Sort schema entries by OID (equivalent to _by_schema but explicit)."""
        return self._by_schema()

    def _sort_combined(self) -> r[list[m.Ldif.Entry]]:
        """Sort EVERYTHING: entries + attributes + ACL + schema."""
        # Step 1: Sort entries
        result = self._sort_entries()
        if not result.is_success:
            return result

        # Use map_or for railway pattern
        sorted_entries_raw = result.map_or(None)
        if sorted_entries_raw is None:
            error_msg = (
                result.error
                if hasattr(result, "error") and result.error
                else "Sort failed"
            )
            return r[list[m.Ldif.Entry]].fail(error_msg)
        sorted_entries: list[m.Ldif.Entry] = sorted_entries_raw

        # Step 2: Sort attributes if configured
        if self.sort_attributes or self.attribute_order:
            result = self._sort_attributes_in_entries(sorted_entries)
            if not result.is_success:
                return result
            sorted_entries_attr_raw = result.map_or(None)
            if sorted_entries_attr_raw is None:
                error_msg = (
                    result.error
                    if hasattr(result, "error") and result.error
                    else "Attribute sort failed"
                )
                return r[list[m.Ldif.Entry]].fail(error_msg)
            sorted_entries = sorted_entries_attr_raw

        # Step 3: Sort ACL if configured
        if self.sort_acl:
            result = self._sort_acl_in_entries(sorted_entries)
            if not result.is_success:
                return result
            sorted_entries_raw = result.map_or(None)
            if sorted_entries_raw is None:
                error_msg = (
                    result.error
                    if hasattr(result, "error") and result.error
                    else "ACL sort failed"
                )
                return r[list[m.Ldif.Entry]].fail(error_msg)
            # Type narrowing: unwrap_or(, default=None) on r[list[Entry]] returns list[Entry]
            # Reassign to existing variable instead of redefining
            sorted_entries = sorted_entries_raw

        return r[list[m.Ldif.Entry]].ok(sorted_entries)

    def _sort_attributes_in_entries(
        self,
        entries: list[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Sort attributes in all entries."""

        def sort_entry(
            entry: m.Ldif.Entry,
        ) -> m.Ldif.Entry:
            """Sort entry attributes."""
            if self.attribute_order:
                result = self._sort_entry_attributes_by_order(entry)
            else:
                result = self._sort_entry_attributes_alphabetically(entry)

            # Log on failure and raise
            if result.is_failure:
                self.logger.error(
                    "Failed to sort entry attributes",
                    action_attempted="sort_entry_attributes",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    entry_index=0,  # Index not available in batch context
                    total_entries=u.count(entries),
                    error=str(result.error),
                    error_type=type(result.error).__name__ if result.error else None,
                    attributes_count=u.count(
                        list(entry.attributes.attributes.keys())
                        if entry.attributes
                        else [],
                    ),
                    consequence="Entry attributes were not sorted",
                )
                error_msg = f"Attribute sort failed: {result.error}"
                raise ValueError(error_msg)
            return result.value

        # Direct iteration instead of u.Collection.batch
        processed: list[m.Ldif.Entry] = []
        for entry in entries:
            try:
                result = sort_entry(entry)
                # Handle both direct return and FlextResult return
                if isinstance(result, r):
                    if result.is_success and isinstance(result.value, m.Ldif.Entry):
                        processed.append(result.value)
                    else:
                        return r[list[m.Ldif.Entry]].fail(
                            result.error or "Attribute sort failed",
                        )
                elif isinstance(result, m.Ldif.Entry):
                    processed.append(result)
            except Exception as exc:
                return r[list[m.Ldif.Entry]].fail(f"Attribute sort failed: {exc}")
        return r[list[m.Ldif.Entry]].ok(processed)

    @staticmethod
    def _ensure_metadata_extensions(
        entry: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
        """Ensure entry metadata has extensions initialized.

        Uses Entry Model + Metadata pattern.
        """
        # Use QuirkMetadata.create_for() factory method which handles defaults
        # QuirkMetadata.extensions has default_factory, so it's never None
        if entry.metadata is None:
            return entry.model_copy(
                update={"metadata": m.Ldif.QuirkMetadata.create_for()},
            )
        # Type narrowing: entry.metadata is not None here
        # extensions always has a value due to default_factory
        return entry

    def _track_acl_sorting_metadata(
        self,
        entry: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
        """Track ACL sorting transformation in metadata.

        Uses Entry Model + Metadata pattern.
        """
        new_entry = FlextLdifSorting._ensure_metadata_extensions(entry)
        # After _ensure_metadata_extensions, metadata is guaranteed non-None
        if new_entry.metadata is not None:
            extensions = new_entry.metadata.extensions
            # DynamicMetadata supports __setitem__ for extra fields
            # Use constants directly via c.Ldif.MetadataKeys namespace
            extensions[c.Ldif.MetadataKeys.SORTING_ACL_ATTRIBUTES] = self.acl_attributes
            extensions[c.Ldif.MetadataKeys.SORTING_ACL_SORTED] = True
        return new_entry

    def _sort_acl_in_entries(
        self,
        entries: list[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Sort ACL attributes in all entries."""

        def sort_acl_entry(
            entry: m.Ldif.Entry,
        ) -> m.Ldif.Entry:
            """Sort ACL attributes in entry."""
            if not entry.attributes:
                return entry

            attrs_dict: dict[str, list[str]] = {
                str(k): (
                    [str(v) for v in vals]
                    if isinstance(vals, (list, tuple))
                    else [str(vals)]
                )
                for k, vals in entry.attributes.attributes.items()
            }
            modified = False

            for acl_attr in self.acl_attributes:
                if acl_attr in attrs_dict:
                    acl_values_raw = attrs_dict[acl_attr]
                    acl_values_raw_normalized = (
                        acl_values_raw
                        if isinstance(acl_values_raw, (list, tuple))
                        else [str(acl_values_raw)]
                    )
                    # Type narrowing: ensure acl_values is list[str] for count
                    # Convert all items to str to ensure type safety
                    acl_values: list[str] = [
                        str(item)
                        for item in (
                            acl_values_raw_normalized
                            if isinstance(acl_values_raw_normalized, (list, tuple))
                            else [acl_values_raw_normalized]
                        )
                    ]
                    if u.count(acl_values) > 1:
                        sorted_acl: list[str] = [
                            str(item)
                            for item in sorted(acl_values, key=lambda x: str(x).lower())
                        ]
                        attrs_dict[acl_attr] = sorted_acl
                        modified = True

            if modified:
                sorted_attrs = m.Ldif.Attributes(attributes=attrs_dict)
                new_entry = entry.model_copy(update={"attributes": sorted_attrs})
                return self._track_acl_sorting_metadata(new_entry)
            return entry

        # Use u.batch for unified batch processing (DSL pattern)
        batch_result = u.Collection.batch(
            entries,
            sort_acl_entry,
            on_error="skip",
        )
        if batch_result.is_failure:
            return r[list[m.Ldif.Entry]].fail(
                batch_result.error or "ACL sort failed",
            )
        # Extract results from batch result with explicit type narrowing
        batch_data = batch_result.value
        processed_raw = batch_data.get("results", [])
        # Loop-based narrowing for mypy compatibility (list comp breaks type inference)
        processed: list[m.Ldif.Entry] = [
            item for item in processed_raw if isinstance(item, m.Ldif.Entry)
        ]
        return r[list[m.Ldif.Entry]].ok(processed)

    @staticmethod
    def _build_dn_tree(
        entries: list[m.Ldif.Entry],
    ) -> tuple[dict[str, list[str]], dict[str, list[m.Ldif.Entry]], list[str]]:
        """Build DN tree structure for depth-first traversal.

        Returns:
            Tuple of (parent_to_children, dn_to_entries, root_dns)
            - parent_to_children: Dict mapping parent DN to list of child DNs
            - dn_to_entries: Dict mapping DN to list of Entry objects
                (supports duplicates)
            - root_dns: List of root DNs (depth 1-2)

        """
        parent_to_children: dict[str, list[str]] = {}
        dn_to_entries: dict[str, list[m.Ldif.Entry]] = {}

        # First pass: build dn_to_entries and parent_to_children mappings
        for entry in entries:
            dn_value = str(u.Ldif.DN.get_dn_value(entry.dn)) if entry.dn else ""
            if not dn_value:
                continue

            # Normalize DN for consistent handling
            norm_result = u.Ldif.DN.norm(dn_value)
            normalized_dn = norm_result.map_or(None)
            normalized_result = u.Ldif.normalize_ldif(
                normalized_dn or dn_value,
                case="lower",
            )
            # Type narrowing: when passing str and no `other`, normalize_ldif returns str
            dn_key: str = (
                normalized_result
                if isinstance(normalized_result, str)
                else str(normalized_result)
            )

            # Store entry (append to list to support duplicates)
            if dn_key not in dn_to_entries:
                dn_to_entries[dn_key] = []
            dn_to_entries[dn_key].append(entry)

            # Extract parent DN (everything after first comma)
            if "," in dn_value:
                parent_dn = dn_value.split(",", 1)[1]
                parent_norm_result = u.Ldif.DN.norm(parent_dn)
                parent_normalized: str | None = parent_norm_result.map_or(None)
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
        dn_to_entries: dict[str, list[m.Ldif.Entry]],
        visited: set[str],
    ) -> list[m.Ldif.Entry]:
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
        # Use u.get for unified extraction (DSL pattern)
        # Type narrowing: u.mapper().get with default=[] returns list[str]
        children_raw: list[str] | None = u.mapper().get(
            parent_to_children,
            dn,
            default=[],
        )
        children = children_raw if children_raw is not None else []
        for child_dn in children:
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
        dn_to_entries: dict[str, list[m.Ldif.Entry]],
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
            dn_value = str(u.Ldif.DN.get_dn_value(entry.dn)) if entry.dn else ""

            if "," not in dn_value:
                # True root (no parent)
                root_dns.append(dn_key)
            else:
                # Check if parent exists in entry list
                parent_dn = dn_value.split(",", 1)[1]
                parent_norm_result = u.Ldif.DN.norm(parent_dn)
                parent_normalized: str | None = parent_norm_result.map_or(None)
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
        entries: list[m.Ldif.Entry],
    ) -> list[m.Ldif.Entry]:
        """Level-order traversal (original behavior for backward compatibility).

        Sorts by (depth, normalized_dn) - all depth=1, then all depth=2, etc.
        This is NOT proper depth-first but provided for backward compatibility.

        Args:
            entries: Entries to sort

        Returns:
            List of entries in level-order (grouped by depth)

        """

        def sort_key(entry: m.Ldif.Entry) -> tuple[int, str]:
            dn_value = str(u.Ldif.DN.get_dn_value(entry.dn)) if entry.dn else ""
            if not dn_value:
                return (0, "")

            depth = dn_value.count(",") + 1
            norm_result = u.Ldif.DN.norm(dn_value)
            normalized = norm_result.map_or(None)
            # Type narrowing: when passing str and no `other`, normalize_ldif returns str
            sort_result = u.Ldif.normalize_ldif(normalized or dn_value, case="lower")
            sort_dn: str = (
                sort_result if isinstance(sort_result, str) else str(sort_result)
            )

            return (depth, sort_dn)

        return sorted(entries, key=sort_key)

    def _by_hierarchy(self) -> r[list[m.Ldif.Entry]]:
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

        Uses u.Ldif.DN.norm() for RFC 4514 compliant DN normalization.
        Preserves duplicate DNs (same DN but different attributes).
        """
        if not self.entries:
            return r[list[m.Ldif.Entry]].ok([])

        # Choose traversal strategy based on self.traversal
        if self.traversal == "depth-first":
            # Build DN tree structure
            parent_to_children, dn_to_entries, root_dns = self._build_dn_tree(
                self.entries,
            )

            # DFS traverse from each root
            sorted_entries: list[m.Ldif.Entry] = []
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
                dn_value = str(u.Ldif.DN.get_dn_value(entry.dn)) if entry.dn else ""
                if dn_value:
                    norm_result = u.Ldif.DN.norm(dn_value)
                    normalized = norm_result.map_or(None)
                    normalized_result = u.Ldif.normalize_ldif(
                        normalized or dn_value,
                        case="lower",
                    )
                    # Type narrowing: when passing str and no `other`, normalize_ldif returns str
                    dn_key: str = (
                        normalized_result
                        if isinstance(normalized_result, str)
                        else str(normalized_result)
                    )
                    if dn_key not in visited:
                        # Add all entries with this DN
                        # Use u.get for unified extraction (DSL pattern)
                        # Type narrowing: u.mapper().get with default=[] returns list[m.Ldif.Entry]
                        entries_for_dn_raw: list[m.Ldif.Entry] | None = u.mapper().get(
                            dn_to_entries,
                            dn_key,
                            default=[],
                        )
                        entries_for_dn: list[m.Ldif.Entry] = (
                            entries_for_dn_raw if entries_for_dn_raw is not None else []
                        )
                        sorted_entries.extend(entries_for_dn)
                        visited.add(dn_key)

            return r[list[m.Ldif.Entry]].ok(sorted_entries)

        if self.traversal == "level-order":
            # Use level-order traversal (original behavior)
            sorted_entries = self._levelorder_traverse(self.entries)
            return r[list[m.Ldif.Entry]].ok(sorted_entries)

        # Should never happen due to validator, but handle gracefully
        return r[list[m.Ldif.Entry]].fail(
            f"Unknown traversal mode: {self.traversal}",
        )

    def _by_dn(self) -> r[list[m.Ldif.Entry]]:
        """Sort alphabetically by DN using RFC 4514 normalization.

        Uses u.Ldif.DN.norm() for RFC 4514 compliant DN normalization
        before sorting, ensuring consistent canonical ordering.
        """

        def dn_sort_key(entry: m.Ldif.Entry) -> str:
            dn_value = str(u.Ldif.DN.get_dn_value(entry.dn)) if entry.dn else ""
            if not dn_value:
                return ""

            # Normalize DN using u for RFC 4514 compliance
            norm_result = u.Ldif.DN.norm(dn_value)
            normalized = norm_result.map_or(None)
            # Type narrowing: when passing str and no `other`, normalize_ldif returns str
            result = u.Ldif.normalize_ldif(normalized or dn_value, case="lower")
            return result if isinstance(result, str) else str(result)

        sorted_entries = sorted(self.entries, key=dn_sort_key)
        return r[list[m.Ldif.Entry]].ok(sorted_entries)

    def _by_schema(self) -> r[list[m.Ldif.Entry]]:
        """Sort schema entries by OID."""

        def schema_key(entry: m.Ldif.Entry) -> tuple[int, str]:
            if not entry.attributes:
                # Entries without attributes go to the end
                return (3, u.Ldif.DN.get_dn_value(entry.dn).lower())

            attrs = entry.attributes.attributes

            # Priority: attributetypes (1) before objectclasses (2)
            # Use c.Ldif.SchemaFields constants directly
            if c.Ldif.SchemaFields.ATTRIBUTE_TYPES in attrs:
                priority = 1
                oid_values = attrs[c.Ldif.SchemaFields.ATTRIBUTE_TYPES]
            elif c.Ldif.SchemaFields.OBJECT_CLASSES in attrs:
                priority = 2
                oid_values = attrs[c.Ldif.SchemaFields.OBJECT_CLASSES]
            else:
                return (3, u.Ldif.DN.get_dn_value(entry.dn).lower())

            # Extract OID using u.OID for consistency
            first_val = str(
                oid_values[0] if isinstance(oid_values, (list, tuple)) else oid_values,
            )
            oid = u.Ldif.OID.extract_from_definition(first_val) or first_val

            return (priority, oid)

        sorted_entries = sorted(self.entries, key=schema_key)
        return r[list[m.Ldif.Entry]].ok(sorted_entries)

    def _by_custom(self) -> r[list[m.Ldif.Entry]]:
        """Sort using custom predicate."""
        if self.custom_predicate is None:
            return r[list[m.Ldif.Entry]].fail(
                "Custom predicate not provided",
            )
        sorted_entries = sorted(self.entries, key=self.custom_predicate)
        return r[list[m.Ldif.Entry]].ok(sorted_entries)

    def _sort_entry_attributes_alphabetically(
        self,
        entry: m.Ldif.Entry,
        *,
        case_sensitive: bool = False,
    ) -> r[m.Ldif.Entry]:
        """Sort entry attributes alphabetically using Entry Model + Metadata pattern."""
        if not entry.attributes:
            return r[m.Ldif.Entry].ok(entry)

        attrs_dict = entry.attributes.attributes
        # Sort attributes based on case sensitivity
        sorted_items: list[tuple[str, list[str]]] = (
            sorted(attrs_dict.items(), key=operator.itemgetter(0))
            if case_sensitive
            else sorted(attrs_dict.items(), key=lambda x: x[0].lower())
        )

        original_attr_order = list(attrs_dict.keys())
        sorted_dict: dict[str, list[str]] = dict(sorted_items)
        sorted_attrs = m.Ldif.Attributes(attributes=sorted_dict)
        new_entry = entry.model_copy(update={"attributes": sorted_attrs})

        # Track sorting transformation in metadata if order changed
        # Uses Entry Model + Metadata pattern
        new_attr_order = list(sorted_dict.keys())
        if original_attr_order != new_attr_order:
            # Ensure metadata extensions are initialized
            new_entry = FlextLdifSorting._ensure_metadata_extensions(new_entry)
            # After _ensure_metadata_extensions, metadata is guaranteed non-None
            if new_entry.metadata is not None:
                extensions = new_entry.metadata.extensions
                # Track attribute order transformation in metadata extensions
                # Use constants directly via c.Ldif.MetadataKeys and c.Ldif.SortingStrategyType
                strategy_type = (
                    c.Ldif.SortingStrategyType.ALPHABETICAL_CASE_SENSITIVE
                    if case_sensitive
                    else c.Ldif.SortingStrategyType.ALPHABETICAL_CASE_INSENSITIVE
                )
                # DynamicMetadata supports __setitem__ for extra fields
                extensions[c.Ldif.MetadataKeys.ATTRIBUTE_ORDER] = original_attr_order
                extensions[c.Ldif.MetadataKeys.SORTING_NEW_ATTRIBUTE_ORDER] = (
                    new_attr_order
                )
                extensions[c.Ldif.MetadataKeys.SORTING_STRATEGY] = strategy_type.value

                self.logger.debug(
                    "Sorted entry attributes",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    attributes_count=u.count(original_attr_order),
                )

        return r[m.Ldif.Entry].ok(new_entry)

    def _sort_entry_attributes_by_order(
        self,
        entry: m.Ldif.Entry,
    ) -> r[m.Ldif.Entry]:
        """Sort entry attributes by custom order.

        Uses Entry Model + Metadata pattern.
        """
        if not self.attribute_order:
            return self._sort_entry_attributes_alphabetically(entry)

        if not entry.attributes:
            return r[m.Ldif.Entry].ok(entry)

        attrs_dict = entry.attributes.attributes
        order = self.attribute_order
        original_attr_order = list(attrs_dict.keys())
        # Use named functions for clarity (DSL pattern)

        def key_in_attrs(key: str) -> bool:
            """Check if key exists in attrs_dict."""
            return key in attrs_dict

        def map_to_pair(key: str) -> tuple[str, list[str]]:
            """Map key to (key, value) pair."""
            return (key, attrs_dict[key])

        def key_not_in_order(pair: tuple[str, list[str]]) -> bool:
            """Check if key is not in order."""
            return pair[0] not in order

        # Build ordered pairs directly instead of using Collection.map
        ordered: list[tuple[str, list[str]]] = [
            map_to_pair(key) for key in order if key_in_attrs(key)
        ]
        remaining = sorted(
            [item for item in attrs_dict.items() if key_not_in_order(item)],
            key=lambda x: x[0].lower(),
        )
        sorted_dict = dict(ordered + remaining)
        sorted_attrs = m.Ldif.Attributes(attributes=sorted_dict)
        new_entry = entry.model_copy(update={"attributes": sorted_attrs})

        # Track sorting transformation in metadata if order changed
        # Uses Entry Model + Metadata pattern
        new_attr_order = list(sorted_dict.keys())
        if original_attr_order != new_attr_order:
            # Ensure metadata extensions are initialized
            new_entry = FlextLdifSorting._ensure_metadata_extensions(new_entry)
            # After _ensure_metadata_extensions, metadata is guaranteed non-None
            if new_entry.metadata is not None:
                extensions = new_entry.metadata.extensions
                # Track custom order transformation in metadata extensions
                # Use constants directly via c.Ldif.MetadataKeys and c.Ldif.SortingStrategyType
                ordered_attrs = [k for k, _ in ordered]
                remaining_attrs = [k for k, _ in remaining]
                # DynamicMetadata supports __setitem__ for extra fields
                extensions[c.Ldif.MetadataKeys.ATTRIBUTE_ORDER] = original_attr_order
                extensions[c.Ldif.MetadataKeys.SORTING_NEW_ATTRIBUTE_ORDER] = (
                    new_attr_order
                )
                extensions[c.Ldif.MetadataKeys.SORTING_STRATEGY] = (
                    c.Ldif.SortingStrategyType.CUSTOM_ORDER.value
                )
                extensions[c.Ldif.MetadataKeys.SORTING_CUSTOM_ORDER] = order
                extensions[c.Ldif.MetadataKeys.SORTING_ORDERED_ATTRIBUTES] = (
                    ordered_attrs
                )
                extensions[c.Ldif.MetadataKeys.SORTING_REMAINING_ATTRIBUTES] = (
                    remaining_attrs
                )

                self.logger.debug(
                    "Sorted entry attributes by custom order",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    attributes_count=u.count(original_attr_order),
                    ordered_count=u.count(ordered_attrs),
                    remaining_count=u.count(remaining_attrs),
                )

        return r[m.Ldif.Entry].ok(new_entry)
