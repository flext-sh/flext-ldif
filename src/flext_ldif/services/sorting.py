"""Sorting Service - LDIF Entry and Attribute Sorting Operations."""

from __future__ import annotations

import operator
import struct
from collections.abc import Callable, MutableMapping, MutableSequence
from typing import Annotated, ClassVar, Self, override

from pydantic import Field, field_validator, model_validator

from flext_ldif import FlextLdifServiceBase, c, m, r, u


class FlextLdifSorting(FlextLdifServiceBase[MutableSequence[m.Ldif.Entry]]):
    """LDIF Sorting Service - Universal Sorting Engine."""

    auto_execute: ClassVar[bool] = False

    @staticmethod
    def _empty_entries() -> MutableSequence[m.Ldif.Entry]:
        return []

    @classmethod
    def builder(cls) -> Self:
        """Create a new sorting service instance for builder pattern."""
        return cls()

    entries: Annotated[MutableSequence[m.Ldif.Entry], Field(default_factory=list)]
    sort_target: Annotated[str, Field()] = "entries"
    sort_by: Annotated[str, Field()] = "hierarchy"
    custom_predicate: Annotated[
        Callable[[m.Ldif.Entry], str | int | float] | None,
        Field(),
    ] = None
    sort_attributes: Annotated[bool, Field()] = False
    attribute_order: Annotated[MutableSequence[str] | None, Field()] = None
    sort_acl: Annotated[bool, Field()] = False
    acl_attributes: Annotated[
        MutableSequence[str],
        Field(default_factory=lambda: list(c.Ldif.DEFAULT_ACL_ATTRIBUTES)),
    ]
    traversal: Annotated[str, Field()] = "depth-first"

    @classmethod
    def by_custom(
        cls,
        entries: MutableSequence[m.Ldif.Entry],
        predicate: Callable[[m.Ldif.Entry], str | int | float],
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort entries using custom predicate function."""
        sorting_instance = cls(
            entries=list(entries),
            sort_target=c.Ldif.SortTarget.ENTRIES.value,
            sort_by=c.Ldif.SortStrategy.CUSTOM.value,
            custom_predicate=predicate,
        )
        return sorting_instance.execute()

    @classmethod
    def by_dn(
        cls,
        entries: MutableSequence[m.Ldif.Entry],
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort entries alphabetically by full DN."""
        sorting_instance = cls(
            entries=list(entries),
            sort_target=c.Ldif.SortTarget.ENTRIES.value,
            sort_by=c.Ldif.SortStrategy.DN.value,
        )
        return sorting_instance.execute()

    @classmethod
    def by_hierarchy(
        cls,
        entries: MutableSequence[m.Ldif.Entry],
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort entries by hierarchy (depth-first, then alphabetical)."""
        sorting_instance = cls(
            entries=list(entries),
            sort_target=c.Ldif.SortTarget.ENTRIES.value,
            sort_by=c.Ldif.SortStrategy.HIERARCHY.value,
        )
        return sorting_instance.execute()

    @classmethod
    def by_schema(
        cls,
        entries: MutableSequence[m.Ldif.Entry],
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort schema entries by OID (attributeTypes before objectClasses)."""
        sorting_instance = cls(
            entries=list(entries),
            sort_target=c.Ldif.SortTarget.SCHEMA.value,
            sort_by=c.Ldif.SortStrategy.SCHEMA.value,
        )
        return sorting_instance.execute()

    @classmethod
    def sort(
        cls,
        config: m.Ldif.SortConfig | None = None,
        entries: MutableSequence[m.Ldif.Entry] | None = None,
        target: str | None = None,
        by: str | None = None,
        traversal: str = "depth-first",
        predicate: Callable[[m.Ldif.Entry], str | int | float] | None = None,
        attribute_order: MutableSequence[str] | None = None,
        acl_attributes: MutableSequence[str] | None = None,
        *,
        sort_attributes: bool = False,
        sort_acl: bool = False,
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort entries with r for composable operations."""
        default_target = c.Ldif.SortTarget.ENTRIES.value
        default_by = c.Ldif.SortStrategy.HIERARCHY.value
        default_acl_attrs = list(c.Ldif.DEFAULT_ACL_ATTRIBUTES)
        if config is not None:
            strategy = config.by
            entries_final = list(config.entries)
            acl_attrs_final = config.acl_attributes or []
            sorting_instance = cls(
                entries=entries_final,
                sort_target=config.target,
                sort_by=strategy,
                traversal=config.traversal,
                sort_attributes=config.sort_attributes,
                attribute_order=config.attribute_order,
                sort_acl=config.sort_acl,
                acl_attributes=acl_attrs_final,
            )
            if config.predicate is not None:
                sorting_instance = sorting_instance.model_copy(
                    update={"custom_predicate": config.predicate},
                )
            return sorting_instance.execute()
        entries_list = list(entries) if entries is not None else []
        target_str = target if target is not None else default_target
        by_str = by if by is not None else default_by
        acl_attrs_list = (
            acl_attributes if acl_attributes is not None else default_acl_attrs
        )
        sorting_instance = cls(
            entries=entries_list,
            sort_target=target_str,
            sort_by=by_str,
            traversal=traversal,
            sort_attributes=sort_attributes,
            attribute_order=attribute_order,
            sort_acl=sort_acl,
            acl_attributes=acl_attrs_list,
        )
        if predicate is not None:
            sorting_instance = sorting_instance.model_copy(
                update={"custom_predicate": predicate},
            )
        return sorting_instance.execute()

    @classmethod
    def sort_acl_in_entries(
        cls,
        entries: MutableSequence[m.Ldif.Entry],
        acl_attrs: MutableSequence[str] | None = None,
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort ACL attribute values within entries."""
        sorting_instance = cls(
            entries=list(entries),
            sort_target=c.Ldif.SortTarget.ACL.value,
            acl_attributes=acl_attrs if acl_attrs is not None else [],
        )
        return sorting_instance.execute()

    @classmethod
    def sort_attributes_in_entries(
        cls,
        entries: MutableSequence[m.Ldif.Entry],
        order: MutableSequence[str] | None = None,
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort attributes within entries."""
        sorting_instance = cls(
            entries=list(entries),
            sort_target=c.Ldif.SortTarget.ATTRIBUTES.value,
            attribute_order=order,
        )
        return sorting_instance.execute()

    @field_validator("sort_by")
    @classmethod
    def validate_sort_strategy(cls, v: str) -> str:
        """Validate sort_by parameter."""
        valid_values = {
            c.Ldif.SortStrategy.HIERARCHY.value,
            c.Ldif.SortStrategy.DN.value,
            c.Ldif.SortStrategy.ALPHABETICAL.value,
            c.Ldif.SortStrategy.SCHEMA.value,
            c.Ldif.SortStrategy.CUSTOM.value,
        }
        if v in valid_values:
            return v
        msg = f"Invalid sort_by: {v!r}. Valid: {', '.join(sorted(valid_values))}"
        raise ValueError(msg)

    @field_validator("sort_target")
    @classmethod
    def validate_sort_target(cls, v: str) -> str:
        """Validate sort_target parameter."""
        valid_values = {
            c.Ldif.SortTarget.ENTRIES.value,
            c.Ldif.SortTarget.ATTRIBUTES.value,
            c.Ldif.SortTarget.ACL.value,
            c.Ldif.SortTarget.SCHEMA.value,
            c.Ldif.SortTarget.COMBINED.value,
        }
        if v in valid_values:
            return v
        msg = f"Invalid sort_target: {v!r}. Valid: {', '.join(sorted(valid_values))}"
        raise ValueError(msg)

    @field_validator("traversal")
    @classmethod
    def validate_traversal(cls, v: str) -> str:
        """Validate traversal parameter."""
        if v not in {"depth-first", "level-order"}:
            msg = f"Invalid traversal: {v!r}"
            raise ValueError(msg)
        return v

    @staticmethod
    def _build_dn_tree(
        entries: MutableSequence[m.Ldif.Entry],
    ) -> tuple[
        MutableMapping[str, MutableSequence[str]],
        MutableMapping[str, MutableSequence[m.Ldif.Entry]],
        MutableSequence[str],
    ]:
        """Build DN tree structure for depth-first traversal."""
        parent_to_children: MutableMapping[str, MutableSequence[str]] = {}
        dn_to_entries: MutableMapping[str, MutableSequence[m.Ldif.Entry]] = {}
        for entry in entries:
            dn_value = FlextLdifSorting._entry_dn_value(entry)
            if not dn_value:
                continue
            dn_key = FlextLdifSorting._normalized_dn_key(dn_value)
            if dn_key not in dn_to_entries:
                dn_to_entries[dn_key] = []
            dn_to_entries[dn_key].append(entry)
            if "," in dn_value:
                parent_dn = dn_value.split(",", 1)[1]
                parent_key = FlextLdifSorting._normalized_parent_dn_key(parent_dn)
                if parent_key not in parent_to_children:
                    parent_to_children[parent_key] = []
                if dn_key not in parent_to_children[parent_key]:
                    parent_to_children[parent_key].append(dn_key)
        for parent_key in parent_to_children:
            parent_to_children[parent_key] = sorted(parent_to_children[parent_key])
        root_dns = FlextLdifSorting._identify_root_dns(dn_to_entries)
        return (parent_to_children, dn_to_entries, root_dns)

    @staticmethod
    def _dfs_traverse(
        dn: str,
        parent_to_children: MutableMapping[str, MutableSequence[str]],
        dn_to_entries: MutableMapping[str, MutableSequence[m.Ldif.Entry]],
        visited: set[str],
    ) -> MutableSequence[m.Ldif.Entry]:
        """Depth-first traversal of DN tree."""
        if dn in visited or dn not in dn_to_entries:
            return []
        visited.add(dn)
        result = list(dn_to_entries[dn])
        children = list(parent_to_children.get(dn, []))
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
    def _ensure_metadata_extensions(entry: m.Ldif.Entry) -> m.Ldif.Entry:
        """Ensure entry metadata has extensions initialized."""
        if entry.metadata is None:
            return entry.model_copy(
                update={"metadata": m.Ldif.QuirkMetadata.create_for()},
            )
        return entry

    @staticmethod
    def _entry_dn_value(entry: m.Ldif.Entry) -> str:
        return str(u.Ldif.get_dn_value(entry.dn)) if entry.dn else ""

    @staticmethod
    def _identify_root_dns(
        dn_to_entries: MutableMapping[str, MutableSequence[m.Ldif.Entry]],
    ) -> MutableSequence[str]:
        """Identify root DNs (entries whose parents are not in the list)."""
        root_dns: MutableSequence[str] = []
        for dn_key, entry_list in dn_to_entries.items():
            entry = entry_list[0]
            dn_value = FlextLdifSorting._entry_dn_value(entry)
            if "," not in dn_value:
                root_dns.append(dn_key)
            else:
                parent_dn = dn_value.split(",", 1)[1]
                parent_key = FlextLdifSorting._normalized_parent_dn_key(parent_dn)
                if parent_key not in dn_to_entries:
                    root_dns.append(dn_key)
        return sorted(root_dns, key=lambda dn_key: (dn_key.count(","), dn_key))

    @staticmethod
    def _levelorder_traverse(
        entries: MutableSequence[m.Ldif.Entry],
    ) -> MutableSequence[m.Ldif.Entry]:

        def sort_key(entry: m.Ldif.Entry) -> tuple[int, str]:
            dn_value = FlextLdifSorting._entry_dn_value(entry)
            if not dn_value:
                return (0, "")
            depth = dn_value.count(",") + 1
            sort_dn = FlextLdifSorting._normalized_dn_key(dn_value)
            return (depth, sort_dn)

        return sorted(entries, key=sort_key)

    @staticmethod
    def _normalized_dn_key(dn_value: str) -> str:
        norm_result = u.Ldif.norm(dn_value)
        normalized = norm_result.map_or(None)
        normalized_result = u.Ldif.normalize_ldif(normalized or dn_value, case="lower")
        if isinstance(normalized_result, str):
            return normalized_result
        return str(normalized_result)

    @staticmethod
    def _normalized_parent_dn_key(parent_dn: str) -> str:
        parent_norm_result = u.Ldif.norm(parent_dn)
        parent_normalized: str | None = parent_norm_result.map_or(None)
        return parent_normalized.lower() if parent_normalized else parent_dn.lower()

    @override
    def execute(self) -> r[MutableSequence[m.Ldif.Entry]]:
        """Execute sorting based on sort_target."""
        if not self.entries:
            return r[MutableSequence[m.Ldif.Entry]].ok([])
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
            else r[MutableSequence[m.Ldif.Entry]].fail(
                f"Unknown sort_target: {self.sort_target}",
            )
        )

    @model_validator(mode="after")
    def validate_custom_predicate(self) -> Self:
        """Validate custom predicate requirements."""
        if self.sort_by == c.Ldif.SortStrategy.CUSTOM.value and (
            not self.custom_predicate
        ):
            msg = "custom_predicate required when sort_by='custom'"
            raise ValueError(msg)
        return self

    def with_attribute_sorting(
        self,
        *,
        alphabetical: bool | None = None,
        order: MutableSequence[str] | None = None,
    ) -> Self:
        """Configure attribute sorting."""
        update_dict: MutableMapping[str, bool | MutableSequence[str] | None] = {}
        if alphabetical is not None:
            update_dict["sort_attributes"] = alphabetical
            update_dict["attribute_order"] = None
        if order is not None:
            update_dict["attribute_order"] = order
            update_dict["sort_attributes"] = False
        return self.model_copy(update=update_dict) if update_dict else self

    def with_entries(self, entries: MutableSequence[m.Ldif.Entry]) -> Self:
        """Set entries to sort."""
        return self.model_copy(update={"entries": entries})

    def with_strategy(self, strategy: str) -> Self:
        """Set sorting strategy."""
        return self.model_copy(update={"sort_by": strategy})

    def with_target(self, target: str) -> Self:
        """Set sorting target (entries, attributes, acl, schema, combined)."""
        return self.model_copy(update={"sort_target": target})

    def _by_custom(self) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort using custom predicate."""
        if self.custom_predicate is None:
            return r[MutableSequence[m.Ldif.Entry]].fail(
                "Custom predicate not provided",
            )
        sorted_entries = sorted(self.entries, key=self.custom_predicate)
        return r[MutableSequence[m.Ldif.Entry]].ok(sorted_entries)

    def _by_dn(self) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort alphabetically by DN using RFC 4514 normalization."""

        def dn_sort_key(entry: m.Ldif.Entry) -> str:
            dn_value = FlextLdifSorting._entry_dn_value(entry)
            if not dn_value:
                return ""
            return FlextLdifSorting._normalized_dn_key(dn_value)

        sorted_entries = sorted(self.entries, key=dn_sort_key)
        return r[MutableSequence[m.Ldif.Entry]].ok(sorted_entries)

    def _by_hierarchy(self) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort by DN hierarchy using configurable traversal strategy."""
        if not self.entries:
            return r[MutableSequence[m.Ldif.Entry]].ok([])
        if self.traversal == "depth-first":
            parent_to_children, dn_to_entries, root_dns = self._build_dn_tree(
                self.entries,
            )
            sorted_entries: MutableSequence[m.Ldif.Entry] = []
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
            for entry in self.entries:
                dn_value = FlextLdifSorting._entry_dn_value(entry)
                if dn_value:
                    dn_key = FlextLdifSorting._normalized_dn_key(dn_value)
                    if dn_key not in visited:
                        entries_raw = dn_to_entries.get(dn_key, [])
                        entries_for_dn = list(entries_raw)
                        sorted_entries.extend(entries_for_dn)
                        visited.add(dn_key)
            return r[MutableSequence[m.Ldif.Entry]].ok(sorted_entries)
        if self.traversal == "level-order":
            sorted_entries = self._levelorder_traverse(self.entries)
            return r[MutableSequence[m.Ldif.Entry]].ok(sorted_entries)
        return r[MutableSequence[m.Ldif.Entry]].fail(
            f"Unknown traversal mode: {self.traversal}",
        )

    def _by_schema(self) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort schema entries by OID."""

        def schema_key(entry: m.Ldif.Entry) -> tuple[int, str]:
            if not entry.attributes:
                dn_value = u.Ldif.get_dn_value(entry.dn) if entry.dn else ""
                return (3, dn_value.lower())
            attrs = entry.attributes.attributes
            if c.Ldif.ATTRIBUTE_TYPES in attrs:
                priority = 1
                oid_values = attrs[c.Ldif.ATTRIBUTE_TYPES]
            elif c.Ldif.OBJECT_CLASSES in attrs:
                priority = 2
                oid_values = attrs[c.Ldif.OBJECT_CLASSES]
            else:
                dn_value = u.Ldif.get_dn_value(entry.dn) if entry.dn else ""
                return (3, dn_value.lower())
            first_val = str(oid_values[0])
            oid_result = u.Ldif.extract_from_definition(first_val)
            oid = oid_result.value if oid_result.is_success else first_val
            return (priority, oid)

        sorted_entries = sorted(self.entries, key=schema_key)
        return r[MutableSequence[m.Ldif.Entry]].ok(sorted_entries)

    def _sort_acl_in_entries(
        self,
        entries: MutableSequence[m.Ldif.Entry],
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort ACL attributes in all entries."""

        def sort_acl_entry(entry: m.Ldif.Entry) -> m.Ldif.Entry:
            """Sort ACL attributes in entry."""
            if not entry.attributes:
                return entry
            attrs_dict: MutableMapping[str, MutableSequence[str]] = {
                str(k): [str(v) for v in vals]
                for k, vals in entry.attributes.attributes.items()
            }
            modified = False
            for acl_attr in self.acl_attributes:
                if acl_attr in attrs_dict:
                    acl_values_raw_normalized = attrs_dict[acl_attr]
                    acl_values: MutableSequence[str] = [
                        str(item) for item in acl_values_raw_normalized
                    ]
                    if u.count(acl_values) > 1:
                        sorted_acl: MutableSequence[str] = [
                            str(item)
                            for item in sorted(acl_values, key=lambda x: str(x).lower())
                        ]
                        attrs_dict[acl_attr] = sorted_acl
                        modified = True
            if modified:
                sorted_attrs = m.Ldif.Attributes.model_validate({
                    "attributes": attrs_dict,
                })
                new_entry = entry.model_copy(update={"attributes": sorted_attrs})
                return self._track_acl_sorting_metadata(new_entry)
            return entry

        processed: MutableSequence[m.Ldif.Entry] = []
        for entry in entries:
            try:
                processed.append(sort_acl_entry(entry))
            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ) as exc:
                return r[MutableSequence[m.Ldif.Entry]].fail(f"ACL sort failed: {exc}")
        return r[MutableSequence[m.Ldif.Entry]].ok(processed)

    def _sort_attributes_in_entries(
        self,
        entries: MutableSequence[m.Ldif.Entry],
    ) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort attributes in all entries."""

        def sort_entry(entry: m.Ldif.Entry) -> m.Ldif.Entry:
            """Sort entry attributes."""
            if self.attribute_order:
                result = self._sort_entry_attributes_by_order(entry)
            else:
                result = self._sort_entry_attributes_alphabetically(entry)
            if result.is_failure:
                entry_dn_value = self._entry_dn_value(entry)
                error_type = "unknown_error"
                if result.error is not None:
                    error_type = result.error.__class__.__name__
                self.logger.error(
                    "Failed to sort entry attributes",
                    action_attempted="sort_entry_attributes",
                    entry_dn=entry_dn_value,
                    entry_index=0,
                    total_entries=u.count(entries),
                    error=str(result.error),
                    error_type=error_type,
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

        processed: MutableSequence[m.Ldif.Entry] = []
        for entry in entries:
            try:
                processed.append(sort_entry(entry))
            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ) as exc:
                return r[MutableSequence[m.Ldif.Entry]].fail(
                    f"Attribute sort failed: {exc}",
                )
        return r[MutableSequence[m.Ldif.Entry]].ok(processed)

    def _sort_combined(self) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort EVERYTHING: entries + attributes + ACL + schema."""
        result = self._sort_entries()
        if not result.is_success:
            return result
        sorted_entries_raw = result.map_or(None)
        if sorted_entries_raw is None:
            error_msg = (
                result.error
                if hasattr(result, "error") and result.error
                else "Sort failed"
            )
            return r[MutableSequence[m.Ldif.Entry]].fail(error_msg)
        sorted_entries: MutableSequence[m.Ldif.Entry] = sorted_entries_raw
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
                return r[MutableSequence[m.Ldif.Entry]].fail(error_msg)
            sorted_entries = sorted_entries_attr_raw
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
                return r[MutableSequence[m.Ldif.Entry]].fail(error_msg)
            sorted_entries = sorted_entries_raw
        return r[MutableSequence[m.Ldif.Entry]].ok(sorted_entries)

    def _sort_entries(self) -> r[MutableSequence[m.Ldif.Entry]]:
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
            return r[MutableSequence[m.Ldif.Entry]].fail(
                f"Unknown strategy: {self.sort_by}",
            )
        return method()

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
        sorted_items: MutableSequence[tuple[str, MutableSequence[str]]] = (
            sorted(attrs_dict.items(), key=operator.itemgetter(0))
            if case_sensitive
            else sorted(attrs_dict.items(), key=lambda x: x[0].lower())
        )
        original_attr_order = list(attrs_dict.keys())
        sorted_dict: MutableMapping[str, MutableSequence[str]] = dict(sorted_items)
        sorted_attrs = m.Ldif.Attributes.model_validate({"attributes": sorted_dict})
        new_entry = entry.model_copy(update={"attributes": sorted_attrs})
        new_attr_order = list(sorted_dict.keys())
        if original_attr_order != new_attr_order:
            new_entry = FlextLdifSorting._ensure_metadata_extensions(new_entry)
            if new_entry.metadata is not None:
                extensions = new_entry.metadata.extensions
                strategy_type = (
                    c.Ldif.SortingStrategyType.ALPHABETICAL_CASE_SENSITIVE
                    if case_sensitive
                    else c.Ldif.SortingStrategyType.ALPHABETICAL_CASE_INSENSITIVE
                )
                extensions[c.Ldif.ATTRIBUTE_ORDER] = [
                    str(item) for item in original_attr_order
                ]
                extensions[c.Ldif.SORTING_NEW_ATTRIBUTE_ORDER] = [
                    str(item) for item in new_attr_order
                ]
                extensions[c.Ldif.SORTING_STRATEGY] = strategy_type.value
                self.logger.debug(
                    "Sorted entry attributes",
                    entry_dn=self._entry_dn_value(entry),
                    attributes_count=u.count(original_attr_order),
                )
        return r[m.Ldif.Entry].ok(new_entry)

    def _sort_entry_attributes_by_order(self, entry: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Sort entry attributes by custom order."""
        if not self.attribute_order:
            return self._sort_entry_attributes_alphabetically(entry)
        if not entry.attributes:
            return r[m.Ldif.Entry].ok(entry)
        attrs_dict = entry.attributes.attributes
        order = self.attribute_order
        original_attr_order = list(attrs_dict.keys())

        def key_in_attrs(key: str) -> bool:
            """Check if key exists in attrs_dict."""
            return key in attrs_dict

        def map_to_pair(key: str) -> tuple[str, MutableSequence[str]]:
            """Map key to (key, value) pair."""
            return (key, attrs_dict[key])

        def key_not_in_order(pair: tuple[str, MutableSequence[str]]) -> bool:
            """Check if key is not in order."""
            return pair[0] not in order

        ordered: MutableSequence[tuple[str, MutableSequence[str]]] = [
            map_to_pair(key) for key in order if key_in_attrs(key)
        ]
        remaining = sorted(
            [item for item in attrs_dict.items() if key_not_in_order(item)],
            key=lambda x: x[0].lower(),
        )
        sorted_dict = dict([*ordered, *remaining])
        sorted_attrs = m.Ldif.Attributes.model_validate({"attributes": sorted_dict})
        new_entry = entry.model_copy(update={"attributes": sorted_attrs})
        new_attr_order = list(sorted_dict.keys())
        if original_attr_order != new_attr_order:
            new_entry = FlextLdifSorting._ensure_metadata_extensions(new_entry)
            if new_entry.metadata is not None:
                extensions = new_entry.metadata.extensions
                ordered_attrs = [k for k, _ in ordered]
                remaining_attrs = [k for k, _ in remaining]
                extensions[c.Ldif.ATTRIBUTE_ORDER] = [
                    str(item) for item in original_attr_order
                ]
                extensions[c.Ldif.SORTING_NEW_ATTRIBUTE_ORDER] = [
                    str(item) for item in new_attr_order
                ]
                extensions[c.Ldif.SORTING_STRATEGY] = (
                    c.Ldif.SortingStrategyType.CUSTOM_ORDER.value
                )
                extensions[c.Ldif.SORTING_CUSTOM_ORDER] = [str(item) for item in order]
                extensions[c.Ldif.SORTING_ORDERED_ATTRIBUTES] = [
                    str(item) for item in ordered_attrs
                ]
                extensions[c.Ldif.SORTING_REMAINING_ATTRIBUTES] = [
                    str(item) for item in remaining_attrs
                ]
                self.logger.debug(
                    "Sorted entry attributes by custom order",
                    entry_dn=self._entry_dn_value(entry),
                    attributes_count=u.count(original_attr_order),
                    ordered_count=u.count(ordered_attrs),
                    remaining_count=u.count(remaining_attrs),
                )
        return r[m.Ldif.Entry].ok(new_entry)

    def _sort_only_acl(self) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort ONLY ACL attributes (no entry sorting)."""
        return self._sort_acl_in_entries(self.entries)

    def _sort_only_attributes(self) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort ONLY attributes (no entry sorting)."""
        return self._sort_attributes_in_entries(self.entries)

    def _sort_schema_entries(self) -> r[MutableSequence[m.Ldif.Entry]]:
        """Sort schema entries by OID (equivalent to _by_schema but explicit)."""
        return self._by_schema()

    def _track_acl_sorting_metadata(self, entry: m.Ldif.Entry) -> m.Ldif.Entry:
        """Track ACL sorting transformation in metadata."""
        new_entry = FlextLdifSorting._ensure_metadata_extensions(entry)
        if new_entry.metadata is not None:
            extensions = new_entry.metadata.extensions
            extensions[c.Ldif.SORTING_ACL_ATTRIBUTES] = [
                str(item) for item in self.acl_attributes
            ]
            extensions[c.Ldif.SORTING_ACL_SORTED] = True
        return new_entry
