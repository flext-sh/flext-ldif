"""Sorting Service - LDIF Entry and Attribute Sorting Operations."""

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
    """LDIF Sorting Service - Universal Sorting Engine."""

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
        return self.model_copy(update={"entries": entries})

    def with_strategy(
        self,
        strategy: str,
    ) -> Self:
        """Set sorting strategy."""
        return self.model_copy(update={"sort_by": strategy})

    def with_attribute_sorting(
        self,
        *,
        alphabetical: bool | None = None,
        order: list[str] | None = None,
    ) -> Self:
        """Configure attribute sorting."""
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
        return self.model_copy(update={"sort_target": target})

    @field_validator("sort_target")
    @classmethod
    def validate_sort_target(
        cls,
        v: str,
    ) -> str:
        """Validate sort_target parameter."""
        valid_values = {
            c.Ldif.SortTarget.ENTRIES.value,
            c.Ldif.SortTarget.ATTRIBUTES.value,
            c.Ldif.SortTarget.ACL.value,
            c.Ldif.SortTarget.SCHEMA.value,
            c.Ldif.SortTarget.COMBINED.value,
        }
        if isinstance(v, str) and v in valid_values:
            return v
        msg = f"Invalid sort_target: {v!r}. Valid: {', '.join(sorted(valid_values))}"
        raise ValueError(msg)

    @field_validator("sort_by")
    @classmethod
    def validate_sort_strategy(
        cls,
        v: str,
    ) -> str:
        """Validate sort_by parameter."""
        valid_values = {
            c.Ldif.SortStrategy.HIERARCHY.value,
            c.Ldif.SortStrategy.DN.value,
            c.Ldif.SortStrategy.ALPHABETICAL.value,
            c.Ldif.SortStrategy.SCHEMA.value,
            c.Ldif.SortStrategy.CUSTOM.value,
        }
        if isinstance(v, str) and v in valid_values:
            return v
        msg = f"Invalid sort_by: {v!r}. Valid: {', '.join(sorted(valid_values))}"
        raise ValueError(msg)

    @field_validator("traversal")
    @classmethod
    def validate_traversal(cls, v: str) -> str:
        """Validate traversal parameter."""
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
        """Execute sorting based on sort_target."""
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
        """Sort entries with FlextResult for composable operations."""
        default_target = c.Ldif.SortTarget.ENTRIES.value
        default_by = c.Ldif.SortStrategy.HIERARCHY.value
        default_acl_attrs = list(c.Ldif.AclAttributes.DEFAULT_ACL_ATTRIBUTES)

        if config is not None:
            strategy = config.by if isinstance(config.by, str) else str(config.by)

            entries_final = [e for e in config.entries if isinstance(e, m.Ldif.Entry)]
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
                    update={"custom_predicate": config.predicate}
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
                update={"custom_predicate": predicate}
            )
        return sorting_instance.execute()

    @classmethod
    def by_hierarchy(
        cls,
        entries: Sequence[m.Ldif.Entry],
    ) -> r[list[m.Ldif.Entry]]:
        """Sort entries by hierarchy (depth-first, then alphabetical)."""
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
        """Sort entries alphabetically by full DN."""
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
        """Sort schema entries by OID (attributeTypes before objectClasses)."""
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
        """Sort entries using custom predicate function."""
        sorting_instance = cls(
            entries=list(entries),
            sort_target=c.Ldif.SortTarget.ENTRIES.value,
            sort_by=c.Ldif.SortStrategy.CUSTOM.value,
        )
        sorting_instance = sorting_instance.model_copy(
            update={"custom_predicate": predicate}
        )
        return sorting_instance.execute()

    @classmethod
    def sort_attributes_in_entries(
        cls,
        entries: Sequence[m.Ldif.Entry],
        order: list[str] | None = None,
    ) -> r[list[m.Ldif.Entry]]:
        """Sort attributes within entries."""
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
        """Sort ACL attribute values within entries."""
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
            return r[list[m.Ldif.Entry]].fail(error_msg)
        sorted_entries: list[m.Ldif.Entry] = sorted_entries_raw

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

            if result.is_failure:
                self.logger.error(
                    "Failed to sort entry attributes",
                    action_attempted="sort_entry_attributes",
                    entry_dn=str(entry.dn) if entry.dn else None,
                    entry_index=0,
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

        processed: list[m.Ldif.Entry] = []
        for entry in entries:
            try:
                result = sort_entry(entry)

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
        """Ensure entry metadata has extensions initialized."""
        if entry.metadata is None:
            return entry.model_copy(
                update={"metadata": m.Ldif.QuirkMetadata.create_for()},
            )

        return entry

    def _track_acl_sorting_metadata(
        self,
        entry: m.Ldif.Entry,
    ) -> m.Ldif.Entry:
        """Track ACL sorting transformation in metadata."""
        new_entry = FlextLdifSorting._ensure_metadata_extensions(entry)

        if new_entry.metadata is not None:
            extensions = new_entry.metadata.extensions

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

        batch_result = u.Collection.batch(
            entries,
            sort_acl_entry,
            on_error="skip",
        )
        if batch_result.is_failure:
            return r[list[m.Ldif.Entry]].fail(
                batch_result.error or "ACL sort failed",
            )

        batch_data = batch_result.value
        if isinstance(batch_data, dict):
            processed_raw_value = u.take(batch_data, "results", default=[])
            processed_raw = (
                processed_raw_value if isinstance(processed_raw_value, list) else []
            )
        else:
            processed_raw = batch_data.results

        processed: list[m.Ldif.Entry] = [
            item for item in processed_raw if isinstance(item, m.Ldif.Entry)
        ]
        return r[list[m.Ldif.Entry]].ok(processed)

    @staticmethod
    def _build_dn_tree(
        entries: list[m.Ldif.Entry],
    ) -> tuple[dict[str, list[str]], dict[str, list[m.Ldif.Entry]], list[str]]:
        """Build DN tree structure for depth-first traversal."""
        parent_to_children: dict[str, list[str]] = {}
        dn_to_entries: dict[str, list[m.Ldif.Entry]] = {}

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

        for children in parent_to_children.values():
            children.sort()

        root_dns = FlextLdifSorting._identify_root_dns(dn_to_entries)

        return parent_to_children, dn_to_entries, root_dns

    @staticmethod
    def _dfs_traverse(
        dn: str,
        parent_to_children: dict[str, list[str]],
        dn_to_entries: dict[str, list[m.Ldif.Entry]],
        visited: set[str],
    ) -> list[m.Ldif.Entry]:
        """Depth-first traversal of DN tree."""
        if dn in visited or dn not in dn_to_entries:
            return []

        visited.add(dn)

        result = list(dn_to_entries[dn])

        children_raw = u.mapper().get(
            parent_to_children,
            dn,
            default=[],
        )
        children: list[str] = []
        if isinstance(children_raw, Sequence) and not isinstance(children_raw, str):
            children.extend(item for item in children_raw if isinstance(item, str))
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
        """Identify root DNs (entries whose parents are not in the list)."""
        root_dns: list[str] = []

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

        root_dns.sort(key=lambda dn_key: (dn_key.count(","), dn_key))

        return root_dns

    @staticmethod
    def _levelorder_traverse(
        entries: list[m.Ldif.Entry],
    ) -> list[m.Ldif.Entry]:
        """Level-order traversal (original behavior for backward compatibility)."""

        def sort_key(entry: m.Ldif.Entry) -> tuple[int, str]:
            dn_value = FlextLdifSorting._entry_dn_value(entry)
            if not dn_value:
                return (0, "")

            depth = dn_value.count(",") + 1
            sort_dn = FlextLdifSorting._normalized_dn_key(dn_value)

            return (depth, sort_dn)

        return sorted(entries, key=sort_key)

    def _by_hierarchy(self) -> r[list[m.Ldif.Entry]]:
        """Sort by DN hierarchy using configurable traversal strategy."""
        if not self.entries:
            return r[list[m.Ldif.Entry]].ok([])

        if self.traversal == "depth-first":
            parent_to_children, dn_to_entries, root_dns = self._build_dn_tree(
                self.entries,
            )

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

            for entry in self.entries:
                dn_value = FlextLdifSorting._entry_dn_value(entry)
                if dn_value:
                    dn_key = FlextLdifSorting._normalized_dn_key(dn_value)
                    if dn_key not in visited:
                        entries_raw = u.mapper().get(
                            dn_to_entries,
                            dn_key,
                            default=[],
                        )

                        entries_for_dn: list[m.Ldif.Entry] = []
                        if isinstance(entries_raw, Sequence) and not isinstance(
                            entries_raw, str
                        ):
                            entries_for_dn.extend(
                                item
                                for item in entries_raw
                                if isinstance(item, m.Ldif.Entry)
                            )
                        sorted_entries.extend(entries_for_dn)
                        visited.add(dn_key)

            return r[list[m.Ldif.Entry]].ok(sorted_entries)

        if self.traversal == "level-order":
            sorted_entries = self._levelorder_traverse(self.entries)
            return r[list[m.Ldif.Entry]].ok(sorted_entries)

        return r[list[m.Ldif.Entry]].fail(
            f"Unknown traversal mode: {self.traversal}",
        )

    def _by_dn(self) -> r[list[m.Ldif.Entry]]:
        """Sort alphabetically by DN using RFC 4514 normalization."""

        def dn_sort_key(entry: m.Ldif.Entry) -> str:
            dn_value = FlextLdifSorting._entry_dn_value(entry)
            if not dn_value:
                return ""
            return FlextLdifSorting._normalized_dn_key(dn_value)

        sorted_entries = sorted(self.entries, key=dn_sort_key)
        return r[list[m.Ldif.Entry]].ok(sorted_entries)

    @staticmethod
    def _entry_dn_value(entry: m.Ldif.Entry) -> str:
        return str(u.Ldif.DN.get_dn_value(entry.dn)) if entry.dn else ""

    @staticmethod
    def _normalized_dn_key(dn_value: str) -> str:
        norm_result = u.Ldif.DN.norm(dn_value)
        normalized = norm_result.map_or(None)
        normalized_result = u.Ldif.normalize_ldif(normalized or dn_value, case="lower")
        return (
            normalized_result
            if isinstance(normalized_result, str)
            else str(normalized_result)
        )

    @staticmethod
    def _normalized_parent_dn_key(parent_dn: str) -> str:
        parent_norm_result = u.Ldif.DN.norm(parent_dn)
        parent_normalized: str | None = parent_norm_result.map_or(None)
        return parent_normalized.lower() if parent_normalized else parent_dn.lower()

    def _by_schema(self) -> r[list[m.Ldif.Entry]]:
        """Sort schema entries by OID."""

        def schema_key(entry: m.Ldif.Entry) -> tuple[int, str]:
            if not entry.attributes:
                return (3, u.Ldif.DN.get_dn_value(entry.dn).lower())

            attrs = entry.attributes.attributes

            if c.Ldif.SchemaFields.ATTRIBUTE_TYPES in attrs:
                priority = 1
                oid_values = attrs[c.Ldif.SchemaFields.ATTRIBUTE_TYPES]
            elif c.Ldif.SchemaFields.OBJECT_CLASSES in attrs:
                priority = 2
                oid_values = attrs[c.Ldif.SchemaFields.OBJECT_CLASSES]
            else:
                return (3, u.Ldif.DN.get_dn_value(entry.dn).lower())

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

        sorted_items: list[tuple[str, list[str]]] = (
            sorted(attrs_dict.items(), key=operator.itemgetter(0))
            if case_sensitive
            else sorted(attrs_dict.items(), key=lambda x: x[0].lower())
        )

        original_attr_order = list(attrs_dict.keys())
        sorted_dict: dict[str, list[str]] = dict(sorted_items)
        sorted_attrs = m.Ldif.Attributes(attributes=sorted_dict)
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

        def map_to_pair(key: str) -> tuple[str, list[str]]:
            """Map key to (key, value) pair."""
            return (key, attrs_dict[key])

        def key_not_in_order(pair: tuple[str, list[str]]) -> bool:
            """Check if key is not in order."""
            return pair[0] not in order

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

        new_attr_order = list(sorted_dict.keys())
        if original_attr_order != new_attr_order:
            new_entry = FlextLdifSorting._ensure_metadata_extensions(new_entry)

            if new_entry.metadata is not None:
                extensions = new_entry.metadata.extensions

                ordered_attrs = [k for k, _ in ordered]
                remaining_attrs = [k for k, _ in remaining]

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
