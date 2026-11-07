"""Categorization filtering concern: forbidden/OID/base-DN post-filters.

Holds the filtering half of the LDIF categorization service; composition and
rejection tracking live on ``FlextLdifCategorization``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping, MutableSequence

from flext_ldif import c, m, p, r, t, u
from flext_ldif.services import FlextLdifCategorizationRules, FlextLdifFilters


class FlextLdifCategorizationFiltering(FlextLdifCategorizationRules):
    """Forbidden-attribute, whitelist-OID, and base-DN filtering helpers."""

    def _ensure_entry_model(
        self,
        value: t.JsonValue | m.BaseModel | p.Ldif.Entry,
    ) -> p.Ldif.Entry | None:
        if isinstance(value, m.Ldif.Entry):
            return value
        if isinstance(value, m.BaseModel):
            validation_result = u.try_(lambda: u.Ldif.as_entry(value))
            if validation_result.success:
                validated: p.Ldif.Entry = validation_result.value
                return validated
            self.logger.warning(
                "Failed to coerce BaseModel to Entry",
                error=validation_result.error,
                error_type="ValidationError",
            )
            return None
        return None

    @staticmethod
    def _filter_entries_by_base_dn(
        entries: MutableSequence[p.Ldif.Entry],
        base_dn: str,
    ) -> tuple[MutableSequence[p.Ldif.Entry], MutableSequence[p.Ldif.Entry]]:
        """Filter entries by base DN using u.Ldif.

        Returns:
            The resulting ``tuple[MutableSequence[p.Ldif.Entry],
                MutableSequence[p.Ldif.Entry]]``.

        """
        model_entries: MutableSequence[p.Ldif.Entry] = list(entries)
        included: MutableSequence[p.Ldif.Entry] = []
        excluded: MutableSequence[p.Ldif.Entry] = []
        for entry in model_entries:
            dn_str = str(entry.dn) if entry.dn else None
            if dn_str and u.Ldif.under_base(dn_str, base_dn):
                included.append(entry)
            else:
                excluded.append(entry)
        return (included, excluded)

    def _append_rejected_entries(
        self,
        filtered: p.Ldif.FlexibleCategories,
        rejected_entries: MutableSequence[p.Ldif.Entry],
    ) -> None:
        """Append rejected entries into the canonical REJECTED bucket."""
        if not rejected_entries:
            return
        rejected_category = c.Ldif.Category.REJECTED
        existing_rejected_raw: MutableSequence[p.Ldif.Entry] = filtered.get(
            rejected_category,
            [],
        )
        filtered[rejected_category] = [
            entry_model
            for rejected_raw_item in [*existing_rejected_raw, *rejected_entries]
            if (
                entry_model := self._ensure_entry_model(
                    rejected_raw_item,
                )
            )
            is not None
        ]

    def _apply_post_categorization_filters(
        self,
        category_lists: MutableMapping[str, list[p.Ldif.Entry]],
    ) -> None:
        """Apply forbidden attribute/objectClass and schema OID value filters.

        Mutates ``category_lists`` in place. Uses ``forbidden_attributes``,
        ``forbidden_objectclasses``, and ``schema_whitelist_rules`` stored
        during ``__init__``.
        """
        schema_whitelist_rules = self._whitelist_rules_with_oid_filters()
        forbidden_attributes = self.forbidden_attributes or []
        forbidden_objectclasses = self.forbidden_objectclasses or []
        has_attribute_filters = bool(forbidden_attributes or forbidden_objectclasses)
        if schema_whitelist_rules is None and not has_attribute_filters:
            return

        for category, entries in category_lists.items():
            if category == c.Ldif.Category.REJECTED:
                continue
            if not entries:
                continue
            filtered = entries
            if (
                category == c.Ldif.Category.SCHEMA
                and schema_whitelist_rules is not None
            ):
                filtered = [
                    filtered_entry
                    for entry in filtered
                    for filtered_entry in (
                        FlextLdifFilters.filter_schema_attribute_values(
                            entry,
                            schema_whitelist_rules,
                        ),
                    )
                    if not filtered_entry.is_change_record
                    or filtered_entry.change_operations
                ]
            if has_attribute_filters:
                filtered = [
                    FlextLdifFilters.filter_entry_attributes(
                        entry,
                        forbidden_attributes,
                        forbidden_objectclasses,
                    )
                    for entry in filtered
                ]
            category_lists[category] = filtered

    def filter_by_base_dn(
        self,
        categories: p.Ldif.FlexibleCategories,
    ) -> p.Ldif.FlexibleCategories:
        """Filter entries by base DN (if configured).

        Returns:
            The resulting ``m.Ldif.FlexibleCategories``.

        """
        if not self.base_dn:
            return categories
        filtered = m.Ldif.FlexibleCategories()
        for category in c.Ldif.CATEGORY_BUCKET_ORDER:
            filtered[category] = []
        all_excluded_entries: MutableSequence[p.Ldif.Entry] = []
        for category, entries in categories.items():
            if not entries:
                continue
            if category in c.Ldif.CATEGORY_FILTERABLE_BY_BASE_DN:
                entries_list: MutableSequence[p.Ldif.Entry] = [
                    entry_model
                    for entry_raw in entries
                    if (
                        entry_model := self._ensure_entry_model(
                            entry_raw,
                        )
                    )
                    is not None
                ]
                included, excluded = (
                    FlextLdifCategorizationFiltering._filter_entries_by_base_dn(
                        entries_list,
                        self.base_dn,
                    )
                )
                included_updated = self._update_metadata_for_filtered_entries(
                    included,
                    passed=True,
                )
                excluded_updated = self._update_metadata_for_filtered_entries(
                    excluded,
                    passed=False,
                    rejection_reason=f"DN not under base DN: {self.base_dn}",
                )
                filtered[category] = included_updated
                all_excluded_entries.extend(excluded_updated)
                self.rejection_tracker[
                    c.Ldif.RejectionTrackerKey.BASE_DN_FILTER
                ].extend(excluded_updated)
                if excluded_updated:
                    self.logger.info(
                        "Applied base DN filter",
                        category=category,
                        total_entries=u.count(entries),
                        kept_entries=u.count(included_updated),
                        rejected_entries=u.count(excluded_updated),
                    )
            else:
                filtered[category] = [
                    entry_model
                    for entry_raw in entries
                    if (
                        entry_model := self._ensure_entry_model(
                            entry_raw,
                        )
                    )
                    is not None
                ]
        self._append_rejected_entries(
            filtered,
            all_excluded_entries,
        )
        return filtered

    def filter_schema_by_oids(
        self,
        schema_entries: MutableSequence[p.Ldif.Entry],
    ) -> p.Result[MutableSequence[p.Ldif.Entry]]:
        """Filter schema entries by OID whitelist.

        Returns:
            The resulting ``p.Result[MutableSequence[p.Ldif.Entry]]``.

        """
        sw_rules = self._whitelist_rules_with_oid_filters()
        if sw_rules is None:
            return r[MutableSequence[p.Ldif.Entry]].ok(schema_entries)
        result = FlextLdifFilters.filter_schema_by_oids(
            entries=schema_entries,
            allowed_oids=sw_rules,
            logger=self.logger,
        )
        if result.success:
            filtered = result.map_or(None)
            if filtered is not None:
                self.logger.info(
                    "Applied schema OID whitelist filter",
                    total_entries=u.count(schema_entries),
                    filtered_entries=u.count(filtered),
                    removed_entries=u.count(schema_entries) - u.count(filtered),
                )
                return r[MutableSequence[p.Ldif.Entry]].ok(filtered)
        error_msg = result.error or c.Ldif.ERR_FAILED_FILTER_ENTRIES
        return r[MutableSequence[p.Ldif.Entry]].fail(error_msg)

    @staticmethod
    def _update_metadata_for_filtered_entries(
        entries: MutableSequence[p.Ldif.Entry],
        *,
        passed: bool,
        rejection_reason: str | None = None,
    ) -> MutableSequence[p.Ldif.Entry]:
        """Update metadata for filtered entries using u.

        Returns:
            The resulting ``MutableSequence[p.Ldif.Entry]``.

        """
        return [
            u.Ldif.update_entry_statistics(
                entry,
                mark_filtered=(c.Ldif.RejectionCategory.BASE_DN_FILTER.value, passed),
                mark_rejected=(
                    c.Ldif.RejectionCategory.BASE_DN_FILTER.value,
                    rejection_reason,
                )
                if not passed and rejection_reason
                else None,
            )
            for entry in entries
        ]


__all__: list[str] = ["FlextLdifCategorizationFiltering"]
