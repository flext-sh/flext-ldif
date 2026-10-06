"""Categorization rules concern: fields, normalization, merging, matching.

Owns the categorization configuration fields and the rule/constant
normalization and entry-matching half of the LDIF categorization service;
``FlextLdifCategorization`` composes it via MRO.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import struct
from collections.abc import MutableMapping

from flext_ldif import c, m, p, s, t, u


class FlextLdifCategorizationRules(s):
    """Categorization configuration fields and rule matching helpers."""

@staticmethod


@staticmethod

def categorize_entries(
    self,
    entries: t.MutableSequenceOf[m.Ldif.Entry],
) -> p.Result[m.Ldif.FlexibleCategories]:
    """Categorize entries into 6 categories.

    Returns:
        The resulting ``p.Result[m.Ldif.FlexibleCategories]``.
    """
    category_lists: MutableMapping[str, list[m.Ldif.Entry]] = {

    }

    for entry in entries:
        category, match_reason = self.categorize_entry(entry)
        is_rejected = category == c.Ldif.Category.REJECTED
        updated_entry = u.Ldif.update_entry_statistics(
            entry,
            category=category,
            mark_rejected=(
                c.Ldif.RejectionCategory.NO_CATEGORY_MATCH.value,
                match_reason
                if match_reason is not None
                else c.Ldif.REJECTION_REASON_NO_CATEGORY_MATCH,
            )
            if is_rejected
            else None,
        )
        category_lists[category].append(updated_entry)
        if is_rejected:
            self.rejection_tracker[
                c.Ldif.RejectionTrackerKey.CATEGORIZATION_REJECTED
            ].append(updated_entry)

    self._apply_post_categorization_filters(category_lists)

    categories = m.Ldif.FlexibleCategories()
    for cat, cat_entries in category_lists.items():
        categories[cat] = cat_entries
        if cat_entries:
            self.logger.info(
                "Category entries",
                category=cat,
                entries_count=len(cat_entries),
            )
    return r[m.Ldif.FlexibleCategories].ok(categories)


def categorize_entry(
    self,
    entry: m.Ldif.Entry,
    rules: m.Ldif.CategoryRules | t.MutableJsonMapping | None = None,
    server_type: str | None = None,
) -> tuple[str, str | None]:
    """Categorize single entry using provided or instance categorization rules.

    Returns:
        The resulting ``tuple[str, str | None]``.
    """
    rules_result = self._normalize_rules(rules)
    normalized_rules = rules_result.map_or(None)
    if normalized_rules is None:
        return (
            c.Ldif.Category.REJECTED,
            rules_result.error or c.Ldif.ERR_FAILED_NORMALIZE_RULES,
        )
    effective_server_type_raw = server_type or self.server_type
    try:
        effective_server_type = u.Ldif.normalize_server_type(
            effective_server_type_raw,
        )
    except c.EXC_TYPE_VALIDATION as e:
        return (
            c.Ldif.Category.REJECTED,
            f"Unknown server type: {effective_server_type_raw} - {e}",
        )
    if self.matches_schema_entry(entry):
        return (c.Ldif.Category.SCHEMA, None)
    merged_category_map = dict(normalized_rules.category_markers)
    constants: type | None = None
    constants_result = self._get_categorization_server_constants(
        effective_server_type,
    )
    if constants_result.success:
        constants_raw = constants_result.map_or(None)
        if constants_raw is not None:
            constants = constants_raw
    elif not merged_category_map:
        return (c.Ldif.Category.REJECTED, constants_result.error)
    if constants is not None:
        self._merge_server_constants_to_map(
            merged_category_map,
            constants,
            override_existing=not bool(rules),
        )
    priority_order = self._get_priority_order_from_constants(constants)
    return (
        (c.Ldif.Category.HIERARCHY, None)
        if constants is not None

        else self._match_entry_to_category(
            entry,
            priority_order,
            merged_category_map,
        )
    )


def validate_dns(
    self,
    entries: t.MutableSequenceOf[m.Ldif.Entry] | m.Ldif.ParseResponse,
) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
    """Validate and normalize all DNs to RFC 4514.

    Returns:
        The resulting ``p.Result[t.MutableSequenceOf[m.Ldif.Entry]]``.
    """

            if entry.dn
            else ""
            for entry in self.rejection_tracker[
                c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514
            ][:5]
        ]
        self.logger.debug(
            "Sample rejected DNs",
            sample_count=len(sample_rejected_dns),
            rejected_dns_preview=", ".join(sample_rejected_dns),
        )
    return r[t.MutableSequenceOf[m.Ldif.Entry]].ok(validated)

@staticmethod


l__: list[str] = ["FlextLdifCategorization"]


__all__: list[str] = ["FlextLdifCategorizationRules"]
