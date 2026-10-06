"""Categorization Service - LDIF Entry Categorization Operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import struct
from collections.abc import MutableMapping
from typing import Annotated

from flext_ldif import c, m, p, r, s, t, u
from flext_ldif.services.filters import FlextLdifFilters


class FlextLdifCategorization(FlextLdifCategorizationFiltering, s):
    """LDIF Entry Categorization Service."""

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
            category: [] for category in c.Ldif.CATEGORY_BUCKET_ORDER
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
            and self._check_hierarchy_priority(entry, constants)
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
        normalized_entries = u.Ldif.as_entries(entries)

        def validate_entry(entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
            """Validate and normalize entry DN.

            Returns:
                The resulting ``p.Result[m.Ldif.Entry]``.
            """
            dn_str = str(entry.dn) if entry.dn else ""
            if not u.Ldif.validate_dn(dn_str):
                rejected_entry = u.Ldif.update_entry_statistics(
                    entry,
                    mark_rejected=(
                        c.Ldif.RejectionCategory.INVALID_DN.value,
                        f"DN validation failed (RFC 4514): {dn_str[:80]}",
                    ),
                )
                self.rejection_tracker[
                    c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514
                ].append(rejected_entry)
                self.logger.debug(
                    "Entry DN failed RFC 4514 validation",
                    entry_dn=dn_str,
                )
                return r[m.Ldif.Entry].fail_op("DN validation", dn_str[:80])
            norm_result = u.Ldif.norm(dn_str)
            normalized_dn = norm_result.map_or(None)
            if normalized_dn is None:
                rejected_entry = u.Ldif.update_entry_statistics(
                    entry,
                    mark_rejected=(
                        c.Ldif.RejectionCategory.INVALID_DN.value,
                        (
                            f"DN normalization "
                            f"failed: {norm_result.error or c.Ldif.ERR_UNKNOWN}"
                        ),
                    ),
                )
                self.rejection_tracker[
                    c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514
                ].append(rejected_entry)
                return r[m.Ldif.Entry].fail_op(
                    "DN normalization",
                    norm_result.error or c.Ldif.ERR_UNKNOWN,
                )
            dn_obj = m.Ldif.DN(value=normalized_dn)
            return r[m.Ldif.Entry].ok(entry.model_copy(update={"dn": dn_obj}))

        validated: t.MutableSequenceOf[m.Ldif.Entry] = [
            validation_result.value
            for entry in normalized_entries
            if (validation_result := validate_entry(entry)).success
        ]
        self.logger.info(
            "Validated entries",
            validated_count=len(validated),
            rejected_count=len(
                self.rejection_tracker[c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514],
            ),
            rejection_reason=c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514,
        )
        if self.rejection_tracker[c.Ldif.RejectionTrackerKey.INVALID_DN_RFC4514]:
            sample_rejected_dns = [
                entry.dn.value[: c.Ldif.DN_PREVIEW_LENGTH]
                if entry.dn and len(entry.dn.value) > c.Ldif.DN_PREVIEW_LENGTH
                else entry.dn.value
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


__all__: list[str] = ["FlextLdifCategorization"]
