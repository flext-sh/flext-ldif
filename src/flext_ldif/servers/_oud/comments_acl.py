"""OUD entry — Acl comment collectors.

Per AGENTS.md §2.3 (MRO Composition) + §3.1 (200-LOC cap): one of the
domain-specific Mixins composed into ``FlextLdifServersOudCommentsMixin``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, m, t, u
from flext_ldif.servers._oud import (
    FlextLdifServersOudAclExtractMixin,
    FlextLdifServersOudAclMetadataMixin,
)


class FlextLdifServersOudCommentsAclMixin:
    """OUD Acl comment collection helpers (phases 01-03 comment sources)."""

    @staticmethod
    def _add_acl_value_comments(
        comments: t.MutableSequenceOf[str],
        original_attr: str,
        attr_name: str,
        acl_values: t.MutableSequenceOf[str] | str | m.Ldif.Acl,
    ) -> None:
        """Add TRANSFORMED and SKIP_TO_04 comments for ACL values."""
        values = acl_values if isinstance(acl_values, list) else [str(acl_values)]
        for v in values:
            comments.extend([
                f"# [TRANSFORMED] {original_attr}: {v}",
                f"# [SKIP_TO_04] {attr_name}: {v}",
            ])

    @staticmethod
    def _collect_acl_from_extensions(
        entry: m.Ldif.Entry,
        acl_comments_dict: t.MutableStrSequenceMapping,
        acl_attr_names_to_skip: set[str],
    ) -> None:
        """Collect ACL comments from extensions.commented_attribute_values."""
        if not entry.metadata or not entry.metadata.extensions:
            return
        commented_acl_values_raw = entry.metadata.extensions.get(
            c.Ldif.COMMENTED_ATTRIBUTE_VALUES,
        )
        commented_acl_values = (
            FlextLdifServersOudAclExtractMixin.parse_commented_values(
                commented_acl_values_raw,
            )
        )
        if not commented_acl_values:
            return
        original_acl_attr = (
            FlextLdifServersOudAclMetadataMixin.resolve_original_acl_attr(
                entry,
            )
        )
        for acl_attr_name, acl_values_raw in commented_acl_values.items():
            if acl_attr_name.lower() in acl_attr_names_to_skip:
                continue
            acl_attr_names_to_skip.add(acl_attr_name.lower())
            sort_key = original_acl_attr or acl_attr_name
            if sort_key not in acl_comments_dict:
                acl_comments_dict[sort_key] = []
            if isinstance(acl_values_raw, list):
                acl_values: t.MutableSequenceOf[str] = [
                    u.to_str(item) for item in acl_values_raw
                ]
            elif isinstance(acl_values_raw, dict):
                acl_values = [u.to_str(acl_values_raw)]
            else:
                normalized = FlextLdifServersOudAclExtractMixin.normalize_acl_values(
                    acl_values_raw,
                )
                acl_values = (
                    list(normalized)
                    if isinstance(normalized, list)
                    else [u.to_str(normalized)]
                )
            FlextLdifServersOudCommentsAclMixin._add_acl_value_comments(
                acl_comments_dict[sort_key],
                original_acl_attr,
                acl_attr_name,
                acl_values,
            )

    @staticmethod
    def _collect_acl_from_transformations(
        entry: m.Ldif.Entry,
        acl_comments_dict: t.MutableStrSequenceMapping,
        acl_attr_names_to_skip: set[str],
    ) -> None:
        """Collect ACL comments from attribute_transformations with SKIP_TO_04."""
        if not entry.metadata or not entry.metadata.attribute_transformations:
            return
        for (
            attr_name,
            transformation,
        ) in entry.metadata.attribute_transformations.items():
            is_skip_to_04 = (
                transformation.reason and "SKIP_TO_04" in transformation.reason.upper()
            )
            if is_skip_to_04 and attr_name.lower() in c.Ldif.ACL_ATTR_NAMES:
                acl_attr_names_to_skip.add(attr_name.lower())
                if attr_name not in acl_comments_dict:
                    acl_comments_dict[attr_name] = []
                for acl_value in transformation.original_values:
                    acl_comments_dict[attr_name].extend([
                        f"# [REMOVED] {attr_name}: {acl_value}",
                        f"# [SKIP_TO_04] {attr_name}: {acl_value}",
                    ])


__all__: list[str] = ["FlextLdifServersOudCommentsAclMixin"]
