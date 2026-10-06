"""OUD entry — Comments helpers.

Per AGENTS.md §2.3 (MRO Composition) + §3.1 (200-LOC cap): one of the
domain-specific Mixins composed into ``FlextLdifServersOudHelpersMixin``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, m, t, u
from flext_ldif.servers._oud.comments_acl import FlextLdifServersOudCommentsAclMixin
from flext_ldif.servers._oud.transform import FlextLdifServersOudTransformMixin


class FlextLdifServersOudCommentsMixin(FlextLdifServersOudCommentsAclMixin):
    """OUD Comments helpers."""

    @staticmethod
    def _add_attribute_transformation_comments(
        comment_lines: t.MutableSequenceOf[str],
        attr_name: str,
        _transformation: m.Ldif.AttributeTransformation,
        comment_type: str,
    ) -> None:
        """Add comment for attribute transformation."""
        comment_lines.append(f"# [{comment_type}] {attr_name}: transformation applied")

    @staticmethod
    def add_original_entry_comments(
        entry_data: m.Ldif.Entry,
        write_options: m.Ldif.WriteFormatOptions | None,
    ) -> t.MutableSequenceOf[str]:
        """Add original entry as commented LDIF block.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        if not (write_options and write_options.write_original_entry_as_comment):
            return []
        if not entry_data.metadata:
            return []
        original_ldif_raw = u.to_str(
            entry_data.metadata.original_strings.get(c.Ldif.ENTRY_ORIGINAL_LDIF),
        )
        if not original_ldif_raw:
            return []
        ldif_parts: t.MutableSequenceOf[str] = []
        ldif_parts.extend([
            "# " + "=" * 70,
            "# ORIGINAL Entry (alternative format) (commented)",
            "# " + "=" * 70,
        ])
        ldif_parts.extend(
            "#" if not line else f"# {line}" for line in original_ldif_raw.splitlines()
        )
        ldif_parts.extend([
            "",
            "# " + "=" * 70,
            "# CONVERTED OUD Entry (active)",
            "# " + "=" * 70,
        ])
        return ldif_parts

    @staticmethod
    def _add_oud_acl_comments(
        comment_lines: t.MutableSequenceOf[str],
        entry: m.Ldif.Entry,
        format_options: m.Ldif.WriteFormatOptions | None = None,
    ) -> set[str]:
        """Add OUD-specific ACL comments for phases 01-03.

        Returns:
            The resulting ``set[str]``.
        """
        acl_attr_names_to_skip: set[str] = set()
        if not entry.metadata:
            return acl_attr_names_to_skip
        acl_comments_dict: t.MutableStrSequenceMapping = {}
        FlextLdifServersOudCommentsMixin._collect_acl_from_transformations(
            entry,
            acl_comments_dict,
            acl_attr_names_to_skip,
        )
        FlextLdifServersOudCommentsMixin._collect_acl_from_extensions(
            entry,
            acl_comments_dict,
            acl_attr_names_to_skip,
        )
        if acl_comments_dict:
            acl_attr_names = list(acl_comments_dict.keys())
            ordered_acl_attrs = (
                FlextLdifServersOudTransformMixin.determine_attribute_order(
                    acl_attr_names,
                    format_options,
                )
            )
            for attr_name in ordered_acl_attrs:
                if attr_name in acl_comments_dict:
                    comment_lines.extend(acl_comments_dict[attr_name])
        return acl_attr_names_to_skip

    @staticmethod
    def _add_rejection_reason_comments(
        comment_lines: t.MutableSequenceOf[str],
        entry: m.Ldif.Entry,
    ) -> None:
        """Add comments with rejection reason if entry was rejected."""
        if (
            entry.metadata
            and entry.metadata.extensions
            and u.matches_type(entry.metadata.extensions, dict)
        ):
            rejection_reason_raw = u.to_str(
                entry.metadata.extensions.get("rejection_reason"),
            )
            if rejection_reason_raw:
                comment_lines.append(f"# [REJECTION] {rejection_reason_raw}")

    @staticmethod
    def _removed_attribute_values(removed_raw: t.JsonValue) -> t.MutableSequenceOf[str]:
        """Render removed-attribute raw metadata as comment values.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        normalized = u.normalize_to_metadata(removed_raw)
        return (
            [u.to_str(v) for v in t.json_list_adapter().validate_python(normalized)]
            if u.matches_type(normalized, list)
            else [u.to_str(normalized)]
        )

    @staticmethod
    def _add_transformation_comments(
        comment_lines: t.MutableSequenceOf[str],
        entry: m.Ldif.Entry,
        format_options: m.Ldif.WriteFormatOptions | None = None,
    ) -> None:
        """Add transformation comments for attribute changes, including OUD-specific ACL
        handling.
        """
        if not entry.metadata:
            return
        acl_attr_names_to_skip = FlextLdifServersOudCommentsMixin._add_oud_acl_comments(
            comment_lines,
            entry,
            format_options,
        )
        processed_attrs = FlextLdifServersOudCommentsMixin._add_attribute_comments(
            comment_lines,
            entry,
            format_options,
            acl_attr_names_to_skip,
        )
        FlextLdifServersOudCommentsMixin._add_removed_attribute_comments(
            comment_lines,
            entry,
            format_options,
            acl_attr_names_to_skip,
            processed_attrs,
        )
        if comment_lines:
            comment_lines.append("")

    @staticmethod
    def _add_attribute_comments(
        comment_lines: t.MutableSequenceOf[str],
        entry: m.Ldif.Entry,
        format_options: m.Ldif.WriteFormatOptions | None,
        acl_attr_names_to_skip: set[str],
    ) -> set[str]:
        """Add transformation comments and return the processed attribute names.

        Returns:
            The resulting ``set[str]``.
        """
        processed_attrs: set[str] = set()
        if not entry.metadata.attribute_transformations:
            return processed_attrs
        attr_names = [
            attr_name
            for attr_name in entry.metadata.attribute_transformations
            if attr_name.lower() not in acl_attr_names_to_skip
        ]
        ordered_attr_names = FlextLdifServersOudTransformMixin.determine_attribute_order(
            attr_names,
            format_options,
        )
        for attr_name in ordered_attr_names:
            transformation = entry.metadata.attribute_transformations[attr_name]
            transformation_type = transformation.transformation_type.upper()
            comment_type = (
                "TRANSFORMED"
                if transformation_type in {"MODIFIED", "TRANSFORMED"}
                else transformation_type
            )
            FlextLdifServersOudCommentsMixin._add_attribute_transformation_comments(
                comment_lines,
                attr_name,
                transformation,
                comment_type,
            )
            processed_attrs.add(attr_name.lower())
        return processed_attrs

    @staticmethod
    def _add_removed_attribute_comments(
        comment_lines: t.MutableSequenceOf[str],
        entry: m.Ldif.Entry,
        format_options: m.Ldif.WriteFormatOptions | None,
        acl_attr_names_to_skip: set[str],
        processed_attrs: set[str],
    ) -> None:
        """Add comments for attributes removed during transformation."""
        if not (
            format_options
            and format_options.write_removed_attributes_as_comments
            and entry.metadata
            and entry.metadata.removed_attributes
        ):
            return
        removed_attrs_dict = entry.metadata.removed_attributes
        removed_attr_names: t.MutableSequenceOf[str] = [
            attr_name
            for attr_name in removed_attrs_dict
            if u.matches_type(attr_name, str)
            and attr_name.lower() not in acl_attr_names_to_skip
        ]
        ordered_removed_attrs = FlextLdifServersOudTransformMixin.determine_attribute_order(
            removed_attr_names,
            format_options,
        )
        for attr_name in ordered_removed_attrs:
            if attr_name.lower() in processed_attrs:
                continue
            removed_values = FlextLdifServersOudCommentsMixin._removed_attribute_values(
                removed_attrs_dict[attr_name],
            )
            comment_lines.extend(
                f"# [REMOVED] {attr_name}: {value}" for value in removed_values
            )


__all__: list[str] = ["FlextLdifServersOudCommentsMixin"]
