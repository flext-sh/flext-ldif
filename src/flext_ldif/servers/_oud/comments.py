"""OUD entry — Comments helpers.

Per AGENTS.md §2.3 (MRO Composition) + §3.1 (200-LOC cap): one of the
domain-specific Mixins composed into ``FlextLdifServersOudHelpersMixin``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import (
    c,
    m,
    t,
    u,
)
from flext_ldif.servers._oud.acl_extract import FlextLdifServersOudAclExtractMixin
from flext_ldif.servers._oud.acl_metadata import FlextLdifServersOudAclMetadataMixin
from flext_ldif.servers._oud.transform import FlextLdifServersOudTransformMixin

logger = u.fetch_logger(__name__)


class FlextLdifServersOudCommentsMixin:
    """OUD Comments helpers."""

    @staticmethod
    def _add_acl_value_comments(
        comments: t.MutableSequenceOf[str],
        original_attr: str,
        attr_name: str,
        acl_values: t.MutableSequenceOf[str] | str | m.Ldif.Acl,
    ) -> None:
        """Add TRANSFORMED and SKIP_TO_04 comments for ACL values."""
        if isinstance(acl_values, list):
            for acl_value in acl_values:
                comments.extend([
                    f"# [TRANSFORMED] {original_attr}: {acl_value}",
                    f"# [SKIP_TO_04] {attr_name}: {acl_value}",
                ])
        else:
            acl_val_str = str(acl_values)
            comments.extend([
                f"# [TRANSFORMED] {original_attr}: {acl_val_str}",
                f"# [SKIP_TO_04] {attr_name}: {acl_val_str}",
            ])

    @staticmethod
    def _add_attribute_transformation_comments(
        comment_lines: t.MutableSequenceOf[str],
        attr_name: str,
        _transformation: m.Ldif.AttributeTransformation,
        comment_type: str,
    ) -> None:
        """Add comment for attribute transformation.

        Args:
            comment_lines: List to append comments to
            attr_name: Name of transformed attribute
            _transformation: Transformation metadata (reserved for future use)
            comment_type: Type of transformation (MODIFIED, TRANSFORMED, etc.)

        """
        comment_lines.append(f"# [{comment_type}] {attr_name}: transformation applied")

    @staticmethod
    def _add_original_entry_comments(
        entry_data: m.Ldif.Entry,
        write_options: m.Ldif.WriteFormatOptions | None,
    ) -> t.MutableSequenceOf[str]:
        """Add original entry as commented LDIF block.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline**:
        - No original entry commenting support
        - Writes only the current entry format

        **OUD Override** (this method):
        - Writes original source entry as commented LDIF block
        - Helps debug migration issues by showing source format
        - Enables auditing of OID → OUD conversions

        Output Format
        -------------

        When enabled, output includes both original and converted entry::

            # ======================================================================
            # ORIGINAL Entry (alternative format) (commented)
            # ======================================================================
            # dn: cn=user, dc=example, dc=com
            # objectclass: person
            # cn: user
            #
            # ======================================================================
            # CONVERTED OUD Entry (active)
            # ======================================================================
            dn: cn=user,dc=example,dc=com
            objectClass: person
            cn: user

        Configuration
        -------------

        Controlled via ``WriteFormatOptions``:
        - ``write_original_entry_as_comment: True`` - Enable original entry comments
        - Original LDIF stored in ``metadata.original_strings["entry_original_ldif"]``

        Args:
            entry_data: Entry with metadata containing original entry
            write_options: Write options with write_original_entry_as_comment flag

        Returns:
            List of LDIF comment lines (empty if feature disabled)

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

        Checks both attribute_transformations and extensions.commented_attribute_values.
        Returns set of ACL attribute names to skip in regular processing.

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
                FlextLdifServersOudTransformMixin._determine_attribute_order(
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
        """Add comments with rejection reason if entry was rejected.

        Args:
            comment_lines: List to append comments to
            entry: Entry model with potential rejection metadata

        """
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
    def _add_transformation_comments(
        comment_lines: t.MutableSequenceOf[str],
        entry: m.Ldif.Entry,
        format_options: m.Ldif.WriteFormatOptions | None = None,
    ) -> None:
        """Add transformation comments for attribute changes, including OUD-specific ACL handling.

        OUD Override of RFC's _add_transformation_comments to handle OID→OUD transformations:
        - [TRANSFORMED] for original ACL values (orclaci)
        - [SKIP TO 04] for new ACL values (aci) in phases 01-03

        Uses generic utilities with hooks/parameters for extensibility.
        Attributes are sorted using the same ordering logic as normal attributes.

        Args:
            comment_lines: List to append comments to
            entry: Entry with transformation metadata
            format_options: Write format options for attribute ordering

        """
        if not entry.metadata:
            return
        acl_attr_names_to_skip = FlextLdifServersOudCommentsMixin._add_oud_acl_comments(
            comment_lines,
            entry,
            format_options,
        )
        processed_attrs: set[str] = set()
        if entry.metadata.attribute_transformations:
            attr_names = [
                attr_name
                for attr_name in entry.metadata.attribute_transformations
                if attr_name.lower() not in acl_attr_names_to_skip
            ]
            ordered_attr_names = (
                FlextLdifServersOudTransformMixin._determine_attribute_order(
                    attr_names,
                    format_options,
                )
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
        if (
            format_options
            and format_options.write_removed_attributes_as_comments
            and entry.metadata.removed_attributes
        ):
            removed_attrs_dict = entry.metadata.removed_attributes.to_dict()
            removed_attr_names: t.MutableSequenceOf[str] = [
                attr_name
                for attr_name in removed_attrs_dict
                if u.matches_type(attr_name, str)
                and attr_name.lower() not in acl_attr_names_to_skip
            ]
            ordered_removed_attrs = (
                FlextLdifServersOudTransformMixin._determine_attribute_order(
                    removed_attr_names,
                    format_options,
                )
            )
            for attr_name in ordered_removed_attrs:
                if attr_name.lower() in processed_attrs:
                    continue
                removed_values_raw = removed_attrs_dict[attr_name]
                normalized_removed_values = u.normalize_to_metadata(
                    removed_values_raw,
                )
                if u.matches_type(normalized_removed_values, list):
                    removed_values = [
                        u.to_str(value)
                        for value in t.json_list_adapter().validate_python(
                            normalized_removed_values,
                        )
                    ]
                else:
                    removed_values = [u.to_str(normalized_removed_values)]
                comment_lines.extend(
                    f"# [REMOVED] {attr_name}: {value}" for value in removed_values
                )
        if comment_lines:
            comment_lines.append("")

    @staticmethod
    def _collect_acl_from_extensions(
        entry: m.Ldif.Entry,
        acl_comments_dict: t.MutableStrSequenceMapping,
        acl_attr_names_to_skip: set[str],
    ) -> None:
        """Collect ACL comments from extensions.commented_attribute_values."""
        if not entry.metadata or not entry.metadata.extensions:
            return
        commented_acl_values_raw = entry.metadata.extensions.to_dict().get(
            c.Ldif.COMMENTED_ATTRIBUTE_VALUES,
        )
        commented_acl_values = FlextLdifServersOudAclExtractMixin._parse_commented_values(
            commented_acl_values_raw
        )
        if not commented_acl_values:
            return
        original_acl_attr = FlextLdifServersOudAclMetadataMixin._get_original_acl_attr(
            entry
        )
        for acl_attr_name, acl_values_raw in commented_acl_values.items():
            if acl_attr_name.lower() in acl_attr_names_to_skip:
                continue
            acl_attr_names_to_skip.add(acl_attr_name.lower())
            sort_key = original_acl_attr or acl_attr_name
            if sort_key not in acl_comments_dict:
                acl_comments_dict[sort_key] = []
            acl_values: t.MutableSequenceOf[str]
            if isinstance(acl_values_raw, list):
                acl_values = [u.to_str(item) for item in acl_values_raw]
            elif isinstance(acl_values_raw, dict):
                acl_values = [u.to_str(acl_values_raw)]
            else:
                normalized_acl_values = (
                    FlextLdifServersOudAclExtractMixin._normalize_acl_values(
                        acl_values_raw
                    )
                )
                if isinstance(normalized_acl_values, list):
                    acl_values = list(normalized_acl_values)
                else:
                    acl_values = [u.to_str(normalized_acl_values)]
            FlextLdifServersOudCommentsMixin._add_acl_value_comments(
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
        acl_attr_set = {"aci", "orclaci", "orclentrylevelaci"}
        for (
            attr_name,
            transformation,
        ) in entry.metadata.attribute_transformations.items():
            is_skip_to_04 = (
                transformation.reason and "SKIP_TO_04" in transformation.reason.upper()
            )
            if is_skip_to_04 and attr_name.lower() in acl_attr_set:
                acl_attr_names_to_skip.add(attr_name.lower())
                if attr_name not in acl_comments_dict:
                    acl_comments_dict[attr_name] = []
                for acl_value in transformation.original_values:
                    acl_comments_dict[attr_name].extend([
                        f"# [REMOVED] {attr_name}: {acl_value}",
                        f"# [SKIP_TO_04] {attr_name}: {acl_value}",
                    ])


__all__: list[str] = ["FlextLdifServersOudCommentsMixin"]
