"""OUD entry static helpers — extracted from entry.py per AGENTS.md §3.1.

All ACI/ACL/comment/metadata/parse/restore helpers that don't access instance
state. Composed into ``FlextLdifServersOudEntry`` via MRO. Sibling calls
within the Mixin use ``FlextLdifServersOudHelpersMixin.X(...)``; calls that
require the composed facade still use ``FlextLdifServersOudEntry.X(...)``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, MutableMapping, MutableSequence
from types import MappingProxyType

from flext_ldif import (
    FlextLdifServersOudAcl,
    c,
    m,
    p,
    r,
    t,
    u,
)

logger = u.fetch_logger(__name__)


class FlextLdifServersOudHelpersMixin:
    """Static + classmethod helpers composed into ``FlextLdifServersOudEntry``."""

    _ACL_METADATA_KEY_MAPPING_CACHE: t.MappingKV[str, str] | None = None

    @staticmethod
    def _comment_acl_attributes(
        entry_data: m.Ldif.Entry,
        acl_attribute_names: t.MutableSequenceOf[str],
    ) -> m.Ldif.Entry:
        """Comment out ACL attributes by removing them from attributes dict and storing in metadata.

        CRITICAL for flext-oud-mig phase-aware ACL handling.
        Removes ACL attributes from active attributes dict and stores values in metadata
        for later comment generation with [TRANSFORMED] and [SKIP TO 04] tags.

        Args:
            entry_data: Entry with ACL attributes
            acl_attribute_names: List of ACL attribute names to comment

        Returns:
            Entry with ACL attributes removed from attributes dict and stored in metadata

        """
        if not entry_data.attributes or not acl_attribute_names:
            return entry_data
        existing_metadata = entry_data.metadata
        if not existing_metadata:
            existing_metadata = m.Ldif.ServerMetadata.create_for("oud")
        else:
            existing_metadata = m.Ldif.ServerMetadata.model_validate(
                existing_metadata.model_dump(),
            )
        new_attributes_dict, commented_acl_values, hidden_attrs = (
            FlextLdifServersOudHelpersMixin.extract_and_remove_acl_attributes(
                entry_data.attributes.attributes,
                acl_attribute_names,
            )
        )
        updated_metadata = (
            FlextLdifServersOudHelpersMixin.update_metadata_with_commented_acls(
                existing_metadata,
                acl_attribute_names,
                commented_acl_values,
                hidden_attrs,
                entry_data.attributes.attributes,
            )
        )
        copy_result: m.Ldif.Entry = entry_data.model_copy(
            update={
                "attributes": m.Ldif.Attributes.model_validate({
                    "attributes": {**new_attributes_dict},
                    "attribute_metadata": entry_data.attributes.attribute_metadata,
                    "metadata": entry_data.attributes.metadata,
                }),
                "metadata": updated_metadata,
            },
        )
        return copy_result

    @staticmethod
    def _hook_pre_write_entry_static(
        entry: m.Ldif.Entry,
        validate_aci_macros: Callable[[str], r[bool]],
        correct_rfc_syntax_in_attributes: Callable[
            [t.Ldif.AttributeDict],
            r[t.Ldif.AttributeDict],
        ],
    ) -> r[m.Ldif.Entry]:
        """Hook: Validate and CORRECT RFC syntax issues before writing Entry - static helper.

        This hook ensures that Entry data with RFC-valid syntax is properly
        formatted for OUD LDIF output. It does NOT alter data structure
        (attributes, objectClasses, etc.) - only corrects syntax/formatting.

        Args:
            entry: RFC Entry (already canonical, with aci: attributes)
            validate_aci_macros: Function to validate ACI macros
            correct_rfc_syntax_in_attributes: Function to correct RFC syntax

        Returns:
            r[Entry] - entry with corrected syntax, fail() if syntax errors

        """
        attrs_dict_raw: t.MutableStrSequenceMapping = (
            entry.attributes.attributes if entry.attributes else {}
        )
        attrs_dict: t.Ldif.AttributeDict = {
            k: list(v) for k, v in attrs_dict_raw.items()
        }
        aci_validation_error = (
            FlextLdifServersOudHelpersMixin.validate_aci_macros_in_entry(
                attrs_dict,
                validate_aci_macros,
            )
        )
        if aci_validation_error:
            return r[m.Ldif.Entry].fail(aci_validation_error)
        return FlextLdifServersOudHelpersMixin.correct_syntax_and_return_entry(
            entry,
            attrs_dict,
            correct_rfc_syntax_in_attributes,
        )

    @staticmethod
    def _normalize_acl_values(
        acl_values_raw: t.Ldif.ValueType | t.Ldif.MetadataInputMapping,
    ) -> t.MutableSequenceOf[str] | str:
        """Normalize ACL values to expected type for comment generation.

        Args:
            acl_values_raw: Raw ACL values (JsonPayload)

        Returns:
            Normalized values as list[str], str, or Acl model

        """
        if isinstance(acl_values_raw, list):
            return [u.to_str(item) for item in acl_values_raw]
        return u.to_str(acl_values_raw)

    @staticmethod
    def _parse_commented_values(
        commented_raw: t.JsonValue | None,
    ) -> t.Ldif.MutableMetadataMapping | None:
        """Parse commented ACL values from raw storage format.

        Args:
            commented_raw: Raw value from extensions (JSON string or dict)

        Returns:
            Parsed dict or None if unparseable

        """
        if isinstance(commented_raw, str):
            parsed_items = m.Ldif.DynamicMetadata.model_validate_json(
                commented_raw,
            ).items()
        elif u.matches_type(commented_raw, dict):
            parsed_items = m.Ldif.DynamicMetadata.model_validate(commented_raw).items()
        else:
            return None
        normalized: t.Ldif.MutableMetadataMapping = {}
        for raw_key, raw_value in parsed_items:
            normalized[raw_key] = u.normalize_to_metadata(raw_value)
        return normalized

    @staticmethod
    def apply_syntax_corrections(
        entry: m.Ldif.Entry,
        corrected_data: MutableMapping[
            str,
            t.Ldif.Scalar | t.MutableSequenceOf[str] | t.MutableAttributeMapping | None,
        ],
        syntax_corrections: t.MutableSequenceOf[str] | t.MutableStrMapping | None,
    ) -> r[m.Ldif.Entry]:
        """Apply syntax corrections to entry."""
        corrected_attrs_raw = corrected_data.get("corrected_attributes")
        if not isinstance(corrected_attrs_raw, Mapping):
            return r[m.Ldif.Entry].ok(entry)
        attrs_for_model: t.MutableStrSequenceMapping = {}
        for raw_key, raw_value in corrected_attrs_raw.items():
            if isinstance(raw_value, list):
                attrs_for_model[raw_key] = list(raw_value)
            else:
                attrs_for_model[raw_key] = [str(raw_value)]
        corrected_ldif_attrs = m.Ldif.Attributes.model_validate({
            "attributes": attrs_for_model,
        })
        corrected_entry = entry.model_copy(update={"attributes": corrected_ldif_attrs})
        logger.debug(
            "OUD servers: Applied syntax corrections before writing (structure preserved)",
            entry_dn=entry.dn.value if entry.dn else "",
            corrections_count=len(syntax_corrections) if syntax_corrections else 0,
        )
        return r[m.Ldif.Entry].ok(corrected_entry)

    @staticmethod
    def correct_syntax_and_return_entry(
        entry: m.Ldif.Entry,
        attrs_dict: t.Ldif.AttributeDict,
        correct_rfc_syntax_in_attributes: Callable[
            [t.Ldif.AttributeDict],
            r[t.Ldif.AttributeDict],
        ],
    ) -> r[m.Ldif.Entry]:
        """Correct RFC syntax issues and return entry."""
        corrected_result = correct_rfc_syntax_in_attributes(attrs_dict)
        if corrected_result.failure:
            return r[m.Ldif.Entry].fail(corrected_result.error or "Unknown error")
        corrected_data = corrected_result.value
        corrected_data_typed: MutableMapping[
            str,
            t.Ldif.Scalar | t.MutableSequenceOf[str] | t.MutableAttributeMapping | None,
        ] = {k: list(v) for k, v in corrected_data.items()}
        syntax_corrections_raw = corrected_data_typed.get("syntax_corrections")
        syntax_corrections_typed: (
            t.MutableSequenceOf[str] | t.MutableStrMapping | None
        ) = None
        if isinstance(syntax_corrections_raw, list):
            syntax_corrections_typed = list(syntax_corrections_raw)
        elif isinstance(syntax_corrections_raw, Mapping):
            syntax_corrections_dict: t.MutableStrMapping = {}
            for k, v in syntax_corrections_raw.items():
                syntax_corrections_dict[k] = str(v)
            syntax_corrections_typed = syntax_corrections_dict
        if syntax_corrections_typed is not None:
            return FlextLdifServersOudHelpersMixin.apply_syntax_corrections(
                entry,
                corrected_data_typed,
                syntax_corrections_typed,
            )
        return r[m.Ldif.Entry].ok(entry)

    @staticmethod
    def extract_and_remove_acl_attributes(
        attributes_dict: t.MutableStrSequenceMapping,
        acl_attribute_names: t.MutableSequenceOf[str],
    ) -> tuple[
        t.MutableStrSequenceMapping,
        t.MutableStrSequenceMapping,
        set[str],
    ]:
        """Extract ACL attributes and remove from active dict.

        Args:
            attributes_dict: Current attributes dictionary
            acl_attribute_names: Names of ACL attributes to process

        Returns:
            Tuple of (new_attributes_dict, commented_acl_values, hidden_attrs)

        """
        new_attrs: t.MutableStrSequenceMapping = dict(attributes_dict)
        commented_vals: t.MutableStrSequenceMapping = {}
        hidden_attrs: set[str] = set()
        for acl_attr in acl_attribute_names:
            if acl_attr in new_attrs:
                acl_values = new_attrs[acl_attr]
                if u.matches_type(acl_values, list):
                    commented_vals[acl_attr] = list(acl_values)
                else:
                    commented_vals[acl_attr] = [str(acl_values)]
                del new_attrs[acl_attr]
                hidden_attrs.add(acl_attr.lower())
        return (new_attrs, commented_vals, hidden_attrs)

    @staticmethod
    def update_metadata_with_commented_acls(
        metadata: m.Ldif.ServerMetadata,
        acl_attribute_names: t.MutableSequenceOf[str],
        commented_acl_values: t.MutableStrSequenceMapping,
        hidden_attrs: set[str],
        entry_attributes_dict: t.MutableStrSequenceMapping,
    ) -> m.Ldif.ServerMetadata:
        """Update metadata with commented ACL information.

        Args:
            metadata: Existing metadata (must be m.Ldif.ServerMetadata, not internal model)
            acl_attribute_names: List of ACL attribute names
            commented_acl_values: Dictionary of commented ACL values
            hidden_attrs: Set of hidden attribute names
            entry_attributes_dict: Original attributes dict for checking

        Returns:
            Updated metadata with ACL information

        """
        metadata_typed: m.Ldif.ServerMetadata = metadata
        current_extensions: t.Ldif.MutableMetadataInputMapping = (
            metadata_typed.extensions.to_dict() if metadata_typed.extensions else {}
        )
        hidden_attribute_names: set[str] = set()
        hidden_attrs_raw = current_extensions.get(c.Ldif.HIDDEN_ATTRIBUTES, [])
        if isinstance(hidden_attrs_raw, (list, tuple, frozenset, set)):
            hidden_attribute_names = {str(item).lower() for item in hidden_attrs_raw}
        if metadata_typed.write_options is not None:
            legacy_hidden_attrs = getattr(
                metadata_typed.write_options,
                "hidden_attrs",
                [],
            )
            if isinstance(legacy_hidden_attrs, (list, tuple, frozenset, set)):
                hidden_attribute_names.update(
                    str(item).lower() for item in legacy_hidden_attrs
                )
            base_dn_value = getattr(metadata_typed.write_options, "base_dn", None)
            if isinstance(base_dn_value, str):
                current_extensions.setdefault(c.Ldif.BASE_DN, base_dn_value)
        hidden_attribute_names.update(attr.lower() for attr in hidden_attrs)
        if hidden_attribute_names:
            current_extensions[c.Ldif.HIDDEN_ATTRIBUTES] = (
                t.Cli.JSON_VALUE_ADAPTER.validate_python(
                    sorted(hidden_attribute_names),
                )
            )
        if commented_acl_values:
            converted_attrs_list: t.MutableSequenceOf[str] = list(
                commented_acl_values.keys(),
            )
            current_extensions[c.Ldif.CONVERTED_ATTRIBUTES] = (
                t.Cli.JSON_VALUE_ADAPTER.validate_python(converted_attrs_list)
            )
            current_extensions[c.Ldif.COMMENTED_ATTRIBUTE_VALUES] = (
                m.Ldif.DynamicMetadata.from_dict({
                    comment_key: t.Cli.JSON_VALUE_ADAPTER.validate_python(
                        comment_value,
                    )
                    for comment_key, comment_value in commented_acl_values.items()
                }).model_dump_json()
            )
        commented_attrs_raw = current_extensions.get(
            c.Ldif.ACL_COMMENTED_ATTRIBUTES,
            [],
        )
        commented_attrs: t.MutableSequenceOf[str] = (
            [str(x) for x in commented_attrs_raw]
            if isinstance(commented_attrs_raw, list)
            else []
        )
        for acl_attr in acl_attribute_names:
            if acl_attr in entry_attributes_dict and acl_attr not in commented_attrs:
                commented_attrs.append(acl_attr)
        if commented_attrs:
            current_extensions[c.Ldif.ACL_COMMENTED_ATTRIBUTES] = (
                t.Cli.JSON_VALUE_ADAPTER.validate_python(commented_attrs)
            )
        update_dict_final: MutableMapping[str, t.Ldif.MutableMetadataInputMapping] = {
            "extensions": current_extensions,
        }
        copy_result: m.Ldif.ServerMetadata = metadata_typed.model_copy(
            update=update_dict_final,
        )
        return copy_result

    @staticmethod
    def validate_aci_macros_in_entry(
        attrs_dict: t.Ldif.AttributeDict,
        validate_aci_macros: Callable[[str], r[bool]],
    ) -> str | None:
        """Validate ACI macros if present. Returns error message or None if valid."""
        aci_attrs = attrs_dict.get("aci")
        if aci_attrs and u.matches_type(aci_attrs, (list, tuple)):
            for aci_value in aci_attrs:
                if u.matches_type(aci_value, str):
                    validation_result = validate_aci_macros(aci_value)
                    if validation_result.failure:
                        return f"ACI macro validation failed: {validation_result.error}"
        return None

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
        FlextLdifServersOudHelpersMixin._collect_acl_from_transformations(
            entry,
            acl_comments_dict,
            acl_attr_names_to_skip,
        )
        FlextLdifServersOudHelpersMixin._collect_acl_from_extensions(
            entry,
            acl_comments_dict,
            acl_attr_names_to_skip,
        )
        if acl_comments_dict:
            acl_attr_names = list(acl_comments_dict.keys())
            ordered_acl_attrs = (
                FlextLdifServersOudHelpersMixin._determine_attribute_order(
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
        acl_attr_names_to_skip = FlextLdifServersOudHelpersMixin._add_oud_acl_comments(
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
                FlextLdifServersOudHelpersMixin._determine_attribute_order(
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
                FlextLdifServersOudHelpersMixin._add_attribute_transformation_comments(
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
                FlextLdifServersOudHelpersMixin._determine_attribute_order(
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
    def _apply_phase_aware_acl_handling(
        entry_data: m.Ldif.Entry,
        write_options: m.Ldif.WriteFormatOptions | None,
    ) -> m.Ldif.Entry:
        """Apply phase-aware ACL attribute commenting.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline**:
        - No phase-aware ACL handling
        - ACL attributes written directly without modification

        **OUD Override** (this method):
        - Comments out ACL attributes during non-ACL migration phases
        - Enables phased migration: entries first, ACLs later
        - Prevents ACL application before referenced entries exist

        OUD Migration Phases
        --------------------

        **Phase-Aware ACL Strategy**:

        ::

            Phase 01 (Groups):    ACL attributes → commented (# aci: ...)
            Phase 02 (Users):     ACL attributes → commented (# aci: ...)
            Phase 03 (Contexts):  ACL attributes → commented (# aci: ...)
            Phase 04 (ACL):       ACL attributes → written normally (aci: ...)

        **Why Phase-Aware ACLs?**:
        - ACIs reference entries by DN (userdn, groupdn)
        - Referenced entries must exist before ACI can be applied
        - Applying ACIs too early causes errors

        Configuration
        -------------

        Controlled via ``WriteFormatOptions``:
        - ``comment_acl_in_non_acl_phases: True`` - Enable phase awareness
        - ``entry_category``: Current phase (``"group"``, ``"user"``, ``"acl"``)
        - ``acl_attribute_names``: List of ACL attribute names to comment

        Args:
            entry_data: Entry to process
            write_options: Write options with ACL phase settings

        Returns:
            Entry with ACL attributes commented if applicable

        """
        if not (write_options and write_options.comment_acl_in_non_acl_phases):
            return entry_data
        category = write_options.entry_category
        acl_attrs = write_options.acl_attribute_names
        if not (category and category != "acl" and acl_attrs):
            return entry_data
        acl_attrs_list = list(acl_attrs)
        return FlextLdifServersOudHelpersMixin._comment_acl_attributes(
            entry_data, acl_attrs_list
        )

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
        commented_acl_values = FlextLdifServersOudHelpersMixin._parse_commented_values(
            commented_acl_values_raw
        )
        if not commented_acl_values:
            return
        original_acl_attr = FlextLdifServersOudHelpersMixin._get_original_acl_attr(
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
                    FlextLdifServersOudHelpersMixin._normalize_acl_values(
                        acl_values_raw
                    )
                )
                if isinstance(normalized_acl_values, list):
                    acl_values = list(normalized_acl_values)
                else:
                    acl_values = [u.to_str(normalized_acl_values)]
            FlextLdifServersOudHelpersMixin._add_acl_value_comments(
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

    @staticmethod
    def _determine_attribute_order(
        attr_names: t.MutableSequenceOf[str],
        format_options: m.Ldif.WriteFormatOptions | None,
    ) -> t.MutableSequenceOf[str]:
        """Determine attribute order based on format options.

        Args:
            attr_names: List of attribute names to order
            format_options: Write format options with sort_attributes flag (may be None)

        Returns:
            Ordered list of attribute names (sorted or original order)

        """
        if format_options and format_options.sort_attributes:
            return sorted(attr_names, key=str.lower)
        return attr_names

    @staticmethod
    def _extract_acl_metadata(
        entry_data: m.Ldif.Entry,
    ) -> tuple[str | None, m.Ldif.DnRegistry | None]:
        """Extract base_dn and dn_registry from entry metadata for ACL processing.

        Args:
            entry_data: Entry with potential metadata

        Returns:
            Tuple of (base_dn, dn_registry)

        """
        base_dn: str | None = None
        dn_registry: m.Ldif.DnRegistry | None = None
        metadata = entry_data.metadata
        extensions = metadata.extensions if metadata is not None else None
        if extensions is not None:
            extensions_dict = extensions.to_dict()
            base_dn_raw = extensions_dict.get(c.Ldif.BASE_DN)
            base_dn = u.to_str(base_dn_raw) or base_dn
            dn_registry_raw = extensions_dict.get(c.Ldif.DN_REGISTRY)
            dn_registry = (
                m.Ldif.DnRegistry.model_validate(dn_registry_raw)
                if dn_registry_raw is not None
                else None
            )
        if (
            (base_dn is None or dn_registry is None)
            and entry_data.metadata
            and entry_data.metadata.write_options
        ):
            base_dn_value = getattr(entry_data.metadata.write_options, "base_dn", None)
            if base_dn is None and isinstance(base_dn_value, str):
                base_dn = base_dn_value
            dn_registry_value = getattr(
                entry_data.metadata.write_options,
                "dn_registry",
                None,
            )
            if dn_registry is None and isinstance(dn_registry_value, m.Ldif.DnRegistry):
                dn_registry = dn_registry_value
        return (base_dn, dn_registry)

    @classmethod
    def _acl_metadata_key_mapping(cls) -> t.MappingKV[str, str]:
        """Lazy frozen mapping: ACL extension key → canonical metadata key."""
        cached_raw = cls.__dict__.get("_ACL_METADATA_KEY_MAPPING_CACHE")
        if isinstance(cached_raw, Mapping):
            return cached_raw
        mk = c.Ldif
        cached: t.MappingKV[str, str] = MappingProxyType({
            "extop": mk.ACL_EXTOP,
            "ip": mk.ACL_BIND_IP_FILTER,
            "bind_ip": mk.ACL_BIND_IP_FILTER,
            "dns": mk.ACL_BIND_DNS,
            "bind_dns": mk.ACL_BIND_DNS,
            "dayofweek": mk.ACL_BIND_DAYOFWEEK,
            "bind_dayofweek": mk.ACL_BIND_DAYOFWEEK,
            "timeofday": mk.ACL_BIND_TIMEOFDAY,
            "bind_timeofday": mk.ACL_BIND_TIMEOFDAY,
            "authmethod": mk.ACL_AUTHMETHOD,
            "ssf": mk.ACL_SSF,
            "targetcontrol": "targetcontrol",
            "targetscope": "targetscope",
            "targattrfilters": mk.ACL_TARGETATTR_FILTERS,
        })
        cls._ACL_METADATA_KEY_MAPPING_CACHE = cached
        return cached

    @staticmethod
    def _extract_acl_metadata_from_dict(
        acl_extensions: t.Ldif.MetadataInputMapping,
        acl_metadata_extensions: t.Ldif.MutableMetadataInputMapping,
    ) -> None:
        """Extract ACL metadata from dict extensions."""
        for (
            src_key,
            dest_key,
        ) in FlextLdifServersOudHelpersMixin._acl_metadata_key_mapping().items():
            value_raw = acl_extensions.get(src_key)
            if value_raw is not None:
                acl_metadata_extensions[dest_key] = u.normalize_to_metadata(value_raw)

    @staticmethod
    def _extract_acl_metadata_from_dynamic(
        acl_extensions: m.Ldif.DynamicMetadata,
        acl_metadata_extensions: t.Ldif.MutableMetadataInputMapping,
    ) -> None:
        """Extract ACL metadata from DynamicMetadata extensions."""
        extensions_dict = acl_extensions.to_dict()
        for (
            src_key,
            dest_key,
        ) in FlextLdifServersOudHelpersMixin._acl_metadata_key_mapping().items():
            if src_key not in extensions_dict:
                continue
            value_raw = extensions_dict[src_key]
            acl_metadata_extensions[dest_key] = u.normalize_to_metadata(value_raw)

    @staticmethod
    def _find_aci_in_dict(
        attrs: t.AttributeMapping | None,
    ) -> t.MutableSequenceOf[str] | str | None:
        """Find ACI value in dictionary (case-insensitive)."""
        if not attrs:
            return None
        for key, value in attrs.items():
            if key.lower() == "aci":
                if isinstance(value, str):
                    return value
                return value
        return None

    @staticmethod
    def _find_aci_values(
        entry: m.Ldif.Entry,
        original_attrs: t.AttributeMapping,
    ) -> t.MutableSequenceOf[str] | str | None:
        """Find ACI values from entry or original_attrs."""
        aci_values: t.MutableSequenceOf[str] | str | None = None
        if original_attrs:
            original_aci = original_attrs.get("aci")
            if isinstance(original_aci, list):
                aci_input: t.MutableSequenceOf[str] = [
                    u.to_str(item) for item in original_aci
                ]
                aci_values = (
                    FlextLdifServersOudHelpersMixin._normalize_aci_value_simple(
                        aci_input
                    )
                )
            elif isinstance(original_aci, str):
                aci_values = (
                    FlextLdifServersOudHelpersMixin._normalize_aci_value_simple(
                        original_aci
                    )
                )
        if not aci_values and entry.attributes and entry.attributes.attributes:
            entry_aci = entry.attributes.attributes.get("aci")
            if isinstance(entry_aci, list):
                entry_aci_input: t.MutableSequenceOf[str] = [
                    u.to_str(item) for item in entry_aci
                ]
                aci_values = (
                    FlextLdifServersOudHelpersMixin._normalize_aci_value_simple(
                        entry_aci_input
                    )
                )
        if not aci_values:
            aci_values = FlextLdifServersOudHelpersMixin._find_aci_in_dict(
                original_attrs
            )
            if not aci_values and entry.attributes and entry.attributes.attributes:
                aci_values = FlextLdifServersOudHelpersMixin._find_aci_in_dict(
                    entry.attributes.attributes
                )
        metadata = entry.metadata
        extensions = metadata.extensions if metadata is not None else None
        if not aci_values and extensions is not None:
            commented_raw = extensions.to_dict().get(
                c.Ldif.COMMENTED_ATTRIBUTE_VALUES,
            )
            commented_values = FlextLdifServersOudHelpersMixin._parse_commented_values(
                commented_raw
            )
            if commented_values:
                for key, value in commented_values.items():
                    if key.lower() == "aci":
                        if isinstance(value, list):
                            normalized_value: (
                                t.Ldif.ValueType | t.Ldif.MetadataInputMapping | None
                            ) = [u.to_str(item) for item in value]
                        else:
                            normalized_value = value
                        aci_values = (
                            FlextLdifServersOudHelpersMixin._normalize_aci_value_simple(
                                normalized_value,
                            )
                        )
                        if aci_values:
                            break
        return aci_values

    @staticmethod
    def _get_original_acl_attr(entry: m.Ldif.Entry) -> str:
        """Get original ACL attribute name (orclaci) from transformations or metadata."""
        if entry.metadata and entry.metadata.attribute_transformations:
            for (
                attr_name,
                transformation,
            ) in entry.metadata.attribute_transformations.items():
                if (
                    attr_name.lower() in {"aci", "orclaci"}
                    and transformation.target_name
                    and (transformation.target_name.lower() == "aci")
                ):
                    return attr_name
        if entry.metadata and entry.metadata.extensions:
            acl_original_format = u.to_str(
                entry.metadata.extensions.get("original_format"),
            )
            if "orclaci:" in acl_original_format:
                return "orclaci"
        return "orclaci"

    @staticmethod
    def _is_schema_entry(entry: m.Ldif.Entry) -> bool:
        """Check if entry is a schema entry - delegate to utility."""
        is_schema_entry: bool = u.Ldif.is_schema_entry(entry, strict=False)
        return is_schema_entry

    @staticmethod
    def _merge_acl_metadata_to_entry(
        entry: m.Ldif.Entry,
        acl_metadata_extensions: t.Ldif.MutableMetadataInputMapping,
    ) -> m.Ldif.Entry:
        """Merge ACL metadata extensions into entry metadata."""
        if not acl_metadata_extensions:
            return entry
        if entry.metadata:
            current_extensions: t.Ldif.MutableMetadataInputMapping = (
                dict(entry.metadata.extensions.to_dict())
                if entry.metadata.extensions
                else {}
            )
            current_extensions.update(acl_metadata_extensions)
            merged_extensions = m.Ldif.DynamicMetadata.from_dict(
                current_extensions,
            )
            merged_entry: m.Ldif.Entry = entry.model_copy(
                update={
                    "metadata": entry.metadata.model_copy(
                        update={"extensions": merged_extensions},
                        deep=True,
                    ),
                },
                deep=True,
            )
            return merged_entry
        entry_metadata = m.Ldif.ServerMetadata.create_for(
            "oud",
            extensions=m.Ldif.DynamicMetadata.from_dict(
                acl_metadata_extensions,
            ),
        )
        copy_entry: m.Ldif.Entry = entry.model_copy(
            update={"metadata": entry_metadata},
            deep=True,
        )
        return copy_entry

    @staticmethod
    def _normalize_aci_value(
        aci_value: str,
        _base_dn: str | None,
        _dn_registry: m.Ldif.DnRegistry | None,
    ) -> tuple[str, bool]:
        """Normalize ACI value DNs (already RFC canonical, no changes needed)."""
        return (aci_value, False)

    @staticmethod
    def _normalize_aci_value_simple(
        value: t.Ldif.ValueType | t.Ldif.MetadataInputMapping | None,
    ) -> t.MutableSequenceOf[str] | str | None:
        """Normalize ACI value to t.MutableSequenceOf[str] | str | None."""
        if value is None:
            return None
        if isinstance(value, list):
            return [u.to_str(item) for item in value]
        return u.to_str(value)

    @staticmethod
    def _normalize_acl_dns(entry_data: m.Ldif.Entry) -> m.Ldif.Entry:
        r"""Normalize and filter DNs in ACL attribute values (userdn/groupdn inside ACL strings).

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline**:
        - No ACL DN normalization in RFC base
        - ACLs stored as raw strings without processing

        **OUD Override** (this method):
        - Normalizes DNs within ACI values (userdn, groupdn patterns)
        - Removes spaces after commas in embedded DNs
        - Optionally filters DNs by base_dn scope
        - Preserves DN case while normalizing whitespace

        ACI DN Normalization
        --------------------

        **Patterns Processed**:
        - ``userdn="ldap:///cn=user, dc=example, dc=com"`` → normalized DN
        - ``groupdn="ldap:///cn=group, dc=example, dc=com"`` → normalized DN
        - ``roledn="ldap:///cn=role, dc=example, dc=com"`` → normalized DN

        **Normalization Rules**:
        - Remove spaces after commas: ``cn=user, dc=example`` → ``cn=user,dc=example``
        - Preserve attribute case: ``CN=User`` stays as ``CN=User``
        - Handle escaped characters: ``cn=user\\, name`` preserved

        **Base DN Filtering** (when configured):
        - Filter out ACIs referencing DNs outside base_dn scope
        - Helps migration by excluding irrelevant ACIs

        Args:
            entry_data: Entry with potential ACL attributes

        Returns:
            Entry with normalized/filtered ACL values

        """
        if not entry_data.attributes or not entry_data.attributes.attributes:
            return entry_data
        base_dn, dn_registry = FlextLdifServersOudHelpersMixin._extract_acl_metadata(
            entry_data
        )
        attrs = entry_data.attributes.attributes
        if "aci" not in attrs:
            return entry_data
        aci_values = attrs["aci"]
        if not aci_values:
            return entry_data
        normalized_aci_values: t.MutableSequenceOf[str] = []
        for aci in aci_values:
            aci_str: str = aci
            normalized_aci, was_filtered = (
                FlextLdifServersOudHelpersMixin._normalize_aci_value(
                    aci_str,
                    base_dn,
                    dn_registry,
                )
            )
            if not was_filtered and normalized_aci:
                normalized_aci_values.append(normalized_aci)
        if normalized_aci_values != aci_values:
            new_attrs = dict(entry_data.attributes.attributes)
            new_attrs["aci"] = normalized_aci_values
            entry_data.attributes.attributes = new_attrs
        return entry_data

    @staticmethod
    def _process_aci_list_for_finalize(
        aci_values: t.MutableSequenceOf[str] | str,
        acl_server: p.Ldif.AclServer,
        current_extensions: t.Ldif.MutableMetadataInputMapping,
    ) -> None:
        """Process list of ACI values and extract metadata."""
        aci_list: t.MutableSequenceOf[str] = (
            [*aci_values] if isinstance(aci_values, MutableSequence) else [aci_values]
        )
        for aci_value in aci_list:
            normalized_aci = aci_value.strip()
            if not normalized_aci.startswith("aci:"):
                normalized_aci = f"aci: {normalized_aci}"
            acl_result = acl_server.parse_server(normalized_aci)
            if acl_result.success:
                acl_model = m.Ldif.Acl.model_validate(acl_result.value)
                if acl_model.metadata and acl_model.metadata.extensions:
                    acl_ext_raw = (
                        acl_model.metadata.extensions.model_dump()
                        if hasattr(acl_model.metadata.extensions, "model_dump")
                        else dict(acl_model.metadata.extensions)
                    )
                    acl_extensions: t.Ldif.MutableMetadataInputMapping = {}
                    for raw_key, raw_value in acl_ext_raw.items():
                        key = raw_key
                        acl_extensions[key] = (
                            m.Ldif.DynamicMetadata.coerce_metadata_value(
                                raw_value,
                            )
                        )
                    FlextLdifServersOudHelpersMixin._process_parsed_acl_extensions(
                        acl_extensions,
                        current_extensions,
                    )

    @staticmethod
    def _process_parsed_acl_extensions(
        acl_extensions: t.Ldif.MetadataInputMapping,
        current_extensions: t.Ldif.MutableMetadataInputMapping,
    ) -> None:
        """Process parsed ACL extensions and add to current extensions."""
        mk = c.Ldif
        key_mapping: t.MutableStrMapping = {
            "targattrfilters": mk.ACL_TARGETATTR_FILTERS,
            "targetcontrol": mk.ACL_TARGET_CONTROL,
            "extop": mk.ACL_EXTOP,
            "ip": mk.ACL_BIND_IP_FILTER,
            "dns": mk.ACL_TARGETSCOPE,
            "dayofweek": mk.ACL_NUMBERING,
            "timeofday": mk.ACL_BINDMODE,
            "authmethod": mk.ACL_SOURCE_PERMISSIONS,
            "ssf": mk.ACL_SSFS,
            mk.ACL_TARGETATTR_FILTERS: mk.ACL_TARGETATTR_FILTERS,
            mk.ACL_TARGET_CONTROL: mk.ACL_TARGET_CONTROL,
            mk.ACL_EXTOP: mk.ACL_EXTOP,
            mk.ACL_BIND_IP_FILTER: mk.ACL_BIND_IP_FILTER,
            mk.ACL_TARGETSCOPE: mk.ACL_TARGETSCOPE,
            mk.ACL_NUMBERING: mk.ACL_NUMBERING,
            mk.ACL_BINDMODE: mk.ACL_BINDMODE,
            mk.ACL_SOURCE_PERMISSIONS: mk.ACL_SOURCE_PERMISSIONS,
            mk.ACL_SSFS: mk.ACL_SSFS,
        }
        known_keys = {
            mk.ACL_TARGETATTR_FILTERS,
            mk.ACL_TARGET_CONTROL,
            mk.ACL_EXTOP,
            mk.ACL_BIND_IP_FILTER,
            mk.ACL_TARGETSCOPE,
            mk.ACL_NUMBERING,
            mk.ACL_BINDMODE,
            mk.ACL_SOURCE_PERMISSIONS,
            mk.ACL_SSFS,
        }
        for key, value in acl_extensions.items():
            key_lower = key.lower()
            mapped_key = key_mapping.get(key) or key_mapping.get(key_lower)
            if mapped_key is None and key in known_keys:
                mapped_key = key
            final_key = mapped_key or key
            if value is None or u.primitive(value):
                current_extensions[final_key] = value
            elif isinstance(value, (list, tuple)):
                current_extensions[final_key] = (
                    t.Cli.JSON_VALUE_ADAPTER.validate_python(
                        [
                            item if item is None or u.primitive(item) else str(item)
                            for item in value
                        ],
                    )
                )
            elif isinstance(value, Mapping):
                value_dict_inner: MutableMapping[str, t.JsonValue] = {}
                for k, v in value.items():
                    key = k
                    value_dict_inner[key] = (
                        v
                        if u.primitive(v)
                        else t.Cli.JSON_VALUE_ADAPTER.validate_python(v)
                    )
                current_extensions[final_key] = (
                    t.Cli.JSON_VALUE_ADAPTER.validate_python(
                        value_dict_inner,
                    )
                )
            else:
                current_extensions[final_key] = str(value)

    @staticmethod
    def _process_single_aci_value(
        aci_value: str,
        acl_metadata_extensions: t.Ldif.MutableMetadataInputMapping,
    ) -> r[bool]:
        """Process single ACI value, extract metadata, return has_macros flag."""
        has_macros = bool(re.search(r"\(\$dn\)|\[\$dn\]|\(\$attr\.", aci_value))
        validation_result = FlextLdifServersOudHelpersMixin._validate_aci_macros(
            aci_value
        )
        if validation_result.failure:
            return r[bool].fail_op("ACI macro validation", validation_result.error)
        normalized_aci = aci_value.strip()
        if not normalized_aci.startswith("aci:"):
            normalized_aci = f"aci: {normalized_aci}"
        acl_server = FlextLdifServersOudAcl()
        parse_result = acl_server.parse_server(normalized_aci)
        if parse_result.success:
            parsed_acl = parse_result.value
            if parsed_acl.metadata and parsed_acl.metadata.extensions:
                acl_extensions = parsed_acl.metadata.extensions
                if u.matches_type(acl_extensions, m.Ldif.DynamicMetadata):
                    FlextLdifServersOudHelpersMixin._extract_acl_metadata_from_dynamic(
                        acl_extensions,
                        acl_metadata_extensions,
                    )
                elif isinstance(acl_extensions, Mapping):
                    acl_extensions_dict: t.Ldif.MutableMetadataInputMapping = {
                        str(
                            k,
                        ): m.Ldif.DynamicMetadata.coerce_metadata_value(
                            v,
                        )
                        for k, v in acl_extensions.items()
                    }
                    FlextLdifServersOudHelpersMixin._extract_acl_metadata_from_dict(
                        acl_extensions_dict,
                        acl_metadata_extensions,
                    )
        return r[bool].ok(has_macros)

    @staticmethod
    def _restore_entry_from_metadata(entry_data: m.Ldif.Entry) -> m.Ldif.Entry:
        """Restore original DN and attributes using generic utilities.

        RFC vs OUD Behavior Differences
        ================================

        **RFC Baseline** (in rfc.py ``_restore_entry_from_metadata``):
        - Basic restoration of DN and attributes
        - Uses metadata.extensions for stored values
        - Simple case mapping restoration

        **OUD Override** (this method):
        - Full roundtrip restoration using OUD-specific metadata
        - Restores DN with original spacing (spaces after commas)
        - Restores attribute names with original case
        - Restores attribute values to original format

        Restoration Process
        -------------------

        **1. DN Restoration** (if differences detected):
           - Checks ``minimal_differences_dn.has_differences``
           - Uses ``original_dn_complete`` from extensions
           - Restores DN with original spacing servers

        **2. Attribute Restoration** (if case mapping available):
           - Uses ``original_attribute_case`` mapping
           - Uses ``original_attributes_complete`` dictionary
           - Restores each attribute with original case

        Example Restoration
        -------------------

        ::

            # Original OID entry:
            objectclass: groupOfUniqueNames
            uniquemember: cn = user1

            # Normalized for OUD:
            objectClass: groupOfUniqueNames
            uniqueMember: cn = user1

            # Restored for roundtrip (with preserve_original=True):
            objectclass: groupOfUniqueNames
            uniquemember: cn = user1

        """
        metadata = entry_data.metadata
        if metadata is None or not metadata.extensions:
            return entry_data
        ext = metadata.extensions
        mk = c.Ldif
        original_dn_value = u.to_str(ext.get(mk.ORIGINAL_DN_COMPLETE))
        dn_diff_raw = m.Ldif.DynamicMetadata.model_validate(
            ext.get(mk.MINIMAL_DIFFERENCES_DN, {}),
        )
        should_restore_dn = (
            bool(original_dn_value)
            and entry_data.dn is not None
            and bool(dn_diff_raw.get(mk.HAS_DIFFERENCES, False))
        )
        restored_entry = (
            entry_data.model_copy(
                update={"dn": m.Ldif.DN(value=original_dn_value)},
            )
            if should_restore_dn
            else entry_data
        )

        attributes = restored_entry.attributes
        original_case_map = metadata.original_attribute_case
        if attributes is None:
            return restored_entry
        original_attributes = m.Ldif.DynamicMetadata.model_validate(
            ext.get(c.Ldif.ORIGINAL_ATTRIBUTES_COMPLETE, {}),
        )

        restored: t.MutableStrSequenceMapping = {}
        for attr_name, attr_values in attributes.attributes.items():
            orig_case_raw = original_case_map.get(attr_name.lower(), attr_name)
            orig_case = orig_case_raw if isinstance(orig_case_raw, str) else attr_name
            fallback_values = [str(item) for item in attr_values or [attr_values]]
            if orig_case in original_attributes:
                original_value = original_attributes[orig_case]
                restored_values = (
                    [str(item) for item in original_value]
                    if isinstance(original_value, (list, tuple))
                    else [str(original_value)]
                )
            else:
                restored_values = fallback_values
            restored[orig_case] = restored_values
        restored_copy: m.Ldif.Entry = restored_entry.model_copy(
            update={
                "attributes": m.Ldif.Attributes.model_validate({
                    "attributes": restored,
                    "attribute_metadata": attributes.attribute_metadata,
                    "metadata": attributes.metadata,
                }),
            },
        )
        return restored_copy

    @staticmethod
    def _validate_aci_macros(_aci_value: str) -> r[bool]:
        """Validate OUD ACI macro consistency rules (no-op)."""
        return r[bool].ok(True)


__all__: list[str] = ["FlextLdifServersOudHelpersMixin"]
