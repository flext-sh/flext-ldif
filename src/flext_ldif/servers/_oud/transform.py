"""OUD entry — Transform helpers.

Per AGENTS.md §2.3 (MRO Composition) + §3.1 (200-LOC cap): one of the
domain-specific Mixins composed into ``FlextLdifServersOudHelpersMixin``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping
from typing import ClassVar

from flext_ldif import (
    c,
    m,
    p,
    r,
    t,
    u,
)
from flext_ldif.servers._oud.aci import FlextLdifServersOudAciMixin
from flext_ldif.servers._oud.acl_extract import FlextLdifServersOudAclExtractMixin
from flext_ldif.servers._oud.acl_metadata import FlextLdifServersOudAclMetadataMixin


class FlextLdifServersOudTransformMixin:
    """OUD Transform helpers."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @staticmethod
    def apply_phase_aware_acl_handling(
        entry_data: p.Ldif.Entry,
        write_options: m.Ldif.WriteFormatOptions | None,
    ) -> p.Ldif.Entry:
        """Apply phase-aware ACL attribute commenting."""
        if not (write_options and write_options.comment_acl_in_non_acl_phases):
            return entry_data
        category = write_options.entry_category
        acl_attrs = write_options.acl_attribute_names
        if not (category and category != "acl" and acl_attrs):
            return entry_data
        acl_attrs_list = list(acl_attrs)
        return FlextLdifServersOudAclExtractMixin.comment_acl_attributes(
            entry_data,
            acl_attrs_list,
        )

    @staticmethod
    def determine_attribute_order(
        attr_names: t.MutableSequenceOf[str],
        format_options: m.Ldif.WriteFormatOptions | None,
    ) -> t.MutableSequenceOf[str]:
        """Determine attribute order based on format options."""
        if format_options and format_options.sort_attributes:
            return sorted(attr_names, key=str.lower)
        return attr_names

    @staticmethod
    def _hook_pre_write_entry_static(
        entry: p.Ldif.Entry,
        validate_aci_macros: Callable[[str], r[bool]],
        correct_rfc_syntax_in_attributes: Callable[
            [t.Ldif.AttributeDict],
            r[t.Ldif.AttributeDict],
        ],
    ) -> p.Result[p.Ldif.Entry]:
        """Validate and correct RFC syntax issues before writing entry (static helper)."""
        attrs_dict_raw: t.MutableStrSequenceMapping = (
            entry.attributes.attributes if entry.attributes else {}
        )
        attrs_dict: t.Ldif.AttributeDict = {
            k: list(v) for k, v in attrs_dict_raw.items()
        }
        aci_validation_error = FlextLdifServersOudAciMixin.validate_aci_macros_in_entry(
            attrs_dict,
            validate_aci_macros,
        )
        if aci_validation_error:
            return r[p.Ldif.Entry].fail(aci_validation_error)
        return FlextLdifServersOudTransformMixin.correct_syntax_and_return_entry(
            entry,
            attrs_dict,
            correct_rfc_syntax_in_attributes,
        )

    @staticmethod
    def _is_schema_entry(entry: p.Ldif.Entry) -> bool:
        """Check if entry is a schema entry - delegate to utility."""
        is_schema_entry: bool = u.Ldif.is_schema_entry(entry, strict=False)
        return is_schema_entry

    @staticmethod
    def normalize_acl_dns(entry_data: p.Ldif.Entry) -> p.Ldif.Entry:
        """Normalize and filter DNs in ACL attribute values (userdn/groupdn inside ACL strings)."""
        if not entry_data.attributes or not entry_data.attributes.attributes:
            return entry_data
        base_dn, dn_registry = FlextLdifServersOudAclMetadataMixin.extract_acl_metadata(
            entry_data,
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
                FlextLdifServersOudAciMixin.normalize_aci_value(
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
    def restore_entry_from_metadata(entry_data: p.Ldif.Entry) -> p.Ldif.Entry:
        """Restore original DN and attributes using generic utilities."""
        metadata = entry_data.metadata
        if metadata is None or not metadata.extensions:
            return entry_data
        ext = metadata.extensions
        mk = c.Ldif
        original_dn_value = u.to_str(ext.get(mk.ORIGINAL_DN_COMPLETE))
        dn_diff_raw: t.MutableJsonMapping = t.json_dict_adapter().validate_python(
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
        original_attributes: t.MutableJsonMapping = (
            t.json_dict_adapter().validate_python(
                ext.get(c.Ldif.ORIGINAL_ATTRIBUTES_COMPLETE, {}),
            )
        )

        restored: t.MutableStrSequenceMapping = {}
        for attr_name, attr_values in attributes.attributes.items():
            orig_case_raw = original_case_map.get(attr_name.lower(), attr_name)
            orig_case = orig_case_raw if isinstance(orig_case_raw, str) else attr_name
            fallback_values: list[str] = (
                list(attr_values) if attr_values else [str(attr_values)]
            )
            if orig_case in original_attributes:
                original_value = original_attributes[orig_case]
                restored_values = [str(original_value)]
            else:
                restored_values = fallback_values
            restored[orig_case] = restored_values
        restored_copy: p.Ldif.Entry = restored_entry.model_copy(
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
    def apply_syntax_corrections(
        entry: p.Ldif.Entry,
        corrected_data: MutableMapping[
            str,
            t.Ldif.Scalar | t.MutableSequenceOf[str] | t.MutableAttributeMapping | None,
        ],
        syntax_corrections: t.MutableSequenceOf[str] | t.MutableStrMapping | None,
    ) -> p.Result[p.Ldif.Entry]:
        """Apply syntax corrections to entry."""
        corrected_attrs_raw = corrected_data.get("corrected_attributes")
        if not isinstance(corrected_attrs_raw, Mapping):
            return r[p.Ldif.Entry].ok(entry)
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
        FlextLdifServersOudTransformMixin._module_logger.debug(
            "OUD servers: Applied syntax corrections before writing (structure preserved)",
            entry_dn=str(entry.dn) if entry.dn else "",
            corrections_count=len(syntax_corrections) if syntax_corrections else 0,
        )
        return r[p.Ldif.Entry].ok(corrected_entry)

    @staticmethod
    def correct_syntax_and_return_entry(
        entry: p.Ldif.Entry,
        attrs_dict: t.Ldif.AttributeDict,
        correct_rfc_syntax_in_attributes: Callable[
            [t.Ldif.AttributeDict],
            r[t.Ldif.AttributeDict],
        ],
    ) -> p.Result[p.Ldif.Entry]:
        """Correct RFC syntax issues and return entry."""
        corrected_result = correct_rfc_syntax_in_attributes(attrs_dict)
        if corrected_result.failure:
            return r[p.Ldif.Entry].fail(corrected_result.error or "Unknown error")
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
            return FlextLdifServersOudTransformMixin.apply_syntax_corrections(
                entry,
                corrected_data_typed,
                syntax_corrections_typed,
            )
        return r[p.Ldif.Entry].ok(entry)


__all__: list[str] = ["FlextLdifServersOudTransformMixin"]
