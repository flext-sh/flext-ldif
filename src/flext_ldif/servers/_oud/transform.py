"""OUD entry — Transform helpers.

Per AGENTS.md §2.3 (MRO Composition) + §3.1 (200-LOC cap): one of the
domain-specific Mixins composed into ``FlextLdifServersOudHelpers``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, MutableSequence
from typing import ClassVar

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._oud import (
    FlextLdifServersOudAci,
    FlextLdifServersOudAclMetadata,
)


class FlextLdifServersOudTransform:
    """OUD Transform helpers."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @staticmethod
    def determine_attribute_order(
        attr_names: MutableSequence[str],
        format_options: m.Ldif.WriteFormatOptions | None,
    ) -> MutableSequence[str]:
        """Order attribute names according to the format options.

        Args:
            attr_names: Attribute names in declaration order.
            format_options: Output formatting options; sorting is applied only
                when requested.

        Returns:
            Attribute names in output order.

        """
        if format_options and format_options.sort_attributes:
            return sorted(attr_names, key=str.lower)
        return attr_names

    @staticmethod
    def _hook_pre_write_entry_static(
        entry: m.Ldif.Entry,
        validate_aci_macros: Callable[[str], r[bool]],
        correct_rfc_syntax_in_attributes: Callable[
            [t.Ldif.AttributeDict],
            r[t.Ldif.AttributeDict],
        ],
    ) -> p.Result[m.Ldif.Entry]:
        """Validate ACI macros and correct RFC syntax before writing.

        Args:
            entry: Entry about to be written.
            validate_aci_macros: Validator for ACI macro syntax.
            correct_rfc_syntax_in_attributes: Corrector for attribute syntax.

        Returns:
            Result carrying the corrected entry, or a failure.

        """
        attrs_dict_raw: t.MutableStrSequenceMapping = (
            entry.attributes.attributes if entry.attributes else {}
        )
        attrs_dict: t.Ldif.AttributeDict = {
            k: list(v) for k, v in attrs_dict_raw.items()
        }
        aci_validation_error = FlextLdifServersOudAci.validate_aci_macros_in_entry(
            attrs_dict,
            validate_aci_macros,
        )
        if aci_validation_error:
            return r[m.Ldif.Entry].fail(aci_validation_error)
        return FlextLdifServersOudTransform.correct_syntax_and_return_entry(
            entry,
            attrs_dict,
            correct_rfc_syntax_in_attributes,
        )

    @staticmethod
    def _is_schema_entry(entry: m.Ldif.Entry) -> bool:
        """Schema-entry classification of an entry.

        Args:
            entry: Entry to classify.

        Returns:
            True when the entry carries schema definitions.

        """
        is_schema_entry: bool = u.Ldif.detects_schema_entry(entry, strict=False)
        return is_schema_entry

    @staticmethod
    def normalize_acl_dns(entry_data: m.Ldif.Entry) -> m.Ldif.Entry:
        """Normalize and filter DNs inside ACL attribute values.

        Rewrites ``userdn``/``groupdn`` DN references in ACI values against
        the entry's base DN and drops values that no longer resolve.

        Args:
            entry_data: Entry whose ACI values are normalized.

        Returns:
            The entry with normalized ACI values.

        """
        if not entry_data.attributes or not entry_data.attributes.attributes:
            return entry_data
        base_dn, dn_registry = FlextLdifServersOudAclMetadata.extract_acl_metadata(
            entry_data,
        )
        attrs = entry_data.attributes.attributes
        if "aci" not in attrs:
            return entry_data
        aci_values = attrs["aci"]
        if not aci_values:
            return entry_data
        normalized_aci_values: MutableSequence[str] = []
        for aci in aci_values:
            aci_str: str = aci
            normalized_aci, was_filtered = FlextLdifServersOudAci.normalize_aci_value(
                aci_str,
                base_dn,
                dn_registry,
            )
            if not was_filtered and normalized_aci:
                normalized_aci_values.append(normalized_aci)
        if normalized_aci_values != aci_values:
            new_attrs = dict(entry_data.attributes.attributes)
            new_attrs["aci"] = normalized_aci_values
            entry_data.attributes.attributes = new_attrs
        return entry_data

    @staticmethod
    def restore_entry_from_metadata(entry_data: m.Ldif.Entry) -> m.Ldif.Entry:
        """Restore the original DN and attributes from metadata.

        Args:
            entry_data: Entry whose original form is restored.

        Returns:
            The entry with original DN and attribute names applied.

        """
        metadata = entry_data.metadata
        if metadata is None or not metadata.extensions:
            return entry_data
        dn_restored = FlextLdifServersOudTransform._dn_restored_entry(entry_data)
        return FlextLdifServersOudTransform._attributes_restored_entry(
            dn_restored,
            metadata,
        )

    @staticmethod
    def _dn_restored_entry(entry_data: m.Ldif.Entry) -> m.Ldif.Entry:
        """Restore the original DN from entry metadata extensions.

        Args:
            entry_data: Entry whose original DN is restored.

        Returns:
            The entry with the original DN when differences are recorded.

        """
        metadata = entry_data.metadata
        if metadata is None:
            return entry_data
        mk = c.Ldif
        original_dn_value = u.to_str(metadata.extensions.get(mk.ORIGINAL_DN_COMPLETE))
        dn_diff_raw: t.MutableJsonMapping = u.json_dict_adapter().validate_python(
            metadata.extensions.get(mk.MINIMAL_DIFFERENCES_DN, {}),
        )
        should_restore_dn = (
            bool(original_dn_value)
            and entry_data.dn is not None
            and bool(dn_diff_raw.get(mk.HAS_DIFFERENCES, False))
        )
        if should_restore_dn:
            return entry_data.model_copy(
                update={"dn": m.Ldif.DN(value=original_dn_value)},
            )
        return entry_data

    @staticmethod
    def _attributes_restored_entry(
        entry_data: m.Ldif.Entry,
        metadata: m.Ldif.ServerMetadata,
    ) -> m.Ldif.Entry:
        """Restore original attribute names and values from metadata.

        Args:
            entry_data: Entry whose original attributes are restored.
            metadata: Metadata carrying the original names and values.

        Returns:
            The entry with original attribute names and values applied.

        """
        attributes = entry_data.attributes
        if attributes is None:
            return entry_data
        original_case_map = metadata.original_attribute_case
        original_attributes: t.MutableJsonMapping = (
            u.json_dict_adapter().validate_python(
                metadata.extensions.get(c.Ldif.ORIGINAL_ATTRIBUTES_COMPLETE, {}),
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
                restored_values = [str(original_attributes[orig_case])]
            else:
                restored_values = fallback_values
            restored[orig_case] = restored_values
        return u.Ldif.entry_with_attributes(entry_data, restored)

    @staticmethod
    def apply_syntax_corrections(
        entry: m.Ldif.Entry,
        corrected_data: MutableMapping[
            str,
            t.Ldif.Scalar | MutableSequence[str] | t.MutableAttributeMapping | None,
        ],
        syntax_corrections: MutableSequence[str] | t.MutableStrMapping | None,
    ) -> p.Result[m.Ldif.Entry]:
        """Apply corrected attributes to the entry before writing.

        Args:
            entry: Entry to correct.
            corrected_data: Correction payload carrying the corrected
                attributes.
            syntax_corrections: Corrections applied, for logging.

        Returns:
            Result carrying the corrected entry, or the entry unchanged.

        """
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
        FlextLdifServersOudTransform._module_logger.debug(
            "OUD servers: Applied syntax corrections before writing (structure "
            "preserved)",
            entry_dn=str(entry.dn) if entry.dn else "",
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
    ) -> p.Result[m.Ldif.Entry]:
        """Correct RFC syntax issues in the entry attributes.

        Args:
            entry: Entry whose attributes are corrected.
            attrs_dict: Attribute names mapped to value lists.
            correct_rfc_syntax_in_attributes: Corrector for attribute syntax.

        Returns:
            Result carrying the corrected entry, or a failure.

        """
        corrected_result = correct_rfc_syntax_in_attributes(attrs_dict)
        if corrected_result.failure:
            return r[m.Ldif.Entry].from_failure(corrected_result)
        corrected_data = corrected_result.unwrap()
        corrected_data_typed: MutableMapping[
            str,
            t.Ldif.Scalar | MutableSequence[str] | t.MutableAttributeMapping | None,
        ] = {k: list(v) for k, v in corrected_data.items()}
        syntax_corrections_raw = corrected_data_typed.get("syntax_corrections")
        syntax_corrections_typed: MutableSequence[str] | t.MutableStrMapping | None = (
            None
        )
        if isinstance(syntax_corrections_raw, list):
            syntax_corrections_typed = list(syntax_corrections_raw)
        elif isinstance(syntax_corrections_raw, Mapping):
            syntax_corrections_dict: t.MutableStrMapping = {}
            for k, v in syntax_corrections_raw.items():
                syntax_corrections_dict[k] = str(v)
            syntax_corrections_typed = syntax_corrections_dict
        if syntax_corrections_typed is not None:
            return FlextLdifServersOudTransform.apply_syntax_corrections(
                entry,
                corrected_data_typed,
                syntax_corrections_typed,
            )
        return r[m.Ldif.Entry].ok(entry)


__all__: list[str] = ["FlextLdifServersOudTransform"]
