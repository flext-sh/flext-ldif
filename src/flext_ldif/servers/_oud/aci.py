"""OUD entry — Aci helpers.

Per AGENTS.md §2.3 (MRO Composition) + §3.1 (200-LOC cap): one of the
domain-specific Mixins composed into ``FlextLdifServersOudHelpersMixin``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, MutableSequence

from flext_ldif import (
    FlextLdifServersOudAcl,
    c,
    m,
    p,
    r,
    t,
    u,
)
from flext_ldif.servers._oud.acl_extract import FlextLdifServersOudAclExtractMixin
from flext_ldif.servers._oud.acl_metadata import FlextLdifServersOudAclMetadataMixin

logger = u.fetch_logger(__name__)


class FlextLdifServersOudAciMixin:
    """OUD Aci helpers."""

    @staticmethod
    def _find_aci_in_dict(
        attrs: t.AttributeMapping | None,
    ) -> t.MutableSequenceOf[str] | str | None:
        """Find ACI value in dictionary (case-insensitive)."""
        if not attrs:
            return None
        for key, value in attrs.items():
            if key.lower() == "aci":
                return value
        return None

    @staticmethod
    def _find_aci_values(
        entry: m.Ldif.Entry,
        original_attrs: t.AttributeMapping,
    ) -> t.MutableSequenceOf[str] | str | None:
        """Find ACI values from entry attributes, original_attrs, or commented metadata."""
        normalize = FlextLdifServersOudAciMixin._normalize_aci_value_simple
        find_in_dict = FlextLdifServersOudAciMixin._find_aci_in_dict
        entry_attrs = (
            entry.attributes.attributes
            if entry.attributes and entry.attributes.attributes
            else None
        )
        # Try direct "aci" key (list/str), normalised through the simple helper
        for source in (original_attrs, entry_attrs):
            if source:
                raw = source.get("aci")
                if isinstance(raw, list):
                    raw = [u.to_str(item) for item in raw]
                if raw and (values := normalize(raw)):
                    return values
        # Fallback: case-insensitive search in either dict
        for source in (original_attrs, entry_attrs):
            if source and (values := find_in_dict(source)):
                return values
        # Last resort: commented values stored in entry metadata extensions
        extensions = entry.metadata.extensions if entry.metadata is not None else None
        if extensions is None:
            return None
        commented = FlextLdifServersOudAclExtractMixin._parse_commented_values(
            extensions.to_dict().get(c.Ldif.COMMENTED_ATTRIBUTE_VALUES),
        )
        if not commented:
            return None
        for key, value in commented.items():
            if key.lower() == "aci":
                normalized_value = (
                    [u.to_str(item) for item in value]
                    if isinstance(value, list)
                    else value
                )
                if values := normalize(normalized_value):
                    return values
        return None

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
                    FlextLdifServersOudAclMetadataMixin._process_parsed_acl_extensions(
                        acl_extensions,
                        current_extensions,
                    )

    @staticmethod
    def _process_single_aci_value(
        aci_value: str,
        acl_metadata_extensions: t.Ldif.MutableMetadataInputMapping,
    ) -> p.Result[bool]:
        """Process single ACI value, extract metadata, return has_macros flag."""
        has_macros = bool(re.search(r"\(\$dn\)|\[\$dn\]|\(\$attr\.", aci_value))
        validation_result = FlextLdifServersOudAciMixin._validate_aci_macros(aci_value)
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
                    FlextLdifServersOudAclMetadataMixin._extract_acl_metadata_from_dynamic(
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
                    FlextLdifServersOudAclMetadataMixin._extract_acl_metadata_from_dict(
                        acl_extensions_dict,
                        acl_metadata_extensions,
                    )
        return r[bool].ok(has_macros)

    @staticmethod
    def _validate_aci_macros(_aci_value: str) -> p.Result[bool]:
        """Validate OUD ACI macro consistency rules (no-op)."""
        return r[bool].ok(True)

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


__all__: list[str] = ["FlextLdifServersOudAciMixin"]
