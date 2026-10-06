"""OUD entry — Aci helpers.

Per AGENTS.md §2.3 (MRO Composition) + §3.1 (200-LOC cap): one of the
domain-specific Mixins composed into ``FlextLdifServersOudHelpersMixin``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, m, t, u
from flext_ldif.servers._oud.aci_process import FlextLdifServersOudAciProcessMixin
from flext_ldif.servers._oud.acl_extract import FlextLdifServersOudAclExtractMixin


class FlextLdifServersOudAciMixin(FlextLdifServersOudAciProcessMixin):
    """OUD Aci helpers."""

    @staticmethod
    def _find_aci_in_dict(
        attrs: t.AttributeMapping | None,
    ) -> t.MutableSequenceOf[str] | str | None:
        """Find ACI value in dictionary (case-insensitive).

        Returns:
            The resulting ``t.MutableSequenceOf[str] | str | None``.
        """
        if not attrs:
            return None
        for key, value in attrs.items():
            if key.lower() == "aci":
                return value
        return None

    @staticmethod
    def _aci_from_attr_sources(
        original_attrs: t.AttributeMapping | None,
        entry_attrs: t.AttributeMapping | None,
    ) -> t.MutableSequenceOf[str] | str | None:
        """Find ACI values under the literal or case-insensitive ``aci`` keys.

        Returns:
            The resulting ``t.MutableSequenceOf[str] | str | None``.
        """
        normalize = FlextLdifServersOudAciMixin.normalize_aci_value_simple
        find_in_dict = FlextLdifServersOudAciMixin._find_aci_in_dict
        for source in (original_attrs, entry_attrs):
            if source:
                raw = source.get("aci")
                if isinstance(raw, list):
                    raw = [u.to_str(item) for item in raw]
                if raw and (values := normalize(raw)):
                    return values
        for source in (original_attrs, entry_attrs):
            if source and (values := find_in_dict(source)):
                return values
        return None

    @staticmethod
    def _aci_from_commented_extensions(
        entry: m.Ldif.Entry,
    ) -> t.MutableSequenceOf[str] | str | None:
        """Find ACI values stored as commented values in entry metadata.

        Returns:
            The resulting ``t.MutableSequenceOf[str] | str | None``.
        """
        extensions = entry.metadata.extensions if entry.metadata is not None else None
        if extensions is None:
            return None
        commented = FlextLdifServersOudAclExtractMixin.parse_commented_values(
            extensions.get(c.Ldif.COMMENTED_ATTRIBUTE_VALUES),
        )
        for key, value in commented.items():
            if key.lower() != "aci":
                continue
            normalized_value = (
                [u.to_str(item) for item in value] if isinstance(value, list) else value
            )
            if values := FlextLdifServersOudAciMixin.normalize_aci_value_simple(
                normalized_value,
            ):
                return values
        return None

    @staticmethod
    def find_aci_values(
        entry: m.Ldif.Entry,
        original_attrs: t.AttributeMapping,
    ) -> t.MutableSequenceOf[str] | str | None:
        """Find ACI values from entry attributes, original_attrs, or commented metadata.

        Returns:
            The resulting ``t.MutableSequenceOf[str] | str | None``.
        """
        entry_attrs = (
            entry.attributes.attributes
            if entry.attributes and entry.attributes.attributes
            else None
        )
        direct = FlextLdifServersOudAciMixin._aci_from_attr_sources(
            original_attrs,
            entry_attrs,
        )
        if direct is not None:
            return direct
        return FlextLdifServersOudAciMixin._aci_from_commented_extensions(entry)

    @staticmethod
    def normalize_aci_value(
        aci_value: str,
        _base_dn: str | None,
        _dn_registry: m.Ldif.DnRegistry | None,
    ) -> tuple[str, bool]:
        """Normalize ACI value DNs (already RFC canonical, no changes needed).

        Returns:
            The resulting ``tuple[str, bool]``.
        """
        return (aci_value, False)

    @staticmethod
    def normalize_aci_value_simple(
        value: t.Ldif.ValueType | t.Ldif.MetadataInputMapping | None,
    ) -> t.MutableSequenceOf[str] | str | None:
        """Normalize ACI value to t.MutableSequenceOf[str] | str | None.

        Returns:
            The resulting ``t.MutableSequenceOf[str] | str | None``.
        """
        if value is None:
            return None
        if isinstance(value, list):
            return [u.to_str(item) for item in value]
        return u.to_str(value)


__all__: list[str] = ["FlextLdifServersOudAciMixin"]
