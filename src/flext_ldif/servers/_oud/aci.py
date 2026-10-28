"""OUD entry — Aci helpers.

Per AGENTS.md §2.3 (MRO Composition) + §3.1 (200-LOC cap): one of the
domain-specific Mixins composed into ``FlextLdifServersOudHelpers``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence

from flext_ldif import c, m, t, u
from flext_ldif.servers._oud import (
    FlextLdifServersOudAciProcess,
    FlextLdifServersOudAclExtract,
)


class FlextLdifServersOudAci(FlextLdifServersOudAciProcess):
    """OUD Aci helpers."""

    @staticmethod
    def _find_aci_in_dict(
        attrs: t.AttributeMapping | None,
    ) -> MutableSequence[str] | str | None:
        """Find ACI value in dictionary (case-insensitive).

        Returns:
            The resulting ``MutableSequence[str] | str | None``.

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
    ) -> MutableSequence[str] | str | None:
        """Find ACI values under the literal or case-insensitive ``aci`` keys.

        Returns:
            The resulting ``MutableSequence[str] | str | None``.

        """
        normalize = FlextLdifServersOudAci.normalize_aci_value_simple
        find_in_dict = FlextLdifServersOudAci._find_aci_in_dict
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
    ) -> MutableSequence[str] | str | None:
        """Find ACI values stored as commented values in entry metadata.

        Returns:
            The resulting ``MutableSequence[str] | str | None``.

        """
        extensions = entry.metadata.extensions if entry.metadata is not None else None
        if extensions is None:
            return None
        commented = FlextLdifServersOudAclExtract.parse_commented_values(
            extensions.get(c.Ldif.COMMENTED_ATTRIBUTE_VALUES),
        )
        if commented is None:
            return None
        for key, value in commented.items():
            if key.lower() != "aci":
                continue
            normalized_value = (
                [u.to_str(item) for item in value] if isinstance(value, list) else value
            )
            if values := FlextLdifServersOudAci.normalize_aci_value_simple(
                normalized_value,
            ):
                return values
        return None

    @staticmethod
    def find_aci_values(
        entry: m.Ldif.Entry,
        original_attrs: t.AttributeMapping,
    ) -> MutableSequence[str] | str | None:
        """Find ACI values from entry attributes, original_attrs, or commented metadata.

        Returns:
            The resulting ``MutableSequence[str] | str | None``.

        """
        entry_attrs = (
            entry.attributes.attributes
            if entry.attributes and entry.attributes.attributes
            else None
        )
        direct = FlextLdifServersOudAci._aci_from_attr_sources(
            original_attrs,
            entry_attrs,
        )
        if direct is not None:
            return direct
        return FlextLdifServersOudAci._aci_from_commented_extensions(entry)

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
        del _base_dn, _dn_registry
        return (aci_value, False)

    @staticmethod
    def normalize_aci_value_simple(
        value: t.Ldif.ValueType | t.Ldif.MetadataInputMapping | None,
    ) -> MutableSequence[str] | str | None:
        """Normalize ACI value to MutableSequence[str] | str | None.

        Returns:
            The resulting ``MutableSequence[str] | str | None``.

        """
        if value is None:
            return None
        if isinstance(value, list):
            return [u.to_str(item) for item in value]
        return u.to_str(value)


__all__: list[str] = ["FlextLdifServersOudAci"]
