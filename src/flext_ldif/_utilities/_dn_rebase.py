"""LDIF entry base-DN rebasing utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldif import FlextLdifModels, c, t

if TYPE_CHECKING:
    from collections.abc import MutableMapping


class FlextLdifDNRebasing:
    """Rebase entry DNs and DN-valued attributes onto a new base DN."""

    @staticmethod
    def _first_rdn_component(dn: str) -> str:
        """Return the leftmost RDN of a DN, honouring escaped separators."""
        index = 0
        while index < len(dn):
            char = dn[index]
            if char == "\\":
                index += 2
                continue
            if char == ",":
                return dn[:index]
            index += 1
        return dn

    @staticmethod
    def _rdn_attribute_pairs(rdn: str) -> list[tuple[str, str]]:
        """Parse an RDN into (attribute, unescaped value) pairs.

        Supports multi-valued RDNs (``cn=a+sn=b``); every component must be a
        ``attribute=value`` pair or the RDN is unparseable (fail loud).

        Returns:
            The resulting ``list[tuple[str, str]]``.

        Raises:
            ValueError: If Unparseable RDN component (missing attribute=value); or if
                Unparseable RDN component (empty attribute).
        """
        from flext_ldif._utilities import FlextLdifDNEscaping

        components: list[str] = []
        current: list[str] = []
        index = 0
        while index < len(rdn):
            char = rdn[index]
            if char == "\\" and index + 1 < len(rdn):
                current.extend((char, rdn[index + 1]))
                index += 2
                continue
            if char == "+":
                components.append("".join(current))
                current = []
                index += 1
                continue
            current.append(char)
            index += 1
        components.append("".join(current))
        pairs: list[tuple[str, str]] = []
        for component in components:
            if "=" not in component:
                msg = (
                    f"Unparseable RDN component "
                    f"(missing attribute=value): {component!r}"
                )
                raise ValueError(msg)
            attribute, _, raw_value = component.partition("=")
            attribute = attribute.strip()
            if not attribute:
                msg = f"Unparseable RDN component (empty attribute): {component!r}"
                raise ValueError(msg)
            pairs.append((attribute, FlextLdifDNEscaping.unesc(raw_value)))
        return pairs

    @staticmethod
    def _modrdn_naming_delta(
        old_dn: str,
        new_dn: str,
    ) -> (
        MutableMapping[str, tuple[t.MutableSequenceOf[str], t.MutableSequenceOf[str]]]
        | None
    ):
        """Compute deleteoldrdn attribute changes when the entry's own RDN changes.

        Returns ``None`` when the leftmost RDN is unchanged (case-insensitive);
        otherwise maps each affected attribute to ``(old_values, new_values)``
        so the caller removes the old pairs and adds the new ones.

        Returns:
            The resulting ``MutableMapping[str, tuple[t.MutableSequenceOf[str],
                t.MutableSequenceOf[str]]] | None``.
        """
        old_rdn = FlextLdifDNRebasing._first_rdn_component(old_dn)
        new_rdn = FlextLdifDNRebasing._first_rdn_component(new_dn)
        if old_rdn.lower() == new_rdn.lower():
            return None
        old_pairs = FlextLdifDNRebasing._rdn_attribute_pairs(old_rdn)
        new_pairs = FlextLdifDNRebasing._rdn_attribute_pairs(new_rdn)
        delta: MutableMapping[
            str,
            tuple[t.MutableSequenceOf[str], t.MutableSequenceOf[str]],
        ] = {}
        for attribute, value in old_pairs:
            removes, _ = delta.setdefault(attribute.lower(), ([], []))
            removes.append(value)
        for attribute, value in new_pairs:
            _, adds = delta.setdefault(attribute.lower(), ([], []))
            adds.append(value)
        return delta

    @staticmethod
    def _rebase_entry_dn(
        entry: FlextLdifModels.Ldif.Entry,
        source_dn: str,
        target_dn: str,
        updates: MutableMapping[
            str,
            FlextLdifModels.Ldif.DN | FlextLdifModels.Ldif.Attributes,
        ],
    ) -> (
        MutableMapping[str, tuple[t.MutableSequenceOf[str], t.MutableSequenceOf[str]]]
        | None
    ):
        """Rewrite the entry DN onto the target base and record the update.

        Returns:
            The resulting ``MutableMapping[str, tuple[t.MutableSequenceOf[str],
                t.MutableSequenceOf[str]]] | None``.
        """
        from flext_ldif._utilities import FlextLdifDNParsing, FlextLdifDNTransforming

        entry_dn = entry.dn
        if entry_dn is None:
            return None
        dn_str = FlextLdifDNParsing.resolve_dn_value(entry_dn)
        if not dn_str:
            return None
        new_dn_str = FlextLdifDNTransforming.transform_dn_attribute(
            dn_str,
            source_dn,
            target_dn,
        )
        if new_dn_str == dn_str:
            return None
        updates["dn"] = FlextLdifModels.Ldif.DN(value=new_dn_str)
        return FlextLdifDNRebasing._modrdn_naming_delta(dn_str, new_dn_str)

    @staticmethod
    def _transform_dn_valued_values(
        values: t.MutableSequenceOf[str],
        source_dn: str,
        target_dn: str,
    ) -> tuple[t.MutableSequenceOf[str], bool]:
        """Transform one attribute's DN values, reporting whether any changed.

        Returns:
            The resulting ``tuple[t.MutableSequenceOf[str], bool]``.
        """
        from flext_ldif._utilities import FlextLdifDNTransforming

        new_values: t.MutableSequenceOf[str] = []
        attr_changed = False
        for val in values:
            new_val = FlextLdifDNTransforming.transform_dn_attribute(
                val,
                source_dn,
                target_dn,
            )
            new_values.append(new_val)
            if new_val != val:
                attr_changed = True
        return (new_values, attr_changed)

    @staticmethod
    def _collect_changed_dn_attrs(
        entry_attrs: FlextLdifModels.Ldif.Attributes,
        attrs_to_transform: frozenset[str] | t.MutableSequenceOf[str],
        source_dn: str,
        target_dn: str,
    ) -> MutableMapping[str, t.MutableSequenceOf[str]]:
        """Transform DN-valued attributes and collect the changed entries.

        Returns:
            The resulting ``MutableMapping[str, t.MutableSequenceOf[str]]``.
        """
        attr_dict = entry_attrs.attributes
        transform_lowers = {a.lower() for a in attrs_to_transform}
        changed_attrs: MutableMapping[str, t.MutableSequenceOf[str]] = {}
        for attr_name, values in attr_dict.items():
            if attr_name.lower() not in transform_lowers:
                continue
            new_values, attr_changed = FlextLdifDNRebasing._transform_dn_valued_values(
                values,
                source_dn,
                target_dn,
            )
            if attr_changed:
                changed_attrs[attr_name] = new_values
        return changed_attrs

    @staticmethod
    def _merge_rdn_delta_values(
        merged_values: t.MutableSequenceOf[str],
        old_values: t.MutableSequenceOf[str],
        new_values_rdn: t.MutableSequenceOf[str],
    ) -> t.MutableSequenceOf[str]:
        """Drop old naming values then append missing new naming values.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        old_lowers = {value.lower() for value in old_values}
        merged = [value for value in merged_values if value.lower() not in old_lowers]
        present_lowers = {value.lower() for value in merged}
        merged.extend(
            value for value in new_values_rdn if value.lower() not in present_lowers
        )
        return merged

    @staticmethod
    def _apply_rdn_delta(
        entry_attrs: FlextLdifModels.Ldif.Attributes,
        rdn_delta: MutableMapping[
            str,
            tuple[t.MutableSequenceOf[str], t.MutableSequenceOf[str]],
        ],
        changed_attrs: MutableMapping[str, t.MutableSequenceOf[str]],
    ) -> None:
        """Apply deleteoldrdn naming-attribute changes to the changed set."""
        attr_dict = entry_attrs.attributes
        for rdn_attr, (old_values, new_values_rdn) in rdn_delta.items():
            existing_key = next(
                (key for key in attr_dict if key.lower() == rdn_attr.lower()),
                rdn_attr,
            )
            merged_values: t.MutableSequenceOf[str] = list(
                changed_attrs.get(
                    existing_key,
                    attr_dict.get(existing_key, []),
                ),
            )
            changed_attrs[existing_key] = FlextLdifDNRebasing._merge_rdn_delta_values(
                merged_values,
                old_values,
                new_values_rdn,
            )

    @staticmethod
    def _apply_changed_attributes(
        entry_attrs: FlextLdifModels.Ldif.Attributes,
        changed_attrs: MutableMapping[str, t.MutableSequenceOf[str]],
        updates: MutableMapping[
            str,
            FlextLdifModels.Ldif.DN | FlextLdifModels.Ldif.Attributes,
        ],
    ) -> None:
        """Record the copied attributes model when any attribute changed."""
        if not changed_attrs:
            return
        new_attr_dict = dict(entry_attrs.attributes)
        new_attr_dict.update(changed_attrs)
        updates["attributes"] = entry_attrs.model_copy(
            update={"attributes": new_attr_dict},
        )

    @staticmethod
    def transform_entry_base_dn(
        entry: FlextLdifModels.Ldif.Entry,
        source_dn: str,
        target_dn: str,
        dn_valued_attributes: frozenset[str] | None = None,
    ) -> FlextLdifModels.Ldif.Entry:
        """Transform an entry's DN and DN-valued attributes from source to target base.

        DN.

        Rewrites:
        - The entry's own DN
        - All attributes whose name is in dn_valued_attributes (member, uniqueMember,
        etc.)

        When the entry's own leftmost RDN changes (a root entry rebased onto a
        different naming value), LDAP modrdn semantics apply to the naming
        attribute values: the old RDN pairs are removed and the new pairs added
        (deleteoldrdn). Descendant entries keep the pure suffix rebase. An
        unparseable changed RDN fails loud with ``ValueError``.

        Returns a model_copy with transformed values. Original entry is not mutated.

        Returns:
            The resulting ``FlextLdifModels.Ldif.Entry``.
        """
        attrs_to_transform = dn_valued_attributes or c.Ldif.ALL_DN_VALUED
        updates: MutableMapping[
            str,
            FlextLdifModels.Ldif.DN | FlextLdifModels.Ldif.Attributes,
        ] = {}
        rdn_delta = FlextLdifDNRebasing._rebase_entry_dn(
            entry,
            source_dn,
            target_dn,
            updates,
        )
        entry_attrs = entry.attributes
        if entry_attrs is not None:
            changed_attrs = FlextLdifDNRebasing._collect_changed_dn_attrs(
                entry_attrs,
                attrs_to_transform,
                source_dn,
                target_dn,
            )
            if rdn_delta is not None:
                FlextLdifDNRebasing._apply_rdn_delta(
                    entry_attrs,
                    rdn_delta,
                    changed_attrs,
                )
            FlextLdifDNRebasing._apply_changed_attributes(
                entry_attrs,
                changed_attrs,
                updates,
            )
        if updates:
            copied: FlextLdifModels.Ldif.Entry = entry.model_copy(update=updates)
            return copied
        return entry


__all__: list[str] = ["FlextLdifDNRebasing"]
