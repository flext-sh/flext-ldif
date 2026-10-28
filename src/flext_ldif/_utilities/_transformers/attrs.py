"""Attribute normalization step for LDIF entry pipelines.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import MutableMapping

from flext_ldif import m, p, r, t


class FlextLdifUtilitiesTransformersAttrs:
    """Stateless attribute normalization of one LDIF entry."""

    @staticmethod
    def entry_with_attributes(
        entry: m.Ldif.Entry,
        attributes: t.MutableStrSequenceMapping,
    ) -> m.Ldif.Entry:
        """Replace an entry's attribute values, keeping its attribute metadata.

        Returns:
            A copy of ``entry`` carrying ``attributes`` with the original
            per-attribute and container metadata.

        """
        current = entry.attributes
        return entry.model_copy(
            update={
                "attributes": m.Ldif.Attributes.model_validate({
                    "attributes": attributes,
                    "attribute_metadata": (
                        current.attribute_metadata if current is not None else {}
                    ),
                    "metadata": current.metadata if current is not None else None,
                }),
            },
        )

    @staticmethod
    def normalize_entry_attrs(
        item: m.Ldif.Entry,
        *,
        case_fold_names: bool = True,
        trim_values: bool = True,
        remove_empty: bool = False,
    ) -> p.Result[m.Ldif.Entry]:
        """Normalize attribute names and values of one entry.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.

        """
        if item.attributes is None:
            return r[m.Ldif.Entry].fail("Entry has no attributes")
        attrs: t.MutableStrSequenceMapping = item.attributes.attributes
        if case_fold_names:
            attrs = {k.lower(): v for k, v in attrs.items()}
        new_attrs: t.MutableStrSequenceMapping = {}
        for key, values in attrs.items():
            processed = [value.strip() if trim_values else value for value in values]
            new_attrs[key] = [value for value in processed if value or not remove_empty]
        needs_update = (
            case_fold_names or trim_values or remove_empty or (new_attrs != attrs)
        )
        if needs_update:
            update_dict: MutableMapping[str, m.Ldif.Attributes] = {
                "attributes": m.Ldif.Attributes.model_validate({
                    "attributes": new_attrs,
                }),
            }
            item = item.model_copy(update=update_dict)
        return r[m.Ldif.Entry].ok(item)


__all__: list[str] = ["FlextLdifUtilitiesTransformersAttrs"]
