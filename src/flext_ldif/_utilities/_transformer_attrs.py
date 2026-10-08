"""Attribute normalization step for LDIF entry pipelines.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import r
from flext_ldif import m, p, t

if TYPE_CHECKING:
    from collections.abc import MutableMapping


class FlextLdifUtilitiesEntryAttrsNormalization:
    """Stateless attribute normalization of one LDIF entry."""

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


__all__: list[str] = ["FlextLdifUtilitiesEntryAttrsNormalization"]
