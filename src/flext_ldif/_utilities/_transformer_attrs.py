"""Attribute normalization transformer."""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from flext_ldif import FlextLdifModels as m, p, r, t
from flext_ldif._utilities._transformer_base import FlextLdifUtilitiesTransformer

if TYPE_CHECKING:
    from collections.abc import MutableMapping


class FlextLdifUtilitiesNormalizeAttrsTransformer(
    FlextLdifUtilitiesTransformer[p.Ldif.Entry],
):
    """Transformer for attribute normalization."""

    __slots__ = ("_case_fold_names", "_remove_empty", "_trim_values")

    def __init__(
        self,
        *,
        case_fold_names: bool = True,
        trim_values: bool = True,
        remove_empty: bool = False,
    ) -> None:
        """Initialize attribute normalization transformer."""
        super().__init__()
        self._case_fold_names = case_fold_names
        self._trim_values = trim_values
        self._remove_empty = remove_empty

    @override
    def apply(self, item: p.Ldif.Entry) -> p.Result[p.Ldif.Entry]:
        """Apply attribute normalization to an entry."""
        if item.attributes is None:
            return r[p.Ldif.Entry].fail("Entry has no attributes")
        attrs: t.MutableStrSequenceMapping = (
            item.attributes.attributes
            if getattr(item.attributes, "attributes", None) is not None
            else {}
        )
        if self._case_fold_names:
            attrs = {k.lower(): v for k, v in attrs.items()}
        new_attrs = {
            key: self._process_value_list(value) for key, value in attrs.items()
        }
        needs_update = (
            self._case_fold_names
            or self._trim_values
            or self._remove_empty
            or (new_attrs != attrs)
        )
        if needs_update:
            update_dict: MutableMapping[str, p.Ldif.Attributes] = {
                "attributes": m.Ldif.Attributes.model_validate({
                    "attributes": new_attrs,
                }),
            }
            item = item.model_copy(update=update_dict)
        return r[p.Ldif.Entry].ok(item)

    def _process_value_list(
        self,
        values: t.MutableSequenceOf[str],
    ) -> t.MutableSequenceOf[str]:
        """Process a single attribute's values."""
        processed: t.MutableSequenceOf[str] = []
        for value_item in values:
            trimmed_value = value_item.strip() if self._trim_values else value_item
            if self._remove_empty and (not trimmed_value):
                continue
            processed.append(trimmed_value)
        return processed


__all__: list[str] = ["FlextLdifUtilitiesNormalizeAttrsTransformer"]
