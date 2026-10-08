"""Oracle Internet Directory (OID) entry server — metadata-driven attribute restore.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping

from flext_ldif import c, m, t
from flext_ldif.servers._oid.entry_boolean import FlextLdifServersOidEntryBooleanMixin
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOidEntryRestoreMixin(
    FlextLdifServersOidEntryBooleanMixin,
    FlextLdifServersRfc.Entry,
):
    """OID entry round-trip attribute denormalization from metadata."""

    def _denormalize_oid_attributes_for_output(
        self,
        attrs: t.MutableStrSequenceMapping,
        metadata: m.Ldif.ServerMetadata | None,
    ) -> t.MutableStrSequenceMapping:
        """Denormalize RFC attributes to OID format.

        Returns:
            The resulting ``t.MutableStrSequenceMapping``.
        """
        mk = c.Ldif
        original_attrs_raw = (
            metadata.extensions.get(mk.ORIGINAL_ATTRIBUTES_COMPLETE)
            if metadata and metadata.extensions
            else None
        )
        original_attrs_value: t.JsonPayload | None = original_attrs_raw
        original_attrs: t.MutableStrSequenceMapping | None = None
        if isinstance(original_attrs_value, Mapping):
            result_attrs: t.MutableStrSequenceMapping = {}
            for k, v in original_attrs_value.items():
                if isinstance(v, list):
                    result_attrs[k] = [str(item) for item in v]
                else:
                    result_attrs[k] = [str(v)]
            original_attrs = result_attrs
        denormalized: t.MutableStrSequenceMapping = {}
        for attr_name, attr_values in attrs.items():
            restored_name, restored_values = self._restore_single_attribute(
                attr_name,
                attr_values,
                original_attrs,
            )
            denormalized[restored_name] = restored_values
        return denormalized

    def restore_entry_from_metadata(self, entry_data: m.Ldif.Entry) -> m.Ldif.Entry:
        """Restore OID-specific formats from metadata (RFC → OID denormalization).

        Returns:
            The resulting ``m.Ldif.Entry``.
        """
        restored_entry = self._restore_boolean_values_to_oid(entry_data)
        metadata = restored_entry.metadata
        attributes = restored_entry.attributes
        if metadata is None or attributes is None:
            return restored_entry
        rename_map_raw = metadata.extensions.get("attribute_name_renames")
        rename_map: t.JsonPayload | None = rename_map_raw
        if not isinstance(rename_map, Mapping) or not rename_map:
            return restored_entry
        restored_attrs = dict(attributes.attributes)
        changed = False
        for current_name, original_name in rename_map.items():
            if not isinstance(original_name, str):
                continue
            current_values = restored_attrs.pop(current_name, None)
            if current_values is None or original_name in restored_attrs:
                continue
            restored_attrs[original_name] = list(current_values)
            changed = True
        if not changed:
            return restored_entry
        restored_copy: m.Ldif.Entry = restored_entry.model_copy(
            update={
                "attributes": m.Ldif.Attributes.model_validate({
                    "attributes": restored_attrs,
                    "attribute_metadata": attributes.attribute_metadata,
                    "metadata": attributes.metadata,
                }),
            },
        )
        return restored_copy

    def _restore_single_attribute(
        self,
        attr_name: str,
        attr_values: t.MutableSequenceOf[str],
        original_attrs: t.MutableStrSequenceMapping | None,
    ) -> tuple[str, t.MutableSequenceOf[str]]:
        """Restore attribute from metadata or apply denormalization.

        Returns:
            The resulting ``tuple[str, t.MutableSequenceOf[str]]``.
        """
        from flext_ldif.servers._oid.server_constants import (
            FlextLdifServersOidConstants,
        )

        if original_attrs:
            for orig_name, orig_values in original_attrs.items():
                if self._normalize_attribute_name(orig_name) == attr_name:
                    restored_values = list(orig_values)
                    return (orig_name, restored_values)
        denorm_name = (
            FlextLdifServersOidConstants.ORCLACI
            if attr_name.lower()
            == FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME.lower()
            else attr_name
        )
        return (denorm_name, attr_values)


__all__: list[str] = ["FlextLdifServersOidEntryRestoreMixin"]
