"""Oracle Internet Directory (OID) entry server — metadata-driven attribute restore.

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

from collections.abc import Mapping

from flext_ldif import m, t, u
from flext_ldif.servers._oid import FlextLdifServersOidEntryBoolean
from flext_ldif.servers._rfc import FlextLdifServersRfcEntry


class FlextLdifServersOidEntryRestore(
    FlextLdifServersOidEntryBoolean,
    FlextLdifServersRfcEntry,
):
    """OID entry round-trip attribute denormalization from metadata."""

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
        return u.Ldif.entry_with_attributes(restored_entry, restored_attrs)


__all__: list[str] = ["FlextLdifServersOidEntryRestore"]
