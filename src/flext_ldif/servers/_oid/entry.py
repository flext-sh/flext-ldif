"""Oracle Internet Directory (OID) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, override

from flext_ldif import m, p, t, u
from flext_ldif.servers._oid import (
    FlextLdifServersOidEntryNormalizeMixin,
    FlextLdifServersOidEntryParseMixin,
    FlextLdifServersOidEntryRestoreMixin,
)
from flext_ldif.servers._rfc import FlextLdifServersRfcEntry


class FlextLdifServersOidEntry(
    FlextLdifServersOidEntryParseMixin,
    FlextLdifServersOidEntryRestoreMixin,
    FlextLdifServersOidEntryNormalizeMixin,
    FlextLdifServersRfcEntry,
):
    """Oracle Internet Directory (OID) Entry implementation.

    OID-specific behavior is composed from focused mixins: boolean value
    conversion (``entry_boolean``), metadata extraction (``entry_metadata``),
    parse hooks (``entry_parse``), round-trip attribute restore
    (``entry_restore``), and schema value normalization (``entry_normalize``).
    The OID ACL attributes (``orclaci``/``orclentrylevelaci``) keep their names
    through parse and write; only OID→OUD conversion renames them to ``aci``.
    """

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @override
    def _parse_entry_from_lines(
        self,
        lines: t.MutableSequenceOf[str],
    ) -> p.Result[m.Ldif.Entry]:
        """Parse entry from LDIF lines, apply OID→RFC normalization, finalize metadata.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.

        """
        result = super()._parse_entry_from_lines(lines)
        if result.failure:
            return result
        entry = result.value
        if entry.dn and str(entry.dn):
            original_dn = str(entry.dn)
            cleaned_dn, _ = u.Ldif.clean_dn_with_statistics(original_dn)
            if cleaned_dn != original_dn:
                entry.dn = m.Ldif.DN.model_validate({"value": cleaned_dn})
        finalize_result = self._hook_finalize_entry_parse(
            entry,
            str(entry.dn) if entry.dn else "",
        )
        if finalize_result.failure:
            return finalize_result
        return self._hook_post_parse_entry(finalize_result.value)

    @override
    def _write_entry(self, entry_data: m.Ldif.Entry) -> p.Result[str]:
        """Write OID entry preserving OID-specific denormalized attribute names.

        Returns:
            The resulting ``p.Result[str]``.

        """
        entry_to_write = self.restore_entry_from_metadata(entry_data)
        return super()._write_entry(entry_to_write)


__all__: list[str] = ["FlextLdifServersOidEntry"]
