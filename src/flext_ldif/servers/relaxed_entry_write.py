"""Relaxed entry server — lenient LDIF write side.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_ldif import c, m, p, r, t
from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry


class FlextLdifServersRelaxedEntryWriteMixin(FlextLdifServersRfcEntry):
    """Relaxed entry write side and predicate hooks for lenient processing."""

    @override
    def can_handle(
        self,
        entry_dn: str,
        attributes: t.MutableStrSequenceMapping,
    ) -> bool:
        """Accept any entry in relaxed mode.

        Returns:
            The resulting ``bool``.
        """
        _ = entry_dn
        _ = attributes
        return True

    @override
    def can_handle_attribute(self, attribute: m.Ldif.SchemaAttribute) -> bool:
        """Check if this Entry server has special attribute handling.

        Returns:
            The resulting ``bool``.
        """
        _ = attribute
        return True

    @override
    def can_handle_objectclass(self, objectclass: m.Ldif.SchemaObjectClass) -> bool:
        """Check if this Entry server has special objectClass handling.

        Returns:
            The resulting ``bool``.
        """
        _ = objectclass
        return True

    @staticmethod
    def process_entry(entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Process entry for relaxed mode.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        return r[m.Ldif.Entry].ok(entry)

    @override
    def _write_entry(self, entry_data: m.Ldif.Entry) -> p.Result[str]:
        """Write Entry model to RFC-compliant LDIF string format (internal).

        Returns:
            The resulting ``p.Result[str]``.
        """
        parent_result = super()._write_entry(entry_data)
        if parent_result.success:
            return parent_result
        self.logger.debug(
            "RFC write failed, using relaxed mode: %s",
            parent_result.error,
        )
        try:
            return self._write_relaxed_entry(entry_data)
        except c.Ldif.EXC_LDIF_PARSE as e:
            self.logger.debug("Write entry failed: %s", e)
            return r[str].fail(f"Failed to write entry: {e}", exception=e)

    @staticmethod
    def _write_relaxed_entry(entry_data: m.Ldif.Entry) -> p.Result[str]:
        """Write entry in relaxed LDIF format.

        Returns:
            The resulting ``p.Result[str]``.
        """
        from flext_ldif.servers._relaxed.server_constants import (
            FlextLdifServersRelaxedConstants,
        )

        ldif_lines: t.MutableSequenceOf[str] = []
        if not entry_data.dn or not entry_data.dn.value:
            return r[str].fail("Entry DN is required for LDIF output")
        ldif_lines.append(
            f"{FlextLdifServersRelaxedConstants.LDIF_DN_PREFIX}{entry_data.dn.value}",
        )
        if entry_data.attributes and entry_data.attributes.attributes:
            for attr_name, attr_values in entry_data.attributes.attributes.items():
                ldif_lines.extend(
                    f"{attr_name}{FlextLdifServersRelaxedConstants.LDIF_ATTR_SEPARATOR}{value}"
                    for value in attr_values
                )
        ldif_text = FlextLdifServersRelaxedConstants.LDIF_JOIN_SEPARATOR.join(
            ldif_lines,
        )
        if ldif_text and (
            not ldif_text.endswith(FlextLdifServersRelaxedConstants.LDIF_NEWLINE)
        ):
            ldif_text += FlextLdifServersRelaxedConstants.LDIF_NEWLINE
        return r[str].ok(ldif_text)


__all__: list[str] = ["FlextLdifServersRelaxedEntryWriteMixin"]
