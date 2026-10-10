"""RFC 2849 compliant LDIF entry parser and writer for flext-ldif.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, override

from flext_ldif import m, p, r, t, u
from flext_ldif.servers._base import FlextLdifServersBaseEntry


class FlextLdifServersRfcEntry(FlextLdifServersBaseEntry):
    """RFC 2849 compliant LDIF entry processing."""

    __doc_inline__ = True

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @override
    def can_handle_attribute(self, attribute: m.Ldif.SchemaAttribute) -> bool:
        """Check if this server can handle a schema attribute.

        Returns:
            The resulting ``bool``.
        """
        return False

    @override
    def can_handle_objectclass(self, objectclass: m.Ldif.SchemaObjectClass) -> bool:
        """Check if this server can handle a schema objectClass.

        Returns:
            The resulting ``bool``.
        """
        return False

    @override
    def _hook_post_parse_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Run hook after parsing an entry.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        return r[m.Ldif.Entry].ok(entry)

    @override
    def _hook_pre_write_entry(self, entry: m.Ldif.Entry) -> p.Result[m.Ldif.Entry]:
        """Run hook before writing an entry.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        return r[m.Ldif.Entry].ok(entry)

    @override
    def _normalize_attribute_name(self, attr_name: str) -> str:
        """Normalize attribute name to RFC 2849 canonical form.

        Returns:
            The resulting ``str``.
        """
        if not attr_name:
            return attr_name
        if attr_name.lower() == "objectclass":
            return "objectClass"
        return attr_name

    @override
    def _parse_entry_from_lines(
        self,
        lines: t.MutableSequenceOf[str],
    ) -> p.Result[m.Ldif.Entry]:
        """Parse one unfolded LDIF record using the shared RFC utility.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        parsed: p.Result[m.Ldif.Entry] = u.Ldif.parse_ldif_record(lines)
        return parsed

    @override
    def can_handle(
        self,
        entry_dn: str,
        attributes: t.MutableStrSequenceMapping,
    ) -> bool:
        """Check if this RFC server can handle the entry.

        Returns:
            The resulting ``bool``.
        """
        if not entry_dn or not entry_dn.strip():
            return False
        attr_lower = {k.lower(): v for k, v in attributes.items()}
        return "objectclass" in attr_lower or "changetype" in attr_lower

    @override
    def _parse_content(
        self,
        ldif_content: str,
    ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Parse raw LDIF content string into Entry models.

        Returns:
            The resulting ``p.Result[t.MutableSequenceOf[m.Ldif.Entry]]``.
        """
        if not ldif_content or not ldif_content.strip():
            return r[t.MutableSequenceOf[m.Ldif.Entry]].ok([])
        try:
            return self._parse_ldif_records(ldif_content)
        except ValueError as exc:
            FlextLdifServersRfcEntry._module_logger.exception(
                "Failed to parse LDIF content",
            )
            return r[t.MutableSequenceOf[m.Ldif.Entry]].fail_op("Processing", exc)

    def _parse_ldif_records(
        self,
        ldif_content: str,
    ) -> p.Result[t.MutableSequenceOf[m.Ldif.Entry]]:
        """Parse all LDIF records from non-empty content.

        Returns:
            The resulting ``p.Result[t.MutableSequenceOf[m.Ldif.Entry]]``.
        """
        entries: t.MutableSequenceOf[m.Ldif.Entry] = []
        for record_lines in u.Ldif.split_ldif_records(ldif_content):
            result = self._parse_entry_from_lines(record_lines)
            if result.success:
                entries.append(result.value)
                continue
            FlextLdifServersRfcEntry._module_logger.debug(
                "Skipping invalid entry block",
                error=result.error or "",
            )
        return r[t.MutableSequenceOf[m.Ldif.Entry]].ok(entries)


__all__: list[str] = ["FlextLdifServersRfcEntry"]
