"""RFC 2849 compliant LDIF entry parser and writer for flext-ldif.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import ClassVar, override

from flext_ldif import c, p, r, t, u
from flext_ldif.servers._base import FlextLdifServersBaseEntry


class FlextLdifServersRfcEntry(
    FlextLdifServersBaseEntry,
):
    """RFC 2849 compliant LDIF entry processing."""

    __doc_inline__ = True

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @override
    def can_handle_attribute(self, attribute: p.Ldif.SchemaAttribute) -> bool:
        """Check if this server can handle a schema attribute.

        Returns:
            The resulting ``bool``.

        """
        del attribute
        return False

    @override
    def can_handle_objectclass(self, objectclass: p.Ldif.SchemaObjectClass) -> bool:
        """Check if this server can handle a schema objectClass.

        Returns:
            The resulting ``bool``.

        """
        del objectclass
        return False

    @override
    def _hook_post_parse_entry(self, entry: p.Ldif.Entry) -> p.Result[p.Ldif.Entry]:
        """Run hook after parsing an entry.

        Returns:
            The resulting ``p.Result[p.Ldif.Entry]``.

        """
        return r[p.Ldif.Entry].ok(entry)

    @override
    def _hook_pre_write_entry(self, entry: p.Ldif.Entry) -> p.Result[p.Ldif.Entry]:
        """Run hook before writing an entry.

        Returns:
            The resulting ``p.Result[p.Ldif.Entry]``.

        """
        return r[p.Ldif.Entry].ok(entry)

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
        lines: MutableSequence[str],
    ) -> p.Result[p.Ldif.Entry]:
        """Parse one unfolded LDIF record using the shared RFC utility.

        Returns:
            The resulting ``p.Result[p.Ldif.Entry]``.

        """
        parsed: p.Result[p.Ldif.Entry] = u.Ldif.parse_ldif_record(lines)
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
    ) -> p.Result[MutableSequence[p.Ldif.Entry]]:
        """Parse raw LDIF content string into Entry models.

        Returns:
            The resulting ``p.Result[MutableSequence[p.Ldif.Entry]]``.

        """
        if not ldif_content or not ldif_content.strip():
            return r[MutableSequence[p.Ldif.Entry]].ok([])
        try:
            return self._parse_ldif_records(ldif_content)
        except ValueError as exc:
            FlextLdifServersRfcEntry._module_logger.exception(
                "Failed to parse LDIF content",
            )
            return r[MutableSequence[p.Ldif.Entry]].fail_op("Processing", exc)

    def _parse_ldif_records(
        self,
        ldif_content: str,
    ) -> p.Result[MutableSequence[p.Ldif.Entry]]:
        """Parse all LDIF records from non-empty content.

        A record that cannot become an entry fails the whole parse with the
        cause and the physical line number of the offending line, or of the
        record's first line when no single line is at fault.

        Returns:
            The resulting ``p.Result[MutableSequence[p.Ldif.Entry]]``.

        """
        entries: MutableSequence[p.Ldif.Entry] = []
        for record in u.Ldif.split_numbered_records(ldif_content):
            result = self._parse_entry_from_lines([line for _, line in record])
            if result.failure:
                line_index = (result.error_data or {}).get(c.Ldif.RECORD_LINE_INDEX)
                offending = line_index if isinstance(line_index, int) else 0
                line_number = record[offending][0]
                position = f"LDIF line {line_number}: "
                return r[MutableSequence[p.Ldif.Entry]].from_failure(
                    result.map_error(position.__add__),
                )
            entries.append(result.value)
        return r[MutableSequence[p.Ldif.Entry]].ok(entries)


__all__: list[str] = ["FlextLdifServersRfcEntry"]
