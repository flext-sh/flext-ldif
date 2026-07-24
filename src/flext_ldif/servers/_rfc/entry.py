"""RFC 2849 compliant LDIF entry parser and writer for flext-ldif."""

from __future__ import annotations

from typing import ClassVar, override

from flext_ldif import p, r, t, u
from flext_ldif.servers.base import FlextLdifServersBase


class FlextLdifServersRfcEntry(FlextLdifServersBase.Entry):
    """RFC 2849 compliant LDIF entry processing."""

    __doc_inline__ = True

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    def _parse_entry_from_lines(
        self, lines: t.MutableSequenceOf[str]
    ) -> p.Result[p.Ldif.Entry]:
        """Parse one unfolded LDIF record using the shared RFC utility."""
        parsed: p.Result[p.Ldif.Entry] = u.Ldif.parse_ldif_record(lines)
        return parsed

    @override
    def can_handle(
        self, entry_dn: str, attributes: t.MutableStrSequenceMapping
    ) -> bool:
        """Check if this RFC server can handle the entry."""
        if not entry_dn or not entry_dn.strip():
            return False
        attr_lower = {k.lower(): v for k, v in attributes.items()}
        return "objectclass" in attr_lower or "changetype" in attr_lower

    @override
    def _parse_content(
        self, ldif_content: str
    ) -> p.Result[t.MutableSequenceOf[p.Ldif.Entry]]:
        """Parse raw LDIF content string into Entry models."""
        if not ldif_content or not ldif_content.strip():
            return r[t.MutableSequenceOf[p.Ldif.Entry]].ok([])
        try:
            return self._parse_ldif_records(ldif_content)
        except ValueError as exc:
            FlextLdifServersRfcEntry._module_logger.exception(
                "Failed to parse LDIF content"
            )
            return r[t.MutableSequenceOf[p.Ldif.Entry]].fail_op("Processing", exc)

    def _parse_ldif_records(
        self, ldif_content: str
    ) -> p.Result[t.MutableSequenceOf[p.Ldif.Entry]]:
        """Parse all LDIF records from non-empty content."""
        entries: t.MutableSequenceOf[p.Ldif.Entry] = []
        for record_lines in u.Ldif.split_ldif_records(ldif_content):
            result = self._parse_entry_from_lines(record_lines)
            if result.success:
                entries.append(result.value)
                continue
            FlextLdifServersRfcEntry._module_logger.debug(
                "Skipping invalid entry block", error=result.error or ""
            )
        return r[t.MutableSequenceOf[p.Ldif.Entry]].ok(entries)


__all__: list[str] = ["FlextLdifServersRfcEntry"]
