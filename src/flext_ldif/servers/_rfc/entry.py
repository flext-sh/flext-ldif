"""RFC 2849 compliant LDIF entry parser and writer for flext-ldif."""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import override

from flext_core import FlextLogger, r
from flext_ldif import FlextLdifServersBase, m, t, u

logger = FlextLogger(__name__)


class FlextLdifServersRfcEntry(FlextLdifServersBase.Entry):
    """RFC 2849 compliant LDIF entry processing."""

    __doc_inline__ = True

    def _parse_entry_from_lines(
        self,
        lines: MutableSequence[str],
    ) -> r[m.Ldif.Entry]:
        """Parse one unfolded LDIF record using the shared RFC utility."""
        return u.Ldif.parse_ldif_record(lines)

    @override
    def can_handle(
        self,
        entry_dn: str,
        attributes: t.MutableStrSequenceMapping,
    ) -> bool:
        """Check if this RFC quirk can handle the entry."""
        if not entry_dn or not entry_dn.strip():
            return False
        attr_lower = {k.lower(): v for k, v in attributes.items()}
        return "objectclass" in attr_lower or "changetype" in attr_lower

    @override
    def _parse_content(self, ldif_content: str) -> r[MutableSequence[m.Ldif.Entry]]:
        """Parse raw LDIF content string into Entry models."""
        if not ldif_content or not ldif_content.strip():
            return r[MutableSequence[m.Ldif.Entry]].ok([])
        try:
            entries: MutableSequence[m.Ldif.Entry] = []
            for record_lines in u.Ldif.split_ldif_records(ldif_content):
                result = self._parse_entry_from_lines(record_lines)
                if result.is_success:
                    entries.append(result.value)
                    continue
                logger.debug(
                    "Skipping invalid entry block",
                    error=str(result.error) if result.error else "",
                )
            return r[MutableSequence[m.Ldif.Entry]].ok(entries)
        except ValueError as exc:
            logger.exception("Failed to parse LDIF content")
            return r[MutableSequence[m.Ldif.Entry]].fail(
                f"Processing failed: {exc}",
            )


__all__ = ["FlextLdifServersRfcEntry"]
