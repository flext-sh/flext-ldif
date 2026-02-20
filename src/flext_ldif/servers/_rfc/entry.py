"""RFC 2849 Compliant LDIF Entry Parser and Writer for flext-ldif."""

from __future__ import annotations

from flext_core import FlextLogger, FlextResult, r

from flext_ldif.models import FlextLdifModels as m
from flext_ldif.servers.base import FlextLdifServersBase

logger = FlextLogger(__name__)


class FlextLdifServersRfcEntry(FlextLdifServersBase.Entry):
    """RFC 2849 Compliant LDIF Entry Processing."""

    __doc_inline__ = True

    def __init__(self) -> None:
        """Initialize RFC LDIF Entry processor."""
        super().__init__()

    def can_handle(
        self,
        entry_dn: str,
        attributes: dict[str, list[str]],
    ) -> bool:
        """Check if this RFC quirk can handle the entry."""
        if not entry_dn or not entry_dn.strip():
            return False

        attr_lower = {k.lower(): v for k, v in attributes.items()}
        return "objectclass" in attr_lower

    def _parse_content(self, ldif_content: str) -> FlextResult[list[m.Ldif.Entry]]:
        """Parse raw LDIF content string into Entry models (internal)."""
        if not ldif_content or not ldif_content.strip():
            return FlextResult[list[m.Ldif.Entry]].ok([])

        try:
            entries: list[m.Ldif.Entry] = []

            raw_entries = ldif_content.strip().split("\n\n")

            for raw_entry in raw_entries:
                if not raw_entry.strip():
                    continue

                lines = raw_entry.strip().split("\n")
                if lines and lines[0].lower().startswith("version:"):
                    lines = lines[1:]
                    if not lines:
                        continue

                result = self._parse_entry_from_lines(lines)
                if result.is_success:
                    entries.append(result.value)
                else:
                    logger.debug(
                        "Skipping invalid entry block",
                        error=result.error,
                    )

            return FlextResult[list[m.Ldif.Entry]].ok(entries)

        except Exception as e:
            logger.exception("Failed to parse LDIF content")
            return FlextResult[list[m.Ldif.Entry]].fail(f"Processing failed: {e}")

    def _parse_entry_from_lines(self, lines: list[str]) -> FlextResult[m.Ldif.Entry]:
        """Parse entry from LDIF lines."""
        dn: str = ""
        attrs: dict[str, list[str]] = {}
        original_content_lines: list[str] = []

        for raw_line in lines:
            line = raw_line.rstrip()
            if not line or line.startswith("#"):
                continue
            original_content_lines.append(line)

            if line.startswith(" ") and attrs:
                last_key = list(attrs.keys())[-1]
                if attrs[last_key]:
                    attrs[last_key][-1] += line[1:]
                continue

            if ":" not in line:
                continue

            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()

            if key.lower() == "dn":
                dn = value
            else:
                if key not in attrs:
                    attrs[key] = []
                attrs[key].append(value)

        if not dn:
            return FlextResult[m.Ldif.Entry].fail("No DN found in entry")

        create_result = self._create_entry(dn, attrs)
        if create_result.is_failure:
            return create_result

        entry = create_result.value
        if entry.metadata is None:
            entry.metadata = m.Ldif.QuirkMetadata.create_for("rfc")

        original_ldif = "\n".join(original_content_lines)
        if original_ldif:
            entry.metadata.original_strings["entry_original_ldif"] = original_ldif
        entry.metadata.original_strings["dn_original"] = dn

        return FlextResult[m.Ldif.Entry].ok(entry)

    def _create_entry(
        self,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> r[m.Ldif.Entry]:
        """Create Entry from DN and attributes."""
        if not dn or not isinstance(dn, str):
            return r[m.Ldif.Entry].fail(f"Invalid DN: {dn}")
        if not isinstance(attributes, dict):
            return r[m.Ldif.Entry].fail(f"Invalid attributes: {attributes}")

        try:
            entry = m.Ldif.Entry(
                dn=m.Ldif.DN(value=dn.strip()),
                attributes=m.Ldif.Attributes(attributes=attributes or {}),
            )
            return r[m.Ldif.Entry].ok(entry)
        except Exception as e:
            return r[m.Ldif.Entry].fail(f"Failed to create entry {dn}: {e}")

    def validate_entry(self, entry: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Validate RFC 2849 compliance."""
        if not entry or not isinstance(entry, m.Ldif.Entry):
            return r[m.Ldif.Entry].fail(f"Invalid entry: {entry}")

        if not entry.dn or not hasattr(entry.dn, "value"):
            return r[m.Ldif.Entry].fail(f"Invalid DN in entry: {entry.dn}")
        if not entry.attributes or not isinstance(entry.attributes, dict):
            return r[m.Ldif.Entry].fail(
                f"Invalid attributes in entry: {entry.attributes}"
            )

        return r[m.Ldif.Entry].ok(entry)


__all__ = ["FlextLdifServersRfcEntry"]
