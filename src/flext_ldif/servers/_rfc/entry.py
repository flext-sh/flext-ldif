"""RFC 2849 Compliant LDIF Entry Parser and Writer for flext-ldif.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides RFC 2849 baseline LDIF entry parsing and manipulation.
Server-specific entry handling extends this RFC base implementation.

References:
    - RFC 2849: LDIF Format Specification
    - RFC 4512: LDAP Directory Information Models

"""

from __future__ import annotations

from flext_core import FlextLogger, FlextResult, r

from flext_ldif.models import FlextLdifModels as m
from flext_ldif.servers.base import FlextLdifServersBase

logger = FlextLogger(__name__)


class FlextLdifServersRfcEntry(FlextLdifServersBase.Entry):
    """RFC 2849 Compliant LDIF Entry Processing.

    Provides baseline entry parsing, validation, and manipulation
    following RFC 2849 LDIF format specification.

    Features:
    - RFC 2849 compliant LDIF parsing
    - Entry validation and transformation
    - Safe attribute handling
    - DN normalization

    """

    __doc_inline__ = True

    def __init__(self) -> None:
        """Initialize RFC LDIF Entry processor."""
        super().__init__()

    def _parse_content(self, ldif_content: str) -> FlextResult[list[m.Ldif.Entry]]:
        """Parse raw LDIF content string into Entry models (internal).

        PRIMARY parsing entry point - implements base class abstract method.

        Args:
            ldif_content: Raw LDIF content as string

        Returns:
            FlextResult with list of Entry models

        """
        if not ldif_content or not ldif_content.strip():
            return FlextResult[list[m.Ldif.Entry]].ok([])

        try:
            entries: list[m.Ldif.Entry] = []

            # Split by empty lines to get entry blocks
            raw_entries = ldif_content.strip().split("\n\n")

            for raw_entry in raw_entries:
                if not raw_entry.strip():
                    continue

                # Handle version line (global header)
                lines = raw_entry.strip().split("\n")
                if lines and lines[0].lower().startswith("version:"):
                    lines = lines[1:]
                    if not lines:
                        continue

                # Parse entry from lines
                result = self._parse_entry_from_lines(lines)
                if result.is_success:
                    entries.append(result.unwrap())
                else:
                    logger.warning(
                        "Failed to parse entry block",
                        error=result.error,
                    )

            return FlextResult[list[m.Ldif.Entry]].ok(entries)

        except Exception as e:
            logger.exception("Failed to parse LDIF content")
            return FlextResult[list[m.Ldif.Entry]].fail(f"Processing failed: {e}")

    def _parse_entry_from_lines(self, lines: list[str]) -> FlextResult[m.Ldif.Entry]:
        """Parse entry from LDIF lines.

        Args:
            lines: LDIF lines for a single entry

        Returns:
            FlextResult with parsed Entry

        """
        dn: str = ""
        attrs: dict[str, list[str]] = {}

        for raw_line in lines:
            line = raw_line.rstrip()
            if not line or line.startswith("#"):
                continue

            # Handle line folding (continuation lines start with space)
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

        return self._create_entry(dn, attrs)

    def _create_entry(
        self, dn: str, attributes: dict[str, list[str]]
    ) -> r[m.Ldif.Entry]:
        """Create Entry from DN and attributes.

        Args:
            dn: Distinguished name (RFC 4512 format)
            attributes: LDAP attributes (case-insensitive keys)

        Returns:
            FlextResult containing Entry or error

        """
        if not dn or not isinstance(dn, str):
            return r.fail(f"Invalid DN: {dn}")
        if not isinstance(attributes, dict):
            return r.fail(f"Invalid attributes: {attributes}")

        try:
            entry = m.Ldif.Entry(dn=dn.strip(), attributes=attributes or {})
            return r.ok(entry)
        except Exception as e:
            return r.fail(f"Failed to create entry {dn}: {e}")

    def validate(self, entry: m.Ldif.Entry) -> r[m.Ldif.Entry]:
        """Validate RFC 2849 compliance.

        Args:
            entry: Entry to validate

        Returns:
            FlextResult containing validated Entry or error

        """
        if not entry or not isinstance(entry, m.Ldif.Entry):
            return r.fail(f"Invalid entry: {entry}")
        # Entry.dn is DistinguishedName, not str - check .value
        if not entry.dn or not hasattr(entry.dn, "value"):
            return r.fail(f"Invalid DN in entry: {entry.dn}")
        if not entry.attributes or not isinstance(entry.attributes, dict):
            return r.fail(f"Invalid attributes in entry: {entry.attributes}")

        return r.ok(entry)


__all__ = ["FlextLdifServersRfcEntry"]
