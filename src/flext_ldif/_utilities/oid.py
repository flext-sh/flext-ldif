"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import re

from flext_ldif import r


class FlextLdifUtilitiesOID:
    """OID extraction and validation utilities."""

    @staticmethod
    def extract_from_definition(definition: str) -> r[str]:
        """Extract OID from schema definition string."""
        match = re.search(r"\(\s*([\d.]+)", definition)
        if match:
            return r[str].ok(match.group(1))
        return r[str].fail(f"missing an OID in definition: {definition!r}")

    @staticmethod
    def matches_pattern(definition: str, oid_pattern: re.Pattern[str]) -> bool:
        r"""Check if schema definition string matches server's OID pattern.

        Generic method for checking if a schema definition matches an OID pattern.
        Works with raw definition strings BEFORE parsing.

        This is a pure utility function with no dependencies on quirks or services.

        Example:
            # Check if attribute matches Oracle OID pattern
            if FlextLdifUtilitiesOID.matches_pattern(
                attr_definition,  # Raw string: "( 2.16.840.1.113894.1.1.1 ...)"
                re.compile(r'2\\.16\\.840\\.1\\.113894\\..*')  # Oracle OID pattern
            ):
                # Handle Oracle-specific attribute

        Args:
            definition: Raw attribute or objectClass definition string
            oid_pattern: Compiled regex pattern to match OID (e.g., re.compile(r'2\\\\.16\\\\.840\\\\..*'))

        Returns:
            True if OID matches pattern, False otherwise

        """
        return FlextLdifUtilitiesOID.extract_from_definition(definition).map_or(
            False,
            lambda oid: bool(oid_pattern.match(oid)),
        )

    @staticmethod
    def validate_format(oid: str) -> r[bool]:
        """Validate OID format compliance with LDAP OID syntax."""
        if not oid:
            return r[bool].ok(False)
        oid_pattern = "^[0-2](\\.[0-9]+)*$"
        try:
            valid = bool(re.match(oid_pattern, oid))
            return r[bool].ok(valid)
        except (TypeError, re.error) as e:
            return r[bool].fail(f"Failed to validate OID format: {e}")


__all__: list[str] = ["FlextLdifUtilitiesOID"]
