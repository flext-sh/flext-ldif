"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

from flext_ldif import c, p, r, t


class FlextLdifUtilitiesOID:
    """OID extraction and validation utilities."""

    @staticmethod
    def extract_from_definition(definition: str) -> p.Result[str]:
        """Extract OID from schema definition string."""
        match = c.Ldif.SCHEMA_OID_CAPTURE_RE.search(definition)
        if match:
            return r[str].ok(match.group(1))
        return r[str].fail(f"missing an OID in definition: {definition!r}")

    @staticmethod
    def matches_pattern(definition: str, oid_pattern: t.Ldif.RegexPattern) -> bool:
        r"""Check if schema definition string matches server's OID pattern.

        Generic method for checking if a schema definition matches an OID pattern.
        Works with raw definition strings BEFORE parsing.

        Args:
            definition: Raw attribute or objectClass definition string
            oid_pattern: Compiled ``t.Ldif.RegexPattern`` (build via
                ``c.Ldif.compile_pattern(...)`` — never call ``re.compile``
                directly).

        Returns:
            True if OID matches pattern, False otherwise.

        """
        return FlextLdifUtilitiesOID.extract_from_definition(definition).map_or(
            False,
            lambda oid: bool(oid_pattern.match(oid)),
        )

    @staticmethod
    def validate_format(oid: str) -> p.Result[bool]:
        """Validate OID format compliance with LDAP OID syntax."""
        if not oid:
            return r[bool].ok(False)
        try:
            valid = bool(c.Ldif.NUMERIC_OID_RE.match(oid))
        except c.Ldif.EXC_LDIF_PARSE as e:
            return r[bool].fail(f"Failed to validate OID format: {e}")
        return r[bool].ok(valid)


__all__: list[str] = ["FlextLdifUtilitiesOID"]
