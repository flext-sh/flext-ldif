"""Attribute utilities for RFC 4512 § 2.5 compliance."""

from __future__ import annotations

from flext_ldif import c


class FlextLdifUtilitiesAttribute:
    """Attribute utilities for RFC-compliant attribute operations."""

    @staticmethod
    def validate_attribute_name(attribute_name: str) -> bool:
        """Validate base attribute name against RFC 4512 § 2.5."""
        if not attribute_name:
            return False
        if len(attribute_name) > c.Ldif.MAX_ATTRIBUTE_NAME_LENGTH:
            return False
        return c.Ldif.ATTRIBUTE_NAME_RE.match(attribute_name) is not None


__all__: list[str] = ["FlextLdifUtilitiesAttribute"]
