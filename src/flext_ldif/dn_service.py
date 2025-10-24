r"""DN Service - RFC 4514 Compliant Distinguished Name Operations.

ARCHITECTURAL NOTE: This service uses ldap3.utils.dn for DN format parsing,
which is appropriate as DN parsing is LDIF data format handling (RFC 4514
string representation), NOT LDAP protocol operations. The DN utilities are
data format utilities for processing LDIF files, not LDAP server communication.

This service provides DN operations using ldap3 for RFC 4514 compliance.
Replaces naive DN parsing from utilities.py with proper LDAP DN handling.

RFC 4514: LDAP Distinguished Names String Representation
- Handles escaped characters (\\, \\2C, etc.)
- Handles quoted values ("Smith, John")
- Handles multi-valued RDNs (cn=user+ou=people)
- Handles special characters (+, =, <, >, #, ;)
- Handles UTF-8 encoding

Standardization Architecture:
- flext-ldif: Handles LDIF data format operations (including DN parsing)
- flext-ldap: Handles LDAP protocol operations (server communication)
- client-a-oud-mig: Uses ONLY flext-ldif and flext-ldap, NO direct ldap3 imports

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
from typing import override

from flext_core import FlextDecorators, FlextResult, FlextService
from ldap3.utils.dn import parse_dn, safe_dn

from flext_ldif.constants import FlextLdifConstants


class FlextLdifDnService(FlextService[dict[str, object]]):
    r"""RFC 4514 compliant DN operations using ldap3.

    Provides methods for DN parsing, validation, and normalization
    following RFC 4514 (LDAP Distinguished Names String Representation).

    This service replaces the naive DN parsing from utilities.py which
    violated RFC 4514 by using simple string split operations.

    Example:
        >>> dn_service = FlextLdifDnService()
        >>>
        >>> # Parse DN into components
        >>> result = dn_service.parse_components(
        ...     "cn=Smith\\, John,ou=People,dc=example,dc=com"
        ... )
        >>> if result.is_success:
        >>>     components = result.unwrap()
        >>> # Returns: [(FlextLdifConstants.DictKeys.CN, "Smith, John", "cn=Smith\\, John"), ...]
        >>>
        >>> # Validate DN format
        >>> result = dn_service.validate_format("cn=test,dc=example,dc=com")
        >>> if result.is_success:
        >>>     is_valid = result.unwrap()  # True
        >>>
        >>> # Normalize DN
        >>> result = dn_service.normalize("CN=Admin,DC=Example,DC=Com")
        >>> if result.is_success:
        >>>     normalized = result.unwrap()  # "cn=Admin,dc=Example,dc=Com"

    """

    def __init__(self) -> None:
        """Initialize DN service."""
        super().__init__()

    @override
    @FlextDecorators.log_operation("dn_service_check")
    @FlextDecorators.track_performance()
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute DN service self-check.

        FlextDecorators automatically:
        - Log operation start/completion/failure
        - Track performance metrics
        - Handle context propagation (correlation_id, operation_name)

        Returns:
        FlextResult containing service status

        """
        return FlextResult[dict[str, object]].ok({
            "service": "DnService",
            "status": "operational",
            "rfc_compliance": "RFC 4514",
            "library": "ldap3",
        })

    def parse_components(self, dn: str) -> FlextResult[list[tuple[str, str, str]]]:
        r"""Parse DN into RFC 4514 compliant components using ldap3.

        Uses ldap3.utils.dn.parse_dn() for proper RFC 4514 parsing that handles:
        - Escaped commas: cn=Smith\\, John
        - Quoted values: cn="Smith, John"
        - Multi-valued RDNs: cn=user+ou=people
        - Special characters: +, =, <, >, #, ;
        - UTF-8 encoding
        - Hex escaping: cn=\\23value

        Args:
            dn: Distinguished name string to parse

        Returns:
            FlextResult containing list of (attr, value, rdn) tuples
            where:
            - attr: Attribute name (e.g., FlextLdifConstants.DictKeys.CN)
            - value: Attribute value (e.g., "John Smith")
            - rdn: Full RDN component (e.g., "cn=John Smith")

        Example:
            >>> result = service.parse_components("cn=test,dc=example,dc=com")
            >>> if result.is_success:
            >>>     components = result.unwrap()
            >>> # [(FlextLdifConstants.DictKeys.CN, "test", "cn=test"), ("dc", "example", "dc=example"), ...]

        """
        try:
            # Use ldap3 for RFC 4514 compliant parsing
            components = parse_dn(dn, escape=False, strip=True)
            return FlextResult[list[tuple[str, str, str]]].ok(components)
        except Exception as e:
            return FlextResult[list[tuple[str, str, str]]].fail(
                f"Invalid DN format (RFC 4514): {e}"
            )

    def validate_format(self, dn: str) -> FlextResult[bool]:
        r"""Validate DN format against RFC 4514 using ldap3.

        Uses ldap3.utils.dn.parse_dn() to validate DN syntax.
        A valid DN must parse successfully according to RFC 4514.

        Args:
            dn: Distinguished name string to validate

        Returns:
            FlextResult containing True if valid, False otherwise

        Example:
            >>> result = service.validate_format("cn=test,dc=example,dc=com")
            >>> if result.is_success:
            >>>     is_valid = result.unwrap()  # True
            >>>
            >>> result = service.validate_format("invalid dn")
            >>> if result.is_success:
            >>>     is_valid = result.unwrap()  # False

        """
        if not dn:
            return FlextResult[bool].ok(False)

        try:
            # Try parsing - if it succeeds, DN is valid per RFC 4514
            parse_dn(dn, escape=False, strip=True)
            return FlextResult[bool].ok(True)
        except Exception:
            return FlextResult[bool].ok(False)

    def normalize(self, dn: str) -> FlextResult[str]:
        r"""Normalize DN using RFC 4514 compliant normalization via ldap3.

        Uses ldap3.utils.dn.safe_dn() for proper RFC 4514 normalization:
        - Lowercases attribute names
        - Preserves case in attribute values
        - Handles escaped characters
        - Handles quoted values
        - Handles special characters
        - Handles UTF-8 encoding

        Args:
            dn: Distinguished name string to normalize

        Returns:
            FlextResult containing normalized DN string

        Example:
            >>> result = service.normalize("CN=Admin,DC=Example,DC=Com")
            >>> if result.is_success:
            >>>     normalized = result.unwrap()
            >>> # Returns: "cn=Admin,dc=Example,dc=Com"
            >>> # Note: Attribute names lowercased, values preserved

        """
        try:
            # Use ldap3 for RFC 4514 compliant normalization
            normalized = safe_dn(dn)
            return FlextResult[str].ok(str(normalized))
        except Exception as e:
            return FlextResult[str].fail(f"Failed to normalize DN (RFC 4514): {e}")

    @staticmethod
    def clean_dn(dn: str) -> str:
        r"""Clean a DN string to be RFC 4514 compliant.

        This method fixes common DN formatting issues found in LDAP exports:
        - Removes spaces around '=' in RDN components
        - Fixes malformed backslash escapes
        - Removes trailing backslash+space patterns
        - Normalizes whitespace

        Args:
            dn: The original DN string

        Returns:
            Cleaned DN string

        Example:
            >>> DnService.clean_dn("cn = John, ou = Users")
            'cn=John,ou=Users'
            >>> DnService.clean_dn("cn=OIM-TEST\\ ,ou=Users")
            'cn=OIM-TEST,ou=Users'

        """
        if not dn:
            return dn

        # Remove spaces around '=' in each RDN component
        # Pattern: "cn = value" -> "cn=value"
        cleaned = re.sub(
            FlextLdifConstants.DnPatterns.DN_SPACES_AROUND_EQUALS,
            FlextLdifConstants.DnPatterns.DN_EQUALS,
            dn,
        )

        # Fix trailing backslash+space before commas
        # Pattern: "cn=VALUE\ ," -> "cn=VALUE,"
        # This is a common OID export issue where trailing spaces are escaped
        cleaned = re.sub(
            FlextLdifConstants.DnPatterns.DN_TRAILING_BACKSLASH_SPACE,
            FlextLdifConstants.DnPatterns.DN_COMMA,
            cleaned,
        )

        # Normalize spaces around commas: ", cn=..." -> ",cn=..."
        cleaned = re.sub(
            FlextLdifConstants.DnPatterns.DN_SPACES_AROUND_COMMA,
            FlextLdifConstants.DnPatterns.DN_COMMA,
            cleaned,
        )

        # Fix malformed backslash escapes in middle of values (e.g., "\ " -> " ")
        # Common in OID exports where spaces are unnecessarily escaped
        cleaned = re.sub(FlextLdifConstants.DnPatterns.DN_BACKSLASH_SPACE, " ", cleaned)

        # Remove unnecessary character escapes (RFC 4514 compliance)
        # Only these need escaping: , + " \ < > ; (and leading/trailing spaces, leading #)
        # Remove backslash before characters that don't need escaping (e.g., \- \. \_ etc.)
        # Pattern: \X where X is NOT a special character -> X
        cleaned = re.sub(
            FlextLdifConstants.DnPatterns.DN_UNNECESSARY_ESCAPES, r"\1", cleaned
        )

        # Normalize multiple spaces to single space
        cleaned = re.sub(FlextLdifConstants.DnPatterns.DN_MULTIPLE_SPACES, " ", cleaned)

        return cleaned.strip()

    def build_canonical_dn_map(
        self, categorized: dict[str, list[dict[str, object]]]
    ) -> FlextResult[dict[str, str]]:
        """Build mapping of lowercase(cleaned DN) -> canonical cleaned DN.

        Uses clean_dn to normalize formatting and ensures
        case-consistent canonical values based on parsed entries.

        Args:
            categorized: Dictionary mapping category to entry list

        Returns:
            FlextResult containing dictionary mapping lowercase cleaned DN to canonical cleaned DN

        """
        dn_map: dict[str, str] = {}
        for entries in categorized.values():
            for entry in entries:
                if isinstance(entry, dict):
                    dn_value = entry.get(FlextLdifConstants.DictKeys.DN)
                    if isinstance(dn_value, str) and dn_value:
                        cleaned = self.clean_dn(dn_value)
                        if cleaned:
                            dn_map[cleaned.lower()] = cleaned
        return FlextResult[dict[str, str]].ok(dn_map)

    def normalize_dn_value(self, value: str, dn_map: dict[str, str]) -> str:
        """Normalize a single DN value using canonical map, fallback to cleaned DN.

        Args:
            value: DN value to normalize
            dn_map: Canonical DN mapping

        Returns:
            Normalized DN value

        """
        cleaned = self.clean_dn(value)
        return dn_map.get(cleaned.lower(), cleaned)

    def normalize_dn_references_for_entry(
        self,
        entry: dict[str, object],
        dn_map: dict[str, str],
        ref_attrs_lower: set[str],
    ) -> FlextResult[dict[str, object]]:
        """Normalize DN-valued attributes in an entry according to dn_map.

        Handles both str and list[str] attribute values.

        Args:
            entry: Entry to normalize
            dn_map: Canonical DN mapping
            ref_attrs_lower: Set of lowercase DN reference attribute names

        Returns:
            FlextResult containing entry with normalized DN attributes

        """
        try:
            normalized = entry.copy()
            attrs = normalized.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
            if not isinstance(attrs, dict):
                return FlextResult[dict[str, object]].ok(normalized)

            new_attrs: dict[str, object] = {}
            for attr_name, attr_value in attrs.items():
                if attr_name.lower() in ref_attrs_lower:
                    if isinstance(attr_value, list):
                        new_attrs[attr_name] = [
                            self.normalize_dn_value(v, dn_map)
                            if isinstance(v, str)
                            else v
                            for v in attr_value
                        ]
                    elif isinstance(attr_value, str):
                        new_attrs[attr_name] = self.normalize_dn_value(
                            attr_value, dn_map
                        )
                    else:
                        new_attrs[attr_name] = attr_value
                else:
                    new_attrs[attr_name] = attr_value

            normalized[FlextLdifConstants.DictKeys.ATTRIBUTES] = new_attrs
            return FlextResult[dict[str, object]].ok(normalized)
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to normalize DN references: {e}"
            )

    def normalize_aci_dn_references(
        self, entry: dict[str, object], dn_map: dict[str, str]
    ) -> FlextResult[dict[str, object]]:
        """Normalize DNs embedded in ACI attribute strings using dn_map.

        Attempts to detect DN substrings in common OUD ACI patterns and
        replace them with canonical DNs.

        Args:
            entry: Entry with ACI attributes to normalize
            dn_map: Canonical DN mapping

        Returns:
            FlextResult containing entry with normalized ACI DN references

        """
        try:
            attrs = entry.get(FlextLdifConstants.DictKeys.ATTRIBUTES, {})
            if not isinstance(attrs, dict):
                return FlextResult[dict[str, object]].ok(entry)

            def normalize_in_text(text: str) -> str:
                """Normalize DNs in ACI text."""

                def repl_ldap(m: re.Match[str]) -> str:
                    dn_part = m.group(1)
                    norm = self.normalize_dn_value(dn_part, dn_map)
                    return f"ldap:///{norm}"

                text2 = re.sub(
                    FlextLdifConstants.DnPatterns.ACI_LDAP_URL_PATTERN, repl_ldap, text
                )

                # Also handle bare quoted DN-like sequences (best-effort)
                def repl_quoted(m: re.Match[str]) -> str:
                    dn_part = m.group(1)
                    norm = self.normalize_dn_value(dn_part, dn_map)
                    return f'"{norm}"'

                return re.sub(
                    FlextLdifConstants.DnPatterns.ACI_QUOTED_DN_PATTERN,
                    repl_quoted,
                    text2,
                )

            aci_value = attrs.get("aci")
            if isinstance(aci_value, list):
                attrs["aci"] = [
                    normalize_in_text(v) if isinstance(v, str) else v for v in aci_value
                ]
            elif isinstance(aci_value, str):
                attrs["aci"] = normalize_in_text(aci_value)

            entry_out = entry.copy()
            entry_out[FlextLdifConstants.DictKeys.ATTRIBUTES] = attrs
            return FlextResult[dict[str, object]].ok(entry_out)
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to normalize ACI DN references: {e}"
            )


__all__ = ["FlextLdifDnService"]
