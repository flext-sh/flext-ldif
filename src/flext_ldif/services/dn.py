r"""DN Operations - RFC 4514 Compliant Distinguished Name Service and Case Registry.

ARCHITECTURAL NOTE: This service uses ldap3.utils.dn for DN format parsing,
which is appropriate as DN parsing is LDIF data format handling (RFC 4514
string representation), NOT LDAP protocol operations. The DN utilities are
data format utilities for processing LDIF files, not LDAP server communication.

This module provides:
1. FlextLdifDnService: RFC 4514 compliant DN operations (parsing, validation, normalization)
2. FlextLdifDnService.CaseRegistry: Case tracking registry for server conversions

RFC 4514: LDAP Distinguished Names String Representation
- Handles escaped characters (\\, \\2C, etc.)
- Handles quoted values ("Smith, John")
- Handles multi-valued RDNs (cn=user+ou=people)
- Handles special characters (+, =, <, >, #, ;)
- Handles UTF-8 encoding

Standardization Architecture:
- flext-ldif: Handles LDIF data format operations (including DN parsing)
- flext-ldap: Handles LDAP protocol operations (server communication)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
import string
from typing import override

from flext_core import FlextDecorators, FlextModels, FlextResult, FlextService
from ldap3.core.exceptions import LDAPInvalidDnError
from ldap3.utils.dn import parse_dn, safe_dn
from pydantic import ConfigDict

from flext_ldif.constants import FlextLdifConstants

type DN = str


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
        except (ValueError, TypeError, AttributeError, LDAPInvalidDnError) as e:
            return FlextResult[list[tuple[str, str, str]]].fail(
                f"Invalid DN format (RFC 4514): {e}",
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
        except (ValueError, TypeError, AttributeError, LDAPInvalidDnError):
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
        except (ValueError, TypeError, AttributeError, LDAPInvalidDnError) as e:
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

        # Remove spaces ONLY BEFORE '=' in each RDN component
        # RFC 4514: "cn = value" -> "cn=value" but "cn=Example Corporation" stays as is
        # Pattern matches spaces before equals, but NOT spaces after (which are part of the value)
        cleaned = re.sub(
            r"\s+=",  # Only spaces BEFORE equals
            "=",
            dn,
        )

        # Fix trailing backslash+space before commas
        # Pattern: "cn=VALUE\ ," -> "cn=VALUE,"
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

        # Fix malformed backslash escapes ONLY in specific contexts
        # RFC 4514: Spaces in the middle of values don't need escaping
        # Only fix trailing "\ ," patterns, not all "\ " patterns
        # This preserves legitimate spaces like in "o=Example Corporation"

        # Remove unnecessary character escapes (RFC 4514 compliance)
        # Only these need escaping: , + " \ < > ; (and leading/trailing spaces, leading #)
        # Remove backslash before characters that don't need escaping (e.g., \- \. \_ etc.)
        # Pattern: \X where X is NOT a special character -> X
        cleaned = re.sub(
            FlextLdifConstants.DnPatterns.DN_UNNECESSARY_ESCAPES,
            r"\1",
            cleaned,
        )

        # Normalize multiple spaces to single space
        cleaned = re.sub(FlextLdifConstants.DnPatterns.DN_MULTIPLE_SPACES, " ", cleaned)

        return cleaned.strip()

    @staticmethod
    def escape_dn_value(value: str) -> str:
        r"""Escape special characters in DN value per RFC 4514.

        RFC 4514 requires escaping of these characters: , + " \ < > ; #
        Also escapes leading/trailing spaces.

        Escaping uses backslash format: \XX where XX is hex code.

        Args:
            value: DN attribute value to escape

        Returns:
            Escaped DN value per RFC 4514

        Example:
            >>> FlextLdifDnService.escape_dn_value("Smith, John")
            'Smith\\, John'
            >>> FlextLdifDnService.escape_dn_value("User #1")
            'User \\#1'
            >>> FlextLdifDnService.escape_dn_value(" leading space")
            '\\ leading space'

        """
        if not value:
            return value

        # Characters requiring escape per RFC 4514
        # (comma, plus, quote, backslash, less, greater, semicolon, hash)
        escape_chars = {",", "+", '"', "\\", "<", ">", ";", "#"}

        result: list[str] = []
        for i, char in enumerate(value):
            # Check if character needs escaping
            if char in escape_chars:
                # Use hex escape format
                result.append(f"\\{ord(char):02x}")
            elif (i == 0 or i == len(value) - 1) and char == " ":
                # Escape leading/trailing spaces
                result.append(f"\\{ord(char):02x}")
            else:
                result.append(char)

        return "".join(result)

    @staticmethod
    def unescape_dn_value(value: str) -> str:
        r"""Unescape special characters in DN value per RFC 4514.

        Handles both hex escape format (\XX) and backslash escape format (\char).
        Reverses the escaping done by escape_dn_value().

        Args:
            value: Escaped DN attribute value

        Returns:
            Unescaped DN value

        Example:
            >>> FlextLdifDnService.unescape_dn_value("Smith\\2c John")
            'Smith, John'
            >>> FlextLdifDnService.unescape_dn_value("User \\#1")
            'User #1'
            >>> FlextLdifDnService.unescape_dn_value("\\ leading space")
            ' leading space'

        """
        if not value or "\\" not in value:
            return value

        result: list[str] = []
        i = 0
        while i < len(value):
            if value[i] == "\\" and i + 1 < len(value):
                # Check if next two chars are hex digits
                if i + 2 < len(value) and all(
                    c in string.hexdigits for c in value[i + 1 : i + 3]
                ):
                    # Hex escape format: \XX
                    hex_code = value[i + 1 : i + 3]
                    result.append(chr(int(hex_code, 16)))
                    i += 3
                else:
                    # Single character escape: \c
                    result.append(value[i + 1])
                    i += 2
            else:
                result.append(value[i])
                i += 1

        return "".join(result)

    @staticmethod
    def hex_escape(value: str) -> str:
        r"""Escape entire string to hex format per RFC 4514.

        Converts every character to \XX hex format.
        This is more aggressive than escape_dn_value() which only escapes special chars.

        Args:
            value: String to convert to hex escape format

        Returns:
            String with all characters in \XX format

        Example:
            >>> FlextLdifDnService.hex_escape("abc")
            '\\61\\62\\63'
            >>> FlextLdifDnService.hex_escape("test#1")
            '\\74\\65\\73\\74\\23\\31'

        """
        if not value:
            return value

        return "".join(f"\\{ord(char):02x}" for char in value)

    @staticmethod
    def hex_unescape(value: str) -> str:
        r"""Unescape hex format string per RFC 4514.

        Converts \XX hex format back to characters.
        Reverses the encoding done by hex_escape().

        Args:
            value: String in \XX hex escape format

        Returns:
            Decoded string

        Example:
            >>> FlextLdifDnService.hex_unescape("\\61\\62\\63")
            'abc'
            >>> FlextLdifDnService.hex_unescape("\\74\\65\\73\\74\\23\\31")
            'test#1'

        """
        if not value or "\\" not in value:
            return value

        result: list[str] = []
        i = 0
        while i < len(value):
            if value[i] == "\\" and i + 2 < len(value):
                # Try to parse hex code
                hex_part = value[i + 1 : i + 3]
                if all(c in string.hexdigits for c in hex_part):
                    result.append(chr(int(hex_part, 16)))
                    i += 3
                else:
                    # Not valid hex, include as-is
                    result.append(value[i])
                    i += 1
            else:
                result.append(value[i])
                i += 1

        return "".join(result)

    def compare_dns(self, dn1: str, dn2: str) -> FlextResult[int]:
        r"""Compare two DNs per RFC 4514 (case-insensitive).

        Performs RFC 4514 compliant DN comparison using ldap3's safe_dn()
        to normalize both DNs before comparison.

        Comparison rules (per RFC 4514):
        - Case-insensitive (attribute names and values)
        - Space-insensitive (spaces around commas and equals)
        - Handles escaped characters correctly

        Args:
            dn1: First Distinguished Name to compare
            dn2: Second Distinguished Name to compare

        Returns:
            FlextResult containing:
            - -1 if dn1 < dn2
            - 0 if dn1 == dn2
            - 1 if dn1 > dn2

        Example:
            >>> service = FlextLdifDnService()
            >>> result = service.compare_dns(
            ...     "cn=Admin,dc=example,dc=com", "CN=ADMIN,DC=EXAMPLE,DC=COM"
            ... )
            >>> if result.is_success:
            >>>     comparison = result.unwrap()
            >>>     if comparison == 0:
            >>>         print("DNs are equivalent")

        """
        try:
            # Normalize both DNs using RFC 4514 normalization
            norm1_result = self.normalize(dn1)
            norm2_result = self.normalize(dn2)

            if norm1_result.is_failure or norm2_result.is_failure:
                return FlextResult[int].fail(
                    "Cannot compare invalid DNs (RFC 4514)",
                )

            norm1 = norm1_result.unwrap()
            norm2 = norm2_result.unwrap()

            # Case-insensitive comparison using lowercase normalized DNs
            norm1_lower = norm1.lower()
            norm2_lower = norm2.lower()

            if norm1_lower < norm2_lower:
                return FlextResult[int].ok(-1)
            if norm1_lower > norm2_lower:
                return FlextResult[int].ok(1)
            return FlextResult[int].ok(0)

        except (ValueError, TypeError, AttributeError, LDAPInvalidDnError) as e:
            return FlextResult[int].fail(f"DN comparison failed: {e}")

    def parse_rdn(self, rdn: str) -> FlextResult[list[tuple[str, str]]]:
        r"""Parse a single RDN (Relative Distinguished Name) component per RFC 4514.

        An RDN can contain multiple attribute-value pairs separated by '+'.
        Example: "cn=John+ou=people" is one RDN with two attribute-value pairs.

        This method parses a single RDN string and returns all attribute-value pairs
        it contains.

        Args:
            rdn: Single RDN component string (e.g., "cn=John+ou=people")

        Returns:
            FlextResult containing list of (attribute, value) tuples

        Example:
            >>> service = FlextLdifDnService()
            >>>
            >>> # Simple RDN
            >>> result = service.parse_rdn("cn=John")
            >>> if result.is_success:
            >>>     pairs = result.unwrap()
            >>> # [(cn, John)]
            >>>
            >>> # Multi-valued RDN
            >>> result = service.parse_rdn("cn=John+ou=people")
            >>> if result.is_success:
            >>>     pairs = result.unwrap()
            >>> # [(cn, John), (ou, people)]
            >>>
            >>> # Escaped special characters
            >>> result = service.parse_rdn(r"cn=Smith\, John")
            >>> if result.is_success:
            >>>     pairs = result.unwrap()
            >>> # [(cn, Smith, John)]

        """
        if not rdn or not isinstance(rdn, str):
            return FlextResult[list[tuple[str, str]]].fail(
                "RDN must be a non-empty string",
            )

        try:
            pairs: list[tuple[str, str]] = []
            current_attr = ""
            current_val = ""
            in_value = False
            i = 0

            while i < len(rdn):
                char = rdn[i]

                # Handle escape sequence
                if char == "\\" and i + 1 < len(rdn):
                    next_char = rdn[i + 1]
                    # Check if it's a hex escape (\XX)
                    if i + 2 < len(rdn) and all(
                        c in string.hexdigits for c in rdn[i + 1 : i + 3]
                    ):
                        # Hex escape
                        current_val += rdn[i : i + 3]
                        i += 3
                    else:
                        # Single character escape
                        current_val += next_char
                        i += 2
                    continue

                # Handle equals (attribute-value separator)
                if char == "=" and not in_value:
                    current_attr = current_attr.strip().lower()
                    if not current_attr:
                        return FlextResult[list[tuple[str, str]]].fail(
                            "Empty attribute name in RDN",
                        )
                    in_value = True
                    i += 1
                    continue

                # Handle plus (multi-valued RDN separator)
                if char == "+" and in_value:
                    # Save current pair
                    current_val = current_val.strip()
                    if current_attr:
                        pairs.append((current_attr, current_val))
                    # Reset for next pair
                    current_attr = ""
                    current_val = ""
                    in_value = False
                    i += 1
                    continue

                # Accumulate character
                if in_value:
                    current_val += char
                else:
                    current_attr += char

                i += 1

            # Handle final pair
            if not in_value or not current_attr:
                return FlextResult[list[tuple[str, str]]].fail(
                    "Invalid RDN format (incomplete attribute-value pair)",
                )

            current_val = current_val.strip()
            # RFC 4514: Value cannot be empty
            if not current_val:
                return FlextResult[list[tuple[str, str]]].fail(
                    "Invalid RDN format (empty attribute value)",
                )
            pairs.append((current_attr, current_val))

            return FlextResult[list[tuple[str, str]]].ok(pairs)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[tuple[str, str]]].fail(
                f"RDN parsing failed: {e}",
            )

    def build_canonical_dn_map(
        self,
        categorized: dict[str, list[dict[str, object]]],
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
                            (
                                self.normalize_dn_value(v, dn_map)
                                if isinstance(v, str)
                                else v
                            )
                            for v in attr_value
                        ]
                    elif isinstance(attr_value, str):
                        new_attrs[attr_name] = self.normalize_dn_value(
                            attr_value,
                            dn_map,
                        )
                    else:
                        new_attrs[attr_name] = attr_value
                else:
                    new_attrs[attr_name] = attr_value

            normalized[FlextLdifConstants.DictKeys.ATTRIBUTES] = new_attrs
            return FlextResult[dict[str, object]].ok(normalized)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to normalize DN references: {e}",
            )

    def normalize_aci_dn_references(
        self,
        entry: dict[str, object],
        dn_map: dict[str, str],
    ) -> FlextResult[dict[str, object]]:
        """Normalize DNs embedded in ACI attribute strings using dn_map.

        Attempts to detect DN substrings in ACI patterns and
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
                    FlextLdifConstants.DnPatterns.ACI_LDAP_URL_PATTERN,
                    repl_ldap,
                    text,
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

            # Check all ACL attributes using constants
            for acl_attr in FlextLdifConstants.AclAttributes.ALL_ACL_ATTRIBUTES:
                aci_value = attrs.get(acl_attr)
                if aci_value:
                    if isinstance(aci_value, list):
                        attrs[acl_attr] = [
                            normalize_in_text(v) if isinstance(v, str) else v
                            for v in aci_value
                        ]
                    elif isinstance(aci_value, str):
                        attrs[acl_attr] = normalize_in_text(aci_value)

            entry_out = entry.copy()
            entry_out[FlextLdifConstants.DictKeys.ATTRIBUTES] = attrs
            return FlextResult[dict[str, object]].ok(entry_out)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to normalize ACI DN references: {e}",
            )

    class CaseRegistry(FlextModels.Value):
        """Registry for tracking canonical DN case during conversions.

        This class maintains a mapping of DNs in normalized form (lowercase, no spaces)
        to their canonical case representation. It's used during server conversions to
        ensure DN case consistency.

        Examples:
            >>> registry = FlextLdifDnService.CaseRegistry()
            >>>
            >>> # Register canonical case
            >>> canonical = registry.register_dn("CN=Admin, DC=Example, DC=Com")
            >>> # Returns: "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
            >>>
            >>> # Get canonical case for variant
            >>> registry.get_canonical_dn("cn=ADMIN,dc=example,dc=com")
            >>> # Returns: "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
            >>>
            >>> # Validate consistency
            >>> result = registry.validate_oud_consistency()
            >>> # Returns: FlextResult[bool]

        Attributes:
            _registry: Dict mapping normalized DN → canonical DN
            _case_variants: Dict tracking all case variants seen for each normalized DN

        """

        # Allow mutation for internal state management
        model_config = ConfigDict(frozen=False)

        def __init__(self) -> None:
            """Initialize empty DN case registry."""
            super().__init__()
            self._registry: dict[str, str] = {}
            self._case_variants: dict[str, set[str]] = {}

        def _normalize_dn(self, dn: str) -> str:
            """Normalize DN for case-insensitive comparison.

            Normalization rules:
            - Convert to lowercase
            - Remove all spaces
            - Preserve structure (commas, equals)

            Args:
                dn: Distinguished Name to normalize

            Returns:
                Normalized DN string

            Examples:
                >>> registry._normalize_dn("CN=Test, DC=Example, DC=Com")
                'cn=test,dc=example,dc=com'
                >>> registry._normalize_dn("cn = REDACTED_LDAP_BIND_PASSWORD , dc = com")
                'cn=REDACTED_LDAP_BIND_PASSWORD,dc=com'

            """
            return dn.lower().replace(" ", "")

        def register_dn(self, dn: str, *, force: bool = False) -> str:
            """Register DN and return its canonical case.

            If this is the first time seeing this DN (normalized), it becomes
            the canonical case. If seen before, returns the existing canonical case.

            Args:
                dn: Distinguished Name to register
                force: If True, override existing canonical case with this one

            Returns:
                Canonical case DN string

            Examples:
                >>> registry = FlextLdifDnService.CaseRegistry()
                >>> registry.register_dn(
                ...     "CN=Admin,DC=Com"
                ... )  # First seen - becomes canonical
                'CN=Admin,DC=Com'
                >>> registry.register_dn(
                ...     "cn=REDACTED_LDAP_BIND_PASSWORD,dc=com"
                ... )  # Returns existing canonical
                'CN=Admin,DC=Com'
                >>> registry.register_dn(
                ...     "cn=ADMIN,dc=COM", force=True
                ... )  # Force new canonical
                'cn=ADMIN,dc=COM'

            """
            normalized = self._normalize_dn(dn)

            # Track this case variant
            if normalized not in self._case_variants:
                self._case_variants[normalized] = set()
            self._case_variants[normalized].add(dn)

            # Register or return canonical case
            if normalized not in self._registry or force:
                self._registry[normalized] = dn

            return self._registry[normalized]

        def get_canonical_dn(self, dn: str) -> str | None:
            """Get canonical case for a DN (case-insensitive lookup).

            Args:
                dn: Distinguished Name to lookup

            Returns:
                Canonical case DN string, or None if not registered

            Examples:
                >>> registry = FlextLdifDnService.CaseRegistry()
                >>> registry.register_dn("CN=Admin,DC=Com")
                >>> registry.get_canonical_dn("cn=ADMIN,dc=com")
                'CN=Admin,DC=Com'
                >>> registry.get_canonical_dn("cn=Unknown,dc=com")
                None

            """
            normalized = self._normalize_dn(dn)
            return self._registry.get(normalized)

        def has_dn(self, dn: str) -> bool:
            """Check if DN is registered (case-insensitive).

            Args:
                dn: Distinguished Name to check

            Returns:
                True if DN is registered, False otherwise

            Examples:
                >>> registry = FlextLdifDnService.CaseRegistry()
                >>> registry.register_dn("CN=Admin,DC=Com")
                >>> registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
                True
                >>> registry.has_dn("cn=Other,dc=com")
                False

            """
            normalized = self._normalize_dn(dn)
            return normalized in self._registry

        def get_case_variants(self, dn: str) -> set[str]:
            """Get all case variants seen for a DN.

            Args:
                dn: Distinguished Name to get variants for

            Returns:
                Set of all case variants seen (including canonical)

            Examples:
                >>> registry = FlextLdifDnService.CaseRegistry()
                >>> registry.register_dn("CN=Admin,DC=Com")
                >>> registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
                >>> registry.register_dn("cn=ADMIN,dc=COM")
                >>> registry.get_case_variants("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
                {'CN=Admin,DC=Com', 'cn=REDACTED_LDAP_BIND_PASSWORD,dc=com', 'cn=ADMIN,dc=COM'}

            """
            normalized = self._normalize_dn(dn)
            return self._case_variants.get(normalized, set())

        def validate_oud_consistency(self) -> FlextResult[bool]:
            """Validate DN case consistency for server conversion.

            Verifies that all references to the same DN use the same case.
            This method checks if any DNs have multiple case variants, which would
            cause problems when converting between case-sensitive servers.

            Returns:
                FlextResult[bool]:
                    - Success with True if all DNs have consistent case
                    - Success with False if inconsistencies found (with warnings in metadata)
                    - Failure if validation cannot be performed

            Examples:
                >>> registry = FlextLdifDnService.CaseRegistry()
                >>> registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
                >>> result = registry.validate_oud_consistency()
                >>> result.unwrap()  # True - only one case variant

                >>> registry.register_dn("CN=Admin,DC=Com")  # Different case
                >>> result = registry.validate_oud_consistency()
                >>> result.is_success  # True but with warnings
                >>> result.unwrap()  # False - multiple case variants

            """
            inconsistencies: list[dict[str, object]] = []

            for normalized_dn, variants in self._case_variants.items():
                if len(variants) > 1:
                    canonical = self._registry[normalized_dn]
                    inconsistencies.append({
                        "normalized_dn": normalized_dn,
                        "canonical_case": canonical,
                        "variants": list(variants),
                        "variant_count": len(variants),
                    })

            if inconsistencies:
                warning_msg = (
                    f"Found {len(inconsistencies)} DNs with case inconsistencies. "
                    "These will be normalized to canonical case. "
                    f"Example: {inconsistencies[0]['canonical_case']} has "
                    f"{inconsistencies[0]['variant_count']} variants."
                )
                result = FlextResult[bool].ok(False)
                result.metadata = {
                    "inconsistencies": inconsistencies,
                    "warning": warning_msg,
                }
                return result

            return FlextResult[bool].ok(True)

        def normalize_dn_references(
            self,
            data: dict[str, object],
            dn_fields: list[str] | None = None,
        ) -> FlextResult[dict[str, object]]:
            """Normalize DN references in data to use canonical case.

            This method searches through a dictionary and normalizes any DN values
            to use their canonical case from the registry. Useful for normalizing
            ACL "by" clauses, group memberships, etc.

            Args:
                data: Dictionary containing potential DN references
                dn_fields: List of field names that contain DNs (e.g., [FlextLdifConstants.DictKeys.DN, FlextLdifConstants.DnValuedAttributes.MEMBER, "uniqueMember"])
                        If None, uses default DN fields

            Returns:
                FlextResult containing normalized data dictionary

            Examples:
                >>> registry = FlextLdifDnService.CaseRegistry()
                >>> registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
                >>>
                >>> entry = {
                ...     FlextLdifConstants.DictKeys.DN: "CN=Admin,DC=Com",
                ...     FlextLdifConstants.DnValuedAttributes.MEMBER: [
                ...         "cn=ADMIN,dc=com"
                ...     ],
                ... }
                >>> result = registry.normalize_dn_references(
                ...     entry,
                ...     [
                ...         FlextLdifConstants.DictKeys.DN,
                ...         FlextLdifConstants.DnValuedAttributes.MEMBER,
                ...     ],
                ... )
                >>> normalized = result.unwrap()
                >>> normalized
                {FlextLdifConstants.DictKeys.DN: 'cn=REDACTED_LDAP_BIND_PASSWORD,dc=com', FlextLdifConstants.DnValuedAttributes.MEMBER: ['cn=REDACTED_LDAP_BIND_PASSWORD,dc=com']}

            """
            if dn_fields is None:
                # Default DN fields to normalize
                dn_fields = [
                    FlextLdifConstants.DictKeys.DN,
                    FlextLdifConstants.DnValuedAttributes.MEMBER,
                    "uniqueMember",
                    "owner",
                    "seeAlso",
                    "secretary",
                    "manager",
                    "roleOccupant",
                    "by",  # ACL by clause
                ]

            try:
                normalized_data = data.copy()

                for field in dn_fields:
                    if field not in normalized_data:
                        continue

                    value = normalized_data[field]

                    # Handle string DN
                    if isinstance(value, str):
                        canonical = self.get_canonical_dn(value)
                        if canonical is not None:
                            normalized_data[field] = canonical

                    # Handle list of DNs
                    elif isinstance(value, list):
                        normalized_list = []
                        for item in value:
                            if isinstance(item, str):
                                canonical = self.get_canonical_dn(item)
                                normalized_list.append(
                                    canonical if canonical is not None else item,
                                )
                            else:
                                normalized_list.append(item)
                        normalized_data[field] = normalized_list

                return FlextResult[dict[str, object]].ok(normalized_data)

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[dict[str, object]].fail(
                    f"Failed to normalize DN references: {e}",
                )

        def clear(self) -> None:
            """Clear all DN registrations.

            Useful when starting a new conversion to avoid DN pollution
            from previous operations.

            Examples:
                >>> registry = FlextLdifDnService.CaseRegistry()
                >>> registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
                >>> registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
                True
                >>> registry.clear()
                >>> registry.has_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
                False

            """
            self._registry.clear()
            self._case_variants.clear()

        def get_stats(self) -> dict[str, int]:
            """Get registry statistics.

            Returns:
                Dictionary with registry statistics

            Examples:
                >>> registry = FlextLdifDnService.CaseRegistry()
                >>> registry.register_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=com")
                >>> registry.register_dn("CN=Admin,DC=Com")
                >>> registry.get_stats()
                {
                    'total_dns': 1,
                    'total_variants': 2,
                    'dns_with_multiple_variants': 1
                }

            """
            total_variants = sum(
                len(variants) for variants in self._case_variants.values()
            )
            multiple_variants = sum(
                1 for variants in self._case_variants.values() if len(variants) > 1
            )

            return {
                "total_dns": len(self._registry),
                "total_variants": total_variants,
                "dns_with_multiple_variants": multiple_variants,
            }


__all__ = ["FlextLdifDnService"]
