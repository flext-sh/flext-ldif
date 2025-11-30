"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import dataclasses
import re
import string
from collections.abc import Generator
from pathlib import Path
from typing import overload

from flext_core import FlextResult

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


@dataclasses.dataclass
class _TransformationFlags:
    """Type-safe container for DN transformation flags."""

    had_tab_chars: bool = False
    had_trailing_spaces: bool = False
    had_leading_spaces: bool = False
    had_extra_spaces: bool = False
    was_base64_encoded: bool = False
    had_utf8_chars: bool = False
    had_escape_sequences: bool = False
    validation_status: str = ""
    validation_warnings: list[str] = dataclasses.field(default_factory=list)
    validation_errors: list[str] = dataclasses.field(default_factory=list)


# Type alias from FlextLdifTypes
DnInput = str  # DN input is a string


class FlextLdifUtilitiesDN:
    r"""RFC 4514 DN Operations - STRICT Implementation.

    RFC 4514 ABNF Grammar (Section 2):
    ==================================
    distinguishedName = [ relativeDistinguishedName
                         *( COMMA relativeDistinguishedName ) ]
    relativeDistinguishedName = attributeTypeAndValue
                         *( PLUS attributeTypeAndValue )
    attributeTypeAndValue = attributeType EQUALS attributeValue
    attributeType = descr / numericoid
    attributeValue = string / hexstring

    String Encoding (Section 2.4):
    ==============================
    string = [ ( leadchar / pair ) [ *( stringchar / pair )
               ( trailchar / pair ) ] ]
    leadchar = LUTF1 / UTFMB  ; not SPACE, not '#', not special
    trailchar = TUTF1 / UTFMB  ; not SPACE
    stringchar = SUTF1 / UTFMB

    Escape Mechanism:
    =================
    pair = ESC ( ESC / special / hexpair )
    special = escaped / SPACE / SHARP / EQUALS  ; Rfc.DN_SPECIAL_CHARS
    escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE
              ; Rfc.DN_ESCAPED_CHARS
    hexstring = SHARP 1*hexpair
    hexpair = HEX HEX

    Character Classes (FlextLdifConstants.Rfc):
    ============================================
    LUTF1  = %x01-1F / %x21 / %x24-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
             ; Rfc.DN_LUTF1_EXCLUDE
    TUTF1  = %x01-1F / %x21 / %x23-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
             ; Rfc.DN_TUTF1_EXCLUDE
    SUTF1  = %x01-21 / %x23-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
             ; Rfc.DN_SUTF1_EXCLUDE
    COMMA  = %x2C  ; Rfc.DN_RDN_SEPARATOR
    PLUS   = %x2B  ; Rfc.DN_MULTIVALUE_SEPARATOR
    EQUALS = %x3D  ; Rfc.DN_ATTR_VALUE_SEPARATOR
    SPACE  = %x20
    SHARP  = %x23  ; '#'
    ESC    = %x5C  ; '\'

    Escaping Rules (FlextLdifConstants.Rfc):
    ========================================
    - Characters always requiring escaping: Rfc.DN_ESCAPE_CHARS
    - Characters requiring escaping at start: Rfc.DN_ESCAPE_AT_START
    - Characters requiring escaping at end: Rfc.DN_ESCAPE_AT_END

    Metadata Keys (FlextLdifConstants.Rfc):
    =======================================
    - META_DN_ORIGINAL: Original DN before normalization
    - META_DN_WAS_BASE64: DN was base64 encoded
    - META_DN_ESCAPES_APPLIED: Escape sequences used

    All methods return primitives (str, list, tuple, bool, int, None).
    Pure functions: no server-specific logic, no side effects.

    Supports both:
    - FlextLdifModels.DistinguishedName (DN model)
    - str (DN string value)

    """

    # Minimum length for valid DN strings (to check trailing escape)
    MIN_DN_LENGTH: int = 2

    # ==========================================================================
    # RFC 4514 Character Class Validation (ABNF-based)
    # ==========================================================================

    @staticmethod
    def is_lutf1_char(char: str) -> bool:
        """Check if char is valid LUTF1 (lead char) per RFC 4514.

        LUTF1 = %x01-1F / %x21 / %x24-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
        (excludes NUL, SPACE, DQUOTE, SHARP, PLUS, COMMA, SEMI, LANGLE, RANGLE, ESC)

        Uses FlextLdifConstants.Rfc.DN_LUTF1_EXCLUDE for exclusion set.

        Args:
            char: Single character to validate

        Returns:
            True if char is valid LUTF1, False otherwise

        """
        if not char or len(char) != 1:
            return False
        code = ord(char)
        # Must be in ASCII range 0x01-0x7F and not in exclusion set
        safe_min = FlextLdifConstants.Rfc.SAFE_CHAR_MIN
        safe_max = FlextLdifConstants.Rfc.SAFE_CHAR_MAX
        if code < safe_min or code > safe_max:
            return False
        return code not in FlextLdifConstants.Rfc.DN_LUTF1_EXCLUDE

    @staticmethod
    def is_tutf1_char(char: str) -> bool:
        """Check if char is valid TUTF1 (trail char) per RFC 4514.

        TUTF1 = %x01-1F / %x21 / %x23-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
        (excludes NUL, SPACE, and special chars but allows SHARP)

        Uses FlextLdifConstants.Rfc.DN_TUTF1_EXCLUDE for exclusion set.

        Args:
            char: Single character to validate

        Returns:
            True if char is valid TUTF1, False otherwise

        """
        if not char or len(char) != 1:
            return False
        code = ord(char)
        safe_min = FlextLdifConstants.Rfc.SAFE_CHAR_MIN
        safe_max = FlextLdifConstants.Rfc.SAFE_CHAR_MAX
        if code < safe_min or code > safe_max:
            return False
        return code not in FlextLdifConstants.Rfc.DN_TUTF1_EXCLUDE

    @staticmethod
    def is_sutf1_char(char: str) -> bool:
        """Check if char is valid SUTF1 (string char) per RFC 4514.

        SUTF1 = %x01-21 / %x23-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
        (excludes special chars but allows SPACE and SHARP)

        Uses FlextLdifConstants.Rfc.DN_SUTF1_EXCLUDE for exclusion set.

        Args:
            char: Single character to validate

        Returns:
            True if char is valid SUTF1, False otherwise

        """
        if not char or len(char) != 1:
            return False
        code = ord(char)
        safe_min = FlextLdifConstants.Rfc.SAFE_CHAR_MIN
        safe_max = FlextLdifConstants.Rfc.SAFE_CHAR_MAX
        if code < safe_min or code > safe_max:
            return False
        return code not in FlextLdifConstants.Rfc.DN_SUTF1_EXCLUDE

    @staticmethod
    def needs_escaping_at_position(char: str, position: int, total_len: int) -> bool:
        r"""Check if char needs escaping based on position per RFC 4514.

        RFC 4514 Escaping Requirements:
        - Always escape: DN_ESCAPE_CHARS (" + , ; < > \)
        - At start (position=0): DN_ESCAPE_AT_START (SPACE, #)
        - At end (position=total_len-1): DN_ESCAPE_AT_END (SPACE)

        Args:
            char: Single character to check
            position: Position in the value string (0-indexed)
            total_len: Total length of the value string

        Returns:
            True if char needs escaping at this position

        """
        if not char:
            return False

        # Always escape these characters
        if char in FlextLdifConstants.Rfc.DN_ESCAPE_CHARS:
            return True

        # Escape at start
        if position == 0 and char in FlextLdifConstants.Rfc.DN_ESCAPE_AT_START:
            return True

        # Escape at end
        is_last = position == total_len - 1
        return is_last and char in FlextLdifConstants.Rfc.DN_ESCAPE_AT_END

    @staticmethod
    def is_valid_dn_string(
        value: str,
        *,
        strict: bool = True,
    ) -> tuple[bool, list[str]]:
        """Validate DN attribute value per RFC 4514 string production.

        RFC 4514 ABNF:
            string = [ ( leadchar / pair ) [ *( stringchar / pair )
                       ( trailchar / pair ) ] ]

        Args:
            value: DN attribute value to validate
            strict: If True, apply strict RFC 4514 validation

        Returns:
            Tuple of (is_valid, list of validation errors)

        """
        errors: list[str] = []

        if not value:
            return True, errors  # Empty string is valid

        # Single character
        if len(value) == 1:
            if not FlextLdifUtilitiesDN.is_lutf1_char(value) and strict:
                errors.append(f"Invalid lead character: {value!r}")
            return len(errors) == 0, errors

        # Check lead character - not LUTF1 and not escaped (pair)
        is_escaped_lead = value[0] == "\\" and len(value) > 1
        is_bad_lead = (
            not FlextLdifUtilitiesDN.is_lutf1_char(value[0]) and not is_escaped_lead
        )
        if is_bad_lead and strict:
            errors.append(f"Invalid lead character: {value[0]!r}")

        # Check trail character - not TUTF1 and not escaped
        min_len_for_escape = FlextLdifUtilitiesDN.MIN_DN_LENGTH
        is_escaped_trail = len(value) >= min_len_for_escape and value[-2] == "\\"
        is_bad_trail = (
            not FlextLdifUtilitiesDN.is_tutf1_char(value[-1]) and not is_escaped_trail
        )
        if is_bad_trail and strict:
            errors.append(f"Invalid trail character: {value[-1]!r}")

        # Check middle characters (stringchar or pair)
        for i, char in enumerate(value[1:-1], start=1):
            if FlextLdifUtilitiesDN.is_sutf1_char(char):
                continue
            # Check if part of escape pair
            is_escape_char = char == "\\"
            is_after_escape = i > 0 and value[i - 1] == "\\"
            if not is_escape_char and not is_after_escape and strict:
                errors.append(f"Invalid character at position {i}: {char!r}")

        return len(errors) == 0, errors

    # ==========================================================================
    # Core DN Operations
    # ==========================================================================

    @staticmethod
    def get_dn_value(
        dn: FlextLdifModels.DistinguishedName | str | object,
    ) -> str:
        """Extract DN string value from DN model or string (public utility method).

        Args:
            dn: DN model (Any) or DN string

        Returns:
            DN string value

        """
        # Check if it's a DistinguishedName model (local import to avoid circular dependency)

        if isinstance(dn, FlextLdifModels.DistinguishedName):
            return dn.value
        if isinstance(dn, str):
            return dn
        return str(dn)

    @overload
    @staticmethod
    def split(dn: str) -> list[str]: ...

    @overload
    @staticmethod
    def split(dn: FlextLdifModels.DistinguishedName) -> list[str]: ...

    @staticmethod
    def split(dn: str | object) -> list[str]:
        r"""Split DN string into individual RDN components per RFC 4514.

        RFC 4514 Section 2 ABNF:
        ========================
        distinguishedName = [ relativeDistinguishedName
                             *( COMMA relativeDistinguishedName ) ]
        COMMA = %x2C  ; comma (",")

        Properly handles escaped commas (\\,) and other special characters.
        Does NOT treat escaped commas as component separators.
        """
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not dn_str:
            return []

        # Split by commas but respect backslash escapes (functional approach with generator)
        def split_components() -> Generator[str]:
            """Generator that yields DN components respecting RFC 4514 escapes."""
            current = ""
            chars = iter(dn_str)

            for char in chars:
                if char == "\\":
                    # Escaped character - include both backslash and next char
                    try:
                        next_char = next(chars)
                        current += char + next_char
                    except StopIteration:
                        current += char  # Trailing backslash
                elif char == ",":
                    # Unescaped comma - component boundary
                    if current.strip():
                        yield current.strip()
                        current = ""
                else:
                    current += char

            # Add final component if exists
            if current.strip():
                yield current.strip()

        return list(split_components())

    @staticmethod
    def norm_component(component: str) -> str:
        """Normalize single DN component (e.g., 'cn = John' → 'cn=John')."""
        if "=" not in component:
            return component
        parts = component.split("=", 1)
        return f"{parts[0].strip()}={parts[1].strip()}"

    @overload
    @staticmethod
    def norm_string(dn: str) -> str: ...

    @overload
    @staticmethod
    def norm_string(dn: FlextLdifModels.DistinguishedName) -> str: ...

    @staticmethod
    def norm_string(dn: str | object) -> str:
        """Normalize full DN to RFC 4514 format."""
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not dn_str or "=" not in dn_str:
            return dn_str  # Return as-is if invalid (legacy method - returns str not FlextResult)
        components = FlextLdifUtilitiesDN.split(dn_str)
        normalized = [FlextLdifUtilitiesDN.norm_component(comp) for comp in components]
        return ",".join(normalized)

    @staticmethod
    def _validate_components(components: list[str]) -> bool:
        """Validate each DN component has attr=value format (helper method)."""
        for comp in components:
            if "=" not in comp:
                return False
            attr, _, value = comp.partition("=")
            # RFC 4514: both attribute and value must be non-empty
            if not attr.strip() or not value.strip():
                return False
        return True

    @overload
    @staticmethod
    def validate(dn: str) -> bool: ...

    @overload
    @staticmethod
    def validate(dn: FlextLdifModels.DistinguishedName) -> bool: ...

    @staticmethod
    def validate(dn: str | object) -> bool:
        r"""Validate DN format according to RFC 4514.

        Properly handles escaped characters. Checks for:
        - No double unescaped commas
        - No leading/trailing unescaped commas
        - All components have attr=value format
        - Valid hex escape sequences (\XX where X is hex digit)
        """
        if dn is None:
            return False
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not dn_str:
            return False
        if "=" not in dn_str:
            return False

        # Validate hex escape sequences
        if not FlextLdifUtilitiesDN._validate_escape_sequences(dn_str):
            return False

        # Check for invalid patterns with unescaped commas
        if FlextLdifUtilitiesDN._has_double_unescaped_commas(dn_str):
            return False

        # Leading unescaped comma
        if dn_str.startswith(","):
            return False

        # Trailing unescaped comma
        if dn_str.endswith(",") and (
            len(dn_str) < FlextLdifUtilitiesDN.MIN_DN_LENGTH or dn_str[-2] != "\\"
        ):
            return False

        try:
            # Use split() which properly handles escaped characters
            components = FlextLdifUtilitiesDN.split(dn_str)
            if not components:
                return False
            # Check each component has attr=value format with non-empty attr and value
            return FlextLdifUtilitiesDN._validate_components(components)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _has_double_unescaped_commas(dn_str: str) -> bool:
        """Check for consecutive unescaped commas in DN string."""
        i = 0
        while i < len(dn_str) - 1:
            if (
                dn_str[i] == ","
                and dn_str[i + 1] == ","
                and (i == 0 or dn_str[i - 1] != "\\")
            ):
                return True
            i += 1
        return False

    @staticmethod
    def _validate_escape_sequences(dn_str: str) -> bool:
        r"""Validate escape sequences in DN string.

        RFC 4514 Section 2.4: Implementations MUST allow UTF-8 characters
        to appear in values (both in their UTF-8 form and in their escaped form).
        This means UTF-8 bytes (> 127) are VALID and do NOT need escaping.

        Checks for:
        - Valid hex escapes: \XX where X is hex digit (0-9, A-F, a-f)
        - No incomplete hex escapes: \X or \
        - No invalid hex escapes: \ZZ
        - UTF-8 characters (> 127) are ALLOWED without escaping

        Returns:
            True if all escape sequences are valid

        """
        hex_escape_length = 2  # Length of hex digits in escape sequence
        i = 0
        while i < len(dn_str):
            if dn_str[i] == "\\":
                # Check if we have at least 2 more characters for hex escape
                if i + hex_escape_length >= len(dn_str):
                    # Dangling backslash or incomplete hex escape
                    return False

                # Check if next two chars are hex digits
                next_two = dn_str[i + 1 : i + 1 + hex_escape_length]
                if len(next_two) == hex_escape_length:
                    # If it looks like a hex escape (both chars could be hex)
                    # validate that both are actually hex digits
                    if all(c in "0123456789ABCDEFabcdef" for c in next_two):
                        # Valid hex escape, skip all 3 chars
                        i += 3
                        continue
                    # Check if it's a valid special char escape (not hex)
                    # RFC 4514 allows: \ escaping special chars like ,+=\<>#;
                    # Also allow escaping ANY character (including UTF-8)
                    # RFC 2253 Section 2.3: Whitespace normalization (space, TAB, CR, LF)
                    # OID Quirk: Exports DNs with TAB characters that need normalization
                    # UTF-8 starts at codepoint 128 (0x80)
                    utf8_start = 128
                    if (
                        next_two[0] in ' \t\r\n,+"\\<>;='
                        or ord(next_two[0]) >= utf8_start
                    ):
                        # Valid special char escape or UTF-8 escape, skip backslash
                        i += 1
                        continue
                    # Invalid hex escape
                    return False
                # Incomplete escape
                return False
            # RFC 4514: UTF-8 characters (> 127) are VALID and do NOT require escaping
            # Just skip UTF-8 bytes - they are allowed in DNs
            i += 1
        return True

    @overload
    @staticmethod
    def parse(dn: str) -> FlextResult[list[tuple[str, str]]]: ...

    @overload
    @staticmethod
    def parse(
        dn: FlextLdifModels.DistinguishedName,
    ) -> FlextResult[list[tuple[str, str]]]: ...

    @staticmethod
    def parse(
        dn: str | FlextLdifModels.DistinguishedName | None,
    ) -> FlextResult[list[tuple[str, str]]]:
        """Parse DN into RFC 4514 components (attr, value pairs).

        RFC 4514 Section 3 - Parsing a String Back to DN:
        =================================================
        1. Split on unescaped commas to get RDNs
        2. For each RDN, split on unescaped plus signs for multi-valued
        3. Each AVA is attributeType=attributeValue
        4. Unescape the attributeValue

        Returns:
            FlextResult with [(attr1, value1), (attr2, value2), ...] or failure.

        """
        if dn is None:
            return FlextResult[list[tuple[str, str]]].fail("DN cannot be None")
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not dn_str:
            return FlextResult[list[tuple[str, str]]].fail("DN string is empty")
        if "=" not in dn_str:
            return FlextResult[list[tuple[str, str]]].fail(
                f"Invalid DN format: missing '=' separator in '{dn_str}'",
            )

        try:
            components = FlextLdifUtilitiesDN.split(dn_str)
            result: list[tuple[str, str]] = []

            for comp in components:
                if "=" not in comp:
                    continue
                attr, _, value = comp.partition("=")
                result.append((attr.strip(), value.strip()))

            if not result:
                return FlextResult[list[tuple[str, str]]].fail(
                    f"Failed to parse DN components from '{dn_str}'",
                )
            return FlextResult[list[tuple[str, str]]].ok(result)
        except Exception as e:
            return FlextResult[list[tuple[str, str]]].fail(f"DN parsing error: {e}")

    @overload
    @staticmethod
    def norm(dn: str) -> FlextResult[str]: ...

    @overload
    @staticmethod
    def norm(dn: FlextLdifModels.DistinguishedName) -> FlextResult[str]: ...

    @staticmethod
    def norm(dn: str | FlextLdifModels.DistinguishedName | None) -> FlextResult[str]:
        """Normalize DN per RFC 4514 (lowercase attrs, preserve values).

        Pure implementation without external dependencies.
        Returns FlextResult with normalized DN string or failure.
        """
        if dn is None:
            return FlextResult[str].fail("DN cannot be None")
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        try:
            if not dn_str:
                return FlextResult[str].fail(
                    "Failed to normalize DN: DN string is empty",
                )
            if "=" not in dn_str:
                return FlextResult[str].fail(
                    f"Failed to normalize DN: Invalid DN format: missing '=' separator in '{dn_str}'",
                )

            components = FlextLdifUtilitiesDN.split(dn_str)
            normalized: list[str] = []

            for comp in components:
                if "=" not in comp:
                    continue
                attr, _, value = comp.partition("=")
                # RFC 4514 normalization: lowercase attribute TYPE, preserve value case
                # Attribute types are case-insensitive, values are case-preserving
                normalized.append(f"{attr.strip().lower()}={value.strip()}")

            if not normalized:
                return FlextResult[str].fail(
                    f"Failed to normalize DN: no valid components in '{dn_str}'",
                )
            return FlextResult[str].ok(",".join(normalized))
        except Exception as e:
            return FlextResult[str].fail(f"DN normalization error: {e}")

    @staticmethod
    def norm_with_statistics(
        dn: DnInput,
        original_dn: str | None = None,
    ) -> FlextResult[tuple[str, FlextLdifModels.DNStatistics]]:
        """Normalize DN with statistics tracking.

        Args:
            dn: DN to normalize
            original_dn: Original DN before any transformations (optional)

        Returns:
            FlextResult with tuple of (normalized_dn, DNStatistics) or failure

        """
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not dn_str:
            return FlextResult[tuple[str, FlextLdifModels.DNStatistics]].fail(
                "DN string is empty or invalid",
            )
        # Use original_dn if provided, otherwise use dn_str
        orig = original_dn or dn_str

        norm_result = FlextLdifUtilitiesDN.norm(dn_str)
        if not norm_result.is_success:
            return FlextResult[tuple[str, FlextLdifModels.DNStatistics]].fail(
                norm_result.error or "DN normalization failed",
            )
        normalized = norm_result.unwrap()

        # Track if normalization changed the DN
        transformations: list[str] = []
        if dn_str != normalized:
            transformations.append(FlextLdifConstants.TransformationType.DN_NORMALIZED)

        # Create statistics - use model_copy() for safety
        stats_domain = FlextLdifModels.DNStatistics.create_with_transformation(
            original_dn=orig,
            cleaned_dn=dn_str,
            normalized_dn=normalized,
            transformations=transformations,
        )
        # Convert domain DNStatistics to public DNStatistics
        if isinstance(
            stats_domain,
            FlextLdifModelsDomains.DNStatistics,
        ) and not isinstance(stats_domain, FlextLdifModels.DNStatistics):
            stats = FlextLdifModels.DNStatistics.model_validate(
                stats_domain.model_dump(),
            )
        else:
            stats = stats_domain

        return FlextResult[tuple[str, FlextLdifModels.DNStatistics]].ok(
            (
                normalized,
                stats,
            ),
        )

    @overload
    @staticmethod
    def clean_dn(dn: str) -> str: ...

    @overload
    @staticmethod
    def clean_dn(dn: FlextLdifModels.DistinguishedName) -> str: ...

    @staticmethod
    def clean_dn(dn: str | FlextLdifModels.DistinguishedName) -> str:
        """Clean DN string to fix spacing and escaping issues.

        Removes spaces before '=', fixes trailing backslash+space,
        normalizes whitespace around commas.

        **DRY Optimization**: Uses FlextUtilities.StringParser.apply_regex_pipeline()
        to consolidate 5 sequential regex.sub() calls into one pipeline.
        """
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not dn_str:
            return dn_str

        # Define regex pipeline for DN cleaning
        patterns = [
            # RFC 2253 Section 2.3: Normalize whitespace control characters
            # OID Quirk: Exports DNs with TAB, CR, LF characters - normalize to space
            # MUST be first to normalize before other space-removal patterns
            (r"[\t\r\n\x0b\x0c]", " "),
            # Remove spaces ONLY BEFORE '=' in each RDN component
            (r"\s+=", "="),
            # Fix trailing backslash+space before commas
            # MUST come BEFORE general space removal to handle escaped spaces correctly
            (
                FlextLdifConstants.DnPatterns.DN_TRAILING_BACKSLASH_SPACE,
                FlextLdifConstants.DnPatterns.DN_COMMA,
            ),
            # Remove spaces BEFORE commas (OID quirk: "cn=user ,ou=..." -> "cn=user,ou=...")
            (r"\s+,", ","),
            # Normalize spaces around commas: ", cn=..." -> ",cn=..."
            (
                FlextLdifConstants.DnPatterns.DN_SPACES_AROUND_COMMA,
                FlextLdifConstants.DnPatterns.DN_COMMA,
            ),
            # Remove unnecessary character escapes (RFC 4514 compliance)
            (FlextLdifConstants.DnPatterns.DN_UNNECESSARY_ESCAPES, r"\1"),
            # Normalize multiple spaces to single space
            (FlextLdifConstants.DnPatterns.DN_MULTIPLE_SPACES, " "),
        ]

        # Apply regex pipeline using local implementation
        try:
            result = dn_str
            for pattern, replacement in patterns:
                result = re.sub(pattern, replacement, result)
            return result
        except Exception:
            return dn_str

    @staticmethod
    def clean_dn_with_statistics(
        dn: DnInput,
    ) -> tuple[str, FlextLdifModels.DNStatistics]:
        r"""Clean DN and track all transformations with statistics.

        Returns both cleaned DN and complete transformation history
        for diagnostic and audit purposes.

        Args:
            dn: DN string or DistinguishedName object

        Returns:
            Tuple of (cleaned_dn, DNStatistics with transformation history)

        Example:
            cleaned_dn, stats = FlextLdifUtilitiesDN.clean_dn_with_statistics(
                "cn=test  ,\tdc=example,dc=com"
            )
            # cleaned_dn: "cn=test,dc=example,dc=com"
            # stats.had_extra_spaces: True
            # stats.had_tab_chars: True
            # stats.transformations: [TAB_NORMALIZED, SPACE_CLEANED]

        """
        original_dn = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not original_dn:
            stats_domain = FlextLdifModels.DNStatistics.create_minimal(original_dn)
            stats = FlextLdifModels.DNStatistics.model_validate(
                stats_domain.model_dump(),
            )
            return original_dn, stats

        # Apply transformations and collect flags
        result, transformations, flags = FlextLdifUtilitiesDN._apply_dn_transformations(
            original_dn,
        )

        # Create statistics using type-safe flags from dataclass
        stats_domain = FlextLdifModels.DNStatistics.create_with_transformation(
            original_dn=original_dn,
            cleaned_dn=result,
            normalized_dn=result,
            transformations=transformations,
            had_tab_chars=flags.had_tab_chars,
            had_trailing_spaces=flags.had_trailing_spaces,
            had_leading_spaces=flags.had_leading_spaces,
            had_extra_spaces=flags.had_extra_spaces,
            was_base64_encoded=flags.was_base64_encoded,
            had_utf8_chars=flags.had_utf8_chars,
            had_escape_sequences=flags.had_escape_sequences,
            validation_status=flags.validation_status,
            validation_warnings=flags.validation_warnings,
            validation_errors=flags.validation_errors,
        )
        # Convert domain DNStatistics to public DNStatistics
        if isinstance(
            stats_domain,
            FlextLdifModelsDomains.DNStatistics,
        ) and not isinstance(stats_domain, FlextLdifModels.DNStatistics):
            stats = FlextLdifModels.DNStatistics.model_validate(
                stats_domain.model_dump(),
            )
        else:
            stats = stats_domain
        return result, stats

    @staticmethod
    def _apply_dn_transformations(
        original_dn: str,
    ) -> tuple[str, list[str], _TransformationFlags]:
        """Apply DN transformations and collect flags.

        Extracted to reduce complexity of clean_dn_with_statistics.
        """
        transformations: list[str] = []
        flags = _TransformationFlags()
        result = original_dn

        # Define transformation rules: (detect_pattern, replace_pattern, replacement, transform_type, flag_name)
        # Each rule: (detect_regex, replace_regex, replacement, transformation_type, flag_attr)
        transform_rules: list[tuple[str, str, str, str, str]] = [
            # 1. Tab/whitespace control chars
            (
                r"[\t\r\n\x0b\x0c]",
                r"[\t\r\n\x0b\x0c]",
                " ",
                FlextLdifConstants.TransformationType.TAB_NORMALIZED,
                "had_tab_chars",
            ),
            # 2. Spaces before equals
            (
                r"\s+=",
                r"\s+=",
                "=",
                FlextLdifConstants.TransformationType.SPACE_CLEANED,
                "had_leading_spaces",
            ),
            # 3. Spaces before commas
            (
                r"\s+,",
                r"\s+,",
                ",",
                FlextLdifConstants.TransformationType.SPACE_CLEANED,
                "had_trailing_spaces",
            ),
            # 4. Trailing backslash+space
            (
                FlextLdifConstants.DnPatterns.DN_TRAILING_BACKSLASH_SPACE,
                FlextLdifConstants.DnPatterns.DN_TRAILING_BACKSLASH_SPACE,
                FlextLdifConstants.DnPatterns.DN_COMMA,
                FlextLdifConstants.TransformationType.ESCAPE_NORMALIZED,
                "had_escape_sequences",
            ),
            # 5. Spaces around commas
            (
                FlextLdifConstants.DnPatterns.DN_SPACES_AROUND_COMMA,
                FlextLdifConstants.DnPatterns.DN_SPACES_AROUND_COMMA,
                FlextLdifConstants.DnPatterns.DN_COMMA,
                FlextLdifConstants.TransformationType.SPACE_CLEANED,
                "",
            ),
            # 6. Unnecessary escapes
            (
                FlextLdifConstants.DnPatterns.DN_UNNECESSARY_ESCAPES,
                FlextLdifConstants.DnPatterns.DN_UNNECESSARY_ESCAPES,
                r"\1",
                FlextLdifConstants.TransformationType.ESCAPE_NORMALIZED,
                "",
            ),
            # 7. Multiple spaces
            (
                FlextLdifConstants.DnPatterns.DN_MULTIPLE_SPACES,
                FlextLdifConstants.DnPatterns.DN_MULTIPLE_SPACES,
                " ",
                FlextLdifConstants.TransformationType.SPACE_CLEANED,
                "had_extra_spaces",
            ),
        ]

        for (
            detect_pattern,
            replace_pattern,
            replacement,
            transform_type,
            flag_name,
        ) in transform_rules:
            if re.search(detect_pattern, result):
                result = re.sub(replace_pattern, replacement, result)
                transformations.append(transform_type)
                if flag_name:
                    setattr(flags, flag_name, True)

        return result, transformations, flags

    @staticmethod
    def esc(value: str) -> str:
        r"""Escape special characters in DN value per RFC 4514 Section 2.4.

        RFC 4514 Escaping Requirements:
        ===============================
        - Special characters MUST be escaped: " + , ; < > \
        - A leading SHARP ('#') MUST be escaped
        - A leading/trailing SPACE MUST be escaped
        - Characters can be escaped as \\XX where XX is hex

        Args:
            value: The DN attribute value to escape.

        Returns:
            The escaped value string.

        """
        if not value:
            return value

        escape_chars = FlextLdifConstants.Rfc.DN_ESCAPE_CHARS
        result: list[str] = []

        for i, char in enumerate(value):
            is_special = char in escape_chars
            is_leading_space = i == 0 and char == " "
            is_trailing_space = i == len(value) - 1 and char == " "
            is_leading_sharp = i == 0 and char == "#"
            if is_special or is_leading_space or is_trailing_space or is_leading_sharp:
                result.append(f"\\{ord(char):02x}")
            else:
                result.append(char)

        return "".join(result)

    @staticmethod
    def unesc(value: str) -> str:
        r"""Unescape special characters in DN value per RFC 4514 Section 3.

        RFC 4514 Unescaping Requirements:
        =================================
        - \\XX where XX is hex digits -> character with that code
        - \\<special> -> the literal special character
        - Escape sequences: \\", \\+, \\,, \\;, \\<, \\>, \\\\

        Args:
            value: The escaped DN attribute value.

        Returns:
            The unescaped value string.

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
                    hex_code = value[i + 1 : i + 3]
                    result.append(chr(int(hex_code, 16)))
                    i += 3
                else:
                    result.append(value[i + 1])
                    i += 2
            else:
                result.append(value[i])
                i += 1

        return "".join(result)

    @staticmethod
    def compare_dns(
        dn1: str | None,
        dn2: str | None,
    ) -> FlextResult[int]:
        """Compare two DNs per RFC 4514 (case-insensitive).

        Returns: FlextResult with -1 if dn1 < dn2, 0 if equal, 1 if dn1 > dn2, or failure
        """
        try:
            # Validate inputs first
            if not dn1 or not dn2:
                return FlextResult[int].fail("Both DNs must be provided for comparison")

            norm1_result = FlextLdifUtilitiesDN.norm(dn1)
            if not norm1_result.is_success:
                return FlextResult[int].fail(
                    f"Comparison failed (RFC 4514): Failed to normalize first DN: {norm1_result.error}",
                )
            norm1 = norm1_result.unwrap()

            norm2_result = FlextLdifUtilitiesDN.norm(dn2)
            if not norm2_result.is_success:
                return FlextResult[int].fail(
                    f"Comparison failed (RFC 4514): Failed to normalize second DN: {norm2_result.error}",
                )
            norm2 = norm2_result.unwrap()

            norm1_lower = norm1.lower()
            norm2_lower = norm2.lower()

            if norm1_lower < norm2_lower:
                return FlextResult[int].ok(-1)
            if norm1_lower > norm2_lower:
                return FlextResult[int].ok(1)
            return FlextResult[int].ok(0)
        except Exception as e:
            return FlextResult[int].fail(f"DN comparison error: {e}")

    @staticmethod
    def _process_rdn_escape(rdn: str, i: int, current_val: str) -> tuple[str, int]:
        """Process escape sequence in RDN parsing (extracted to reduce complexity)."""
        if i + 1 < len(rdn):
            next_char = rdn[i + 1]
            if i + 2 < len(rdn) and all(
                c in string.hexdigits for c in rdn[i + 1 : i + 3]
            ):
                return current_val + rdn[i : i + 3], i + 3
            return current_val + next_char, i + 2
        return current_val, i + 1

    @staticmethod
    def _process_rdn_char(
        char: str,
        rdn: str,
        i: int,
        current_attr: str,
        current_val: str,
        *,
        in_value: bool,
        pairs: list[tuple[str, str]],
    ) -> tuple[str, str, bool, int, bool]:
        """Process single character in RDN parsing.

        Returns: (current_attr, current_val, in_value, next_i, should_continue)
        should_continue=True means skip normal increment
        """
        if char == "\\" and i + 1 < len(rdn):
            current_val, next_i = FlextLdifUtilitiesDN._process_rdn_escape(
                rdn,
                i,
                current_val,
            )
            return current_attr, current_val, in_value, next_i, True

        if char == "=" and not in_value:
            current_attr = current_attr.strip().lower()
            return current_attr, current_val, True, i + 1, True

        if char == "+" and in_value:
            current_val = current_val.strip()
            if current_attr:
                pairs.append((current_attr, current_val))
            return "", "", False, i + 1, True

        if in_value:
            current_val += char
        else:
            current_attr += char

        return current_attr, current_val, in_value, i + 1, False

    @staticmethod
    def _advance_rdn_position(
        char: str,
        rdn: str,
        position: int,
        current_attr: str,
        current_val: str,
        *,
        in_value: bool,
        pairs: list[tuple[str, str]],
    ) -> tuple[str, str, bool, int]:
        """Advance position during RDN parsing and return new state.

        Returns: (current_attr, current_val, in_value, next_position)
        """
        result = FlextLdifUtilitiesDN._process_rdn_char(
            char,
            rdn,
            position,
            current_attr,
            current_val,
            in_value=in_value,
            pairs=pairs,
        )
        attr, val, in_val, next_pos, _ = result
        return (attr, val, in_val, next_pos)

    @staticmethod
    def parse_rdn(rdn: str) -> FlextResult[list[tuple[str, str]]]:
        """Parse a single RDN component per RFC 4514.

        Returns FlextResult with list of (attr, value) pairs or failure.
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
            rdn_len: int = len(rdn)
            position: int = 0

            while position < rdn_len:
                # Extract character first to avoid type checker confusion
                idx: int = position
                char_at_pos: str = rdn[idx]
                # Advance position using helper method that returns explicit int
                current_attr, current_val, in_value, position = (
                    FlextLdifUtilitiesDN._advance_rdn_position(
                        char_at_pos,
                        rdn,
                        idx,
                        current_attr,
                        current_val,
                        in_value=in_value,
                        pairs=pairs,
                    )
                )

                if char_at_pos == "=" and not in_value and not current_attr:
                    return FlextResult[list[tuple[str, str]]].fail(
                        f"Invalid RDN format: unexpected '=' at position {idx}",
                    )

            if not in_value or not current_attr:
                return FlextResult[list[tuple[str, str]]].fail(
                    f"Invalid RDN format: missing attribute or value in '{rdn}'",
                )

            current_val = current_val.strip()
            if not current_val:
                return FlextResult[list[tuple[str, str]]].fail(
                    f"Invalid RDN format: empty value in '{rdn}'",
                )
            pairs.append((current_attr, current_val))

            return FlextResult[list[tuple[str, str]]].ok(pairs)

        except Exception as e:
            return FlextResult[list[tuple[str, str]]].fail(f"RDN parsing error: {e}")

    @staticmethod
    def extract_rdn(dn: str) -> FlextResult[str]:
        """Extract leftmost RDN from DN.

        For DN "cn=John,ou=Users,dc=example,dc=com", returns "cn=John".

        Args:
            dn: Distinguished Name string

        Returns:
            FlextResult with leftmost RDN (attr=value) or failure

        """
        if not dn or "=" not in dn:
            return FlextResult[str].fail(
                f"Invalid DN format: missing '=' separator in '{dn}'",
            )

        try:
            components = FlextLdifUtilitiesDN.split(dn)
            if not components:
                return FlextResult[str].fail(
                    f"Failed to extract RDN: no components found in '{dn}'",
                )
            return FlextResult[str].ok(components[0])
        except Exception as e:
            return FlextResult[str].fail(f"RDN extraction error: {e}")

    @staticmethod
    def extract_parent_dn(dn: str) -> FlextResult[str]:
        """Extract parent DN (remove leftmost RDN).

        For DN "cn=John,ou=Users,dc=example,dc=com",
        returns "ou=Users,dc=example,dc=com".

        Args:
            dn: Distinguished Name string

        Returns:
            FlextResult with parent DN (without leftmost RDN) or failure if DN has ≤1 component

        """
        if not dn or "=" not in dn:
            return FlextResult[str].fail(
                f"Invalid DN format: missing '=' separator in '{dn}'",
            )

        try:
            components = FlextLdifUtilitiesDN.split(dn)
            if len(components) <= 1:
                return FlextResult[str].fail(
                    f"Cannot extract parent DN: DN has only one component '{dn}'",
                )
            return FlextResult[str].ok(",".join(components[1:]))
        except Exception as e:
            return FlextResult[str].fail(f"Parent DN extraction error: {e}")

    @staticmethod
    def is_config_dn(dn: str) -> bool:
        """Check if DN is in cn=config tree (OpenLDAP dynamic config).

        Used by OpenLDAP and other servers for config DN detection.

        Args:
            dn: Distinguished Name string

        Returns:
            True if DN contains cn=config component, False otherwise

        """
        if not dn:
            return False
        return "cn=config" in dn.lower()

    @staticmethod
    def contains_pattern(
        dn: str,
        pattern: str,
        *,
        case_sensitive: bool = False,
    ) -> bool:
        """Check if DN contains pattern substring.

        Useful for DN filtering by organizational unit, DC, etc.

        Args:
            dn: Distinguished Name string
            pattern: Pattern to search for (can be full component or substring)
            case_sensitive: If True, match case exactly

        Returns:
            True if pattern is found in DN, False otherwise

        Example:
            contains_pattern("cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example", "ou=users")
            # Returns: True
            contains_pattern("cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example", "OU=USERS")
            # Returns: False (case mismatch)
            contains_pattern("cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example", "OU=USERS", case_sensitive=False)
            # Returns: True

        """
        if not dn or not pattern:
            return False

        search_dn = dn if case_sensitive else dn.lower()
        search_pattern = pattern if case_sensitive else pattern.lower()

        return search_pattern in search_dn

    @staticmethod
    def is_under_base(
        dn: str | None,
        base_dn: str | None,
    ) -> bool:
        """Check if DN is under base DN (hierarchical check).

        Returns True if:
        - DN exactly equals base_dn (case-insensitive)
        - DN is a child/descendant of base_dn

        Args:
            dn: Distinguished Name to check
            base_dn: Base DN to check against

        Returns:
            True if DN is equal to or under base_dn, False otherwise

        Example:
            is_under_base("cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example", "dc=example")
            # Returns: True
            is_under_base("cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example", "ou=users,dc=example")
            # Returns: True
            is_under_base("cn=REDACTED_LDAP_BIND_PASSWORD,ou=users,dc=example", "ou=other,dc=example")
            # Returns: False

        """
        # Validate inputs first
        if not dn or not base_dn:
            return False

        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        base_dn_str = FlextLdifUtilitiesDN.get_dn_value(base_dn)

        if not dn_str or not base_dn_str:
            return False

        # Normalize both DNs for comparison (case-insensitive)
        dn_lower = dn_str.lower().strip()
        base_dn_lower = base_dn_str.lower().strip()

        # Check if DN equals base_dn OR if DN ends with ",base_dn"
        return dn_lower == base_dn_lower or dn_lower.endswith(f",{base_dn_lower}")

    @staticmethod
    def validate_dn_with_context(
        dn_value: str | None,
        context_dn: str | None,
        dn_label: str = "DN",
    ) -> FlextResult[bool]:
        """Validate DN format and compare against context DN if provided.

        Generic DN validation combining RFC 4514 format check and context comparison.
        Used for ACL subject/target DN validation and similar use cases.

        Args:
            dn_value: DN string to validate (None or "*" treated as wildcard)
            context_dn: Optional context DN to compare against
            dn_label: Label for error messages (e.g., "subject DN", "target DN")

        Returns:
            FlextResult[bool]: Success if valid, failure with descriptive error

        Example:
            # Validate subject DN
            result = validate_dn_with_context(
                "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                "subject DN"
            )

            # Wildcard DN (always valid)
            result = validate_dn_with_context("*", None, "target DN")
            # Returns: FlextResult.ok(True)

            # Invalid DN format
            result = validate_dn_with_context("invalid", None, "DN")
            # Returns: FlextResult.fail("Invalid DN format per RFC 4514: invalid")

        """
        # Wildcard or None is always valid
        if not dn_value or dn_value == "*":
            return FlextResult[bool].ok(True)

        # Validate DN format per RFC 4514
        if not FlextLdifUtilitiesDN.validate(dn_value):
            return FlextResult[bool].fail(
                f"Invalid {dn_label} format per RFC 4514: {dn_value}",
            )

        # If context DN provided, compare case-insensitively
        if context_dn:
            comparison_result = FlextLdifUtilitiesDN.compare_dns(
                str(context_dn),
                dn_value,
            )
            if not comparison_result.is_success:
                return FlextResult[bool].fail(
                    f"DN comparison failed: {comparison_result.error}",
                )
            comparison_value = comparison_result.unwrap()
            if comparison_value != 0:  # 0 means equal
                return FlextResult[bool].fail(
                    f"{dn_label.capitalize()} mismatch: {context_dn} != {dn_value}",
                )

        return FlextResult[bool].ok(True)

    @overload
    @staticmethod
    def transform_dn_attribute(
        value: str,
        source_dn: str,
        target_dn: str,
    ) -> str: ...

    @overload
    @staticmethod
    def transform_dn_attribute(
        value: FlextLdifModels.DistinguishedName,
        source_dn: str,
        target_dn: str,
    ) -> str: ...

    @overload
    @staticmethod
    def transform_dn_attribute(
        value: FlextLdifModelsDomains.DistinguishedName,
        source_dn: str,
        target_dn: str,
    ) -> str: ...

    @staticmethod
    def transform_dn_attribute(
        value: str
        | FlextLdifModels.DistinguishedName
        | FlextLdifModelsDomains.DistinguishedName
        | object,
        source_dn: str,
        target_dn: str,
    ) -> str:
        """Transform a single DN attribute value by replacing base DN.

        Used for transforming DN-syntax attributes (member, uniqueMember, manager, etc.)
        when migrating from one LDAP server to another with different base DNs.

        Args:
            value: DN value to transform (str or DistinguishedName model)
            source_dn: Source base DN to replace (e.g., "dc=ctbc")
            target_dn: Target base DN replacement (e.g., "dc=example,dc=com")

        Returns:
            Transformed DN with base DN replaced, or original value if no match

        Example:
            transform_dn_attribute(
                "cn=REDACTED_LDAP_BIND_PASSWORD,dc=ctbc",
                "dc=ctbc",
                "dc=example,dc=com"
            )
            # Returns: "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

        """
        dn_str = FlextLdifUtilitiesDN.get_dn_value(value)
        if not dn_str or not source_dn or not target_dn:
            return dn_str

        # Normalize the DN first
        norm_result = FlextLdifUtilitiesDN.norm(dn_str)
        normalized_dn = norm_result.unwrap() if norm_result.is_success else dn_str

        # Use regex to replace source base DN suffix with target base DN
        # Pattern: match either:
        # 1. ",source_dn" at the END of DN (e.g., "ou=people,dc=ctbc")
        # 2. "source_dn" alone at the END of DN (e.g., "dc=ctbc" as root DN)
        # Both cases are case-insensitive
        source_escaped = re.escape(source_dn)

        # Try replacing with comma first (non-root DN case: "ou=people,dc=ctbc")
        result = re.sub(
            f",{source_escaped}$",
            f",{target_dn}",
            normalized_dn,
            flags=re.IGNORECASE,
        )

        # If no substitution happened, try without comma (root DN case: "dc=ctbc")
        if result == normalized_dn:
            result = re.sub(
                f"^{source_escaped}$",
                target_dn,
                normalized_dn,
                flags=re.IGNORECASE,
            )

        return result

    @staticmethod
    def replace_base_dn(
        entries: list[FlextLdifModels.Entry],
        source_dn: str,
        target_dn: str,
    ) -> list[FlextLdifModels.Entry]:
        """Replace base DN in all entries and DN-valued attributes.

        Transforms:
        - Entry DNs (dn property)
        - DN-syntax attributes (member, uniqueMember, manager, owner, seeAlso, etc.)
        - Any other DN references in attribute values

        Used for server-to-server migration when source and target have different base DNs.

        Args:
            entries: List of Entry models to transform
            source_dn: Source base DN to replace (e.g., "dc=ctbc")
            target_dn: Target base DN replacement (e.g., "dc=example,dc=com")

        Returns:
            List of Entry models with all base DN references replaced

        Example:
            entries = [
                Entry(
                    dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=ctbc",
                    attributes={"member": ["cn=user,dc=ctbc"]}
                ),
                ...
            ]
            transformed = replace_base_dn(entries, "dc=ctbc", "dc=example,dc=com")
            # transformed[0].dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
            # transformed[0].attributes["member"][0] == "cn=user,dc=example,dc=com"

        """
        if not entries or not source_dn or not target_dn:
            return entries

        # DN-syntax attribute names that may contain DN references
        dn_attributes = {
            "member",
            "uniquemember",
            "manager",
            "owner",
            "seealso",
            "memberof",
            "distinguishedname",
        }

        transformed_entries: list[FlextLdifModels.Entry] = []

        for entry in entries:
            # Transform entry DN
            transformed_dn = FlextLdifUtilitiesDN.transform_dn_attribute(
                entry.dn,
                source_dn,
                target_dn,
            )

            # Transform DN-valued attributes
            transformed_attrs: dict[str, list[str]] = {}
            for attr_name, attr_values in entry.attributes.items():
                attr_lower = attr_name.lower()
                if attr_lower in dn_attributes:
                    # Transform each value in DN-syntax attributes
                    transformed_attrs[attr_name] = [
                        FlextLdifUtilitiesDN.transform_dn_attribute(
                            val,
                            source_dn,
                            target_dn,
                        )
                        for val in attr_values
                    ]
                else:
                    # Keep other attributes unchanged
                    transformed_attrs[attr_name] = attr_values

            # Create new entry with transformed DN and attributes
            # Use model_copy to preserve all other properties
            new_attributes = FlextLdifModels.LdifAttributes(
                attributes=transformed_attrs,
            )
            transformed_entry = entry.model_copy(
                update={
                    "dn": transformed_dn,
                    "attributes": new_attributes,
                },
            )
            transformed_entries.append(transformed_entry)

        return transformed_entries

    @staticmethod
    def transform_ldif_files_in_directory(
        ldif_dir: Path,
        source_basedn: str,
        target_basedn: str,
    ) -> FlextResult[dict[str, object]]:
        """Transform BaseDN in all LDIF files in directory.

        Reads all *.ldif files from directory, transforms BaseDN in entries,
        and writes updated files back. Preserves file organization and metadata.

        Args:
            ldif_dir: Directory containing LDIF files
            source_basedn: Source base DN to replace
            target_basedn: Target base DN replacement

        Returns:
            FlextResult with dict containing:
            - transformed_count: Number of successfully transformed files
            - failed_count: Number of files that failed
            - total_count: Total LDIF files processed

        """
        try:
            if not ldif_dir.exists():
                return FlextResult.fail(f"Directory not found: {ldif_dir}")

            transformed_count = 0
            failed_count = 0

            for ldif_file in sorted(ldif_dir.glob("*.ldif")):
                try:
                    content = ldif_file.read_text(encoding="utf-8")
                    lines = content.split("\n")
                    transformed_lines: list[str] = []

                    for line in lines:
                        if not line or ":" not in line:
                            transformed_lines.append(line)
                            continue

                        parts = line.split(":", 1)
                        attr_name = parts[0]
                        attr_value = parts[1].strip() if len(parts) > 1 else ""

                        if not attr_value or source_basedn not in attr_value:
                            transformed_lines.append(line)
                            continue

                        # Check if attribute is DN-valued
                        dn_attrs = {
                            "dn",
                            "member",
                            "uniquemember",
                            "manager",
                            "owner",
                            "seealso",
                            "memberof",
                            "distinguishedname",
                        }
                        is_dn_attr = attr_name.lower() in dn_attrs
                        is_dn_like = "=" in attr_value and "," in attr_value

                        if is_dn_attr or is_dn_like:
                            transformed_value = (
                                FlextLdifUtilitiesDN.transform_dn_attribute(
                                    attr_value,
                                    source_basedn,
                                    target_basedn,
                                )
                            )
                            transformed_lines.append(
                                f"{attr_name}: {transformed_value}",
                            )
                        else:
                            transformed_lines.append(line)

                    transformed_content = "\n".join(transformed_lines)
                    ldif_file.write_text(transformed_content, encoding="utf-8")
                    transformed_count += 1

                except (OSError, ValueError):
                    failed_count += 1
                    continue

            return FlextResult.ok({
                "transformed_count": transformed_count,
                "failed_count": failed_count,
                "total_count": transformed_count + failed_count,
            })

        except Exception as e:
            return FlextResult.fail(f"LDIF directory transformation failed: {e}")

    @staticmethod
    def transform_dn_with_metadata(
        entry: FlextLdifModels.Entry,
        source_dn: str,
        target_dn: str,
    ) -> FlextLdifModels.Entry:
        """Transform DN and DN-valued attributes with metadata tracking.

        RFC Compliant: Tracks all transformations in QuirkMetadata for round-trip support.
        Uses FlextLdifConstants.Rfc.META_DN_* and MetadataKeys for standardized tracking.

        Args:
            entry: Entry to transform
            source_dn: Source base DN to replace
            target_dn: Target base DN replacement

        Returns:
            New Entry with transformed DN, attributes, and metadata tracking

        Example:
            >>> entry = FlextLdifModels.Entry(
            ...     dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=ctbc", attributes={"member": ["cn=user,dc=ctbc"]}
            ... )
            >>> transformed = FlextLdifUtilitiesDN.transform_dn_with_metadata(
            ...     entry, "dc=ctbc", "dc=example,dc=com"
            ... )
            >>> # DN transformed: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
            >>> # metadata.conversion_notes tracks the transformation

        """
        if not source_dn or not target_dn:
            return entry

        # DN-syntax attribute names
        dn_attributes = {
            "member",
            "uniquemember",
            "manager",
            "owner",
            "seealso",
            "memberof",
            "distinguishedname",
        }

        original_dn_str = FlextLdifUtilitiesDN.get_dn_value(entry.dn)

        # Transform entry DN
        transformed_dn = FlextLdifUtilitiesDN.transform_dn_attribute(
            entry.dn,
            source_dn,
            target_dn,
        )

        # Transform DN-valued attributes and track changes
        transformed_attrs: dict[str, list[str]] = {}
        transformed_attr_names: list[str] = []

        for attr_name, attr_values in entry.attributes.items():
            attr_lower = attr_name.lower()
            if attr_lower in dn_attributes:
                new_values = [
                    FlextLdifUtilitiesDN.transform_dn_attribute(
                        val,
                        source_dn,
                        target_dn,
                    )
                    for val in attr_values
                ]
                transformed_attrs[attr_name] = new_values

                # Track if values actually changed
                if new_values != attr_values:
                    transformed_attr_names.append(attr_name)
            else:
                transformed_attrs[attr_name] = attr_values

        # Create updated metadata with transformation tracking
        if entry.metadata is None:
            metadata = FlextLdifModels.QuirkMetadata.create_for()
        else:
            metadata = entry.metadata.model_copy(deep=True)

        # Track DN transformation
        if transformed_dn != original_dn_str:
            metadata.track_dn_transformation(
                original_dn=original_dn_str,
                transformed_dn=transformed_dn,
                transformation_type="basedn_transform",
            )

        # Track attribute transformations
        for attr_name in transformed_attr_names:
            original_values = list(entry.attributes.get(attr_name, []))
            new_values = transformed_attrs[attr_name]
            metadata.track_attribute_transformation(
                original_name=attr_name,
                new_name=attr_name,
                transformation_type="modified",
                original_values=original_values,
                new_values=new_values,
                reason=f"BaseDN transformation: {source_dn} → {target_dn}",
            )

        # Add overall conversion note
        metadata.add_conversion_note(
            operation="basedn_transform",
            description=f"Transformed BaseDN from {source_dn} to {target_dn}",
        )

        # Store transformation context in extensions
        metadata.extensions[FlextLdifConstants.MetadataKeys.ENTRY_SOURCE_DN_CASE] = (
            original_dn_str
        )
        metadata.extensions[FlextLdifConstants.MetadataKeys.ENTRY_TARGET_DN_CASE] = (
            transformed_dn
        )

        # Create new entry with transformed data and metadata
        return entry.model_copy(
            update={
                "dn": transformed_dn,
                "attributes": transformed_attrs,
                "metadata": metadata,
            },
        )

    @staticmethod
    def replace_base_dn_with_metadata(
        entries: list[FlextLdifModels.Entry],
        source_dn: str,
        target_dn: str,
    ) -> list[FlextLdifModels.Entry]:
        """Replace base DN in all entries with metadata tracking.

        RFC Compliant: Tracks all transformations for audit trail and round-trip support.

        Args:
            entries: List of Entry models to transform
            source_dn: Source base DN to replace
            target_dn: Target base DN replacement

        Returns:
            List of Entry models with transformed DNs and metadata

        Example:
            >>> entries = FlextLdifUtilitiesDN.replace_base_dn_with_metadata(
            ...     entries, "dc=ctbc", "dc=example,dc=com"
            ... )
            >>> # Each entry.metadata.conversion_notes tracks transformation

        """
        if not entries or not source_dn or not target_dn:
            return entries

        return [
            FlextLdifUtilitiesDN.transform_dn_with_metadata(entry, source_dn, target_dn)
            for entry in entries
        ]


__all__ = [
    "FlextLdifUtilitiesDN",
]
