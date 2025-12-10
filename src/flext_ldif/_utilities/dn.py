"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
import string
from collections.abc import Callable, Generator, Mapping, Sequence
from pathlib import Path
from typing import Literal, cast, overload

from flext_core import (
    FlextTypes,
    FlextUtilities as u,
    r,
)

from flext_ldif._models.config import FlextLdifModelsConfig
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import c
from flext_ldif.models import m


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

    Character Classes (c.Ldif.Rfc):
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

    Escaping Rules (c.Ldif.Rfc):
    ========================================
    - Characters always requiring escaping: Rfc.DN_ESCAPE_CHARS
    - Characters requiring escaping at start: Rfc.DN_ESCAPE_AT_START
    - Characters requiring escaping at end: Rfc.DN_ESCAPE_AT_END

    Metadata Keys (c.Ldif.Rfc):
    =======================================
    - META_DN_ORIGINAL: Original DN before normalization
    - META_DN_WAS_BASE64: DN was base64 encoded
    - META_DN_ESCAPES_APPLIED: Escape sequences used

    All methods return primitives (str, list, tuple, bool, int, None).
    Pure functions: no server-specific logic, no side effects.

    Supports both:
    - m.Ldif.DN (DN model)
    - str (DN string value)

    """

    # Minimum length for valid DN strings (to check trailing escape)
    # Use constant from c.Ldif.Rfc
    MIN_DN_LENGTH: int = c.Ldif.Format.MIN_DN_LENGTH

    # ==========================================================================
    # RFC 4514 Character Class Validation (ABNF-based)
    # ==========================================================================

    @staticmethod
    def is_lutf1_char(char: str) -> bool:
        """Check if char is valid LUTF1 (lead char) per RFC 4514.

        LUTF1 = %x01-1F / %x21 / %x24-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
        (excludes NUL, SPACE, DQUOTE, SHARP, PLUS, COMMA, SEMI, LANGLE, RANGLE, ESC)

        Uses c.Ldif.Format.DN_LUTF1_EXCLUDE for exclusion set.

        Args:
            char: Single character to validate

        Returns:
            True if char is valid LUTF1, False otherwise

        """
        if not char or len(char) != 1:
            return False
        code = ord(char)
        # Must be in ASCII range 0x01-0x7F and not in exclusion set
        # Use getattr to help type checker understand nested class access
        rfc_format = c.Ldif.Format
        safe_min = rfc_format.SAFE_CHAR_MIN
        safe_max = rfc_format.SAFE_CHAR_MAX
        if code < safe_min or code > safe_max:
            return False
        return code not in c.Ldif.Format.DN_LUTF1_EXCLUDE

    @staticmethod
    def is_tutf1_char(char: str) -> bool:
        """Check if char is valid TUTF1 (trail char) per RFC 4514.

        TUTF1 = %x01-1F / %x21 / %x23-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
        (excludes NUL, SPACE, and special chars but allows SHARP)

        Uses c.Ldif.Format.DN_TUTF1_EXCLUDE for exclusion set.

        Args:
            char: Single character to validate

        Returns:
            True if char is valid TUTF1, False otherwise

        """
        if not char or len(char) != 1:
            return False
        code = ord(char)
        # Use getattr to help type checker understand nested class access
        rfc_format = c.Ldif.Format
        safe_min = rfc_format.SAFE_CHAR_MIN
        safe_max = rfc_format.SAFE_CHAR_MAX
        if code < safe_min or code > safe_max:
            return False
        return code not in c.Ldif.Format.DN_TUTF1_EXCLUDE

    @staticmethod
    def is_sutf1_char(char: str) -> bool:
        """Check if char is valid SUTF1 (string char) per RFC 4514.

        SUTF1 = %x01-21 / %x23-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
        (excludes special chars but allows SPACE and SHARP)

        Uses c.Ldif.Format.DN_SUTF1_EXCLUDE for exclusion set.

        Args:
            char: Single character to validate

        Returns:
            True if char is valid SUTF1, False otherwise

        """
        if not char or len(char) != 1:
            return False
        code = ord(char)
        # Use getattr to help type checker understand nested class access
        rfc_format = c.Ldif.Format
        safe_min = rfc_format.SAFE_CHAR_MIN
        safe_max = rfc_format.SAFE_CHAR_MAX
        if code < safe_min or code > safe_max:
            return False
        return code not in c.Ldif.Format.DN_SUTF1_EXCLUDE

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
        if char in c.Ldif.Format.DN_ESCAPE_CHARS:
            return True

        # Escape at start
        if position == 0 and char in c.Ldif.Format.DN_ESCAPE_AT_START:
            return True

        # Escape at end
        is_last = position == total_len - 1
        return is_last and char in c.Ldif.Format.DN_ESCAPE_AT_END

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
        dn: m.Ldif.DN | str | object,
    ) -> str:
        """Extract DN string value from DN model or string (public utility method).

        Args:
            dn: DN model (Any) or DN string

        Returns:
            DN string value

        """
        # Check if it's a DN model (local import to avoid circular dependency)

        if isinstance(dn, m.Ldif.DN):
            return dn.value
        if isinstance(dn, str):
            return dn
        return str(dn)

    @overload
    @staticmethod
    def split(dn: str) -> list[str]: ...

    @overload
    @staticmethod
    def split(dn: m.Ldif.DN) -> list[str]: ...

    @staticmethod
    def split(dn: str | m.Ldif.DN) -> list[str]:
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
    def norm_string(dn: m.Ldif.DN) -> str: ...

    @staticmethod
    def norm_string(dn: str | m.Ldif.DN) -> str:
        """Normalize full DN to RFC 4514 format."""
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not dn_str or "=" not in dn_str:
            return dn_str  # Return as-is if invalid (legacy method - returns str not r)
        components = FlextLdifUtilitiesDN.split(dn_str)
        normalized = u.Collection.map(
            components,
            mapper=FlextLdifUtilitiesDN.norm_component,
        )
        return ",".join(normalized if isinstance(normalized, list) else components)

    @staticmethod
    def _validate_components(components: list[str]) -> bool:
        """Validate each DN component has attr=value format (helper method)."""

        def is_valid_component(comp: str) -> bool:
            """Check if component is valid."""
            if "=" not in comp:
                return False
            attr, _, value = comp.partition("=")
            return bool(attr.strip() and value.strip())

        filtered = u.Collection.filter(components, is_valid_component)
        return isinstance(filtered, list) and len(filtered) == len(components)

    @staticmethod
    def _validate_basic_format(dn_str: str) -> bool:
        """Validate basic DN format requirements."""
        return bool(dn_str and "=" in dn_str)

    @staticmethod
    def _validate_dn_structure(dn_str: str) -> bool:
        """Validate DN structure (commas, escape sequences, components)."""
        checks: list[Callable[[], bool]] = [
            lambda: FlextLdifUtilitiesDN._validate_escape_sequences(dn_str),
            lambda: not FlextLdifUtilitiesDN._has_double_unescaped_commas(dn_str),
            lambda: not dn_str.startswith(","),
            lambda: not (
                dn_str.endswith(",")
                and (
                    len(dn_str) < FlextLdifUtilitiesDN.MIN_DN_LENGTH
                    or dn_str[-2] != "\\"
                )
            ),
        ]
        return all(check() for check in checks)

    @staticmethod
    def validate(dn: str | m.Ldif.DN) -> bool:
        r"""Validate DN format according to RFC 4514.

        Properly handles escaped characters. Checks for:
        - No double unescaped commas
        - No leading/trailing unescaped commas
        - All components have attr=value format
        - Valid hex escape sequences (\XX where X is hex digit)
        """
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not FlextLdifUtilitiesDN._validate_basic_format(dn_str):
            return False
        if not FlextLdifUtilitiesDN._validate_dn_structure(dn_str):
            return False

        try:
            components = FlextLdifUtilitiesDN.split(dn_str)
            return bool(
                components and FlextLdifUtilitiesDN._validate_components(components),
            )
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
    def parse(dn: str) -> r[list[tuple[str, str]]]: ...

    @overload
    @staticmethod
    def parse(
        dn: m.Ldif.DN,
    ) -> r[list[tuple[str, str]]]: ...

    @staticmethod
    def parse(
        dn: str | m.Ldif.DN | None,
    ) -> r[list[tuple[str, str]]]:
        """Parse DN into RFC 4514 components (attr, value pairs).

        RFC 4514 Section 3 - Parsing a String Back to DN:
        =================================================
        1. Split on unescaped commas to get RDNs
        2. For each RDN, split on unescaped plus signs for multi-valued
        3. Each AVA is attributeType=attributeValue
        4. Unescape the attributeValue

        Returns:
            r with [(attr1, value1), (attr2, value2), ...] or failure.

        """
        # Early validation - consolidate returns
        if dn is None:
            return r.fail("DN cannot be None")
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not dn_str or "=" not in dn_str:
            error_msg = (
                "DN string is empty"
                if not dn_str
                else f"Invalid DN format: missing '=' separator in '{dn_str}'"
            )
            return r.fail(error_msg)

        try:
            components = FlextLdifUtilitiesDN.split(dn_str)

            def parse_component(comp: str) -> tuple[str, str] | None:
                """Parse single component into (attr, value) tuple."""
                if "=" not in comp:
                    return None
                attr, _, value = comp.partition("=")
                return (attr.strip(), value.strip())

            process_result = u.Collection.process(
                components,
                processor=parse_component,
                predicate=lambda comp: "=" in comp,
                on_error="skip",
            )
            if process_result.is_failure:
                return r.fail(f"Failed to parse DN components from '{dn_str}'")
            parsed_list = process_result.value
            if not isinstance(parsed_list, list):
                return r.fail(f"Unexpected parse result type from '{dn_str}'")
            tuple_length = 2
            result = [
                item
                for item in parsed_list
                if isinstance(item, tuple) and len(item) == tuple_length
            ]
            return (
                r.ok(result)
                if result
                else r.fail(f"Failed to parse DN components from '{dn_str}'")
            )
        except Exception as e:
            return r.fail(f"DN parsing error: {e}")

    @overload
    @staticmethod
    def norm(dn: str) -> r[str]: ...

    @overload
    @staticmethod
    def norm(dn: m.Ldif.DN) -> r[str]: ...

    @staticmethod
    def norm(
        dn: str | m.Ldif.DN | None,
    ) -> r[str]:
        """Normalize DN per RFC 4514 (lowercase attrs, preserve values).

        Pure implementation without external dependencies.
        Returns r with normalized DN string or failure.
        """
        # Early validation - consolidate returns
        if dn is None:
            return r.fail("DN cannot be None")
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not dn_str or "=" not in dn_str:
            error_msg = (
                "Failed to normalize DN: DN string is empty"
                if not dn_str
                else f"Failed to normalize DN: Invalid DN format: missing '=' separator in '{dn_str}'"
            )
            return r.fail(error_msg)

        try:
            components = FlextLdifUtilitiesDN.split(dn_str)

            def normalize_component(comp: str) -> str | None:
                """Normalize single component."""
                if "=" not in comp:
                    return None
                attr, _, value = comp.partition("=")
                # RFC 4514 normalization: lowercase attribute TYPE, preserve value case
                return f"{attr.strip().lower()}={value.strip()}"

            process_result = u.Collection.process(
                components,
                processor=normalize_component,
                predicate=lambda comp: "=" in comp,
                on_error="skip",
            )
            if process_result.is_failure:
                return r.fail(
                    f"Failed to normalize DN: no valid components in '{dn_str}'",
                )
            normalized_list = process_result.value
            if not isinstance(normalized_list, list):
                return r.fail(f"Unexpected normalize result type from '{dn_str}'")
            filtered_str = u.Collection.filter(
                normalized_list,
                predicate=lambda x: isinstance(x, str),
            )
            # Ensure we have a list of strings for join
            normalized: list[str] = [
                str(item)
                for item in (filtered_str if isinstance(filtered_str, list) else [])
                if item is not None
            ]
            return (
                r.ok(",".join(normalized))
                if normalized
                else r.fail(
                    f"Failed to normalize DN: no valid components in '{dn_str}'",
                )
            )
        except Exception as e:
            return r.fail(f"DN normalization error: {e}")

    @staticmethod
    def norm_with_statistics(
        dn: str,
        original_dn: str | None = None,
    ) -> r[tuple[str, FlextLdifModelsDomains.DNStatistics]]:
        """Normalize DN with statistics tracking.

        Args:
            dn: DN to normalize
            original_dn: Original DN before any transformations (optional)

        Returns:
            r with tuple of (normalized_dn, DNStatistics) or failure

        """
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not dn_str:
            return r.fail(
                "DN string is empty or invalid",
            )
        # Use original_dn if provided, otherwise use dn_str
        orig = original_dn or dn_str

        norm_result = FlextLdifUtilitiesDN.norm(dn_str)
        if not norm_result.is_success:
            return r.fail(
                norm_result.error or "DN normalization failed",
            )
        normalized = norm_result.value

        # Track if normalization changed the DN
        transformations: list[str] = []
        if dn_str != normalized:
            transformations.append(c.Ldif.TransformationType.DN_NORMALIZED)

        # Create statistics
        stats = FlextLdifModelsDomains.DNStatistics.create_with_transformation(
            original_dn=orig,
            cleaned_dn=dn_str,
            normalized_dn=normalized,
            transformations=transformations,
        )

        return r.ok(
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
    def clean_dn(dn: m.Ldif.DN) -> str: ...

    @staticmethod
    def clean_dn(dn: str | m.Ldif.DN) -> str:
        """Clean DN string to fix spacing and escaping issues.

        Removes spaces before '=', fixes trailing backslash+space,
        normalizes whitespace around commas.

        **DRY Optimization**: Uses u.LdifParser.apply_regex_pipeline()
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
                c.Ldif.DnPatterns.DN_TRAILING_BACKSLASH_SPACE,
                c.Ldif.DnPatterns.DN_COMMA,
            ),
            # Remove spaces BEFORE commas (OID quirk: "cn=user ,ou=..." -> "cn=user,ou=...")
            (r"\s+,", ","),
            # Normalize spaces around commas: ", cn=..." -> ",cn=..."
            (
                c.Ldif.DnPatterns.DN_SPACES_AROUND_COMMA,
                c.Ldif.DnPatterns.DN_COMMA,
            ),
            # Remove unnecessary character escapes (RFC 4514 compliance)
            (c.Ldif.DnPatterns.DN_UNNECESSARY_ESCAPES, r"\1"),
            # Normalize multiple spaces to single space
            (c.Ldif.DnPatterns.DN_MULTIPLE_SPACES, " "),
        ]

        # Apply regex pipeline using sequential processing
        try:
            result = dn_str
            for pattern, replacement in patterns:
                result = re.sub(pattern, replacement, result)
            return result
        except Exception:
            return dn_str

    @staticmethod
    def clean_dn_with_statistics(
        dn: str,
    ) -> tuple[str, FlextLdifModelsDomains.DNStatistics]:
        r"""Clean DN and track all transformations with statistics.

        Returns both cleaned DN and complete transformation history
        for diagnostic and audit purposes.

        Args:
            dn: DN string or DN object

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
            stats_domain = FlextLdifModelsDomains.DNStatistics.create_minimal(
                original_dn,
            )
            stats = FlextLdifModelsDomains.DNStatistics.model_validate(
                stats_domain.model_dump(),
            )
            return original_dn, stats

        # Apply transformations and collect flags
        result, transformations, flags = FlextLdifUtilitiesDN._apply_dn_transformations(
            original_dn,
        )

        # Create statistics using type-safe flags from dict
        # Extract and type-narrow validation fields
        validation_status_raw = flags.get("validation_status", "")
        validation_status: str = (
            validation_status_raw if isinstance(validation_status_raw, str) else ""
        )
        validation_warnings_raw = flags.get("validation_warnings", [])
        validation_warnings: list[str] = (
            validation_warnings_raw if isinstance(validation_warnings_raw, list) else []
        )
        validation_errors_raw = flags.get("validation_errors", [])
        validation_errors: list[str] = (
            validation_errors_raw if isinstance(validation_errors_raw, list) else []
        )

        stats_domain = FlextLdifModelsDomains.DNStatistics.create_with_transformation(
            original_dn=original_dn,
            cleaned_dn=result,
            normalized_dn=result,
            transformations=transformations,
            had_tab_chars=flags.get("had_tab_chars", False) is True,
            had_trailing_spaces=flags.get("had_trailing_spaces", False) is True,
            had_leading_spaces=flags.get("had_leading_spaces", False) is True,
            had_extra_spaces=flags.get("had_extra_spaces", False) is True,
            was_base64_encoded=flags.get("was_base64_encoded", False) is True,
            had_utf8_chars=flags.get("had_utf8_chars", False) is True,
            had_escape_sequences=flags.get("had_escape_sequences", False) is True,
            validation_status=validation_status,
            validation_warnings=validation_warnings,
            validation_errors=validation_errors,
        )
        return result, stats_domain

    @staticmethod
    def _apply_dn_transformations(
        original_dn: str,
    ) -> tuple[str, list[str], dict[str, bool | str | list[str]]]:
        """Apply DN transformations and collect flags.

        Extracted to reduce complexity of clean_dn_with_statistics.

        Returns:
            Tuple of (transformed_dn, transformations_list, flags_dict)
            flags_dict follows m.TransformationFlags structure

        """
        transformations: list[str] = []
        flags: dict[str, bool | str | list[str]] = {
            "had_tab_chars": False,
            "had_trailing_spaces": False,
            "had_leading_spaces": False,
            "had_extra_spaces": False,
            "was_base64_encoded": False,
            "had_utf8_chars": False,
            "had_escape_sequences": False,
            "validation_status": "",
            "validation_warnings": [],
            "validation_errors": [],
        }
        result = original_dn

        # Define transformation rules: (detect_pattern, replace_pattern, replacement, transform_type, flag_name)
        # Each rule: (detect_regex, replace_regex, replacement, transformation_type, flag_attr)
        transform_rules: list[tuple[str, str, str, str, str]] = [
            # 1. Tab/whitespace control chars
            (
                r"[\t\r\n\x0b\x0c]",
                r"[\t\r\n\x0b\x0c]",
                " ",
                c.Ldif.TransformationType.TAB_NORMALIZED,
                "had_tab_chars",
            ),
            # 2. Spaces before equals
            (
                r"\s+=",
                r"\s+=",
                "=",
                c.Ldif.TransformationType.SPACE_CLEANED,
                "had_leading_spaces",
            ),
            # 3. Spaces before commas
            (
                r"\s+,",
                r"\s+,",
                ",",
                c.Ldif.TransformationType.SPACE_CLEANED,
                "had_trailing_spaces",
            ),
            # 4. Trailing backslash+space
            (
                c.Ldif.DnPatterns.DN_TRAILING_BACKSLASH_SPACE,
                c.Ldif.DnPatterns.DN_TRAILING_BACKSLASH_SPACE,
                c.Ldif.DnPatterns.DN_COMMA,
                c.Ldif.TransformationType.ESCAPE_NORMALIZED,
                "had_escape_sequences",
            ),
            # 5. Spaces around commas
            (
                c.Ldif.DnPatterns.DN_SPACES_AROUND_COMMA,
                c.Ldif.DnPatterns.DN_SPACES_AROUND_COMMA,
                c.Ldif.DnPatterns.DN_COMMA,
                c.Ldif.TransformationType.SPACE_CLEANED,
                "",
            ),
            # 6. Unnecessary escapes
            (
                c.Ldif.DnPatterns.DN_UNNECESSARY_ESCAPES,
                c.Ldif.DnPatterns.DN_UNNECESSARY_ESCAPES,
                r"\1",
                c.Ldif.TransformationType.ESCAPE_NORMALIZED,
                "",
            ),
            # 7. Multiple spaces
            (
                c.Ldif.DnPatterns.DN_MULTIPLE_SPACES,
                c.Ldif.DnPatterns.DN_MULTIPLE_SPACES,
                " ",
                c.Ldif.TransformationType.SPACE_CLEANED,
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
                    flags[flag_name] = True

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

        escape_chars = c.Ldif.Format.DN_ESCAPE_CHARS

        def escape_char(item: tuple[int, str]) -> str:
            """Escape single character if needed."""
            i, char = item
            is_special = char in escape_chars
            is_leading_space = i == 0 and char == " "
            is_trailing_space = i == len(value) - 1 and char == " "
            is_leading_sharp = i == 0 and char == "#"
            if is_special or is_leading_space or is_trailing_space or is_leading_sharp:
                return f"\\{ord(char):02x}"
            return char

        enumerated = list(enumerate(value))
        mapped_result = u.Collection.map(enumerated, mapper=escape_char)
        mapped = (
            mapped_result
            if isinstance(mapped_result, list)
            else [escape_char(item) for item in enumerated]
        )
        return "".join(mapped)

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
    def _normalize_dns_for_comparison(
        dn1: str,
        dn2: str,
    ) -> r[tuple[str, str]]:
        """Normalize both DNs for comparison."""
        norm1_result = FlextLdifUtilitiesDN.norm(dn1)
        if not norm1_result.is_success:
            return r.fail(
                f"Comparison failed (RFC 4514): Failed to normalize first DN: {norm1_result.error}",
            )

        norm2_result = FlextLdifUtilitiesDN.norm(dn2)
        if not norm2_result.is_success:
            return r.fail(
                f"Comparison failed (RFC 4514): Failed to normalize second DN: {norm2_result.error}",
            )

        return r.ok((
            norm1_result.value.lower(),
            norm2_result.value.lower(),
        ))

    @staticmethod
    def compare_dns(
        dn1: str | None,
        dn2: str | None,
    ) -> r[int]:
        """Compare two DNs per RFC 4514 (case-insensitive).

        Returns: r with -1 if dn1 < dn2, 0 if equal, 1 if dn1 > dn2, or failure
        """
        try:
            if not dn1 or not dn2:
                return r.fail("Both DNs must be provided for comparison")

            norm_result = FlextLdifUtilitiesDN._normalize_dns_for_comparison(dn1, dn2)
            if not norm_result.is_success:
                return r.fail(norm_result.error or "Normalization failed")

            norm1_lower, norm2_lower = norm_result.value
            comparison = (norm1_lower > norm2_lower) - (norm1_lower < norm2_lower)
            return r.ok(comparison)
        except Exception as e:
            return r.fail(f"DN comparison error: {e}")

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
        config: FlextLdifModelsConfig.RdnProcessingConfig,
    ) -> tuple[str, str, bool, int, bool]:
        """Process single character in RDN parsing.

        Returns: (current_attr, current_val, in_value, next_i, should_continue)
        should_continue=True means skip normal increment
        Updates config.pairs when a pair is completed.
        """
        current_attr = config.current_attr
        current_val = config.current_val
        in_value = config.in_value

        if char == "\\" and i + 1 < len(rdn):
            current_val, next_i = FlextLdifUtilitiesDN._process_rdn_escape(
                rdn,
                i,
                config.current_val,
            )
            config.current_val = current_val
            return current_attr, current_val, in_value, next_i, True

        if char == "=" and not in_value:
            current_attr = current_attr.strip().lower()
            config.current_attr = current_attr
            config.in_value = True
            return current_attr, current_val, True, i + 1, True

        if char == "+" and in_value:
            current_val = current_val.strip()
            if current_attr:
                config.pairs.append((current_attr, current_val))
            config.current_attr = ""
            config.current_val = ""
            config.in_value = False
            return "", "", False, i + 1, True

        if in_value:
            current_val += char
            config.current_val = current_val
        else:
            current_attr += char
            config.current_attr = current_attr

        return current_attr, current_val, in_value, i + 1, False

    @staticmethod
    def _advance_rdn_position(
        char: str,
        rdn: str,
        position: int,
        config: FlextLdifModelsConfig.RdnProcessingConfig,
    ) -> tuple[str, str, bool, int]:
        """Advance position during RDN parsing and return new state.

        Returns: (current_attr, current_val, in_value, next_position)
        """
        result = FlextLdifUtilitiesDN._process_rdn_char(
            char,
            rdn,
            position,
            config,
        )
        attr, val, in_val, next_pos, _ = result
        return (attr, val, in_val, next_pos)

    @staticmethod
    def parse_rdn(rdn: str) -> r[list[tuple[str, str]]]:
        """Parse a single RDN component per RFC 4514.

        Returns r with list of (attr, value) pairs or failure.
        """
        if not rdn or not isinstance(rdn, str):
            return r.fail(
                "RDN must be a non-empty string",
            )

        try:
            pairs: list[tuple[str, str]] = []
            current_attr = ""
            current_val = ""
            in_value = False
            rdn_len: int = len(rdn)
            position: int = 0

            rdn_config = FlextLdifModelsConfig.RdnProcessingConfig(
                current_attr=current_attr,
                current_val=current_val,
                in_value=in_value,
                pairs=pairs,
            )

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
                        rdn_config,
                    )
                )
                # Update config state from return values
                rdn_config.current_attr = current_attr
                rdn_config.current_val = current_val
                rdn_config.in_value = in_value
                # Update pairs from config (mutated by _process_rdn_char)
                pairs = rdn_config.pairs

                if char_at_pos == "=" and not in_value and not current_attr:
                    return r.fail(
                        f"Invalid RDN format: unexpected '=' at position {idx}",
                    )

            if not in_value or not current_attr:
                return r.fail(
                    f"Invalid RDN format: missing attribute or value in '{rdn}'",
                )

            current_val = current_val.strip()
            if not current_val:
                return r.fail(
                    f"Invalid RDN format: empty value in '{rdn}'",
                )
            pairs.append((current_attr, current_val))

            return r.ok(pairs)

        except Exception as e:
            return r.fail(f"RDN parsing error: {e}")

    @staticmethod
    def extract_rdn(dn: str) -> r[str]:
        """Extract leftmost RDN from DN.

        For DN "cn=John,ou=Users,dc=example,dc=com", returns "cn=John".

        Args:
            dn: Distinguished Name string

        Returns:
            r with leftmost RDN (attr=value) or failure

        """
        if not dn or "=" not in dn:
            return r.fail(
                f"Invalid DN format: missing '=' separator in '{dn}'",
            )

        try:
            components = FlextLdifUtilitiesDN.split(dn)
            if not components:
                return r.fail(
                    f"Failed to extract RDN: no components found in '{dn}'",
                )
            return r.ok(components[0])
        except Exception as e:
            return r.fail(f"RDN extraction error: {e}")

    @staticmethod
    def extract_parent_dn(dn: str) -> r[str]:
        """Extract parent DN (remove leftmost RDN).

        For DN "cn=John,ou=Users,dc=example,dc=com",
        returns "ou=Users,dc=example,dc=com".

        Args:
            dn: Distinguished Name string

        Returns:
            r with parent DN (without leftmost RDN) or failure if DN has ≤1 component

        """
        if not dn or "=" not in dn:
            return r.fail(
                f"Invalid DN format: missing '=' separator in '{dn}'",
            )

        try:
            components = FlextLdifUtilitiesDN.split(dn)
            if len(components) <= 1:
                return r.fail(
                    f"Cannot extract parent DN: DN has only one component '{dn}'",
                )
            return r.ok(",".join(components[1:]))
        except Exception as e:
            return r.fail(f"Parent DN extraction error: {e}")

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
    ) -> r[bool]:
        """Validate DN format and compare against context DN if provided.

        Generic DN validation combining RFC 4514 format check and context comparison.
        Used for ACL subject/target DN validation and similar use cases.

        Args:
            dn_value: DN string to validate (None or "*" treated as wildcard)
            context_dn: Optional context DN to compare against
            dn_label: Label for error messages (e.g., "subject DN", "target DN")

        Returns:
            r[bool]: Success if valid, failure with descriptive error

        Example:
            # Validate subject DN
            result = validate_dn_with_context(
                "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                "subject DN"
            )

            # Wildcard DN (always valid)
            result = validate_dn_with_context("*", None, "target DN")
            # Returns: r.ok(True)

            # Invalid DN format
            result = validate_dn_with_context("invalid", None, "DN")
            # Returns: r.fail("Invalid DN format per RFC 4514: invalid")

        """
        # Wildcard or None is always valid
        if not dn_value or dn_value == "*":
            return r.ok(True)

        # Validate DN format per RFC 4514
        if not FlextLdifUtilitiesDN.validate(dn_value):
            return r.fail(
                f"Invalid {dn_label} format per RFC 4514: {dn_value}",
            )

        # If context DN provided, compare case-insensitively
        if context_dn:
            comparison_result = FlextLdifUtilitiesDN.compare_dns(
                str(context_dn),
                dn_value,
            )
            if not comparison_result.is_success:
                return r.fail(
                    f"DN comparison failed: {comparison_result.error}",
                )
            comparison_value = comparison_result.value
            if comparison_value != 0:  # 0 means equal
                return r.fail(
                    f"{dn_label.capitalize()} mismatch: {context_dn} != {dn_value}",
                )

        return r.ok(True)

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
        value: m.Ldif.DN,
        source_dn: str,
        target_dn: str,
    ) -> str: ...

    @staticmethod
    def transform_dn_attribute(
        value: str | m.Ldif.DN,
        source_dn: str,
        target_dn: str,
    ) -> str:
        """Transform a single DN attribute value by replacing base DN.

        Used for transforming DN-syntax attributes (member, uniqueMember, manager, etc.)
        when migrating from one LDAP server to another with different base DNs.

        Args:
            value: DN value to transform (str or DN model)
            source_dn: Source base DN to replace (e.g., "dc=example")
            target_dn: Target base DN replacement (e.g., "dc=example,dc=com")

        Returns:
            Transformed DN with base DN replaced, or original value if no match

        Example:
            transform_dn_attribute(
                "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example",
                "dc=example",
                "dc=example,dc=com"
            )
            # Returns: "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"

        """
        dn_str = FlextLdifUtilitiesDN.get_dn_value(value)
        if not dn_str or not source_dn or not target_dn:
            return dn_str

        # Normalize the DN first
        norm_result = FlextLdifUtilitiesDN.norm(dn_str)
        normalized_dn = norm_result.value if norm_result.is_success else dn_str

        # Use regex to replace source base DN suffix with target base DN
        # Pattern: match either:
        # 1. ",source_dn" at the END of DN (e.g., "ou=people,dc=example")
        # 2. "source_dn" alone at the END of DN (e.g., "dc=example" as root DN)
        # Both cases are case-insensitive
        source_escaped = re.escape(source_dn)

        # Try replacing with comma first (non-root DN case: "ou=people,dc=example")
        result = re.sub(
            f",{source_escaped}$",
            f",{target_dn}",
            normalized_dn,
            flags=re.IGNORECASE,
        )

        # If no substitution happened, try without comma (root DN case: "dc=example")
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
        entries: list[m.Ldif.Entry],
        source_dn: str,
        target_dn: str,
    ) -> list[m.Ldif.Entry]:
        """Replace base DN in all entries and DN-valued attributes.

        Transforms:
        - Entry DNs (dn property)
        - DN-syntax attributes (member, uniqueMember, manager, owner, seeAlso, etc.)
        - Any other DN references in attribute values

        Used for server-to-server migration when source and target have different base DNs.

        Args:
            entries: List of Entry models to transform
            source_dn: Source base DN to replace (e.g., "dc=example")
            target_dn: Target base DN replacement (e.g., "dc=example,dc=com")

        Returns:
            List of Entry models with all base DN references replaced

        Example:
            entries = [
                Entry(
                    dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example",
                    attributes={"member": ["cn=user,dc=example"]}
                ),
                ...
            ]
            transformed = replace_base_dn(entries, "dc=example", "dc=example,dc=com")
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

        def transform_entry(
            entry: m.Ldif.Entry,
        ) -> m.Ldif.Entry | r[m.Ldif.Entry]:
            """Transform single entry."""
            if entry.dn is None or entry.attributes is None:
                return r[m.Ldif.Entry].fail("Entry has no DN or attributes")
            # Type narrowing: entry.dn is not None after check
            # Use get_dn_value to handle str | DN | None
            dn_value = FlextLdifUtilitiesDN.get_dn_value(entry.dn)
            if not dn_value:
                return r[m.Ldif.Entry].fail("Entry DN is empty")
            transformed_dn = FlextLdifUtilitiesDN.transform_dn_attribute(
                dn_value,
                source_dn,
                target_dn,
            )
            transformed_attrs = FlextLdifUtilitiesDN._transform_attrs_with_dn(
                dict(entry.attributes.items())
                if hasattr(entry.attributes, "items")
                else {},
                dn_attributes,
                source_dn,
                target_dn,
            )
            return entry.model_copy(
                update={
                    "dn": transformed_dn,
                    "attributes": m.Ldif.Attributes(attributes=transformed_attrs),
                },
            )

        batch_result = u.Collection.batch(
            list(entries),
            transform_entry,
            on_error="skip",
        )
        if batch_result.is_failure:
            return entries
        batch_data = batch_result.value
        # Type narrowing: batch_data["results"] is object, check if list
        results_raw = batch_data.get("results", [])
        if isinstance(results_raw, list):
            return [item for item in results_raw if isinstance(item, m.Ldif.Entry)]
        return entries

    @staticmethod
    def transform_ldif_files_in_directory(
        ldif_dir: Path,
        source_basedn: str,
        target_basedn: str,
    ) -> r[dict[str, FlextTypes.GeneralValueType]]:
        """Transform BaseDN in all LDIF files in directory.

        Reads all *.ldif files from directory, transforms BaseDN in entries,
        and writes updated files back. Preserves file organization and metadata.

        Args:
            ldif_dir: Directory containing LDIF files
            source_basedn: Source base DN to replace
            target_basedn: Target base DN replacement

        Returns:
            r with dict containing:
            - transformed_count: Number of successfully transformed files
            - failed_count: Number of files that failed
            - total_count: Total LDIF files processed

        """
        try:
            if not ldif_dir.exists():
                return r.fail(f"Directory not found: {ldif_dir}")

            transformed_count = 0
            failed_count = 0

            for ldif_file in sorted(ldif_dir.glob("*.ldif")):
                try:
                    content = ldif_file.read_text(encoding="utf-8")
                    lines = content.split("\n")
                    transformed_lines: list[str] = []

                    def transform_line(line: str) -> str:
                        """Transform single LDIF line."""
                        if not line or ":" not in line:
                            return line
                        parts = line.split(":", 1)
                        attr_name = parts[0]
                        attr_value = parts[1].strip() if len(parts) > 1 else ""
                        if not attr_value or source_basedn not in attr_value:
                            return line
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
                            return f"{attr_name}: {transformed_value}"
                        return line

                    mapped_result = u.Collection.map(lines, mapper=transform_line)
                    transformed_lines = (
                        mapped_result if isinstance(mapped_result, list) else lines
                    )

                    transformed_content = "\n".join(transformed_lines)
                    ldif_file.write_text(transformed_content, encoding="utf-8")
                    transformed_count += 1

                except (OSError, ValueError):
                    failed_count += 1
                    continue

            return r.ok({
                "transformed_count": transformed_count,
                "failed_count": failed_count,
                "total_count": transformed_count + failed_count,
            })

        except Exception as e:
            return r.fail(f"LDIF directory transformation failed: {e}")

    @staticmethod
    def _transform_attrs_with_dn(
        attrs: dict[str, list[str]],
        dn_attributes: set[str],
        source_dn: str,
        target_dn: str,
    ) -> dict[str, list[str]]:
        """Transform DN-valued attributes using u.map()."""

        def map_attr(k: str, v: list[str]) -> list[str]:
            """Map attribute: transform DN values if needed."""
            if k.lower() in dn_attributes:
                return [
                    FlextLdifUtilitiesDN.transform_dn_attribute(
                        val,
                        source_dn,
                        target_dn,
                    )
                    for val in v
                ]
            return v

        mapped = u.Collection.map(attrs, mapper=map_attr)
        return mapped if isinstance(mapped, dict) else attrs

    @staticmethod
    def _get_changed_attr_names(
        original: dict[str, list[str]],
        transformed: dict[str, list[str]],
        dn_attributes: set[str],
    ) -> list[str]:
        """Get list of attribute names that changed using u.Collection.filter()."""
        filtered_dict = u.Collection.filter(
            transformed,
            predicate=lambda k, v: (
                k.lower() in dn_attributes and v != original.get(k, [])
            ),
        )
        return list(filtered_dict.keys()) if isinstance(filtered_dict, dict) else []

    @staticmethod
    def _update_metadata_for_transformation(
        metadata: m.Ldif.QuirkMetadata,
        config: FlextLdifModelsConfig.MetadataTransformationConfig,
    ) -> None:
        """Update metadata with transformation tracking."""
        if config.transformed_dn != config.original_dn:
            metadata.track_dn_transformation(
                original_dn=config.original_dn,
                transformed_dn=config.transformed_dn,
                transformation_type="basedn_transform",
            )

        def track_attr(attr_name: str) -> None:
            """Track single attribute transformation."""
            metadata.track_attribute_transformation(
                original_name=attr_name,
                new_name=attr_name,
                transformation_type="modified",
                original_values=list(config.original_attrs.get(attr_name, [])),
                new_values=config.transformed_attrs[attr_name],
                reason=f"BaseDN transformation: {config.source_dn} → {config.target_dn}",
            )

        u.Collection.process(
            config.transformed_attr_names,
            processor=track_attr,
            on_error="skip",
        )
        metadata.add_conversion_note(
            operation="basedn_transform",
            description=f"Transformed BaseDN from {config.source_dn} to {config.target_dn}",
        )
        metadata.extensions[c.Ldif.MetadataKeys.ENTRY_SOURCE_DN_CASE] = (
            config.original_dn
        )
        metadata.extensions[c.Ldif.MetadataKeys.ENTRY_TARGET_DN_CASE] = (
            config.transformed_dn
        )

    @staticmethod
    def transform_dn_with_metadata(
        entry: m.Ldif.Entry,
        source_dn: str,
        target_dn: str,
    ) -> m.Ldif.Entry:
        """Transform DN and DN-valued attributes with metadata tracking.

        RFC Compliant: Tracks all transformations in QuirkMetadata for round-trip support.
        Uses c.Ldif.Format.Rfc.META_DN_* and MetadataKeys for standardized tracking.

        Args:
            entry: Entry to transform
            source_dn: Source base DN to replace
            target_dn: Target base DN replacement

        Returns:
            New Entry with transformed DN, attributes, and metadata tracking

        Example:
            >>> entry = m.Ldif.Entry(
            ...     dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example",
            ...     attributes={"member": ["cn=user,dc=example"]},
            ... )
            >>> transformed = FlextLdifUtilitiesDN.transform_dn_with_metadata(
            ...     entry, "dc=example", "dc=example,dc=com"
            ... )
            >>> # DN transformed: cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
            >>> # metadata.conversion_notes tracks the transformation

        """
        # Early returns for invalid inputs
        if not source_dn or not target_dn:
            return entry
        if entry.dn is None or entry.attributes is None:
            return entry

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
        # Type narrowing: entry.dn is not None (checked earlier)
        # Use get_dn_value to handle str | DN | None
        dn_value = FlextLdifUtilitiesDN.get_dn_value(entry.dn)
        if not dn_value:
            # Return original entry if DN is empty (early return pattern)
            return entry
        transformed_dn = FlextLdifUtilitiesDN.transform_dn_attribute(
            dn_value,
            source_dn,
            target_dn,
        )
        # Convert Attributes to dict for processing
        if hasattr(entry.attributes, "attributes"):
            attrs_dict = entry.attributes.attributes
        elif isinstance(entry.attributes, Mapping):
            attrs_dict = dict(entry.attributes)
        else:
            # Fallback for unknown attribute types
            attrs_dict = (
                dict(entry.attributes) if hasattr(entry.attributes, "items") else {}
            )
        transformed_attrs = FlextLdifUtilitiesDN._transform_attrs_with_dn(
            attrs_dict,
            dn_attributes,
            source_dn,
            target_dn,
        )
        transformed_attr_names = FlextLdifUtilitiesDN._get_changed_attr_names(
            attrs_dict,
            transformed_attrs,
            dn_attributes,
        )

        # Ensure metadata is always m.Ldif.QuirkMetadata (public facade)
        # Business Rule: entry.metadata can be domain or facade, but we need facade
        if entry.metadata:
            # Create new facade instance from domain metadata to ensure type compatibility
            # Use model_validate to convert domain to facade if needed
            metadata_dict = entry.metadata.model_dump()
            metadata = m.Ldif.QuirkMetadata.model_validate(metadata_dict)
        else:
            metadata = m.Ldif.QuirkMetadata.create_for()

        transform_config = FlextLdifModelsConfig.MetadataTransformationConfig(
            original_dn=original_dn_str,
            transformed_dn=transformed_dn,
            source_dn=source_dn,
            target_dn=target_dn,
            transformed_attr_names=transformed_attr_names,
            original_attrs=attrs_dict,
            transformed_attrs=transformed_attrs,
        )
        FlextLdifUtilitiesDN._update_metadata_for_transformation(
            metadata,
            transform_config,
        )
        return entry.model_copy(
            update={
                "dn": transformed_dn,
                "attributes": transformed_attrs,
                "metadata": metadata,
            },
        )

    @staticmethod
    def replace_base_dn_with_metadata(
        entries: list[m.Ldif.Entry],
        source_dn: str,
        target_dn: str,
    ) -> list[m.Ldif.Entry]:
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
            ...     entries, "dc=example", "dc=example,dc=com"
            ... )
            >>> # Each entry.metadata.conversion_notes tracks transformation

        """
        if not entries or not source_dn or not target_dn:
            return entries

        def transform_entry(
            entry: m.Ldif.Entry,
        ) -> m.Ldif.Entry:
            """Transform single entry."""
            return FlextLdifUtilitiesDN.transform_dn_with_metadata(
                entry,
                source_dn,
                target_dn,
            )

        batch_result = u.Collection.batch(
            list(entries),
            transform_entry,
            on_error="skip",
        )
        if batch_result.is_success:
            batch_data = batch_result.value
            # Type narrowing: batch_data["results"] is object, check if list
            results_raw = batch_data.get("results", [])
            if isinstance(results_raw, list):
                return [item for item in results_raw if isinstance(item, m.Ldif.Entry)]
        return entries

    # =========================================================================
    # BATCH METHODS - Power Method Support
    # =========================================================================

    @staticmethod
    def norm_or_fallback(
        dn: str | None,
        *,
        fallback: Literal["lower", "upper", "original"] = "lower",
    ) -> str:
        r"""Normalize DN or return fallback if normalization fails.

        Replaces the common 3-line pattern:
            norm_result = FlextLdifUtilitiesDN.norm(dn)
            normalized = norm_result.value if norm_result.is_success else dn.lower()

        With a single call:
            normalized = FlextLdifUtilitiesDN.norm_or_fallback(dn)

        Args:
            dn: DN string to normalize (or None)
            fallback: Fallback strategy if normalization fails:
                - "lower": Return dn.lower()
                - "upper": Return dn.upper()
                - "original": Return dn unchanged

        Returns:
            Normalized DN string, or fallback if normalization fails

        Examples:
            >>> FlextLdifUtilitiesDN.norm_or_fallback("CN=Test,DC=Example")
            'cn=test,dc=example'
            >>> FlextLdifUtilitiesDN.norm_or_fallback(None)
            ''
            >>> FlextLdifUtilitiesDN.norm_or_fallback(
            ...     "invalid\\\\dn", fallback="original"
            ... )
            'invalid\\\\dn'

        """
        if dn is None:
            return ""

        result = FlextLdifUtilitiesDN.norm(dn)
        if result.is_success:
            return result.value

        # Apply fallback strategy
        if fallback == "lower":
            return dn.lower()
        if fallback == "upper":
            return dn.upper()
        # "original"
        return dn

    @staticmethod
    def norm_batch(
        dns: Sequence[str],
        *,
        fallback: Literal["lower", "upper", "original", "skip"] = "lower",
        fail_fast: bool = False,
    ) -> r[list[str]]:
        """Normalize multiple DNs in one call.

        Args:
            dns: Sequence of DN strings to normalize
            fallback: Strategy for failed normalizations:
                - "lower": Use dn.lower() as fallback
                - "upper": Use dn.upper() as fallback
                - "original": Keep original DN unchanged
                - "skip": Exclude failed DNs from results
            fail_fast: If True, return error on first failure (ignores fallback)

        Returns:
            r containing list of normalized DNs

        Examples:
            >>> result = FlextLdifUtilitiesDN.norm_batch([
            ...     "CN=User1,DC=Example",
            ...     "CN=User2,DC=Example",
            ... ])
            >>> result.value
            ['cn=user1,dc=example', 'cn=user2,dc=example']

            >>> # With skip fallback for invalid DNs
            >>> result = FlextLdifUtilitiesDN.norm_batch(
            ...     ["CN=Valid", "invalid"],
            ...     fallback="skip",
            ... )

        """

        def normalize_dn(dn: str) -> r[str]:
            """Normalize single DN with fallback."""
            result = FlextLdifUtilitiesDN.norm(dn)
            if result.is_success:
                return result
            if fallback == "skip":
                return r.fail("Skipped")
            if fallback == "lower":
                return r.ok(dn.lower())
            if fallback == "upper":
                return r.ok(dn.upper())
            return r.ok(dn)

        if fail_fast:
            batch_result = u.Collection.batch(
                list(dns),
                cast("Callable[[str], r[str] | str]", normalize_dn),
                on_error="fail",
            )
            if batch_result.is_failure:
                return r.fail(batch_result.error or "Normalization failed")
            batch_data = batch_result.value
            return r.ok([
                item for item in batch_data["results"] if isinstance(item, str)
            ])

        batch_result = u.Collection.batch(
            list(dns),
            cast("Callable[[str], r[str] | str]", normalize_dn),
            on_error="skip",
        )
        if batch_result.is_failure:
            return r.fail(batch_result.error or "Normalization failed")
        batch_data = batch_result.value
        return r.ok([item for item in batch_data["results"] if isinstance(item, str)])

    @staticmethod
    def validate_batch(
        dns: Sequence[str],
        *,
        collect_errors: bool = True,
    ) -> r[list[tuple[str, bool, list[str]]]]:
        """Validate multiple DNs, returning validation status for each.

        Args:
            dns: Sequence of DN strings to validate
            collect_errors: Collect all errors (vs. fail on first)

        Returns:
            r containing list of (dn, is_valid, errors) tuples

        Examples:
            >>> result = FlextLdifUtilitiesDN.validate_batch([
            ...     "CN=Valid,DC=Example",
            ...     "invalid-dn",
            ... ])
            >>> for dn, is_valid, errors in result.value:
            ...     print(f"{dn}: {'valid' if is_valid else 'invalid'}")

        """

        def validate_dn(dn: str) -> tuple[str, bool, list[str]]:
            """Validate single DN."""
            is_valid, dn_errors = FlextLdifUtilitiesDN.is_valid_dn_string(dn)
            return (dn, is_valid, dn_errors)

        batch_result = u.Collection.batch(list(dns), validate_dn, on_error="skip")
        if batch_result.is_failure:
            return r.fail(batch_result.error or "Validation failed")
        batch_data = batch_result.value
        tuple_length = 3
        results = [
            item
            for item in batch_data["results"]
            if isinstance(item, tuple) and len(item) == tuple_length
        ]
        if not collect_errors:
            invalid_results = [item for item in results if not item[1]]
            if invalid_results:
                results = results[: results.index(invalid_results[0]) + 1]
        return r.ok(results)

    @staticmethod
    def replace_base_batch(
        dns: Sequence[str],
        old_base: str,
        new_base: str,
        *,
        fail_fast: bool = False,
    ) -> r[list[str]]:
        """Replace base DN in multiple DNs.

        Args:
            dns: Sequence of DN strings
            old_base: Old base DN to replace
            new_base: New base DN
            fail_fast: Stop on first error

        Returns:
            r containing list of DNs with replaced bases

        Examples:
            >>> result = FlextLdifUtilitiesDN.replace_base_batch(
            ...     ["cn=user1,dc=old,dc=com", "cn=user2,dc=old,dc=com"],
            ...     "dc=old,dc=com",
            ...     "dc=new,dc=com",
            ... )
            >>> result.value
            ['cn=user1,dc=new,dc=com', 'cn=user2,dc=new,dc=com']

        """
        old_base_lower = old_base.lower()

        def replace_dn(dn: str) -> str:
            """Replace base DN in single DN."""
            try:
                dn_lower = dn.lower()
                if dn_lower.endswith(old_base_lower):
                    prefix = dn[: len(dn) - len(old_base)]
                    return prefix + new_base
                return dn
            except Exception:
                if fail_fast:
                    raise
                return dn

        on_error_mode = "fail" if fail_fast else "skip"
        batch_result = u.Collection.batch(list(dns), replace_dn, on_error=on_error_mode)
        if batch_result.is_failure:
            return r.fail(batch_result.error or "Base replacement failed")
        batch_data = batch_result.value
        results = [item for item in batch_data["results"] if isinstance(item, str)]
        return r.ok(results)

    @staticmethod
    def process_complete(
        dn: str,
        *,
        clean: bool = True,
        validate: bool = True,
        normalize: bool = True,
        parse: bool = False,
    ) -> r[str | list[tuple[str, str]]]:
        """Complete DN processing pipeline in one call.

        Applies processing steps in order: clean → validate → normalize → parse.

        Args:
            dn: DN string to process
            clean: Clean whitespace and normalize escapes
            validate: Validate DN structure
            normalize: Normalize DN format
            parse: If True, return parsed components instead of string

        Returns:
            r containing:
                - Processed DN string if parse=False
                - List of (attribute, value) tuples if parse=True

        Examples:
            >>> # Full processing
            >>> result = FlextLdifUtilitiesDN.process_complete(
            ...     "  CN = Test , DC = Example ",
            ...     clean=True,
            ...     validate=True,
            ...     normalize=True,
            ... )
            >>> result.value
            'cn=test,dc=example'

            >>> # Parse into components
            >>> result = FlextLdifUtilitiesDN.process_complete(
            ...     "CN=Test,DC=Example",
            ...     parse=True,
            ... )
            >>> result.value
            [('cn', 'test'), ('dc', 'example')]

        """
        current_dn = dn

        # Step 1: Clean (clean_dn returns str directly)
        if clean:
            try:
                current_dn = FlextLdifUtilitiesDN.clean_dn(current_dn)
            except Exception as exc:
                return r.fail(f"Clean failed: {exc}")

        # Step 2: Validate
        if validate:
            is_valid, errors = FlextLdifUtilitiesDN.is_valid_dn_string(current_dn)
            if not is_valid:
                return r.fail(f"Validation failed: {', '.join(errors)}")

        # Step 3: Normalize
        if normalize:
            norm_result = FlextLdifUtilitiesDN.norm(current_dn)
            if norm_result.is_failure:
                return r.fail(f"Normalization failed: {norm_result.error}")
            current_dn = norm_result.value

        # Step 4: Parse (optional)
        # Business Rule: When parse=True, use parse() method which returns r[list[tuple[str, str]]]
        # This provides RFC 4514 compliant parsing into (attribute, value) pairs for audit trail
        # split() only returns list[str] and doesn't parse attribute/value pairs
        if parse:
            parse_result = FlextLdifUtilitiesDN.parse(current_dn)
            if parse_result.is_failure:
                return r.fail(f"Parse failed: {parse_result.error}")
            return r.ok(parse_result.value)

        return r.ok(current_dn)


__all__ = [
    "FlextLdifUtilitiesDN",
]
