"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
import string
from collections.abc import Generator
from typing import cast, overload

from flext_core import FlextResult

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes

# Type alias from FlextLdifTypes
DnInput = FlextLdifTypes.DnInput


class FlextLdifUtilitiesDN:
    """RFC 4514 DN Operations - Works with both DN models and string values.

    All methods return primitives (str, list, tuple, bool, int, None).
    Pure functions: no server-specific logic, no side effects.

    Supports both:
    - Any (DN model)
    - str (DN string value)

    Methods:
    - split: Split DN string into components
    - norm_component: Normalize single DN component
    - norm_string: Normalize full DN to RFC 4514 format
    - validate: Validate DN format according to RFC 4514
    - parse: Parse DN into (attr, value) tuples
    - norm: Normalize DN per RFC 4514 (lowercase attrs, preserve values)
    - clean_dn: Clean DN string to fix spacing and escaping issues
    - esc: Escape special characters in DN value per RFC 4514
    - unesc: Unescape special characters in DN value per RFC 4514
    - compare_dns: Compare two DNs per RFC 4514 (case-insensitive)
    - parse_rdn: Parse a single RDN component per RFC 4514

    """

    # Minimum length for valid DN strings (to check trailing escape)
    MIN_DN_LENGTH: int = 2

    @staticmethod
    def get_dn_value(
        dn: FlextLdifModelsDomains.DistinguishedName
        | FlextLdifModels.DistinguishedName
        | str
        | object,
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
        r"""Split DN string into individual components respecting RFC 4514 escapes.

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
            return dn_str
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
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not dn_str or "=" not in dn_str:
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
    def parse(dn: str) -> list[tuple[str, str]] | None: ...

    @overload
    @staticmethod
    def parse(
        dn: FlextLdifModels.DistinguishedName,
    ) -> list[tuple[str, str]] | None: ...

    @staticmethod
    def parse(dn: DnInput) -> list[tuple[str, str]] | None:
        """Parse DN into RFC 4514 components (attr, value pairs).

        Pure RFC 4514 parsing without external dependencies.
        Returns [(attr1, value1), (attr2, value2), ...] or None on error.
        """
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not dn_str or "=" not in dn_str:
            return None

        try:
            components = FlextLdifUtilitiesDN.split(dn_str)
            result: list[tuple[str, str]] = []

            for comp in components:
                if "=" not in comp:
                    continue
                attr, _, value = comp.partition("=")
                result.append((attr.strip(), value.strip()))

            return result or None
        except Exception:
            return None

    @overload
    @staticmethod
    def norm(dn: str) -> str | None: ...

    @overload
    @staticmethod
    def norm(dn: FlextLdifModels.DistinguishedName) -> str | None: ...

    @staticmethod
    def norm(dn: DnInput) -> str | None:
        """Normalize DN per RFC 4514 (lowercase attrs, preserve values).

        Pure implementation without external dependencies.
        """
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        try:
            if not dn_str or "=" not in dn_str:
                return None

            components = FlextLdifUtilitiesDN.split(dn_str)
            normalized: list[str] = []

            for comp in components:
                if "=" not in comp:
                    continue
                attr, _, value = comp.partition("=")
                # RFC 4514 normalization: lowercase attribute TYPE, preserve value case
                # Attribute types are case-insensitive, values are case-preserving
                normalized.append(f"{attr.strip().lower()}={value.strip()}")

            return ",".join(normalized) if normalized else None
        except Exception:
            return None

    @staticmethod
    def norm_with_statistics(
        dn: DnInput,
        original_dn: str | None = None,
    ) -> tuple[str | None, FlextLdifModels.DNStatistics | None]:
        """Normalize DN with statistics tracking.

        Args:
            dn: DN to normalize
            original_dn: Original DN before any transformations (optional)

        Returns:
            Tuple of (normalized_dn, DNStatistics) or (None, None) if invalid

        """
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if dn_str is None:
            return None, None
        orig = original_dn or dn_str

        normalized = FlextLdifUtilitiesDN.norm(dn_str)
        if normalized is None:
            return None, None

        # Track if normalization changed the DN
        transformations: list[str] = []
        if dn_str != normalized:
            transformations.append(FlextLdifConstants.TransformationType.DN_NORMALIZED)

        # Create statistics
        stats = FlextLdifModels.DNStatistics.create_with_transformation(
            original_dn=orig,
            cleaned_dn=dn_str,
            normalized_dn=normalized,
            transformations=transformations,
        )

        # Type narrowing: normalized and stats are guaranteed non-None here
        return cast(
            "tuple[str, FlextLdifModels.DNStatistics]",
            (normalized, stats),
        )

    @overload
    @staticmethod
    def clean_dn(dn: str) -> str: ...

    @overload
    @staticmethod
    def clean_dn(dn: FlextLdifModels.DistinguishedName) -> str: ...

    @staticmethod
    def clean_dn(dn: DnInput) -> str:
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
            # Cast to public type (FlextLdifModels.DNStatistics inherits from FlextLdifModelsDomains.DNStatistics)
            stats_minimal = cast(
                "FlextLdifModels.DNStatistics",
                FlextLdifModels.DNStatistics.create_minimal(original_dn),
            )
            return original_dn, stats_minimal

        # Track transformations and flags
        transformations: list[str] = []
        transformation_flags: dict[str, bool | str | list[str]] = {}

        # Detect transformation needs BEFORE applying changes
        had_tab_chars = bool(re.search(r"[\t\r\n\x0b\x0c]", original_dn))
        had_spaces_before_equals = bool(re.search(r"\s+=", original_dn))
        had_spaces_before_comma = bool(re.search(r"\s+,", original_dn))
        had_trailing_backslash_space = bool(
            re.search(
                FlextLdifConstants.DnPatterns.DN_TRAILING_BACKSLASH_SPACE,
                original_dn,
            )
        )
        had_spaces_around_comma = bool(
            re.search(FlextLdifConstants.DnPatterns.DN_SPACES_AROUND_COMMA, original_dn)
        )
        had_unnecessary_escapes = bool(
            re.search(FlextLdifConstants.DnPatterns.DN_UNNECESSARY_ESCAPES, original_dn)
        )
        had_multiple_spaces = bool(
            re.search(FlextLdifConstants.DnPatterns.DN_MULTIPLE_SPACES, original_dn)
        )

        # Apply transformations (same order as clean_dn)
        result = original_dn

        # 1. Normalize whitespace control characters (TAB, CR, LF)
        if had_tab_chars:
            result = re.sub(r"[\t\r\n\x0b\x0c]", " ", result)
            transformations.append(FlextLdifConstants.TransformationType.TAB_NORMALIZED)
            transformation_flags["had_tab_chars"] = True

        # 2. Remove spaces before '='
        if had_spaces_before_equals:
            result = re.sub(r"\s+=", "=", result)
            transformations.append(FlextLdifConstants.TransformationType.SPACE_CLEANED)
            transformation_flags["had_leading_spaces"] = True

        # 3. Remove spaces before commas
        if had_spaces_before_comma:
            result = re.sub(r"\s+,", ",", result)
            transformations.append(FlextLdifConstants.TransformationType.SPACE_CLEANED)
            transformation_flags["had_trailing_spaces"] = True

        # 4. Fix trailing backslash+space
        if had_trailing_backslash_space:
            result = re.sub(
                FlextLdifConstants.DnPatterns.DN_TRAILING_BACKSLASH_SPACE,
                FlextLdifConstants.DnPatterns.DN_COMMA,
                result,
            )
            transformations.append(
                FlextLdifConstants.TransformationType.ESCAPE_NORMALIZED
            )
            transformation_flags["had_escape_sequences"] = True

        # 5. Normalize spaces around commas
        if had_spaces_around_comma:
            result = re.sub(
                FlextLdifConstants.DnPatterns.DN_SPACES_AROUND_COMMA,
                FlextLdifConstants.DnPatterns.DN_COMMA,
                result,
            )
            transformations.append(FlextLdifConstants.TransformationType.SPACE_CLEANED)

        # 6. Remove unnecessary escapes
        if had_unnecessary_escapes:
            result = re.sub(
                FlextLdifConstants.DnPatterns.DN_UNNECESSARY_ESCAPES, r"\1", result
            )
            transformations.append(
                FlextLdifConstants.TransformationType.ESCAPE_NORMALIZED
            )

        # 7. Normalize multiple spaces
        if had_multiple_spaces:
            result = re.sub(
                FlextLdifConstants.DnPatterns.DN_MULTIPLE_SPACES, " ", result
            )
            transformations.append(FlextLdifConstants.TransformationType.SPACE_CLEANED)
            transformation_flags["had_extra_spaces"] = True

        # Create statistics
        # Cast to TypedDict for type-safe unpacking
        flags_typed = cast("FlextLdifModelsDomains._DNStatisticsFlags", transformation_flags)  # noqa: SLF001
        stats = FlextLdifModels.DNStatistics.create_with_transformation(
            original_dn=original_dn,
            cleaned_dn=result,
            normalized_dn=result,  # Will be updated by norm() if called
            transformations=transformations,
            **flags_typed,
        )

        # Cast to public type (FlextLdifModels.DNStatistics inherits from FlextLdifModelsDomains.DNStatistics)
        stats_public = cast("FlextLdifModels.DNStatistics", stats)
        return result, stats_public

    @staticmethod
    def esc(value: str) -> str:
        """Escape special characters in DN value per RFC 4514."""
        if not value:
            return value

        escape_chars = {",", "+", '"', "\\", "<", ">", ";", "#"}
        result: list[str] = []

        for i, char in enumerate(value):
            is_special = char in escape_chars
            is_edge_space = (i == 0 or i == len(value) - 1) and char == " "
            if is_special or is_edge_space:
                result.append(f"\\{ord(char):02x}")
            else:
                result.append(char)

        return "".join(result)

    @staticmethod
    def unesc(value: str) -> str:
        """Unescape special characters in DN value per RFC 4514."""
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
    ) -> int | None:
        """Compare two DNs per RFC 4514 (case-insensitive).

        Returns: -1 if dn1 < dn2, 0 if equal, 1 if dn1 > dn2, None on error
        """
        try:
            # Validate inputs first
            if not dn1 or not dn2:
                return None
            norm1 = FlextLdifUtilitiesDN.norm(dn1)
            norm2 = FlextLdifUtilitiesDN.norm(dn2)

            if norm1 is None or norm2 is None:
                return None

            norm1_lower = norm1.lower()
            norm2_lower = norm2.lower()

            if norm1_lower < norm2_lower:
                return -1
            if norm1_lower > norm2_lower:
                return 1
            return 0
        except Exception:
            return None

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
    def parse_rdn(rdn: str) -> list[tuple[str, str]] | None:
        """Parse a single RDN component per RFC 4514.

        Returns None on error.
        """
        if not rdn or not isinstance(rdn, str):
            return None

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
                    return None

            if not in_value or not current_attr:
                return None

            current_val = current_val.strip()
            if not current_val:
                return None
            pairs.append((current_attr, current_val))

            return pairs

        except Exception:
            return None

    @staticmethod
    def extract_rdn(dn: str) -> str | None:
        """Extract leftmost RDN from DN.

        For DN "cn=John,ou=Users,dc=example,dc=com", returns "cn=John".

        Args:
            dn: Distinguished Name string

        Returns:
            Leftmost RDN (attr=value) or None if DN is empty/invalid

        """
        if not dn or "=" not in dn:
            return None

        try:
            components = FlextLdifUtilitiesDN.split(dn)
            return components[0] if components else None
        except Exception:
            return None

    @staticmethod
    def extract_parent_dn(dn: str) -> str | None:
        """Extract parent DN (remove leftmost RDN).

        For DN "cn=John,ou=Users,dc=example,dc=com",
        returns "ou=Users,dc=example,dc=com".

        Args:
            dn: Distinguished Name string

        Returns:
            Parent DN (without leftmost RDN) or None if DN has ≤1 component

        """
        if not dn or "=" not in dn:
            return None

        try:
            components = FlextLdifUtilitiesDN.split(dn)
            if len(components) <= 1:
                return None
            return ",".join(components[1:])
        except Exception:
            return None

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
            contains_pattern("cn=admin,ou=users,dc=example", "ou=users")
            # Returns: True
            contains_pattern("cn=admin,ou=users,dc=example", "OU=USERS")
            # Returns: False (case mismatch)
            contains_pattern("cn=admin,ou=users,dc=example", "OU=USERS", case_sensitive=False)
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
            is_under_base("cn=admin,ou=users,dc=example", "dc=example")
            # Returns: True
            is_under_base("cn=admin,ou=users,dc=example", "ou=users,dc=example")
            # Returns: True
            is_under_base("cn=admin,ou=users,dc=example", "ou=other,dc=example")
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
                "cn=admin,dc=example,dc=com",
                "cn=admin,dc=example,dc=com",
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
            if comparison_result != 0:  # 0 means equal
                return FlextResult[bool].fail(
                    f"{dn_label.capitalize()} mismatch: {context_dn} != {dn_value}",
                )

        return FlextResult[bool].ok(True)


__all__ = [
    "FlextLdifUtilitiesDN",
]
