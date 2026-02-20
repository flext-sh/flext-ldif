"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import re
import string
from collections.abc import Callable, Generator, Sequence
from pathlib import Path
from typing import Literal, overload

from flext_core import r, u

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.settings import FlextLdifModelsSettings
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

    MIN_DN_LENGTH: int = c.Ldif.Format.MIN_DN_LENGTH

    @staticmethod
    def is_lutf1_char(char: str) -> bool:
        """Check if char is valid LUTF1 (lead char) per RFC 4514."""
        if not char or len(char) != 1:
            return False
        code = ord(char)
        rfc_format = c.Ldif.Format
        safe_min = rfc_format.SAFE_CHAR_MIN
        safe_max = rfc_format.SAFE_CHAR_MAX
        if code < safe_min or code > safe_max:
            return False
        return code not in c.Ldif.Format.DN_LUTF1_EXCLUDE

    @staticmethod
    def is_tutf1_char(char: str) -> bool:
        """Check if char is valid TUTF1 (trail char) per RFC 4514."""
        if not char or len(char) != 1:
            return False
        code = ord(char)
        rfc_format = c.Ldif.Format
        safe_min = rfc_format.SAFE_CHAR_MIN
        safe_max = rfc_format.SAFE_CHAR_MAX
        if code < safe_min or code > safe_max:
            return False
        return code not in c.Ldif.Format.DN_TUTF1_EXCLUDE

    @staticmethod
    def is_sutf1_char(char: str) -> bool:
        """Check if char is valid SUTF1 (string char) per RFC 4514."""
        if not char or len(char) != 1:
            return False
        code = ord(char)
        rfc_format = c.Ldif.Format
        safe_min = rfc_format.SAFE_CHAR_MIN
        safe_max = rfc_format.SAFE_CHAR_MAX
        if code < safe_min or code > safe_max:
            return False
        return code not in c.Ldif.Format.DN_SUTF1_EXCLUDE

    @staticmethod
    def is_valid_dn_string(
        value: str,
        *,
        strict: bool = True,
    ) -> tuple[bool, list[str]]:
        """Validate DN attribute value per RFC 4514 string production."""
        errors: list[str] = []

        if not value:
            return True, errors  # Empty string is valid

        if len(value) == 1:
            if not FlextLdifUtilitiesDN.is_lutf1_char(value) and strict:
                errors.append(f"Invalid lead character: {value!r}")
            return len(errors) == 0, errors

        is_escaped_lead = value[0] == "\\" and len(value) > 1
        is_bad_lead = (
            not FlextLdifUtilitiesDN.is_lutf1_char(value[0]) and not is_escaped_lead
        )
        if is_bad_lead and strict:
            errors.append(f"Invalid lead character: {value[0]!r}")

        min_len_for_escape = FlextLdifUtilitiesDN.MIN_DN_LENGTH
        is_escaped_trail = len(value) >= min_len_for_escape and value[-2] == "\\"
        is_bad_trail = (
            not FlextLdifUtilitiesDN.is_tutf1_char(value[-1]) and not is_escaped_trail
        )
        if is_bad_trail and strict:
            errors.append(f"Invalid trail character: {value[-1]!r}")

        for i, char in enumerate(value[1:-1], start=1):
            if FlextLdifUtilitiesDN.is_sutf1_char(char):
                continue
            is_escape_char = char == "\\"
            is_after_escape = i > 0 and value[i - 1] == "\\"
            if not is_escape_char and not is_after_escape and strict:
                errors.append(f"Invalid character at position {i}: {char!r}")

        return len(errors) == 0, errors

    @staticmethod
    def get_dn_value(
        dn: m.Ldif.DN | str | object,
    ) -> str:
        """Extract DN string value from DN model or string (public utility method)."""
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

        def split_components() -> Generator[str]:
            """Generator that yields DN components respecting RFC 4514 escapes."""
            current = ""
            chars = iter(dn_str)

            for char in chars:
                if char == "\\":
                    try:
                        next_char = next(chars)
                        current += char + next_char
                    except StopIteration:
                        current += char  # Trailing backslash
                elif char == ",":
                    if current.strip():
                        yield current.strip()
                        current = ""
                else:
                    current += char

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
            lambda: (
                not (
                    dn_str.endswith(",")
                    and (
                        len(dn_str) < FlextLdifUtilitiesDN.MIN_DN_LENGTH
                        or dn_str[-2] != "\\"
                    )
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
                if i + hex_escape_length >= len(dn_str):
                    return False

                next_two = dn_str[i + 1 : i + 1 + hex_escape_length]
                if len(next_two) == hex_escape_length:
                    if all(c in "0123456789ABCDEFabcdef" for c in next_two):
                        i += 3
                        continue
                    utf8_start = 128
                    if (
                        next_two[0] in ' \t\r\n,+"\\<>;='
                        or ord(next_two[0]) >= utf8_start
                    ):
                        i += 1
                        continue
                    return False
                return False
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
        """Parse DN into RFC 4514 components (attr, value pairs)."""
        if dn is None:
            return r[list[tuple[str, str]]].fail("DN cannot be None")
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not dn_str or "=" not in dn_str:
            error_msg = (
                "DN string is empty"
                if not dn_str
                else f"Invalid DN format: missing '=' separator in '{dn_str}'"
            )
            return r[list[tuple[str, str]]].fail(error_msg)

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
                return r[list[tuple[str, str]]].fail(
                    f"Failed to parse DN components from '{dn_str}'"
                )
            parsed_list = process_result.value
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
            return r[list[tuple[str, str]]].fail(f"DN parsing error: {e}")

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
        """Normalize DN per RFC 4514 (lowercase attrs, preserve values)."""
        if dn is None:
            return r[str].fail("DN cannot be None")
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not dn_str or "=" not in dn_str:
            error_msg = (
                "Failed to normalize DN: DN string is empty"
                if not dn_str
                else f"Failed to normalize DN: Invalid DN format: missing '=' separator in '{dn_str}'"
            )
            return r[str].fail(error_msg)

        try:
            components = FlextLdifUtilitiesDN.split(dn_str)

            def normalize_component(comp: str) -> str | None:
                """Normalize single component."""
                if "=" not in comp:
                    return None
                attr, _, value = comp.partition("=")
                return f"{attr.strip().lower()}={value.strip()}"

            process_result = u.Collection.process(
                components,
                processor=normalize_component,
                predicate=lambda comp: "=" in comp,
                on_error="skip",
            )
            if process_result.is_failure:
                return r[str].fail(
                    f"Failed to normalize DN: no valid components in '{dn_str}'",
                )
            normalized_list = process_result.value
            filtered_str = u.Collection.filter(
                normalized_list,
                predicate=lambda x: isinstance(x, str),
            )
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
            return r[str].fail(f"DN normalization error: {e}")

    @overload
    @staticmethod
    def clean_dn(dn: str) -> str: ...

    @overload
    @staticmethod
    def clean_dn(dn: m.Ldif.DN) -> str: ...

    @staticmethod
    def clean_dn(dn: str | m.Ldif.DN) -> str:
        """Clean DN string to fix spacing and escaping issues."""
        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not dn_str:
            return dn_str

        patterns = [
            (r"[\t\r\n\x0b\x0c]", " "),
            (r"\s+=", "="),
            (
                c.Ldif.DnPatterns.DN_TRAILING_BACKSLASH_SPACE,
                c.Ldif.DnPatterns.DN_COMMA,
            ),
            (r"\s+,", ","),
            (
                c.Ldif.DnPatterns.DN_SPACES_AROUND_COMMA,
                c.Ldif.DnPatterns.DN_COMMA,
            ),
            (c.Ldif.DnPatterns.DN_UNNECESSARY_ESCAPES, r"\1"),
            (c.Ldif.DnPatterns.DN_MULTIPLE_SPACES, " "),
        ]

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

        result, transformations, flags = FlextLdifUtilitiesDN._apply_dn_transformations(
            original_dn,
        )

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

        stats_flags: FlextLdifModelsDomains.DNStatisticsFlags = {
            "had_tab_chars": flags.get("had_tab_chars", False) is True,
            "had_trailing_spaces": flags.get("had_trailing_spaces", False) is True,
            "had_leading_spaces": flags.get("had_leading_spaces", False) is True,
            "had_extra_spaces": flags.get("had_extra_spaces", False) is True,
            "was_base64_encoded": flags.get("was_base64_encoded", False) is True,
            "had_utf8_chars": flags.get("had_utf8_chars", False) is True,
            "had_escape_sequences": flags.get("had_escape_sequences", False) is True,
            "validation_status": validation_status,
            "validation_warnings": validation_warnings,
            "validation_errors": validation_errors,
        }
        stats_domain = FlextLdifModelsDomains.DNStatistics.create_with_transformation(
            original_dn=original_dn,
            cleaned_dn=result,
            normalized_dn=result,
            transformations=transformations,
            **stats_flags,
        )
        return result, stats_domain

    @staticmethod
    def _apply_dn_transformations(
        original_dn: str,
    ) -> tuple[str, list[str], dict[str, bool | str | list[str]]]:
        """Apply DN transformations and collect flags."""
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

        transform_rules: list[tuple[str, str, str, str, str]] = [
            (
                r"[\t\r\n\x0b\x0c]",
                r"[\t\r\n\x0b\x0c]",
                " ",
                c.Ldif.TransformationType.TAB_NORMALIZED,
                "had_tab_chars",
            ),
            (
                r"\s+=",
                r"\s+=",
                "=",
                c.Ldif.TransformationType.SPACE_CLEANED,
                "had_leading_spaces",
            ),
            (
                r"\s+,",
                r"\s+,",
                ",",
                c.Ldif.TransformationType.SPACE_CLEANED,
                "had_trailing_spaces",
            ),
            (
                c.Ldif.DnPatterns.DN_TRAILING_BACKSLASH_SPACE,
                c.Ldif.DnPatterns.DN_TRAILING_BACKSLASH_SPACE,
                c.Ldif.DnPatterns.DN_COMMA,
                c.Ldif.TransformationType.ESCAPE_NORMALIZED,
                "had_escape_sequences",
            ),
            (
                c.Ldif.DnPatterns.DN_SPACES_AROUND_COMMA,
                c.Ldif.DnPatterns.DN_SPACES_AROUND_COMMA,
                c.Ldif.DnPatterns.DN_COMMA,
                c.Ldif.TransformationType.SPACE_CLEANED,
                "",
            ),
            (
                c.Ldif.DnPatterns.DN_UNNECESSARY_ESCAPES,
                c.Ldif.DnPatterns.DN_UNNECESSARY_ESCAPES,
                r"\1",
                c.Ldif.TransformationType.ESCAPE_NORMALIZED,
                "",
            ),
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
            return r[tuple[str, str]].fail(
                f"Comparison failed (RFC 4514): Failed to normalize first DN: {norm1_result.error}",
            )

        norm2_result = FlextLdifUtilitiesDN.norm(dn2)
        if not norm2_result.is_success:
            return r[tuple[str, str]].fail(
                f"Comparison failed (RFC 4514): Failed to normalize second DN: {norm2_result.error}",
            )

        return r[tuple[str, str]].ok((
            norm1_result.value.lower(),
            norm2_result.value.lower(),
        ))

    @staticmethod
    def compare_dns(
        dn1: str | None,
        dn2: str | None,
    ) -> r[int]:
        """Compare two DNs per RFC 4514 (case-insensitive)."""
        try:
            if not dn1 or not dn2:
                return r[int].fail("Both DNs must be provided for comparison")

            norm_result = FlextLdifUtilitiesDN._normalize_dns_for_comparison(dn1, dn2)
            if not norm_result.is_success:
                return r[int].fail(norm_result.error or "Normalization failed")

            norm1_lower, norm2_lower = norm_result.value
            comparison = (norm1_lower > norm2_lower) - (norm1_lower < norm2_lower)
            return r[int].ok(comparison)
        except Exception as e:
            return r[int].fail(f"DN comparison error: {e}")

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
        config: FlextLdifModelsSettings.RdnProcessingConfig,
    ) -> tuple[str, str, bool, int, bool]:
        """Process single character in RDN parsing."""
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
        config: FlextLdifModelsSettings.RdnProcessingConfig,
    ) -> tuple[str, str, bool, int]:
        """Advance position during RDN parsing and return new state."""
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
        """Parse a single RDN component per RFC 4514."""
        if not rdn or not isinstance(rdn, str):
            return r[list[tuple[str, str]]].fail(
                "RDN must be a non-empty string",
            )

        try:
            pairs: list[tuple[str, str]] = []
            current_attr = ""
            current_val = ""
            in_value = False
            rdn_len: int = len(rdn)
            position: int = 0

            rdn_config = FlextLdifModelsSettings.RdnProcessingConfig(
                current_attr=current_attr,
                current_val=current_val,
                in_value=in_value,
                pairs=pairs,
            )

            while position < rdn_len:
                idx: int = position
                char_at_pos: str = rdn[idx]
                current_attr, current_val, in_value, position = (
                    FlextLdifUtilitiesDN._advance_rdn_position(
                        char_at_pos,
                        rdn,
                        idx,
                        rdn_config,
                    )
                )
                rdn_config.current_attr = current_attr
                rdn_config.current_val = current_val
                rdn_config.in_value = in_value
                pairs = rdn_config.pairs

                if char_at_pos == "=" and not in_value and not current_attr:
                    return r[list[tuple[str, str]]].fail(
                        f"Invalid RDN format: unexpected '=' at position {idx}",
                    )

            if not in_value or not current_attr:
                return r[list[tuple[str, str]]].fail(
                    f"Invalid RDN format: missing attribute or value in '{rdn}'",
                )

            current_val = current_val.strip()
            if not current_val:
                return r[list[tuple[str, str]]].fail(
                    f"Invalid RDN format: empty value in '{rdn}'",
                )
            pairs.append((current_attr, current_val))

            return r[list[tuple[str, str]]].ok(pairs)

        except Exception as e:
            return r[list[tuple[str, str]]].fail(f"RDN parsing error: {e}")

    @staticmethod
    def extract_rdn(dn: str) -> r[str]:
        """Extract leftmost RDN from DN."""
        if not dn or "=" not in dn:
            return r[str].fail(
                f"Invalid DN format: missing '=' separator in '{dn}'",
            )

        try:
            components = FlextLdifUtilitiesDN.split(dn)
            if not components:
                return r[str].fail(
                    f"Failed to extract RDN: no components found in '{dn}'",
                )
            return r[str].ok(components[0])
        except Exception as e:
            return r[str].fail(f"RDN extraction error: {e}")

    @staticmethod
    def extract_parent_dn(dn: str) -> r[str]:
        """Extract parent DN (remove leftmost RDN)."""
        if not dn or "=" not in dn:
            return r[str].fail(
                f"Invalid DN format: missing '=' separator in '{dn}'",
            )

        try:
            components = FlextLdifUtilitiesDN.split(dn)
            if len(components) <= 1:
                return r[str].fail(
                    f"Cannot extract parent DN: DN has only one component '{dn}'",
                )
            return r[str].ok(",".join(components[1:]))
        except Exception as e:
            return r[str].fail(f"Parent DN extraction error: {e}")

    @staticmethod
    def is_config_dn(dn: str) -> bool:
        """Check if DN is in cn=config tree (OpenLDAP dynamic config)."""
        if not dn:
            return False
        return "cn=config" in dn.lower()

    @staticmethod
    def is_under_base(
        dn: str | None,
        base_dn: str | None,
    ) -> bool:
        """Check if DN is under base DN (hierarchical check)."""
        if not dn or not base_dn:
            return False

        dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
        base_dn_str = FlextLdifUtilitiesDN.get_dn_value(base_dn)

        if not dn_str or not base_dn_str:
            return False

        dn_lower = dn_str.lower().strip()
        base_dn_lower = base_dn_str.lower().strip()

        return dn_lower == base_dn_lower or dn_lower.endswith(f",{base_dn_lower}")

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
        """Transform a single DN attribute value by replacing base DN."""
        dn_str = FlextLdifUtilitiesDN.get_dn_value(value)
        if not dn_str or not source_dn or not target_dn:
            return dn_str

        norm_result = FlextLdifUtilitiesDN.norm(dn_str)
        normalized_dn = norm_result.map_or(dn_str)

        source_escaped = re.escape(source_dn)

        result = re.sub(
            f",{source_escaped}$",
            f",{target_dn}",
            normalized_dn,
            flags=re.IGNORECASE,
        )

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
        """Replace base DN in all entries and DN-valued attributes."""
        if not entries or not source_dn or not target_dn:
            return entries

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
        return [item for item in batch_data.results if isinstance(item, m.Ldif.Entry)]

    @staticmethod
    def _transform_attrs_with_dn(
        attrs: dict[str, list[str]],
        dn_attributes: set[str],
        source_dn: str,
        target_dn: str,
    ) -> dict[str, list[str]]:
        """Transform DN-valued attributes using u.map()."""
        return {
            k: [
                FlextLdifUtilitiesDN.transform_dn_attribute(
                    val,
                    source_dn,
                    target_dn,
                )
                for val in v
            ]
            if k.lower() in dn_attributes
            else v
            for k, v in attrs.items()
        }

    @staticmethod
    def _get_changed_attr_names(
        original: dict[str, list[str]],
        transformed: dict[str, list[str]],
        dn_attributes: set[str],
    ) -> list[str]:
        """Get list of attribute names that changed using dict comprehension."""
        return [
            k
            for k, v in transformed.items()
            if k.lower() in dn_attributes and v != original.get(k, [])
        ]

    @staticmethod
    def _update_metadata_for_transformation(
        metadata: m.Ldif.QuirkMetadata,
        config: FlextLdifModelsSettings.MetadataTransformationConfig,
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
        """Transform DN and DN-valued attributes with metadata tracking."""
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
        dn_value = FlextLdifUtilitiesDN.get_dn_value(entry.dn)
        if not dn_value:
            return entry
        transformed_dn = FlextLdifUtilitiesDN.transform_dn_attribute(
            dn_value,
            source_dn,
            target_dn,
        )
        if hasattr(entry.attributes, "attributes"):
            attrs_dict = entry.attributes.attributes
        else:
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

        if entry.metadata:
            metadata_dict = entry.metadata.model_dump()
            metadata = m.Ldif.QuirkMetadata.model_validate(metadata_dict)
        else:
            metadata = m.Ldif.QuirkMetadata.create_for()

        transform_config = FlextLdifModelsSettings.MetadataTransformationConfig(
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
    def transform_ldif_files_in_directory(
        ldif_dir: str | Path,
        source_basedn: str,
        target_basedn: str,
    ) -> r[dict[str, int]]:
        """Compatibility helper to transform BaseDN in all LDIF files in a directory."""
        if not source_basedn or not target_basedn:
            return r[dict[str, int]].fail(
                "source_basedn and target_basedn are required"
            )

        directory = Path(ldif_dir)
        if not directory.exists() or not directory.is_dir():
            return r[dict[str, int]].fail(f"Invalid LDIF directory: {directory}")

        transformed_count = 0
        scanned_count = 0
        source_pattern = re.compile(re.escape(source_basedn), re.IGNORECASE)

        for ldif_file in sorted(directory.glob("*.ldif")):
            scanned_count += 1
            content = ldif_file.read_text(encoding="utf-8")
            transformed_content = source_pattern.sub(target_basedn, content)
            if transformed_content != content:
                ldif_file.write_text(transformed_content, encoding="utf-8")
                transformed_count += 1

        return r[dict[str, int]].ok({
            "total_count": transformed_count,
            "transformed_count": transformed_count,
            "scanned_count": scanned_count,
        })

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

        if fallback == "lower":
            return dn.lower()
        if fallback == "upper":
            return dn.upper()
        return dn

    @staticmethod
    def norm_batch(
        dns: Sequence[str],
        *,
        fallback: Literal["lower", "upper", "original", "skip"] = "lower",
        fail_fast: bool = False,
    ) -> r[list[str]]:
        """Normalize multiple DNs in one call."""

        def normalize_dn(dn: str) -> r[str]:
            """Normalize single DN with fallback."""
            result = FlextLdifUtilitiesDN.norm(dn)
            if result.is_success:
                return result
            if fallback == "skip":
                return r[str].fail("Skipped")
            if fallback == "lower":
                return r[str].ok(dn.lower())
            if fallback == "upper":
                return r[str].ok(dn.upper())
            return r[str].ok(dn)

        normalized_results: list[str] = []

        if fail_fast:
            for dn in dns:
                result = normalize_dn(dn)
                if result.is_failure:
                    return r[list[str]].fail(
                        result.error or f"Failed to normalize DN: {dn}"
                    )
                normalized_results.append(result.value)
            return r[list[str]].ok(normalized_results)

        for dn in dns:
            result = normalize_dn(dn)
            if result.is_success:
                normalized_results.append(result.value)

        return r[list[str]].ok(normalized_results)

    @staticmethod
    def validate_batch(
        dns: Sequence[str],
        *,
        collect_errors: bool = True,
    ) -> r[list[tuple[str, bool, list[str]]]]:
        """Validate multiple DNs, returning validation status for each."""

        def validate_dn(dn: str) -> tuple[str, bool, list[str]]:
            """Validate single DN."""
            is_valid, dn_errors = FlextLdifUtilitiesDN.is_valid_dn_string(dn)
            return (dn, is_valid, dn_errors)

        batch_result = u.Collection.batch(list(dns), validate_dn, on_error="skip")
        if batch_result.is_failure:
            return r[list[tuple[str, bool, list[str]]]].fail(
                batch_result.error or "Validation failed"
            )
        batch_data = batch_result.value
        tuple_length = 3
        results_raw = [
            item
            for item in batch_data.results
            if isinstance(item, tuple) and len(item) == tuple_length
        ]
        results: list[tuple[str, bool, list[str]]] = []
        for item in results_raw:
            dn_str = str(item[0])
            is_valid = bool(item[1])
            errors_list: list[str] = (
                [str(e) for e in item[2]] if isinstance(item[2], (list, tuple)) else []
            )
            results.append((dn_str, is_valid, errors_list))
        if not collect_errors:
            invalid_results = [item for item in results if not item[1]]
            if invalid_results:
                results = results[: results.index(invalid_results[0]) + 1]
        return r[list[tuple[str, bool, list[str]]]].ok(results)

    @staticmethod
    def replace_base_batch(
        dns: Sequence[str],
        old_base: str,
        new_base: str,
        *,
        fail_fast: bool = False,
    ) -> r[list[str]]:
        """Replace base DN in multiple DNs."""
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
        batch_result = u.Collection.batch(
            list(dns),
            replace_dn,
            on_error=on_error_mode,
        )
        if batch_result.is_failure:
            return r[list[str]].fail(batch_result.error or "Base replacement failed")
        batch_data = batch_result.value
        results = [item for item in batch_data.results if isinstance(item, str)]
        return r[list[str]].ok(results)

    @staticmethod
    def process_complete(
        dn: str,
        *,
        clean: bool = True,
        validate: bool = True,
        normalize: bool = True,
        parse: bool = False,
    ) -> r[str | list[tuple[str, str]]]:
        """Complete DN processing pipeline in one call."""
        current_dn = dn

        if clean:
            try:
                current_dn = FlextLdifUtilitiesDN.clean_dn(current_dn)
            except Exception as exc:
                return r[str | list[tuple[str, str]]].fail(f"Clean failed: {exc}")

        if validate:
            is_valid, errors = FlextLdifUtilitiesDN.is_valid_dn_string(current_dn)
            if not is_valid:
                return r[str | list[tuple[str, str]]].fail(
                    f"Validation failed: {', '.join(errors)}"
                )

        if normalize:
            norm_result = FlextLdifUtilitiesDN.norm(current_dn)
            if norm_result.is_failure:
                return r[str | list[tuple[str, str]]].fail(
                    f"Normalization failed: {norm_result.error}"
                )
            current_dn = norm_result.value

        if parse:
            parse_result = FlextLdifUtilitiesDN.parse(current_dn)
            if parse_result.is_failure:
                return r[str | list[tuple[str, str]]].fail(
                    f"Parse failed: {parse_result.error}"
                )
            return r[str | list[tuple[str, str]]].ok(parse_result.value)

        return r[str | list[tuple[str, str]]].ok(current_dn)


__all__ = [
    "FlextLdifUtilitiesDN",
]
