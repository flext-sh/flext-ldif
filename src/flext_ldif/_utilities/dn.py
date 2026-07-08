"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import string
from pathlib import Path
from typing import TYPE_CHECKING, overload

from flext_cli import u
from flext_ldif import c, p, r, t
from flext_ldif.models import FlextLdifModels as m

if TYPE_CHECKING:
    from collections.abc import (
        Callable,
        Generator,
        MutableMapping,
    )


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
    ESC    = %x5C  ; '\\'

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

    MIN_DN_LENGTH: int = c.Ldif.MIN_DN_LENGTH

    @staticmethod
    def _advance_rdn_position(
        char: str,
        rdn: str,
        position: int,
        settings: m.Ldif.RdnProcessingConfig,
    ) -> tuple[str, str, bool, int]:
        """Advance position during RDN parsing and return new state."""
        result = FlextLdifUtilitiesDN._process_rdn_char(char, rdn, position, settings)
        attr, val, in_val, next_pos, _ = result
        return (attr, val, in_val, next_pos)

    @staticmethod
    def _apply_dn_transformations(
        original_dn: str,
    ) -> tuple[
        str,
        t.MutableSequenceOf[str],
        MutableMapping[str, bool | str | t.MutableSequenceOf[str]],
    ]:
        """Apply DN transformations and collect flags."""
        transformations: t.MutableSequenceOf[str] = []
        empty_warnings: t.MutableSequenceOf[str] = []
        empty_errors: t.MutableSequenceOf[str] = []
        flags: MutableMapping[str, bool | str | t.MutableSequenceOf[str]] = {
            "had_tab_chars": False,
            "had_trailing_spaces": False,
            "had_leading_spaces": False,
            "had_extra_spaces": False,
            "was_base64_encoded": False,
            "had_utf8_chars": False,
            "had_escape_sequences": False,
            "validation_status": "",
            "validation_warnings": empty_warnings,
            "validation_errors": empty_errors,
        }
        result = original_dn
        transform_rules: t.MutableSequenceOf[tuple[str, str, str, str, str]] = [
            (
                "[\\t\\r\\n\\x0b\\x0c]",
                "[\\t\\r\\n\\x0b\\x0c]",
                " ",
                c.Ldif.TransformationType.TAB_NORMALIZED,
                "had_tab_chars",
            ),
            (
                "\\s+=",
                "\\s+=",
                "=",
                c.Ldif.TransformationType.SPACE_CLEANED,
                "had_leading_spaces",
            ),
            (
                "\\s+,",
                "\\s+,",
                ",",
                c.Ldif.TransformationType.SPACE_CLEANED,
                "had_trailing_spaces",
            ),
            (
                c.Ldif.DN_TRAILING_BACKSLASH_SPACE,
                c.Ldif.DN_TRAILING_BACKSLASH_SPACE,
                c.Ldif.DN_COMMA,
                c.Ldif.TransformationType.ESCAPE_NORMALIZED,
                "had_escape_sequences",
            ),
            (
                c.Ldif.DN_SPACES_AROUND_COMMA,
                c.Ldif.DN_SPACES_AROUND_COMMA,
                c.Ldif.DN_COMMA,
                c.Ldif.TransformationType.SPACE_CLEANED,
                "",
            ),
            (
                c.Ldif.DN_UNNECESSARY_ESCAPES,
                c.Ldif.DN_UNNECESSARY_ESCAPES,
                "\\1",
                c.Ldif.TransformationType.ESCAPE_NORMALIZED,
                "",
            ),
            (
                c.Ldif.DN_MULTIPLE_SPACES,
                c.Ldif.DN_MULTIPLE_SPACES,
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
            if c.Ldif.compile_pattern(detect_pattern).search(result):
                result = c.Ldif.sub_pattern(replace_pattern, replacement, result)
                transformations.append(transform_type)
                if flag_name:
                    flags[flag_name] = True
        return (result, transformations, flags)

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
    def _normalize_dns_for_comparison(dn1: str, dn2: str) -> p.Result[t.StrPair]:
        """Normalize both DNs for comparison."""
        norm1_result = FlextLdifUtilitiesDN.norm(dn1)
        if not norm1_result.success:
            return r[t.StrPair].fail(
                f"Comparison failed (RFC 4514): Failed to normalize first DN: {norm1_result.error}",
            )
        norm2_result = FlextLdifUtilitiesDN.norm(dn2)
        if not norm2_result.success:
            return r[t.StrPair].fail(
                f"Comparison failed (RFC 4514): Failed to normalize second DN: {norm2_result.error}",
            )
        return r[t.StrPair].ok((
            norm1_result.value.lower(),
            norm2_result.value.lower(),
        ))

    @staticmethod
    def _process_rdn_char(
        char: str,
        rdn: str,
        i: int,
        settings: m.Ldif.RdnProcessingConfig,
    ) -> tuple[str, str, bool, int, bool]:
        """Process single character in RDN parsing."""
        current_attr = settings.current_attr
        current_val = settings.current_val
        in_value = settings.in_value
        if char == "\\" and i + 1 < len(rdn):
            current_val, next_i = FlextLdifUtilitiesDN._process_rdn_escape(
                rdn,
                i,
                settings.current_val,
            )
            settings.current_val = current_val
            return (current_attr, current_val, in_value, next_i, True)
        if char == "=" and (not in_value):
            current_attr = current_attr.strip().lower()
            settings.current_attr = current_attr
            settings.in_value = True
            return (current_attr, current_val, True, i + 1, True)
        if char == "+" and in_value:
            current_val = current_val.strip()
            if current_attr:
                settings.pairs.append((current_attr, current_val))
            settings.current_attr = ""
            settings.current_val = ""
            settings.in_value = False
            return ("", "", False, i + 1, True)
        if in_value:
            current_val += char
            settings.current_val = current_val
        else:
            current_attr += char
            settings.current_attr = current_attr
        return (current_attr, current_val, in_value, i + 1, False)

    @staticmethod
    def _process_rdn_escape(rdn: str, i: int, current_val: str) -> tuple[str, int]:
        """Process escape sequence in RDN parsing (extracted to reduce complexity)."""
        if i + 1 < len(rdn):
            next_char = rdn[i + 1]
            if i + 2 < len(rdn) and all(
                c in string.hexdigits for c in rdn[i + 1 : i + 3]
            ):
                return (current_val + rdn[i : i + 3], i + 3)
            return (current_val + next_char, i + 2)
        return (current_val, i + 1)

    @staticmethod
    def _validate_basic_format(dn_str: str) -> bool:
        """Validate basic DN format requirements."""
        return bool(dn_str and "=" in dn_str)

    @staticmethod
    def _validate_components(components: t.MutableSequenceOf[str]) -> bool:
        """Validate each DN component has attr=value format (helper method)."""

        def is_valid_component(comp: str) -> bool:
            """Check if component is valid."""
            if "=" not in comp:
                return False
            attr, _, value = comp.partition("=")
            return bool(attr.strip() and value.strip())

        filtered = u.filter(components, is_valid_component)
        return len(filtered) == len(components)

    @staticmethod
    def _validate_dn_structure(dn_str: str) -> bool:
        """Validate DN structure (commas, escape sequences, components)."""
        checks: t.MutableSequenceOf[Callable[[], bool]] = [
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
    def _validate_escape_sequences(dn_str: str) -> bool:
        r"""Validate escape sequences in DN string.

        RFC 4514 Section 2.4: Implementations MUST allow UTF-8 characters
        to appear in values (both in their UTF-8 form and in their escaped form).
        This means UTF-8 bytes (> 127) are VALID and do NOT need escaping.

        Checks for:
        - Valid hex escapes: \\XX where X is hex digit (0-9, A-F, a-f)
        - No incomplete hex escapes: \\X or \\
        - No invalid hex escapes: \\ZZ
        - UTF-8 characters (> 127) are ALLOWED without escaping

        Returns:
            True if all escape sequences are valid

        """
        hex_escape_length = 2
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
            ("[\\t\\r\\n\\x0b\\x0c]", " "),
            ("\\s+=", "="),
            (c.Ldif.DN_TRAILING_BACKSLASH_SPACE, c.Ldif.DN_COMMA),
            ("\\s+,", ","),
            (c.Ldif.DN_SPACES_AROUND_COMMA, c.Ldif.DN_COMMA),
            (c.Ldif.DN_UNNECESSARY_ESCAPES, "\\1"),
            (c.Ldif.DN_MULTIPLE_SPACES, " "),
        ]
        try:
            result = dn_str
            for pattern, replacement in patterns:
                result = c.Ldif.sub_pattern(pattern, replacement, result)
            return result
        except c.Ldif.EXC_LDIF_PARSE:
            return dn_str

    @staticmethod
    def clean_dn_with_statistics(
        dn: str,
    ) -> tuple[str, m.Ldif.DNStatistics]:
        r"""Clean DN and track all transformations with statistics.

        Returns both cleaned DN and complete transformation history
        for diagnostic and audit purposes.

        Args:
            dn: DN string or DN t.JsonValue

        Returns:
            Tuple of (cleaned_dn, DNStatistics with transformation history)

        Example:
            cleaned_dn, stats = FlextLdifUtilitiesDN.clean_dn_with_statistics(
                "cn=test  ,\\tdc=example,dc=com"
            )

        """
        original_dn = FlextLdifUtilitiesDN.get_dn_value(dn)
        if not original_dn:
            stats_domain = m.Ldif.DNStatistics.create_minimal(
                original_dn,
            )
            stats = m.Ldif.DNStatistics.model_validate(
                stats_domain.model_dump(),
            )
            return (original_dn, stats)
        result, transformations, flags = FlextLdifUtilitiesDN._apply_dn_transformations(
            original_dn,
        )
        validation_status_raw = flags.get("validation_status", "")
        validation_status: str = (
            validation_status_raw if isinstance(validation_status_raw, str) else ""
        )
        validation_warnings_raw = flags.get("validation_warnings", [])
        validation_warnings: t.MutableSequenceOf[str] = (
            list(validation_warnings_raw)
            if isinstance(validation_warnings_raw, list)
            else []
        )
        validation_errors_raw = flags.get("validation_errors", [])
        validation_errors: t.MutableSequenceOf[str] = (
            list(validation_errors_raw)
            if isinstance(validation_errors_raw, list)
            else []
        )
        stats_domain = m.Ldif.DNStatistics(
            original_dn=original_dn,
            cleaned_dn=result,
            normalized_dn=result,
            transformations=transformations,
            had_tab_chars=bool(flags.get("had_tab_chars", False)),
            had_trailing_spaces=bool(flags.get("had_trailing_spaces", False)),
            had_leading_spaces=bool(flags.get("had_leading_spaces", False)),
            had_extra_spaces=bool(flags.get("had_extra_spaces", False)),
            was_base64_encoded=bool(flags.get("was_base64_encoded", False)),
            had_utf8_chars=bool(flags.get("had_utf8_chars", False)),
            had_escape_sequences=bool(flags.get("had_escape_sequences", False)),
            validation_status=validation_status,
            validation_warnings=validation_warnings,
            validation_errors=validation_errors,
        )
        return (result, stats_domain)

    @staticmethod
    def compare_dns(dn1: str | None, dn2: str | None) -> p.Result[int]:
        """Compare two DNs per RFC 4514 (case-insensitive)."""
        try:
            return FlextLdifUtilitiesDN._compare_dns_core(dn1, dn2)
        except c.Ldif.EXC_LDIF_PARSE as e:
            return r[int].fail(f"DN comparison error: {e}")

    @staticmethod
    def _compare_dns_core(dn1: str | None, dn2: str | None) -> p.Result[int]:
        """Compare normalized DN pair."""
        if not dn1 or not dn2:
            return r[int].fail("Both DNs must be provided for comparison")
        norm_result = FlextLdifUtilitiesDN._normalize_dns_for_comparison(dn1, dn2)
        if not norm_result.success:
            return r[int].fail(norm_result.error or "Normalization failed")
        normalized_pair = norm_result.value
        if len(normalized_pair) != c.Ldif.TUPLE_LENGTH_PAIR:
            return r[int].fail("Normalization returned unexpected DN pair")
        norm1_lower = normalized_pair[0]
        norm2_lower = normalized_pair[1]
        comparison = (norm1_lower > norm2_lower) - (norm1_lower < norm2_lower)
        return r[int].ok(comparison)

    @staticmethod
    def esc(value: str) -> str:
        r"""Escape special characters in DN value per RFC 4514 Section 2.4.

        RFC 4514 Escaping Requirements:
        ===============================
        - Special characters MUST be escaped: " + , ; < > \\
        - A leading SHARP ('#') MUST be escaped
        - A leading/trailing SPACE MUST be escaped
        - Characters can be escaped as \\\\XX where XX is hex

        Args:
            value: The DN attribute value to escape.

        Returns:
            The escaped value string.

        """
        if not value:
            return value

        def escape_char(item: tuple[int, str]) -> str:
            """Escape single character if needed."""
            i, char = item
            is_special = char in c.Ldif.DN_ESCAPE_CHARS
            is_leading_space = i == 0 and char == " "
            is_trailing_space = i == len(value) - 1 and char == " "
            is_leading_sharp = i == 0 and char == "#"
            if is_special or is_leading_space or is_trailing_space or is_leading_sharp:
                return f"\\{ord(char):02x}"
            return char

        enumerated = list(enumerate(value))
        mapped_result = u.map(enumerated, mapper=escape_char)
        return "".join(mapped_result)

    @staticmethod
    def get_dn_value(dn: m.Ldif.DN | str) -> str:
        """Extract DN string value from DN model or string (public utility method)."""
        if isinstance(dn, str):
            return dn
        return dn.value

    @staticmethod
    def is_lutf1_char(char: str) -> bool:
        """Check if char is valid LUTF1 (lead char) per RFC 4514."""
        if not char or len(char) != 1:
            return False
        code = ord(char)
        rfc_format = c.Ldif
        safe_min = rfc_format.SAFE_CHAR_MIN
        safe_max = rfc_format.SAFE_CHAR_MAX
        if code < safe_min or code > safe_max:
            return False
        return code not in c.Ldif.DN_LUTF1_EXCLUDE

    @staticmethod
    def is_sutf1_char(char: str) -> bool:
        """Check if char is valid SUTF1 (string char) per RFC 4514."""
        if not char or len(char) != 1:
            return False
        code = ord(char)
        rfc_format = c.Ldif
        safe_min = rfc_format.SAFE_CHAR_MIN
        safe_max = rfc_format.SAFE_CHAR_MAX
        if code < safe_min or code > safe_max:
            return False
        return code not in c.Ldif.DN_SUTF1_EXCLUDE

    @staticmethod
    def is_tutf1_char(char: str) -> bool:
        """Check if char is valid TUTF1 (trail char) per RFC 4514."""
        if not char or len(char) != 1:
            return False
        code = ord(char)
        rfc_format = c.Ldif
        safe_min = rfc_format.SAFE_CHAR_MIN
        safe_max = rfc_format.SAFE_CHAR_MAX
        if code < safe_min or code > safe_max:
            return False
        return code not in c.Ldif.DN_TUTF1_EXCLUDE

    @staticmethod
    def is_under_base(dn: str | None, base_dn: str | None) -> bool:
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

    @staticmethod
    def is_valid_dn_string(
        value: str,
        *,
        strict: bool = True,
    ) -> tuple[bool, t.MutableSequenceOf[str]]:
        """Validate DN attribute value per RFC 4514 string production."""
        errors: t.MutableSequenceOf[str] = []
        if not value:
            return (True, errors)
        if len(value) == 1:
            if not FlextLdifUtilitiesDN.is_lutf1_char(value) and strict:
                errors.append(f"Invalid lead character: {value!r}")
            return (not errors, errors)
        is_escaped_lead = value[0] == "\\" and len(value) > 1
        is_bad_lead = not FlextLdifUtilitiesDN.is_lutf1_char(value[0]) and (
            not is_escaped_lead
        )
        if is_bad_lead and strict:
            errors.append(f"Invalid lead character: {value[0]!r}")
        min_len_for_escape = FlextLdifUtilitiesDN.MIN_DN_LENGTH
        is_escaped_trail = len(value) >= min_len_for_escape and value[-2] == "\\"
        is_bad_trail = not FlextLdifUtilitiesDN.is_tutf1_char(value[-1]) and (
            not is_escaped_trail
        )
        if is_bad_trail and strict:
            errors.append(f"Invalid trail character: {value[-1]!r}")
        for i, char in enumerate(value[1:-1], start=1):
            if FlextLdifUtilitiesDN.is_sutf1_char(char):
                continue
            is_escape_char = char == "\\"
            is_after_escape = i > 0 and value[i - 1] == "\\"
            if not is_escape_char and (not is_after_escape) and strict:
                errors.append(f"Invalid character at position {i}: {char!r}")
        return (not errors, errors)

    @overload
    @staticmethod
    def norm(dn: str) -> p.Result[str]: ...

    @overload
    @staticmethod
    def norm(dn: m.Ldif.DN) -> p.Result[str]: ...

    @staticmethod
    def norm(dn: str | m.Ldif.DN | None) -> p.Result[str]:
        """Normalize DN per RFC 4514 (lowercase attrs, preserve values)."""
        result = r[str].fail("DN cannot be None")
        if dn is not None:
            dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
            if not dn_str or "=" not in dn_str:
                error_msg = (
                    "Failed to normalize DN: DN string is empty"
                    if not dn_str
                    else f"Failed to normalize DN: Invalid DN format: missing '=' separator in '{dn_str}'"
                )
                result = r[str].fail(error_msg)
            else:
                try:
                    normalized: t.MutableSequenceOf[str] = [
                        f"{attr.strip().lower()}={value.strip()}"
                        for component in FlextLdifUtilitiesDN.split(dn_str)
                        if "=" in component
                        for attr, _, value in [component.partition("=")]
                    ]
                    result = (
                        r[str].ok(",".join(normalized))
                        if normalized
                        else r[str].fail(
                            f"Failed to normalize DN: no valid components in '{dn_str}'",
                        )
                    )
                except c.Ldif.EXC_LDIF_PARSE as e:
                    result = r[str].fail(f"DN normalization error: {e}")
        return result

    @staticmethod
    def norm_or_fallback(
        dn: str | None,
        *,
        fallback: c.Ldif.NormalizeFallback = c.Ldif.NormalizeFallback.LOWER,
    ) -> str:
        r"""Normalize DN or return fallback if normalization fails.

        Replaces the common 3-line pattern:
            norm_result = FlextLdifUtilitiesDN.norm(dn)
            normalized = norm_result.value if norm_result.success else dn.lower()

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
            ...     "invalid\\\\\\\\dn", fallback="original"
            ... )
            'invalid\\\\\\\\dn'

        """
        if dn is None:
            return ""
        result = FlextLdifUtilitiesDN.norm(dn)
        if result.success:
            normalized_dn: str = result.value
            return normalized_dn
        if fallback == c.Ldif.NormalizeFallback.LOWER:
            return dn.lower()
        if fallback == c.Ldif.NormalizeFallback.UPPER:
            return dn.upper()
        return dn

    @overload
    @staticmethod
    def parse_dn(dn: str) -> p.Result[t.MutableStrPairSequence]: ...

    @overload
    @staticmethod
    def parse_dn(
        dn: m.Ldif.DN,
    ) -> p.Result[t.MutableStrPairSequence]: ...

    @staticmethod
    def parse_dn(
        dn: str | m.Ldif.DN | None,
    ) -> p.Result[t.MutableStrPairSequence]:
        """Parse DN into RFC 4514 components (attr, value pairs)."""
        result = r[t.MutableStrPairSequence].fail("DN cannot be None")
        if dn is not None:
            dn_str = FlextLdifUtilitiesDN.get_dn_value(dn)
            if not dn_str or "=" not in dn_str:
                error_msg = (
                    "DN string is empty"
                    if not dn_str
                    else f"Invalid DN format: missing '=' separator in '{dn_str}'"
                )
                result = r[t.MutableStrPairSequence].fail(error_msg)
            else:
                try:
                    result = FlextLdifUtilitiesDN._parse_dn_components(dn_str)
                except c.Ldif.EXC_LDIF_PARSE as e:
                    result = r[t.MutableStrPairSequence].fail(
                        f"DN parsing error: {e}",
                    )
        return result

    @staticmethod
    def parse_rdn(rdn: str) -> p.Result[t.MutableStrPairSequence]:
        """Parse a single RDN component per RFC 4514."""
        result = r[t.MutableStrPairSequence].fail(
            "RDN must be a non-empty string",
        )
        if rdn:
            try:
                result = FlextLdifUtilitiesDN._parse_rdn_core(rdn)
            except c.Ldif.EXC_LDIF_PARSE as e:
                result = r[t.MutableStrPairSequence].fail(
                    f"RDN parsing error: {e}",
                )
        return result

    @staticmethod
    def _parse_dn_components(dn_str: str) -> p.Result[t.MutableStrPairSequence]:
        """Parse already validated DN string components."""
        parsed_pairs: t.MutableStrPairSequence = []
        failure_message: str | None = None
        for component in FlextLdifUtilitiesDN.split(dn_str):
            parsed_component = FlextLdifUtilitiesDN.parse_rdn(component)
            if parsed_component.failure:
                failure_message = str(parsed_component.error)
                break
            parsed_pairs.extend(parsed_component.value)
        if failure_message is None and parsed_pairs:
            return r[t.MutableStrPairSequence].ok(parsed_pairs)
        return r[t.MutableStrPairSequence].fail(
            failure_message or f"Failed to parse DN components from '{dn_str}'",
        )

    @staticmethod
    def _parse_rdn_core(rdn: str) -> p.Result[t.MutableStrPairSequence]:
        """Parse a non-empty RDN component."""
        pairs: t.MutableStrPairSequence = []
        current_attr = ""
        current_val = ""
        in_value = False
        rdn_len: int = len(rdn)
        position: int = 0
        error_message: str | None = None
        rdn_config = m.Ldif.RdnProcessingConfig()
        rdn_config.current_attr = current_attr
        rdn_config.current_val = current_val
        rdn_config.in_value = in_value
        rdn_config.pairs = pairs
        while position < rdn_len and error_message is None:
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
            if char_at_pos == "=" and (not in_value) and (not current_attr):
                error_message = f"Invalid RDN format: unexpected '=' at position {idx}"
        if error_message is None and (not in_value or not current_attr):
            error_message = f"Invalid RDN format: missing attribute or value in '{rdn}'"
        current_val = current_val.strip()
        if error_message is None and not current_val:
            error_message = f"Invalid RDN format: empty value in '{rdn}'"
        if error_message is None:
            pairs.append((current_attr, current_val))
            return r[t.MutableStrPairSequence].ok(pairs)
        return r[t.MutableStrPairSequence].fail(error_message)

    @overload
    @staticmethod
    def split(dn: str) -> t.MutableSequenceOf[str]: ...

    @overload
    @staticmethod
    def split(dn: m.Ldif.DN) -> t.MutableSequenceOf[str]: ...

    @staticmethod
    def split(dn: str | m.Ldif.DN) -> t.MutableSequenceOf[str]:
        r"""Split DN string into individual RDN components per RFC 4514.

        RFC 4514 Section 2 ABNF:
        ========================
        distinguishedName = [ relativeDistinguishedName
                             *( COMMA relativeDistinguishedName ) ]
        COMMA = %x2C  ; comma (",")

        Properly handles escaped commas (\\\\,) and other special characters.
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
                        current += char
                elif char == ",":
                    if current.strip():
                        yield current.strip()
                        current = ""
                else:
                    current += char
            if current.strip():
                yield current.strip()

        return list(split_components())

    @overload
    @staticmethod
    def transform_dn_attribute(value: str, source_dn: str, target_dn: str) -> str: ...

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
        if not dn_str or not source_dn or (not target_dn):
            return dn_str
        norm_result = FlextLdifUtilitiesDN.norm(dn_str)
        normalized_dn = norm_result.map_or(dn_str)
        source_escaped = c.Ldif.escape_pattern(source_dn)
        result = u.to_str(
            c.Ldif.sub_pattern(
                f",{source_escaped}$",
                f",{target_dn}",
                normalized_dn,
                ignorecase=True,
            )
        )
        if result == normalized_dn:
            result = u.to_str(
                c.Ldif.sub_pattern(
                    f"^{source_escaped}$",
                    target_dn,
                    normalized_dn,
                    ignorecase=True,
                )
            )
        return result

    @staticmethod
    def unesc(value: str) -> str:
        r"""Unescape special characters in DN value per RFC 4514 Section 3.

        RFC 4514 Unescaping Requirements:
        =================================
        - \\\\XX where XX is hex digits -> character with that code
        - \\\\<special> -> the literal special character
        - Escape sequences: \\\\", \\\\+, \\\\,, \\\\;, \\\\<, \\\\>, \\\\\\\\

        Args:
            value: The escaped DN attribute value.

        Returns:
            The unescaped value string.

        """
        if not value or "\\" not in value:
            return value
        result: t.MutableSequenceOf[str] = []
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
    def transform_entry_base_dn(
        entry: m.Ldif.Entry,
        source_dn: str,
        target_dn: str,
        dn_valued_attributes: frozenset[str] | None = None,
    ) -> m.Ldif.Entry:
        """Transform an entry's DN and DN-valued attributes from source to target base DN.

        Rewrites:
        - The entry's own DN
        - All attributes whose name is in dn_valued_attributes (member, uniqueMember, etc.)

        Returns a model_copy with transformed values. Original entry is not mutated.
        """
        attrs_to_transform = dn_valued_attributes or c.Ldif.ALL_DN_VALUED
        updates: MutableMapping[str, object] = {}
        entry_dn = entry.dn
        if entry_dn is not None:
            dn_str = FlextLdifUtilitiesDN.get_dn_value(entry_dn)
            if dn_str:
                new_dn_str = FlextLdifUtilitiesDN.transform_dn_attribute(
                    dn_str,
                    source_dn,
                    target_dn,
                )
                if new_dn_str != dn_str:
                    updates["dn"] = m.Ldif.DN(value=new_dn_str)
        entry_attrs = entry.attributes
        if entry_attrs is not None:
            attr_dict = entry_attrs.attributes
            changed_attrs: MutableMapping[str, t.MutableSequenceOf[str]] = {}
            for attr_name, values in attr_dict.items():
                if attr_name.lower() in {a.lower() for a in attrs_to_transform}:
                    new_values: t.MutableSequenceOf[str] = []
                    attr_changed = False
                    for val in values:
                        new_val = FlextLdifUtilitiesDN.transform_dn_attribute(
                            val,
                            source_dn,
                            target_dn,
                        )
                        new_values.append(new_val)
                        if new_val != val:
                            attr_changed = True
                    if attr_changed:
                        changed_attrs[attr_name] = new_values
            if changed_attrs:
                new_attr_dict = dict(attr_dict)
                new_attr_dict.update(changed_attrs)
                new_attrs = entry_attrs.model_copy(update={"attributes": new_attr_dict})
                updates["attributes"] = new_attrs
        if updates:
            copied: m.Ldif.Entry = entry.model_copy(update=updates)
            return copied
        return entry

    @staticmethod
    def transform_ldif_files_in_directory(
        ldif_dir: str | object,
        source_basedn: str,
        target_basedn: str,
    ) -> MutableMapping[str, int | t.MutableSequenceOf[str]]:
        """Transform base DN in all LDIF files in a directory.

        Reads each .ldif file, replaces source_basedn with target_basedn
        in all DN lines and DN-valued attribute values, and writes back.

        Returns dict with total_count (files transformed) and transformed_files list.
        """
        directory = Path(str(ldif_dir))
        transformed_files: t.MutableSequenceOf[str] = []
        for ldif_file in sorted(directory.glob("*.ldif")):
            content = ldif_file.read_text(encoding=c.Ldif.DEFAULT_ENCODING)
            new_content = FlextLdifUtilitiesDN._transform_ldif_content(
                content,
                source_basedn,
                target_basedn,
            )
            if new_content != content:
                _ = ldif_file.write_text(new_content, encoding=c.Ldif.DEFAULT_ENCODING)
                transformed_files.append(ldif_file.name)
        return {
            "total_count": len(transformed_files),
            "transformed_files": transformed_files,
        }

    @staticmethod
    def _transform_ldif_content(content: str, source_dn: str, target_dn: str) -> str:
        """Transform all DN references in raw LDIF content string."""
        return u.to_str(
            c.Ldif.sub_pattern(
                c.Ldif.escape_pattern(source_dn),
                target_dn,
                content,
                ignorecase=True,
            )
        )

    @staticmethod
    def validate_dn(dn: str | m.Ldif.DN) -> bool:
        r"""Validate DN format according to RFC 4514.

        Properly handles escaped characters. Checks for:
        - No double unescaped commas
        - No leading/trailing unescaped commas
        - All components have attr=value format
        - Valid hex escape sequences (\\XX where X is hex digit)
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
        except c.EXC_TYPE_VALIDATION:
            return False


__all__: list[str] = ["FlextLdifUtilitiesDN"]
