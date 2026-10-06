"""RFC 4514 DN character classification utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, t


class FlextLdifDNCharClass:
    """Classify DN characters per RFC 4514 LUTF1/TUTF1/SUTF1 productions."""

    @staticmethod
    def _is_rfc_char_class(char: str, excluded: frozenset[int]) -> bool:
        """Check one character against the shared safe range and an exclusion set.

        Returns:
            The resulting ``bool``.
        """
        if not char or len(char) != 1:
            return False
        code = ord(char)
        if code < c.Ldif.SAFE_CHAR_MIN or code > c.Ldif.SAFE_CHAR_MAX:
            return False
        return code not in excluded

    @staticmethod
    def is_lutf1_char(char: str) -> bool:
        """Check if char is valid LUTF1 (lead char) per RFC 4514.

        Returns:
            The resulting ``bool``.
        """
        return FlextLdifDNCharClass._is_rfc_char_class(char, c.Ldif.DN_LUTF1_EXCLUDE)

    @staticmethod
    def is_sutf1_char(char: str) -> bool:
        """Check if char is valid SUTF1 (string char) per RFC 4514.

        Returns:
            The resulting ``bool``.
        """
        return FlextLdifDNCharClass._is_rfc_char_class(char, c.Ldif.DN_SUTF1_EXCLUDE)

    @staticmethod
    def is_tutf1_char(char: str) -> bool:
        """Check if char is valid TUTF1 (trail char) per RFC 4514.

        Returns:
            The resulting ``bool``.
        """
        return FlextLdifDNCharClass._is_rfc_char_class(char, c.Ldif.DN_TUTF1_EXCLUDE)

    @staticmethod
    def is_valid_dn_string(
        value: str,
        *,
        strict: bool = True,
    ) -> tuple[bool, t.MutableSequenceOf[str]]:
        """Validate DN attribute value per RFC 4514 string production.

        Returns:
            The resulting ``tuple[bool, t.MutableSequenceOf[str]]``.
        """
        errors: t.MutableSequenceOf[str] = []
        if not value:
            return (True, errors)
        if len(value) == 1:
            if not FlextLdifDNCharClass.is_lutf1_char(value) and strict:
                errors.append(f"Invalid lead character: {value!r}")
            return (not errors, errors)
        is_escaped_lead = value[0] == "\\" and len(value) > 1
        is_bad_lead = not FlextLdifDNCharClass.is_lutf1_char(value[0]) and (
            not is_escaped_lead
        )
        if is_bad_lead and strict:
            errors.append(f"Invalid lead character: {value[0]!r}")
        min_len_for_escape = c.Ldif.MIN_DN_LENGTH
        is_escaped_trail = len(value) >= min_len_for_escape and value[-2] == "\\"
        is_bad_trail = not FlextLdifDNCharClass.is_tutf1_char(value[-1]) and (
            not is_escaped_trail
        )
        if is_bad_trail and strict:
            errors.append(f"Invalid trail character: {value[-1]!r}")
        for i, char in enumerate(value[1:-1], start=1):
            if FlextLdifDNCharClass.is_sutf1_char(char):
                continue
            is_escape_char = char == "\\"
            is_after_escape = i > 0 and value[i - 1] == "\\"
            if not is_escape_char and (not is_after_escape) and strict:
                errors.append(f"Invalid character at position {i}: {char!r}")
        return (not errors, errors)


__all__: list[str] = ["FlextLdifDNCharClass"]
