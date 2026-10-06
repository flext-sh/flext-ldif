"""RFC 4514 DN structural validation utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_cli import u

from flext_ldif import FlextLdifModels, c, t
from flext_ldif._utilities._dn_parse import FlextLdifDNParsing

if TYPE_CHECKING:
    from collections.abc import Callable


class FlextLdifDNValidation:
    """Validate DN structure, escapes, and components per RFC 4514."""

    @staticmethod
    def _has_double_unescaped_commas(dn_str: str) -> bool:
        """Check for consecutive unescaped commas in DN string.

        Returns:
            The resulting ``bool``.
        """
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
    def _consume_dn_escape(dn_str: str, i: int) -> int | None:
        """Return the next index after a valid escape at ``i``, else ``None``.

        Hex escapes (``\\\\XX``) consume three characters; escaped specials and
        UTF-8 lead bytes consume the backslash only.

        Returns:
            The resulting ``int | None``.
        """
        hex_escape_length = 2
        if i + hex_escape_length >= len(dn_str):
            return None
        next_two = dn_str[i + 1 : i + 1 + hex_escape_length]
        if len(next_two) == hex_escape_length:
            if all(ch in "0123456789ABCDEFabcdef" for ch in next_two):
                return i + 3
            utf8_start = 128
            if next_two[0] in ' \t\r\n,+"\\<>;=' or ord(next_two[0]) >= utf8_start:
                return i + 1
            return None
        return None

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
        i = 0
        while i < len(dn_str):
            if dn_str[i] == "\\":
                next_index = FlextLdifDNValidation._consume_dn_escape(dn_str, i)
                if next_index is None:
                    return False
                i = next_index
                continue
            i += 1
        return True

    @staticmethod
    def _validate_basic_format(dn_str: str) -> bool:
        """Validate basic DN format requirements.

        Returns:
            The resulting ``bool``.
        """
        return bool(dn_str and "=" in dn_str)

    @staticmethod
    def _validate_components(components: t.MutableSequenceOf[str]) -> bool:
        """Validate each DN component has attr=value format (helper method).

        Returns:
            The resulting ``bool``.
        """

        def is_valid_component(comp: str) -> bool:
            """Check if component is valid.

            Returns:
                The resulting ``bool``.
            """
            if "=" not in comp:
                return False
            attr, _, value = comp.partition("=")
            return bool(attr.strip() and value.strip())

        filtered = u.filter(components, is_valid_component)
        return len(filtered) == len(components)

    @staticmethod
    def _validate_dn_structure(dn_str: str) -> bool:
        """Validate DN structure (commas, escape sequences, components).

        Returns:
            The resulting ``bool``.
        """
        checks: t.MutableSequenceOf[Callable[[], bool]] = [
            lambda: FlextLdifDNValidation._validate_escape_sequences(dn_str),
            lambda: not FlextLdifDNValidation._has_double_unescaped_commas(dn_str),
            lambda: not dn_str.startswith(","),
            lambda: (
                not (
                    dn_str.endswith(",")
                    and (len(dn_str) < c.Ldif.MIN_DN_LENGTH or dn_str[-2] != "\\")
                )
            ),
        ]
        return all(check() for check in checks)

    @staticmethod
    def validate_dn(dn: str | FlextLdifModels.Ldif.DN) -> bool:
        r"""Validate DN format according to RFC 4514.

        Properly handles escaped characters. Checks for:
        - No double unescaped commas
        - No leading/trailing unescaped commas
        - All components have attr=value format
        - Valid hex escape sequences (\\XX where X is hex digit)

        Returns:
            The resulting ``bool``.
        """
        dn_str = FlextLdifDNParsing.get_dn_value(dn)
        if not FlextLdifDNValidation._validate_basic_format(dn_str):
            return False
        if not FlextLdifDNValidation._validate_dn_structure(dn_str):
            return False
        components = FlextLdifDNParsing.split(dn_str)
        return bool(
            components and FlextLdifDNValidation._validate_components(components),
        )


__all__: list[str] = ["FlextLdifDNValidation"]
