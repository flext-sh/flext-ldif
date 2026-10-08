"""RFC 4514 DN value escaping utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import string

from flext_ldif import c, t


class FlextLdifDNEscaping:
    """Escape and unescape DN attribute values per RFC 4514 Section 2.4/3."""

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
        from flext_cli import u

        if not value:
            return value

        def escape_char(item: tuple[int, str]) -> str:
            """Escape single character if needed.

            Returns:
                The resulting ``str``.
            """
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
                    ch in string.hexdigits for ch in value[i + 1 : i + 3]
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


__all__: list[str] = ["FlextLdifDNEscaping"]
