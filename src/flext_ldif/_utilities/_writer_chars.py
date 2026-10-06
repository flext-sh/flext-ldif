"""LDIF RFC 2849 character safety utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c


class FlextLdifWriterRfcChars:
    """Classify LDIF value characters per RFC 2849 §2."""

    @staticmethod
    def is_safe_char(char: str) -> bool:
        """Check if char is SAFE-CHAR per RFC 2849 §2.

        Returns:
            The resulting ``bool``.
        """
        if not char or len(char) != 1:
            return False
        code = ord(char)
        return (
            c.Ldif.SAFE_CHAR_MIN <= code <= c.Ldif.SAFE_CHAR_MAX
            and code not in c.Ldif.SAFE_CHAR_EXCLUDE
        )

    @staticmethod
    def is_safe_init_char(char: str) -> bool:
        """Check if char is SAFE-INIT-CHAR per RFC 2849 §2.

        Returns:
            The resulting ``bool``.
        """
        if not char or len(char) != 1:
            return False
        code = ord(char)
        if not FlextLdifWriterRfcChars.is_safe_char(char):
            return False
        return code not in c.Ldif.SAFE_INIT_CHAR_EXCLUDE

    @staticmethod
    def needs_base64_encoding(value: str, *, check_trailing_space: bool = True) -> bool:
        """Check if value needs base64 encoding per RFC 2849 §2.

        Returns:
            The resulting ``bool``.
        """
        if not value:
            return False
        if value[0] in c.Ldif.BASE64_START_CHARS:
            return True
        if check_trailing_space and value[-1] == " ":
            return True
        for char in value:
            byte_val = ord(char)
            if (
                byte_val < c.Ldif.SAFE_CHAR_MIN
                or byte_val > c.Ldif.SAFE_CHAR_MAX
                or byte_val in c.Ldif.SAFE_CHAR_EXCLUDE
            ):
                return True
        return False


__all__: list[str] = ["FlextLdifWriterRfcChars"]
