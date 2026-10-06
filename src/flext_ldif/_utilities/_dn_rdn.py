"""RFC 4514 RDN parsing utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import string

from flext_core import r

from flext_ldif import FlextLdifModels, c, p, t


class FlextLdifDNRdnParsing:
    """Parse single RDN components into attribute/value pairs."""

    @staticmethod
    def _process_rdn_escape(rdn: str, i: int, current_val: str) -> tuple[str, int]:
        """Process escape sequence in RDN parsing (extracted to reduce complexity).

        Returns:
            The resulting ``tuple[str, int]``.
        """
        if i + 1 < len(rdn):
            next_char = rdn[i + 1]
            if i + 2 < len(rdn) and all(
                ch in string.hexdigits for ch in rdn[i + 1 : i + 3]
            ):
                return (current_val + rdn[i : i + 3], i + 3)
            return (current_val + next_char, i + 2)
        return (current_val, i + 1)

    @staticmethod
    def _process_rdn_char(
        char: str,
        rdn: str,
        i: int,
        settings: FlextLdifModels.Ldif.RdnProcessingConfig,
    ) -> tuple[str, str, bool, int, bool]:
        """Process single character in RDN parsing.

        Returns:
            The resulting ``tuple[str, str, bool, int, bool]``.
        """
        current_attr = settings.current_attr
        current_val = settings.current_val
        in_value = settings.in_value
        if char == "\\" and i + 1 < len(rdn):
            current_val, next_i = FlextLdifDNRdnParsing._process_rdn_escape(
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
    def _advance_rdn_position(
        char: str,
        rdn: str,
        position: int,
        settings: FlextLdifModels.Ldif.RdnProcessingConfig,
    ) -> tuple[str, str, bool, int]:
        """Advance position during RDN parsing and return new state.

        Returns:
            The resulting ``tuple[str, str, bool, int]``.
        """
        result = FlextLdifDNRdnParsing._process_rdn_char(char, rdn, position, settings)
        attr, val, in_val, next_pos, _ = result
        return (attr, val, in_val, next_pos)

    @staticmethod
    def _parse_rdn_core(rdn: str) -> p.Result[t.MutableStrPairSequence]:
        """Parse a non-empty RDN component.

        Returns:
            The resulting ``p.Result[t.MutableStrPairSequence]``.
        """
        pairs: t.MutableStrPairSequence = []
        current_attr = ""
        current_val = ""
        in_value = False
        rdn_len: int = len(rdn)
        position: int = 0
        error_message: str | None = None
        rdn_config = FlextLdifModels.Ldif.RdnProcessingConfig()
        rdn_config.current_attr = current_attr
        rdn_config.current_val = current_val
        rdn_config.in_value = in_value
        rdn_config.pairs = pairs
        while position < rdn_len and error_message is None:
            idx: int = position
            char_at_pos: str = rdn[idx]
            current_attr, current_val, in_value, position = (
                FlextLdifDNRdnParsing._advance_rdn_position(
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

    @staticmethod
    def parse_rdn(rdn: str) -> p.Result[t.MutableStrPairSequence]:
        """Parse a single RDN component per RFC 4514.

        Returns:
            The resulting ``p.Result[t.MutableStrPairSequence]``.
        """
        result: p.Result[t.MutableStrPairSequence] = r[t.MutableStrPairSequence].fail(
            "RDN must be a non-empty string",
        )
        if rdn:
            try:
                result = FlextLdifDNRdnParsing._parse_rdn_core(rdn)
            except c.Ldif.EXC_LDIF_PARSE as e:
                result = r[t.MutableStrPairSequence].fail(
                    f"RDN parsing error: {e}",
                    exception=e,
                )
        return result


__all__: list[str] = ["FlextLdifDNRdnParsing"]
