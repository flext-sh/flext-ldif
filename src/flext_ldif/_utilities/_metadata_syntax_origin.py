"""LDIF schema SYNTAX/X-ORIGIN/OBSOLETE/OID formatting detail extraction.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping

from flext_ldif import c, t


class FlextLdifMetadataSyntaxOriginDetails:
    """Extract SYNTAX, X-ORIGIN, OBSOLETE, and OID formatting details."""

    @staticmethod
    def extract_syntax_details(definition: str) -> t.MutableOptionalFeatureFlagMapping:
        """Extract SYNTAX formatting details.

        Returns:
            The resulting ``t.MutableOptionalFeatureFlagMapping``.
        """
        details: t.MutableOptionalFeatureFlagMapping = {
            "syntax_quotes": False,
            "syntax_quote_char": "",
            "syntax_oid": None,
            "syntax_length": None,
        }
        syntax_match = c.Ldif.SCHEMA_SYNTAX_LOOSE_RE.search(definition)
        if syntax_match:
            details["syntax_quotes"] = bool(
                syntax_match.group(1) or syntax_match.group(3),
            )
            details["syntax_quote_char"] = (
                syntax_match.group(1) or syntax_match.group(3) or ""
            )
            details["syntax_oid"] = syntax_match.group(2)
            details["syntax_length"] = syntax_match.group(4) or None
            syntax_pos = definition.find("SYNTAX")
            if syntax_pos >= 0:
                after_syntax = definition[syntax_pos + 6 :]
                spacing_match = c.Ldif.WHITESPACE_LEADING_RE.match(after_syntax)
                if spacing_match:
                    details["syntax_spacing"] = spacing_match.group(1)
                before_match = c.Ldif.WHITESPACE_TRAILING_RE.search(
                    definition[:syntax_pos],
                )
                details["syntax_spacing_before"] = (
                    before_match.group(1) if before_match else ""
                )
        return details

    @staticmethod
    def extract_x_origin_details(
        definition: str,
    ) -> t.MutableOptionalFeatureFlagMapping:
        """Extract X-ORIGIN details.

        Returns:
            The resulting ``t.MutableOptionalFeatureFlagMapping``.
        """
        details: t.MutableOptionalFeatureFlagMapping = {}
        x_origin_match = c.Ldif.SCHEMA_X_ORIGIN_RE.search(definition)
        if x_origin_match:
            details["x_origin_presence"] = True
            details["x_origin_quotes"] = (
                x_origin_match.group(1) or x_origin_match.group(3) or ""
            )
            details["x_origin_value"] = x_origin_match.group(2)
            x_origin_pos = definition.find("X-ORIGIN")
            if x_origin_pos >= 0:
                before_match = c.Ldif.WHITESPACE_TRAILING_RE.search(
                    definition[:x_origin_pos],
                )
                details["x_origin_spacing_before"] = (
                    before_match.group(1) if before_match else ""
                )
        else:
            details["x_origin_presence"] = False
            details["x_origin_value"] = None
            details["x_origin_quotes"] = ""
        return details

    @staticmethod
    def extract_obsolete_details(
        definition: str,
    ) -> MutableMapping[str, bool | int | str | None]:
        """Extract OBSOLETE details.

        Returns:
            The resulting ``MutableMapping[str, bool | int | str | None]``.
        """
        details: MutableMapping[str, bool | int | str | None] = {}
        obsolete_match = c.Ldif.SCHEMA_OBSOLETE_RE.search(definition)
        if obsolete_match:
            details["obsolete_presence"] = True
            details["obsolete_position"] = obsolete_match.start()
            before_match = c.Ldif.WHITESPACE_TRAILING_RE.search(
                definition[: obsolete_match.start()],
            )
            details["obsolete_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        else:
            details["obsolete_presence"] = False
            details["obsolete_position"] = None
        return details

    @staticmethod
    def extract_oid_details(definition: str) -> t.MutableStrMapping:
        """Extract OID and spacing details.

        Returns:
            The resulting ``t.MutableStrMapping``.
        """
        details: t.MutableStrMapping = {}
        oid_match = c.Ldif.OID_CAPTURE_NUMERIC_RE.search(definition)
        if oid_match:
            details["oid_value"] = oid_match.group(1)
            details["oid_spacing_after"] = oid_match.group(2)
        return details


__all__: list[str] = ["FlextLdifMetadataSyntaxOriginDetails"]
