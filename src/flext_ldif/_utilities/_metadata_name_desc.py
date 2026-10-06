"""LDIF schema NAME and DESC formatting detail extraction.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, t


class FlextLdifMetadataNameDescDetails:
    """Extract NAME and DESC formatting details from schema definitions."""

    @staticmethod
    def _extract_name_details(definition: str) -> t.MutableAttributeMapping:
        """Extract NAME format details.

        Returns:
            The resulting ``t.MutableAttributeMapping``.
        """
        details: t.MutableAttributeMapping = {
            "name_format": "single",
            "name_values": [],
            "name_quotes": [],
            "name_spacing_before": "",
        }
        name_match = c.Ldif.SCHEMA_NAME_LOOSE_RE.search(definition)
        if name_match is None:
            return details
        has_parens = bool(name_match.group(1))
        name_quote_start = name_match.group(2) or ""
        name_value = name_match.group(3)
        name_quote_end = name_match.group(4) or ""
        multiple_match = c.Ldif.SCHEMA_NAME_MULTIPLE_RE.search(definition)
        name_section = definition[name_match.start() : name_match.end() + 50]
        if multiple_match or (has_parens and " " in name_value):
            all_name_matches = c.Ldif.QUOTED_NAME_TRIPLE_RE.findall(name_section)
            details.update({
                "name_format": "multiple",
                "name_values": [match[1] for match in all_name_matches],
                "name_quotes": [match[0] for match in all_name_matches],
                "name_spacing_between": c.Ldif.QUOTED_SPACE_QUOTE_RE.findall(
                    name_section,
                ),
            })
        else:
            quote_char = name_quote_start or name_quote_end
            details.update({
                "name_values": [name_value],
                "name_quotes": [quote_char] if quote_char else [],
            })
        name_pos = definition.find("NAME")
        if name_pos >= 0:
            before_match = c.Ldif.WHITESPACE_TRAILING_RE.search(definition[:name_pos])
            details["name_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        return details

    @staticmethod
    def _extract_desc_details(definition: str) -> t.MutableFeatureFlagMapping:
        """Extract DESC details.

        Returns:
            The resulting ``t.MutableFeatureFlagMapping``.
        """
        details: t.MutableFeatureFlagMapping = {}
        desc_match = c.Ldif.SCHEMA_DESC_LOOSE_RE.search(definition)
        if desc_match:
            details["desc_presence"] = True
            details["desc_quotes"] = desc_match.group(1) or desc_match.group(3) or ""
            details["desc_value"] = desc_match.group(2)
            desc_pos = definition.find("DESC")
            if desc_pos >= 0:
                before_match = c.Ldif.WHITESPACE_TRAILING_RE.search(
                    definition[:desc_pos],
                )
                details["desc_spacing_before"] = (
                    before_match.group(1) if before_match else ""
                )
        else:
            details["desc_presence"] = False
        return details


__all__: list[str] = ["FlextLdifMetadataNameDescDetails"]
