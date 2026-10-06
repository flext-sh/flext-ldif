"""LDIF schema prefix formatting detail extraction.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, t


class FlextLdifMetadataPrefixDetails:
    """Extract attributetypes/objectclasses LDIF prefix details."""

    @staticmethod
    def _extract_single_prefix_details(
        definition: str,
        *,
        marker_present: bool,
        prefix_pattern: t.Ldif.RegexPattern,
        case_key: str,
        spacing_key: str,
        details: t.MutableStrMapping,
    ) -> None:
        """Record prefix case and spacing details for one LDIF prefix."""
        if not marker_present:
            return
        prefix_match = prefix_pattern.search(definition)
        if prefix_match is None:
            return
        details[case_key] = prefix_match.group(1)
        colon_pos = definition.find(":")
        if colon_pos >= 0 and colon_pos + 1 < len(definition):
            spacing_match = c.Ldif.WHITESPACE_LEADING_RE.match(
                definition[colon_pos + 1 :],
            )
            if spacing_match:
                details[spacing_key] = spacing_match.group(1)

    @staticmethod
    def _extract_prefix_details(definition: str) -> t.MutableStrMapping:
        """Extract attribute/ObjectClass prefix details.

        Returns:
            The resulting ``t.MutableStrMapping``.
        """
        details: t.MutableStrMapping = {}
        FlextLdifMetadataPrefixDetails._extract_single_prefix_details(
            definition,
            marker_present="attributetypes:" in definition.lower(),
            prefix_pattern=c.Ldif.LDIF_ATTR_TYPES_PREFIX_RE,
            case_key="attribute_case",
            spacing_key="attribute_prefix_spacing",
            details=details,
        )
        FlextLdifMetadataPrefixDetails._extract_single_prefix_details(
            definition,
            marker_present=(
                "objectclasses:" in definition.lower()
                or "objectClasses:" in definition
            ),
            prefix_pattern=c.Ldif.LDIF_OBJECTCLASSES_PREFIX_RE,
            case_key="objectclass_case",
            spacing_key="objectclass_prefix_spacing",
            details=details,
        )
        return details


__all__: list[str] = ["FlextLdifMetadataPrefixDetails"]
