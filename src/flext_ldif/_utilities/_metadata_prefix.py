"""LDIF schema prefix formatting detail extraction.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, t


class FlextLdifMetadataPrefixDetails:
    """Extract attributetypes/objectclasses LDIF prefix details."""

    class PrefixSpec:
        """One LDIF prefix marker and the detail keys it records."""

        def __init__(
            self,
            marker_present: bool,
            prefix_pattern: t.Ldif.RegexPattern,
            case_key: str,
            spacing_key: str,
        ) -> None:
            """Bind one prefix probe.

            Args:
                marker_present: Whether the definition carries the marker.
                prefix_pattern: Regex matching the prefix declaration.
                case_key: Detail key recording the declared case.
                spacing_key: Detail key recording the declared spacing.
            """
            self.marker_present = marker_present
            self.prefix_pattern = prefix_pattern
            self.case_key = case_key
            self.spacing_key = spacing_key

    @staticmethod
    def _extract_single_prefix_details(
        definition: str,
        spec: PrefixSpec,
        details: t.MutableStrMapping,
    ) -> None:
        """Record prefix case and spacing details for one LDIF prefix."""
        if not spec.marker_present:
            return
        prefix_match = spec.prefix_pattern.search(definition)
        if prefix_match is None:
            return
        details[spec.case_key] = prefix_match.group(1)
        colon_pos = definition.find(":")
        if colon_pos >= 0 and colon_pos + 1 < len(definition):
            spacing_match = c.Ldif.WHITESPACE_LEADING_RE.match(
                definition[colon_pos + 1 :],
            )
            if spacing_match:
                details[spec.spacing_key] = spacing_match.group(1)

    @classmethod
    def _extract_prefix_details(cls, definition: str) -> t.MutableStrMapping:
        """Extract attribute/ObjectClass prefix details.

        Returns:
            The resulting ``t.MutableStrMapping``.
        """
        details: t.MutableStrMapping = {}
        specs = (
            cls.PrefixSpec(
                marker_present="attributetypes:" in definition.lower(),
                prefix_pattern=c.Ldif.LDIF_ATTR_TYPES_PREFIX_RE,
                case_key="attribute_case",
                spacing_key="attribute_prefix_spacing",
            ),
            cls.PrefixSpec(
                marker_present=(
                    "objectclasses:" in definition.lower()
                    or "objectClasses:" in definition
                ),
                prefix_pattern=c.Ldif.LDIF_OBJECTCLASSES_PREFIX_RE,
                case_key="objectclass_case",
                spacing_key="objectclass_prefix_spacing",
            ),
        )
        for spec in specs:
            FlextLdifMetadataPrefixDetails._extract_single_prefix_details(
                definition,
                spec,
                details,
            )
        return details


__all__: list[str] = ["FlextLdifMetadataPrefixDetails"]
