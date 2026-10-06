"""LDIF schema matching-rule/SUP/SINGLE-VALUE detail extraction.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, t


class FlextLdifMetadataMatchDetails:
    """Extract matching-rule, SUP, and value-flag formatting details."""

    @staticmethod
    def _extract_matching_rule_details(definition: str) -> t.MutableFeatureFlagMapping:
        """Extract EQUALITY/SUBSTR/ORDERING details.

        Returns:
            The resulting ``t.MutableFeatureFlagMapping``.
        """
        details: t.MutableFeatureFlagMapping = {}
        equality_match = c.Ldif.SCHEMA_EQUALITY_TOKEN_RE.search(definition)
        if equality_match:
            details["equality_presence"] = True
            before_match = c.Ldif.WHITESPACE_TRAILING_RE.search(
                definition[: equality_match.start()],
            )
            details["equality_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        else:
            details["equality_presence"] = False
        substr_match = c.Ldif.SCHEMA_SUBSTR_TOKEN_BARE_RE.search(definition)
        if substr_match:
            details["substr_presence"] = True
            before_match = c.Ldif.WHITESPACE_TRAILING_RE.search(
                definition[: substr_match.start()],
            )
            details["substr_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        else:
            details["substr_presence"] = False
        ordering_match = c.Ldif.SCHEMA_ORDERING_TOKEN_BARE_RE.search(definition)
        if ordering_match:
            details["ordering_presence"] = True
            before_match = c.Ldif.WHITESPACE_TRAILING_RE.search(
                definition[: ordering_match.start()],
            )
            details["ordering_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        else:
            details["ordering_presence"] = False
        return details

    @staticmethod
    def _extract_sup_details(definition: str) -> t.MutableFeatureFlagMapping:
        """Extract SUP details.

        Returns:
            The resulting ``t.MutableFeatureFlagMapping``.
        """
        details: t.MutableFeatureFlagMapping = {}
        sup_match = c.Ldif.SCHEMA_SUP_LOOSE_RE.search(definition)
        if sup_match:
            details["sup_presence"] = True
            details["sup_value"] = sup_match.group(1)
            sup_pos = definition.find("SUP")
            if sup_pos >= 0:
                before_match = c.Ldif.WHITESPACE_TRAILING_RE.search(
                    definition[:sup_pos],
                )
                details["sup_spacing_before"] = (
                    before_match.group(1) if before_match else ""
                )
        else:
            details["sup_presence"] = False
        return details

    @staticmethod
    def _extract_single_value_details(definition: str) -> t.MutableFeatureFlagMapping:
        """Extract SINGLE-VALUE details.

        Returns:
            The resulting ``t.MutableFeatureFlagMapping``.
        """
        details: t.MutableFeatureFlagMapping = {}
        single_value_match = c.Ldif.SCHEMA_SINGLE_VALUE_RE.search(definition)
        if single_value_match:
            details["single_value_presence"] = True
            before_match = c.Ldif.WHITESPACE_TRAILING_RE.search(
                definition[: single_value_match.start()],
            )
            details["single_value_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        else:
            details["single_value_presence"] = False
        return details

    @staticmethod
    def _extract_leading_trailing_spaces(definition: str) -> t.MutableStrMapping:
        """Extract leading and trailing spaces.

        Returns:
            The resulting ``t.MutableStrMapping``.
        """
        details: t.MutableStrMapping = {}
        trailing_match = c.Ldif.SCHEMA_TRAILING_PAREN_RE.search(definition)
        details["trailing_spaces"] = (
            definition[trailing_match.end() :] if trailing_match else ""
        )
        leading_match = c.Ldif.SCHEMA_LEADING_PAREN_RE.search(definition)
        details["leading_spaces"] = leading_match.group(0)[:-1] if leading_match else ""
        return details


__all__: list[str] = ["FlextLdifMetadataMatchDetails"]
