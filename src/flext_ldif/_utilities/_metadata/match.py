"""LDIF schema matching-rule/SUP/SINGLE-VALUE detail extraction.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, t
from flext_ldif._utilities._metadata import FlextLdifUtilitiesMetadataSpacing


class FlextLdifUtilitiesMetadataMatch:
    """Extract matching-rule, SUP, and value-flag formatting details."""

    @staticmethod
    def extract_matching_rule_details(definition: str) -> t.MutableFeatureFlagMapping:
        """Extract EQUALITY/SUBSTR/ORDERING details.

        Returns:
            The resulting ``t.MutableFeatureFlagMapping``.

        """
        token = FlextLdifUtilitiesMetadataSpacing.token_details
        return {
            **token(definition, c.Ldif.SCHEMA_EQUALITY_TOKEN_RE, "equality"),
            **token(definition, c.Ldif.SCHEMA_SUBSTR_TOKEN_BARE_RE, "substr"),
            **token(definition, c.Ldif.SCHEMA_ORDERING_TOKEN_BARE_RE, "ordering"),
        }

    @staticmethod
    def extract_sup_details(definition: str) -> t.MutableFeatureFlagMapping:
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
                details["sup_spacing_before"] = (
                    FlextLdifUtilitiesMetadataSpacing.spacing_before(
                        definition, sup_pos
                    )
                )
        else:
            details["sup_presence"] = False
        return details

    @staticmethod
    def extract_single_value_details(definition: str) -> t.MutableFeatureFlagMapping:
        """Extract SINGLE-VALUE details.

        Returns:
            The resulting ``t.MutableFeatureFlagMapping``.

        """
        return FlextLdifUtilitiesMetadataSpacing.token_details(
            definition, c.Ldif.SCHEMA_SINGLE_VALUE_RE, "single_value"
        )

    @staticmethod
    def extract_leading_trailing_spaces(definition: str) -> t.MutableStrMapping:
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


__all__: list[str] = ["FlextLdifUtilitiesMetadataMatch"]
