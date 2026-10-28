"""LDIF schema token spacing primitives shared by the formatting extractors.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_ldif import c, t


class FlextLdifUtilitiesMetadataSpacing:
    """Measure the whitespace around schema definition tokens."""

    @staticmethod
    def spacing_before(definition: str, position: int) -> str:
        """Return the whitespace that ends right before ``position``.

        Returns:
            The trailing whitespace of ``definition[:position]``.

        """
        before = c.Ldif.WHITESPACE_TRAILING_RE.search(definition[:position])
        return before.group(1) if before else ""

    @staticmethod
    def token_details(
        definition: str, token: re.Pattern[str], key: str
    ) -> t.MutableFeatureFlagMapping:
        """Return whether one token occurs and the whitespace before it.

        Returns:
            ``<key>_presence`` and, when present, ``<key>_spacing_before``.

        """
        found = token.search(definition)
        if found is None:
            return {f"{key}_presence": False}
        return {
            f"{key}_presence": True,
            f"{key}_spacing_before": FlextLdifUtilitiesMetadataSpacing.spacing_before(
                definition, found.start()
            ),
        }


__all__: list[str] = ["FlextLdifUtilitiesMetadataSpacing"]
