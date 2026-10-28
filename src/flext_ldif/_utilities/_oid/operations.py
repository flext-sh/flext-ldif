"""OID extraction and validation operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from flext_ldif import c, p, r

if TYPE_CHECKING:
    from flext_ldif import t


class FlextLdifUtilitiesOIDOperations:
    """OID extraction and validation operations."""

    @staticmethod
    def extract_from_definition(
        definition: str,
        *,
        patterns: Sequence[t.Ldif.RegexPattern] = (c.Ldif.SCHEMA_OID_CAPTURE_RE,),
        empty_error: str = "",
    ) -> p.Result[str]:
        """Extract OID from schema definition string.

        Returns:
            The resulting ``p.Result[str]``.

        """
        if not definition and empty_error:
            return r[str].fail(empty_error)
        for pattern in patterns:
            match = pattern.search(definition)
            if match:
                return r[str].ok(match.group(1))
        return r[str].fail(f"missing an OID in definition: {definition!r}")

    @staticmethod
    def matches_pattern(definition: str, oid_pattern: t.Ldif.RegexPattern) -> bool:
        """Check if schema definition string matches server's OID pattern.

        Returns:
            The resulting ``bool``.

        """
        if not definition:
            return False
        oid_res = FlextLdifUtilitiesOIDOperations.extract_from_definition(definition)
        if oid_res.failure:
            return False
        return oid_pattern.search(oid_res.value) is not None

    @staticmethod
    def validate_format(oid: str) -> p.Result[bool]:
        """Validate OID format against standard numerical dotted notation.

        Returns:
            The resulting ``p.Result[bool]``.

        """
        if not oid:
            return r[bool].fail("OID cannot be empty")
        match = c.Ldif.NUMERIC_OID_RE.match(oid)
        if not match:
            return r[bool].fail(f"Invalid OID format: {oid}")
        return r[bool].ok(value=True)


__all__: list[str] = ["FlextLdifUtilitiesOIDOperations"]
