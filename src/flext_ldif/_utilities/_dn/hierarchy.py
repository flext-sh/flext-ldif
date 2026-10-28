"""DN hierarchy operations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from flext_ldif import c
from flext_ldif._utilities._dn import FlextLdifUtilitiesDNParse


class FlextLdifUtilitiesDNHierarchy:
    """DN hierarchy and relationship utilities."""

    @classmethod
    def under_base(cls, dn: str | None, base_dn: str | None) -> bool:
        """Check if DN is under base DN (hierarchical check).

        Returns:
            The resulting ``bool``.

        """
        if not dn or not base_dn:
            return False
        dn_str = FlextLdifUtilitiesDNParse.resolve_dn_value(dn)
        base_dn_str = FlextLdifUtilitiesDNParse.resolve_dn_value(base_dn)
        if not dn_str or not base_dn_str:
            return False
        dn_lower = dn_str.lower().strip()
        base_dn_lower = base_dn_str.lower().strip()
        return dn_lower == base_dn_lower or dn_lower.endswith(f",{base_dn_lower}")

    @classmethod
    def hierarchy_key(cls, dn: str) -> tuple[int, str]:
        """Order key placing parents before children, then siblings by name.

        The key is the RDN count followed by the case-folded RDNs joined from
        the root down, with spacing around ``=`` removed.

        Returns:
            The resulting ``tuple[int, str]``.

        """
        rdns = [
            c.Ldif.DN_NORMALIZE_EQUALS_RE.sub("=", rdn)
            for rdn in FlextLdifUtilitiesDNParse.split(dn)
        ]
        return (len(rdns), ",".join(reversed(rdns)).lower())


__all__: list[str] = ["FlextLdifUtilitiesDNHierarchy"]
