"""Single-RDN parsing through the native RFC 4514 parser.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from ldap3.core.exceptions import LDAPInvalidDnError
from ldap3.utils.dn import parse_dn

from flext_ldif import p, r, t
from flext_ldif._utilities._dn import FlextLdifUtilitiesDNEscape


class FlextLdifUtilitiesDNRdn:
    """Return decoded attribute/value pairs for one RDN."""

    @staticmethod
    def parse_rdn(rdn: str) -> p.Result[t.MutableStrPairSequence]:
        """Parse one RDN, preserving its AVAs and decoded UTF-8 values.

        Returns:
            Native parsed pairs, or the original parsing/decoding failure.

        """
        try:
            parsed = parse_dn(rdn, strip=True)
            if not parsed or any(separator == "," for _, _, separator in parsed):
                return r[t.MutableStrPairSequence].fail("Expected one nonempty RDN")
            return r[t.MutableStrPairSequence].ok([
                (attribute.lower(), FlextLdifUtilitiesDNEscape.unesc(value))
                for attribute, value, _ in parsed
            ])
        except (LDAPInvalidDnError, UnicodeError) as exc:
            return r[t.MutableStrPairSequence].fail_op("RDN parsing", exc)


__all__: list[str] = ["FlextLdifUtilitiesDNRdn"]
