"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._utilities import FlextLdifDNCharClass
from flext_ldif._utilities import FlextLdifDNCleaning
from flext_ldif._utilities import FlextLdifDNEscaping
from flext_ldif._utilities import FlextLdifDNNormalization
from flext_ldif._utilities import FlextLdifDNParsing
from flext_ldif._utilities import FlextLdifDNRdnParsing
from flext_ldif._utilities import FlextLdifDNRebasing
from flext_ldif._utilities import FlextLdifDNTransforming
from flext_ldif._utilities import FlextLdifDNValidation


class FlextLdifUtilitiesDN(
    FlextLdifDNCharClass,
    FlextLdifDNEscaping,
    FlextLdifDNParsing,
    FlextLdifDNRdnParsing,
    FlextLdifDNNormalization,
    FlextLdifDNValidation,
    FlextLdifDNCleaning,
    FlextLdifDNTransforming,
    FlextLdifDNRebasing,
):
    r"""RFC 4514 DN Operations - STRICT Implementation.

    RFC 4514 ABNF Grammar (Section 2):
    ==================================
    distinguishedName = [ relativeDistinguishedName
                         *( COMMA relativeDistinguishedName ) ]
    relativeDistinguishedName = attributeTypeAndValue
                         *( PLUS attributeTypeAndValue )
    attributeTypeAndValue = attributeType EQUALS attributeValue
    attributeType = descr / numericoid
    attributeValue = string / hexstring

    String Encoding (Section 2.4):
    ==============================
    string = [ ( leadchar / pair ) [ *( stringchar / pair )
               ( trailchar / pair ) ] ]
    leadchar = LUTF1 / UTFMB  ; not SPACE, not '#', not special
    trailchar = TUTF1 / UTFMB  ; not SPACE
    stringchar = SUTF1 / UTFMB

    Escape Mechanism:
    =================
    pair = ESC ( ESC / special / hexpair )
    special = escaped / SPACE / SHARP / EQUALS  ; Rfc.DN_SPECIAL_CHARS
    escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE
              ; Rfc.DN_ESCAPED_CHARS
    hexstring = SHARP 1*hexpair
    hexpair = HEX HEX

    Character Classes (c.Ldif.Rfc):
    ============================================
    LUTF1  = %x01-1F / %x21 / %x24-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
             ; Rfc.DN_LUTF1_EXCLUDE
    TUTF1  = %x01-1F / %x21 / %x23-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
             ; Rfc.DN_TUTF1_EXCLUDE
    SUTF1  = %x01-21 / %x23-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
             ; Rfc.DN_SUTF1_EXCLUDE
    COMMA  = %x2C  ; Rfc.DN_RDN_SEPARATOR
    PLUS   = %x2B  ; Rfc.DN_MULTIVALUE_SEPARATOR
    EQUALS = %x3D  ; Rfc.DN_ATTR_VALUE_SEPARATOR
    SPACE  = %x20
    SHARP  = %x23  ; '#'
    ESC    = %x5C  ; '\\'

    Escaping Rules (c.Ldif.Rfc):
    ========================================
    - Characters always requiring escaping: Rfc.DN_ESCAPE_CHARS
    - Characters requiring escaping at start: Rfc.DN_ESCAPE_AT_START
    - Characters requiring escaping at end: Rfc.DN_ESCAPE_AT_END

    Metadata Keys (c.Ldif.Rfc):
    =======================================
    - META_DN_ORIGINAL: Original DN before normalization
    - META_DN_WAS_BASE64: DN was base64 encoded
    - META_DN_ESCAPES_APPLIED: Escape sequences used

    All methods return primitives (str, list, tuple, bool, int, None).
    Pure functions: no server-specific logic, no side effects.

    Supports both:
    - FlextLdifModels.Ldif.DN (DN model)
    - str (DN string value)

    """

    @staticmethod
    def under_base(dn: str | None, base_dn: str | None) -> bool:
        """Check if DN is under base DN (hierarchical check).

        Returns:
            The resulting ``bool``.

        """
        if not dn or not base_dn:
            return False
        dn_str = FlextLdifUtilitiesDN.resolve_dn_value(dn)
        base_dn_str = FlextLdifUtilitiesDN.resolve_dn_value(base_dn)
        if not dn_str or not base_dn_str:
            return False
        dn_lower = dn_str.lower().strip()
        base_dn_lower = base_dn_str.lower().strip()
        return dn_lower == base_dn_lower or dn_lower.endswith(f",{base_dn_lower}")


__all__: list[str] = ["FlextLdifUtilitiesDN"]
