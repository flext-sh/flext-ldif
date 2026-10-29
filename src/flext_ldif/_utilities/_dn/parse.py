"""RFC 4514 DN string parsing utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import overload

from flext_ldif import FlextLdifModels, c, p, r, t
from flext_ldif._utilities import FlextLdifUtilitiesEntry
from flext_ldif._utilities._dn import FlextLdifUtilitiesDNRdn


class FlextLdifUtilitiesDNParse:
    """Split DN strings and parse them into RFC 4514 components."""

    @staticmethod
    def resolve_dn_value(dn: FlextLdifModels.Ldif.DN | str) -> str:
        """Extract DN string value from DN model or string (public utility method).

        Returns:
            The resulting ``str``.

        """
        if isinstance(dn, str):
            return dn
        return dn.value

    @overload
    @staticmethod
    def split(dn: str) -> MutableSequence[str]: ...

    @overload
    @staticmethod
    def split(dn: FlextLdifModels.Ldif.DN) -> MutableSequence[str]: ...

    @staticmethod
    def split(dn: str | FlextLdifModels.Ldif.DN) -> MutableSequence[str]:
        r"""Split DN string into individual RDN components per RFC 4514.

        RFC 4514 Section 2 ABNF:
        ========================
        distinguishedName = [ relativeDistinguishedName
                             *( COMMA relativeDistinguishedName ) ]
        COMMA = %x2C  ; comma (",")

        Properly handles escaped commas (\\\\,) and other special characters.
        Does NOT treat escaped commas as component separators.

        Returns:
            The resulting ``MutableSequence[str]``.

        """
        return list(
            FlextLdifUtilitiesEntry.dn_components(
                FlextLdifUtilitiesDNParse.resolve_dn_value(dn)
            )
        )

    @staticmethod
    def _parse_dn_components(dn_str: str) -> p.Result[t.MutableStrPairSequence]:
        """Parse already validated DN string components.

        Returns:
            The resulting ``p.Result[t.MutableStrPairSequence]``.

        """
        parsed_pairs: t.MutableStrPairSequence = []
        failure_message: str | None = None
        for component in FlextLdifUtilitiesDNParse.split(dn_str):
            parsed_component = FlextLdifUtilitiesDNRdn.parse_rdn(component)
            if parsed_component.failure:
                failure_message = str(parsed_component.error)
                break
            parsed_pairs.extend(parsed_component.value)
        if failure_message is None and parsed_pairs:
            return r[t.MutableStrPairSequence].ok(parsed_pairs)
        return r[t.MutableStrPairSequence].fail(
            failure_message or f"Failed to parse DN components from '{dn_str}'",
        )

    @overload
    @staticmethod
    def parse_dn(dn: str) -> p.Result[t.MutableStrPairSequence]: ...

    @overload
    @staticmethod
    def parse_dn(dn: FlextLdifModels.Ldif.DN) -> p.Result[t.MutableStrPairSequence]: ...

    @staticmethod
    def parse_dn(
        dn: str | FlextLdifModels.Ldif.DN | None,
    ) -> p.Result[t.MutableStrPairSequence]:
        """Parse DN into RFC 4514 components (attr, value pairs).

        Returns:
            The resulting ``p.Result[t.MutableStrPairSequence]``.

        """
        result: p.Result[t.MutableStrPairSequence] = r[t.MutableStrPairSequence].fail(
            "DN cannot be None",
        )
        if dn is not None:
            dn_str = FlextLdifUtilitiesDNParse.resolve_dn_value(dn)
            if not dn_str or "=" not in dn_str:
                error_msg = (
                    "DN string is empty"
                    if not dn_str
                    else f"Invalid DN format: missing '=' separator in '{dn_str}'"
                )
                result = r[t.MutableStrPairSequence].fail(error_msg)
            else:
                try:
                    result = FlextLdifUtilitiesDNParse._parse_dn_components(dn_str)
                except c.Ldif.EXC_LDIF_PARSE as e:
                    result = r[t.MutableStrPairSequence].fail(
                        f"DN parsing error: {e}",
                        exception=e,
                    )
        return result


__all__: list[str] = ["FlextLdifUtilitiesDNParse"]
