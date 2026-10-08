"""RFC 4514 DN normalization and comparison utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import overload

from flext_core import r
from flext_ldif import FlextLdifModels, c, p, t
from flext_ldif._utilities._dn_parse import FlextLdifDNParsing


class FlextLdifDNNormalization:
    """Normalize DNs per RFC 4514 and compare normalized pairs."""

    @overload
    @staticmethod
    def norm(dn: str) -> p.Result[str]: ...

    @overload
    @staticmethod
    def norm(dn: FlextLdifModels.Ldif.DN) -> p.Result[str]: ...

    @staticmethod
    def norm(dn: str | FlextLdifModels.Ldif.DN | None) -> p.Result[str]:
        """Normalize DN per RFC 4514 (lowercase attrs, preserve values).

        Returns:
            The resulting ``p.Result[str]``.
        """
        result: p.Result[str] = r[str].fail("DN cannot be None")
        if dn is not None:
            dn_str = FlextLdifDNParsing.resolve_dn_value(dn)
            if not dn_str or "=" not in dn_str:
                error_msg = (
                    "Failed to normalize DN: DN string is empty"
                    if not dn_str
                    else (
                        f"Failed to normalize DN: Invalid DN format: "
                        f"missing '=' separator in '{dn_str}'"
                    )
                )
                result = r[str].fail(error_msg)
            else:
                try:
                    normalized: t.MutableSequenceOf[str] = [
                        f"{attr.strip().lower()}={value.strip()}"
                        for component in FlextLdifDNParsing.split(dn_str)
                        if "=" in component
                        for attr, _, value in [component.partition("=")]
                    ]
                    result = (
                        r[str].ok(",".join(normalized))
                        if normalized
                        else r[str].fail(
                            f"Failed to normalize DN: "
                            f"no valid components in '{dn_str}'",
                        )
                    )
                except c.Ldif.EXC_LDIF_PARSE as e:
                    result = r[str].fail(f"DN normalization error: {e}", exception=e)
        return result

    @staticmethod
    def norm_or_fallback(
        dn: str | None,
        *,
        fallback: c.Ldif.NormalizeFallback = c.Ldif.NormalizeFallback.LOWER,
    ) -> str:
        r"""Normalize DN or return fallback if normalization fails.

        Replaces the common 3-line pattern:
            norm_result = FlextLdifUtilitiesDN.norm(dn)
            normalized = norm_result.value if norm_result.success else dn.lower()

        With a single call:
            normalized = FlextLdifUtilitiesDN.norm_or_fallback(dn)

        Args:
            dn: DN string to normalize (or None)
            fallback: Fallback strategy if normalization fails:
                - "lower": Return dn.lower()
                - "upper": Return dn.upper()
                - "original": Return dn unchanged

        Returns:
            Normalized DN string, or fallback if normalization fails

        Examples:
            >>> FlextLdifUtilitiesDN.norm_or_fallback("CN=Test,DC=Example")
            'cn=test,dc=example'
            >>> FlextLdifUtilitiesDN.norm_or_fallback(None)
            ''
            >>> FlextLdifUtilitiesDN.norm_or_fallback(
            ...     "invalid\\\\\\\\dn",
            ...     fallback="original",
            ... )
            'invalid\\\\\\\\dn'

        """
        if dn is None:
            return ""
        result = FlextLdifDNNormalization.norm(dn)
        if result.success:
            normalized_dn: str = result.value
            return normalized_dn
        if fallback == c.Ldif.NormalizeFallback.LOWER:
            return dn.lower()
        if fallback == c.Ldif.NormalizeFallback.UPPER:
            return dn.upper()
        return dn

    @staticmethod
    def _normalize_dns_for_comparison(dn1: str, dn2: str) -> p.Result[t.StrPair]:
        """Normalize both DNs for comparison.

        Returns:
            The resulting ``p.Result[t.StrPair]``.
        """
        norm1_result = FlextLdifDNNormalization.norm(dn1)
        if not norm1_result.success:
            return r[t.StrPair].fail(
                f"Comparison failed (RFC 4514): "
                f"Failed to normalize first DN: {norm1_result.error}",
            )
        norm2_result = FlextLdifDNNormalization.norm(dn2)
        if not norm2_result.success:
            return r[t.StrPair].fail(
                f"Comparison failed (RFC 4514): "
                f"Failed to normalize second DN: {norm2_result.error}",
            )
        return r[t.StrPair].ok((norm1_result.value.lower(), norm2_result.value.lower()))

    @staticmethod
    def _compare_dns_core(dn1: str | None, dn2: str | None) -> p.Result[int]:
        """Compare normalized DN pair.

        Returns:
            The resulting ``p.Result[int]``.
        """
        if not dn1 or not dn2:
            return r[int].fail("Both DNs must be provided for comparison")
        norm_result = FlextLdifDNNormalization._normalize_dns_for_comparison(dn1, dn2)
        if not norm_result.success:
            return r[int].fail(norm_result.error or "Normalization failed")
        normalized_pair = norm_result.value
        if len(normalized_pair) != c.Ldif.TUPLE_LENGTH_PAIR:
            return r[int].fail("Normalization returned unexpected DN pair")
        norm1_lower = normalized_pair[0]
        norm2_lower = normalized_pair[1]
        comparison = (norm1_lower > norm2_lower) - (norm1_lower < norm2_lower)
        return r[int].ok(comparison)

    @staticmethod
    def compare_dns(dn1: str | None, dn2: str | None) -> p.Result[int]:
        """Compare two DNs per RFC 4514 (case-insensitive).

        Returns:
            The resulting ``p.Result[int]``.
        """
        try:
            return FlextLdifDNNormalization._compare_dns_core(dn1, dn2)
        except c.Ldif.EXC_LDIF_PARSE as e:
            return r[int].fail(f"DN comparison error: {e}", exception=e)


__all__: list[str] = ["FlextLdifDNNormalization"]
