"""LDIF DN cleaning and transformation-statistics utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, overload

from flext_ldif import FlextLdifModels, c, t

if TYPE_CHECKING:
    from collections.abc import MutableMapping


class FlextLdifDNCleaning:
    """Clean DN strings and track transformation statistics."""

    @staticmethod
    def _apply_dn_transformations(
        original_dn: str,
    ) -> tuple[
        str,
        t.MutableSequenceOf[str],
        MutableMapping[str, bool | str | t.MutableSequenceOf[str]],
    ]:
        """Apply DN transformations and collect flags.

        Returns:
            The resulting ``tuple[str, t.MutableSequenceOf[str], MutableMapping[str,
                bool | str | t.MutableSequenceOf[str]]]``.
        """
        transformations: t.MutableSequenceOf[str] = []
        empty_warnings: t.MutableSequenceOf[str] = []
        empty_errors: t.MutableSequenceOf[str] = []
        flags: MutableMapping[str, bool | str | t.MutableSequenceOf[str]] = {
            "had_tab_chars": False,
            "had_trailing_spaces": False,
            "had_leading_spaces": False,
            "had_extra_spaces": False,
            "was_base64_encoded": False,
            "had_utf8_chars": False,
            "had_escape_sequences": False,
            "validation_status": "",
            "validation_warnings": empty_warnings,
            "validation_errors": empty_errors,
        }
        result = original_dn
        transform_rules: t.MutableSequenceOf[tuple[str, str, str, str, str]] = [
            (
                "[\\t\\r\\n\\x0b\\x0c]",
                "[\\t\\r\\n\\x0b\\x0c]",
                " ",
                c.Ldif.TransformationType.TAB_NORMALIZED,
                "had_tab_chars",
            ),
            (
                "\\s+=",
                "\\s+=",
                "=",
                c.Ldif.TransformationType.SPACE_CLEANED,
                "had_leading_spaces",
            ),
            (
                "\\s+,",
                "\\s+,",
                ",",
                c.Ldif.TransformationType.SPACE_CLEANED,
                "had_trailing_spaces",
            ),
            (
                c.Ldif.DN_TRAILING_BACKSLASH_SPACE,
                c.Ldif.DN_TRAILING_BACKSLASH_SPACE,
                c.Ldif.DN_COMMA,
                c.Ldif.TransformationType.ESCAPE_NORMALIZED,
                "had_escape_sequences",
            ),
            (
                c.Ldif.DN_SPACES_AROUND_COMMA,
                c.Ldif.DN_SPACES_AROUND_COMMA,
                c.Ldif.DN_COMMA,
                c.Ldif.TransformationType.SPACE_CLEANED,
                "",
            ),
            (
                c.Ldif.DN_UNNECESSARY_ESCAPES,
                c.Ldif.DN_UNNECESSARY_ESCAPES,
                "\\1",
                c.Ldif.TransformationType.ESCAPE_NORMALIZED,
                "",
            ),
            (
                c.Ldif.DN_MULTIPLE_SPACES,
                c.Ldif.DN_MULTIPLE_SPACES,
                " ",
                c.Ldif.TransformationType.SPACE_CLEANED,
                "had_extra_spaces",
            ),
        ]
        for (
            detect_pattern,
            replace_pattern,
            replacement,
            transform_type,
            flag_name,
        ) in transform_rules:
            if c.Ldif.compile_pattern(detect_pattern).search(result):
                result = c.Ldif.compile_pattern(replace_pattern).sub(
                    replacement,
                    result,
                )
                transformations.append(transform_type)
                if flag_name:
                    flags[flag_name] = True
        return (result, transformations, flags)

    @staticmethod
    def _statistics_from_flags(
        original_dn: str,
        result: str,
        transformations: t.MutableSequenceOf[str],
        flags: MutableMapping[str, bool | str | t.MutableSequenceOf[str]],
    ) -> FlextLdifModels.Ldif.DNStatistics:
        """Build the DNStatistics model from transformation flags.

        Returns:
            The resulting ``FlextLdifModels.Ldif.DNStatistics``.
        """
        validation_status_raw = flags.get("validation_status", "")
        validation_status: str = (
            validation_status_raw if isinstance(validation_status_raw, str) else ""
        )
        validation_warnings_raw = flags.get("validation_warnings", [])
        validation_warnings: t.MutableSequenceOf[str] = (
            list(validation_warnings_raw)
            if isinstance(validation_warnings_raw, list)
            else []
        )
        validation_errors_raw = flags.get("validation_errors", [])
        validation_errors: t.MutableSequenceOf[str] = (
            list(validation_errors_raw)
            if isinstance(validation_errors_raw, list)
            else []
        )
        return FlextLdifModels.Ldif.DNStatistics(
            original_dn=original_dn,
            cleaned_dn=result,
            normalized_dn=result,
            transformations=transformations,
            had_tab_chars=bool(flags.get("had_tab_chars", False)),
            had_trailing_spaces=bool(flags.get("had_trailing_spaces", False)),
            had_leading_spaces=bool(flags.get("had_leading_spaces", False)),
            had_extra_spaces=bool(flags.get("had_extra_spaces", False)),
            was_base64_encoded=bool(flags.get("was_base64_encoded", False)),
            had_utf8_chars=bool(flags.get("had_utf8_chars", False)),
            had_escape_sequences=bool(flags.get("had_escape_sequences", False)),
            validation_status=validation_status,
            validation_warnings=validation_warnings,
            validation_errors=validation_errors,
        )

    @overload
    @staticmethod
    def clean_dn(dn: str) -> str: ...

    @overload
    @staticmethod
    def clean_dn(dn: FlextLdifModels.Ldif.DN) -> str: ...

    @staticmethod
    def clean_dn(dn: str | FlextLdifModels.Ldif.DN) -> str:
        """Clean DN string to fix spacing and escaping issues.

        Returns:
            The resulting ``str``.
        """
        from flext_ldif._utilities import FlextLdifDNParsing

        dn_str = FlextLdifDNParsing.resolve_dn_value(dn)
        if not dn_str:
            return dn_str
        patterns = [
            ("[\\t\\r\\n\\x0b\\x0c]", " "),
            ("\\s+=", "="),
            (c.Ldif.DN_TRAILING_BACKSLASH_SPACE, c.Ldif.DN_COMMA),
            ("\\s+,", ","),
            (c.Ldif.DN_SPACES_AROUND_COMMA, c.Ldif.DN_COMMA),
            (c.Ldif.DN_UNNECESSARY_ESCAPES, "\\1"),
            (c.Ldif.DN_MULTIPLE_SPACES, " "),
        ]
        try:
            result = dn_str
            for pattern, replacement in patterns:
                result = c.Ldif.compile_pattern(pattern).sub(replacement, result)
        except c.Ldif.EXC_LDIF_PARSE:
            return dn_str
        else:
            return result

    @staticmethod
    def clean_dn_with_statistics(
        dn: str,
    ) -> tuple[str, FlextLdifModels.Ldif.DNStatistics]:
        r"""Clean DN and track all transformations with statistics.

        Returns both cleaned DN and complete transformation history
        for diagnostic and audit purposes.

        Args:
            dn: DN string or DN t.JsonValue

        Returns:
            Tuple of (cleaned_dn, DNStatistics with transformation history)

        Example:
            cleaned_dn, stats = FlextLdifUtilitiesDN.clean_dn_with_statistics(
                "cn=test  ,\\tdc=example,dc=com"
            )

        """
        from flext_ldif._utilities import FlextLdifDNParsing

        original_dn = FlextLdifDNParsing.resolve_dn_value(dn)
        if not original_dn:
            stats_domain = FlextLdifModels.Ldif.DNStatistics.create_minimal(original_dn)
            stats = FlextLdifModels.Ldif.DNStatistics.model_validate(
                stats_domain.model_dump(),
            )
            return (original_dn, stats)
        result, transformations, flags = FlextLdifDNCleaning._apply_dn_transformations(
            original_dn,
        )
        stats_domain = FlextLdifDNCleaning._statistics_from_flags(
            original_dn,
            result,
            transformations,
            flags,
        )
        return (result, stats_domain)


__all__: list[str] = ["FlextLdifDNCleaning"]
