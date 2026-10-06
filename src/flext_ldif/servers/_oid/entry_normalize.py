"""Oracle Internet Directory (OID) entry server — schema value normalization helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, t
from flext_ldif.servers._oid.server_constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOidEntryNormalizeMixin(FlextLdifServersRfc.Entry):
    """OID entry schema value normalization helpers."""

    @staticmethod
    def _apply_matching_rule_tokens(
        value: str,
        token_map: t.MappingKV[str, str],
        prefix: str,
    ) -> tuple[str, bool]:
        """Replace ``<PREFIX> <oid>`` tokens with their RFC rule names.

        Returns:
            The resulting ``tuple[str, bool]``.
        """
        new_value = value
        changed = False
        for oid_rule, rfc_rule in token_map.items():
            token = f"{prefix} {oid_rule}"
            if token in new_value:
                new_value = new_value.replace(token, f"{prefix} {rfc_rule}")
                changed = True
        return (new_value, changed)

    @staticmethod
    def _apply_syntax_tokens(
        value: str,
        syntax_map: t.MappingKV[str, str],
    ) -> tuple[str, bool]:
        """Replace quoted or space-delimited syntax OIDs with RFC names.

        Returns:
            The resulting ``tuple[str, bool]``.
        """
        new_value = value
        changed = False
        for oid_syntax, rfc_syntax in syntax_map.items():
            token = f"'{oid_syntax}'"
            replacement = f"'{rfc_syntax}'"
            if token in new_value:
                new_value = new_value.replace(token, replacement)
                changed = True
            elif f" {oid_syntax} " in new_value:
                new_value = new_value.replace(
                    f" {oid_syntax} ",
                    f" {rfc_syntax} ",
                )
                changed = True
        return (new_value, changed)

    @staticmethod
    def _unquote_sup_value(value: str) -> tuple[str, bool]:
        """Unquote ``SUP '<oid>'`` tokens in schema definition strings.

        Returns:
            The resulting ``tuple[str, bool]``.
        """
        sup_quoted = c.Ldif.compile_pattern(r"SUP\s+'([^']+)'", ignorecase=False).sub(
            r"SUP \1",
            value,
        )
        if sup_quoted != value:
            return (sup_quoted, True)
        return (value, False)

    @staticmethod
    def _normalize_schema_value(value: str, attr_name_lower: str) -> str:
        """Apply all OID→RFC replacements to one schema definition value.

        Returns:
            The resulting ``str``.
        """
        equality_map: t.MappingKV[str, str] = {
            "caseIgnoreSubStringsMatch": "caseIgnoreMatch",
            "caseIgnoreSubstringsMatch": "caseIgnoreMatch",
        }
        mixin = FlextLdifServersOidEntryNormalizeMixin
        new_value, _ = mixin._apply_matching_rule_tokens(
            value,
            equality_map,
            "EQUALITY",
        )
        new_value, _ = mixin._apply_matching_rule_tokens(
            new_value,
            FlextLdifServersOidConstants.MATCHING_RULE_TO_RFC,
            "SUBSTR",
        )
        new_value, _ = mixin._apply_syntax_tokens(
            new_value,
            FlextLdifServersOidConstants.SYNTAX_OID_TO_RFC,
        )
        if attr_name_lower in {"objectclasses", "attributetypes"}:
            new_value, _ = mixin._unquote_sup_value(new_value)
        return new_value

    @staticmethod
    def _normalize_schema_values(attrs: t.MutableStrSequenceMapping) -> None:
        """Normalize OID matching rules and syntax OIDs in schema definition strings.

        Applies MATCHING_RULE_TO_RFC and SYNTAX_OID_TO_RFC conversions to the raw
        attributeTypes/objectClasses/matchingRules value strings. Handles context-aware
        replacement: ``caseIgnoreSubStringsMatch`` in EQUALITY context is replaced with
        ``caseIgnoreMatch`` (not a substring matching rule), while in SUBSTR context it
        becomes ``caseIgnoreSubstringsMatch`` (lowercase 's').
        """
        schema_fields = {"attributetypes", "objectclasses", "matchingrules"}
        for attr_name in list(attrs):
            if attr_name.lower() not in schema_fields:
                continue
            values = attrs[attr_name]
            updated: list[str] = [
                FlextLdifServersOidEntryNormalizeMixin._normalize_schema_value(
                    value,
                    attr_name.lower(),
                )
                for value in values
            ]
            if updated != values:
                attrs[attr_name] = updated


__all__: list[str] = ["FlextLdifServersOidEntryNormalizeMixin"]
