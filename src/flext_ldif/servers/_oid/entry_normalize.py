"""Oracle Internet Directory (OID) entry server — schema value normalization helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._oid.server_constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOidEntryNormalizeMixin(FlextLdifServersRfc.Entry):
    """OID entry schema value normalization helpers."""

    @staticmethod
    def _normalize_schema_values(attrs: t.MutableStrSequenceMapping) -> None:
        """Normalize OID matching rules and syntax OIDs in schema definition strings.

        Applies MATCHING_RULE_TO_RFC and SYNTAX_OID_TO_RFC conversions to the raw
        attributeTypes/objectClasses/matchingRules value strings. Handles context-aware
        replacement: ``caseIgnoreSubStringsMatch`` in EQUALITY context is replaced with
        ``caseIgnoreMatch`` (not a substring matching rule), while in SUBSTR context it
        becomes ``caseIgnoreSubstringsMatch`` (lowercase 's').
        """
        equality_map: t.MappingKV[str, str] = {
            "caseIgnoreSubStringsMatch": "caseIgnoreMatch",
            "caseIgnoreSubstringsMatch": "caseIgnoreMatch",
        }
        substr_map = FlextLdifServersOidConstants.MATCHING_RULE_TO_RFC
        syntax_map = FlextLdifServersOidConstants.SYNTAX_OID_TO_RFC
        schema_fields = {"attributetypes", "objectclasses", "matchingrules"}
        for attr_name in list(attrs):
            if attr_name.lower() not in schema_fields:
                continue
            values = attrs[attr_name]
            updated: list[str] = []
            changed = False
            for value in values:
                new_value = value
                for oid_rule, rfc_rule in equality_map.items():
                    eq_token = f"EQUALITY {oid_rule}"
                    if eq_token in new_value:
                        new_value = new_value.replace(eq_token, f"EQUALITY {rfc_rule}")
                        changed = True
                for oid_rule, rfc_rule in substr_map.items():
                    substr_token = f"SUBSTR {oid_rule}"
                    if substr_token in new_value:
                        new_value = new_value.replace(
                            substr_token,
                            f"SUBSTR {rfc_rule}",
                        )
                        changed = True
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
                if attr_name.lower() in {"objectclasses", "attributetypes"}:
                    sup_quoted = c.Ldif.sub_pattern(
                        r"SUP\s+'([^']+)'",
                        r"SUP \1",
                        new_value,
                    )
                    if sup_quoted != new_value:
                        new_value = sup_quoted
                        changed = True
                updated.append(new_value)
            if changed:
                attrs[attr_name] = updated


__all__: list[str] = ["FlextLdifServersOidEntryNormalizeMixin"]
