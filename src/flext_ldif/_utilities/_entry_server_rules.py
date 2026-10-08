"""LDIF entry server-rule validation utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, p, t
from flext_ldif._models import FlextLdifModelsSettings


class FlextLdifEntryServerRules:
    """Check server-specific validation rules against entries."""

    @staticmethod
    def check_binary_option_rule(
        entry: p.Ldif.EntryValidationSubject,
        rules: FlextLdifModelsSettings.ServerValidationRules,
    ) -> t.MutableSequenceOf[str]:
        """Check binary attribute option requirement from server rules.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        violations: t.MutableSequenceOf[str] = []
        if not rules.requires_binary_option or not entry.attributes:
            return violations
        for attr_name, attr_values in entry.attributes.items():
            if ";binary" in attr_name.lower():
                continue
            for value in attr_values:
                if any(
                    ord(char) < c.Ldif.ASCII_PRINTABLE_MIN
                    or ord(char) > c.Ldif.ASCII_PRINTABLE_MAX
                    for char in value
                ):
                    violations.append(
                        f"Server requires ';binary' option for '{attr_name}'",
                    )
                    break
        return violations

    @staticmethod
    def check_naming_attr_rule(
        entry: p.Ldif.EntryValidationSubject,
        rules: FlextLdifModelsSettings.ServerValidationRules,
        dn_value: str,
    ) -> t.MutableSequenceOf[str]:
        """Check naming attribute requirement from server rules.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        violations: t.MutableSequenceOf[str] = []
        if not rules.requires_naming_attr or not dn_value or (not entry.attributes):
            return violations
        first_rdn = dn_value.split(",", maxsplit=1)[0].strip()
        if "=" not in first_rdn:
            return violations
        naming_attr = first_rdn.split("=")[0].strip().lower()
        has_naming_attr = any(
            attr_name.lower() == naming_attr
            for attr_name in entry.attributes.attributes
        )
        if not has_naming_attr:
            violations.append(f"Server requires naming attribute '{naming_attr}'")
        return violations

    @staticmethod
    def check_objectclass_rule(
        entry: p.Ldif.EntryValidationSubject,
        rules: FlextLdifModelsSettings.ServerValidationRules,
        dn_value: str,
    ) -> t.MutableSequenceOf[str]:
        """Check objectClass requirement from server rules.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        violations: t.MutableSequenceOf[str] = []
        if not rules.requires_objectclass:
            return violations
        has_objectclass = (
            any(
                attr_name.lower() == c.Ldif.DictKeys.OBJECTCLASS.lower()
                for attr_name in entry.attributes.attributes
            )
            if entry.attributes
            else False
        )
        dn_value_lower = dn_value.lower()
        is_schema_entry = dn_value and any(
            dn_value_lower.startswith(marker) for marker in c.Ldif.SCHEMA_DN_MARKERS
        )
        if not has_objectclass and (not is_schema_entry):
            violations.append("Server requires objectClass attribute")
        return violations

    @staticmethod
    def parse_validation_rules(
        validation_rules: FlextLdifModelsSettings.ServerValidationRules
        | str
        | t.JsonMapping
        | None,
    ) -> FlextLdifModelsSettings.ServerValidationRules | None:
        """Normalize dynamic validation_rules payload to ServerValidationRules.

        Returns:
            The resulting ``FlextLdifModelsSettings.ServerValidationRules | None``.
        """
        if isinstance(validation_rules, FlextLdifModelsSettings.ServerValidationRules):
            return validation_rules
        if isinstance(validation_rules, str):
            return FlextLdifModelsSettings.ServerValidationRules.model_validate_json(
                validation_rules,
            )
        if validation_rules is not None:
            return FlextLdifModelsSettings.ServerValidationRules.model_validate(
                validation_rules,
            )
        return None


__all__: list[str] = ["FlextLdifEntryServerRules"]
