"""Entry quirks module for LDIF processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast, override

from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.manager import FlextLdifQuirksManager
from flext_ldif.typings import FlextLdifTypes


class FlextLdifEntryQuirks(FlextService[dict[str, object]]):
    """Entry adaptation and validation for server-specific quirks."""

    @override
    def __init__(self, quirks_manager: FlextLdifQuirksManager | None = None) -> None:
        """Initialize entry quirks handler.

        Args:
            quirks_manager: Quirks manager for server-specific rules

        """
        super().__init__()
        self._quirks = quirks_manager or FlextLdifQuirksManager()

    @override
    def execute(self: object) -> FlextResult[dict[str, object]]:
        """Execute entry quirks service."""
        return FlextResult[dict[str, object]].ok({
            "service": FlextLdifEntryQuirks,
            "status": "ready",
        })

    def adapt_entry(
        self, entry: FlextLdifModels.Entry, target_server: str | None = None
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Adapt entry for specific server type.

        Args:
            entry: Entry to adapt
            target_server: Target server type

        Returns:
            FlextResult containing adapted entry

        """
        quirks_result: FlextResult[dict[str, object]] = self._quirks.get_server_quirks(
            target_server
        )
        if quirks_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                quirks_result.error or "Failed to get server quirks"
            )

        rules = quirks_result.value

        # Create adapted entry data - FlextResult handles errors explicitly
        adapted_data: dict[str, object] = {"dn": entry.dn.value, "attributes": {}}

        attribute_mappings_raw = rules.get("attribute_mappings", {})
        attribute_mappings = cast("FlextLdifTypes.StringDict", attribute_mappings_raw)
        adapted_attrs: dict[str, FlextLdifModels.AttributeValues] = {}

        for attr_name, attr_values in entry.attributes.data.items():
            mapped_name = attribute_mappings.get(attr_name, attr_name)

            adapted_values = self._adapt_attribute_values(
                attr_name,
                attr_values,
                target_server or FlextLdifConstants.LdapServers.GENERIC,
            )

            adapted_attrs[mapped_name] = FlextLdifModels.AttributeValues(
                values=adapted_values
            )

        adapted_data["attributes"] = adapted_attrs

        # Create adapted entry - FlextResult pattern with explicit error handling
        adapted_entry_result: FlextResult[FlextLdifModels.Entry] = (
            FlextLdifModels.Entry.create(
                dn=adapted_data["dn"], attributes=adapted_data["attributes"]
            )
        )
        if adapted_entry_result.is_failure:
            error_msg = f"Failed to create adapted entry: {adapted_entry_result.error}"
            if self.logger is not None:
                self.logger.error(error_msg)  # type: ignore[attr-defined]
            return FlextResult[FlextLdifModels.Entry].fail(error_msg)

        return adapted_entry_result

    def _adapt_attribute_values(
        self, attr_name: str, attr_values: FlextLdifTypes.StringList, server_type: str
    ) -> FlextLdifTypes.StringList:
        """Adapt attribute values for specific server type.

        Args:
            attr_name: Attribute name
            attr_values: Original attribute values
            server_type: Target server type

        Returns:
            Adapted attribute values

        """
        adapted_values = attr_values.copy()

        quirks_result: FlextResult[dict[str, object]] = self._quirks.get_server_quirks(
            server_type
        )
        if quirks_result.is_failure:
            return adapted_values

        rules = quirks_result.value

        if attr_name.lower() == "objectclass":
            required_classes_raw = rules.get("required_object_classes", [])
            required_classes = cast("FlextLdifTypes.StringList", required_classes_raw)
            for required_class in required_classes:
                if required_class not in adapted_values:
                    adapted_values.append(required_class)

        elif (
            server_type == FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
            and attr_name.lower()
            in {
                "userprincipalname",
                "samaccountname",
            }
        ):
            adapted_values = [val.lower() for val in adapted_values]

        return adapted_values

    def validate_entry(
        self, entry: FlextLdifModels.Entry, server_type: str | None = None
    ) -> FlextResult[dict[str, object]]:
        """Validate entry compliance with server-specific rules.

        Args:
            entry: Entry to validate
            server_type: Server type to validate against

        Returns:
            FlextResult containing validation report

        """
        quirks_result: FlextResult[dict[str, object]] = self._quirks.get_server_quirks(
            server_type
        )
        if quirks_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                quirks_result.error or "Failed to get server quirks"
            )

        rules = quirks_result.value
        validation_report: dict[str, object] = {
            "server_type": server_type or FlextLdifConstants.LdapServers.GENERIC,
            "compliant": True,
            "issues": [],
            "warnings": [],
        }

        issues: FlextLdifTypes.StringList = []
        warnings: FlextLdifTypes.StringList = []

        dn_validation = self._validate_dn_format(
            entry.dn.value, server_type or FlextLdifConstants.LdapServers.GENERIC
        )
        if not dn_validation["valid"]:
            dn_issues = dn_validation["issues"]
            if isinstance(dn_issues, list):
                issues.extend(dn_issues)

        obj_classes_raw: object = entry.get_attribute("objectClass") or []
        obj_classes: FlextLdifTypes.StringList = (
            obj_classes_raw if isinstance(obj_classes_raw, list) else []
        )
        required_classes_raw = rules.get("required_object_classes", [])
        required_classes: FlextLdifTypes.StringList = cast(
            "FlextLdifTypes.StringList", required_classes_raw
        )

        issues.extend(
            f"Missing required object class: {required_class}"
            for required_class in required_classes
            if required_class not in obj_classes
        )

        special_attrs_raw = rules.get("special_attributes", [])
        special_attrs: FlextLdifTypes.StringList = cast(
            "FlextLdifTypes.StringList", special_attrs_raw
        )
        warnings.extend(
            f"Missing recommended attribute: {special_attr}"
            for special_attr in special_attrs
            if not entry.has_attribute(special_attr)
        )

        validation_report["issues"] = issues
        validation_report["warnings"] = warnings
        validation_report["compliant"] = len(issues) == 0

        return FlextResult[dict[str, object]].ok(validation_report)

    def _validate_dn_format(self, dn: str, server_type: str) -> dict[str, object]:
        """Validate DN format for specific server type.

        Args:
            dn: DN to validate
            server_type: Server type to validate against

        Returns:
            Validation result dictionary

        """
        quirks_result: FlextResult[dict[str, object]] = self._quirks.get_server_quirks(
            server_type
        )
        if quirks_result.is_failure:
            return {"valid": True, "issues": []}

        rules = quirks_result.value
        dn_patterns_raw = rules.get("dn_patterns", [])
        dn_patterns: FlextLdifTypes.StringList = (
            cast("FlextLdifTypes.StringList", dn_patterns_raw)
            if isinstance(dn_patterns_raw, list)
            else []
        )
        case_sensitive_raw = rules.get("dn_case_sensitive", False)
        case_sensitive = cast("bool", case_sensitive_raw)

        issues: FlextLdifTypes.StringList = []

        # Use DistinguishedName Model for DN parsing
        try:
            dn_model = FlextLdifModels.DistinguishedName(value=dn)
            components = dn_model.components
        except ValueError as e:
            issues.append(f"Invalid DN format: {e}")
            return {"valid": False, "issues": issues}

        for component in components:
            if "=" not in component:
                issues.append(f"Invalid DN component format: {component}")
                continue

            attr_name = component.split("=")[0].strip()

            if not case_sensitive:
                attr_name_lower = attr_name.lower()
                matching_patterns = [
                    p
                    for p in dn_patterns
                    if isinstance(p, str) and p.lower() == attr_name_lower
                ]
            else:
                matching_patterns = [p for p in dn_patterns if p == attr_name]

            if dn_patterns and not matching_patterns:
                issues.append(f"Unknown DN attribute for {server_type}: {attr_name}")

        return {"valid": len(issues) == 0, "issues": issues}


__all__ = ["FlextLdifEntryQuirks"]
