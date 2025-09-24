"""LDAP Entry Quirks Handler.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from typing import cast

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks import constants
from flext_ldif.quirks.manager import FlextLdifQuirksManager


class FlextLdifEntryQuirks(FlextService[dict[str, object]]):
    """Entry adaptation and validation for server-specific quirks."""

    def __init__(self, quirks_manager: FlextLdifQuirksManager | None = None) -> None:
        """Initialize entry quirks handler.

        Args:
            quirks_manager: Quirks manager for server-specific rules

        """
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._quirks = quirks_manager or FlextLdifQuirksManager()

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute entry quirks service."""
        return FlextResult[dict[str, object]].ok({
            "service": "FlextLdifEntryQuirks",
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
        quirks_result = self._quirks.get_server_quirks(target_server)
        if quirks_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(
                quirks_result.error or "Failed to get server quirks"
            )

        rules = quirks_result.value

        try:
            adapted_data: dict[str, object] = {"dn": entry.dn.value, "attributes": {}}

            attribute_mappings = cast(
                "dict[str, str]", rules.get("attribute_mappings", {})
            )
            adapted_attrs: dict[str, list[str]] = {}

            for attr_name, attr_values in entry.attributes.data.items():
                mapped_name = attribute_mappings.get(attr_name, attr_name)

                adapted_values = self._adapt_attribute_values(
                    attr_name, attr_values, target_server or constants.SERVER_TYPE_GENERIC
                )

                adapted_attrs[mapped_name] = adapted_values

            adapted_data["attributes"] = adapted_attrs

            adapted_entry_result = FlextLdifModels.Entry.create(adapted_data)
            if adapted_entry_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create adapted entry: {adapted_entry_result.error}"
                )

            return FlextResult[FlextLdifModels.Entry].ok(adapted_entry_result.value)

        except Exception as e:
            error_msg = f"Entry adaptation failed: {e}"
            self._logger.exception(error_msg)
            return FlextResult[FlextLdifModels.Entry].fail(error_msg)

    def _adapt_attribute_values(
        self, attr_name: str, attr_values: list[str], server_type: str
    ) -> list[str]:
        """Adapt attribute values for specific server type.

        Args:
            attr_name: Attribute name
            attr_values: Original attribute values
            server_type: Target server type

        Returns:
            Adapted attribute values

        """
        adapted_values = attr_values.copy()

        quirks_result = self._quirks.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return adapted_values

        rules = quirks_result.value

        if attr_name.lower() == "objectclass":
            required_classes = cast(
                "list[str]", rules.get("required_object_classes", [])
            )
            for required_class in required_classes:
                if required_class not in adapted_values:
                    adapted_values.append(required_class)

        elif server_type == constants.SERVER_TYPE_ACTIVE_DIRECTORY and attr_name.lower() in {
            "userprincipalname",
            "samaccountname",
        }:
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
        quirks_result = self._quirks.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                quirks_result.error or "Failed to get server quirks"
            )

        rules = quirks_result.value
        validation_report: dict[str, object] = {
            "server_type": server_type or constants.SERVER_TYPE_GENERIC,
            "compliant": True,
            "issues": [],
            "warnings": [],
        }

        issues: list[str] = []
        warnings: list[str] = []

        dn_validation = self._validate_dn_format(
            entry.dn.value, server_type or constants.SERVER_TYPE_GENERIC
        )
        if not dn_validation["valid"]:
            dn_issues = dn_validation["issues"]
            if isinstance(dn_issues, list):
                issues.extend(dn_issues)

        obj_classes = entry.get_attribute("objectClass") or []
        required_classes = cast("list[str]", rules.get("required_object_classes", []))

        issues.extend(
            f"Missing required object class: {required_class}"
            for required_class in required_classes
            if required_class not in obj_classes
        )

        special_attrs = cast("list[str]", rules.get("special_attributes", []))
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
        quirks_result = self._quirks.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return {"valid": True, "issues": []}

        rules = quirks_result.value
        dn_patterns = cast("list[str]", rules.get("dn_patterns", []))
        case_sensitive = cast("bool", rules.get("dn_case_sensitive", False))

        issues: list[str] = []

        components = [comp.strip() for comp in dn.split(",")]
        for component in components:
            if "=" not in component:
                issues.append(f"Invalid DN component format: {component}")
                continue

            attr_name = component.split("=")[0].strip()

            if not case_sensitive:
                attr_name_lower = attr_name.lower()
                matching_patterns = [
                    p for p in dn_patterns if p.lower() == attr_name_lower
                ]
            else:
                matching_patterns = [p for p in dn_patterns if p == attr_name]

            if dn_patterns and not matching_patterns:
                issues.append(f"Unknown DN attribute for {server_type}: {attr_name}")

        return {"valid": len(issues) == 0, "issues": issues}


__all__ = ["FlextLdifEntryQuirks"]
