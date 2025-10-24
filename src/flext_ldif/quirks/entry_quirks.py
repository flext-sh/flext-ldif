"""Entry quirks module for LDIF processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import override

from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.dn_service import FlextLdifDnService
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.manager import FlextLdifQuirksManager


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
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute entry quirks service."""
        return FlextResult[dict[str, object]].ok({
            "service": FlextLdifEntryQuirks,
            "status": "ready",
        })

    def clean_dn(self, dn: str) -> str:
        """Clean a DN string before it's processed.

        This acts as a hook for server-specific quirks to fix common
        formatting issues in DNs from specific LDAP server exports.

        Fixes applied:
        - Removes spaces around '=' in RDN components (e.g., "cn = value" -> "cn=value")
        - Fixes malformed backslash escapes
        - Normalizes whitespace

        Args:
            dn: The original DN string from the LDIF file.

        Returns:
            The cleaned DN string.

        """
        # Use DN utils for proper RFC 4514 compliant cleaning
        return FlextLdifDnService.clean_dn(dn)

    def adapt_entry(
        self, entry: FlextLdifModels.Entry, target_server: str | None = None
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Adapt entry for specific server type.

        Performs the following adaptations:
        1. Strip operational attributes from source server
        2. Apply attribute name mappings
        3. Transform attribute values
        4. Add required objectClasses

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

        # Get operational attributes for SOURCE server (from quirks manager)
        # We strip operational attrs from source, not add them for target
        source_server = self._quirks.server_type
        operational_attrs = self._get_operational_attrs(source_server)

        # Create adapted entry data - FlextResult handles errors explicitly
        adapted_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: entry.dn,  # Keep as DistinguishedName object
            FlextLdifConstants.DictKeys.ATTRIBUTES: {},
        }

        # Type narrow attribute_mappings
        attribute_mappings_raw = rules.get("attribute_mappings", {})
        if not isinstance(attribute_mappings_raw, dict):
            return FlextResult[FlextLdifModels.Entry].fail(
                f"attribute_mappings must be dict, got {type(attribute_mappings_raw).__name__}"
            )
        attribute_mappings: dict[str, str] = attribute_mappings_raw
        adapted_attrs: dict[str, FlextLdifModels.AttributeValues] = {}

        # Strip operational attributes FIRST, then apply transformations
        operational_attrs_lower = {attr.lower() for attr in operational_attrs}

        for attr_name, attr_values in entry.attributes.attributes.items():
            # Skip operational attributes (case-insensitive check)
            if attr_name.lower() in operational_attrs_lower:
                if self.logger is not None:
                    self.logger.debug(
                        f"Stripped operational attribute '{attr_name}' from {entry.dn.value}"
                    )
                continue

            # Apply attribute name mapping
            mapped_name = attribute_mappings.get(attr_name, attr_name) or attr_name

            # Transform attribute values
            adapted_values = self._adapt_attribute_values(
                attr_name,
                attr_values.values,
                target_server or FlextLdifConstants.LdapServers.GENERIC,
            )

            adapted_attrs[mapped_name] = FlextLdifModels.AttributeValues(
                values=adapted_values
            )

        # Convert adapted_attrs to LdifAttributes (Entry.create needs proper format)
        ldif_attributes = FlextLdifModels.LdifAttributes(attributes=adapted_attrs)

        # Type narrowing: Extract DN with proper type (stored on line 77 as DistinguishedName)
        dn_value: object = adapted_data[FlextLdifConstants.DictKeys.DN]
        if not isinstance(dn_value, (FlextLdifModels.DistinguishedName, str)):
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Invalid DN type in adapted_data: {type(dn_value).__name__}"
            )
        # Type narrowed: dn_value is now FlextLdifModels.DistinguishedName | str
        adapted_dn: FlextLdifModels.DistinguishedName | str = dn_value

        # Create adapted entry - FlextResult pattern with explicit error handling
        adapted_entry_result: FlextResult[FlextLdifModels.Entry] = (
            FlextLdifModels.Entry.create(
                dn=adapted_dn,
                attributes=ldif_attributes,
            )
        )
        if adapted_entry_result.is_failure:
            error_msg = f"Failed to create adapted entry: {adapted_entry_result.error}"
            if self.logger is not None:
                self.logger.error(error_msg)
            return FlextResult[FlextLdifModels.Entry].fail(error_msg)

        return adapted_entry_result

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

        quirks_result: FlextResult[dict[str, object]] = self._quirks.get_server_quirks(
            server_type
        )
        if quirks_result.is_failure:
            return adapted_values

        rules = quirks_result.value

        if attr_name.lower() == FlextLdifConstants.DictKeys.OBJECTCLASS:
            required_classes_raw = rules.get("required_object_classes", [])
            # Type narrow with default for non-list types
            required_classes: list[str] = (
                required_classes_raw if isinstance(required_classes_raw, list) else []
            )
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

        issues: list[str] = []
        warnings: list[str] = []

        dn_validation = self._validate_dn_format(
            entry.dn.value, server_type or FlextLdifConstants.LdapServers.GENERIC
        )
        if not dn_validation["valid"]:
            dn_issues = dn_validation["issues"]
            if isinstance(dn_issues, list):
                issues.extend(dn_issues)

        obj_classes_raw: object = entry.get_attribute_values(
            FlextLdifConstants.DictKeys.OBJECTCLASS
        )
        obj_classes: list[str] = (
            obj_classes_raw if isinstance(obj_classes_raw, list) else []
        )
        # Type narrow with default for non-list types
        required_classes_raw = rules.get("required_object_classes", [])
        required_classes: list[str] = (
            required_classes_raw if isinstance(required_classes_raw, list) else []
        )

        issues.extend(
            f"Missing required object class: {required_class}"
            for required_class in required_classes
            if required_class not in obj_classes
        )

        # Type narrow with default for non-list types
        special_attrs_raw = rules.get("special_attributes", [])
        special_attrs: list[str] = (
            special_attrs_raw if isinstance(special_attrs_raw, list) else []
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

        # Type narrow with default for non-list types
        dn_patterns_raw = rules.get("dn_patterns", [])
        dn_patterns: list[str] = (
            dn_patterns_raw if isinstance(dn_patterns_raw, list) else []
        )

        # Type narrow with default for non-bool types
        case_sensitive_raw = rules.get("dn_case_sensitive", False)
        case_sensitive: bool = (
            case_sensitive_raw if isinstance(case_sensitive_raw, bool) else False
        )

        issues: list[str] = []

        # Use DistinguishedName Model for DN parsing
        try:
            dn_model = FlextLdifModels.DistinguishedName(value=dn)
            # components is a computed_field that returns list[str]
            # Call it directly to get the actual list
            dn_components_value = dn_model.components
            # Ensure it's a list, not a callable
            if callable(dn_components_value):
                dn_components = dn_components_value()
            else:
                dn_components = dn_components_value
        except ValueError as e:
            issues.append(f"Invalid DN format: {e}")
            return {"valid": False, "issues": issues}

        for component in dn_components:
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

    def _get_operational_attrs(self, server_type: str) -> list[str]:
        """Get operational attributes for specific server type.

        Combines COMMON operational attributes with server-specific ones.

        Args:
        server_type: Source LDAP server type (case-insensitive)

        Returns:
        List of operational attribute names to strip

        """
        # Start with common operational attributes
        operational_attrs = set(FlextLdifConstants.OperationalAttributes.COMMON)

        # Normalize server type for matching (case-insensitive)
        server_lower = server_type.lower()

        # Add server-specific operational attributes using ServerTypes constants
        # Check more specific patterns first to avoid substring matches
        # Use ServerTypes constants instead of string literals
        if (
            server_lower == FlextLdifConstants.ServerTypes.OPENLDAP.lower()
            or server_lower == FlextLdifConstants.ServerTypes.OPENLDAP1.lower()
            or server_lower == FlextLdifConstants.ServerTypes.OPENLDAP2.lower()
            or FlextLdifConstants.LdapServers.OPENLDAP in server_lower
        ):
            operational_attrs |= (
                FlextLdifConstants.OperationalAttributes.OPENLDAP_SPECIFIC
            )
        elif (
            server_lower == FlextLdifConstants.ServerTypes.OID.lower()
            or FlextLdifConstants.LdapServers.ORACLE_OID in server_lower
        ):
            operational_attrs |= FlextLdifConstants.OperationalAttributes.OID_SPECIFIC
        elif (
            server_lower == FlextLdifConstants.ServerTypes.OUD.lower()
            or FlextLdifConstants.LdapServers.ORACLE_OUD in server_lower
        ):
            operational_attrs |= FlextLdifConstants.OperationalAttributes.OUD_SPECIFIC
        elif (
            server_lower == FlextLdifConstants.ServerTypes.DS_389.lower()
            or FlextLdifConstants.LdapServers.DS_389 in server_lower
        ):
            operational_attrs |= (
                FlextLdifConstants.OperationalAttributes.DS_389_SPECIFIC
            )
        elif (
            server_lower == FlextLdifConstants.ServerTypes.AD.lower()
            or FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY in server_lower
        ):
            operational_attrs |= FlextLdifConstants.OperationalAttributes.AD_SPECIFIC
        elif FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY in server_lower:
            operational_attrs |= (
                FlextLdifConstants.OperationalAttributes.NOVELL_SPECIFIC
            )
        elif FlextLdifConstants.LdapServers.IBM_TIVOLI in server_lower:
            operational_attrs |= (
                FlextLdifConstants.OperationalAttributes.IBM_TIVOLI_SPECIFIC
            )

        return list(operational_attrs)


__all__ = ["FlextLdifEntryQuirks"]
