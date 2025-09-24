"""LDAP Server Quirks Handler - Implementation-Specific Adaptations.

This module handles quirks and differences between various LDAP server
implementations to ensure compatibility across different systems.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import operator
from typing import cast

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifQuirksAdapter(FlextService[dict[str, object]]):
    """Handler for LDAP server implementation quirks and differences.

    Provides adaptation mechanisms for different LDAP server implementations
    including Active Directory, OpenLDAP, Apache Directory Server, etc.
    """

    def __init__(self, server_type: str | None = None) -> None:
        """Initialize server quirks handler.

        Args:
            server_type: Specific server type to handle, or None for auto-detection

        """
        self._logger = FlextLogger(__name__)
        self._server_type = server_type or FlextLdifConstants.LdapServers.GENERIC
        self._adaptation_rules: dict[str, dict[str, object]] = {}
        self._setup_adaptation_rules()

    def _setup_adaptation_rules(self) -> None:
        """Setup adaptation rules for different server types."""
        self._adaptation_rules = {
            FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY: {
                "dn_case_sensitive": True,
                "required_object_classes": list(
                    FlextLdifConstants.LdapServers.AD_REQUIRED_CLASSES
                ),
                "attribute_mappings": {
                    "userPrincipalName": "uid",
                    "sAMAccountName": "uid",
                    "displayName": "cn",
                    "givenName": "givenName",
                    "sn": "sn",
                    "mail": "mail",
                    "telephoneNumber": "telephoneNumber",
                },
                "dn_patterns": list(FlextLdifConstants.LdapServers.AD_DN_PATTERNS),
                "special_attributes": [
                    "userPrincipalName",
                    "sAMAccountName",
                    "objectSid",
                ],
            },
            FlextLdifConstants.LdapServers.OPENLDAP: {
                "dn_case_sensitive": False,
                "required_object_classes": list(
                    FlextLdifConstants.LdapServers.OPENLDAP_REQUIRED_CLASSES
                ),
                "attribute_mappings": {
                    "uid": "uid",
                    "cn": "cn",
                    "sn": "sn",
                    "givenName": "givenName",
                    "mail": "mail",
                    "telephoneNumber": "telephoneNumber",
                },
                "dn_patterns": list(
                    FlextLdifConstants.LdapServers.OPENLDAP_DN_PATTERNS
                ),
                "special_attributes": ["uid", "userPassword"],
            },
            FlextLdifConstants.LdapServers.APACHE_DIRECTORY: {
                "dn_case_sensitive": False,
                "required_object_classes": ["top", "person", "organizationalPerson"],
                "attribute_mappings": {
                    "uid": "uid",
                    "cn": "cn",
                    "sn": "sn",
                    "givenName": "givenName",
                    "mail": "mail",
                },
                "dn_patterns": ["cn=", "ou=", "dc=", "o="],
                "special_attributes": ["uid", "userPassword"],
            },
            FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY: {
                "dn_case_sensitive": False,
                "required_object_classes": ["top", "person", "organizationalPerson"],
                "attribute_mappings": {
                    "cn": "cn",
                    "sn": "sn",
                    "givenName": "givenName",
                    "mail": "mail",
                },
                "dn_patterns": ["cn=", "ou=", "dc=", "o="],
                "special_attributes": ["uid", "userPassword"],
            },
            FlextLdifConstants.LdapServers.IBM_TIVOLI: {
                "dn_case_sensitive": False,
                "required_object_classes": ["top", "person", "organizationalPerson"],
                "attribute_mappings": {
                    "cn": "cn",
                    "sn": "sn",
                    "givenName": "givenName",
                    "mail": "mail",
                },
                "dn_patterns": ["cn=", "ou=", "dc=", "o="],
                "special_attributes": ["uid", "userPassword"],
            },
            FlextLdifConstants.LdapServers.GENERIC: {
                "dn_case_sensitive": False,
                "required_object_classes": ["top"],
                "attribute_mappings": {},
                "dn_patterns": [],
                "special_attributes": [],
            },
        }

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute quirks adapter health check operation - required by FlextService.

        Returns:
            FlextResult containing adapter health status information.

        """
        try:
            health_info: dict[str, object] = {
                "status": "healthy",
                "adapter_type": "FlextLdifQuirksAdapter",
                "current_server_type": self._server_type,
                "supported_servers": list(self._adaptation_rules.keys()),
                "capabilities": [
                    "detect_server_type",
                    "adapt_entry",
                    "validate_server_compliance",
                    "get_server_info",
                    "attribute_mapping",
                    "dn_format_validation",
                    "object_class_validation",
                    "server_specific_adaptations",
                ],
                "adaptation_rules_count": len(self._adaptation_rules),
            }
            return FlextResult[dict[str, object]].ok(health_info)
        except Exception as e:
            error_msg = f"Quirks adapter health check failed: {e}"
            self._logger.exception(error_msg)
            return FlextResult[dict[str, object]].fail(error_msg)

    def detect_server_type(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[str]:
        """Detect LDAP server type from entries.

        Args:
            entries: List of LDIF entries to analyze

        Returns:
            FlextResult containing detected server type

        """
        if not entries:
            return FlextResult[str].ok(FlextLdifConstants.LdapServers.GENERIC)

        # Analyze DN patterns and object classes
        dn_patterns: set[str] = set()
        object_classes: set[str] = set()
        special_attributes: set[str] = set()

        for entry in entries:
            # Analyze DN patterns
            dn_value = entry.dn.value
            components = [comp.strip() for comp in dn_value.split(",")]
            for component in components:
                if "=" in component:
                    attr_name = component.split("=")[0].strip()
                    dn_patterns.add(attr_name)

            # Analyze object classes
            obj_classes: list[str] = entry.get_attribute("objectClass") or []
            object_classes.update(obj_classes)

            # Analyze special attributes
            special_attributes.update(entry.attributes.data.keys())

        # Score each server type based on matches
        server_scores: dict[str, float] = {}

        for server_type, rules in self._adaptation_rules.items():
            if server_type == FlextLdifConstants.LdapServers.GENERIC:
                continue

            score = 0.0

            # Score DN patterns
            dn_patterns_raw = rules.get("dn_patterns", [])
            server_dn_patterns: set[str] = (
                set(dn_patterns_raw) if isinstance(dn_patterns_raw, list) else set()
            )
            dn_matches = len(dn_patterns.intersection(server_dn_patterns))
            if server_dn_patterns:
                score += (dn_matches / len(server_dn_patterns)) * 0.4

            # Score object classes
            obj_classes_raw = rules.get("required_object_classes", [])
            server_obj_classes: set[str] = (
                set(obj_classes_raw) if isinstance(obj_classes_raw, list) else set()
            )
            obj_class_matches = len(object_classes.intersection(server_obj_classes))
            if server_obj_classes:
                score += (obj_class_matches / len(server_obj_classes)) * 0.3

            # Score special attributes
            special_attrs_raw = rules.get("special_attributes", [])
            server_special_attrs: set[str] = (
                set(special_attrs_raw) if isinstance(special_attrs_raw, list) else set()
            )
            attr_matches = len(special_attributes.intersection(server_special_attrs))
            if server_special_attrs:
                score += (attr_matches / len(server_special_attrs)) * 0.3

            server_scores[server_type] = score

        # Find best match
        if server_scores:
            best_server = max(server_scores.items(), key=operator.itemgetter(1))
            min_confidence_threshold = 0.3
            if (
                best_server[1] > min_confidence_threshold
            ):  # Minimum confidence threshold
                self._server_type = best_server[0]
                self._logger.info(
                    f"Detected server type: {best_server[0]} (confidence: {best_server[1]:.2f})"
                )
                return FlextResult[str].ok(best_server[0])

        # Default to generic
        self._server_type = FlextLdifConstants.LdapServers.GENERIC
        return FlextResult[str].ok(FlextLdifConstants.LdapServers.GENERIC)

    def adapt_entry(
        self, entry: FlextLdifModels.Entry, target_server: str | None = None
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Adapt entry for specific server type.

        Args:
            entry: Entry to adapt
            target_server: Target server type, or None to use current server type

        Returns:
            FlextResult containing adapted entry

        """
        target = target_server or self._server_type

        if target not in self._adaptation_rules:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Unknown server type: {target}"
            )

        rules = self._adaptation_rules[target]

        try:
            # Create adapted entry data
            adapted_data: dict[str, object] = {"dn": entry.dn.value, "attributes": {}}

            # Apply attribute mappings
            attribute_mappings = cast(
                "dict[str, str]", rules.get("attribute_mappings", {})
            )
            adapted_attrs: dict[str, list[str]] = {}

            for attr_name, attr_values in entry.attributes.data.items():
                # Map attribute name if needed
                mapped_name = attribute_mappings.get(attr_name, attr_name)

                # Apply server-specific adaptations
                adapted_values = self._adapt_attribute_values(
                    attr_name, attr_values, target
                )

                adapted_attrs[mapped_name] = adapted_values

            adapted_data["attributes"] = adapted_attrs

            # Create adapted entry
            adapted_entry_result: FlextResult[FlextLdifModels.Entry] = (
                FlextLdifModels.Entry.create(adapted_data)
            )
            if adapted_entry_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create adapted entry: {adapted_entry_result.error}"
                )

            return adapted_entry_result

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

        # Server-specific value adaptations
        if server_type == FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY:
            # AD-specific adaptations
            if attr_name.lower() == "objectclass":
                # Ensure required AD object classes are present
                required_classes = cast(
                    "list[str]",
                    self._adaptation_rules[server_type]["required_object_classes"],
                )
                for required_class in required_classes:
                    if required_class not in adapted_values:
                        adapted_values.append(required_class)

            elif attr_name.lower() in {"userprincipalname", "samaccountname"}:
                # Normalize AD-specific attributes
                adapted_values = [val.lower() for val in adapted_values]

        elif (
            server_type == FlextLdifConstants.LdapServers.OPENLDAP
            and attr_name.lower() == "objectclass"
        ):
            # OpenLDAP-specific adaptations
            # Ensure required OpenLDAP object classes are present
            required_classes = cast(
                "list[str]",
                self._adaptation_rules[server_type]["required_object_classes"],
            )
            for required_class in required_classes:
                if required_class not in adapted_values:
                    adapted_values.append(required_class)

        return adapted_values

    def validate_server_compliance(
        self, entry: FlextLdifModels.Entry, server_type: str | None = None
    ) -> FlextResult[dict[str, object]]:
        """Validate entry compliance with server-specific rules.

        Args:
            entry: Entry to validate
            server_type: Server type to validate against, or None for current

        Returns:
            FlextResult containing validation report

        """
        target = server_type or self._server_type

        if target not in self._adaptation_rules:
            return FlextResult[dict[str, object]].fail(f"Unknown server type: {target}")

        rules = self._adaptation_rules[target]
        validation_report: dict[str, object] = {
            "server_type": target,
            "compliant": True,
            "issues": [],
            "warnings": [],
            "recommendations": [],
        }

        issues: list[str] = []
        recommendations: list[str] = []

        # Validate DN format
        dn_validation = self._validate_dn_format(entry.dn.value, target)
        if not dn_validation["valid"]:
            issues_list = dn_validation.get("issues", [])
            if isinstance(issues_list, list):
                issues.extend(issues_list)

        # Validate object classes
        obj_classes: list[str] = entry.get_attribute("objectClass") or []
        required_classes: list[str] = cast(
            "list[str]", rules.get("required_object_classes", [])
        )

        issues.extend(
            f"Missing required object class: {required_class}"
            for required_class in required_classes
            if required_class not in obj_classes
        )

        # Validate special attributes
        special_attrs: list[str] = cast(
            "list[str]", rules.get("special_attributes", [])
        )
        warnings: list[str] = [
            f"Missing recommended attribute: {special_attr}"
            for special_attr in special_attrs
            if not entry.has_attribute(special_attr)
        ]

        # Update validation report
        validation_report["issues"] = issues
        validation_report["warnings"] = warnings
        validation_report["recommendations"] = recommendations
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
        rules: dict[str, object] = self._adaptation_rules.get(server_type, {})
        dn_patterns_raw = rules.get("dn_patterns", [])
        dn_patterns: list[str] = (
            cast("list[str]", dn_patterns_raw)
            if isinstance(dn_patterns_raw, list)
            else []
        )
        case_sensitive_raw = rules.get("dn_case_sensitive", False)
        case_sensitive = cast("bool", case_sensitive_raw)

        issues: list[str] = []

        # Check DN components
        components = [comp.strip() for comp in dn.split(",")]
        for component in components:
            if "=" not in component:
                issues.append(f"Invalid DN component format: {component}")
                continue

            attr_name = component.split("=")[0].strip()

            # Check case sensitivity
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

    def get_server_info(
        self, server_type: str | None = None
    ) -> FlextResult[dict[str, object]]:
        """Get information about server type and its quirks.

        Args:
            server_type: Server type to get info for, or None for current

        Returns:
            FlextResult containing server information

        """
        target = server_type or self._server_type

        if target not in self._adaptation_rules:
            return FlextResult[dict[str, object]].fail(f"Unknown server type: {target}")

        rules = self._adaptation_rules[target]

        server_info: dict[str, object] = {
            "server_type": target,
            "dn_case_sensitive": rules.get("dn_case_sensitive", False),
            "required_object_classes": rules.get("required_object_classes", []),
            "attribute_mappings": rules.get("attribute_mappings", {}),
            "dn_patterns": rules.get("dn_patterns", []),
            "special_attributes": rules.get("special_attributes", []),
            "description": self._get_server_description(target),
        }

        return FlextResult[dict[str, object]].ok(server_info)

    def _get_server_description(self, server_type: str) -> str:
        """Get human-readable description of server type.

        Args:
            server_type: Server type

        Returns:
            Server description

        """
        descriptions = {
            FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY: "Microsoft Active Directory",
            FlextLdifConstants.LdapServers.OPENLDAP: "OpenLDAP",
            FlextLdifConstants.LdapServers.APACHE_DIRECTORY: "Apache Directory Server",
            FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY: "Novell eDirectory",
            FlextLdifConstants.LdapServers.IBM_TIVOLI: "IBM Tivoli Directory Server",
            FlextLdifConstants.LdapServers.GENERIC: "Generic LDAP Server",
        }

        return descriptions.get(server_type, "Unknown Server Type")


__all__ = ["FlextLdifQuirksAdapter"]
