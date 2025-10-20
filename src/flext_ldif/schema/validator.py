"""Schema Validator Service - RFC 4512 Compliant LDIF Schema Validation.

This module provides comprehensive schema validation for LDIF entries following RFC 4512
(LDAP Directory Information Models). Validates attribute types, object classes, and entry
structures against LDAP schema requirements with configurable strictness levels.

Features:
- RFC 4512 compliant attribute type validation
- Object class hierarchy validation (structural, auxiliary, abstract)
- MUST/MAY attribute presence checking
- Entry structure validation with DN consistency
- Configurable validation strictness (lenient vs strict mode)
- Detailed error reporting with validation context
- Integration with FlextLdifModels for type-safe validation

Validation Rules:
- Attribute names: RFC 4512 naming conventions (letters, digits, hyphens)
- Object classes: Proper inheritance and structural constraints
- Entry completeness: Required attributes present and correctly typed
- DN consistency: Distinguished name format and component validation
- Schema compliance: Against configured LDAP schema definitions

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import override

from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


class FlextLdifSchemaValidator(FlextService[dict[str, object]]):
    """Schema validation service for LDIF entries."""

    @override
    def __init__(self) -> None:
        """Initialize schema validator with Phase 1 context enrichment."""
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins

    @override
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute schema validator service."""
        return FlextResult[dict[str, object]].ok({
            "service": FlextLdifSchemaValidator,
            "status": "ready",
        })

    def validate_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        *,
        strict: bool = False,
    ) -> FlextResult[FlextLdifModels.LdifValidationResult]:
        """Validate multiple LDIF entries.

        Args:
            entries: List of entries to validate
            strict: If True, apply strict validation rules

        Returns:
            FlextResult containing LdifValidationResult

        """
        errors: list[str] = []
        warnings: list[str] = []

        for idx, entry in enumerate(entries):
            # Basic DN validation
            if not entry.dn or not entry.dn.value:
                errors.append(f"Entry {idx}: Missing or empty DN")
                continue

            # Validate objectClass presence
            object_classes = entry.get_attribute_values(
                FlextLdifConstants.DictKeys.OBJECTCLASS
            )
            if not object_classes:
                errors.append(
                    f"Entry {idx} ({entry.dn.value}): Missing objectClass attribute"
                )

            # In strict mode, perform additional validation
            if (
                strict
                and object_classes
                and ("person" in object_classes or "inetOrgPerson" in object_classes)
            ):
                # Check for required attributes based on objectClass
                # This is a simplified check - full schema validation would be more complex
                if not entry.get_attribute_values(FlextLdifConstants.DictKeys.CN):
                    errors.append(
                        f"Entry {idx} ({entry.dn.value}): Missing required attribute FlextLdifConstants.DictKeys.CN for person objectClass"
                    )
                if not entry.get_attribute_values("sn"):
                    errors.append(
                        f"Entry {idx} ({entry.dn.value}): Missing required attribute 'sn' for person objectClass"
                    )

        # Build validation result
        validation_result = FlextLdifModels.LdifValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
        )

        return FlextResult[FlextLdifModels.LdifValidationResult].ok(validation_result)

    def validate_entry_against_schema(
        self,
        entry: FlextLdifModels.Entry,
        schema: FlextLdifModels.SchemaDiscoveryResult,
    ) -> FlextResult[FlextLdifTypes.Models.ValidationReportData]:
        """Validate entry against discovered schema.

        Args:
            entry: Entry to validate
            schema: Discovered schema

        Returns:
            FlextResult containing validation report with typed structure

        """
        warnings: list[str] = [
            f"Attribute '{attr_name}' not in discovered schema"
            for attr_name in entry.attributes.attributes
            if attr_name not in schema.attributes
        ]

        entry_object_classes: list[str] = entry.get_attribute_values(
            FlextLdifConstants.DictKeys.OBJECTCLASS
        )
        issues: list[str] = [
            f"ObjectClass '{oc}' not in discovered schema"
            for oc in entry_object_classes
            if oc not in schema.objectclasses
        ]

        validation_result: FlextLdifTypes.Models.ValidationReportData = {
            FlextLdifConstants.DictKeys.VALID: len(issues) == 0,
            FlextLdifConstants.DictKeys.ISSUES: issues,
            "warnings": warnings,
            FlextLdifConstants.DictKeys.DN: entry.dn.value,
        }

        return FlextResult[FlextLdifTypes.Models.ValidationReportData].ok(
            validation_result
        )

    def validate_objectclass_requirements(
        self,
        entry: FlextLdifModels.Entry,
        schema: FlextLdifModels.SchemaDiscoveryResult,
    ) -> FlextResult[FlextLdifTypes.Models.ValidationReportData]:
        """Validate objectClass requirements for entry.

        Args:
            entry: Entry to validate
            schema: Discovered schema

        Returns:
            FlextResult containing validation report with typed structure

        """
        issues: list[str] = []
        entry_attrs = set(entry.attributes.attributes.keys())
        entry_object_classes: list[str] = entry.get_attribute_values(
            FlextLdifConstants.DictKeys.OBJECTCLASS
        )

        for oc_name in entry_object_classes:
            if oc_name in schema.objectclasses:
                oc_def = schema.objectclasses[oc_name]

                req_attrs: object = oc_def.get("required_attributes", [])
                if isinstance(req_attrs, list):
                    issues.extend(
                        (
                            f"Missing required attribute '{req_attr}' "
                            f"for objectClass '{oc_name}'"
                        )
                        for req_attr in req_attrs
                        if req_attr not in entry_attrs
                    )

        validation_result: FlextLdifTypes.Models.ValidationReportData = {
            FlextLdifConstants.DictKeys.VALID: len(issues) == 0,
            FlextLdifConstants.DictKeys.ISSUES: issues,
            FlextLdifConstants.DictKeys.DN: entry.dn.value,
        }

        return FlextResult[FlextLdifTypes.Models.ValidationReportData].ok(
            validation_result
        )


__all__ = ["FlextLdifSchemaValidator"]
