"""Schema validator module for LDIF processing."""

from __future__ import annotations

from typing import override

from flext_core import FlextResult, FlextService

from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


class FlextLdifSchemaValidator(FlextService[FlextLdifTypes.Dict]):
    """Schema validation service for LDIF entries."""

    @override
    def __init__(self) -> None:
        """Initialize schema validator with Phase 1 context enrichment."""
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins

    @override
    def execute(self) -> FlextResult[FlextLdifTypes.Dict]:
        """Execute schema validator service."""
        return FlextResult[FlextLdifTypes.Dict].ok({
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
        errors: FlextLdifTypes.StringList = []
        warnings: FlextLdifTypes.StringList = []

        for idx, entry in enumerate(entries):
            # Basic DN validation
            if not entry.dn or not entry.dn.value:
                errors.append(f"Entry {idx}: Missing or empty DN")
                continue

            # Validate objectClass presence
            object_classes = entry.get_attribute_values("objectClass")
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
                if not entry.get_attribute_values("cn"):
                    errors.append(
                        f"Entry {idx} ({entry.dn.value}): Missing required attribute 'cn' for person objectClass"
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
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Validate entry against discovered schema.

        Args:
            entry: Entry to validate
            schema: Discovered schema

        Returns:
            FlextResult containing validation report

        """
        warnings: FlextLdifTypes.StringList = [
            f"Attribute '{attr_name}' not in discovered schema"
            for attr_name in entry.attributes.data
            if attr_name not in schema.attributes
        ]

        entry_object_classes: FlextLdifTypes.StringList = entry.get_attribute_values(
            "objectClass"
        )
        issues: FlextLdifTypes.StringList = [
            f"ObjectClass '{oc}' not in discovered schema"
            for oc in entry_object_classes
            if oc not in schema.objectclasses
        ]

        validation_result: FlextLdifTypes.Dict = {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "dn": entry.dn.value,
        }

        return FlextResult[FlextLdifTypes.Dict].ok(validation_result)

    def validate_objectclass_requirements(
        self,
        entry: FlextLdifModels.Entry,
        schema: FlextLdifModels.SchemaDiscoveryResult,
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Validate objectClass requirements for entry.

        Args:
            entry: Entry to validate
            schema: Discovered schema

        Returns:
            FlextResult containing validation report

        """
        issues: FlextLdifTypes.StringList = []
        entry_attrs = set(entry.attributes.data.keys())
        entry_object_classes: FlextLdifTypes.StringList = entry.get_attribute_values(
            "objectClass"
        )

        for oc_name in entry_object_classes:
            if oc_name in schema.objectclasses:
                oc_def = schema.objectclasses[oc_name]

                req_attrs = oc_def.get("required_attributes", [])
                if isinstance(req_attrs, list):
                    issues.extend(
                        f"Missing required attribute '{req_attr}' "
                        f"for objectClass '{oc_name}'"
                        for req_attr in req_attrs
                        if req_attr not in entry_attrs
                    )

        validation_result: FlextLdifTypes.Dict = {
            "valid": len(issues) == 0,
            "issues": issues,
            "dn": entry.dn.value,
        }

        return FlextResult[FlextLdifTypes.Dict].ok(validation_result)


__all__ = ["FlextLdifSchemaValidator"]
