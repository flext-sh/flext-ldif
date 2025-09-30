"""Schema validator module for LDIF processing."""

from __future__ import annotations

from typing import override

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels


class FlextLdifSchemaValidator(FlextService[dict[str, object]]):
    """Schema validation service for LDIF entries."""

    @override
    def __init__(self) -> None:
        """Initialize schema validator."""
        super().__init__()
        self._logger = FlextLogger(__name__)

    @override
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute schema validator service."""
        return FlextResult[dict[str, object]].ok(
            {
                "service": FlextLdifSchemaValidator,
                "status": "ready",
            }
        )

    async def execute_async(self) -> FlextResult[dict[str, object]]:
        """Execute schema validator service."""
        return FlextResult[dict[str, object]].ok(
            {
                "service": FlextLdifSchemaValidator,
                "status": "ready",
            }
        )

    def validate_entry_against_schema(
        self,
        entry: FlextLdifModels.Entry,
        schema: FlextLdifModels.SchemaDiscoveryResult,
    ) -> FlextResult[dict[str, object]]:
        """Validate entry against discovered schema.

        Args:
            entry: Entry to validate
            schema: Discovered schema

        Returns:
            FlextResult containing validation report

        """
        warnings: list[str] = [
            f"Attribute '{attr_name}' not in discovered schema"
            for attr_name in entry.attributes.data
            if attr_name not in schema.attributes
        ]

        entry_object_classes: list[str] = entry.get_attribute_values("objectClass")
        issues: list[str] = [
            f"ObjectClass '{oc}' not in discovered schema"
            for oc in entry_object_classes
            if oc not in schema.object_classes
        ]

        validation_result: dict[str, object] = {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "dn": entry.dn.value,
        }

        return FlextResult[dict[str, object]].ok(validation_result)

    def validate_objectclass_requirements(
        self,
        entry: FlextLdifModels.Entry,
        schema: FlextLdifModels.SchemaDiscoveryResult,
    ) -> FlextResult[dict[str, object]]:
        """Validate objectClass requirements for entry.

        Args:
            entry: Entry to validate
            schema: Discovered schema

        Returns:
            FlextResult containing validation report

        """
        issues: list[str] = []
        entry_attrs = set(entry.attributes.data.keys())
        entry_object_classes: list[str] = entry.get_attribute_values("objectClass")

        for oc_name in entry_object_classes:
            if oc_name in schema.object_classes:
                oc_def = schema.object_classes[oc_name]

                issues.extend(
                    f"Missing required attribute '{req_attr}' "
                    f"for objectClass '{oc_name}'"
                    for req_attr in oc_def.required_attributes
                    if req_attr not in entry_attrs
                )

        validation_result: dict[str, object] = {
            "valid": len(issues) == 0,
            "issues": issues,
            "dn": entry.dn.value,
        }

        return FlextResult[dict[str, object]].ok(validation_result)


__all__ = ["FlextLdifSchemaValidator"]
