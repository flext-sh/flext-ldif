"""FLEXT LDIF ObjectClass Manager.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import FlextLogger, FlextResult, FlextService, FlextTypes
from flext_ldif.models import FlextLdifModels


class FlextLdifObjectClassManager(FlextService[FlextTypes.Dict]):
    """ObjectClass hierarchy and validation management."""

    @override
    def __init__(self) -> None:
        """Initialize objectClass manager."""
        super().__init__()
        self._logger = FlextLogger(__name__)

    @override
    def execute(self: object) -> FlextResult[FlextTypes.Dict]:
        """Execute objectClass manager service."""
        return FlextResult[FlextTypes.Dict].ok({
            "service": FlextLdifObjectClassManager,
            "status": "ready",
        })

    def resolve_objectclass_hierarchy(
        self,
        object_class: str,
        schema: FlextLdifModels.SchemaDiscoveryResult,
    ) -> FlextResult[FlextTypes.StringList]:
        """Resolve objectClass hierarchy.

        Args:
            object_class: ObjectClass name
            schema: Discovered schema

        Returns:
            FlextResult containing objectClass hierarchy

        """
        hierarchy: FlextTypes.StringList = [object_class]

        if object_class in schema.object_classes:
            oc_def = schema.object_classes[object_class]
            hierarchy.extend(oc_def.superior)

        return FlextResult[FlextTypes.StringList].ok(hierarchy)

    def get_all_required_attributes(
        self,
        object_classes: FlextTypes.StringList,
        schema: FlextLdifModels.SchemaDiscoveryResult,
    ) -> FlextResult[FlextTypes.StringList]:
        """Get all required attributes for objectClasses.

        Args:
            object_classes: List of objectClass names
            schema: Discovered schema

        Returns:
            FlextResult containing required attributes

        """
        required_attrs: set[str] = set()

        for oc_name in object_classes:
            if oc_name in schema.object_classes:
                oc_def = schema.object_classes[oc_name]
                required_attrs.update(oc_def.required_attributes)

        return FlextResult[FlextTypes.StringList].ok(list(required_attrs))

    def get_all_optional_attributes(
        self,
        object_classes: FlextTypes.StringList,
        schema: FlextLdifModels.SchemaDiscoveryResult,
    ) -> FlextResult[FlextTypes.StringList]:
        """Get all optional attributes for objectClasses.

        Args:
            object_classes: List of objectClass names
            schema: Discovered schema

        Returns:
            FlextResult containing optional attributes

        """
        optional_attrs: set[str] = set()

        for oc_name in object_classes:
            if oc_name in schema.object_classes:
                oc_def = schema.object_classes[oc_name]
                optional_attrs.update(oc_def.optional_attributes)

        return FlextResult[FlextTypes.StringList].ok(list(optional_attrs))

    def validate_objectclass_combination(
        self,
        object_classes: FlextTypes.StringList,
        schema: FlextLdifModels.SchemaDiscoveryResult,
    ) -> FlextResult[FlextTypes.Dict]:
        """Validate objectClass combination.

        Args:
            object_classes: List of objectClass names
            schema: Discovered schema

        Returns:
            FlextResult containing validation report

        """
        issues: FlextTypes.StringList = []
        structural_count = 0

        for oc_name in object_classes:
            if oc_name in schema.object_classes:
                oc_def = schema.object_classes[oc_name]
                if oc_def.structural:
                    structural_count += 1

        if structural_count > 1:
            issues.append(
                f"Multiple structural objectClasses found: {structural_count}"
            )

        validation_result: FlextTypes.Dict = {
            "valid": len(issues) == 0,
            "issues": issues,
            "structural_count": structural_count,
        }

        return FlextResult[FlextTypes.Dict].ok(validation_result)


__all__ = ["FlextLdifObjectClassManager"]
