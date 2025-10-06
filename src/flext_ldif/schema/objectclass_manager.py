"""FLEXT LDIF ObjectClass Manager.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


class FlextLdifObjectClassManager(FlextService[FlextLdifTypes.Dict]):
    """ObjectClass hierarchy and validation management."""

    @override
    def __init__(self) -> None:
        """Initialize objectClass manager."""
        super().__init__()
        self._logger = FlextLogger(__name__)

    @override
    def execute(self: object) -> FlextResult[FlextLdifTypes.Dict]:
        """Execute objectClass manager service."""
        return FlextResult[FlextLdifTypes.Dict].ok({
            "service": FlextLdifObjectClassManager,
            "status": "ready",
        })

    def resolve_objectclass_hierarchy(
        self,
        object_class: str,
        schema: FlextLdifModels.SchemaDiscoveryResult,
    ) -> FlextResult[FlextLdifTypes.StringList]:
        """Resolve objectClass hierarchy.

        Args:
            object_class: ObjectClass name
            schema: Discovered schema

        Returns:
            FlextResult containing objectClass hierarchy

        """
        hierarchy: FlextLdifTypes.StringList = [object_class]

        if object_class in schema.objectclasses:
            oc_def = schema.objectclasses[object_class]
            superior = oc_def.get("superior", [])
            if isinstance(superior, str):
                hierarchy.append(superior)
            elif isinstance(superior, list):
                hierarchy.extend(superior)

        return FlextResult[FlextLdifTypes.StringList].ok(hierarchy)

    def get_all_required_attributes(
        self,
        object_classes: FlextLdifTypes.StringList,
        schema: FlextLdifModels.SchemaDiscoveryResult,
    ) -> FlextResult[FlextLdifTypes.StringList]:
        """Get all required attributes for objectClasses.

        Args:
            object_classes: List of objectClass names
            schema: Discovered schema

        Returns:
            FlextResult containing required attributes

        """
        required_attrs: set[str] = set()

        for oc_name in object_classes:
            if oc_name in schema.objectclasses:
                oc_def = schema.objectclasses[oc_name]
                req_attrs = oc_def.get("required_attributes", [])
                if isinstance(req_attrs, list):
                    required_attrs.update(req_attrs)

        return FlextResult[FlextLdifTypes.StringList].ok(list(required_attrs))

    def get_all_optional_attributes(
        self,
        object_classes: FlextLdifTypes.StringList,
        schema: FlextLdifModels.SchemaDiscoveryResult,
    ) -> FlextResult[FlextLdifTypes.StringList]:
        """Get all optional attributes for objectClasses.

        Args:
            object_classes: List of objectClass names
            schema: Discovered schema

        Returns:
            FlextResult containing optional attributes

        """
        optional_attrs: set[str] = set()

        for oc_name in object_classes:
            if oc_name in schema.objectclasses:
                oc_def = schema.objectclasses[oc_name]
                opt_attrs = oc_def.get("optional_attributes", [])
                if isinstance(opt_attrs, list):
                    optional_attrs.update(opt_attrs)

        return FlextResult[FlextLdifTypes.StringList].ok(list(optional_attrs))

    def validate_objectclass_combination(
        self,
        object_classes: FlextLdifTypes.StringList,
        schema: FlextLdifModels.SchemaDiscoveryResult,
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Validate objectClass combination.

        Args:
            object_classes: List of objectClass names
            schema: Discovered schema

        Returns:
            FlextResult containing validation report

        """
        issues: FlextLdifTypes.StringList = []
        structural_count = 0

        for oc_name in object_classes:
            if oc_name in schema.objectclasses:
                oc_def = schema.objectclasses[oc_name]
                if oc_def.get("structural", False):
                    structural_count += 1

        if structural_count > 1:
            issues.append(
                f"Multiple structural objectClasses found: {structural_count}"
            )

        validation_result: FlextLdifTypes.Dict = {
            "valid": len(issues) == 0,
            "issues": issues,
            "structural_count": structural_count,
        }

        return FlextResult[FlextLdifTypes.Dict].ok(validation_result)


__all__ = ["FlextLdifObjectClassManager"]
