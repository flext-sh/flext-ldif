"""FLEXT LDIF Schema - Schema-related Models.

Schema models for LDAP schema definitions and discovery.
Extends flext-core FlextModels with LDIF-specific schema entities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextModels, FlextResult, FlextTypes
from pydantic import ConfigDict, Field, computed_field, field_serializer

from flext_ldif.models import FlextLdifModels


class FlextLdifSchema:
    """Schema-related models extending FlextModels.

    Contains models for LDAP schema definitions:
    - SchemaObjectClass: Object class definitions
    - SchemaAttribute: Attribute definitions
    - SchemaDiscoveryResult: Schema discovery results
    """

    class SchemaObjectClass(FlextLdifModels.BaseSchemaObjectClass):
        """Standard LDAP object class definition.

        Extends BaseSchemaObjectClass with standard LDIF behavior.
        Inherits superior field which supports both string and list for multiple inheritance.
        """

        must: FlextTypes.StringList = Field(
            default_factory=list,
            description="Required attributes (MUST)",
        )

        may: FlextTypes.StringList = Field(
            default_factory=list,
            description="Optional attributes (MAY)",
        )

        structural: bool = Field(
            default=False,
            description="Whether this is a structural object class",
        )

        @computed_field
        def attribute_summary(self) -> FlextTypes.Dict:
            """Computed field for attribute summary."""
            return {
                "required_count": len(self.required_attributes),
                "optional_count": len(self.optional_attributes),
                "total_attributes": len(self.required_attributes)
                + len(self.optional_attributes),
                "is_structural": self.structural,
            }

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new SchemaObjectClass instance."""
            try:
                _ = args  # Suppress unused argument warning
                name = str(kwargs.get("name", ""))
                description = str(kwargs.get("description", ""))
                required_attrs = kwargs.get("required_attributes", [])
                required_attributes = (
                    list(required_attrs)
                    if isinstance(required_attrs, (list, tuple))
                    else []
                )
                instance = cls(
                    name=name,
                    oid=str(kwargs.get("oid", "")),
                    description=description,
                    required_attributes=required_attributes,
                )
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

        @field_serializer("must", when_used="json")
        def serialize_must_with_schema_context(
            self, value: FlextTypes.StringList, _info: object
        ) -> FlextTypes.Dict:
            """Serialize required attributes with schema context."""
            return {
                "must": value,
                "schema_context": {
                    "objectclass": self.name,
                    "structural": self.structural,
                    "required_count": len(value),
                },
            }

    class SchemaDiscoveryResult(FlextModels.Value):
        """Result of schema discovery operation."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        object_classes: dict[str, FlextLdifModels.SchemaObjectClass] = Field(
            default_factory=dict,
            description="Discovered object classes",
        )

        attributes: dict[str, FlextLdifModels.SchemaAttribute] = Field(
            default_factory=dict,
            description="Discovered attributes",
        )

        server_type: str = Field(
            default="generic",
            description="Server type that was discovered",
        )

        discovery_timestamp: str = Field(
            default="",
            description="Timestamp when discovery was performed",
        )

        @computed_field
        def summary(self) -> FlextTypes.Dict:
            """Computed field for discovery summary."""
            return {
                "object_class_count": len(self.object_classes),
                "attribute_count": len(self.attributes),
                "server_type": self.server_type,
                "total_schema_elements": len(self.object_classes)
                + len(self.attributes),
            }
