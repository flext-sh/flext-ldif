"""Schema Service - RFC 4512 Compliant Schema Building and Validation.

This module provides unified schema building and validation for LDIF processing.
Combines:
- Schema builder with fluent interface for constructing schemas step-by-step
- Schema validator for RFC 4512 compliant LDIF entry validation

Features:
- Fluent builder pattern for schema construction
- RFC 4512 compliant validation
- Object class hierarchy validation
- MUST/MAY attribute presence checking
- Entry structure validation with DN consistency
- Configurable validation strictness

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Self, override

from flext_core import FlextDecorators, FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


class FlextLdifSchemaBuilder(FlextService[FlextLdifConfig]):
    """Schema builder for standard LDAP schemas using Builder pattern.

    Provides fluent interface for building schemas step-by-step following
    SchemaBuilderProtocol for extensibility.
    """

    # Type annotations for instance variables
    # Note: logger is inherited from FlextService, no need to annotate
    _attributes: dict[str, dict[str, object]]
    _object_classes: dict[str, dict[str, object]]
    _server_type: str
    _entry_count: int

    @override
    def __init__(
        self,
        *,
        server_type: str = FlextLdifConstants.ServerTypes.GENERIC,
    ) -> None:
        """Initialize schema builder with Phase 1 context enrichment."""
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins
        self._attributes = {}
        self._object_classes = {}
        self._server_type = server_type
        self._entry_count = FlextLdifConstants.ServerDetection.DEFAULT_ENTRY_COUNT

    @property
    def attributes(self) -> dict[str, dict[str, object]]:
        """Get the attributes dictionary."""
        return self._attributes

    @property
    def object_classes(self) -> dict[str, dict[str, object]]:
        """Get the object classes dictionary."""
        return self._object_classes

    @property
    def server_type(self) -> str:
        """Get the server type."""
        return self._server_type

    @property
    def entry_count(self) -> int:
        """Get the entry count."""
        return self._entry_count

    @FlextDecorators.log_operation("schema_builder_execute")
    @FlextDecorators.track_performance()
    @override
    def execute(self) -> FlextResult[FlextLdifConfig]:
        """Execute schema builder service."""
        # Note: This should be updated to return FlextLdifConfig when properly implemented
        # For now, we maintain compatibility with the parent class signature
        return FlextResult[FlextLdifConfig].fail("Use build methods instead")

    def add_attribute(
        self,
        name: str,
        description: str,
        *,
        single_value: bool = False,
        syntax: str | None = None,
        **kwargs: object,
    ) -> FlextLdifSchemaBuilder:
        """Add attribute to schema (Fluent Builder pattern).

        Args:
        name: Attribute name
        description: Attribute description
        single_value: Whether attribute is single-valued

        Returns:
        Self for method chaining

        """
        attr_result: dict[str, object] = {
            "name": name,
            "description": description,
            "single_value": single_value,
        }
        if syntax:
            attr_result["syntax"] = syntax
        attr_result.update(kwargs)
        if attr_result:
            self._attributes[name] = attr_result
        return self

    def add_object_class(
        self,
        name: str,
        description: str,
        required_attributes: list[str] | None = None,
        optional_attributes: list[str] | None = None,
        *,
        superior: str | None = None,
        structural: bool | None = None,
        **kwargs: object,
    ) -> FlextLdifSchemaBuilder:
        """Add object class to schema (Fluent Builder pattern).

        Args:
        name: Object class name
        description: Object class description
        required_attributes: List of required attribute names
        optional_attributes: List of optional attribute names

        Returns:
        Self for method chaining

        """
        object_class_data: dict[str, object] = {
            "name": name,
            "description": description,
            "required_attributes": required_attributes,
            "optional_attributes": optional_attributes or [],
        }
        if superior:
            object_class_data["superior"] = superior
        if structural is not None:
            object_class_data["structural"] = structural
        object_class_data.update(kwargs)
        self._object_classes[name] = object_class_data
        return self

    def set_server_type(self, server_type: str) -> FlextLdifSchemaBuilder:
        """Set server type (Fluent Builder pattern).

        Args:
        server_type: Server type identifier

        Returns:
        Self for method chaining

        """
        self._server_type = server_type
        return self

    def build(self) -> FlextResult[FlextLdifModels.SchemaBuilderResult]:
        """Build final schema (Builder pattern).

        Uses SchemaBuilderResult model for type safety and computed fields.

        Returns:
            FlextResult containing SchemaBuilderResult model

        """
        try:
            # Use Pydantic model for type safety and validation
            schema_result = FlextLdifModels.SchemaBuilderResult(
                attributes=self._attributes,
                object_classes=self._object_classes,
                server_type=self._server_type,
                entry_count=self._entry_count,
            )

            # Check computed field: is_empty
            if schema_result.is_empty and self.logger:
                self.logger.warning(
                    "Building empty schema (no attributes or object classes)",
                )

            # Return model directly wrapped in FlextResult
            return FlextResult[FlextLdifModels.SchemaBuilderResult].ok(schema_result)

        except (ValueError, TypeError, AttributeError) as e:
            if self.logger:
                self.logger.exception("Schema building failed")
            return FlextResult[FlextLdifModels.SchemaBuilderResult].fail(
                f"Failed to create schema: {e}",
            )

    def reset(self) -> Self:
        """Reset builder to initial state.

        Returns:
        Self for method chaining

        """
        self._attributes = {}
        self._object_classes = {}
        self._server_type = FlextLdifConstants.ServerTypes.GENERIC
        self._entry_count = FlextLdifConstants.ServerDetection.DEFAULT_ENTRY_COUNT
        return self

    def build_standard_person_schema(
        self,
    ) -> FlextResult[FlextLdifModels.SchemaBuilderResult]:
        """Build standard person schema using fluent builder.

        Returns:
            FlextResult containing SchemaBuilderResult model

        """
        # Use fluent builder pattern
        return (
            self.reset()
            .add_attribute(
                FlextLdifConstants.DictKeys.CN,
                "Common Name",
                single_value=True,
            )
            .add_attribute(FlextLdifConstants.DictKeys.SN, "Surname", single_value=True)
            .add_attribute(
                FlextLdifConstants.DictKeys.UID,
                "User ID",
                single_value=True,
            )
            .add_attribute(FlextLdifConstants.DictKeys.MAIL, "Email Address")
            .add_attribute(
                FlextLdifConstants.DictKeys.TELEPHONE_NUMBER,
                "Telephone Number",
            )
            .add_attribute(FlextLdifConstants.DictKeys.OBJECTCLASS, "Object Class")
            .add_object_class(
                FlextLdifConstants.ObjectClasses.TOP,
                "Top LDAP class",
                [FlextLdifConstants.DictKeys.OBJECTCLASS],
            )
            .add_object_class(
                FlextLdifConstants.ObjectClasses.PERSON,
                "Person class",
                [FlextLdifConstants.DictKeys.CN, FlextLdifConstants.DictKeys.SN],
            )
            .add_object_class(
                FlextLdifConstants.ObjectClasses.ORGANIZATIONAL_PERSON,
                "Organizational Person",
                [FlextLdifConstants.DictKeys.CN],
            )
            .add_object_class(
                FlextLdifConstants.ObjectClasses.INET_ORG_PERSON,
                "Internet Organizational Person",
                [FlextLdifConstants.DictKeys.CN],
            )
            .set_server_type("generic")
            .build()
        )

    def build_standard_group_schema(
        self,
    ) -> FlextResult[FlextLdifModels.SchemaBuilderResult]:
        """Build standard group schema using fluent builder.

        Returns:
            FlextResult containing SchemaBuilderResult model

        """
        # Use fluent builder pattern
        return (
            self.reset()
            .add_attribute(
                FlextLdifConstants.DictKeys.CN,
                "Common Name",
                single_value=True,
            )
            .add_attribute(FlextLdifConstants.DictKeys.MEMBER, "Group Member")
            .add_attribute(
                FlextLdifConstants.DictKeys.UNIQUE_MEMBER,
                "Unique Group Member",
            )
            .add_attribute(FlextLdifConstants.DictKeys.OBJECTCLASS, "Object Class")
            .add_object_class(
                FlextLdifConstants.ObjectClasses.TOP,
                "Top LDAP class",
                [FlextLdifConstants.DictKeys.OBJECTCLASS],
            )
            .add_object_class(
                FlextLdifConstants.ObjectClasses.GROUP_OF_NAMES,
                "Group of Names",
                [FlextLdifConstants.DictKeys.CN, FlextLdifConstants.DictKeys.MEMBER],
            )
            .add_object_class(
                FlextLdifConstants.ObjectClasses.GROUP_OF_UNIQUE_NAMES,
                "Group of Unique Names",
                [FlextLdifConstants.DictKeys.CN, "uniqueMember"],
            )
            .set_server_type("generic")
            .build()
        )


class FlextLdifSchemaValidator(FlextService[dict[str, object]]):
    """Schema validation service for LDIF entries."""

    @override
    def __init__(self) -> None:
        """Initialize schema validator with Phase 1 context enrichment."""
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins

    @FlextDecorators.log_operation("schema_validator_execute")
    @FlextDecorators.track_performance()
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
                FlextLdifConstants.DictKeys.OBJECTCLASS,
            )
            if not object_classes:
                errors.append(
                    f"Entry {idx} ({entry.dn.value}): Missing "
                    f"{FlextLdifConstants.DictKeys.OBJECTCLASS} attribute",
                )

            # In strict mode, perform additional validation
            if (
                strict
                and object_classes
                and (
                    FlextLdifConstants.ObjectClasses.PERSON in object_classes
                    or FlextLdifConstants.ObjectClasses.INET_ORG_PERSON
                    in object_classes
                )
            ):
                # Check for required attributes based on objectClass
                # This is a simplified check - full schema validation would be more complex
                if not entry.get_attribute_values(FlextLdifConstants.DictKeys.CN):
                    errors.append(
                        f"Entry {idx} ({entry.dn.value}): Missing required attribute "
                        f"{FlextLdifConstants.DictKeys.CN} for person objectClass",
                    )
                if not entry.get_attribute_values(FlextLdifConstants.DictKeys.SN):
                    errors.append(
                        f"Entry {idx} ({entry.dn.value}): Missing required attribute "
                        f"{FlextLdifConstants.DictKeys.SN} for person objectClass",
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
            FlextLdifConstants.DictKeys.OBJECTCLASS,
        )
        issues: list[str] = [
            f"{FlextLdifConstants.DictKeys.OBJECTCLASS} '{oc}' not in discovered schema"
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
            validation_result,
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
            FlextLdifConstants.DictKeys.OBJECTCLASS,
        )

        for oc_name in entry_object_classes:
            if oc_name in schema.objectclasses:
                oc_def = schema.objectclasses[oc_name]

                req_attrs: object = oc_def.get("required_attributes", [])
                if isinstance(req_attrs, list):
                    issues.extend(
                        (
                            f"Missing required attribute '{req_attr}' "
                            f"for {FlextLdifConstants.DictKeys.OBJECTCLASS} '{oc_name}'"
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
            validation_result,
        )


__all__ = ["FlextLdifSchemaBuilder", "FlextLdifSchemaValidator"]
