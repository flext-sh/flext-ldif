"""Schemas coordinator module for LDIF processing."""

from __future__ import annotations

from typing import override

from pydantic import ConfigDict

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels
from flext_ldif.schema import (
    FlextLdifObjectClassManager,
    FlextLdifSchemaBuilder,
    FlextLdifSchemaExtractor,
    FlextLdifSchemaValidator,
)


class FlextLdifSchemas(FlextService[dict[str, object]]):
    """Unified schema management coordinator following flext-core single class paradigm.

    Provides comprehensive schema management operations including extraction,
    validation, building, and management of LDAP schemas and object classes.
    """

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=False,
        extra="allow",
    )

    class Extractor:
        """Nested class for schema extraction operations."""

        @override
        def __init__(self, parent: FlextLdifSchemas) -> None:
            """Initialize schema extractor with parent coordinator reference."""
            self._parent = parent
            self._extractor = FlextLdifSchemaExtractor()
            self._logger = FlextLogger(__name__)

        def extract_from_entries(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
            """Extract schema from LDIF entries."""
            return self._extractor.extract_from_entries(entries)

        def extract_attributes(
            self, entries: list[FlextLdifModels.Entry]
        ) -> FlextResult[dict[str, dict[str, object]]]:
            """Extract attribute usage statistics from entries."""
            return self._extractor.extract_attribute_usage(entries)

    class Validator:
        """Nested class for schema validation operations."""

        @override
        def __init__(self, parent: FlextLdifSchemas) -> None:
            """Initialize schema validator with parent coordinator reference."""
            self._parent = parent
            self._validator = FlextLdifSchemaValidator()
            self._logger = FlextLogger(__name__)

        def validate_entry(
            self,
            entry: FlextLdifModels.Entry,
            schema: FlextLdifModels.SchemaDiscoveryResult,
        ) -> FlextResult[dict[str, object]]:
            """Validate entry against schema."""
            return self._validator.validate_entry_against_schema(entry, schema)

        def validate_objectclass(
            self, object_class_name: str, schema: FlextLdifModels.SchemaDiscoveryResult
        ) -> FlextResult[dict[str, object]]:
            """Validate objectclass requirements."""
            # Create a minimal entry for validation
            entry_data: dict[str, object] = {
                "dn": f"cn={object_class_name},cn=schema",
                "attributes": {"objectClass": [object_class_name]},
            }
            entry_result = FlextLdifModels.Entry.create(
                dn=entry_data["dn"], attributes=entry_data["attributes"]
            )
            if entry_result.is_failure:
                return FlextResult[dict[str, object]].fail(
                    f"Failed to create validation entry: {entry_result.error}"
                )

            return self._validator.validate_objectclass_requirements(
                entry_result.value, schema
            )

    class Builder:
        """Nested class for schema building operations."""

        @override
        def __init__(self, parent: FlextLdifSchemas) -> None:
            """Initialize schema builder with parent coordinator reference."""
            self._parent = parent
            self._builder = FlextLdifSchemaBuilder()
            self._logger = FlextLogger(__name__)

        def build_standard_person(
            self,
        ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
            """Build standard person schema."""
            return self._builder.build_standard_person_schema()

        def build_standard_group(
            self,
        ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
            """Build standard group schema."""
            return self._builder.build_standard_group_schema()

    class ObjectClassManager:
        """Nested class for objectclass management operations."""

        @override
        def __init__(self, parent: FlextLdifSchemas) -> None:
            """Initialize objectclass manager with parent coordinator reference."""
            self._parent = parent
            self._manager = FlextLdifObjectClassManager()
            self._logger = FlextLogger(__name__)

        def get_hierarchy(self, object_class_name: str) -> FlextResult[list[str]]:
            """Get objectclass inheritance hierarchy."""
            # Create a minimal schema for hierarchy resolution
            schema_result = FlextLdifModels.SchemaDiscoveryResult.create({})
            if schema_result.is_failure:
                return FlextResult[list[str]].fail(
                    f"Failed to create schema: {schema_result.error}"
                )

            if schema_result.is_success and isinstance(
                schema_result.value, FlextLdifModels.SchemaDiscoveryResult
            ):
                return self._manager.resolve_objectclass_hierarchy(
                    object_class_name, schema_result.value
                )
            return FlextResult[list[str]].fail(
                f"Failed to create schema: {schema_result.error}"
            )

        def get_required_attributes(
            self, object_class_names: list[str]
        ) -> FlextResult[list[str]]:
            """Get required attributes for objectclasses."""
            # Create a minimal schema for attribute resolution
            schema_result = FlextLdifModels.SchemaDiscoveryResult.create({})
            if schema_result.is_failure:
                return FlextResult[list[str]].fail(
                    f"Failed to create schema: {schema_result.error}"
                )

            if schema_result.is_success and isinstance(
                schema_result.value, FlextLdifModels.SchemaDiscoveryResult
            ):
                return self._manager.get_all_required_attributes(
                    object_class_names, schema_result.value
                )
            return FlextResult[list[str]].fail(
                f"Failed to create schema: {schema_result.error}"
            )

        def get_definition(
            self, object_class_name: str
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Get objectclass definition."""
            # Create a minimal schema for definition lookup
            schema_result = FlextLdifModels.SchemaDiscoveryResult.create({})
            if schema_result.is_failure:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"Failed to create schema: {schema_result.error}"
                )

            if schema_result.is_success and isinstance(
                schema_result.value, FlextLdifModels.SchemaDiscoveryResult
            ):
                # Get objectclass definition from schema
                if object_class_name in schema_result.value.object_classes:
                    oc_def = schema_result.value.object_classes[object_class_name]
                    return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc_def)
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"ObjectClass '{object_class_name}' not found in schema"
                )
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"Failed to create schema: {schema_result.error}"
            )

        def validate_combination(
            self, object_class_names: list[str]
        ) -> FlextResult[bool]:
            """Validate objectclass combination compatibility."""
            # Create a minimal schema for combination validation
            schema_result = FlextLdifModels.SchemaDiscoveryResult.create({})
            if schema_result.is_failure:
                return FlextResult[bool].fail(
                    f"Failed to create schema: {schema_result.error}"
                )

            if schema_result.is_success and isinstance(
                schema_result.value, FlextLdifModels.SchemaDiscoveryResult
            ):
                result = self._manager.validate_objectclass_combination(
                    object_class_names, schema_result.value
                )
                if result.is_success:
                    # Extract boolean from result
                    validation_data = result.value
                    is_valid: bool = (
                        bool(validation_data.get("valid", False))
                        if isinstance(validation_data, dict)
                        else False
                    )
                    return FlextResult[bool].ok(is_valid)
                return FlextResult[bool].fail(result.error or "Validation failed")
            return FlextResult[bool].fail(
                f"Failed to create schema: {schema_result.error}"
            )

    @override
    def __init__(self) -> None:
        """Initialize schema coordinator with nested operation classes."""
        super().__init__()
        self._logger = FlextLogger(__name__)

        self.extractor = self.Extractor(self)
        self.validator = self.Validator(self)
        self.builder = self.Builder(self)
        self.objectclass = self.ObjectClassManager(self)

    @override
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute health check - required by FlextService."""
        return FlextResult[dict[str, object]].ok({
            "status": "healthy",
            "service": FlextLdifSchemas,
            "operations": ["extractor", "validator", "builder", "objectclass"],
        })

    async def execute_async(self) -> FlextResult[dict[str, object]]:
        """Execute health check - required by FlextService."""
        return FlextResult[dict[str, object]].ok({
            "status": "healthy",
            "service": FlextLdifSchemas,
            "operations": ["extractor", "validator", "builder", "objectclass"],
        })


__all__ = ["FlextLdifSchemas"]
