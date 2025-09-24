"""FLEXT LDIF Schemas Coordinator.

Unified schema management coordinator using flext-core paradigm with nested operation classes.
"""

from typing import Any, ClassVar

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels
from flext_ldif.schema import (
    FlextLdifObjectClassManager,
    FlextLdifSchemaBuilder,
    FlextLdifSchemaExtractor,
    FlextLdifSchemaValidator,
)


class FlextLdifSchemas(FlextService):
    """Unified schema management coordinator following flext-core single class paradigm."""

    model_config: ClassVar[dict[str, Any]] = {"arbitrary_types_allowed": True, "validate_assignment": False, "extra": "allow"}

    class Extractor:
        """Nested class for schema extraction operations."""

        def __init__(self, parent: "FlextLdifSchemas") -> None:
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

        def __init__(self, parent: "FlextLdifSchemas") -> None:
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
            return self._validator.validate_objectclass_requirements(
                object_class_name, schema
            )

    class Builder:
        """Nested class for schema building operations."""

        def __init__(self, parent: "FlextLdifSchemas") -> None:
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

        def __init__(self, parent: "FlextLdifSchemas") -> None:
            """Initialize objectclass manager with parent coordinator reference."""
            self._parent = parent
            self._manager = FlextLdifObjectClassManager()
            self._logger = FlextLogger(__name__)

        def get_hierarchy(
            self, object_class_name: str
        ) -> FlextResult[list[str]]:
            """Get objectclass inheritance hierarchy."""
            return self._manager.get_objectclass_hierarchy(object_class_name)

        def get_required_attributes(
            self, object_class_names: list[str]
        ) -> FlextResult[list[str]]:
            """Get required attributes for objectclasses."""
            return self._manager.get_required_attributes_for_objectclasses(
                object_class_names
            )

        def get_definition(
            self, object_class_name: str
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Get objectclass definition."""
            return self._manager.get_objectclass_definition(object_class_name)

        def validate_combination(
            self, object_class_names: list[str]
        ) -> FlextResult[bool]:
            """Validate objectclass combination compatibility."""
            return self._manager.validate_objectclass_combination(object_class_names)

    def __init__(self) -> None:
        """Initialize schema coordinator with nested operation classes."""
        super().__init__()
        self._logger = FlextLogger(__name__)

        self.extractor = self.Extractor(self)
        self.validator = self.Validator(self)
        self.builder = self.Builder(self)
        self.objectclass = self.ObjectClassManager(self)

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute health check - required by FlextService."""
        return FlextResult[dict[str, object]].ok(
            {
                "status": "healthy",
                "service": "FlextLdifSchemas",
                "operations": ["extractor", "validator", "builder", "objectclass"],
            }
        )


__all__ = ["FlextLdifSchemas"]
