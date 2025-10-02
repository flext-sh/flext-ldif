"""Schema builder module for LDIF processing."""

from __future__ import annotations

from typing import Self, override

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels


class FlextLdifSchemaBuilder(FlextService[FlextLdifModels.SchemaDiscoveryResult]):
    """Schema builder for standard LDAP schemas using Builder pattern.

    Provides fluent interface for building schemas step-by-step following
    SchemaBuilderProtocol for extensibility.
    """

    # Type annotations for instance variables
    _logger: FlextLogger
    _attributes: dict[str, FlextLdifModels.SchemaAttribute]
    _object_classes: dict[str, FlextLdifModels.SchemaObjectClass]
    _server_type: str
    _entry_count: int

    @override
    def __init__(self) -> None:
        """Initialize schema builder."""
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._attributes = {}
        self._object_classes = {}
        self._server_type = "generic"
        self._entry_count = 0

    @property
    def logger(self) -> FlextLogger:
        """Get the logger instance."""
        return self._logger

    @property
    def attributes(self) -> dict[str, FlextLdifModels.SchemaAttribute]:
        """Get the attributes dictionary."""
        return self._attributes

    @property
    def object_classes(self) -> dict[str, FlextLdifModels.SchemaObjectClass]:
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

    @override
    def execute(self) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Execute schema builder service."""
        return self.build_standard_person_schema()

    def add_attribute(
        self, name: str, description: str, *, single_value: bool = False
    ) -> FlextLdifSchemaBuilder:
        """Add attribute to schema (Fluent Builder pattern).

        Args:
            name: Attribute name
            description: Attribute description
            single_value: Whether attribute is single-valued

        Returns:
            Self for method chaining

        """
        attr_result = FlextLdifModels.SchemaAttribute.create(
            name=name,
            description=description,
            single_value=single_value,
        )
        if attr_result.is_success and isinstance(
            attr_result.value, FlextLdifModels.SchemaAttribute
        ):
            self._attributes[name] = attr_result.value
        return self

    def add_object_class(
        self, name: str, description: str, required_attributes: list[str]
    ) -> FlextLdifSchemaBuilder:
        """Add object class to schema (Fluent Builder pattern).

        Args:
            name: Object class name
            description: Object class description
            required_attributes: List of required attribute names

        Returns:
            Self for method chaining

        """
        oc_result = FlextLdifModels.SchemaObjectClass.create(
            name=name,
            description=description,
            required_attributes=required_attributes,
        )
        if oc_result.is_success and isinstance(
            oc_result.value, FlextLdifModels.SchemaObjectClass
        ):
            self._object_classes[name] = oc_result.value
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

    def build(self) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Build final schema (Builder pattern).

        Returns:
            FlextResult containing built schema

        """
        result = FlextLdifModels.SchemaDiscoveryResult.create(
            attributes=self._attributes,
            object_classes=self._object_classes,
            server_type=self._server_type,
            entry_count=self._entry_count,
        )
        if result.is_success and isinstance(
            result.value, FlextLdifModels.SchemaDiscoveryResult
        ):
            return FlextResult[FlextLdifModels.SchemaDiscoveryResult].ok(result.value)
        return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
            result.error or "Failed to create schema"
        )

    def reset(self) -> Self:
        """Reset builder to initial state.

        Returns:
            Self for method chaining

        """
        self._attributes = {}
        self._object_classes = {}
        self._server_type = "generic"
        self._entry_count = 0
        return self

    def build_standard_person_schema(
        self,
    ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Build standard person schema using fluent builder.

        Returns:
            FlextResult containing person schema

        """
        # Use fluent builder pattern
        return (
            self.reset()
            .add_attribute("cn", "Common Name", single_value=True)
            .add_attribute("sn", "Surname", single_value=True)
            .add_attribute("uid", "User ID", single_value=True)
            .add_attribute("mail", "Email Address")
            .add_attribute("telephoneNumber", "Telephone Number")
            .add_attribute("objectClass", "Object Class")
            .add_object_class("top", "Top LDAP class", ["objectClass"])
            .add_object_class("person", "Person class", ["cn", "sn"])
            .add_object_class("organizationalPerson", "Organizational Person", ["cn"])
            .add_object_class("inetOrgPerson", "Internet Organizational Person", ["cn"])
            .set_server_type("generic")
            .build()
        )

    def build_standard_group_schema(
        self,
    ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Build standard group schema using fluent builder.

        Returns:
            FlextResult containing group schema

        """
        # Use fluent builder pattern
        return (
            self.reset()
            .add_attribute("cn", "Common Name", single_value=True)
            .add_attribute("member", "Group Member")
            .add_attribute("uniqueMember", "Unique Group Member")
            .add_attribute("objectClass", "Object Class")
            .add_object_class("top", "Top LDAP class", ["objectClass"])
            .add_object_class("groupOfNames", "Group of Names", ["cn", "member"])
            .add_object_class(
                "groupOfUniqueNames", "Group of Unique Names", ["cn", "uniqueMember"]
            )
            .set_server_type("generic")
            .build()
        )


__all__ = ["FlextLdifSchemaBuilder"]
