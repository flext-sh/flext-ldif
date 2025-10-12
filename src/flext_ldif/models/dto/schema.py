"""Schema DTO models for attributes and object classes."""

from __future__ import annotations

from flext_core import FlextCore
from pydantic import Field


class SchemaAttribute(FlextCore.Models.Value):
    """LDAP schema attribute definition model.

    Represents an LDAP attribute type definition from schema.
    """

    model_config = {"frozen": True}

    name: str = Field(..., description="Attribute name")
    oid: str = Field(..., description="Attribute OID")
    description: str | None = Field(None, description="Attribute description")
    syntax: str = Field(..., description="Attribute syntax OID")
    single_value: bool = Field(
        default=False, description="Whether attribute is single-valued"
    )
    no_user_modification: bool = Field(
        default=False, description="Whether users can modify this attribute"
    )

    @classmethod
    def create(
        cls,
        name: str,
        oid: str,
        syntax: str,
        description: str | None = None,
        single_value: bool = False,
        no_user_modification: bool = False,
    ) -> FlextCore.Result[SchemaAttribute]:
        """Create a SchemaAttribute instance with validation."""
        try:
            return FlextCore.Result[SchemaAttribute].ok(
                cls(
                    name=name,
                    oid=oid,
                    syntax=syntax,
                    description=description,
                    single_value=single_value,
                    no_user_modification=no_user_modification,
                )
            )
        except Exception as e:
            return FlextCore.Result[SchemaAttribute].fail(
                f"Invalid schema attribute: {e}"
            )


class SchemaObjectClass(FlextCore.Models.Value):
    """LDAP schema object class definition model.

    Represents an LDAP object class definition from schema.
    """

    model_config = {"frozen": True}

    name: str = Field(..., description="Object class name")
    oid: str = Field(..., description="Object class OID")
    description: str | None = Field(None, description="Object class description")
    required_attributes: list[str] = Field(
        default_factory=list, description="Required attributes"
    )
    optional_attributes: list[str] = Field(
        default_factory=list, description="Optional attributes"
    )
    structural: bool = Field(
        default=True, description="Whether this is a structural object class"
    )
    auxiliary: bool = Field(
        default=False, description="Whether this is an auxiliary object class"
    )
    abstract: bool = Field(
        default=False, description="Whether this is an abstract object class"
    )

    @classmethod
    def create(
        cls,
        name: str,
        oid: str,
        description: str | None = None,
        required_attributes: list[str] | None = None,
        optional_attributes: list[str] | None = None,
        structural: bool = True,
        auxiliary: bool = False,
        abstract: bool = False,
    ) -> FlextCore.Result[SchemaObjectClass]:
        """Create a SchemaObjectClass instance with validation."""
        try:
            return FlextCore.Result[SchemaObjectClass].ok(
                cls(
                    name=name,
                    oid=oid,
                    description=description,
                    required_attributes=required_attributes or [],
                    optional_attributes=optional_attributes or [],
                    structural=structural,
                    auxiliary=auxiliary,
                    abstract=abstract,
                )
            )
        except Exception as e:
            return FlextCore.Result[SchemaObjectClass].fail(
                f"Invalid schema object class: {e}"
            )
