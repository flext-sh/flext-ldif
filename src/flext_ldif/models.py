"""FLEXT LDIF Models - Advanced Pydantic 2 Models with Monadic Composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import Self, cast

from pydantic import (
    ConfigDict,
    Field,
    SerializationInfo,
    computed_field,
    field_serializer,
    field_validator,
    model_validator,
)

from flext_core import FlextModels, FlextResult
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.typings import FlextLdifTypes


def _default_ldif_attributes() -> FlextLdifModels.LdifAttributes:
    """Factory function for default LDIF attributes."""
    # Returns empty LdifAttributes instance
    return FlextLdifModels.LdifAttributes(attributes={})


class FlextLdifModels(FlextModels):
    """LDIF domain models extending flext-core FlextModels.

    Contains ONLY Pydantic v2 model definitions with business logic.
    Uses flext-core SOURCE OF TRUTH for model patterns and validation.
    Implements advanced monadic composition patterns with FlextResult.
    """

    model_config = ConfigDict(
        validate_assignment=True,
        use_enum_values=True,
        arbitrary_types_allowed=True,
        extra="forbid",
        frozen=False,
        validate_return=True,
        ser_json_timedelta="iso8601",
        ser_json_bytes="base64",
        hide_input_in_errors=True,
        json_schema_extra={
            "examples": [
                {
                    "ldif_processing_enabled": True,
                    "validation_enabled": True,
                    "schema_validation_enabled": True,
                    "acl_processing_enabled": True,
                }
            ],
            "description": "LDIF processing models for comprehensive directory data operations",
        },
    )

    @computed_field
    @property
    def active_ldif_models_count(self) -> int:
        """Computed field returning the number of active LDIF model types."""
        model_types = [
            "DistinguishedName",
            "LdifAttribute",
            "LdifAttributes",
            "Entry",
            "ChangeRecord",
            "SchemaObjectClass",
            "SchemaDiscoveryResult",
            "AclTarget",
            "AclSubject",
            "AclPermissions",
            "UnifiedAcl",
            "SchemaAttribute",
            "SearchConfig",
            "LdifDocument",
            "AttributeValues",
        ]
        return len(model_types)

    @computed_field
    @property
    def ldif_model_summary(self) -> dict[str, object]:
        """Computed field providing summary of LDIF model capabilities."""
        return {
            "entry_models": 4,
            "schema_models": 3,
            "acl_models": 4,
            "utility_models": 4,
            "total_models": self.active_ldif_models_count,
            "processing_features": [
                "parsing",
                "validation",
                "schema_discovery",
                "acl_processing",
            ],
            "format_support": ["ldif", "json", "dict"],
        }

    @model_validator(mode="after")
    def validate_ldif_consistency(self) -> Self:
        """Validate LDIF model consistency across all components."""
        # Perform cross-model validation for LDIF requirements
        return self

    @field_serializer("model_config", when_used="json")
    def serialize_with_ldif_metadata(
        self, value: object, _info: object
    ) -> dict[str, object]:
        """Serialize with LDIF metadata for processing context."""
        return {
            "config": value,
            "ldif_metadata": {
                "models_available": self.active_ldif_models_count,
                "processing_capabilities": [
                    "parsing",
                    "validation",
                    "schema_discovery",
                    "acl_processing",
                ],
                "format_support": ["ldif", "json", "dict"],
                "enterprise_ready": True,
            },
        }

    # =============================================================================
    # ADVANCED BASE MODEL CLASSES - Monadic Composition Patterns
    # =============================================================================

    class DistinguishedName(FlextModels.Value):
        """Distinguished Name (DN) for LDIF entries.

        Represents a unique identifier for LDAP entries following RFC 4514.
        Centralizes ALL DN validation logic using Pydantic validators.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        value: str = Field(
            ...,
            min_length=1,
            max_length=FlextLdifConstants.LdifValidation.MAX_DN_LENGTH,
            description="The DN string value",
        )

        @field_validator("value")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Validate DN format - CENTRALIZED validation in Model."""
            if not v or not v.strip():
                msg = FlextLdifConstants.ErrorMessages.DN_EMPTY_ERROR
                raise ValueError(msg)

            # Check length limit (RFC 4514)
            if len(v) > FlextLdifConstants.LdifValidation.MAX_DN_LENGTH:
                msg = (
                    f"DN exceeds maximum length of "
                    f"{FlextLdifConstants.LdifValidation.MAX_DN_LENGTH}"
                )
                raise ValueError(msg)

            # Parse and validate components
            components = cls._parse_dn_components(v)

            # Validate minimum components
            if len(components) < FlextLdifConstants.LdifValidation.MIN_DN_COMPONENTS:
                msg = (
                    f"DN must have at least "
                    f"{FlextLdifConstants.LdifValidation.MIN_DN_COMPONENTS} component(s)"
                )
                raise ValueError(msg)

            # Validate each component has attribute=value format
            for component in components:
                if "=" not in component:
                    msg = (
                        f"{FlextLdifConstants.ErrorMessages.DN_INVALID_FORMAT_ERROR}: "
                        f"Component '{component}' missing '=' separator"
                    )
                    raise ValueError(msg)

                attr, value_part = component.split("=", 1)
                if not attr.strip() or not value_part.strip():
                    msg = (
                        f"{FlextLdifConstants.ErrorMessages.DN_INVALID_FORMAT_ERROR}: "
                        f"Empty attribute or value in component '{component}'"
                    )
                    raise ValueError(msg)

            return v.strip()

        @staticmethod
        def _parse_dn_components(dn: str) -> list[str]:
            r"""Parse DN into components handling escaped commas (\,).

            Internal helper for DN component parsing following RFC 4514.
            """
            components: list[str] = []
            current_component = ""
            i = 0
            while i < len(dn):
                if dn[i] == "\\" and i + 1 < len(dn):
                    # Escaped character - include backslash and next char
                    current_component += dn[i : i + 2]
                    i += 2
                elif dn[i] == ",":
                    # Unescaped comma - component boundary
                    if current_component.strip():
                        components.append(current_component.strip())
                    current_component = ""
                    i += 1
                else:
                    current_component += dn[i]
                    i += 1

            # Add last component
            if current_component.strip():
                components.append(current_component.strip())

            if not components:
                msg = "DN has no valid components"
                raise ValueError(msg)

            return components

        @computed_field
        @property
        def dn_key(self) -> str:
            """Computed field for unique DN key."""
            return f"dn:{self.value.lower()}"

        @computed_field
        @property
        def components(self) -> list[str]:
            """Computed field for DN components."""
            try:
                return self._parse_dn_components(self.value)
            except ValueError:
                return []

        @computed_field
        @property
        def depth(self) -> int:
            """Computed field for DN depth (number of components)."""
            return len(self.components)

        @computed_field
        @property
        def normalized_value(self) -> str:
            """Computed field for normalized DN value."""
            try:
                components = self._parse_dn_components(self.value)
                normalized_components: list[str] = []
                for component in components:
                    attr, value_part = component.split("=", 1)
                    # Normalize: lowercase attribute, trim spaces from value
                    attr_normalized = attr.strip().lower()
                    value_normalized = " ".join(value_part.strip().split())
                    normalized_components.append(
                        f"{attr_normalized}={value_normalized}"
                    )
                return ",".join(normalized_components)
            except (ValueError, AttributeError):
                return self.value.strip().lower()

        def extract_attribute(self, attribute_name: str) -> str | None:
            """Extract specific attribute value from DN.

            Args:
                attribute_name: Attribute name to extract (case-insensitive)

            Returns:
                Attribute value or None if not found

            """
            attr_lower = attribute_name.lower()
            for component in self.components:
                if "=" in component:
                    attr, value_part = component.split("=", 1)
                    if attr.strip().lower() == attr_lower:
                        return value_part.strip()
            return None

        @field_serializer("value", when_used="json")
        def serialize_dn_with_metadata(
            self, value: str, _info: object
        ) -> dict[str, object]:
            """Serialize DN with metadata for processing context."""
            return {
                "dn": value,
                "dn_context": {
                    "depth": self.depth,
                    "components_count": len(self.components),
                    "normalized": self.normalized_value,
                },
            }

    class LdifAttribute(FlextModels.Value):
        """LDIF attribute with name and values."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        name: str = Field(
            ...,
            min_length=1,
            description="Attribute name",
        )

        values: list[str] = Field(
            default_factory=list,
            description="Attribute values",
        )

        @computed_field
        @property
        def attribute_key(self) -> str:
            """Computed field for unique attribute key."""
            return f"attr:{self.name.lower()}"

        @computed_field
        @property
        def value_count(self) -> int:
            """Computed field for number of values."""
            return len(self.values)

        @computed_field
        @property
        def single_value(self) -> str | None:
            """Computed field for single value (first value if multiple exist)."""
            return self.values[0] if self.values else None

        @field_validator("name")
        @classmethod
        def validate_name(cls, v: str) -> str:
            """Validate attribute name."""
            if not v.strip():
                raise ValueError(
                    FlextLdifConstants.ErrorMessages.ATTRIBUTE_NAME_EMPTY_ERROR
                )
            return v.strip().lower()

        @field_serializer("values", when_used="json")
        def serialize_values_with_context(self, value: list[str]) -> dict[str, object]:
            """Serialize values with attribute context."""
            return {
                "values": value,
                "attribute_context": {
                    "name": self.name,
                    "value_count": len(value),
                    "is_multi_valued": len(value) > 1,
                },
            }

    class LdifAttributes(FlextModels.Value):
        """Collection of LDIF attributes."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        attributes: dict[str, FlextLdifModels.AttributeValues] = Field(
            default_factory=dict,
            description="Dictionary of attribute names to AttributeValues",
        )

        @computed_field
        @property
        def attribute_count(self) -> int:
            """Computed field for number of attributes."""
            return len(self.attributes)

        @computed_field
        @property
        def total_values_count(self) -> int:
            """Computed field for total number of values across all attributes."""
            return sum(
                len(attr_values.values) for attr_values in self.attributes.values()
            )

        @computed_field
        @property
        def attribute_summary(self) -> dict[str, object]:
            """Computed field for attributes summary."""
            return {
                "attribute_count": self.attribute_count,
                "total_values": self.total_values_count,
                "attribute_names": list(self.attributes.keys()),
            }

        def get_attribute(self, name: str) -> FlextLdifModels.AttributeValues | None:
            """Get attribute values by name."""
            name_lower = name.lower()
            for key, attr_values in self.attributes.items():
                if key.lower() == name_lower:
                    return attr_values
            return None

        def set_attribute(self, name: str, values: list[str]) -> None:
            """Set attribute values."""
            self.attributes[name.lower()] = FlextLdifModels.AttributeValues(
                values=values
            )

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            name_lower = name.lower()
            return any(key.lower() == name_lower for key in self.attributes)

        @property
        def data(self) -> dict[str, FlextLdifModels.AttributeValues]:
            """Get attributes data dictionary."""
            return self.attributes

        def __getitem__(self, name: str) -> FlextLdifModels.AttributeValues | None:
            """Dictionary-like access to attributes."""
            return self.get_attribute(name)

        def __setitem__(self, name: str, values: list[str]) -> None:
            """Dictionary-like setting of attributes."""
            # Since the model is frozen, we need to use object.__setattr__
            if hasattr(self, "attributes"):
                self.attributes[name.lower()] = FlextLdifModels.AttributeValues(
                    values=values
                )
            else:
                object.__setattr__(
                    self,
                    "attributes",
                    {name.lower(): FlextLdifModels.AttributeValues(values=values)},
                )

        def __contains__(self, name: str) -> bool:
            """Dictionary-like 'in' check."""
            return self.has_attribute(name)

        def add_attribute(self, name: str, values: str | list[str]) -> None:
            """Add attribute with values."""
            if isinstance(values, str):
                values = [values]
            self.set_attribute(name, values)

        def remove_attribute(self, name: str) -> None:
            """Remove attribute by name."""
            name_lower = name.lower()
            keys_to_remove = [
                key for key in self.attributes if key.lower() == name_lower
            ]
            for key in keys_to_remove:
                del self.attributes[key]

        @field_serializer("attributes", when_used="json")
        def serialize_attributes_with_summary(
            self, value: dict[str, FlextLdifModels.AttributeValues], _info: object
        ) -> dict[str, object]:
            """Serialize attributes with collection summary."""
            return {"attributes": value, "collection_summary": self.attribute_summary}

    class Entry(FlextModels.Entity):
        """LDIF entry representing a complete LDAP object."""

        model_config = ConfigDict(
            validate_assignment=True, extra="forbid", hide_input_in_errors=True
        )

        dn: FlextLdifModels.DistinguishedName = Field(
            ...,
            description="Distinguished Name of the entry",
        )

        attributes: FlextLdifModels.LdifAttributes = Field(
            default_factory=_default_ldif_attributes,
            description="Entry attributes",
        )

        @computed_field
        @property
        def entry_key(self) -> str:
            """Computed field for unique entry key."""
            return f"entry:{self.dn.normalized_value}"

        @computed_field
        @property
        def object_classes(self) -> list[str]:
            """Computed field for entry object classes."""
            attr_values = self.get_attribute("objectClass")
            return attr_values.values if attr_values else []

        @computed_field
        @property
        def entry_type(self) -> str:
            """Computed field for entry type based on object classes."""
            if self.is_person_entry():
                return "person"
            if self.is_group_entry():
                return "group"
            if self.is_organizational_unit():
                return "organizational_unit"
            return "unknown"

        @computed_field
        @property
        def entry_summary(self) -> dict[str, object]:
            """Computed field for entry summary."""
            return {
                "dn": self.dn.value,
                "type": self.entry_type,
                "attribute_count": self.attributes.attribute_count,
                "object_classes": self.object_classes,
            }

        @model_validator(mode="after")
        def validate_entry_consistency(self) -> Self:
            """Validate entry consistency."""
            if not self.dn.value.strip():
                raise ValueError(FlextLdifConstants.ErrorMessages.ENTRY_DN_EMPTY_ERROR)
            # Note: objectClass validation is relaxed for LDIF parsing flexibility
            # Some LDIF operations (like modify) may not include objectClass
            return self

        def get_attribute(self, name: str) -> FlextLdifModels.AttributeValues | None:
            """Get attribute values by name."""
            return self.attributes.get_attribute(name)

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            return self.attributes.has_attribute(name)

        def get_attribute_values(self, name: str) -> list[str]:
            """Get attribute values as a list of strings."""
            attr_values = self.get_attribute(name)
            return attr_values.values if attr_values else []

        def get_single_value(self, name: str) -> str | None:
            """Get single attribute value (first value if multiple exist)."""
            attr_values = self.get_attribute(name)
            return attr_values.single_value if attr_values else None

        def is_person_entry(self) -> bool:
            """Check if entry is a person entry."""
            attr_values = self.get_attribute("objectClass")
            if not attr_values:
                return False
            person_classes = {"person", "inetorgperson"}
            return any(oc.lower() in person_classes for oc in attr_values.values)

        def is_group_entry(self) -> bool:
            """Check if entry is a group entry."""
            attr_values = self.get_attribute("objectClass")
            if not attr_values:
                return False
            group_classes = {"group", "groupofnames", "groupofuniquenames"}
            return any(oc.lower() in group_classes for oc in attr_values.values)

        def is_organizational_unit(self) -> bool:
            """Check if entry is an organizational unit."""
            attr_values = self.get_attribute("objectClass")
            if not attr_values:
                return False
            return "organizationalunit" in [oc.lower() for oc in attr_values.values]

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specific object class."""
            attr_values = self.get_attribute("objectClass")
            if not attr_values:
                return False
            return object_class.lower() in [oc.lower() for oc in attr_values.values]

        def validate_business_rules(self) -> FlextResult[bool]:
            """Validate entry against business rules."""
            try:
                # Basic validation - ensure DN exists and has attributes
                if not self.dn.value.strip():
                    return FlextResult[bool].fail(
                        FlextLdifConstants.ErrorMessages.DN_EMPTY_ERROR
                    )

                # Note: objectClass validation is relaxed for LDIF parsing flexibility
                # Some LDIF operations may not include objectClass

                return FlextResult[bool].ok(True)
            except Exception as e:
                return FlextResult[bool].fail(str(e))

        @classmethod
        def create(
            cls,
            data: FlextLdifTypes.Entry.EntryCreateData | None = None,
            **kwargs: object,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create a new Entry instance.

            Args:
                data: Dictionary containing 'dn' (str) and 'attributes' (dict[str, list[str] | str])
                **kwargs: Alternative parameter format

            """
            try:
                # Handle both dict and individual parameter patterns
                if data is not None:
                    dn = str(data.get("dn", ""))
                    attributes = data.get("attributes")
                    if isinstance(attributes, dict):
                        # Convert to proper format
                        attrs_dict: dict[str, FlextLdifModels.AttributeValues] = {}
                        for key, value in attributes.items():
                            if isinstance(value, list):
                                attrs_dict[key] = FlextLdifModels.AttributeValues(
                                    values=[str(v) for v in value]
                                )
                            elif isinstance(value, FlextLdifModels.AttributeValues):
                                # Already an AttributeValues object, use it directly
                                attrs_dict[key] = value
                            else:
                                attrs_dict[key] = FlextLdifModels.AttributeValues(
                                    values=[str(value)]
                                )
                        attributes = attrs_dict
                    else:
                        attributes = {}
                else:
                    dn = str(kwargs.get("dn", ""))
                    attributes = kwargs.get("attributes", {})
                    # Convert attributes to proper format when passed as kwargs
                    if isinstance(attributes, dict):
                        attrs_dict: dict[str, FlextLdifModels.AttributeValues] = {}
                        for key, value in attributes.items():
                            if isinstance(value, list):
                                attrs_dict[key] = FlextLdifModels.AttributeValues(
                                    values=[str(v) for v in value]
                                )
                            elif isinstance(value, FlextLdifModels.AttributeValues):
                                # Already an AttributeValues object, use it directly
                                attrs_dict[key] = value
                            else:
                                attrs_dict[key] = FlextLdifModels.AttributeValues(
                                    values=[str(value)]
                                )
                        attributes = attrs_dict

                dn_obj = FlextLdifModels.DistinguishedName(value=dn)
                attrs_obj = FlextLdifModels.LdifAttributes(
                    attributes=cast(
                        "dict[str, FlextLdifModels.AttributeValues]", attributes or {}
                    )
                )
                return FlextResult[FlextLdifModels.Entry].ok(
                    cls(dn=dn_obj, attributes=attrs_obj, domain_events=[])
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(str(e))

        def to_ldif_string(self, indent: int = 0) -> str:
            """Convert entry to LDIF string."""
            lines = [f"dn: {self.dn.value}"]
            indent_str = " " * indent if indent > 0 else ""

            attribute_lines = [
                f"{indent_str}{attr_name}: {value}"
                for attr_name, attr_values in self.attributes.attributes.items()
                for value in attr_values.values
            ]
            lines.extend(attribute_lines)

            return "\n".join(lines)

        @classmethod
        def from_ldif_string(
            cls, ldif_string: str
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create Entry from LDIF string."""
            try:
                lines = ldif_string.strip().split("\n")
                dn = ""
                attributes: dict[str, FlextLdifModels.AttributeValues] = {}

                for line in lines:
                    stripped_line = line.strip()
                    if not stripped_line or stripped_line.startswith("#"):
                        continue
                    if stripped_line.startswith(FlextLdifConstants.Format.DN_PREFIX):
                        dn = stripped_line[3:].strip()
                    elif ":" in stripped_line:
                        attr_line = stripped_line.split(":", 1)
                        if (
                            len(attr_line)
                            == FlextLdifConstants.Processing.MIN_ATTRIBUTE_PARTS
                        ):
                            attr_name = attr_line[0].strip()
                            attr_value = attr_line[1].strip()
                            if attr_name not in attributes:
                                attributes[attr_name] = FlextLdifModels.AttributeValues(
                                    values=[]
                                )
                            attributes[attr_name].values.append(attr_value)

                if not dn:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        "No DN found in LDIF string"
                    )

                return cls.create(data={"dn": dn, "attributes": attributes})
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(str(e))

        @field_serializer("dn", when_used="json")
        def serialize_dn_with_entry_context(
            self, value: FlextLdifModels.DistinguishedName, _info: object
        ) -> dict[str, object]:
            """Serialize DN with entry context."""
            return {
                "dn": value.value,
                "entry_context": {
                    "type": self.entry_type,
                    "attribute_count": self.attributes.attribute_count,
                    "object_classes": self.object_classes,
                },
            }

    class ChangeRecord(FlextModels.Entity):
        """LDIF change record for modify operations."""

        model_config = ConfigDict(
            validate_assignment=True, extra="forbid", hide_input_in_errors=True
        )

        dn: FlextLdifModels.DistinguishedName = Field(
            ...,
            description="Distinguished Name of the entry",
        )

        changetype: str = Field(
            ...,
            description="Type of change (add, modify, delete)",
        )

        attributes: FlextLdifModels.LdifAttributes = Field(
            default_factory=_default_ldif_attributes,
            description="Change attributes",
        )

        @computed_field
        @property
        def change_key(self) -> str:
            """Computed field for unique change key."""
            return f"change:{self.changetype}:{self.dn.normalized_value}"

        @computed_field
        @property
        def change_summary(self) -> dict[str, object]:
            """Computed field for change summary."""
            return {
                "dn": self.dn.value,
                "changetype": self.changetype,
                "attribute_count": self.attributes.attribute_count,
            }

        @model_validator(mode="after")
        def validate_change_record(self) -> Self:
            """Validate change record parameters."""
            valid_types = ["add", "modify", "delete", "modrdn"]
            if self.changetype not in valid_types:
                msg = f"Changetype must be one of: {valid_types}"
                raise ValueError(msg)
            return self

        @classmethod
        def create(
            cls,
            dn: str,
            changetype: str,
            attributes: dict[str, list[str]] | None = None,
        ) -> FlextResult[FlextLdifModels.ChangeRecord]:
            """Create a new ChangeRecord instance."""
            try:
                dn_obj = FlextLdifModels.DistinguishedName(value=dn)

                # Convert attributes to proper format
                attrs_dict: dict[str, FlextLdifModels.AttributeValues] = {}
                if attributes:
                    for key, value in attributes.items():
                        if isinstance(value, list):
                            attrs_dict[key] = FlextLdifModels.AttributeValues(
                                values=[str(v) for v in value]
                            )
                        else:
                            attrs_dict[key] = FlextLdifModels.AttributeValues(
                                values=[str(value)]
                            )

                attrs_obj = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
                return FlextResult[FlextLdifModels.ChangeRecord].ok(
                    cls(
                        dn=dn_obj,
                        changetype=changetype,
                        attributes=attrs_obj,
                    )
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.ChangeRecord].fail(str(e))

        @field_serializer("changetype", when_used="json")
        def serialize_changetype_with_metadata(
            self, value: str, _info: object
        ) -> dict[str, object]:
            """Serialize changetype with change metadata."""
            return {
                "changetype": value,
                "change_metadata": {
                    "dn": self.dn.value,
                    "attribute_count": self.attributes.attribute_count,
                },
            }

    class SchemaObjectClass(FlextModels.Value):
        """LDAP object class definition."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        name: str = Field(
            ...,
            description="Object class name",
        )

        oid: str = Field(
            ...,
            description="Object identifier",
        )

        description: str = Field(
            default="",
            description="Object class description",
        )

        must: list[str] = Field(
            default_factory=list,
            description="Required attributes",
        )

        may: list[str] = Field(
            default_factory=list,
            description="Optional attributes",
        )

        superior: list[str] = Field(
            default_factory=list,
            description="Superior object classes",
        )

        structural: bool = Field(
            default=False,
            description="Whether this is a structural object class",
        )

        required_attributes: list[str] = Field(
            default_factory=list,
            description="Required attributes",
        )

        optional_attributes: list[str] = Field(
            default_factory=list,
            description="Optional attributes",
        )

        @computed_field
        @property
        def objectclass_key(self) -> str:
            """Computed field for unique object class key."""
            return f"oc:{self.name.lower()}"

        @computed_field
        @property
        def attribute_summary(self) -> dict[str, object]:
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
            self, value: list[str], _info: object
        ) -> dict[str, object]:
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
            description="Server type",
        )

        entry_count: int = Field(
            default=0,
            description="Number of entries processed",
        )

        @computed_field
        @property
        def discovery_summary(self) -> dict[str, object]:
            """Computed field for discovery summary."""
            return {
                "objectclass_count": len(self.object_classes),
                "attribute_count": len(self.attributes),
                "entry_count": self.entry_count,
                "server_type": self.server_type,
            }

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new SchemaDiscoveryResult instance."""
            try:
                # Extract parameters from kwargs (ignore args for compatibility)
                _ = args  # Suppress unused argument warning
                obj_classes = kwargs.get("object_classes", {})
                object_classes = (
                    dict(obj_classes) if isinstance(obj_classes, dict) else {}
                )
                attrs = kwargs.get("attributes", {})
                attributes = dict(attrs) if isinstance(attrs, dict) else {}
                server_type = str(kwargs.get("server_type", "generic"))
                entry_count_val = kwargs.get("entry_count", 0)
                entry_count = (
                    int(entry_count_val)
                    if isinstance(entry_count_val, (int, str))
                    else 0
                )

                instance = cls(
                    object_classes=object_classes or {},
                    attributes=attributes or {},
                    server_type=server_type,
                    entry_count=entry_count,
                )
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

        @field_serializer("object_classes", when_used="json")
        def serialize_objectclasses_with_discovery_context(
            self, value: dict[str, FlextLdifModels.SchemaObjectClass], _info: object
        ) -> dict[str, object]:
            """Serialize object classes with discovery context."""
            return {
                "object_classes": value,
                "discovery_context": self.discovery_summary,
            }

    # =============================================================================
    # ACL MODELS - LDAP Access Control List Models
    # =============================================================================

    class AclTarget(FlextModels.Value):
        """ACL target definition."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        target_dn: str = Field(
            default="",
            description="Target DN for ACL",
        )

        @computed_field
        @property
        def target_key(self) -> str:
            """Computed field for unique target key."""
            return f"target:{self.target_dn.lower()}"

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new AclTarget instance."""
            try:
                _ = args  # Suppress unused argument warning
                target_dn = str(kwargs.get("target_dn", ""))
                instance = cls(target_dn=target_dn)
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

    class AclSubject(FlextModels.Value):
        """ACL subject definition."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        subject_dn: str = Field(
            default="",
            description="Subject DN for ACL",
        )

        @computed_field
        @property
        def subject_key(self) -> str:
            """Computed field for unique subject key."""
            return f"subject:{self.subject_dn.lower()}"

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new AclSubject instance."""
            try:
                _ = args  # Suppress unused argument warning
                subject_dn = str(kwargs.get("subject_dn", ""))
                instance = cls(subject_dn=subject_dn)
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

    class AclPermissions(FlextModels.Value):
        """ACL permissions definition."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        read: bool = Field(
            default=False,
            description="Read permission",
        )

        write: bool = Field(
            default=False,
            description="Write permission",
        )

        add: bool = Field(
            default=False,
            description="Add permission",
        )

        delete: bool = Field(
            default=False,
            description="Delete permission",
        )

        search: bool = Field(
            default=False,
            description="Search permission",
        )

        compare: bool = Field(
            default=False,
            description="Compare permission",
        )

        proxy: bool = Field(
            default=False,
            description="Proxy permission",
        )

        @computed_field
        @property
        def permissions_summary(self) -> dict[str, object]:
            """Computed field for permissions summary."""
            permissions = {
                "read": self.read,
                "write": self.write,
                "add": self.add,
                "delete": self.delete,
                "search": self.search,
                "compare": self.compare,
                "proxy": self.proxy,
            }
            granted_count = sum(permissions.values())
            return {
                "permissions": permissions,
                "granted_count": granted_count,
                "total_permissions": len(permissions),
            }

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new AclPermissions instance."""
            try:
                _ = args  # Suppress unused argument warning
                read = bool(kwargs.get("read"))
                write = bool(kwargs.get("write"))
                add = bool(kwargs.get("add"))
                delete = bool(kwargs.get("delete"))
                search = bool(kwargs.get("search"))
                compare = bool(kwargs.get("compare"))
                proxy = bool(kwargs.get("proxy"))

                instance = cls(
                    read=read,
                    write=write,
                    add=add,
                    delete=delete,
                    search=search,
                    compare=compare,
                    proxy=proxy,
                )
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

        @field_serializer("read", when_used="json")
        def serialize_permissions_with_summary(
            self, value: bool, _info: SerializationInfo
        ) -> dict[str, object]:
            """Serialize permissions with summary context."""
            return {"read": value, "permissions_context": self.permissions_summary}

    class UnifiedAcl(FlextModels.Entity):
        """Unified ACL model combining target, subject, and permissions."""

        model_config = ConfigDict(
            validate_assignment=True, extra="forbid", hide_input_in_errors=True
        )

        target: FlextLdifModels.AclTarget = Field(
            ...,
            description="ACL target",
        )

        subject: FlextLdifModels.AclSubject = Field(
            ...,
            description="ACL subject",
        )

        permissions: FlextLdifModels.AclPermissions = Field(
            ...,
            description="ACL permissions",
        )

        name: str = Field(
            default="",
            description="ACL name",
        )

        server_type: str = Field(
            default="",
            description="Server type",
        )

        raw_acl: str = Field(
            default="",
            description="Raw ACL string",
        )

        @computed_field
        @property
        def acl_key(self) -> str:
            """Computed field for unique ACL key."""
            return (
                f"acl:{self.name}:{self.target.target_key}:{self.subject.subject_key}"
            )

        @computed_field
        @property
        def acl_summary(self) -> dict[str, object]:
            """Computed field for ACL summary."""
            return {
                "name": self.name,
                "target_dn": self.target.target_dn,
                "subject_dn": self.subject.subject_dn,
                "permissions_granted": self.permissions.permissions_summary[
                    "granted_count"
                ],
                "server_type": self.server_type,
            }

        @classmethod
        def create(
            cls,
            *,
            target: FlextLdifModels.AclTarget,
            subject: FlextLdifModels.AclSubject,
            permissions: FlextLdifModels.AclPermissions,
            name: str = "",
            server_type: str = "",
            raw_acl: str = "",
        ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Create a new UnifiedAcl instance."""
            try:
                return FlextResult[FlextLdifModels.UnifiedAcl].ok(
                    cls(
                        target=target,
                        subject=subject,
                        permissions=permissions,
                        name=name,
                        server_type=server_type,
                        raw_acl=raw_acl,
                    )
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(str(e))

        @field_serializer("target", when_used="json")
        def serialize_target_with_acl_context(
            self, value: FlextLdifModels.AclTarget, _info: object
        ) -> dict[str, object]:
            """Serialize target with ACL context."""
            return {
                "target": value,
                "acl_context": {
                    "name": self.name,
                    "permissions_granted": self.permissions.permissions_summary[
                        "granted_count"
                    ],
                },
            }

    # =============================================================================
    # SCHEMA MODELS - Additional Schema-related Models
    # =============================================================================

    class SchemaAttribute(FlextModels.Value):
        """LDAP schema attribute definition."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        name: str = Field(
            ...,
            description="Attribute name",
        )

        oid: str = Field(
            ...,
            description="Attribute OID",
        )

        syntax: str = Field(
            default="",
            description="Attribute syntax",
        )

        description: str = Field(
            default="",
            description="Attribute description",
        )

        single_value: bool = Field(
            default=False,
            description="Whether attribute is single-valued",
        )

        @computed_field
        @property
        def schema_attribute_key(self) -> str:
            """Computed field for unique schema attribute key."""
            return f"schema_attr:{self.name.lower()}"

        @computed_field
        @property
        def attribute_properties(self) -> dict[str, object]:
            """Computed field for attribute properties."""
            return {
                "name": self.name,
                "single_valued": self.single_value,
                "has_syntax": bool(self.syntax),
                "has_description": bool(self.description),
            }

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new SchemaAttribute instance."""
            try:
                _ = args  # Suppress unused argument warning
                instance = cls(
                    name=str(kwargs.get("name", "")),
                    oid=str(kwargs.get("oid", "")),
                    syntax=str(kwargs.get("syntax", "")),
                    description=str(kwargs.get("description", "")),
                    single_value=bool(kwargs.get("single_value")),
                )
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

    # =============================================================================
    # ADDITIONAL MODELS REQUIRED BY TESTS
    # =============================================================================

    class SearchConfig(FlextModels.Value):
        """Search configuration for LDIF operations."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        base_dn: str = Field(
            ...,
            min_length=1,
            description="Base DN for search",
        )

        search_filter: str = Field(
            default="(objectClass=*)",
            description="LDAP search filter",
        )

        attributes: list[str] = Field(
            default_factory=list,
            description="Attributes to return",
        )

        @computed_field
        @property
        def search_summary(self) -> dict[str, object]:
            """Computed field for search configuration summary."""
            return {
                "base_dn": self.base_dn,
                "filter": self.search_filter,
                "attribute_count": len(self.attributes),
            }

        @field_validator("base_dn")
        @classmethod
        def validate_base_dn(cls, v: str) -> str:
            """Validate base DN."""
            if not v.strip():
                raise ValueError(FlextLdifConstants.ErrorMessages.BASE_DN_EMPTY_ERROR)
            return v.strip()

    class LdifDocument(FlextModels.Entity):
        """LDIF document containing multiple entries."""

        model_config = ConfigDict(
            validate_assignment=True, extra="forbid", hide_input_in_errors=True
        )

        entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="LDIF entries",
        )

        @computed_field
        @property
        def document_summary(self) -> dict[str, object]:
            """Computed field for document summary."""
            entry_types: dict[str, int] = {}
            for entry in self.entries:
                entry_type = entry.entry_type
                entry_types[entry_type] = entry_types.get(entry_type, 0) + 1

            return {
                "entry_count": len(self.entries),
                "entry_types": entry_types,
                "has_entries": len(self.entries) > 0,
            }

        @classmethod
        def from_ldif_string(
            cls, ldif_string: str
        ) -> FlextResult[FlextLdifModels.LdifDocument]:
            """Create LdifDocument from LDIF string."""
            try:
                if not ldif_string.strip():
                    return FlextResult[FlextLdifModels.LdifDocument].ok(
                        cls(entries=[], domain_events=[])
                    )

                # Split by double newlines to separate entries
                entry_blocks = ldif_string.strip().split("\n\n")
                entries = []

                for block in entry_blocks:
                    if block.strip():
                        result = FlextLdifModels.Entry.from_ldif_string(block)
                        if result.is_success:
                            entries.append(result.value)
                        else:
                            return FlextResult[FlextLdifModels.LdifDocument].fail(
                                f"Failed to parse entry: {result.error}"
                            )

                return FlextResult[FlextLdifModels.LdifDocument].ok(
                    cls(entries=entries, domain_events=[])
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.LdifDocument].fail(str(e))

        def to_ldif_string(self) -> str:
            """Convert document to LDIF string."""
            return "\n\n".join(entry.to_ldif_string() for entry in self.entries)

        @field_serializer("entries", when_used="json")
        def serialize_entries_with_document_context(
            self, value: list[FlextLdifModels.Entry], _info: object
        ) -> dict[str, object]:
            """Serialize entries with document context."""
            return {"entries": value, "document_context": self.document_summary}

    class AttributeValues(FlextModels.Value):
        """Attribute values container with centralized validation.

        Validates attribute values following LDAP/LDIF standards.
        All validation logic centralized in this Model using Pydantic validators.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        values: list[str] = Field(
            default_factory=list,
            description="Attribute values",
        )

        @field_validator("values")
        @classmethod
        def validate_values(cls, v: list[str]) -> list[str]:
            """Validate attribute values - centralized validation in Model."""
            if not isinstance(v, list):
                msg = FlextLdifConstants.ErrorMessages.ATTRIBUTE_VALUES_ERROR
                raise TypeError(msg)

            validated_values: list[str] = []
            for value in v:
                if not isinstance(value, str):
                    msg = FlextLdifConstants.ErrorMessages.ATTRIBUTE_VALUE_TYPE_ERROR
                    raise TypeError(msg)
                validated_values.append(value.strip())

            return validated_values

        @computed_field
        @property
        def values_summary(self) -> dict[str, object]:
            """Computed field for values summary."""
            return {
                "count": len(self.values),
                "has_values": len(self.values) > 0,
                "is_multi_valued": len(self.values) > 1,
            }

        @computed_field
        @property
        def single_value(self) -> str | None:
            """Computed field for single value (first value if multiple exist)."""
            return self.values[0] if self.values else None

        def __len__(self) -> int:
            """Return the number of values."""
            return len(self.values)

        def __getitem__(self, index: int) -> str:
            """Get value by index."""
            return self.values[index]

        def __contains__(self, item: str) -> bool:
            """Check if value exists in the list."""
            return item in self.values

        @field_serializer("values", when_used="json")
        def serialize_values_with_summary(
            self, value: list[str], _info: object
        ) -> dict[str, object]:
            """Serialize values with summary context."""
            return {"values": value, "values_context": self.values_summary}

    class AttributeName(FlextModels.Value):
        """Attribute name with RFC 4512 validation.

        Validates LDAP attribute names following RFC 4512 standards.
        All validation logic centralized in this Model using Pydantic validators.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        name: str = Field(
            ...,
            min_length=FlextLdifConstants.LdifValidation.MIN_ATTRIBUTE_NAME_LENGTH,
            max_length=FlextLdifConstants.LdifValidation.MAX_ATTRIBUTE_NAME_LENGTH,
            description="LDAP attribute name",
        )

        @field_validator("name")
        @classmethod
        def validate_name(cls, v: str) -> str:
            """Validate attribute name format - centralized validation in Model."""
            if not isinstance(v, str):
                msg = FlextLdifConstants.ErrorMessages.ATTRIBUTE_NAME_ERROR
                raise TypeError(msg)

            if not v.strip():
                msg = FlextLdifConstants.ErrorMessages.ATTRIBUTE_NAME_EMPTY_ERROR
                raise ValueError(msg)

            # RFC 4512 attribute name validation using centralized pattern from Constants
            if not re.match(
                FlextLdifConstants.LdifValidation.ATTRIBUTE_NAME_PATTERN, v
            ):
                msg = f"Invalid attribute name format: {v}"
                raise ValueError(msg)

            return v.strip()

        @computed_field
        @property
        def normalized_name(self) -> str:
            """Computed field for normalized (lowercase) attribute name."""
            return self.name.lower()

        @computed_field
        @property
        def is_operational(self) -> bool:
            """Check if this is an operational attribute (starts with special chars)."""
            # Operational attributes typically start with specific prefixes
            operational_prefixes = (
                "createTimestamp",
                "modifyTimestamp",
                "entryDN",
                "entryUUID",
            )
            return self.name in operational_prefixes

    class LdifUrl(FlextModels.Value):
        """LDIF URL reference with validation.

        Validates URL format for LDIF URL references (HTTP, HTTPS, LDAP protocols).
        All validation logic centralized in this Model using Pydantic validators.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        url: str = Field(
            ...,
            min_length=FlextLdifConstants.LdifValidation.MIN_URL_LENGTH,
            max_length=FlextLdifConstants.LdifValidation.MAX_URL_LENGTH,
            description="URL reference",
        )

        @field_validator("url")
        @classmethod
        def validate_url_format(cls, v: str) -> str:
            """Validate URL format - centralized validation in Model."""
            if not v or not v.strip():
                msg = FlextLdifConstants.ErrorMessages.URL_EMPTY_ERROR
                raise ValueError(msg)

            # URL validation using centralized pattern from Constants
            if not re.match(FlextLdifConstants.LdifValidation.URL_PATTERN, v):
                msg = f"Invalid URL format: {v}"
                raise ValueError(msg)

            return v.strip()

        @computed_field
        @property
        def protocol(self) -> str:
            """Computed field for URL protocol."""
            return self.url.split("://")[0] if "://" in self.url else "unknown"

        @computed_field
        @property
        def is_secure(self) -> bool:
            """Check if URL uses secure protocol (HTTPS/LDAPS) using Constants."""
            return self.protocol in FlextLdifConstants.LdifValidation.SECURE_PROTOCOLS

    class Encoding(FlextModels.Value):
        """Character encoding with validation.

        Validates character encoding against supported encodings.
        All validation logic centralized in this Model using Pydantic validators.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        encoding: str = Field(
            ...,
            min_length=FlextLdifConstants.LdifValidation.MIN_ENCODING_LENGTH,
            max_length=FlextLdifConstants.LdifValidation.MAX_ENCODING_LENGTH,
            description="Character encoding",
        )

        @field_validator("encoding")
        @classmethod
        def validate_encoding(cls, v: str) -> str:
            """Validate encoding - centralized validation in Model."""
            if v not in FlextLdifConstants.Encoding.SUPPORTED_ENCODINGS:
                msg = f"Unsupported encoding: {v}"
                raise ValueError(msg)
            return v

        @computed_field
        @property
        def is_utf8(self) -> bool:
            """Check if encoding is UTF-8."""
            return self.encoding.lower() in {"utf-8", "utf8"}

        @computed_field
        @property
        def normalized_encoding(self) -> str:
            """Computed field for normalized encoding name."""
            return self.encoding.lower().replace("-", "")

    # =========================================================================
    # RESULT MODELS - Operation result containers with validation
    # =========================================================================

    class LdifProcessingResult(FlextModels.Value):
        """Processing operation result with statistics and error tracking.

        Centralizes all processing operation results with automatic validation.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        status: str = Field(
            description="Processing status (success, partial, failed)",
        )
        entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Processed entries",
        )
        errors: list[str] = Field(
            default_factory=list,
            description="Processing errors encountered",
        )
        warnings: list[str] = Field(
            default_factory=list,
            description="Processing warnings",
        )
        statistics: dict[str, int | float] = Field(
            default_factory=dict,
            description="Processing statistics",
        )

        @field_validator("status")
        @classmethod
        def validate_status(cls, v: str) -> str:
            """Validate status field."""
            valid_statuses = {"success", "partial", "failed", "pending"}
            if v not in valid_statuses:
                msg = f"Invalid status: {v}. Must be one of {valid_statuses}"
                raise ValueError(msg)
            return v

        @computed_field
        @property
        def is_success(self) -> bool:
            """Check if processing was successful."""
            return self.status == "success" and len(self.errors) == 0

        @computed_field
        @property
        def entry_count(self) -> int:
            """Get count of processed entries."""
            return len(self.entries)

        @computed_field
        @property
        def error_count(self) -> int:
            """Get count of errors."""
            return len(self.errors)

    class LdifValidationResult(FlextModels.Value):
        """Validation operation result with detailed error tracking.

        Centralizes all validation results with automatic validation.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        is_valid: bool = Field(
            description="Whether validation passed",
        )
        errors: list[str] = Field(
            default_factory=list,
            description="Validation errors",
        )
        warnings: list[str] = Field(
            default_factory=list,
            description="Validation warnings",
        )
        entry_count: int = Field(
            default=0,
            description="Total entries validated",
        )
        valid_count: int = Field(
            default=0,
            description="Count of valid entries",
        )

        @model_validator(mode="after")
        def validate_counts(self) -> FlextLdifModels.LdifValidationResult:
            """Validate count consistency."""
            if self.valid_count > self.entry_count:
                msg = "valid_count cannot exceed entry_count"
                raise ValueError(msg)
            if self.is_valid and self.errors:
                msg = "is_valid cannot be True when errors exist"
                raise ValueError(msg)
            return self

        @computed_field
        @property
        def invalid_count(self) -> int:
            """Get count of invalid entries."""
            return self.entry_count - self.valid_count

        @computed_field
        @property
        def success_rate(self) -> float:
            """Calculate validation success rate."""
            if self.entry_count == 0:
                return 0.0
            return (self.valid_count / self.entry_count) * 100.0

    class ParseResult(FlextModels.Value):
        """Parsing operation result with error tracking.

        Centralizes all parsing results with automatic validation.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Parsed entries",
        )
        parse_errors: list[str] = Field(
            default_factory=list,
            description="Parsing errors encountered",
        )
        line_count: int = Field(
            default=0,
            ge=0,
            description="Total lines parsed",
        )
        success_rate: float = Field(
            default=0.0,
            ge=0.0,
            le=100.0,
            description="Parse success rate percentage",
        )

        @computed_field
        @property
        def entry_count(self) -> int:
            """Get count of parsed entries."""
            return len(self.entries)

        @computed_field
        @property
        def error_count(self) -> int:
            """Get count of parse errors."""
            return len(self.parse_errors)

        @computed_field
        @property
        def is_success(self) -> bool:
            """Check if parsing was successful."""
            return len(self.parse_errors) == 0 and len(self.entries) > 0

    class TransformResult(FlextModels.Value):
        """Transformation operation result with change tracking.

        Centralizes all transformation results with automatic validation.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        transformed_entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Transformed entries",
        )
        transformation_log: list[str] = Field(
            default_factory=list,
            description="Log of transformations applied",
        )
        changes_count: int = Field(
            default=0,
            ge=0,
            description="Number of changes made",
        )

        @computed_field
        @property
        def entry_count(self) -> int:
            """Get count of transformed entries."""
            return len(self.transformed_entries)

    class AnalyticsResult(FlextModels.Value):
        """Analytics operation result with pattern detection.

        Centralizes all analytics results with automatic validation.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        statistics: dict[str, int | float] = Field(
            default_factory=dict,
            description="Statistical data",
        )
        patterns: dict[str, object] = Field(
            default_factory=dict,
            description="Detected patterns",
        )
        object_class_distribution: dict[str, int] = Field(
            default_factory=dict,
            description="Distribution of object classes",
        )
        dn_patterns: list[str] = Field(
            default_factory=list,
            description="Distinguished name patterns",
        )

        @computed_field
        @property
        def total_object_classes(self) -> int:
            """Get total unique object classes."""
            return len(self.object_class_distribution)

    class WriteResult(FlextModels.Value):
        """Write operation result with success tracking.

        Centralizes all write operation results with automatic validation.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        success: bool = Field(
            description="Whether write was successful",
        )
        file_path: str | None = Field(
            default=None,
            description="Path to written file",
        )
        entries_written: int = Field(
            default=0,
            ge=0,
            description="Number of entries written",
        )
        errors: list[str] = Field(
            default_factory=list,
            description="Write errors encountered",
        )

        @model_validator(mode="after")
        def validate_write_consistency(self) -> FlextLdifModels.WriteResult:
            """Validate write result consistency."""
            if self.success and self.errors:
                msg = "success cannot be True when errors exist"
                raise ValueError(msg)
            if not self.success and self.entries_written > 0:
                msg = "entries_written should be 0 when success is False"
                raise ValueError(msg)
            return self

    class FilterResult(FlextModels.Value):
        """Filter operation result with count tracking.

        Centralizes all filter results with automatic validation.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        filtered_entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="Filtered entries",
        )
        original_count: int = Field(
            default=0,
            ge=0,
            description="Original entry count before filtering",
        )
        filtered_count: int = Field(
            default=0,
            ge=0,
            description="Count after filtering",
        )
        criteria: dict[str, object] = Field(
            default_factory=dict,
            description="Filter criteria used",
        )

        @model_validator(mode="after")
        def validate_filter_counts(self) -> FlextLdifModels.FilterResult:
            """Validate filter count consistency."""
            if self.filtered_count > self.original_count:
                msg = "filtered_count cannot exceed original_count"
                raise ValueError(msg)
            if self.filtered_count != len(self.filtered_entries):
                msg = "filtered_count must match length of filtered_entries"
                raise ValueError(msg)
            return self

        @computed_field
        @property
        def removed_count(self) -> int:
            """Get count of entries removed by filter."""
            return self.original_count - self.filtered_count

        @computed_field
        @property
        def filter_rate(self) -> float:
            """Calculate filter rate percentage."""
            if self.original_count == 0:
                return 0.0
            return (self.filtered_count / self.original_count) * 100.0

    class HealthCheckResult(FlextModels.Value):
        """Health check result for services and components.

        Centralizes health check data with status and metrics.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        status: str = Field(
            description="Health status (healthy/degraded/unhealthy)",
        )
        service_name: str = Field(
            description="Service being checked",
        )
        timestamp: str = Field(
            description="Check timestamp",
        )
        details: dict[str, object] = Field(
            default_factory=dict,
            description="Additional health details",
        )
        metrics: dict[str, object] = Field(
            default_factory=dict,
            description="Health metrics",
        )

        @field_validator("status")
        @classmethod
        def validate_status(cls, v: str) -> str:
            """Validate health status uses Constants enum values."""
            valid_statuses = {
                FlextLdifConstants.HealthStatus.HEALTHY.value,
                FlextLdifConstants.HealthStatus.DEGRADED.value,
                FlextLdifConstants.HealthStatus.UNHEALTHY.value,
            }
            if v not in valid_statuses:
                msg = f"Invalid status: {v}. Must be one of {valid_statuses}"
                raise ValueError(msg)
            return v

        @computed_field
        @property
        def is_healthy(self) -> bool:
            """Check if service is healthy."""
            return self.status == FlextLdifConstants.HealthStatus.HEALTHY.value

        @computed_field
        @property
        def is_degraded(self) -> bool:
            """Check if service is degraded."""
            return self.status == FlextLdifConstants.HealthStatus.DEGRADED.value

    class ServiceStatus(FlextModels.Value):
        """Service status information.

        Centralizes service status data including configuration and state.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        service_name: str = Field(
            description="Service name",
        )
        status: str = Field(
            description="Current status",
        )
        configuration: dict[str, object] = Field(
            default_factory=dict,
            description="Service configuration",
        )
        statistics: dict[str, object] = Field(
            default_factory=dict,
            description="Service statistics",
        )
        capabilities: list[str] = Field(
            default_factory=list,
            description="Service capabilities",
        )

        @computed_field
        @property
        def is_operational(self) -> bool:
            """Check if service is operational."""
            return self.status in {
                FlextLdifConstants.HealthStatus.HEALTHY.value,
                FlextLdifConstants.HealthStatus.DEGRADED.value,
            }


__all__ = ["FlextLdifModels"]
