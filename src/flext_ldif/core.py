"""FLEXT LDIF Core - Core Domain Models.

Core LDIF domain models including Entry, DistinguishedName, LdifAttribute.
Extends flext-core FlextModels with LDIF-specific domain entities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import ItemsView

from flext_core import FlextModels, FlextResult, FlextTypes
from pydantic import (
    ConfigDict,
    Field,
    computed_field,
    field_serializer,
    field_validator,
)

from flext_ldif.constants import FlextLdifConstants


class FlextLdifCore:
    """Core LDIF domain models extending FlextModels.

    Contains the fundamental domain entities for LDIF processing:
    - DistinguishedName: DN validation and manipulation
    - LdifAttribute: Attribute name/value pairs
    - LdifAttributes: Collection of attributes
    - Entry: Complete LDIF entry with DN and attributes
    - ChangeRecord: LDIF change operations
    """

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
        def _parse_dn_components(dn: str) -> FlextTypes.StringList:
            r"""Parse DN into components handling escaped commas (\,).

            Internal helper for DN component parsing following RFC 4514.
            """
            components: FlextTypes.StringList = []
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
        def dn_key(self) -> str:
            """Computed field for unique DN key."""
            return f"dn:{self.value.lower()}"

        @property
        def components(self) -> FlextTypes.StringList:
            """Property for DN components."""
            try:
                return self._parse_dn_components(self.value)
            except ValueError:
                return []

        @computed_field
        def depth(self) -> int:
            """Computed field for DN depth (number of components)."""
            return len(self.components)

        @computed_field
        def normalized_value(self) -> str:
            """Computed field for normalized DN value."""
            try:
                components = self._parse_dn_components(self.value)
                normalized_components: FlextTypes.StringList = []
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
        ) -> FlextTypes.Dict:
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

        values: FlextTypes.StringList = Field(
            default_factory=list,
            description="Attribute values",
        )

        @computed_field
        def attribute_key(self) -> str:
            """Computed field for unique attribute key."""
            return f"attr:{self.name.lower()}"

        @property
        def value_count(self) -> int:
            """Number of values for this attribute."""
            return len(self.values)

        @property
        def has_values(self) -> bool:
            """Check if attribute has any values."""
            return bool(self.values)

        @property
        def first_value(self) -> str | None:
            """Get first value or None if no values."""
            return self.values[0] if self.values else None

        def get_values_as_string(self, separator: str = "; ") -> str:
            """Get all values as single string with separator."""
            return separator.join(self.values)

        @field_validator("name")
        @classmethod
        def validate_attribute_name(cls, v: str) -> str:
            """Validate attribute name format."""
            if not v or not v.strip():
                msg = "Attribute name cannot be empty"
                raise ValueError(msg)

            # Basic attribute name validation (RFC 4512 simplified)
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9\-]*$", v):
                # Allow some special characters for LDIF
                if not re.match(r"^[a-zA-Z][a-zA-Z0-9\-_.]*$", v):
                    msg = f"Invalid attribute name format: {v}"
                    raise ValueError(msg)

            return v.strip()

        @field_serializer("values", when_used="json")
        def serialize_values_with_metadata(
            self, values: FlextTypes.StringList, _info: object
        ) -> FlextTypes.Dict:
            """Serialize attribute values with metadata."""
            return {
                "name": self.name,
                "values": values,
                "value_count": len(values),
                "attribute_key": self.attribute_key,
            }

    class LdifAttributes(FlextModels.Value):
        """Collection of LDIF attributes for an entry."""

        model_config = ConfigDict(
            validate_assignment=True,
            extra="allow",  # Allow additional attributes for flexibility
            hide_input_in_errors=True,
        )

        attributes: dict[str, FlextTypes.StringList] = Field(
            default_factory=dict,
            description="Dictionary of attribute names to value lists",
        )

        @computed_field
        def attribute_count(self) -> int:
            """Total number of attributes."""
            return len(self.attributes)

        @computed_field
        def total_value_count(self) -> int:
            """Total number of attribute values across all attributes."""
            return sum(len(values) for values in self.attributes.values())

        @property
        def attribute_names(self) -> list[str]:
            """List of all attribute names."""
            return list(self.attributes.keys())

        def get_attribute(self, name: str) -> FlextTypes.StringList | None:
            """Get attribute values by name (case-insensitive)."""
            name_lower = name.lower()
            for attr_name, values in self.attributes.items():
                if attr_name.lower() == name_lower:
                    return values
            return None

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists (case-insensitive)."""
            name_lower = name.lower()
            return any(attr_name.lower() == name_lower for attr_name in self.attributes)

        def set_attribute(self, name: str, values: FlextTypes.StringList) -> None:
            """Set attribute values."""
            self.attributes[name] = values

        def add_attribute_value(self, name: str, value: str) -> None:
            """Add a value to an attribute."""
            if name not in self.attributes:
                self.attributes[name] = []
            if value not in self.attributes[name]:
                self.attributes[name].append(value)

        def remove_attribute(self, name: str) -> bool:
            """Remove an attribute. Returns True if removed."""
            name_lower = name.lower()
            for attr_name in list(self.attributes.keys()):
                if attr_name.lower() == name_lower:
                    del self.attributes[attr_name]
                    return True
            return False

        def get_object_classes(self) -> FlextTypes.StringList:
            """Get objectClass attribute values."""
            return self.get_attribute("objectClass") or []

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specific object class."""
            object_classes = self.get_object_classes()
            return object_class.lower() in (oc.lower() for oc in object_classes)

        def items(self) -> ItemsView[str, FlextTypes.StringList]:
            """Iterate over attribute name-value pairs."""
            return self.attributes.items()

        def keys(self) -> list[str]:
            """Get attribute names."""
            return list(self.attributes.keys())

        def values(self) -> list[FlextTypes.StringList]:
            """Get attribute value lists."""
            return list(self.attributes.values())

        @field_serializer("attributes", when_used="json")
        def serialize_attributes_with_metadata(
            self, attributes: dict[str, FlextTypes.StringList], _info: object
        ) -> FlextTypes.Dict:
            """Serialize attributes with metadata."""
            return {
                "attributes": attributes,
                "attribute_count": len(attributes),
                "total_value_count": sum(len(values) for values in attributes.values()),
                "has_object_class": "objectclass" in (k.lower() for k in attributes),
            }

    class Entry(FlextModels.Entity):
        """Complete LDIF entry with DN and attributes."""

        model_config = ConfigDict(
            validate_assignment=True,
            extra="allow",
            hide_input_in_errors=True,
        )

        dn: str = Field(
            ...,
            description="Distinguished Name of the entry",
        )

        attributes: dict[str, FlextTypes.StringList] = Field(
            default_factory=dict,
            description="Entry attributes as name -> value list mapping",
        )

        @computed_field
        def entry_key(self) -> str:
            """Computed field for unique entry key."""
            return f"entry:{self.dn.lower()}"

        @property
        def attribute_count(self) -> int:
            """Number of attributes in this entry."""
            return len(self.attributes)

        @property
        def total_value_count(self) -> int:
            """Total number of attribute values."""
            return sum(len(values) for values in self.attributes.values())

        @property
        def object_classes(self) -> FlextTypes.StringList:
            """Object classes for this entry."""
            return self.attributes.get("objectClass", [])

        def get_attribute(self, name: str) -> FlextTypes.StringList | None:
            """Get attribute values by name (case-insensitive)."""
            name_lower = name.lower()
            for attr_name, values in self.attributes.items():
                if attr_name.lower() == name_lower:
                    return values
            return None

        def has_attribute(self, name: str) -> bool:
            """Check if entry has attribute (case-insensitive)."""
            name_lower = name.lower()
            return any(attr_name.lower() == name_lower for attr_name in self.attributes)

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specific object class."""
            object_classes = self.object_classes
            return object_class.lower() in (oc.lower() for oc in object_classes)

        def is_person_entry(self) -> bool:
            """Check if this is a person entry."""
            return self.has_object_class("person") or self.has_object_class(
                "inetOrgPerson"
            )

        def validate_business_rules(self) -> FlextResult[bool]:
            """Validate entry against business rules."""
            # Basic validation - DN required
            if not self.dn or not self.dn.strip():
                return FlextResult[bool].fail("Entry must have a valid DN")

            # Basic validation - attributes should exist
            if not self.attributes:
                return FlextResult[bool].fail("Entry must have at least one attribute")

            # Object class validation
            if not self.object_classes:
                return FlextResult[bool].fail("Entry must have objectClass attribute")

            return FlextResult[bool].ok(True)

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate DN format."""
            if not v or not v.strip():
                msg = "DN cannot be empty"
                raise ValueError(msg)
            return v.strip()

        @field_serializer("attributes", when_used="json")
        def serialize_attributes_with_context(
            self, attributes: dict[str, FlextTypes.StringList], _info: object
        ) -> FlextTypes.Dict:
            """Serialize entry attributes with context."""
            return {
                "dn": self.dn,
                "attributes": attributes,
                "attribute_count": len(attributes),
                "is_person": self.is_person_entry(),
                "object_classes": self.object_classes,
            }

    class ChangeRecord(FlextModels.Entity):
        """LDIF change record for modify operations."""

        model_config = ConfigDict(
            validate_assignment=True,
            extra="allow",
            hide_input_in_errors=True,
        )

        dn: str = Field(
            ...,
            description="Distinguished Name of the entry to modify",
        )

        changetype: Literal[add, delete, modify] = Field(
            ...,
            description="Type of change operation",
        )

        attributes: dict[str, FlextTypes.StringList] = Field(
            default_factory=dict,
            description="Attributes for add/modify operations",
        )

        delete_attributes: FlextTypes.StringList = Field(
            default_factory=list,
            description="Attributes to delete in modify operations",
        )

        @computed_field
        def change_key(self) -> str:
            """Computed field for unique change record key."""
            return f"change:{self.dn.lower()}:{self.changetype}"
