"""FLEXT LDIF Models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from pydantic import BaseModel, Field, field_validator

from flext_core import FlextModels, FlextResult
from flext_ldif.constants import FlextLdifConstants


class FlextLdifModels(FlextModels):
    """LDIF domain models extending flext-core FlextModels.

    Contains ONLY Pydantic v2 model definitions with business logic.
    """

    class DistinguishedName(BaseModel):
        """Pydantic model for LDAP Distinguished Name."""

        value: str = Field(..., min_length=1, description="DN string value")

        @field_validator("value")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Validate DN format and characters."""
            if not v.strip():
                raise ValueError(FlextLdifConstants.ErrorMessages.DN_EMPTY_ERROR)

            # Basic DN format validation - must contain = character
            if "=" not in v:
                raise ValueError(
                    FlextLdifConstants.ErrorMessages.DN_INVALID_FORMAT_ERROR
                )

            # Check for invalid characters (excluding "@" for email support)
            invalid_chars = {
                "#",
                "$",
                "%",
                "^",
                "&",
                "*",
                "(",
                ")",
                "[",
                "]",
                "{",
                "}",
                "|",
                "\\",
                "/",
                "?",
                "<",
                ">",
            }
            if any(char in v for char in invalid_chars):
                raise ValueError(
                    FlextLdifConstants.ErrorMessages.DN_INVALID_CHARS_ERROR
                )

            return v.strip()

        @property
        def depth(self) -> int:
            """Get DN component depth."""
            return len([
                component for component in self.value.split(",") if component.strip()
            ])

        @property
        def components(self) -> list[str]:
            """Get DN components as list."""
            return [
                component.strip()
                for component in self.value.split(",")
                if component.strip()
            ]

        @classmethod
        def create(
            cls, dn_value: str
        ) -> FlextResult[FlextLdifModels.DistinguishedName]:
            """Create DN with validation returning FlextResult."""
            try:
                dn = cls(value=dn_value)
                return FlextResult["FlextLdifModels.DistinguishedName"].ok(dn)
            except ValueError as e:
                return FlextResult["FlextLdifModels.DistinguishedName"].fail(str(e))

    class LdifAttributes(BaseModel):
        """Pydantic model for LDIF entry attributes."""

        data: dict[str, list[str]] = Field(
            default_factory=dict, description="Attribute name to values mapping"
        )

        @field_validator("data")
        @classmethod
        def validate_attributes(cls, v: object) -> dict[str, list[str]]:
            """Validate attribute data structure."""
            if not isinstance(v, dict):
                raise TypeError(FlextLdifConstants.ErrorMessages.ATTRIBUTES_TYPE_ERROR)

            for attr_name, attr_values in v.items():
                cls._validate_attribute_name(attr_name)  # type: ignore[arg-type]
                cls._validate_attribute_values(attr_name, attr_values)

            return cast("dict[str, list[str]]", v)

        @staticmethod
        def _validate_attribute_name(attr_name: object) -> None:
            """Validate attribute name."""
            if not isinstance(attr_name, str) or not attr_name.strip():
                raise ValueError(FlextLdifConstants.ErrorMessages.ATTRIBUTE_NAME_ERROR)

        @staticmethod
        def _validate_attribute_values(attr_name: str, attr_values: object) -> None:
            """Validate attribute values."""
            if not isinstance(attr_values, list):  # pragma: no cover
                msg = f"Attribute '{attr_name}' {FlextLdifConstants.ErrorMessages.ATTRIBUTE_VALUES_ERROR}"
                raise TypeError(msg)
  # type: ignore[assignment]
            for value in attr_values:
                if not isinstance(value, str):  # pragma: no cover
                    msg = f"Attribute '{attr_name}' values {FlextLdifConstants.ErrorMessages.ATTRIBUTE_VALUE_TYPE_ERROR}"
                    raise TypeError(msg)

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute values by name."""
            return self.data.get(name)

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            return name in self.data

        def add_attribute(self, name: str, values: list[str]) -> None:
            """Add attribute with values."""
            self.data[name] = values

        def remove_attribute(self, name: str) -> bool:
            """Remove attribute. Returns True if removed, False if not found."""
            return self.data.pop(name, None) is not None

        def __contains__(self, name: str) -> bool:
            """Support 'in' operator for attribute names."""
            return name in self.data

        def __len__(self) -> int:
            """Support len() function for number of attributes."""
            return len(self.data)

        @classmethod
        def create(
            cls, data: dict[str, list[str]]
        ) -> FlextResult[FlextLdifModels.LdifAttributes]:
            """Create attributes with validation returning FlextResult."""
            try:
                attributes = cls(data=data)
                return FlextResult["FlextLdifModels.LdifAttributes"].ok(attributes)
            except ValueError as e:
                return FlextResult["FlextLdifModels.LdifAttributes"].fail(str(e))

    class Entry(BaseModel):
        """Pydantic model for LDIF entry."""

        dn: FlextLdifModels.DistinguishedName = Field(
            ..., description="Distinguished Name"
        )
        attributes: FlextLdifModels.LdifAttributes = Field(
            ..., description="Entry attributes"
        )

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute values by name."""
            return self.attributes.get_attribute(name)

        def get_single_value(self, name: str) -> str | None:
            """Get single attribute value by name."""
            values = self.get_attribute(name)
            return values[0] if values else None

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            return self.attributes.has_attribute(name)

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specified object class."""
            object_classes = self.get_attribute("objectClass") or []
            return object_class.lower() in [oc.lower() for oc in object_classes]

        def is_person_entry(self) -> bool:
            """Check if entry is a person entry."""
            object_classes = self.get_attribute("objectClass") or []
            person_classes = {oc.lower() for oc in object_classes}
            ldap_person_classes = {
                oc.lower()
                for oc in FlextLdifConstants.ObjectClasses.LDAP_PERSON_CLASSES
            }
            return bool(person_classes.intersection(ldap_person_classes))

        def is_group_entry(self) -> bool:
            """Check if entry is a group entry."""
            object_classes = self.get_attribute("objectClass") or []
            group_classes = {oc.lower() for oc in object_classes}
            ldap_group_classes = {
                oc.lower() for oc in FlextLdifConstants.ObjectClasses.LDAP_GROUP_CLASSES
            }
            return bool(group_classes.intersection(ldap_group_classes))

        def is_organizational_unit(self) -> bool:
            """Check if entry is an organizational unit."""
            return self.has_object_class("organizationalUnit")

        def validate_business_rules(self) -> FlextResult[bool]:
            """Validate entry against business rules."""
            # Basic validation - entry must have DN and at least one attribute
            if not self.dn.value:  # pragma: no cover
                return FlextResult[bool].fail("Entry must have a valid DN")

            if not self.attributes.data:  # pragma: no cover
                return FlextResult[bool].fail("Entry must have at least one attribute")

            # Check minimum DN components
            if (
                self.dn.depth < FlextLdifConstants.LdifValidation.MIN_DN_COMPONENTS
            ):  # pragma: no cover
                return FlextResult[bool].fail("DN must have at least one component")

            return FlextResult[bool].ok(True)

        @classmethod
        def create(
            cls, dn: str, attributes: dict[str, list[str]]
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create entry with validation returning FlextResult."""
            # Create DN
            dn_result = FlextLdifModels.DistinguishedName.create(dn)
            if dn_result.is_failure:
                return FlextResult["FlextLdifModels.Entry"].fail(
                    dn_result.error or "Invalid DN"
                )

            # Create attributes
            attrs_result = FlextLdifModels.LdifAttributes.create(attributes)
            if attrs_result.is_failure:
                return FlextResult["FlextLdifModels.Entry"].fail(
                    attrs_result.error or "Invalid attributes"
                )

            try:
                entry = cls(dn=dn_result.value, attributes=attrs_result.value)
                return FlextResult["FlextLdifModels.Entry"].ok(entry)
            except Exception as e:  # pragma: no cover
                return FlextResult["FlextLdifModels.Entry"].fail(str(e))

    class LdifUrl(BaseModel):
        """Pydantic model for LDIF URL references."""

        url: str = Field(..., description="URL string")
        description: str = Field(default="", description="Optional description")

        @field_validator("url")
        @classmethod
        def validate_url_format(cls, v: str) -> str:
            """Basic URL format validation."""
            if not v.strip():
                msg = "URL cannot be empty"
                raise ValueError(msg)

            # Basic URL validation - must start with protocol
            valid_protocols = ("http://", "https://", "ldap://", "ldaps://")
            if not v.startswith(valid_protocols):
                msg = "URL must start with valid protocol"
                raise ValueError(msg)

            return v.strip()

        @classmethod
        def create(
            cls, url: str, description: str = ""
        ) -> FlextResult[FlextLdifModels.LdifUrl]:
            """Create URL with validation returning FlextResult."""
            try:
                ldif_url = cls(url=url, description=description)
                return FlextResult["FlextLdifModels.LdifUrl"].ok(ldif_url)
            except ValueError as e:
                return FlextResult["FlextLdifModels.LdifUrl"].fail(str(e))

    # =============================================================================
    # FACTORY METHODS
    # =============================================================================

    @staticmethod
    def create_entry(data: dict[str, object]) -> FlextResult[Entry]:
        """Create entry from dictionary data."""
        dn = data.get("dn")
        if not isinstance(dn, str):
            return FlextResult[FlextLdifModels.Entry].fail("DN must be a string")

        attributes = data.get("attributes", {})
        if not isinstance(attributes, dict):
            return FlextResult[FlextLdifModels.Entry].fail(
                "Attributes must be a dictionary"
            )

        # Convert attributes to proper format
        normalized_attrs: dict[str, list[str]] = {}  # type: ignore[assignment]
        for key, value in attributes.items():
            key_str = str(key)
            if isinstance(value, str):
                normalized_attrs[key_str] = [value]
            elif isinstance(value, list):  # type: ignore[assignment]
                normalized_attrs[key_str] = [str(v) for v in value if v is not None]
            else:  # type: ignore[arg-type]
                normalized_attrs[key_str] = [str(value)]

        return FlextLdifModels.Entry.create(dn, normalized_attrs)

    @staticmethod
    def create_dn(dn_value: str) -> FlextResult[DistinguishedName]:
        """Create DN from string value."""
        return FlextLdifModels.DistinguishedName.create(dn_value)

    @staticmethod
    def create_attributes(data: dict[str, list[str]]) -> FlextResult[LdifAttributes]:
        """Create attributes from dictionary data."""
        return FlextLdifModels.LdifAttributes.create(data)


__all__ = ["FlextLdifModels"]
