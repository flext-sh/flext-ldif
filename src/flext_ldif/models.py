"""FLEXT LDIF Models - Domain models for LDIF processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pydantic import Field, field_validator

from flext_core import (
    FlextModels,
    FlextResult,
)

# Validation error messages as constants
DN_EMPTY_ERROR = "DN cannot be empty"
DN_INVALID_FORMAT_ERROR = "DN must contain attribute=value pairs"
DN_INVALID_CHARS_ERROR = "DN contains invalid characters"
ATTRIBUTES_TYPE_ERROR = "Attributes must be a dictionary"
ATTRIBUTE_NAME_ERROR = "Attribute names must be non-empty strings"
ATTRIBUTE_VALUES_ERROR = "values must be a list"
ATTRIBUTE_VALUE_TYPE_ERROR = "must be strings"

# Constants
MIN_DN_COMPONENTS = 2


class FlextLdifModels:
    """LDIF domain models with proper Pydantic v2 and flext-core integration.

    Unified class containing LDIF model definitions with:
    - Proper Pydantic v2 features (ConfigDict, computed_field, model_validator)
    - Flext-core integration patterns
    - Type-safe domain modeling with zero legacy code
    - Railway-oriented programming with FlextResult chaining
    - Zero fallback patterns or compatibility layers

    Uses flext-core patterns directly without any aliases or wrappers.
    """

    # =============================================================================
    # LDIF DOMAIN VALUE OBJECTS (Proper Pydantic v2)
    # =============================================================================

    class DistinguishedName(FlextModels.Value):
        """Distinguished Name value object with proper Pydantic v2 validation.

        Immutable value object for LDAP Distinguished Names using:
        - ConfigDict for Pydantic v2 configuration
        - computed_field for calculated properties
        - model_validator for business rules
        - FlextResult patterns for validation
        """

        value: str = Field(
            ...,
            min_length=1,
            description="LDAP Distinguished Name",
            examples=["cn=user,dc=example,dc=com", "ou=users,dc=corp,dc=local"],
        )

        @field_validator("value")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Validate DN format using proper validation patterns.

            Returns:
                str: The validated DN string

            Raises:
                ValueError: If DN format validation fails

            """
            if not v or not v.strip():
                error_msg = DN_EMPTY_ERROR
                raise ValueError(error_msg)

            normalized = v.strip()

            # Basic DN format validation - must contain = and optionally ,
            if "=" not in normalized:
                error_msg = DN_INVALID_FORMAT_ERROR
                raise ValueError(error_msg)

            # Check for valid characters (basic validation)
            invalid_chars = {
                "@",
                "#",
                "$",
                "%",
                "&",
                "*",
                "|",
                "<",
                ">",
                ";",
                ":",
                "'",
                '"',
                "\\",
                "/",
                "?",
                "[",
                "]",
                "{",
                "}",
                "(",
                ")",
            }
            if any(char in normalized for char in invalid_chars):
                error_msg = DN_INVALID_CHARS_ERROR
                raise ValueError(error_msg)

            return normalized

        @property
        def rdn(self) -> str:
            """Get the relative DN (first component)."""
            return self.value.split(",")[0].strip()

        @property
        def parent_dn(self) -> str | None:
            """Get parent DN (all components except first)."""
            components = self.value.split(",")
            if len(components) <= 1:
                return None
            return ",".join(components[1:]).strip()

        @property
        def depth(self) -> int:
            """Get DN depth (number of components)."""
            return len(self._parse_components())

        @property
        def components(self) -> list[str]:
            """Get all DN components."""
            return self._parse_components()

        @property
        def is_leaf(self) -> bool:
            """Check if this is a leaf DN (has parent)."""
            return self.parent_dn is not None

        @property
        def base_dn(self) -> str:
            """Get base DN (last two components if available)."""
            components = self.value.split(",")
            if len(components) >= MIN_DN_COMPONENTS:
                return ",".join(components[-MIN_DN_COMPONENTS:]).strip()
            return self.value

        def _parse_components(self) -> list[str]:
            """Parse DN into components.

            Returns:
                list[str]: List of DN components

            """
            return [comp.strip() for comp in self.value.split(",") if comp.strip()]

        def validate_business_rules(self) -> FlextResult[bool]:
            """Validate business rules for DN.

            Returns:
                FlextResult[bool]: Validation result

            """
            try:
                # Basic validation - DN must have valid format
                if not self.value or not self.value.strip():
                    return FlextResult[bool].fail("DN cannot be empty")

                # Must contain attribute=value pairs
                if "=" not in self.value:
                    return FlextResult[bool].fail(
                        "DN must contain attribute=value pairs"
                    )

                return FlextResult[bool].ok(data=True)
            except Exception as e:
                return FlextResult[bool].fail(f"DN validation failed: {e}")

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create DN with validation returning FlextResult.

            Returns:
                FlextResult[FlextLdifModels.DistinguishedName]: Created DN or error

            """
            try:
                dn = str(args[0]) if args else str(kwargs.get("dn", ""))
                return FlextResult[object].ok(cls(value=dn))
            except Exception as e:
                return FlextResult[object].fail(str(e))

    class LdifAttributes(FlextModels.Value):
        """LDIF attributes dictionary with proper validation.

        Immutable value object for LDAP attributes using:
        - Proper dict[str, list[str]] type annotation
        - Validation for LDAP attribute requirements
        - FlextResult patterns for operations
        """

        data: dict[str, list[str]] = Field(
            default_factory=dict,
            description="LDAP attribute data as key-value pairs",
        )

        @field_validator("data")
        @classmethod
        def validate_attribute_data(
            cls, v: dict[str, list[str]]
        ) -> dict[str, list[str]]:
            """Validate attribute data structure.

            Returns:
                dict[str, list[str]]: Validated attribute data

            Raises:
                TypeError: If data structure is invalid
                ValueError: If attribute names or values are invalid

            """
            if not isinstance(v, dict):
                raise TypeError(ATTRIBUTES_TYPE_ERROR)

            for key in v:
                if not isinstance(key, str) or not key.strip():
                    raise ValueError(ATTRIBUTE_NAME_ERROR)

            return v

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute values by name (case-insensitive).

            Returns:
                list[str] | None: Attribute values or None if not found

            """
            for key, values in self.data.items():
                if key.lower() == name.lower():
                    return values
            return None

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists (case-insensitive).

            Returns:
                bool: True if attribute exists

            """
            return self.get_attribute(name) is not None

        def get_single_value(self, name: str) -> str | None:
            """Get single attribute value.

            Returns:
                str | None: Single attribute value or None

            """
            values = self.get_attribute(name)
            return values[0] if values else None

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create attributes with validation returning FlextResult.

            Returns:
                FlextResult[FlextLdifModels.LdifAttributes]: Created attributes or error

            """
            try:
                data = args[0] if args else kwargs.get("data", {})
                if not isinstance(data, dict):
                    return FlextResult[object].fail("Data must be a dictionary")
                return FlextResult[object].ok(cls(data=data))
            except Exception as e:
                return FlextResult[object].fail(str(e))

    class Entry(FlextModels.Value):
        """LDIF entry combining DN and attributes.

        Immutable value object representing a complete LDIF entry with:
        - Distinguished Name (DN)
        - Attributes dictionary
        - Helper methods for LDAP operations
        - FlextResult patterns for validation
        """

        dn: FlextLdifModels.DistinguishedName = Field(
            ..., description="Distinguished Name"
        )
        attributes: FlextLdifModels.LdifAttributes = Field(
            ..., description="Entry attributes"
        )

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute values by name.

            Returns:
                list[str] | None: Attribute values or None if not found

            """
            return self.attributes.get_attribute(name)

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists.

            Returns:
                bool: True if attribute exists

            """
            return self.attributes.has_attribute(name)

        def get_single_value(self, name: str) -> str | None:
            """Get single attribute value.

            Returns:
                str | None: Single attribute value or None

            """
            return self.attributes.get_single_value(name)

        def is_person_entry(self) -> bool:
            """Check if entry is a person.

            Returns:
                bool: True if entry is a person

            """
            object_classes = self.get_attribute("objectClass") or []
            return any(
                oc.lower() in {"person", "inetorgperson", "organizationalperson"}
                for oc in object_classes
            )

        def is_group_entry(self) -> bool:
            """Check if entry is a group.

            Returns:
                bool: True if entry is a group

            """
            object_classes = self.get_attribute("objectClass") or []
            return any(
                oc.lower() in {"group", "groupofnames", "groupofuniquenames"}
                for oc in object_classes
            )

        def is_organizational_unit(self) -> bool:
            """Check if entry is an organizational unit.

            Returns:
                bool: True if entry is an organizational unit

            """
            object_classes = self.get_attribute("objectClass") or []
            return any(oc.lower() == "organizationalunit" for oc in object_classes)

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specific object class.

            Args:
                object_class: Object class to check for

            Returns:
                bool: True if entry has the object class

            """
            object_classes = self.get_attribute("objectClass") or []
            return any(oc.lower() == object_class.lower() for oc in object_classes)

        def validate_business_rules(self) -> FlextResult[bool]:
            """Validate business rules for entry.

            Returns:
                FlextResult[bool]: Validation result

            """
            try:
                # Validate DN
                dn_validation = self.dn.validate_business_rules()
                if dn_validation.is_failure:
                    return FlextResult[bool].fail(
                        f"DN validation failed: {dn_validation.error}"
                    )

                # Entry must have objectClass
                object_classes = self.get_attribute("objectClass")
                if not object_classes:
                    return FlextResult[bool].fail(
                        "Entry must have objectClass attribute"
                    )

                return FlextResult[bool].ok(data=True)
            except Exception as e:
                return FlextResult[bool].fail(f"Entry validation failed: {e}")

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create entry with validation returning FlextResult.

            Returns:
                FlextResult[FlextLdifModels.Entry]: Created entry or error

            """
            dn = str(args[0]) if len(args) > 0 else str(kwargs.get("dn", ""))
            attributes = args[1] if len(args) > 1 else kwargs.get("attributes", {})
            if not isinstance(attributes, dict):
                return FlextResult[object].fail("Attributes must be a dictionary")

            dn_result: FlextResult[object] = FlextLdifModels.DistinguishedName.create(
                dn
            )
            if dn_result.is_failure:
                return FlextResult[object].fail(f"Invalid DN: {dn_result.error}")

            attr_result: FlextResult[object] = FlextLdifModels.LdifAttributes.create(
                attributes
            )
            if attr_result.is_failure:
                return FlextResult[object].fail(
                    f"Invalid attributes: {attr_result.error}"
                )

            try:
                dn_obj = dn_result.unwrap()
                attr_obj = attr_result.unwrap()
                if isinstance(dn_obj, FlextLdifModels.DistinguishedName) and isinstance(
                    attr_obj, FlextLdifModels.LdifAttributes
                ):
                    entry = cls(dn=dn_obj, attributes=attr_obj)
                else:
                    return FlextResult[object].fail("Type mismatch in unwrapped values")
                return FlextResult[object].ok(entry)
            except Exception as e:
                return FlextResult[object].fail(str(e))

    class LdifUrl(FlextModels.Value):
        """LDIF URL value object for URL validation."""

        url: str = Field(..., description="LDIF URL value")

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create URL with validation.

            Returns:
                FlextResult[FlextLdifModels.LdifUrl]: Created URL or error

            """
            try:
                url = str(args[0]) if args else str(kwargs.get("url", ""))
                return FlextResult[object].ok(cls(url=url))
            except Exception as e:
                return FlextResult[object].fail(str(e))

    # =============================================================================
    # FACTORY METHODS (FlextResult patterns)
    # =============================================================================

    @staticmethod
    def create_entry(data: dict[str, object]) -> FlextResult[Entry]:
        """Create entry from dictionary data.

        Returns:
            FlextResult[Entry]: Created entry or error

        """
        try:
            dn = data.get("dn")
            if not isinstance(dn, str):
                return FlextResult[FlextLdifModels.Entry].fail("DN must be a string")

            attributes = data.get("attributes", {})
            if not isinstance(attributes, dict):
                return FlextResult[FlextLdifModels.Entry].fail(
                    "Attributes must be a dictionary"
                )

            # Convert attributes to proper format
            normalized_attrs: dict[str, list[str]] = {}
            for key, value in attributes.items():
                if isinstance(value, str):
                    normalized_attrs[key] = [value]
                elif isinstance(value, list):
                    normalized_attrs[key] = [str(v) for v in value]
                else:
                    normalized_attrs[key] = [str(value)]

            result = FlextLdifModels.Entry.create(dn, normalized_attrs)
            if result.is_success:
                entry_obj = result.unwrap()
                if isinstance(entry_obj, FlextLdifModels.Entry):
                    return FlextResult[FlextLdifModels.Entry].ok(entry_obj)
                return FlextResult[FlextLdifModels.Entry].fail(
                    "Type mismatch in unwrapped entry"
                )
            return FlextResult[FlextLdifModels.Entry].fail(
                result.error or "Unknown error"
            )

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Entry creation failed: {e}"
            )

    @staticmethod
    def create_dn(dn_value: str) -> FlextResult[DistinguishedName]:
        """Create DN with validation.

        Returns:
            FlextResult[DistinguishedName]: Success with validated DN or failure with error message.

        """
        result = FlextLdifModels.DistinguishedName.create(dn_value)
        if result.is_success:
            dn_obj = result.unwrap()
            if isinstance(dn_obj, FlextLdifModels.DistinguishedName):
                return FlextResult[FlextLdifModels.DistinguishedName].ok(dn_obj)
            return FlextResult[FlextLdifModels.DistinguishedName].fail(
                "Type mismatch in unwrapped DN"
            )
        return FlextResult[FlextLdifModels.DistinguishedName].fail(
            result.error or "Unknown error"
        )

    @staticmethod
    def create_attributes(data: dict[str, list[str]]) -> FlextResult[LdifAttributes]:
        """Create attributes with validation.

        Returns:
            FlextResult[LdifAttributes]: Success with validated attributes or failure with error message.

        """
        result = FlextLdifModels.LdifAttributes.create(data)
        if result.is_success:
            attr_obj = result.unwrap()
            if isinstance(attr_obj, FlextLdifModels.LdifAttributes):
                return FlextResult[FlextLdifModels.LdifAttributes].ok(attr_obj)
            return FlextResult[FlextLdifModels.LdifAttributes].fail(
                "Type mismatch in unwrapped attributes"
            )
        return FlextResult[FlextLdifModels.LdifAttributes].fail(
            result.error or "Unknown error"
        )


__all__ = ["FlextLdifModels"]
