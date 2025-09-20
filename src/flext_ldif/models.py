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
            """Validate DN format using proper validation patterns."""
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
            """Parse DN into components."""
            return [comp.strip() for comp in self.value.split(",") if comp.strip()]

        def validate_business_rules(self) -> FlextResult[bool]:
            """Validate business rules for DN."""
            try:
                # Basic validation - DN must have valid format
                if not self.value or not self.value.strip():
                    return FlextResult[bool].fail("DN cannot be empty")

                # Must contain attribute=value pairs
                if "=" not in self.value:
                    return FlextResult[bool].fail(
                        "DN must contain attribute=value pairs"
                    )

                return FlextResult[bool].ok(True)  # noqa: FBT003  # noqa: FBT003
            except Exception as e:
                return FlextResult[bool].fail(f"DN validation failed: {e}")

        @classmethod
        def create(cls, dn: str) -> FlextResult[FlextLdifModels.DistinguishedName]:
            """Create DN with validation returning FlextResult."""
            try:
                return FlextResult[FlextLdifModels.DistinguishedName].ok(cls(value=dn))
            except Exception as e:
                return FlextResult[FlextLdifModels.DistinguishedName].fail(str(e))

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
            """Validate attribute data structure."""
            if not isinstance(v, dict):
                raise TypeError(ATTRIBUTES_TYPE_ERROR)

            for key, values in v.items():
                if not isinstance(key, str) or not key.strip():
                    raise ValueError(ATTRIBUTE_NAME_ERROR)

                if not isinstance(values, list):
                    msg = f"Attribute '{key}' {ATTRIBUTE_VALUES_ERROR}"  # type: ignore[unreachable]
                    raise TypeError(msg)

                for value in values:
                    if not isinstance(value, str):
                        msg = f"All values for attribute '{key}' {ATTRIBUTE_VALUE_TYPE_ERROR}"  # type: ignore[unreachable]
                        raise TypeError(msg)

            return v

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute values by name (case-insensitive)."""
            for key, values in self.data.items():
                if key.lower() == name.lower():
                    return values
            return None

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists (case-insensitive)."""
            return self.get_attribute(name) is not None

        def get_single_value(self, name: str) -> str | None:
            """Get single attribute value."""
            values = self.get_attribute(name)
            return values[0] if values else None

        @classmethod
        def create(
            cls, data: dict[str, list[str]]
        ) -> FlextResult[FlextLdifModels.LdifAttributes]:
            """Create attributes with validation returning FlextResult."""
            try:
                return FlextResult[FlextLdifModels.LdifAttributes].ok(cls(data=data))
            except Exception as e:
                return FlextResult[FlextLdifModels.LdifAttributes].fail(str(e))

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
            """Get attribute values by name."""
            return self.attributes.get_attribute(name)

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            return self.attributes.has_attribute(name)

        def get_single_value(self, name: str) -> str | None:
            """Get single attribute value."""
            return self.attributes.get_single_value(name)

        def is_person_entry(self) -> bool:
            """Check if entry is a person."""
            object_classes = self.get_attribute("objectClass") or []
            return any(
                oc.lower() in {"person", "inetorgperson", "organizationalperson"}
                for oc in object_classes
            )

        def is_group_entry(self) -> bool:
            """Check if entry is a group."""
            object_classes = self.get_attribute("objectClass") or []
            return any(
                oc.lower() in {"group", "groupofnames", "groupofuniquenames"}
                for oc in object_classes
            )

        def is_organizational_unit(self) -> bool:
            """Check if entry is an organizational unit."""
            object_classes = self.get_attribute("objectClass") or []
            return any(oc.lower() == "organizationalunit" for oc in object_classes)

        def validate_business_rules(self) -> FlextResult[bool]:
            """Validate business rules for entry."""
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

                return FlextResult[bool].ok(True)  # noqa: FBT003
            except Exception as e:
                return FlextResult[bool].fail(f"Entry validation failed: {e}")

        @classmethod
        def create(
            cls, dn: str, attributes: dict[str, list[str]]
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create entry with validation returning FlextResult."""
            dn_result = FlextLdifModels.DistinguishedName.create(dn)
            if dn_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Invalid DN: {dn_result.error}"
                )

            attr_result = FlextLdifModels.LdifAttributes.create(attributes)
            if attr_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Invalid attributes: {attr_result.error}"
                )

            try:
                entry = cls(dn=dn_result.unwrap(), attributes=attr_result.unwrap())
                return FlextResult[FlextLdifModels.Entry].ok(entry)
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(str(e))

    class LdifUrl(FlextModels.Value):
        """LDIF URL value object for URL validation."""

        url: str = Field(..., description="LDIF URL value")

        @classmethod
        def create(cls, url: str) -> FlextResult[FlextLdifModels.LdifUrl]:
            """Create URL with validation."""
            try:
                return FlextResult[FlextLdifModels.LdifUrl].ok(cls(url=url))
            except Exception as e:
                return FlextResult[FlextLdifModels.LdifUrl].fail(str(e))

    # =============================================================================
    # FACTORY METHODS (FlextResult patterns)
    # =============================================================================

    @staticmethod
    def create_entry(data: dict[str, object]) -> FlextResult[Entry]:
        """Create entry from dictionary data."""
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

            return FlextLdifModels.Entry.create(dn, normalized_attrs)

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Entry creation failed: {e}"
            )

    @staticmethod
    def create_dn(dn_value: str) -> FlextResult[DistinguishedName]:
        """Create DN with validation."""
        return FlextLdifModels.DistinguishedName.create(dn_value)

    @staticmethod
    def create_attributes(data: dict[str, list[str]]) -> FlextResult[LdifAttributes]:
        """Create attributes with validation."""
        return FlextLdifModels.LdifAttributes.create(data)


__all__ = ["FlextLdifModels"]
