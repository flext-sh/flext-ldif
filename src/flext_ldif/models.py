"""FLEXT-LDIF Domain Models - Zero Duplication with FlextModels.

Ultra-optimized domain models using FlextModels components to eliminate
all custom code duplication and leverage flext-core patterns correctly.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from functools import lru_cache
from typing import override

from flext_core import (
    FlextModels,
    FlextResult,
    FlextValidations,
)
from pydantic import Field, field_validator, model_validator

from flext_ldif.constants import FlextLDIFConstants
from flext_ldif.exceptions import FlextLDIFExceptions


class FlextLDIFModels(FlextModels.AggregateRoot):
    """Zero-duplication LDIF models using FlextModels correctly.

    Eliminates all custom collection/dict/validation code by leveraging
    flext-core components properly. Uses FlextValidations for business rules,
    FlextModels base classes for structure, and FlextResult for error handling.
    """

    # =============================================================================
    # VALUE OBJECTS - Using FlextModels.Value for immutable domain values
    # =============================================================================

    class DistinguishedName(FlextModels.Value):
        """Distinguished Name value object using FlextModels.Value base."""

        value: str = Field(..., min_length=1, description="LDAP Distinguished Name")

        @field_validator("value")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Validate DN format using flext-core validators."""
            if not v or not v.strip():
                msg = FlextLDIFConstants.FlextLDIFValidationMessages.EMPTY_DN
                raise FlextLDIFExceptions.validation_error(msg)

            # Use flext-core validation system - validate non-empty string
            validation_result = FlextValidations.Rules.StringRules.validate_non_empty(
                v.strip()
            )
            if validation_result.is_failure:
                msg = FlextLDIFConstants.FlextLDIFValidationMessages.INVALID_DN.format(
                    dn=v
                )
                raise FlextLDIFExceptions.validation_error(msg, dn=v)

            # Basic DN format validation
            dn_pattern = r"^[^=]+=[^=]+(,[^=]+=[^=]+)*$"
            pattern_result = FlextValidations.Rules.StringRules.validate_pattern(
                v.strip(), dn_pattern, "DN format"
            )
            if pattern_result.is_failure:
                msg = FlextLDIFConstants.FlextLDIFValidationMessages.INVALID_DN.format(
                    dn=v
                )
                raise FlextLDIFExceptions.validation_error(msg, dn=v)

            return v.strip()

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate DN business rules using FlextResult."""
            if not self.value:
                return FlextResult[None].fail(
                    FlextLDIFConstants.FlextLDIFValidationMessages.EMPTY_DN
                )

            # Check minimum DN components using flext-core pattern
            components = [c.strip() for c in self.value.split(",") if c.strip()]
            if len(components) < FlextLDIFConstants.MIN_DN_COMPONENTS:
                error_msg = (
                    FlextLDIFConstants.FlextLDIFValidationMessages.DN_TOO_SHORT.format(
                        components=len(components),
                        minimum=FlextLDIFConstants.MIN_DN_COMPONENTS,
                    )
                )
                return FlextResult[None].fail(error_msg)

            return FlextResult[None].ok(None)

        def get_rdn(self) -> str:
            """Get Relative Distinguished Name (first component)."""
            if not self.value:
                return ""
            return self.value.split(",")[0].strip()

        def get_parent_dn(self) -> str | None:
            """Get parent DN by removing RDN."""
            if not self.value or "," not in self.value:
                return None
            return ",".join(self.value.split(",")[1:]).strip()

        def __str__(self) -> str:
            """String representation."""
            return self.value

    class LdifAttributes(FlextModels.Value):
        """LDIF attributes collection using FlextModels.Value for immutability."""

        data: dict[str, list[str]] = Field(
            default_factory=dict, description="Attribute data"
        )

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute values (case-insensitive)."""
            # Direct match first
            if name in self.data:
                return self.data[name]

            # Case-insensitive fallback
            name_lower = name.lower()
            for attr_name, values in self.data.items():
                if attr_name.lower() == name_lower:
                    return values
            return None

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists (case-insensitive)."""
            return self.get_attribute(name) is not None

        def get_single_attribute(self, name: str) -> str | None:
            """Get first value of attribute."""
            values = self.get_attribute(name)
            return values[0] if values else None

        def get_object_classes(self) -> list[str]:
            """Get objectClass values."""
            return self.get_attribute("objectClass") or []

        def is_person(self) -> bool:
            """Check if entry represents a person."""
            object_classes = {oc.lower() for oc in self.get_object_classes()}
            person_classes = {
                oc.lower() for oc in FlextLDIFConstants.LDAP_PERSON_CLASSES
            }
            return bool(object_classes.intersection(person_classes))

        def is_group(self) -> bool:
            """Check if entry represents a group."""
            object_classes = {oc.lower() for oc in self.get_object_classes()}
            group_classes = {oc.lower() for oc in FlextLDIFConstants.LDAP_GROUP_CLASSES}
            return bool(object_classes.intersection(group_classes))

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate attributes using FlextValidations."""
            for attr_name, attr_values in self.data.items():
                # Validate attribute name using flext-core string validation
                name_validation = FlextValidations.Rules.StringRules.validate_non_empty(
                    attr_name
                )
                if name_validation.is_failure:
                    error_msg = FlextLDIFConstants.FlextLDIFValidationMessages.INVALID_ATTRIBUTE_NAME.format(
                        attr_name=attr_name
                    )
                    return FlextResult[None].fail(error_msg)

                # Validate attribute name pattern (LDAP attribute names)
                attr_pattern = r"^[a-zA-Z][a-zA-Z0-9-]*$"
                pattern_validation = (
                    FlextValidations.Rules.StringRules.validate_pattern(
                        attr_name, attr_pattern, "attribute name"
                    )
                )
                if pattern_validation.is_failure:
                    error_msg = FlextLDIFConstants.FlextLDIFValidationMessages.INVALID_ATTRIBUTE_NAME.format(
                        attr_name=attr_name
                    )
                    return FlextResult[None].fail(error_msg)

                # Validate values are not empty using collection rules
                list_validation = (
                    FlextValidations.Rules.CollectionRules.validate_list_size(
                        attr_values, min_size=1
                    )
                )
                if list_validation.is_failure:
                    error_msg = FlextLDIFConstants.FlextLDIFValidationMessages.EMPTY_ATTRIBUTE_VALUE_NOT_ALLOWED.format(
                        attr_name=attr_name
                    )
                    return FlextResult[None].fail(error_msg)

            return FlextResult[None].ok(None)

    # =============================================================================
    # ENTITIES - Using FlextModels.Entity for mutable domain objects
    # =============================================================================

    class Entry(FlextModels.Entity):
        """LDIF entry entity using FlextModels.Entity base."""

        dn: FlextLDIFModels.DistinguishedName = Field(
            ..., description="Distinguished Name"
        )
        attributes: FlextLDIFModels.LdifAttributes = Field(
            default_factory=lambda: FlextLDIFModels.LdifAttributes(data={}),
            description="LDIF attributes",
        )

        @model_validator(mode="before")
        @classmethod
        def normalize_input_data(cls, data: object) -> object:
            """Normalize input data to proper types."""
            if not isinstance(data, dict):
                return data

            # Convert string DN to DistinguishedName
            if "dn" in data and isinstance(data["dn"], str):
                data["dn"] = {"value": data["dn"]}

            # Convert dict attributes to LdifAttributes
            if "attributes" in data and isinstance(data["attributes"], dict):
                data["attributes"] = {"data": data["attributes"]}

            return data

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate entry business rules using FlextResult pattern."""
            # Validate DN
            dn_result = self.dn.validate_business_rules()
            if not dn_result.is_success:
                return dn_result

            # Validate attributes
            attr_result = self.attributes.validate_business_rules()
            if not attr_result.is_success:
                return attr_result

            # Check for required objectClass using flext-core validation
            if not self.attributes.has_attribute("objectClass"):
                error_msg = (
                    FlextLDIFConstants.FlextLDIFValidationMessages.MISSING_OBJECTCLASS
                )
                return FlextResult[None].fail(error_msg)

            return FlextResult[None].ok(None)

        def get_attribute(self, name: str) -> list[str] | None:
            """Delegate to attributes collection."""
            return self.attributes.get_attribute(name)

        def has_attribute(self, name: str) -> bool:
            """Delegate to attributes collection."""
            return self.attributes.has_attribute(name)

        def get_single_attribute(self, name: str) -> str | None:
            """Delegate to attributes collection."""
            return self.attributes.get_single_attribute(name)

        def set_attribute(self, name: str, values: list[str]) -> None:
            """Set attribute values (creates new immutable attributes object)."""
            # Since attributes is immutable, create new one with updated data
            new_data = dict(self.attributes.data)
            new_data[name] = values
            object.__setattr__(
                self, "attributes", FlextLDIFModels.LdifAttributes(data=new_data)
            )

        def to_ldif(self) -> str:
            """Convert entry to LDIF format."""
            lines = [f"dn: {self.dn.value}"]

            # Sort attributes for consistent output
            for attr_name in sorted(self.attributes.data.keys()):
                values = self.attributes.data[attr_name]
                lines.extend(f"{attr_name}: {value}" for value in values)

            return "\n".join(lines) + "\n"

        @classmethod
        def from_ldif_block(cls, ldif_block: str) -> FlextLDIFModels.Entry:
            """Create entry from LDIF block text."""
            lines = [
                line.strip() for line in ldif_block.strip().split("\n") if line.strip()
            ]

            if not lines:
                msg = "Missing DN"
                raise FlextLDIFExceptions.validation_error(msg)

            # Parse DN
            first_line = lines[0]
            if not first_line.startswith("dn:"):
                msg = "Missing DN"
                raise FlextLDIFExceptions.validation_error(msg)

            dn_value = first_line[3:].strip()
            if not dn_value:
                msg = "Missing DN"
                raise FlextLDIFExceptions.validation_error(msg)

            # Parse attributes
            attributes_data: dict[str, list[str]] = {}
            for line in lines[1:]:
                if ":" not in line:
                    continue  # Skip invalid lines

                attr_name, attr_value = line.split(":", 1)
                attr_name = attr_name.strip()
                attr_value = attr_value.strip()

                if attr_name not in attributes_data:
                    attributes_data[attr_name] = []
                attributes_data[attr_name].append(attr_value)

            return cls(
                id=f"entry_{hash(dn_value)}",  # Required by FlextModels.Entity
                dn=FlextLDIFModels.DistinguishedName(value=dn_value),
                attributes=FlextLDIFModels.LdifAttributes(data=attributes_data),
            )

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specific object class."""
            object_classes = self.get_attribute("objectClass") or []
            return object_class.lower() in [oc.lower() for oc in object_classes]

        def is_person(self) -> bool:
            """Check if entry represents a person."""
            person_classes = ["person", "inetOrgPerson", "organizationalPerson"]
            return any(self.has_object_class(oc) for oc in person_classes)

        def is_group(self) -> bool:
            """Check if entry represents a group."""
            group_classes = [
                "group",
                "groupOfNames",
                "groupOfUniqueNames",
                "posixGroup",
            ]
            return any(self.has_object_class(oc) for oc in group_classes)

        def get_object_classes(self) -> list[str]:
            """Get all object classes for this entry."""
            return self.get_attribute("objectClass") or []

        def is_person_entry(self) -> bool:
            """Alias for is_person() for compatibility."""
            return self.is_person()

        def is_group_entry(self) -> bool:
            """Alias for is_group() for compatibility."""
            return self.is_group()

    # =============================================================================
    # CONFIGURATION - Using FlextModels.Config correctly
    # =============================================================================

    class Config(FlextModels.Config):
        """LDIF configuration using FlextModels.Config base."""

        # LDIF-specific settings
        encoding: str = Field(default="utf-8", description="File encoding")
        line_separator: str = Field(default="\n", description="Line separator")
        max_line_length: int = Field(
            default=76, description="Maximum line length", ge=20, le=1000
        )
        fold_lines: bool = Field(default=True, description="Enable line folding")
        validate_dn: bool = Field(default=True, description="Enable DN validation")
        validate_attributes: bool = Field(
            default=True, description="Enable attribute validation"
        )
        strict_parsing: bool = Field(default=False, description="Strict parsing mode")
        strict_validation: bool = Field(
            default=False, description="Strict validation mode"
        )
        allow_empty_values: bool = Field(
            default=True, description="Allow empty attribute values"
        )
        normalize_attribute_names: bool = Field(
            default=True, description="Normalize attribute names"
        )
        sort_attributes: bool = Field(
            default=True, description="Sort attributes in output"
        )
        max_entries: int = Field(
            default=10000, description="Maximum entries to process", ge=1
        )

        @field_validator("encoding")
        @classmethod
        def validate_encoding(cls, v: str) -> str:
            """Validate encoding using flext-core pattern."""
            # Validate non-empty encoding string
            validation_result = FlextValidations.Rules.StringRules.validate_non_empty(v)
            if validation_result.is_failure:
                msg = f"Invalid encoding: {v}"
                raise FlextLDIFExceptions.configuration_error(msg)

            # Validate common encodings pattern
            valid_encodings = [
                "utf-8",
                "utf-16",
                "utf-32",
                "ascii",
                "iso-8859-1",
                "cp1252",
            ]
            if v.lower() not in valid_encodings:
                msg = f"Unsupported encoding: {v}"
                raise FlextLDIFExceptions.configuration_error(msg)
            return v

    # =============================================================================
    # FACTORY - Zero-duplication object creation
    # =============================================================================

    class Factory:
        """Factory using FlextModels patterns for object creation."""

        @staticmethod
        def create_dn(value: str) -> FlextLDIFModels.DistinguishedName:
            """Create DN value object."""
            return FlextLDIFModels.DistinguishedName(value=value)

        @staticmethod
        def create_attributes(
            data: dict[str, list[str]] | None = None,
        ) -> FlextLDIFModels.LdifAttributes:
            """Create attributes value object."""
            return FlextLDIFModels.LdifAttributes(data=data or {})

        @staticmethod
        def create_entry(data: dict[str, object]) -> FlextLDIFModels.Entry:
            """Create entry entity using FlextModels pattern."""
            # Extract dn
            dn_value = data.get("dn", "")
            if isinstance(dn_value, str):
                dn_obj: FlextLDIFModels.DistinguishedName = (
                    FlextLDIFModels.DistinguishedName(value=dn_value)
                )
            elif isinstance(dn_value, FlextLDIFModels.DistinguishedName):
                dn_obj = dn_value
            else:
                dn_obj = FlextLDIFModels.DistinguishedName(value=str(dn_value))

            # Extract attributes
            attrs_data = data.get("attributes", {})
            if isinstance(attrs_data, dict):
                attrs_obj: FlextLDIFModels.LdifAttributes = (
                    FlextLDIFModels.LdifAttributes(data=attrs_data)
                )
            elif isinstance(attrs_data, FlextLDIFModels.LdifAttributes):
                attrs_obj = attrs_data
            else:
                attrs_obj = FlextLDIFModels.LdifAttributes(data={})

            # Create entity with required ID
            entry_id = f"entry_{hash(str(dn_obj))}"
            return FlextLDIFModels.Entry(id=entry_id, dn=dn_obj, attributes=attrs_obj)

        @staticmethod
        def create_config(**kwargs: object) -> FlextLDIFModels.Config:
            """Create configuration using FlextModels pattern."""
            return FlextLDIFModels.Config.model_validate(kwargs)

    # =============================================================================
    # VALIDATION HELPERS - Using FlextValidations
    # =============================================================================

    @staticmethod
    @lru_cache(maxsize=1000)
    def validate_ldap_dn(dn: str) -> bool:
        """Validate LDAP DN using cached validation."""
        dn_pattern = r"^[^=]+=[^=]+(,[^=]+=[^=]+)*$"
        pattern_result = FlextValidations.Rules.StringRules.validate_pattern(
            dn, dn_pattern, "DN format"
        )
        return pattern_result.is_success

    @staticmethod
    @lru_cache(maxsize=1000)
    def validate_ldap_attribute_name(name: str) -> bool:
        """Validate LDAP attribute name using cached validation."""
        attr_pattern = r"^[a-zA-Z][a-zA-Z0-9-]*$"
        pattern_result = FlextValidations.Rules.StringRules.validate_pattern(
            name, attr_pattern, "attribute name"
        )
        return pattern_result.is_success

    # Required by FlextModels.AggregateRoot
    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate aggregate business rules."""
        return FlextResult[None].ok(None)


# Export only the consolidated class
__all__ = ["FlextLDIFModels"]
