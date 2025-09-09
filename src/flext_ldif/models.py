"""FLEXT-LDIF Domain Models - Using flext-core SOURCE OF TRUTH.

Minimal LDIF-specific domain models using flext-core foundation directly.
No duplication of existing functionality - only domain-specific additions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Generator
from typing import ClassVar, override

from flext_core import (
    FlextModels,
    FlextResult,
    FlextTypes,
    FlextUtilities,
    FlextValidations,
)
from pydantic import ConfigDict, Field, field_validator, model_validator

from flext_ldif.constants import FlextLDIFConstants
from flext_ldif.exceptions import FlextLDIFExceptions


class FlextLDIFModels(FlextModels.Config):
    """Unified LDIF domain models with enterprise-grade architecture.

    Single consolidated class containing all LDIF model definitions
    following SOLID principles, Python 3.13 patterns, and FLEXT ecosystem integration.

    Nested models provide organized functionality while maintaining
    single class responsibility and unified architecture.
    """

    class DistinguishedName(FlextModels.Value):
        """Distinguished Name value object for LDAP entries.

        Immutable value object representing LDAP Distinguished Names
        with comprehensive validation and business rules.
        """

        value: str = Field(..., min_length=1, description="LDAP Distinguished Name")

        @field_validator("value")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Validate DN format using flext-core validators.

            Args:
                v: DN value to validate

            Returns:
                Validated and normalized DN value

            Raises:
                ValidationError: If DN format is invalid

            """
            if not v or not v.strip():
                msg = FlextLDIFConstants.VALIDATION_MESSAGES["MISSING_DN"]
                raise FlextLDIFExceptions.validation_error(msg)

            # Use flext-core validation system
            validation_result = FlextValidations.Rules.StringRules.validate_non_empty(
                v.strip()
            )
            if validation_result.is_failure:
                msg = FlextLDIFConstants.VALIDATION_MESSAGES["INVALID_DN"]
                raise FlextLDIFExceptions.validation_error(msg, dn=v)

            # Basic DN format validation
            dn_pattern = FlextLDIFConstants.DN_PATTERN
            pattern_result = FlextValidations.Rules.StringRules.validate_pattern(
                v.strip(), dn_pattern, "DN format"
            )
            if pattern_result.is_failure:
                msg = FlextLDIFConstants.VALIDATION_MESSAGES["INVALID_DN"]
                raise FlextLDIFExceptions.validation_error(msg, dn=v)

            return v.strip()

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate DN business rules using FlextResult patterns.

            Returns:
                FlextResult indicating validation success or failure

            """
            if not self.value:
                return FlextResult[None].fail(
                    FlextLDIFConstants.VALIDATION_MESSAGES["MISSING_DN"]
                )

            # Check minimum DN components using flext-core utilities
            components = [c.strip() for c in self.value.split(",") if c.strip()]
            if len(components) < FlextLDIFConstants.MIN_DN_COMPONENTS:
                error_msg = (
                    f"DN has too few components: {len(components)}, minimum required: {FlextLDIFConstants.MIN_DN_COMPONENTS}"
                )
                return FlextResult[None].fail(error_msg)

            return FlextResult[None].ok(None)

        def get_rdn(self) -> str:
            """Get Relative Distinguished Name (first component).

            Returns:
                RDN string or empty string if DN is empty

            """
            if not self.value:
                return ""
            return self.value.split(",")[0].strip()

        def get_parent_dn(self) -> str | None:
            """Get parent DN by removing RDN.

            Returns:
                Parent DN string or None if no parent exists

            """
            if not self.value or "," not in self.value:
                return None
            return ",".join(self.value.split(",")[1:]).strip()

        def get_depth(self) -> int:
            """Get DN depth (number of components).

            Returns:
                Number of DN components

            """
            if not self.value:
                return 0
            return len([c for c in self.value.split(",") if c.strip()])

        def __str__(self) -> str:
            """String representation of DN."""
            return self.value

    class LdifAttributes(FlextModels.Value):
        """LDIF attributes collection with case-insensitive access.

        Immutable value object for managing LDAP attribute collections
        with comprehensive validation and utility methods.
        """

        data: dict[str, FlextTypes.Core.StringList] = Field(
            default_factory=dict,
            description="Attribute name-value pairs"
        )

        def get_attribute(self, name: str) -> FlextTypes.Core.StringList | None:
            """Get attribute values with case-insensitive lookup.

            Args:
                name: Attribute name to lookup

            Returns:
                List of attribute values or None if not found

            """
            # Direct match first for performance
            if name in self.data:
                return self.data[name]

            # Case-insensitive fallback
            name_normalized = FlextUtilities.TextProcessor.clean_text(name).lower()
            for attr_name, values in self.data.items():
                attr_normalized = FlextUtilities.TextProcessor.clean_text(attr_name).lower()
                if attr_normalized == name_normalized:
                    return values

            return None

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists (case-insensitive).

            Args:
                name: Attribute name to check

            Returns:
                True if attribute exists, False otherwise

            """
            return self.get_attribute(name) is not None

        def get_single_attribute(self, name: str) -> str | None:
            """Get first value of attribute.

            Args:
                name: Attribute name to get first value from

            Returns:
                First attribute value or None if not found

            """
            values = self.get_attribute(name)
            return values[0] if values else None

        def get_attribute_count(self) -> int:
            """Get total number of attributes.

            Returns:
                Number of attributes in collection

            """
            return len(self.data)

        def get_value_count(self) -> int:
            """Get total number of attribute values.

            Returns:
                Total number of values across all attributes

            """
            return sum(len(values) for values in self.data.values())

        def get_object_classes(self) -> FlextTypes.Core.StringList:
            """Get objectClass values.

            Returns:
                List of objectClass values or empty list

            """
            return self.get_attribute("objectClass") or []

        def is_person(self) -> bool:
            """Check if entry represents a person object.

            Returns:
                True if entry has person-related objectClass values

            """
            object_classes = {oc.lower() for oc in self.get_object_classes()}
            person_classes = {oc.lower() for oc in FlextLDIFConstants.LDAP_PERSON_CLASSES}
            return bool(object_classes.intersection(person_classes))

        def is_group(self) -> bool:
            """Check if entry represents a group object.

            Returns:
                True if entry has group-related objectClass values

            """
            object_classes = {oc.lower() for oc in self.get_object_classes()}
            group_classes = {oc.lower() for oc in FlextLDIFConstants.LDAP_GROUP_CLASSES}
            return bool(object_classes.intersection(group_classes))

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate attributes using flext-core validation rules.

            Returns:
                FlextResult indicating validation success or failure

            """
            if not self.data:
                return FlextResult[None].ok(None)

            for attr_name, attr_values in self.data.items():
                # Validate attribute name using flext-core string validation
                name_validation = FlextValidations.Rules.StringRules.validate_non_empty(
                    attr_name
                )
                if name_validation.is_failure:
                    error_msg = FlextLDIFConstants.VALIDATION_MESSAGES["INVALID_ATTRIBUTE_NAME"]
                    return FlextResult[None].fail(error_msg)

                # Validate attribute name pattern (LDAP attribute names)
                attr_pattern = r"^[a-zA-Z][a-zA-Z0-9-]*$"
                pattern_validation = FlextValidations.Rules.StringRules.validate_pattern(
                    attr_name, attr_pattern, "attribute name"
                )
                if pattern_validation.is_failure:
                    error_msg = FlextLDIFConstants.VALIDATION_MESSAGES["INVALID_ATTRIBUTE_NAME"]
                    return FlextResult[None].fail(error_msg)

                # Validate values are not empty using collection rules
                list_validation = FlextValidations.Rules.CollectionRules.validate_list_size(
                    attr_values, min_size=1
                )
                if list_validation.is_failure:
                    error_msg = f"Empty attribute values not allowed for: {attr_name}"
                    return FlextResult[None].fail(error_msg)

                # Validate individual values are not empty or whitespace-only
                for value in attr_values:
                    if not value or not value.strip():
                        error_msg = f"Empty attribute values not allowed for: {attr_name}"
                        return FlextResult[None].fail(error_msg)

            return FlextResult[None].ok(None)

        # Dictionary-like interface for compatibility
        def __getitem__(self, key: str) -> FlextTypes.Core.StringList:
            """Allow dict-like access to attributes."""
            result = self.get_attribute(key)
            if result is None:
                msg = f"Attribute '{key}' not found"
                raise KeyError(msg)
            return result

        def __contains__(self, key: str) -> bool:
            """Allow 'in' operator for attributes."""
            return self.has_attribute(key)

        def __iter__(self) -> Generator[tuple[str, FlextTypes.Core.StringList]]:
            """Allow iteration over attribute name-value pairs."""
            yield from self.data.items()

        def __len__(self) -> int:
            """Return number of attributes."""
            return len(self.data)

        def keys(self) -> object:
            """Return attribute names."""
            return self.data.keys()

        def values(self) -> object:
            """Return attribute values."""
            return self.data.values()

        def items(self) -> object:
            """Return attribute name-value pairs."""
            return self.data.items()

    class Entry(FlextModels.Value):
        """LDIF entry representing a complete directory entry.

        Immutable value object representing complete LDAP directory entries
        with DN and attributes, including comprehensive validation and utilities.
        """

        model_config: ClassVar[ConfigDict] = ConfigDict(
            extra="allow"  # LDIF entries can have dynamic attributes
        )

        dn: FlextLDIFModels.DistinguishedName = Field(..., description="Distinguished Name")
        attributes: FlextLDIFModels.LdifAttributes = Field(
            default_factory=lambda: FlextLDIFModels.LdifAttributes(data={}),
            description="LDIF attributes",
        )

        @model_validator(mode="before")
        @classmethod
        def validate_entry_data(cls, values: dict[str, object]) -> dict[str, object]:
            """Validate and normalize entry data before model creation.

            Args:
                values: Raw entry data dictionary

            Returns:
                Validated and normalized entry data

            """
            if isinstance(values, dict):
                # Handle string DN conversion
                if "dn" in values and isinstance(values["dn"], str):
                    values["dn"] = FlextLDIFModels.DistinguishedName(value=values["dn"])

                # Handle raw attributes dictionary
                if "attributes" in values and isinstance(values["attributes"], dict):
                    values["attributes"] = FlextLDIFModels.LdifAttributes(
                        data=values["attributes"]
                    )
                elif "attributes" not in values:
                    values["attributes"] = FlextLDIFModels.LdifAttributes(data={})

            return values

        def get_attribute(self, name: str) -> FlextTypes.Core.StringList | None:
            """Get attribute values from entry.

            Args:
                name: Attribute name to get

            Returns:
                List of attribute values or None if not found

            """
            return self.attributes.get_attribute(name)

        def has_attribute(self, name: str) -> bool:
            """Check if entry has attribute.

            Args:
                name: Attribute name to check

            Returns:
                True if attribute exists, False otherwise

            """
            return self.attributes.has_attribute(name)

        def get_single_attribute(self, name: str) -> str | None:
            """Get first value of attribute.

            Args:
                name: Attribute name to get first value from

            Returns:
                First attribute value or None if not found

            """
            return self.attributes.get_single_attribute(name)

        def is_person(self) -> bool:
            """Check if entry represents a person.

            Returns:
                True if entry has person-related objectClass values

            """
            return self.attributes.is_person()

        def is_group(self) -> bool:
            """Check if entry represents a group.

            Returns:
                True if entry has group-related objectClass values

            """
            return self.attributes.is_group()

        def is_person_entry(self) -> bool:
            """Alias for is_person() for compatibility.

            Returns:
                True if entry represents a person

            """
            return self.is_person()

        def is_group_entry(self) -> bool:
            """Alias for is_group() for compatibility.

            Returns:
                True if entry represents a group

            """
            return self.is_group()

        def is_valid_entry(self) -> bool:
            """Check if entry is valid (has required DN and objectClass).

            Returns:
                True if entry has valid DN and objectClass attributes

            """
            # Check if DN exists and is not empty
            if not self.dn or not str(self.dn).strip():
                return False

            # Check if entry has objectClass attribute
            object_classes = self.attributes.data.get("objectClass", [])
            if not object_classes:
                return False

            # If we have a list, check if it's not empty
            return not (isinstance(object_classes, list) and not object_classes)

        def is_add_operation(self) -> bool:
            """Check if entry represents an add operation.

            Returns:
                True if this is an add operation (default for LDIF entries)

            """
            return True  # LDIF entries are typically add operations

        def is_delete_operation(self) -> bool:
            """Check if entry represents a delete operation.

            Returns:
                False - standard LDIF entries are not delete operations

            """
            return False

        def is_modify_operation(self) -> bool:
            """Check if entry represents a modify operation.

            Returns:
                False - standard LDIF entries are not modify operations

            """
            return False

        def get_rdn(self) -> str:
            """Get Relative Distinguished Name.

            Returns:
                RDN string or empty string if DN is empty

            """
            return self.dn.get_rdn()

        def get_parent_dn(self) -> str | None:
            """Get parent DN.

            Returns:
                Parent DN string or None if no parent exists

            """
            return self.dn.get_parent_dn()

        def to_ldif(self) -> str:
            """Convert entry to LDIF string format.

            Returns:
                LDIF string representation of the entry

            """
            lines = [f"dn: {self.dn.value}"]

            # Sort attributes for consistent output
            for attr_name in sorted(self.attributes.data.keys()):
                values = self.attributes.data[attr_name]
                for value in values:
                    # Clean value using flext-core text processor
                    clean_value = FlextUtilities.TextProcessor.clean_text(str(value))
                    lines.append(f"{attr_name}: {clean_value}")

            return "\n".join(lines)

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate entry business rules.

            Returns:
                FlextResult indicating validation success or failure

            """
            # Validate DN
            dn_validation = self.dn.validate_business_rules()
            if dn_validation.is_failure:
                return dn_validation

            # Validate attributes
            attr_validation = self.attributes.validate_business_rules()
            if attr_validation.is_failure:
                return attr_validation

            # Validate objectClass presence (required for LDAP entries)
            if not self.has_attribute("objectClass"):
                error_msg = FlextLDIFConstants.VALIDATION_MESSAGES["MISSING_OBJECTCLASS"]
                return FlextResult[None].fail(error_msg)

            return FlextResult[None].ok(None)

        def __str__(self) -> str:
            """String representation of entry."""
            return f"Entry({self.dn.value})"

        @classmethod
        def from_ldif_block(cls, ldif_block: str) -> FlextLDIFModels.Entry:
            """Create Entry from LDIF block text - simple alias for test compatibility.

            Args:
                ldif_block: LDIF text block

            Returns:
                Parsed Entry object

            """
            lines = ldif_block.strip().split("\n")
            dn = None
            attributes: dict[str, list[str]] = {}

            for line in lines:
                if ":" not in line:
                    continue  # Skip lines without colon (invalid LDIF lines)

                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()

                if key.lower() == "dn":
                    dn = value
                else:
                    if key not in attributes:
                        attributes[key] = []
                    attributes[key].append(value)

            if dn is None:
                missing_dn_msg = "LDIF block must contain a DN"
                raise ValueError(missing_dn_msg)

            return cls(
                dn=FlextLDIFModels.DistinguishedName(value=dn),
                attributes=FlextLDIFModels.LdifAttributes(data=attributes)
            )

    class Config(FlextModels.Config):
        """LDIF processing configuration with enterprise defaults.

        Configuration object for LDIF processing operations with
        comprehensive validation and enterprise-grade defaults.
        """

        model_config: ClassVar[ConfigDict] = ConfigDict(
            extra="allow"  # Allow extra fields for test compatibility
        )

        # Processing options
        strict_validation: bool = Field(
            default=True,
            description="Enable strict validation mode"
        )
        max_entries: int = Field(
            default=10000,
            gt=0,
            description="Maximum number of entries to process"
        )
        buffer_size: int = Field(
            default=8192,
            gt=0,
            description="Buffer size for file operations"
        )

        # Encoding options
        default_encoding: str = Field(
            default="utf-8",
            description="Default file encoding"
        )

        # Validation options
        validate_dn_format: bool = Field(
            default=True,
            description="Validate DN format compliance"
        )
        validate_attribute_names: bool = Field(
            default=True,
            description="Validate attribute name patterns"
        )
        allow_empty_values: bool = Field(
            default=False,
            description="Allow empty attribute values"
        )
        sort_attributes: bool = Field(
            default=False,
            description="Sort attribute names in output"
        )

        # Performance options
        use_caching: bool = Field(
            default=True,
            description="Enable result caching"
        )
        cache_size: int = Field(
            default=1000,
            gt=0,
            description="Maximum cache entries"
        )

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate configuration business rules.

            Returns:
                FlextResult indicating validation success or failure

            """
            # Validate reasonable limits
            if self.max_entries > FlextLDIFConstants.Analytics.MAX_ENTRIES_LIMIT:
                return FlextResult[None].fail("max_entries cannot exceed 1,000,000")

            if self.buffer_size > 1024 * 1024:  # 1MB buffer max
                return FlextResult[None].fail("buffer_size cannot exceed 1MB")

            if self.cache_size > FlextLDIFConstants.Analytics.MAX_CACHE_SIZE:
                return FlextResult[None].fail("cache_size cannot exceed 10,000")

            return FlextResult[None].ok(None)

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate LDIF models business rules.

        Returns:
            FlextResult[None]: Validation result

        """
        try:
            # Call parent validation first (FlextModels.Config validation)
            parent_result = super().validate_business_rules()
            if parent_result.is_failure:
                return parent_result

            # LDIF-specific validation rules
            # For LDIF models, we validate that the constants and factory are properly configured
            if not hasattr(FlextLDIFConstants, "LDIF"):
                return FlextResult[None].fail("LDIF constants not properly configured")

            # All LDIF business rules passed
            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"LDIF models validation failed: {e}")

    # Factory com aliases simples para compatibilidade de testes
    class Factory:
        """Factory usando FlextModels como SOURCE OF TRUTH com aliases simples."""

        @staticmethod
        def create_entry(data: dict[str, object]) -> FlextLDIFModels.Entry:
            """Alias simples para Entry.model_validate."""
            return FlextLDIFModels.Entry.model_validate(data)

        @staticmethod
        def create_config(**kwargs: object) -> FlextLDIFModels.Config:
            """Alias simples para Config."""
            # Handle optional config_path parameter if available
            if "config_path" in kwargs:
                config_path = kwargs.pop("config_path")
                if config_path is not None:
                    return FlextLDIFModels.Config(str(config_path), **kwargs)  # type: ignore[arg-type]
            # Create config without required positional argument
            return FlextLDIFModels.Config("", **kwargs)  # type: ignore[arg-type]

        # Acesso direto aos métodos do FlextModels como SOURCE OF TRUTH
        @staticmethod
        def create_optimized_model(*args: object, **kwargs: object) -> object:
            """Use FlextModels factory method directly."""
            return FlextModels.create_optimized_model(*args, **kwargs)


__all__ = ["FlextLDIFModels"]
