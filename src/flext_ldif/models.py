"""FLEXT-LDIF Domain Models - Consolidated Class Structure.

Single consolidated class containing ALL LDIF models following FLEXT patterns.
Individual models available as nested classes for organization.
"""

from __future__ import annotations

import hashlib
import json
import re as _re
from collections import UserDict
from collections.abc import Callable
from functools import lru_cache
from typing import ClassVar, cast, override

from flext_core import (
    FlextConfig,
    FlextModels,
    FlextResult,
    FlextUtilities,
)
from pydantic import Field, field_validator, model_validator

from flext_ldif.constants import FlextLDIFConstants
from flext_ldif.exceptions import FlextLDIFExceptions

ValidatorFunc = Callable[[str], bool]


class AttributesDict(UserDict[str, list[str]]):
    """Special dict that also provides attributes property for compatibility."""

    def __init__(self, initial_data: dict[str, list[str]] | None = None) -> None:
        """Initialize with proper data handling."""
        super().__init__()
        if initial_data:
            # Use the actual data dict from UserDict directly
            self.data.update(initial_data)

    @property
    def attributes(self) -> dict[str, list[str]]:
        """Return dictionary representation for entry.attributes.attributes compatibility."""
        return dict(self)

    def validate_domain_rules(self) -> None:
        """Validate domain rules for attributes."""
        for attr_name, attr_values in self.items():
            if not FlextLDIFModels._validate_ldap_attribute_name(attr_name):
                msg = f"Invalid LDAP attribute name: {attr_name}"
                raise FlextLDIFExceptions.ValidationError(msg)
            # Values should always be lists in AttributesDict by definition
            if not attr_values:
                msg = f"Attribute cannot be empty: {attr_name}"
                raise FlextLDIFExceptions.ValidationError(msg)

    def get_case_insensitive(self, key: str) -> list[str] | None:
        """Case-insensitive get method."""
        # First try exact match
        if super().__contains__(key):
            return super().__getitem__(key)

        # Then try case-insensitive match
        key_lower = key.lower()
        for actual_key in self:
            if actual_key.lower() == key_lower:
                return super().__getitem__(actual_key)

        return None

    def __contains__(self, key: object) -> bool:
        """Case-insensitive contains check."""
        if not isinstance(key, str):
            return super().__contains__(key)

        # First try exact match
        if super().__contains__(key):
            return True

        # Then try case-insensitive match
        key_lower = key.lower()
        return any(actual_key.lower() == key_lower for actual_key in self)


# Loose helper functions moved to FlextLDIFModels class for FLEXT compliance


# =============================================================================
# CONSOLIDATED MODELS CLASS - Single class containing ALL LDIF models
# =============================================================================


class FlextLDIFModels(FlextModels.AggregateRoot):
    """Single consolidated class containing ALL LDIF models.

    Consolidates ALL model definitions into one class following FLEXT patterns.
    Individual models available as nested classes for organization.
    """

    # Reference to module-level AttributesDict for single-class-per-module pattern
    AttributesDict: ClassVar[type[AttributesDict]] = AttributesDict

    class DistinguishedName(FlextModels.Value):
        """Distinguished Name value object."""

        value: str = Field(...)

        def __str__(self) -> str:
            """Return the DN value as string."""
            return self.value

        def __eq__(self, other: object) -> bool:
            """Compare DN with another DN or string."""
            if isinstance(other, str):
                return self.value == other
            if hasattr(other, "value"):
                other_value = getattr(other, "value", None)
                if isinstance(other_value, str):
                    return self.value == other_value
            return False

        def __hash__(self) -> int:
            """Return hash of DN value for use in sets and dicts."""
            return hash(self.value)

        def to_json(self, **_kwargs: object) -> str:
            """Serialize to JSON string - workaround for Pydantic serialization issue."""
            return json.dumps(self.model_dump(), default=str)

        @field_validator("value")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate and normalize DN format."""
            if not v or not isinstance(v, str) or not v.strip():
                # Domain-specific validation error
                msg = FlextLDIFConstants.FlextLDIFValidationMessages.INVALID_DN.format(
                    dn=v or "empty"
                )
                raise FlextLDIFExceptions.ValidationError(msg)

            # Use local validator to avoid circular dependency
            _, validate_dn = FlextLDIFModels._get_ldap_validators()
            if not validate_dn(v.strip()):
                msg = FlextLDIFConstants.FlextLDIFValidationMessages.INVALID_DN.format(
                    dn=v
                )
                raise FlextLDIFExceptions.ValidationError(msg)

            # Normalize: strip but preserve case for DN
            return v.strip()

        def validate_domain_rules(self) -> None:
            """Validate business rules for DN."""
            if not self.value:
                msg = FlextLDIFConstants.FlextLDIFValidationMessages.EMPTY_DN
                raise FlextLDIFExceptions.ValidationError(msg)

            # Check minimum DN components (at least one attribute=value pair)
            components = [c.strip() for c in self.value.split(",") if c.strip()]
            if len(components) < FlextLDIFConstants.MIN_DN_COMPONENTS:
                msg = (
                    FlextLDIFConstants.FlextLDIFValidationMessages.DN_TOO_SHORT.format(
                        components=len(components),
                        minimum=FlextLDIFConstants.MIN_DN_COMPONENTS,
                    )
                )
                raise FlextLDIFExceptions.ValidationError(msg)

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate business rules for DN - required by FlextModels."""
            try:
                self.validate_domain_rules()
                return FlextResult[None].ok(None)
            except FlextLDIFExceptions.ValidationError as e:
                return FlextResult[None].fail(str(e))

        def get_rdn(self) -> str:
            """Get the Relative Distinguished Name (first component)."""
            if not self.value:
                return ""
            return self.value.split(",")[0].strip()

        def get_parent_dn(self) -> str:
            """Get parent DN (all components except first)."""
            if not self.value:
                return ""
            components = self.value.split(",")
            if len(components) <= 1:
                return ""
            return ",".join(components[1:]).strip()

        def get_base_dn(self) -> str:
            """Get base DN (last component)."""
            if not self.value:
                return ""
            components = self.value.split(",")
            return components[-1].strip() if components else ""

        @classmethod
        def from_components(cls, *components: str) -> FlextLDIFModels.DistinguishedName:
            """Create DN from components."""
            if not components:
                msg = FlextLDIFConstants.FlextLDIFValidationMessages.EMPTY_DN
                raise FlextLDIFExceptions.ValidationError(msg)

            dn_value = ",".join(str(c).strip() for c in components if c.strip())
            return cls(value=dn_value)

    class Attributes(FlextModels.Value):
        """LDIF attributes collection value object."""

        data: dict[str, list[str]] = Field(default_factory=dict)

        def to_json(self, **_kwargs: object) -> str:
            """Serialize to JSON string."""
            return json.dumps(self.model_dump(), default=str)

        @field_validator("data")
        @classmethod
        def validate_attributes(cls, v: object) -> dict[str, list[str]]:
            """Validate attribute names and values."""
            if not isinstance(v, dict):
                msg = f"{FlextLDIFConstants.FlextLDIFValidationMessages.INVALID_ATTRIBUTES}: {v!r}"
                raise FlextLDIFExceptions.ValidationError(msg)

            validate_attr_name, _ = FlextLDIFModels._get_ldap_validators()
            validated = {}

            # We know v is a dict at this point due to the isinstance check above
            v_dict = cast("dict[str, object]", v)

            for attr_name, attr_values in v_dict.items():
                # Validate attribute name
                if not validate_attr_name(attr_name):
                    msg = FlextLDIFConstants.FlextLDIFValidationMessages.INVALID_ATTRIBUTE_NAME.format(
                        attr_name=attr_name
                    )
                    raise FlextLDIFExceptions.ValidationError(msg)

                # Ensure values is a list
                if not isinstance(attr_values, list):
                    values_list = [str(attr_values)]
                else:
                    values_list = attr_values

                # Validate each value is string
                validated_values = []
                for val in values_list:
                    validated_val = str(val) if not isinstance(val, str) else val
                    validated_values.append(validated_val)

                validated[attr_name.lower()] = validated_values

            return validated

        def validate_domain_rules(self) -> None:
            """Validate business rules for attributes."""
            if not self.data:
                return  # Empty attributes are allowed

            # Check for required objectClass
            if "objectclass" not in self.data:
                msg = FlextLDIFConstants.FlextLDIFValidationMessages.MISSING_OBJECTCLASS
                raise FlextLDIFExceptions.ValidationError(msg)

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate business rules for attributes - required by FlextModels."""
            try:
                self.validate_domain_rules()
                return FlextResult[None].ok(None)
            except FlextLDIFExceptions.ValidationError as e:
                return FlextResult[None].fail(str(e))

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute values by name (case-insensitive)."""
            # First try exact match
            if name in self.data:
                return self.data[name]

            # Then try case-insensitive match
            name_lower = name.lower()
            for attr_name in self.data:
                if attr_name.lower() == name_lower:
                    return self.data[attr_name]

            return None

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            return name.lower() in self.data

        def add_attribute(self, name: str, value: str | list[str]) -> None:
            """Add attribute value(s)."""
            validate_attr_name, _ = FlextLDIFModels._get_ldap_validators()
            if not validate_attr_name(name):
                msg = FlextLDIFConstants.FlextLDIFValidationMessages.INVALID_ATTRIBUTE_NAME.format(
                    name=name
                )
                raise FlextLDIFExceptions.ValidationError(msg)

            values = [value] if isinstance(value, str) else list(value)
            attr_key = name.lower()

            if attr_key in self.data:
                self.data[attr_key].extend(values)
            else:
                self.data[attr_key] = values

        def remove_attribute(self, name: str) -> None:
            """Remove attribute."""
            self.data.pop(name.lower(), None)

        @property
        def attributes(self) -> dict[str, list[str]]:
            """Get the raw attributes dictionary."""
            return self.data

        def get_object_classes(self) -> list[str]:
            """Get objectClass values."""
            return self.get_attribute("objectclass") or []

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

    class Entry(FlextModels.Value):
        """LDIF entry domain entity."""

        dn: FlextLDIFModels.DistinguishedName = Field(...)
        attributes: AttributesDict = Field(default_factory=AttributesDict)

        def __init__(self, **data: object) -> None:
            """Initialize with auto-generated ID if not provided."""
            # Ensure we have an id for FlextModels
            if "id" not in data and "dn" in data:
                # Generate ID from DN if not provided
                dn_value = (
                    str(data["dn"])
                    if not isinstance(data["dn"], FlextLDIFModels.DistinguishedName)
                    else data["dn"].value
                )
                dn_hash = hashlib.sha256(dn_value.encode()).hexdigest()[:16]
                data["id"] = f"ldif_entry_{dn_hash}"
            elif "id" not in data:
                # Fallback ID generation using FlextUtilities
                data["id"] = FlextUtilities.Generators.generate_entity_id()

            # Ensure attributes field is provided and is AttributesDict
            if "attributes" not in data:
                data["attributes"] = AttributesDict()
            elif not isinstance(data["attributes"], AttributesDict):
                # Convert regular dict to AttributesDict
                attr_data = data["attributes"]
                if isinstance(attr_data, dict):
                    data["attributes"] = AttributesDict(attr_data)
                else:
                    data["attributes"] = AttributesDict()

            # Extract only the fields that belong to this Entry class
            entry_fields = {"dn", "attributes"}
            entry_data = {k: v for k, v in data.items() if k in entry_fields}

            # Initialize the parent Value class with default values
            super().__init__()

            # Set the Entry-specific fields
            for field_name, value in entry_data.items():
                setattr(self, field_name, value)

        @model_validator(mode="before")
        @classmethod
        def validate_dn_conversion(cls, data: object) -> object:
            """Convert string DN to DistinguishedName object before validation."""
            if isinstance(data, dict) and "dn" in data:
                dn_value = data["dn"]
                if isinstance(dn_value, str):
                    data["dn"] = {"value": dn_value}
            return data

        def to_json(self, **_kwargs: object) -> str:
            """Serialize to JSON string."""
            return json.dumps(self.model_dump(), default=str)

        def get_entity_id(self) -> str:
            """Get unique entity identifier based on DN."""
            dn_hash = hashlib.sha256(self.dn.value.encode()).hexdigest()[:16]
            return f"ldif_entry_{dn_hash}"

        def validate_domain_rules(self) -> None:
            """Validate business rules for LDIF entry."""
            # Validate DN
            self.dn.validate_domain_rules()

            # Validate attributes - check for required objectClass
            if not self.attributes:
                return  # Empty attributes are allowed

            # Check for required objectClass (case insensitive)
            has_objectclass = any(
                key.lower() == "objectclass" for key in self.attributes
            )
            if not has_objectclass:
                msg = FlextLDIFConstants.FlextLDIFValidationMessages.MISSING_OBJECTCLASS
                raise FlextLDIFExceptions.ValidationError(msg)

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate business rules for entry - required by FlextModels."""
            try:
                self.validate_domain_rules()
                return FlextResult[None].ok(None)
            except FlextLDIFExceptions.ValidationError as e:
                return FlextResult[None].fail(str(e))

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute values."""
            return self.attributes.get_case_insensitive(name)

        def get_single_attribute(self, name: str) -> str | None:
            """Get single attribute value."""
            values = self.get_attribute(name)
            return values[0] if values else None

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            return name.lower() in self.attributes

        def set_attribute(self, name: str, value: str | list[str]) -> None:
            """Set attribute value(s), replacing any existing values."""
            values = [value] if isinstance(value, str) else list(value)
            self.attributes[name.lower()] = values

        def get_object_classes(self) -> list[str]:
            """Get objectClass values."""
            return self.get_attribute("objectclass") or []

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specific object class (case-insensitive)."""
            object_classes = [oc.lower() for oc in self.get_object_classes()]
            return object_class.lower() in object_classes

        def is_add_operation(self) -> bool:
            """Check if entry is an add operation (default LDIF behavior)."""
            changetype = self.get_attribute("changetype")
            if not changetype:
                return True  # Default LDIF behavior is add
            return changetype[0].lower() == "add"

        def is_modify_operation(self) -> bool:
            """Check if entry is a modify operation."""
            changetype = self.get_attribute("changetype")
            return bool(changetype and changetype[0].lower() == "modify")

        def is_delete_operation(self) -> bool:
            """Check if entry is a delete operation."""
            changetype = self.get_attribute("changetype")
            return bool(changetype and changetype[0].lower() == "delete")

        def add_attribute(self, name: str, value: str | list[str]) -> None:
            """Add attribute value(s)."""
            values = [value] if isinstance(value, str) else list(value)
            attr_key = name.lower()

            if attr_key in self.attributes:
                self.attributes[attr_key].extend(values)
            else:
                self.attributes[attr_key] = values

        def remove_attribute(self, name: str) -> None:
            """Remove attribute."""
            self.attributes.pop(name.lower(), None)

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

        def is_person_entry(self) -> bool:
            """Check if entry represents a person - alias for is_person."""
            return self.is_person()

        def is_group_entry(self) -> bool:
            """Check if entry represents a group - alias for is_group."""
            return self.is_group()

        def is_valid_entry(self) -> bool:
            """Check if entry meets basic LDIF validity requirements."""
            try:
                # Validate basic domain rules
                self.validate_domain_rules()
                return True
            except FlextLDIFExceptions.ValidationError:
                return False

        def get_rdn(self) -> str:
            """Get Relative Distinguished Name."""
            return self.dn.get_rdn()

        def get_parent_dn(self) -> str:
            """Get parent DN."""
            return self.dn.get_parent_dn()

        def to_ldif(self) -> str:
            """Convert entry to LDIF format."""
            lines = [f"dn: {self.dn.value}"]

            # Add attributes using extend for better performance
            for attr_name, attr_values in self.attributes.data.items():
                lines.extend(f"{attr_name}: {value}" for value in attr_values)

            return "\n".join(lines) + "\n"

        @classmethod
        def from_ldif_block(cls, ldif_text: str) -> FlextLDIFModels.Entry:
            """Create entry from LDIF text block."""
            lines = ldif_text.strip().split("\n")
            data: dict[str, object] = {}

            for raw_line in lines:
                line = raw_line.strip()
                if not line:
                    continue

                if ":" in line:
                    attr_name, attr_value = line.split(":", 1)
                    attr_name = attr_name.strip()
                    attr_value = attr_value.strip()

                    if attr_name.lower() == "dn":
                        data["dn"] = attr_value
                    else:
                        if attr_name not in data:
                            data[attr_name] = []
                        # Type-safe append to list
                        attr_list = data[attr_name]
                        if isinstance(attr_list, list):
                            attr_list.append(attr_value)
                        else:
                            data[attr_name] = [attr_value]

            return cls.from_dict(data)

        @classmethod
        def from_dict(cls, data: dict[str, object]) -> FlextLDIFModels.Entry:
            """Create entry from dictionary."""
            if "dn" not in data:
                msg = FlextLDIFConstants.FlextLDIFValidationMessages.MISSING_DN
                raise FlextLDIFExceptions.ValidationError(msg)

            dn = FlextLDIFModels.DistinguishedName(value=str(data["dn"]))

            # Extract attributes (everything except DN)
            attrs_data = {k: v for k, v in data.items() if k != "dn"}

            # Ensure all values are lists of strings
            normalized_attrs = {}
            for name, value in attrs_data.items():
                if isinstance(value, str):
                    normalized_attrs[name] = [value]
                elif isinstance(value, list):
                    normalized_attrs[name] = [str(v) for v in value]
                else:
                    normalized_attrs[name] = [str(value)]

            attributes = AttributesDict(normalized_attrs)

            return cls(dn=dn, attributes=attributes)

    class Config(FlextConfig):
        """LDIF processing configuration."""

        encoding: str = Field(default="utf-8")
        line_separator: str = Field(default="\n")
        max_line_length: int = Field(default=76)
        fold_lines: bool = Field(default=True)
        validate_dn: bool = Field(default=True)
        validate_attributes: bool = Field(default=True)
        strict_parsing: bool = Field(default=False)
        strict_validation: bool = Field(default=False)
        allow_empty_values: bool = Field(default=True)
        normalize_attribute_names: bool = Field(default=True)
        sort_attributes: bool = Field(default=True)
        max_entries: int = Field(default=10000)

        @field_validator("encoding")
        @classmethod
        def validate_encoding(cls, v: str) -> str:
            """Validate encoding name."""
            try:
                "test".encode(v)
                return v
            except (LookupError, TypeError) as e:
                msg = f"Invalid encoding: {v}"
                raise FlextLDIFExceptions.ValidationError(msg) from e

        @field_validator("max_line_length")
        @classmethod
        def validate_line_length(cls, v: int) -> int:
            """Validate line length limits."""
            min_line_length = 20
            max_line_length = 1000
            if v < min_line_length or v > max_line_length:
                msg = f"Line length must be between {min_line_length} and {max_line_length}, got {v}"
                raise FlextLDIFExceptions.ValidationError(msg)
            return v

        def validate_domain_rules(self) -> None:
            """Validate configuration business rules."""
            # All validation handled by field validators

    class Factory:
        """Factory for creating LDIF model instances."""

        @staticmethod
        def create_dn(value: str) -> FlextLDIFModels.DistinguishedName:
            """Create DN from string value."""
            return FlextLDIFModels.DistinguishedName(value=value)

        @staticmethod
        def create_attributes(
            data: dict[str, list[str]] | None = None,
        ) -> FlextLDIFModels.Attributes:
            """Create attributes from dictionary."""
            return FlextLDIFModels.Attributes(data=data or {})

        @staticmethod
        def create_entry(
            dn: str, attributes: dict[str, list[str]] | None = None
        ) -> FlextLDIFModels.Entry:
            """Create entry from DN and attributes."""
            dn_obj = FlextLDIFModels.DistinguishedName(value=dn)
            attrs_dict = AttributesDict(attributes or {})
            return FlextLDIFModels.Entry(dn=dn_obj, attributes=attrs_dict)

        @staticmethod
        def create_config(**kwargs: object) -> FlextLDIFModels.Config:
            """Create configuration with proper type handling."""
            try:
                # Use model_validate for better type conversion
                return FlextLDIFModels.Config.model_validate(kwargs)
            except Exception:
                # Fallback to default config
                return FlextLDIFModels.Config()

    # =========================================================================
    # HELPER METHODS - Moved from loose functions for FLEXT pattern compliance
    # =========================================================================

    @staticmethod
    def _create_empty_attributes() -> dict[str, list[str]]:
        """Create empty attributes dict that will be converted to Attributes object."""
        return {}

    @staticmethod
    def _validate_ldap_attribute_name(name: str) -> bool:
        """Local LDAP attribute name validator - breaks circular dependency.

        Validates attribute names per RFC 4512: base name + optional language tags/options.
        Supports: displayname;lang-es_es, orclinstancecount;oid-prd-app01.network.ctbc
        """
        if not name or not isinstance(name, str):
            return False
        attr_pattern = _re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*(?:;[a-zA-Z0-9_.-]+)*$")
        return bool(attr_pattern.match(name))

    @staticmethod
    def _validate_ldap_dn(dn: str) -> bool:
        """Local LDAP DN validator - breaks circular dependency.

        Basic DN validation pattern to avoid circular import from flext-ldap.
        """
        if not dn or not isinstance(dn, str):
            return False
        # Basic DN validation pattern
        dn_pattern = _re.compile(r"^[a-zA-Z][\w-]*=.+(?:,[a-zA-Z][\w-]*=.+)*$")
        return bool(dn_pattern.match(dn.strip()))

    @staticmethod
    @lru_cache(maxsize=1)
    def _get_ldap_validators() -> tuple[ValidatorFunc, ValidatorFunc]:
        """Use local validators to avoid circular dependency with flext-ldap.

        Previously imported from flext-ldap.utils, but this creates circular dependency:
        flext-ldap imports flext-ldif, flext-ldif imports flext-ldap.utils.

        Now uses local implementations that match the LDAP RFC requirements.
        """
        return (
            FlextLDIFModels._validate_ldap_attribute_name,
            FlextLDIFModels._validate_ldap_dn,
        )


# =============================================================================
# FLEXT PATTERN EXPORTS - Only consolidated class, NO compatibility aliases
# =============================================================================

# ONLY export the unified class - force usage of FlextLDIFModels.* pattern
__all__ = [
    "AttributesDict",  # Module-level helper class
    "FlextLDIFModels",  # Consolidated class (FLEXT Pattern)
]
