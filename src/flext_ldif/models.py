"""FLEXT-LDIF Domain Models - Single Consolidated Class.

Consolidates ALL model definitions into one class following FLEXT patterns.
Individual models available as nested classes for organization.
"""

from __future__ import annotations

import hashlib
import json
import re as _re
import uuid
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path
from typing import cast, override

from flext_core import (
    FlextConfig,
    FlextEntity,
    FlextEntityId,
    FlextModel,
    FlextResult,
    FlextValidationError,
    FlextValue,
)
from pydantic import Field, field_validator

from flext_ldif.constants import (
    LDAP_DN_ATTRIBUTES,
    LDAP_GROUP_CLASSES,
    LDAP_PERSON_CLASSES,
    MIN_DN_COMPONENTS,
    FlextLdifValidationMessages,
)

ValidatorFunc = Callable[[str], bool]


def _validate_ldap_attribute_name(name: str) -> bool:
    """Local LDAP attribute name validator - breaks circular dependency.

    Validates attribute names per RFC 4512: base name + optional language tags/options.
    Supports: displayname;lang-es_es, orclinstancecount;oid-prd-app01.network.ctbc
    """
    if not name or not isinstance(name, str):
        return False
    attr_pattern = _re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*(?:;[a-zA-Z0-9_.-]+)*$")
    return bool(attr_pattern.match(name))


def _validate_ldap_dn(dn: str) -> bool:
    """Local LDAP DN validator - breaks circular dependency.

    Basic DN validation pattern to avoid circular import from flext-ldap.
    """
    if not dn or not isinstance(dn, str):
        return False
    # Basic DN validation pattern
    dn_pattern = _re.compile(r"^[a-zA-Z][\w-]*=.+(?:,[a-zA-Z][\w-]*=.+)*$")
    return bool(dn_pattern.match(dn.strip()))


@lru_cache(maxsize=1)
def _get_ldap_validators() -> tuple[ValidatorFunc, ValidatorFunc]:
    """Use local validators to avoid circular dependency with flext-ldap.

    Previously imported from flext-ldap.utils, but this creates circular dependency:
    flext-ldap imports flext-ldif, flext-ldif imports flext-ldap.utils.

    Now uses local implementations that match the LDAP RFC requirements.
    """
    return (
        _validate_ldap_attribute_name,
        _validate_ldap_dn,
    )


# =============================================================================
# SINGLE CONSOLIDATED CLASS CONTAINING ALL LDIF MODELS (FLEXT PATTERN)
# =============================================================================


class FlextLdifModels(FlextModel):
    """Single consolidated class containing ALL LDIF models.
    
    Consolidates ALL model definitions into one class following FLEXT patterns.
    Individual models available as nested classes for organization.
    
    This class serves as the main interface for all LDIF domain models:
    - DistinguishedName: DN value objects
    - Attributes: Attribute collections
    - Entry: Main LDIF entries
    - Config: Configuration models
    - Factory: Object creation utilities
    """
    
    # =============================================================================
    # NESTED VALUE OBJECTS - Using FlextValue from flext-core
    # =============================================================================
    
    class DistinguishedName(FlextValue):
        """Distinguished Name value object."""

        value: str = Field(...)

        @override
        def to_json(self, **_kwargs: object) -> str:
            """Serialize to JSON string - workaround for Pydantic serialization issue."""
            return json.dumps(self.model_dump(), default=str)

        @field_validator("value")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate and normalize DN format."""
            if not v or not isinstance(v, str) or not v.strip():
                # Domain-specific validation error
                msg = FlextLdifValidationMessages.DN_EMPTY_ERROR
                raise FlextValidationError(msg)

            dn_clean = v.strip()

            # Use local validator to avoid circular dependency
            _, dn_validator = _get_ldap_validators()
            if not dn_validator(dn_clean):
                msg = FlextLdifValidationMessages.DN_INVALID_FORMAT.format(dn=dn_clean)
                raise FlextValidationError(msg)

            return dn_clean

        def get_components(self) -> list[str]:
            """Get DN components as list."""
            return [comp.strip() for comp in self.value.split(",")]

        def get_depth(self) -> int:
            """Get depth of the DN (number of components)."""
            return len(self.get_components())

        def get_base_dn(self) -> str:
            """Get base DN (parent container)."""
            components = self.get_components()
            if len(components) <= 1:
                return ""
            return ",".join(components[1:])

        def get_rdn(self) -> str:
            """Get Relative Distinguished Name (first component)."""
            components = self.get_components()
            return components[0] if components else ""
    
    class Attributes(FlextValue):
        """LDIF attributes collection value object."""

        attributes: dict[str, list[str]] = Field(default_factory=dict)

        @field_validator("attributes")
        @classmethod
        def validate_attributes(cls, v: dict[str, list[str]]) -> dict[str, list[str]]:
            """Validate attribute names and structure."""
            if not isinstance(v, dict):
                raise FlextValidationError("Attributes must be a dictionary")

            # Use local validator to avoid circular dependency
            attr_validator, _ = _get_ldap_validators()

            validated_attrs: dict[str, list[str]] = {}
            for attr_name, attr_values in v.items():
                if not attr_validator(attr_name):
                    msg = FlextLdifValidationMessages.INVALID_ATTRIBUTE_NAME.format(
                        attr_name=attr_name,
                    )
                    raise FlextValidationError(msg)

                if not isinstance(attr_values, list):
                    raise FlextValidationError(
                        f"Attribute values for '{attr_name}' must be a list"
                    )

                # Ensure all values are strings
                validated_values = []
                for value in attr_values:
                    if not isinstance(value, str):
                        validated_values.append(str(value))
                    else:
                        validated_values.append(value)

                validated_attrs[attr_name] = validated_values

            return validated_attrs

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute values by name (case-insensitive)."""
            return self.attributes.get(name)

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            return name in self.attributes

        def get_object_classes(self) -> list[str]:
            """Get objectClass values."""
            return self.get_attribute("objectClass") or []

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specific objectClass."""
            object_classes = self.get_object_classes()
            return object_class in object_classes

        def add_attribute(self, name: str, values: list[str]) -> None:
            """Add attribute with values."""
            # Use local validator to avoid circular dependency
            attr_validator, _ = _get_ldap_validators()
            
            if not attr_validator(name):
                msg = FlextLdifValidationMessages.INVALID_ATTRIBUTE_NAME.format(
                    attr_name=name,
                )
                raise FlextValidationError(msg)
                
            self.attributes[name] = values

        def remove_attribute(self, name: str) -> bool:
            """Remove attribute by name."""
            if name in self.attributes:
                del self.attributes[name]
                return True
            return False

        def get_size(self) -> int:
            """Get total number of attributes."""
            return len(self.attributes)

    # =============================================================================
    # NESTED DOMAIN ENTITIES - Using FlextEntity from flext-core  
    # =============================================================================
    
    class Entry(FlextEntity):
        """LDIF entry domain entity."""

        dn: FlextLdifModels.DistinguishedName = Field(...)
        attributes: FlextLdifModels.Attributes = Field(default_factory=lambda: FlextLdifModels.Attributes())
        changetype: str = Field(default="add")

        @override
        def generate_id(self) -> FlextEntityId:
            """Generate unique ID based on DN."""
            dn_hash = hashlib.sha256(self.dn.value.encode()).hexdigest()[:16]
            return FlextEntityId(str(uuid.UUID(dn_hash + "0" * 16)))

        @override
        def validate_domain_rules(self) -> None:
            """Validate LDIF entry domain rules."""
            # Validate minimum DN components
            if self.dn.get_depth() < MIN_DN_COMPONENTS:
                msg = FlextLdifValidationMessages.DN_TOO_SHORT.format(
                    min_components=MIN_DN_COMPONENTS
                )
                raise FlextValidationError(msg)

            # Validate required objectClass
            if not self.attributes.has_attribute("objectClass"):
                raise FlextValidationError(
                    FlextLdifValidationMessages.MISSING_OBJECTCLASS
                )

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute values by name."""
            return self.attributes.get_attribute(name)

        def has_attribute(self, name: str) -> bool:
            """Check if entry has attribute."""
            return self.attributes.has_attribute(name)

        def get_object_classes(self) -> list[str]:
            """Get objectClass values."""
            return self.attributes.get_object_classes()

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specific objectClass."""
            return self.attributes.has_object_class(object_class)

        def is_person(self) -> bool:
            """Check if entry is a person object."""
            object_classes = self.get_object_classes()
            return any(object_class in LDAP_PERSON_CLASSES for object_class in object_classes)

        def is_group(self) -> bool:
            """Check if entry is a group object."""
            object_classes = self.get_object_classes()
            return any(object_class in LDAP_GROUP_CLASSES for object_class in object_classes)

        def to_ldif(self) -> str:
            """Convert entry to LDIF format."""
            lines = [f"dn: {self.dn.value}"]

            # Add changetype if not 'add'
            if self.changetype != "add":
                lines.append(f"changetype: {self.changetype}")

            # Add attributes
            for attr_name, attr_values in self.attributes.attributes.items():
                for value in attr_values:
                    lines.append(f"{attr_name}: {value}")

            return "\n".join(lines)

        @classmethod
        def from_ldif(cls, ldif_text: str) -> FlextLdifModels.Entry:
            """Create entry from LDIF text."""
            lines = [line.strip() for line in ldif_text.strip().split("\n") if line.strip()]
            
            if not lines:
                raise FlextValidationError("Empty LDIF content")
            
            # Parse DN
            if not lines[0].startswith("dn:"):
                raise FlextValidationError("LDIF must start with DN")
            
            dn_value = lines[0][3:].strip()
            dn = FlextLdifModels.DistinguishedName(value=dn_value)
            
            # Parse attributes
            attributes_dict: dict[str, list[str]] = {}
            changetype = "add"
            
            for line in lines[1:]:
                if ":" not in line:
                    continue
                    
                attr_name, attr_value = line.split(":", 1)
                attr_name = attr_name.strip()
                attr_value = attr_value.strip()
                
                if attr_name == "changetype":
                    changetype = attr_value
                    continue
                    
                if attr_name not in attributes_dict:
                    attributes_dict[attr_name] = []
                attributes_dict[attr_name].append(attr_value)
            
            attributes = FlextLdifModels.Attributes(attributes=attributes_dict)
            
            return cls(dn=dn, attributes=attributes, changetype=changetype)

    # =============================================================================
    # NESTED CONFIGURATION MODEL - Using FlextConfig from flext-core
    # =============================================================================
    
    class Config(FlextConfig):
        """LDIF processing configuration."""

        strict_validation: bool = Field(default=True)
        allow_empty_attributes: bool = Field(default=False)
        max_line_length: int = Field(default=76)
        encoding: str = Field(default="utf-8")
        buffer_size: int = Field(default=8192)
        max_entries_per_batch: int = Field(default=1000)
        enable_schema_validation: bool = Field(default=False)
        ldap_server_url: str | None = Field(default=None)
        bind_dn: str | None = Field(default=None)
        bind_password: str | None = Field(default=None)

        @field_validator("max_line_length")
        @classmethod
        def validate_max_line_length(cls, v: int) -> int:
            """Validate maximum line length."""
            if v < 60:
                raise FlextValidationError("max_line_length must be at least 60")
            if v > 1000:
                raise FlextValidationError("max_line_length must be at most 1000")
            return v

        @field_validator("buffer_size")
        @classmethod
        def validate_buffer_size(cls, v: int) -> int:
            """Validate buffer size."""
            if v < 1024:
                raise FlextValidationError("buffer_size must be at least 1024")
            if v > 1024 * 1024:
                raise FlextValidationError("buffer_size must be at most 1MB")
            return v

        @field_validator("max_entries_per_batch")
        @classmethod
        def validate_max_entries_per_batch(cls, v: int) -> int:
            """Validate maximum entries per batch."""
            if v < 1:
                raise FlextValidationError("max_entries_per_batch must be at least 1")
            if v > 10000:
                raise FlextValidationError("max_entries_per_batch must be at most 10000")
            return v

        def to_dict(self) -> dict[str, object]:
            """Convert to dictionary format."""
            return self.model_dump()

        @override
        def validate_business_rules(self) -> FlextResult[None]:
            """Validate configuration business rules."""
            try:
                # Validate LDAP connection parameters if provided
                if self.ldap_server_url and not self.bind_dn:
                    return FlextResult[None].fail(
                        "bind_dn is required when ldap_server_url is provided"
                    )
                
                if self.bind_dn and not self.ldap_server_url:
                    return FlextResult[None].fail(
                        "ldap_server_url is required when bind_dn is provided"
                    )
                
                return FlextResult[None].ok(None)
                
            except Exception as e:
                return FlextResult[None].fail(str(e))

    # =============================================================================
    # NESTED FACTORY UTILITIES
    # =============================================================================
    
    class Factory:
        """Factory for creating LDIF model instances."""

        @staticmethod
        def create_entry(
            dn: str,
            attributes: dict[str, list[str]],
            changetype: str = "add"
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create and validate LDIF entry."""
            try:
                dn_obj = FlextLdifModels.DistinguishedName(value=dn)
                attrs_obj = FlextLdifModels.Attributes(attributes=attributes)
                entry = FlextLdifModels.Entry(
                    dn=dn_obj, 
                    attributes=attrs_obj, 
                    changetype=changetype
                )
                entry.validate_domain_rules()
                return FlextResult[FlextLdifModels.Entry].ok(entry)
                
            except FlextValidationError as e:
                return FlextResult[FlextLdifModels.Entry].fail(str(e))
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(f"Unexpected error: {e}")

        @staticmethod
        def create_dn(dn_value: str) -> FlextResult[FlextLdifModels.DistinguishedName]:
            """Create and validate DN."""
            try:
                dn = FlextLdifModels.DistinguishedName(value=dn_value)
                return FlextResult[FlextLdifModels.DistinguishedName].ok(dn)
                
            except FlextValidationError as e:
                return FlextResult[FlextLdifModels.DistinguishedName].fail(str(e))
            except Exception as e:
                return FlextResult[FlextLdifModels.DistinguishedName].fail(f"Unexpected error: {e}")

        @staticmethod
        def create_attributes(
            attributes: dict[str, list[str]]
        ) -> FlextResult[FlextLdifModels.Attributes]:
            """Create and validate attributes."""
            try:
                attrs = FlextLdifModels.Attributes(attributes=attributes)
                return FlextResult[FlextLdifModels.Attributes].ok(attrs)
                
            except FlextValidationError as e:
                return FlextResult[FlextLdifModels.Attributes].fail(str(e))
            except Exception as e:
                return FlextResult[FlextLdifModels.Attributes].fail(f"Unexpected error: {e}")

        @staticmethod
        def create_config(**kwargs: object) -> FlextResult[FlextLdifModels.Config]:
            """Create and validate configuration."""
            try:
                config = FlextLdifModels.Config(**kwargs)
                validation = config.validate_business_rules()
                if validation.is_failure:
                    return FlextResult[FlextLdifModels.Config].fail(validation.error or "Config validation failed")
                    
                return FlextResult[FlextLdifModels.Config].ok(config)
                
            except FlextValidationError as e:
                return FlextResult[FlextLdifModels.Config].fail(str(e))
            except Exception as e:
                return FlextResult[FlextLdifModels.Config].fail(f"Unexpected error: {e}")

    # =============================================================================
    # LEGACY COMPATIBILITY PROPERTIES
    # =============================================================================
    
    @property
    def FlextLdifDistinguishedName(self) -> type[DistinguishedName]:
        """Legacy compatibility property."""
        return self.DistinguishedName
    
    @property
    def FlextLdifAttributes(self) -> type[Attributes]:
        """Legacy compatibility property."""
        return self.Attributes
    
    @property
    def FlextLdifEntry(self) -> type[Entry]:
        """Legacy compatibility property."""
        return self.Entry
    
    @property
    def FlextLdifConfig(self) -> type[Config]:
        """Legacy compatibility property."""
        return self.Config
    
    @property
    def FlextLdifFactory(self) -> type[Factory]:
        """Legacy compatibility property."""
        return self.Factory


# =============================================================================
# LEGACY COMPATIBILITY EXPORTS (temporary during transition)
# =============================================================================

# Direct access to nested classes for backward compatibility
FlextLdifDistinguishedName = FlextLdifModels.DistinguishedName
FlextLdifAttributes = FlextLdifModels.Attributes  
FlextLdifEntry = FlextLdifModels.Entry
FlextLdifConfig = FlextLdifModels.Config
FlextLdifFactory = FlextLdifModels.Factory

__all__ = [
    # FLEXT Consolidated Class (PRIMARY)
    "FlextLdifModels",
    
    # Legacy Compatibility Exports (SECONDARY - will be deprecated)
    "FlextLdifDistinguishedName",
    "FlextLdifAttributes", 
    "FlextLdifEntry",
    "FlextLdifConfig",
    "FlextLdifFactory",
]