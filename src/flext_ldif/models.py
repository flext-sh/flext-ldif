"""FLEXT LDIF Models - Domain models for LDIF processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from pydantic import Field, field_validator

from flext_core import (
    FlextExceptions,
    FlextModels,
    FlextResult,
    FlextTypes,
    FlextUtilities,
)
from flext_ldif.constants import FlextLdifConstants


class FlextLdifModels(FlextModels):
    """LDIF domain models with service architecture.

    Single consolidated class containing LDIF model definitions
    following SOLID principles, Python 3.13 patterns, and FLEXT ecosystem integration.

    Uses FlextModels inheritance to reduce code duplication and ensure
    consistent validation patterns across the FLEXT ecosystem.
    """

    # =============================================================================
    # LDIF DOMAIN VALUE OBJECTS (using FlextModels.Value inheritance)
    # =============================================================================

    class DistinguishedName(FlextModels.Value):
        """Distinguished Name value object for LDAP entries.

        Immutable value object representing LDAP Distinguished Names
        with comprehensive validation and business rules.
        """

        value: str = Field(
            ...,
            min_length=1,
            description="LDAP Distinguished Name",
        )

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
                msg = FlextLdifConstants.VALIDATION_MESSAGES["MISSING_DN"]
                error_msg = f"LDIF DN Validation: {msg}"
                raise FlextExceptions.ValidationError(error_msg)

            # Use flext-core validation system
            if not FlextUtilities.Validation.is_non_empty_string(v.strip()):
                msg = FlextLdifConstants.VALIDATION_MESSAGES["INVALID_DN"]
                error_msg = f"LDIF DN Validation: {msg}"
                raise FlextExceptions.ValidationError(error_msg)

            # Validate DN format using pattern
            if not re.match(FlextLdifConstants.DN_PATTERN, v.strip()):
                msg = FlextLdifConstants.VALIDATION_MESSAGES["INVALID_DN_FORMAT"]
                error_msg = f"LDIF DN Validation: {msg}"
                raise FlextExceptions.ValidationError(error_msg)

            return v.strip()

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate DN business rules using FlextResult patterns.

            Returns:
                FlextResult indicating validation success or failure

            """
            if not self.value:
                return FlextResult[None].fail(
                    FlextLdifConstants.VALIDATION_MESSAGES["MISSING_DN"],
                )

            # Check minimum DN components using flext-core utilities
            components = [c.strip() for c in self.value.split(",") if c.strip()]
            if len(components) < FlextLdifConstants.MIN_DN_COMPONENTS:
                error_msg = f"DN has too few components: {len(components)}, minimum required: {FlextLdifConstants.MIN_DN_COMPONENTS}"
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

        # Note: __str__ and __hash__ inherited from FlextModels.Value (Pydantic BaseModel)

    class LdifAttributes(FlextModels.Value):
        """LDIF attributes collection with case-insensitive access.

        Immutable value object for managing LDAP attribute collections
        with comprehensive validation and utility methods.
        """

        data: dict[str, FlextTypes.Core.StringList] = Field(
            default_factory=dict,
            description="Attribute name-value pairs",
        )

        @field_validator("data")
        @classmethod
        def validate_attribute_data(
            cls, v: dict[str, FlextTypes.Core.StringList]
        ) -> dict[str, FlextTypes.Core.StringList]:
            """Validate attribute data using Pydantic v2 patterns.

            Args:
                v: Attribute data to validate

            Returns:
                Validated attribute data

            Raises:
                ValidationError: If attribute data is invalid

            """
            for attr_name, attr_values in v.items():
                # Use centralized FlextLdifModels.LdifAttributeName validation
                try:
                    FlextLdifModels.LdifAttributeName(name=attr_name.strip())
                except Exception as e:
                    error_msg = f"Invalid attribute name '{attr_name}': {e}"
                    raise FlextExceptions.ValidationError(error_msg) from e

                # Validate attribute values are non-empty list
                if not attr_values or len(attr_values) == 0:
                    error_msg = f"Invalid attribute values for '{attr_name}': must be non-empty list"
                    raise FlextExceptions.ValidationError(error_msg)

            return v

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
            for attr_name, attr_values in self.data.items():
                if attr_name.lower() == name.lower():
                    return attr_values

            return None

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists (case-insensitive).

            Args:
                name: Attribute name to check

            Returns:
                True if attribute exists, False otherwise

            """
            return self.get_attribute(name) is not None

        def get_single_value(self, name: str) -> str | None:
            """Get single attribute value.

            Args:
                name: Attribute name

            Returns:
                First attribute value or None if not found

            """
            values = self.get_attribute(name)
            if values and len(values) > 0:
                return values[0]
            return None

        def get_single_attribute(self, name: str) -> str | None:
            """Get single attribute value (alias for get_single_value).

            Args:
                name: Attribute name

            Returns:
                First attribute value or None if not found

            """
            return self.get_single_value(name)

        def get_values(self, name: str) -> FlextTypes.Core.StringList:
            """Get attribute values (alias for get_attribute with default empty list).

            Args:
                name: Attribute name

            Returns:
                List of attribute values or empty list if not found

            """
            return self.get_attribute(name) or []

        def remove_value(self, name: str, value: str) -> FlextLdifModels.LdifAttributes:
            """Remove specific value from attribute.

            Args:
                name: Attribute name
                value: Value to remove

            Returns:
                New LdifAttributes instance with value removed

            """
            updated_data = dict(self.data)
            if name in updated_data:
                current_values = list(updated_data[name])
                if value in current_values:
                    current_values.remove(value)
                    if current_values:
                        updated_data[name] = current_values
                    else:
                        del updated_data[name]
            return FlextLdifModels.LdifAttributes(data=updated_data)

        def get_total_values(self) -> int:
            """Get total number of values across all attributes.

            Returns:
                Total count of all attribute values

            """
            return sum(len(values) for values in self.data.values())

        def is_empty(self) -> bool:
            """Check if attributes collection is empty.

            Returns:
                True if no attributes or all attributes are empty

            """
            return len(self.data) == 0 or all(len(values) == 0 for values in self.data.values())

        def get_all_attribute_names(self) -> FlextTypes.Core.StringList:
            """Get all attribute names.

            Returns:
                List of all attribute names

            """
            return list(self.data.keys())

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate attributes business rules.

            Returns:
                FlextResult indicating validation success or failure

            """
            # Check for objectClass (required in LDIF)
            object_classes = self.get_attribute(
                FlextLdifConstants.OBJECTCLASS_ATTRIBUTE
            )
            if not object_classes:
                return FlextResult[None].fail(
                    FlextLdifConstants.VALIDATION_MESSAGES["MISSING_OBJECTCLASS"]
                )

            return FlextResult[None].ok(None)

        # Note: __iter__ inherited from FlextModels.Value (Pydantic BaseModel)
        # Domain-specific methods not provided by base class:
        def __len__(self) -> int:
            """Return number of attributes."""
            return len(self.data)

        def __contains__(self, name: str) -> bool:
            """Check if attribute exists (case-insensitive)."""
            return self.has_attribute(name)

    class Entry(FlextModels.Entity):
        """LDIF entry representing a complete directory entry.

        Entity for LDAP directory entries with DN identity,
        comprehensive validation and business logic.
        """

        dn: FlextLdifModels.DistinguishedName = Field(
            ..., description="Distinguished Name of the entry"
        )
        attributes: FlextLdifModels.LdifAttributes = Field(
            ..., description="Attributes collection for the entry"
        )

        def get_attribute(self, name: str) -> FlextTypes.Core.StringList | None:
            """Get attribute values from entry.

            Args:
                name: Attribute name to lookup

            Returns:
                List of attribute values or None if not found

            """
            return self.attributes.get_attribute(name)

        def get_single_attribute(self, name: str) -> str | None:
            """Get single attribute value from entry.

            Args:
                name: Attribute name

            Returns:
                First attribute value or None if not found

            """
            return self.attributes.get_single_value(name)

        def has_attribute(self, name: str) -> bool:
            """Check if entry has attribute.

            Args:
                name: Attribute name to check

            Returns:
                True if attribute exists, False otherwise

            """
            return self.attributes.has_attribute(name)

        def set_attribute(self, name: str, values: FlextTypes.Core.StringList) -> None:
            """Set attribute values for entry.

            Args:
                name: Attribute name to set
                values: List of attribute values

            Note:
                This modifies the entry's attributes in place.
                Entry is now mutable as an Entity with DN identity.

            """
            # Since LdifAttributes is still a Value Object, we need to create a new one
            updated_data = dict(self.attributes.data)
            updated_data[name] = values
            self.attributes = FlextLdifModels.LdifAttributes(data=updated_data)

        def to_ldif(self) -> str:
            """Convert entry to LDIF string format.

            Returns:
                LDIF formatted string representation of the entry

            """
            lines = [f"dn: {self.dn.value}"]

            # Add all attributes in LDIF format
            for attr_name, attr_values in self.attributes.data.items():
                lines.extend(f"{attr_name}: {value}" for value in attr_values)

            # Join with newlines and ensure ending newline
            return "\n".join(lines) + "\n"

        def get_object_classes(self) -> FlextTypes.Core.StringList:
            """Get object classes for entry.

            Returns:
                List of object class values

            """
            return self.get_attribute(FlextLdifConstants.OBJECTCLASS_ATTRIBUTE) or []

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has a specific object class.

            Args:
                object_class: The object class to check for

            Returns:
                True if the entry has the object class, False otherwise

            """
            object_classes = self.get_object_classes()
            return object_class.lower() in [oc.lower() for oc in object_classes]

        def is_person_entry(self) -> bool:
            """Check if entry is a person entry.

            Returns:
                True if entry has person object classes

            """
            object_classes = {oc.lower() for oc in self.get_object_classes()}
            person_classes = {
                oc.lower() for oc in FlextLdifConstants.LDAP_PERSON_CLASSES
            }
            return bool(object_classes.intersection(person_classes))

        def is_group_entry(self) -> bool:
            """Check if entry is a group entry.

            Returns:
            True if entry has group object classes

            """
            object_classes = {oc.lower() for oc in self.get_object_classes()}
            group_classes = {oc.lower() for oc in FlextLdifConstants.LDAP_GROUP_CLASSES}
            return bool(object_classes.intersection(group_classes))

        def is_organizational_unit(self) -> bool:
            """Check if entry is an organizational unit.

            Returns:
            True if entry has organizational unit object classes

            """
            object_classes = {oc.lower() for oc in self.get_object_classes()}
            org_classes = {
            oc.lower() for oc in FlextLdifConstants.LDAP_ORGANIZATIONAL_CLASSES
            }
            return bool(object_classes.intersection(org_classes))

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate entry business rules.

            Returns:
            FlextResult indicating validation success or failure

            """
        # Validate DN using embedded validation
            dn_validation = self.dn.validate_business_rules()
            if dn_validation.is_failure:
                return FlextResult[None].fail(
                    f"DN validation failed: {dn_validation.error}"
                )

        # Validate attributes using embedded validation
            attr_validation = self.attributes.validate_business_rules()
            if attr_validation.is_failure:
                return FlextResult[None].fail(
                    f"Attributes validation failed: {attr_validation.error}"
                )

            # LDIF-specific validation: Entry must have objectClass
            if not self.get_object_classes():
                return FlextResult[None].fail(
                    FlextLdifConstants.VALIDATION_MESSAGES["MISSING_OBJECTCLASS"]
                )

            return FlextResult[None].ok(None)

        def get_rdn(self) -> str:
            """Get Relative Distinguished Name.

            Returns:
            RDN string

            """
            return self.dn.get_rdn()

        def get_parent_dn(self) -> str | None:
            """Get parent DN.

            Returns:
            Parent DN string or None if no parent

            """
            return self.dn.get_parent_dn()

        def get_dn_depth(self) -> int:
            """Get DN depth.

            Returns:
            Number of DN components

            """
            return self.dn.get_depth()

        def is_person(self) -> bool:
            """Check if entry is a person entry (alias for is_person_entry).

            Returns:
                True if entry has person object classes

            """
            return self.is_person_entry()

        def is_add_operation(self) -> bool:
            """Check if this entry represents an add operation.

            Returns:
                True if this is an add operation (always True for parsed entries)

            Note:
                In LDIF format, all parsed entries are implicitly add operations
                unless specified otherwise. This method is provided for completeness.

            """
            return True

        def is_modify_operation(self) -> bool:
            """Check if this entry represents a modify operation.

            Returns:
                False - basic LDIF entries are add operations

            Note:
                LDIF modify operations would be handled differently in actual LDAP operations.
                This method is provided for interface completeness.

            """
            return False

        def is_delete_operation(self) -> bool:
            """Check if this entry represents a delete operation.

            Returns:
                False - basic LDIF entries are add operations

            Note:
                LDIF delete operations would be handled differently in actual LDAP operations.
                This method is provided for interface completeness.

            """
            return False

        # Note: __str__ inherited from FlextModels.Value (Pydantic BaseModel)

        @classmethod
        def from_ldif_block(cls, ldif_block: str) -> FlextLdifModels.Entry:
            """Create Entry from LDIF block string.

            Args:
                ldif_block: LDIF text block for a single entry

            Returns:
                FlextLdifModels.Entry instance

            Raises:
                ValueError: If LDIF block is invalid or missing DN

            """
            if not ldif_block or not ldif_block.strip():
                msg = "Missing DN"
                raise ValueError(msg)

            lines = [
                line.strip() for line in ldif_block.strip().split("\n") if line.strip()
            ]
            if not lines:
                msg = "Missing DN"
                raise ValueError(msg)

            # Parse DN from first line
            first_line = lines[0]
            if not first_line.startswith("dn:"):
                msg = "Missing DN"
                raise ValueError(msg)

            dn = first_line[3:].strip()
            if not dn:
                msg = "Missing DN"
                raise ValueError(msg)

            # Parse attributes from remaining lines
            attributes: dict[str, list[str]] = {}
            for line in lines[1:]:
                if ":" not in line:
                    # Invalid line format - skip or raise error based on test expectations
                    continue

                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()

                if key not in attributes:
                    attributes[key] = []
                attributes[key].append(value)

        # Create entry using existing factory method
            return FlextLdifModels.create_entry({"dn": dn, "attributes": attributes})

    # =============================================================================
    # CENTRALIZED VALIDATION MODELS (replacing scattered regex patterns)
    # =============================================================================

    class LdifFilePath(FlextModels.Value):
        """LDIF file path validation using Pydantic v2 patterns.

        Replaces manual file extension validation in utilities.py
        """

        path: str = Field(..., description="File path with LDIF extension")

        @field_validator("path")
        @classmethod
        def validate_ldif_extension(cls, v: str) -> str:
            """Validate LDIF file extension using Pydantic v2 patterns."""
            if not v or not v.strip():
                msg = "File path cannot be empty"
                raise FlextExceptions.ValidationError(msg)

            path_str = v.strip().lower()
            valid_extensions = [".ldif", ".ldap", ".ldi"]

            if not any(path_str.endswith(ext) for ext in valid_extensions):
                valid_exts_str = ", ".join(valid_extensions)
                msg = f"File must have LDIF extension ({valid_exts_str}), got: {v}"
                raise FlextExceptions.ValidationError(msg)

            return v.strip()

    class LdifUrl(FlextModels.Value):
        """LDIF URL validation using Pydantic v2 patterns.

        Replaces manual URL scheme validation in format_handlers.py
        """

        url: str = Field(
            ...,
            pattern=r"^https?://[^\s/$.?#].[^\s]*$",
            description="URL with allowed scheme",
        )

        @field_validator("url")
        @classmethod
        def validate_url_scheme(cls, v: str) -> str:
            """Validate URL scheme using Pydantic v2 patterns."""
            if not v or not v.strip():
                msg = "URL cannot be empty"
                raise FlextExceptions.ValidationError(msg)

            parsed = urlparse(v.strip())
            allowed_schemes = {"http", "https"}

            if parsed.scheme not in allowed_schemes:
                schemes_str = ", ".join(allowed_schemes)
                msg = (
                    f"URL scheme '{parsed.scheme}' not allowed. "
                    f"Only {schemes_str} schemes are permitted."
                )
                raise FlextExceptions.ValidationError(msg)

            return v.strip()

    class LdifAttributeName(FlextModels.Value):
        """LDIF attribute name validation using Pydantic v2 patterns.

        Centralizes attribute name validation with proper regex pattern.
        """

        name: str = Field(
            ...,
            pattern=r"^[a-zA-Z][a-zA-Z0-9-]*(?:;[a-zA-Z0-9-]+(?:[-_.][a-zA-Z0-9-]+)*)*$",
            min_length=1,
            description="LDAP attribute name",
        )

        @field_validator("name")
        @classmethod
        def validate_attribute_name(cls, v: str) -> str:
            """Validate attribute name using Pydantic v2 patterns."""
            if not v or not v.strip():
                msg = "Attribute name cannot be empty"
                raise FlextExceptions.ValidationError(msg)

            # Use flext-core validation
            if not FlextUtilities.Validation.is_non_empty_string(v.strip()):
                msg = "Attribute name must be non-empty string"
                raise FlextExceptions.ValidationError(msg)

            return v.strip()

    class LdifContent(FlextModels.Value):
        """LDIF content validation using Pydantic v2 patterns.

        Replaces manual LDIF syntax validation in parser_service.py
        """

        content: str = Field(
            ..., min_length=1, description="LDIF content that starts with dn:"
        )

        @field_validator("content")
        @classmethod
        def validate_ldif_syntax(cls, v: str) -> str:
            """Validate LDIF syntax using Pydantic v2 patterns."""
            if not v or not v.strip():
                msg = "LDIF content cannot be empty"
                raise FlextExceptions.ValidationError(msg)

            # Find first non-empty line and check if it starts with dn:
            for line in v.strip().split("\n"):
                if line.strip():
                    if not line.strip().startswith("dn:"):
                        msg = "LDIF must start with dn:"
                        raise FlextExceptions.ValidationError(msg)
                    break

            return v.strip()

    # =============================================================================
    # LDIF FACTORY METHODS (using FlextModels patterns)
    # =============================================================================

    @classmethod
    def create_entry(cls, data: dict[str, object]) -> FlextLdifModels.Entry:
        """Create LDIF entry from dictionary data.

        Args:
            data: Dictionary containing 'dn' and 'attributes' keys

        Returns:
            FlextLdifModels.Entry instance

        Raises:
            ValueError: If required data is missing or invalid

        """
        if "dn" not in data:
            msg = "Entry data must contain 'dn' field"
            raise ValueError(msg)

        # Create DN value object
        dn_value = str(data["dn"])
        dn_obj = cls.DistinguishedName(value=dn_value)

        # Create attributes value object - use empty dict if not provided
        attributes_data = data.get("attributes", {})

        # Validate attributes data type first - must be dict-like
        if not isinstance(attributes_data, dict):
            msg = "Attributes must be dict"
            raise TypeError(msg)

        # Convert dict values to StringList using Pydantic v2 validation
        normalized_attrs: dict[str, FlextTypes.Core.StringList] = {}
        try:
            for attr_name, attr_values in attributes_data.items():
                # Use Pydantic v2 field validation to convert to StringList
                if hasattr(attr_values, "__iter__") and not isinstance(
                    attr_values, str
                ):
                    # It's a list-like object
                    normalized_attrs[attr_name] = [str(v) for v in attr_values]
                else:
                    # It's a single value (string or other)
                    normalized_attrs[attr_name] = [str(attr_values)]

            attrs_obj = cls.LdifAttributes(data=normalized_attrs)
        except (TypeError, AttributeError) as e:
            msg = f"Invalid attributes data format: {e}"
            raise TypeError(msg) from e

        # Create and return entry
        return cls.Entry(dn=dn_obj, attributes=attrs_obj)

    @classmethod
    def create_distinguished_name(
        cls, dn_value: str
    ) -> FlextLdifModels.DistinguishedName:
        """Create distinguished name value object.

        Args:
            dn_value: DN string value

        Returns:
            FlextLdifModels.DistinguishedName instance

        """
        return cls.DistinguishedName(value=dn_value)

    @classmethod
    def create_attributes(
        cls, attributes_data: dict[str, FlextTypes.Core.StringList]
    ) -> FlextLdifModels.LdifAttributes:
        """Create attributes collection value object.

        Args:
            attributes_data: Dictionary of attribute name-value pairs

        Returns:
            FlextLdifModels.LdifAttributes instance

        """
        return cls.LdifAttributes(data=attributes_data)

    @classmethod
    def create_person_entry(
        cls, dn: str, cn: str, sn: str, **additional_attrs: str | list[str]
    ) -> FlextLdifModels.Entry:
        """Create person entry with required attributes.

        Args:
            dn: Distinguished name
            cn: Common name
            sn: Surname
            **additional_attrs: Additional attributes

        Returns:
            FlextLdifModels.Entry configured as person entry

        """
        # Start with required person attributes
        attributes: dict[str, FlextTypes.Core.StringList] = {
            "objectClass": ["person", "inetOrgPerson"],
            "cn": [cn],
            "sn": [sn],
        }

        # Add additional attributes using Pydantic v2 validation patterns
        for attr_name, attr_value in additional_attrs.items():
            # Use hasattr instead of isinstance for duck typing
            if hasattr(attr_value, "__iter__") and not isinstance(attr_value, str):
                attributes[attr_name] = [str(v) for v in attr_value]
            else:
                attributes[attr_name] = [str(attr_value)]

        return cls.create_entry({"dn": dn, "attributes": attributes})

    @classmethod
    def create_organizational_unit(
        cls, dn: str, ou: str, **additional_attrs: str | list[str]
    ) -> FlextLdifModels.Entry:
        """Create organizational unit entry.

        Args:
            dn: Distinguished name
            ou: Organizational unit name
            **additional_attrs: Additional attributes

        Returns:
            FlextLdifModels.Entry configured as organizational unit

        """
        # Start with required OU attributes
        attributes: dict[str, FlextTypes.Core.StringList] = {
            "objectClass": ["organizationalUnit"],
            "ou": [ou],
        }

        # Add additional attributes using Pydantic v2 validation patterns
        for attr_name, attr_value in additional_attrs.items():
            # Use hasattr instead of isinstance for duck typing
            if hasattr(attr_value, "__iter__") and not isinstance(attr_value, str):
                attributes[attr_name] = [str(v) for v in attr_value]
            else:
                attributes[attr_name] = [str(attr_value)]

        return cls.create_entry({"dn": dn, "attributes": attributes})

    # =============================================================================
    # LDIF MODEL VALIDATION AND BUSINESS RULES
    # =============================================================================

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate LDIF models business rules.

        Returns:
            FlextResult indicating validation success or failure

        """
        # FlextLdifModels itself doesn't have specific business rules
        # Individual model instances handle their own validation
        return FlextResult[None].ok(None)


__all__ = ["FlextLdifModels"]
