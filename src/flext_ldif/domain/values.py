"""LDIF Domain Value Objects - Immutable Values.

🏗️ CLEAN ARCHITECTURE: Domain Value Objects
Built on flext-core foundation patterns.

Value objects represent immutable concepts in the LDIF domain.
"""

from __future__ import annotations

from typing import NewType

from flext_core import DomainValueObject
from pydantic import Field, field_validator

# Type aliases for LDIF-specific concepts
LDIFContent = NewType("LDIFContent", str)
LDIFLines = NewType("LDIFLines", list[str])


class DistinguishedName(DomainValueObject):
    """Distinguished Name value object for LDIF entries.

    Represents an immutable LDAP distinguished name.
    """

    value: str = Field(..., description="DN string value")

    @field_validator("value")
    @classmethod
    def validate_dn(cls, v: str) -> str:
        """Validate DN format.

        Args:
            v: DN string to validate

        Returns:
            Validated DN string

        Raises:
            ValueError: If DN format is invalid

        """
        if not v or not isinstance(v, str):
            msg = "DN must be a non-empty string"
            raise ValueError(msg)

        if "=" not in v:
            msg = "DN must contain at least one attribute=value pair"
            raise ValueError(msg)

        # Validate each component
        components = v.split(",")
        for raw_component in components:
            component = raw_component.strip()
            if "=" not in component:
                msg = f"Invalid DN component: {component}"
                raise ValueError(msg)

            attr_name, attr_value = component.split("=", 1)
            if not attr_name.strip() or not attr_value.strip():
                msg = f"Invalid DN component: {component}"
                raise ValueError(msg)

        return v

    def __str__(self) -> str:
        """Return DN string value."""
        return self.value

    def __eq__(self, other: object) -> bool:
        """Compare with string or other DistinguishedName."""
        if isinstance(other, str):
            return self.value == other
        if isinstance(other, DistinguishedName):
            return self.value == other.value
        return False

    def __hash__(self) -> int:
        """Return hash of DN value."""
        return hash(self.value)

    def get_rdn(self) -> str:
        """Get relative distinguished name (first component).

        Returns:
            The RDN (leftmost component)

        """
        return self.value.split(",")[0].strip()

    def get_parent_dn(self) -> DistinguishedName | None:
        """Get parent DN.

        Returns:
            Parent DN or None if this is root

        """
        components = self.value.split(",")
        if len(components) <= 1:
            return None

        parent_dn = ",".join(components[1:]).strip()
        return DistinguishedName(value=parent_dn)

    def is_child_of(self, parent: DistinguishedName) -> bool:
        """Check if this DN is a child of another DN.

        Args:
            parent: Potential parent DN

        Returns:
            True if this DN is a child of parent

        """
        return self.value.lower().endswith(parent.value.lower())

    def get_depth(self) -> int:
        """Get depth of DN (number of components).

        Returns:
            Number of DN components

        """
        return len(self.value.split(","))


class LDIFAttributes(DomainValueObject):
    """LDIF attributes value object.

    Represents the attributes of an LDIF entry as immutable data.
    """

    attributes: dict[str, list[str]] = Field(
        default_factory=dict,
        description="LDIF attributes as name-value pairs",
    )

    def get_single_value(self, name: str) -> str | None:
        """Get single value for attribute.

        Args:
            name: Attribute name

        Returns:
            First value or None if not found

        """
        values = self.attributes.get(name, [])
        return values[0] if values else None

    def get_values(self, name: str) -> list[str]:
        """Get all values for attribute.

        Args:
            name: Attribute name

        Returns:
            List of values (empty if not found)

        """
        return self.attributes.get(name, [])

    def has_attribute(self, name: str) -> bool:
        """Check if attribute exists.

        Args:
            name: Attribute name

        Returns:
            True if attribute exists

        """
        return name in self.attributes

    def add_value(self, name: str, value: str) -> LDIFAttributes:
        """Add value to attribute.

        Args:
            name: Attribute name
            value: Value to add

        Returns:
            New LDIFAttributes instance with added value

        """
        new_attrs = self.attributes.copy()
        if name not in new_attrs:
            new_attrs[name] = []
        new_attrs[name] += [value]
        return LDIFAttributes(attributes=new_attrs)

    def remove_value(self, name: str, value: str) -> LDIFAttributes:
        """Remove value from attribute.

        Args:
            name: Attribute name
            value: Value to remove

        Returns:
            New LDIFAttributes instance with removed value

        """
        new_attrs = self.attributes.copy()
        if name in new_attrs:
            new_values = [v for v in new_attrs[name] if v != value]
            if new_values:
                new_attrs[name] = new_values
            else:
                del new_attrs[name]
        return LDIFAttributes(attributes=new_attrs)

    def get_attribute_names(self) -> list[str]:
        """Get all attribute names.

        Returns:
            List of attribute names

        """
        return list(self.attributes.keys())

    def get_total_values(self) -> int:
        """Get total number of attribute values.

        Returns:
            Total number of values across all attributes

        """
        return sum(len(values) for values in self.attributes.values())

    def is_empty(self) -> bool:
        """Check if attributes are empty.

        Returns:
            True if no attributes are present

        """
        return len(self.attributes) == 0

    def __eq__(self, other: object) -> bool:
        """Compare with dict or other LDIFAttributes."""
        if isinstance(other, dict):
            return self.attributes == other
        if isinstance(other, LDIFAttributes):
            return self.attributes == other.attributes
        return False

    def __hash__(self) -> int:
        """Return hash of attributes for use in sets/dicts."""
        # Convert dict to frozenset of items for hashing
        return hash(
            frozenset((key, tuple(values)) for key, values in self.attributes.items()),
        )


class LDIFChangeType(DomainValueObject):
    """LDIF change type value object."""

    value: str = Field(..., description="Change type")

    @field_validator("value")
    @classmethod
    def validate_change_type(cls, v: str) -> str:
        """Validate change type.

        Args:
            v: Change type to validate

        Returns:
            Validated change type

        Raises:
            ValueError: If change type is invalid

        """
        valid_types = {"add", "modify", "delete", "modrdn"}
        if v not in valid_types:
            msg = f"Invalid change type: {v}. Must be one of {valid_types}"
            raise ValueError(msg)
        return v

    def __str__(self) -> str:
        """Return change type string."""
        return self.value

    def is_add(self) -> bool:
        """Check if this is an add operation."""
        return self.value == "add"

    def is_modify(self) -> bool:
        """Check if this is a modify operation."""
        return self.value == "modify"

    def is_delete(self) -> bool:
        """Check if this is a delete operation."""
        return self.value == "delete"

    def is_modrdn(self) -> bool:
        """Check if this is a modify RDN operation."""
        return self.value == "modrdn"


class LDIFVersion(DomainValueObject):
    """LDIF version value object."""

    value: int = Field(default=1, description="LDIF version number")

    @field_validator("value")
    @classmethod
    def validate_version(cls, v: int) -> int:
        """Validate version number.

        Args:
            v: Version number to validate

        Returns:
            Validated version number

        Raises:
            ValueError: If version is invalid

        """
        if v < 1:
            msg = "LDIF version must be >= 1"
            raise ValueError(msg)
        return v

    def __str__(self) -> str:
        """Return version as string."""
        return str(self.value)

    def is_current(self) -> bool:
        """Check if this is the current LDIF version."""
        return self.value == 1


class LDIFEncoding(DomainValueObject):
    """LDIF encoding value object."""

    value: str = Field(default="utf-8", description="Character encoding")

    @field_validator("value")
    @classmethod
    def validate_encoding(cls, v: str) -> str:
        """Validate encoding name.

        Args:
            v: Encoding name to validate

        Returns:
            Validated encoding name

        Raises:
            ValueError: If encoding is invalid

        """
        try:
            # Test if encoding is valid
            "test".encode(v)
            return v
        except (LookupError, TypeError) as e:
            msg = f"Invalid encoding: {v}"
            raise ValueError(msg) from e

    def __str__(self) -> str:
        """Return encoding name."""
        return self.value

    def is_utf8(self) -> bool:
        """Check if encoding is UTF-8."""
        return self.value.lower() in {"utf-8", "utf8"}


class LDIFLineLength(DomainValueObject):
    """LDIF line length limit value object."""

    value: int = Field(default=79, description="Maximum line length")

    @field_validator("value")
    @classmethod
    def validate_length(cls, v: int) -> int:
        """Validate line length.

        Args:
            v: Line length to validate

        Returns:
            Validated line length

        Raises:
            ValueError: If length is invalid

        """
        if v < 10:
            msg = "Line length must be at least 10 characters"
            raise ValueError(msg)
        if v > 1000:
            msg = "Line length cannot exceed 1000 characters"
            raise ValueError(msg)
        return v

    def __str__(self) -> str:
        """Return length as string."""
        return str(self.value)

    def is_standard(self) -> bool:
        """Check if this is the standard LDIF line length."""
        return self.value == 79
