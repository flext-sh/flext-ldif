"""Attribute domain models."""

from __future__ import annotations

from collections.abc import Iterator

from flext_core import FlextCore
from pydantic import Field


class AttributeValues(FlextCore.Models.Value):
    """LDIF attribute values container."""

    values: FlextCore.Types.StringList = Field(
        default_factory=list, description="Attribute values"
    )

    def get_single_value(self) -> str | None:
        """Get single value if list has exactly one element."""
        return self.values[0] if len(self.values) == 1 else None

    def __iter__(self) -> Iterator[str]:
        """Make AttributeValues iterable for ldap3 compatibility."""
        return iter(self.values)

    def __len__(self) -> int:
        """Return number of values."""
        return len(self.values)

    def __getitem__(self, index: int) -> str:
        """Get value by index for ldap3 compatibility."""
        return self.values[index]

    def __str__(self) -> str:
        """Return first value or empty string for string conversion."""
        return self.values[0] if self.values else ""

    def __repr__(self) -> str:
        """Return representation."""
        return f"AttributeValues(values={self.values!r})"


class LdifAttributes(FlextCore.Models.Value):
    """LDIF attributes container with dict-like interface."""

    attributes: dict[str, AttributeValues] = Field(
        default_factory=dict, description="Attribute name to values mapping"
    )
    metadata: dict[str, str] | None = Field(
        default=None,
        description="Quirk-specific metadata for preserving attribute ordering and formats",
    )

    @classmethod
    def create(
        cls,
        data: FlextCore.Types.Dict | LdifAttributes,
    ) -> FlextCore.Result[LdifAttributes]:
        """Create LdifAttributes from dictionary or existing instance.

        Args:
            data: Dictionary of attributes or existing LdifAttributes instance

        Returns:
            FlextCore.Result[LdifAttributes]: Success with attributes or error

        """
        if isinstance(data, cls):
            return FlextCore.Result[LdifAttributes].ok(data)

        try:
            # Use dict.get() for more Pythonic attribute access
            attributes = data.get("attributes", data)

            # Convert attribute values to AttributeValues instances
            processed_attrs: dict[str, AttributeValues] = {}
            for key, value in attributes.items():
                if isinstance(value, AttributeValues):
                    processed_attrs[key] = value
                elif isinstance(value, list):
                    processed_attrs[key] = AttributeValues(values=value)
                else:
                    processed_attrs[key] = AttributeValues(values=[value])

            return FlextCore.Result[LdifAttributes].ok(cls(attributes=processed_attrs))

        except (KeyError, TypeError, ValueError) as e:
            return FlextCore.Result[LdifAttributes].fail(
                f"LdifAttributesCreationError: {e}",
            )

    def get_data(self) -> dict[str, FlextCore.Types.StringList]:
        """Get attributes data as dict of lists."""
        return {name: attr.values for name, attr in self.attributes.items()}

    def get_keys(self) -> FlextCore.Types.StringList:
        """Get attribute names (dict-like interface)."""
        return list(self.attributes.keys())

    def get_values(self) -> list[AttributeValues]:
        """Get attribute values (dict-like interface)."""
        return list(self.attributes.values())

    def get_items(self) -> list[tuple[str, AttributeValues]]:
        """Get attribute items (dict-like interface)."""
        return list(self.attributes.items())

    def __contains__(self, name: str) -> bool:
        """Check if attribute exists."""
        return name in self.attributes

    def __getitem__(self, name: str) -> AttributeValues:
        """Get attribute by name."""
        return self.attributes[name]

    def __setitem__(self, name: str, value: AttributeValues) -> None:
        """Set attribute value."""
        self.attributes[name] = value

    def __delitem__(self, name: str) -> None:
        """Delete attribute."""
        self.attributes.pop(name, None)

    def get(
        self, name: str, default: FlextCore.Types.StringList | None = None
    ) -> FlextCore.Types.StringList | None:
        """Get attribute values by name."""
        attr_values = self.attributes.get(name)
        return attr_values.values if attr_values else default

    def get_attribute(self, name: str) -> AttributeValues | None:
        """Get attribute by name."""
        return self.attributes.get(name)

    def to_ldap3(
        self, exclude: FlextCore.Types.StringList | None = None
    ) -> dict[str, str | FlextCore.Types.StringList]:
        """Convert attributes to ldap3 format (strings for single values, lists for multi).

        Args:
            exclude: List of attribute names to exclude (e.g., ["objectClass"])

        Returns:
            Dictionary with single-valued attributes as strings and multi-valued as lists

        """
        exclude_set = set(exclude) if exclude else set()
        result: dict[str, str | FlextCore.Types.StringList] = {}

        for name, attr_values in self.attributes.items():
            if name not in exclude_set:
                values = attr_values.values
                result[name] = values[0] if len(values) == 1 else values

        return result

    def add_attribute(self, name: str, value: str | FlextCore.Types.StringList) -> None:
        """Add attribute value(s)."""
        if isinstance(value, str):
            value = [value]
        if name in self.attributes:
            self.attributes[name].values.extend(value)
        else:
            self.attributes[name] = AttributeValues(values=value)

    def remove_attribute(self, name: str) -> None:
        """Remove attribute by name."""
        self.attributes.pop(name, None)
