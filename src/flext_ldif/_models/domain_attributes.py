"""Domain models for LDIF attributes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    KeysView,
    MutableMapping,
    MutableSequence,
    ValuesView,
)
from typing import TYPE_CHECKING, Annotated, ClassVar, Self

from pydantic import ConfigDict

from flext_cli import m, u
from flext_ldif import c, t

if TYPE_CHECKING:
    from flext_ldif import FlextLdifModelsMetadata


class FlextLdifModelsDomainAttributes:
    """Namespace for LDIF attributes domain models."""

    class Attributes(m.ArbitraryTypesModel):
        """LDIF attributes container - simplified dict-like interface."""

        model_config: ClassVar[m.ConfigDict] = ConfigDict(
            validate_assignment=True,
            extra="forbid",
            use_enum_values=True,
            str_strip_whitespace=True,
        )
        attributes: Annotated[
            t.MutableStrSequenceMapping,
            u.Field(description="Attribute name to values list"),
        ]
        attribute_metadata: Annotated[
            MutableMapping[str, t.MutableAttributeMapping],
            u.Field(
                description="Metadata for each attribute, like category or hidden status.",
            ),
        ] = u.Field(default_factory=dict)
        metadata: Annotated[
            FlextLdifModelsMetadata.EntryMetadata | None,
            u.Field(
                description="Metadata for preserving ordering and formats",
            ),
        ] = None

        def __getitem__(self, key: str) -> MutableSequence[str]:
            """Get attribute values by name (case-sensitive LDAP).

            Args:
                key: Attribute name

            Returns:
                List of attribute values

            Raises:
                KeyError if attribute not found

            """
            return self.attributes[key]

        def __setitem__(self, key: str, value: MutableSequence[str]) -> None:
            """Set attribute values by name.

            Args:
                key: Attribute name
                value: List of values

            """
            self.attributes[key] = value

        def __len__(self) -> int:
            """Return the number of attributes."""
            return len(self.attributes)

        def __contains__(self, key: str) -> bool:
            """Check if attribute exists."""
            return key in self.attributes

        def add_attribute(self, key: str, values: MutableSequence[str]) -> Self:
            """Add or update an attribute with values.

            Args:
                key: Attribute name
                values: List of values

            Returns:
                Self for method chaining

            """
            self.attributes[key] = values
            return self

        def get(
            self,
            key: str,
            default: MutableSequence[str] | None = None,
        ) -> MutableSequence[str]:
            """Get attribute values with optional default.

            Args:
                key: Attribute name
                default: Default list if not found
                (defaults to empty list if not provided)

            Returns:
                List of values or default (empty list if not found and no default)

            """
            if default is not None:
                return self.attributes.get(key, default)
            if key in self.attributes:
                return self.attributes[key]
            return []

        def get_values(
            self,
            key: str,
            default: MutableSequence[str] | None = None,
        ) -> MutableSequence[str]:
            """Get attribute values as a list (same as get()).

            Args:
                key: Attribute name
                default: Default list if not found

            Returns:
                List of attribute values, or default if not found

            """
            return self.get(key, default)

        def has_attribute(self, key: str) -> bool:
            """Check if attribute exists.

            Args:
                key: Attribute name

            Returns:
                True if attribute exists

            """
            return key in self.attributes

        def items(self) -> MutableSequence[tuple[str, MutableSequence[str]]]:
            """Get attribute name-values pairs.

            Returns:
                List of (name, values) tuples

            """
            return list(self.attributes.items())

        def iter_attributes(self) -> MutableSequence[str]:
            """Get list of all attribute names.

            Returns:
                List of attribute names

            """
            return list(self.attributes.keys())

        def keys(self) -> KeysView[str]:
            """Get attribute names."""
            return self.attributes.keys()

        def remove_attribute(self, key: str) -> Self:
            """Remove an attribute if it exists.

            Args:
                key: Attribute name

            Returns:
                Self for method chaining

            """
            _ = self.attributes.pop(key, None)
            return self

        def values(self) -> ValuesView[MutableSequence[str]]:
            """Get attribute values lists."""
            return self.attributes.values()

    class AttributeTransformation(m.FrozenModel):
        """Detailed tracking of attribute transformation operations.

        Records complete transformation history for LDIF attribute conversions,
        including original values, target values, transformation type, and reasoning.
        Essential for audit trails and troubleshooting server migrations.

        Attributes:
            original_name: Original attribute name from source server
            target_name: Transformed attribute name for target server (None if removed)
            original_values: List of original attribute values
            target_values: List of transformed values (None if removed)
            transformation_type: Type of transformation applied
            reason: Human-readable explanation of why transformation was needed

        Example:
            transform = AttributeTransformation(
                original_name="orclaci",
                target_name="aci",
                original_values=["(objectClass=*)(version 3.0...)"],
                target_values=["(objectClass=*)(version 3.0...)"],
                transformation_type="renamed",
                reason="OID proprietary format → RFC 2256 standard ACL"
            )

        """

        original_name: Annotated[
            str,
            u.Field(..., description="Original attribute name from source server"),
        ]
        target_name: Annotated[
            str | None,
            u.Field(
                description="Transformed attribute name (None if removed)",
            ),
        ] = None
        original_values: Annotated[
            MutableSequence[str],
            u.Field(
                description="Original attribute values from source",
            ),
        ]
        target_values: Annotated[
            MutableSequence[str] | None,
            u.Field(description="Transformed values (None if removed)"),
        ] = None
        transformation_type: Annotated[
            c.Ldif.TransformationTypeLiteral,
            u.Field(..., description="Type of transformation applied to the attribute"),
        ]
        reason: Annotated[
            str,
            u.Field(description="Human-readable reason for transformation"),
        ] = ""


__all__: list[str] = ["FlextLdifModelsDomainAttributes"]
