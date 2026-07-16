"""Domain models for LDIF attributes.

from flext_ldif import m
from flext_ldif import u
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    ItemsView,
    KeysView,
    MutableMapping,
    ValuesView,
)
from typing import Annotated, ClassVar, Self

from flext_cli import m, u
from flext_ldif import c, p, t


class FlextLdifModelsDomainAttributes:
    """Namespace for LDIF attributes domain models."""

    # NOTE (mro-0ftd.3.7.2): typed dynamic-property container replacing the
    # model-less dict[str, list[str]] (operator law 2026-07-15: never model-less,
    # dynamic entry properties are a typed tuple-of-values model in an advanced
    # Mapping container mirroring flext-core containers.py _MappingRootBase).
    class Property(m.FrozenModel):
        """A single LDIF attribute: its name and its ordered, immutable values."""

        name: Annotated[
            str,
            u.Field(description="The attribute name (case preserved as parsed)."),
        ]
        values: Annotated[
            tuple[str, ...],
            u.Field(description="Ordered attribute values (immutable)."),
        ] = ()

    class Properties(
        m.RootModel[dict[str, "FlextLdifModelsDomainAttributes.Property"]]
    ):
        """Advanced typed Mapping of attribute name -> Property.

        Root-model container with an explicit dict-like API (mirrors flext-core
        FlextModelsContainers._MappingRootBase) so consumers keep ``props[name]``,
        ``props.get``, ``props.items`` ergonomics while every value is a typed
        Property instead of a raw list. This is the SSOT for entry attribute data.
        """

        root: Annotated[
            dict[str, FlextLdifModelsDomainAttributes.Property],
            u.Field(
                default_factory=dict,
                description="Validated attribute-name to Property mapping.",
            ),
        ]

        def __getitem__(
            self,
            key: str,
        ) -> FlextLdifModelsDomainAttributes.Property:
            return self.root[key]

        def __setitem__(
            self,
            key: str,
            value: FlextLdifModelsDomainAttributes.Property,
        ) -> None:
            self.root[key] = value

        def __delitem__(self, key: str) -> None:
            del self.root[key]

        def __contains__(self, key: object) -> bool:
            return key in self.root

        def __len__(self) -> int:
            return len(self.root)

        def __bool__(self) -> bool:
            return bool(self.root)

        def keys(self) -> KeysView[str]:
            return self.root.keys()

        def values(self) -> ValuesView[FlextLdifModelsDomainAttributes.Property]:
            return self.root.values()

        def items(
            self,
        ) -> ItemsView[str, FlextLdifModelsDomainAttributes.Property]:
            return self.root.items()

        def get(
            self,
            key: str,
            default: FlextLdifModelsDomainAttributes.Property | None = None,
        ) -> FlextLdifModelsDomainAttributes.Property | None:
            return self.root.get(key, default)

    class Attributes(m.ArbitraryTypesModel):
        """LDIF attributes container - simplified dict-like interface."""

        model_config: ClassVar[p.ConfigDict] = m.ConfigDict(
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
            t.MutableJsonMapping | None,
            u.Field(
                description="Metadata for preserving ordering and formats",
            ),
        ] = None

        def __getitem__(self, key: str) -> t.MutableSequenceOf[str]:
            """Get attribute values by name (case-sensitive LDAP).

            Args:
                key: Attribute name

            Returns:
                List of attribute values

            Raises:
                KeyError if attribute not found

            """
            return self.attributes[key]

        def __setitem__(self, key: str, value: t.MutableSequenceOf[str]) -> None:
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

        def add_attribute(self, key: str, values: t.MutableSequenceOf[str]) -> Self:
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
            default: t.MutableSequenceOf[str] | None = None,
        ) -> t.MutableSequenceOf[str]:
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

        def has_attribute(self, key: str) -> bool:
            """Check if attribute exists.

            Args:
                key: Attribute name

            Returns:
                True if attribute exists

            """
            return key in self.attributes

        def items(self) -> t.MutableSequenceOf[tuple[str, t.MutableSequenceOf[str]]]:
            """Get attribute name-values pairs.

            Returns:
                List of (name, values) tuples

            """
            return list(self.attributes.items())

        def iter_attributes(self) -> t.MutableSequenceOf[str]:
            """Get list of all attribute names.

            Returns:
                List of attribute names

            """
            return list(self.attributes.keys())

        def keys(self) -> KeysView[str]:
            """Get attribute names."""
            attribute_keys: KeysView[str] = self.attributes.keys()
            return attribute_keys

        def remove_attribute(self, key: str) -> Self:
            """Remove an attribute if it exists.

            Args:
                key: Attribute name

            Returns:
                Self for method chaining

            """
            _ = self.attributes.pop(key, None)
            return self

        def values(self) -> ValuesView[t.MutableSequenceOf[str]]:
            """Get attribute values lists."""
            attribute_values: ValuesView[t.MutableSequenceOf[str]] = (
                self.attributes.values()
            )
            return attribute_values

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
            t.MutableSequenceOf[str],
            u.Field(
                description="Original attribute values from source",
            ),
        ]
        target_values: Annotated[
            t.MutableSequenceOf[str] | None,
            u.Field(description="Transformed values (None if removed)"),
        ] = None
        transformation_type: Annotated[
            c.Ldif.TransformationType,
            u.Field(..., description="Type of transformation applied to the attribute"),
        ]
        reason: Annotated[
            str,
            u.Field(description="Human-readable reason for transformation"),
        ] = ""


__all__: list[str] = ["FlextLdifModelsDomainAttributes"]
