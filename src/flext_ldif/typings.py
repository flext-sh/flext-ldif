"""FLEXT LDIF Types - Pure type definitions only.

This module contains ONLY pure type definitions following FLEXT architecture rules:
- No imports from models, protocols, utilities
- Only TypedDict, TypeAlias, Literal, TypeVar definitions
- Imports only from flext_core and constants

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal, TypeAlias, TypeVar

from flext_core import FlextResult as r, FlextTypes


class FlextLdifTypes(FlextTypes):
    """LDIF domain types extending flext-core FlextTypes.

    Contains ONLY type definitions, no implementations.
    DRY Pattern: Base types defined first, then reused in complex types.
    """

    # =========================================================================
    # NAMESPACE: .Ldif - All LDIF domain types
    # =========================================================================

    class Ldif:
        """LDIF domain type namespace."""

        # Inherit types from parent for hierarchical access
        type MetadataAttributeValue = FlextTypes.MetadataAttributeValue
        type ScalarValue = FlextTypes.ScalarValue

        # =========================================================================
        # BASIC TYPES (Single Source of Truth - DRY)
        # =========================================================================

        # Basic value types
        ValueType: TypeAlias = str | bytes | int | float | bool | list[str] | None
        ValueList: TypeAlias = list[ValueType]
        AttributeValue: TypeAlias = str | bytes

        # DN and RDN types
        DnString: TypeAlias = str
        RdnString: TypeAlias = str

        # Server and metadata types
        ServerType: TypeAlias = str
        MetadataKey: TypeAlias = str

        # =========================================================================
        # COMPLEX TYPES (Built from basic types)
        # =========================================================================

        MetadataType: TypeAlias = dict[str, str | int | float | bool | list[str] | None]

        # Entry attribute dict
        AttributesDict: TypeAlias = dict[str, list[AttributeValue]]
        # Normalized attributes (always strings, no bytes)
        NormalizedAttributesDict: TypeAlias = dict[str, list[str]]

        # Schema definition dicts
        SchemaAttributeDict: TypeAlias = dict[str, FlextTypes.GeneralValueType]
        SchemaObjectClassDict: TypeAlias = dict[str, FlextTypes.GeneralValueType]

        # ACL types
        AclPermission: TypeAlias = str
        AclTarget: TypeAlias = str
        AclSubject: TypeAlias = str

        # Metadata type alias for protocol usage
        Metadata: TypeAlias = dict[str, str | int | float | bool | list[str] | None]

        # Configuration types
        ConfigSection: TypeAlias = str
        ConfigValue: TypeAlias = str | int | float | bool | list[str]

        # Processing types
        ProcessingMode: TypeAlias = Literal["strict", "relaxed", "auto"]
        ValidationLevel: TypeAlias = Literal["none", "basic", "full"]

        # =========================================================================
        # DOMAIN SUB-NAMESPACES (2-level maximum)
        # =========================================================================

        class Entry:
            """Entry-related type definitions."""

            # Entry component types
            EntryDict: TypeAlias = dict[str, list[str]]
            EntryAttributes: TypeAlias = dict[str, list[str]]
            EntryMetadata: TypeAlias = dict[str, FlextTypes.GeneralValueType]

        class Attribute:
            """Attribute-related type definitions."""

            # Attribute component types
            AttributeList: TypeAlias = list[str]
            AttributeOptions: TypeAlias = dict[str, str]
            AttributeMetadata: TypeAlias = dict[str, FlextTypes.GeneralValueType]

        class Schema:
            """Schema-related type definitions."""

            # Schema component types
            SchemaDict: TypeAlias = dict[str, FlextTypes.GeneralValueType]
            SchemaElements: TypeAlias = dict[
                str, dict[str, FlextTypes.GeneralValueType]
            ]
            SchemaMetadata: TypeAlias = dict[str, FlextTypes.GeneralValueType]

        # =========================================================================
        # EXTENSIONS TYPES (Schema extensions and metadata)
        # =========================================================================

        class Extensions:
            """Extension-related type aliases for schema parsing."""

            ExtensionsDict: TypeAlias = dict[str, list[str]]
            ExtensionValue: TypeAlias = str | list[str]
            ExtensionKey: TypeAlias = str

        # =========================================================================
        # MODEL METADATA TYPES (Parsed schema structures)
        # =========================================================================

        class ModelMetadata:
            """Metadata type aliases for parsed schema objects."""

            ParsedAttributeDict: TypeAlias = dict[str, FlextTypes.GeneralValueType]
            ParsedObjectClassDict: TypeAlias = dict[str, FlextTypes.GeneralValueType]
            ParsedSchemaDict: TypeAlias = dict[str, list[FlextTypes.GeneralValueType]]

        # =========================================================================
        # DECORATOR TYPES (Callable types for decorators)
        # =========================================================================

        class Decorators:
            """Decorator-related type aliases."""

            # Basic callable types for decorators
            ParseMethodArg: TypeAlias = str
            ParseMethodReturn: TypeAlias = r[object]
            ParseMethod: TypeAlias = Callable[[object, str], r[object]]
            ParseMethodDecorator: TypeAlias = Callable[[ParseMethod], ParseMethod]

            # Write method types
            WriteMethodArg: TypeAlias = object
            WriteMethodReturn: TypeAlias = object
            WriteMethod: TypeAlias = Callable[
                [object, WriteMethodArg],
                WriteMethodReturn,
            ]
            WriteMethodDecorator: TypeAlias = Callable[[WriteMethod], WriteMethod]

            # Safe method types (with error handling)
            SafeMethod: TypeAlias = Callable[[object, ParseMethodArg], object]
            SafeMethodDecorator: TypeAlias = Callable[[SafeMethod], SafeMethod]

            # Protocol type for implementations
            ProtocolType: TypeAlias = object

        # =========================================================================
        # COMMON DICT TYPES (Used across multiple modules)
        # =========================================================================

        class CommonDict:
            """Common dictionary type aliases used across modules."""

            # Distribution tracking dict (server support distribution)
            DistributionDict: TypeAlias = dict[str, int]

            # Attribute dictionary types
            AttributeDict: TypeAlias = dict[str, list[str]]
            AttributeDictGeneric: TypeAlias = dict[str, list[str] | str]

        # =========================================================================
        # ADDITIONAL TYPE ALIASES (Used by servers and services)
        # =========================================================================

        # ACL-related types
        AclOrString: TypeAlias = str | object  # ACL model or string representation

        # Schema-related types
        SchemaModelOrString: TypeAlias = str | object  # Schema model or string
        ConvertibleModel: TypeAlias = object  # Model that can be converted

        # Metadata dictionary types (mutable variants)
        MetadataDictMutable: TypeAlias = dict[
            str,
            str | int | float | bool | list[str] | None,
        ]
        FlexibleKwargsMutable: TypeAlias = dict[str, FlextTypes.GeneralValueType]

        # Template types
        TemplateValue: TypeAlias = str | int | float | bool | None

        # Transformation types
        TransformationInfo: TypeAlias = dict[str, FlextTypes.GeneralValueType]

        # =========================================================================
        # TYPE VARIABLES (Only TypeVars allowed in typings.py)
        # =========================================================================

        T = TypeVar("T")
        TEntry = TypeVar("TEntry")
        TAttribute = TypeVar("TAttribute")
        TSchema = TypeVar("TSchema")


# Runtime alias - FlextLdifTypes extends FlextTypes
# t.GeneralValueType works (inherited), t.Ldif.* works (defined here)
t = FlextLdifTypes


__all__ = [
    "FlextLdifTypes",
    "t",
]
