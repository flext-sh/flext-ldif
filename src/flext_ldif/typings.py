"""FLEXT LDIF Types - Pure type definitions only.

Tier 0 module: ZERO internal imports. Only flext_core allowed.
All model-based unions belong in consuming modules, NOT here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping
from datetime import datetime
from typing import Annotated, TypeVar

from flext_core import FlextTypes, r
from pydantic import BaseModel, StringConstraints

from flext_ldif import c
from flext_ldif.constants import FlextLdifConstants

# =========================================================================
# RECURSIVE TYPES - Defined at module level for reliable scope resolution
# =========================================================================

type _Scalar = str | int | float | bool | None

type _RecursiveMetadata = (
    _Scalar | list[_RecursiveMetadata] | Mapping[str, _RecursiveMetadata] | datetime
)

type _RecursiveContainer = (
    _Scalar
    | BaseModel
    | list[_RecursiveContainer]
    | Mapping[str, _RecursiveContainer]
    | datetime
)


class FlextLdifTypes(FlextTypes):
    """LDIF domain types extending flext-core FlextTypes."""

    class Ldif:
        """LDIF domain type namespace."""

        type Scalar = _Scalar
        type MetadataValue = _RecursiveMetadata
        type MetadataDict = Mapping[str, MetadataValue]
        type object = _RecursiveContainer

        type ValueType = Scalar | list[str]
        type ValueList = list[ValueType]
        type AttributeValue = str | bytes
        type DnString = str
        type RdnString = str
        type ServerType = str
        type MetadataKey = str
        type ProcessingMode = FlextLdifConstants.ProcessingMode
        type ValidationLevel = FlextLdifConstants.ValidationLevel
        type EntryAttributesDict = dict[str, list[str]]
        type RawEntryDict = dict[str, str | list[str] | set[str]]

        class Rfc:
            """RFC-compliant annotated types (moved from _models/rfc_validation_types.py)."""

            type Rfc4512Descriptor = Annotated[
                str,
                StringConstraints(
                    min_length=c.Ldif.LdifValidation.MIN_ATTRIBUTE_NAME_LENGTH,
                    max_length=c.Ldif.LdifValidation.MAX_ATTRIBUTE_NAME_LENGTH,
                    pattern=c.Ldif.LdifValidation.RFC4512_DESCRIPTOR_PATTERN,
                    strip_whitespace=True,
                ),
            ]
            # Validation types for conversion pipeline
            type Rfc4514DnComponent = Annotated[
                str,
                StringConstraints(
                    min_length=2,
                    pattern=c.Ldif.LdifValidation.RFC4514_DN_COMPONENT_PATTERN,
                ),
            ]
            type Rfc2849AttributeValue = Annotated[
                str,
                StringConstraints(
                    max_length=c.Ldif.ValidationRules.DEFAULT_MAX_ATTR_VALUE_LENGTH
                ),
            ]

        class Extensions:
            """Extension-related type aliases for schema parsing."""

            type ExtensionValue = str | list[str]
            type ExtensionKey = str

        class Decorators:
            """Decorator-related type aliases for quirk server decorators.

            The `self` parameter in wrapped methods is typed as `object` because
            these decorators apply to methods across diverse server classes
            (OID, OUD, RFC, etc.) with no shared base in the type system.
            Runtime isinstance checks narrow types inside the decorator bodies.
            """

            type ParseMethodArg = str
            type ParseMethodReturn = r[FlextTypes.Scalar | list[str] | None]
            type ParseMethod = Callable[[object, str], ParseMethodReturn]
            type ParseMethodDecorator = Callable[[ParseMethod], ParseMethod]
            type WriteMethodArg = FlextTypes.Scalar | list[str] | None
            type WriteMethodReturn = (
                FlextTypes.Scalar
                | list[str]
                | None
                | r[FlextTypes.Scalar | list[str] | None]
            )
            type WriteMethod = Callable[[object, WriteMethodArg], WriteMethodReturn]
            type WriteMethodDecorator = Callable[[WriteMethod], WriteMethod]
            type SafeMethod = Callable[
                [object, ParseMethodArg], FlextTypes.Scalar | list[str] | None
            ]
            type SafeMethodDecorator = Callable[[SafeMethod], SafeMethod]

        class CommonDict:
            """Common dictionary type aliases used across modules."""

            type DistributionDict = MutableMapping[str, int]
            type AttributeDict = Mapping[str, list[str]]
            type AttributeDictGeneric = Mapping[str, list[str] | str]

        type TemplateValue = FlextTypes.Scalar | None
        T = TypeVar("T")
        TEntry = TypeVar("TEntry")
        TAttribute = TypeVar("TAttribute")
        TSchema = TypeVar("TSchema")

    class _Core:
        type ConversionTargetType = FlextLdifConstants.ConversionTargetType
        type ResultValue[T] = T
        type DN = str

    Core = _Core


t = FlextLdifTypes

__all__ = ["FlextLdifTypes", "t"]


type FilterFactoryType = Callable[[], object]


type CategorizationFactoryType = Callable[[str], object]
