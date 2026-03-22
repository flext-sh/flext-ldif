"""FLEXT LDIF Types - Pure type definitions only.

Tier 0 module: ZERO internal imports. Only flext_core allowed.
All model-based unions belong in consuming modules, NOT here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping
from datetime import datetime
from typing import Annotated, Literal, TypeVar

from flext_core import FlextTypes, r, t as _core_t
from pydantic import BaseModel, StringConstraints

# =========================================================================
# RECURSIVE TYPES - Defined at module level for reliable scope resolution
# =========================================================================

type _Scalar = _core_t.Primitives | None

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
        type NormalizedValue = _RecursiveContainer

        type ValueType = Scalar | list[str]
        type ValueList = list[ValueType]
        type AttributeValue = str | bytes
        type DnString = str
        type RdnString = str
        type ServerType = str
        type MetadataKey = str
        type ProcessingMode = Literal["validate", "transform", "filter"]
        type ValidationLevel = Literal["strict", "moderate", "lenient"]
        type EntryAttributesDict = dict[str, list[str]]
        type RawEntryDict = dict[str, str | list[str] | set[str]]

        class Rfc:
            """RFC-compliant annotated types (moved from _models/rfc_validation_types.py)."""

            type Rfc4512Descriptor = Annotated[
                str,
                StringConstraints(
                    min_length=1,
                    max_length=64,
                    pattern=r"^[a-zA-Z0-9-]+$",
                    strip_whitespace=True,
                ),
            ]
            # Validation types for conversion pipeline
            type Rfc4514DnComponent = Annotated[
                str,
                StringConstraints(
                    min_length=2,
                    pattern=r"^[a-zA-Z0-9-]+=[^,]+$",
                ),
            ]
            type Rfc2849AttributeValue = Annotated[
                str,
                StringConstraints(
                    max_length=4096,
                ),
            ]

        class Extensions:
            """Extension-related type aliases for schema parsing."""

            type ExtensionValue = str | list[str]
            type ExtensionKey = str

        class Factories:
            """Factory callable type aliases for LDIF processing.

            These factory types use `t.NormalizedValue` return/parameter types because they are
            callables that dynamically create or process instances of diverse,
            unrelated classes (e.g., different filter/categorization implementations).
            This is a permitted exception per AGENTS.md §3.2 exception #1.
            """

            type FilterFactory = Callable[[], t.NormalizedValue]
            type CategorizationFactory = Callable[[str], t.NormalizedValue]

        class Decorators:
            """Decorator-related type aliases for quirk server decorators.

            The `self` parameter in wrapped methods is typed as `t.NormalizedValue` because
            these decorators apply to methods across diverse server classes
            (OID, OUD, RFC, etc.) with no shared base in the type system.
            Runtime isinstance checks narrow types inside the decorator bodies.
            """

            type ParseMethodArg = str
            type ParseMethodReturn = r[FlextTypes.Scalar | list[str] | None]
            type ParseMethod = Callable[[t.NormalizedValue, str], ParseMethodReturn]
            type ParseMethodDecorator = Callable[[ParseMethod], ParseMethod]
            type WriteMethodArg = FlextTypes.Scalar | list[str] | None
            type WriteMethodReturn = (
                FlextTypes.Scalar
                | list[str]
                | None
                | r[FlextTypes.Scalar | list[str] | None]
            )
            type WriteMethod = Callable[
                [t.NormalizedValue, WriteMethodArg], WriteMethodReturn
            ]
            type WriteMethodDecorator = Callable[[WriteMethod], WriteMethod]
            type SafeMethod = Callable[
                [t.NormalizedValue, ParseMethodArg],
                FlextTypes.Scalar | list[str] | None,
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
        type ConversionTargetType = Literal[
            "str", "int", "float", "bool", "list", "tuple", "dict"
        ]
        type ResultValue[T] = T
        type DN = str

    Core = _Core


t = FlextLdifTypes

__all__ = ["FlextLdifTypes", "t"]
