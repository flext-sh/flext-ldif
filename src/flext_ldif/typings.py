"""FLEXT LDIF Types - Pure type definitions only.

Tier 0 module: ZERO internal imports. Only flext_core allowed.
All model-based unions belong in consuming modules, NOT here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, TypeVar

from flext_core import FlextTypes, r
from pydantic import BaseModel, StringConstraints

if TYPE_CHECKING:
    from flext_ldif import m


class FlextLdifTypes(FlextTypes):
    """LDIF domain types extending flext-core FlextTypes."""

    class Ldif:
        """LDIF domain type namespace."""

        type Scalar = FlextTypes.Primitives | None

        type _MetadataLeaf = FlextTypes.Primitives | None | datetime
        type MetadataValue = (
            _MetadataLeaf
            | Sequence[
                _MetadataLeaf | Sequence[_MetadataLeaf] | Mapping[str, _MetadataLeaf]
            ]
            | Mapping[
                str,
                _MetadataLeaf | Sequence[_MetadataLeaf] | Mapping[str, _MetadataLeaf],
            ]
        )

        type _ContainerLeaf = FlextTypes.Primitives | None | BaseModel | datetime
        type RecursiveContainer = (
            _ContainerLeaf
            | Sequence[
                _ContainerLeaf | Sequence[_ContainerLeaf] | Mapping[str, _ContainerLeaf]
            ]
            | Mapping[
                str,
                _ContainerLeaf
                | Sequence[_ContainerLeaf]
                | Mapping[str, _ContainerLeaf],
            ]
        )

        type NormalizedValue = RecursiveContainer

        type ValueType = Scalar | Sequence[str]
        type ValueList = Sequence[ValueType]
        type AttributeValue = str | bytes
        type DnString = str
        type RdnString = str
        type ServerType = str
        type MetadataKey = str
        type ProcessingMode = Literal["validate", "transform", "filter"]
        type ValidationLevel = Literal["strict", "moderate", "lenient"]
        type EntryAttributesDict = Mapping[str, Sequence[str]]
        type RawEntryDict = Mapping[str, str | Sequence[str] | set[str]]

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

        type ParseMethodArg = str
        type ParseMethodReturn = r[FlextTypes.Scalar | Sequence[str] | None]
        type ParseMethod = Callable[[t.NormalizedValue, str], ParseMethodReturn]
        type ParseMethodDecorator = Callable[[ParseMethod], ParseMethod]
        type WriteMethodArg = FlextTypes.Scalar | Sequence[str] | None
        type WriteMethodReturn = (
            FlextTypes.Scalar
            | Sequence[str]
            | None
            | r[FlextTypes.Scalar | Sequence[str] | None]
        )
        type WriteMethod = Callable[
            [t.NormalizedValue, WriteMethodArg], WriteMethodReturn
        ]
        type WriteMethodDecorator = Callable[[WriteMethod], WriteMethod]
        type SafeMethod = Callable[
            [t.NormalizedValue, ParseMethodArg],
            FlextTypes.Scalar | Sequence[str] | None,
        ]
        type SafeMethodDecorator = Callable[[SafeMethod], SafeMethod]

        type DistributionDict = MutableMapping[str, int]
        type AttributeDict = Mapping[str, Sequence[str]]
        type AttributeDictGeneric = Mapping[str, Sequence[str] | str]

        type TemplateValue = FlextTypes.Scalar | None
        T = TypeVar("T")
        TEntry = TypeVar("TEntry")
        TAttribute = TypeVar("TAttribute")
        TSchema = TypeVar("TSchema")

        TRUE_STRINGS: frozenset[str] = frozenset({"true", "1", "yes", "on"})
        type ConvertValue = (
            t.Container | Sequence[t.Container] | Mapping[str, t.Container]
        )
        CONTAINER_TYPES: tuple[type[t.Container], ...] = (
            str,
            int,
            float,
            bool,
            datetime,
            Path,
        )

        type ConversionRequest = (
            m.Ldif.ConvertToStr
            | m.Ldif.ConvertToInt
            | m.Ldif.ConvertToFloat
            | m.Ldif.ConvertToBool
            | m.Ldif.ConvertToList
            | m.Ldif.ConvertToTuple
            | m.Ldif.ConvertToDict
        )

        type ConversionTargetType = Literal[
            "str", "int", "float", "bool", "list", "tuple", "dict"
        ]
        type ResultValue[T] = T
        type DN = str


t = FlextLdifTypes

__all__ = ["FlextLdifTypes", "t"]
