"""FLEXT LDIF Types - Pure type definitions only.

Tier 0 module: ZERO internal imports. Only flext_core allowed.
All model-based unions belong in consuming modules, NOT here.
"""

from __future__ import annotations

from collections.abc import Callable
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
            | list[_MetadataLeaf | list[_MetadataLeaf] | dict[str, _MetadataLeaf]]
            | dict[
                str,
                _MetadataLeaf | list[_MetadataLeaf] | dict[str, _MetadataLeaf],
            ]
        )

        type _ContainerLeaf = FlextTypes.Primitives | None | BaseModel | datetime
        type RecursiveContainer = (
            _ContainerLeaf
            | list[_ContainerLeaf | list[_ContainerLeaf] | dict[str, _ContainerLeaf]]
            | dict[
                str,
                _ContainerLeaf | list[_ContainerLeaf] | dict[str, _ContainerLeaf],
            ]
        )

        type NormalizedValue = RecursiveContainer

        type ValueType = Scalar | list[str]
        type ValueList = list[ValueType]
        type AttributeValue = str | bytes
        type EntryAttributesDict = dict[str, list[str]]
        type RawEntryDict = dict[str, str | list[str] | set[str]]

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
        type ParseMethodReturn = r[FlextTypes.Scalar | list[str] | None]
        type ParseMethod = Callable[
            [FlextTypes.NormalizedValue, str],
            ParseMethodReturn,
        ]
        type ParseMethodDecorator = Callable[[ParseMethod], ParseMethod]
        type WriteMethodArg = FlextTypes.Scalar | list[str] | None
        type WriteMethodReturn = (
            FlextTypes.Scalar
            | list[str]
            | None
            | r[FlextTypes.Scalar | list[str] | None]
        )
        type WriteMethod = Callable[
            [FlextTypes.NormalizedValue, WriteMethodArg],
            WriteMethodReturn,
        ]
        type WriteMethodDecorator = Callable[[WriteMethod], WriteMethod]
        type SafeMethod = Callable[
            [FlextTypes.NormalizedValue, ParseMethodArg],
            FlextTypes.Scalar | list[str] | None,
        ]
        type SafeMethodDecorator = Callable[[SafeMethod], SafeMethod]

        type DistributionDict = dict[str, int]
        type AttributeDict = dict[str, list[str]]
        type AttributeDictGeneric = dict[str, list[str] | str]

        type TemplateValue = FlextTypes.Scalar | None
        T = TypeVar("T")
        TEntry = TypeVar("TEntry")
        TAttribute = TypeVar("TAttribute")
        TSchema = TypeVar("TSchema")

        TRUE_STRINGS: frozenset[str] = frozenset({"true", "1", "yes", "on"})
        type ConvertValue = (
            FlextTypes.Container
            | list[FlextTypes.Container]
            | dict[str, FlextTypes.Container]
        )
        CONTAINER_TYPES: tuple[type[FlextTypes.Container], ...] = (
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
            "str",
            "int",
            "float",
            "bool",
            "list",
            "tuple",
            "dict",
        ]
        type ResultValue[T] = T
        type DN = str


t = FlextLdifTypes

__all__ = ["FlextLdifTypes", "t"]
