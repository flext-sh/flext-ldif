"""FLEXT LDIF Types - Pure type definitions only.

Tier 0 module: ZERO internal imports. Only flext_core allowed.
All model-based unions belong in consuming modules, NOT here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, MutableSequence, Sequence
from datetime import datetime
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Annotated, Literal, TypeAlias, TypeVar

from annotated_types import Ge, Le
from flext_core import FlextTypes, r
from pydantic import BaseModel, StringConstraints

if TYPE_CHECKING:
    from flext_ldif import m

# ---------------------------------------------------------------------------
# Primitive type building blocks (previously on FlextTypes, removed in migration)
# ---------------------------------------------------------------------------
_Primitives: TypeAlias = str | int | float | bool
_Scalar: TypeAlias = str | int | float | bool | datetime
_Container: TypeAlias = str | int | float | bool | datetime | Path
_NormalizedValue: TypeAlias = (
    _Container
    | BaseModel
    | Mapping[str, "_NormalizedValue"]
    | Sequence["_NormalizedValue"]
    | tuple["_NormalizedValue", ...]
    | None
)


class FlextLdifTypes(FlextTypes):
    """LDIF domain types extending flext-core FlextTypes."""

    # ------------------------------------------------------------------
    # Bridge aliases: types removed from FlextTypes in migration
    # ------------------------------------------------------------------
    Primitives: TypeAlias = _Primitives
    Scalar: TypeAlias = _Scalar
    Container: TypeAlias = _Container
    NormalizedValue: TypeAlias = _NormalizedValue
    Numeric: TypeAlias = int | float

    # Annotated validation types
    NonNegativeInt: TypeAlias = Annotated[int, Ge(0)]
    NonNegativeFloat: TypeAlias = Annotated[float, Ge(0.0)]
    DecimalFraction: TypeAlias = Annotated[float, Ge(0.0), Le(1.0)]

    # Collection types
    StrSequence: TypeAlias = Sequence[str]
    ContainerMapping: TypeAlias = Mapping[str, _NormalizedValue]
    MutableContainerMapping: TypeAlias = MutableMapping[str, _NormalizedValue]
    ContainerList: TypeAlias = Sequence[_NormalizedValue]
    MutableContainerList: TypeAlias = MutableSequence[_NormalizedValue]
    MutableConfigurationMapping: TypeAlias = MutableMapping[
        str, MutableMapping[str, str] | MutableSequence[str] | str
    ]
    MutableFlatContainerMapping: TypeAlias = MutableMapping[str, _Scalar | None]
    ScalarMapping: TypeAlias = Mapping[str, _Scalar]
    ValueOrModel: TypeAlias = _NormalizedValue | BaseModel

    # Runtime tuple constants for isinstance checks
    PRIMITIVES_TYPES: tuple[type, ...] = (str, int, float, bool)
    SCALAR_TYPES: tuple[type, ...] = (str, int, float, bool, datetime)
    CONTAINER_TYPES: tuple[type, ...] = (str, int, float, bool, datetime, Path)

    # Module export type (for lazy __init__.py loaders)
    ModuleExport: TypeAlias = (
        _NormalizedValue | type | ModuleType | Callable[..., object]
    )

    # Metadata value (top-level alias for t.MetadataValue usage)
    MetadataValue: TypeAlias = (
        _Primitives
        | None
        | datetime
        | list[_Primitives | None | datetime]
        | dict[str, _Primitives | None | datetime]
    )

    class Ldif:
        """LDIF domain type namespace."""

        type Scalar = _Primitives | None

        type _MetadataLeaf = _Primitives | None | datetime
        type MetadataValue = (
            _MetadataLeaf
            | list[_MetadataLeaf | list[_MetadataLeaf] | dict[str, _MetadataLeaf]]
            | dict[
                str,
                _MetadataLeaf | list[_MetadataLeaf] | dict[str, _MetadataLeaf],
            ]
        )

        type _ContainerLeaf = _Primitives | None | BaseModel | datetime
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
        type ParseMethodReturn = r[_Scalar | list[str] | None]
        type ParseMethod = Callable[
            [_NormalizedValue, str],
            ParseMethodReturn,
        ]
        type ParseMethodDecorator = Callable[[ParseMethod], ParseMethod]
        type WriteMethodArg = _Scalar | list[str] | None
        type WriteMethodReturn = (
            _Scalar
            | list[str]
            | None
            | r[_Scalar | list[str] | None]
        )
        type WriteMethod = Callable[
            [_NormalizedValue, WriteMethodArg],
            WriteMethodReturn,
        ]
        type WriteMethodDecorator = Callable[[WriteMethod], WriteMethod]
        type SafeMethod = Callable[
            [_NormalizedValue, ParseMethodArg],
            _Scalar | list[str] | None,
        ]
        type SafeMethodDecorator = Callable[[SafeMethod], SafeMethod]

        type DistributionDict = dict[str, int]
        type AttributeDict = dict[str, list[str]]
        type AttributeDictGeneric = dict[str, list[str] | str]

        type TemplateValue = _Scalar | None
        T = TypeVar("T")
        TEntry = TypeVar("TEntry")
        TAttribute = TypeVar("TAttribute")
        TSchema = TypeVar("TSchema")

        TRUE_STRINGS: frozenset[str] = frozenset({"true", "1", "yes", "on"})
        type ConvertValue = (
            _Container
            | list[_Container]
            | dict[str, _Container]
        )
        CONTAINER_TYPES: tuple[type, ...] = (
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

        type ConvertedModel = (
            m.Ldif.Entry
            | m.Ldif.SchemaAttribute
            | m.Ldif.SchemaObjectClass
            | m.Ldif.Acl
        )
        type SchemaConversionValue = (
            m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass | str
        )


t = FlextLdifTypes

__all__ = ["FlextLdifTypes", "t"]
