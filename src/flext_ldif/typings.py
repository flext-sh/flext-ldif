"""FLEXT LDIF Types - Pure type definitions only.

Tier 0 module: ZERO internal imports. Only flext_core allowed.
All model-based unions belong in consuming modules, NOT here.
"""

from __future__ import annotations

from collections.abc import (
    Callable,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
    Set as AbstractSet,
)
from datetime import datetime
from typing import TYPE_CHECKING, Annotated

from pydantic import BaseModel, StringConstraints

from flext_core import FlextTypes, r

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

        type ValueType = Scalar | t.StrSequence
        type ValueList = Sequence[ValueType]
        type AttributeValue = str | bytes
        type EntryAttributesDict = t.StrSequenceMapping
        type MutableEntryAttributesDict = t.MutableStrSequenceMapping
        type RawEntryDict = Mapping[str, str | t.StrSequence | AbstractSet[str]]
        type MutableRawEntryDict = MutableMapping[
            str, str | MutableSequence[str] | AbstractSet[str]
        ]

        type Rfc4512Descriptor = Annotated[
            str,
            StringConstraints(
                min_length=1,
                max_length=64,
                pattern=r"^[a-zA-Z0-9-]+$",
                strip_whitespace=True,
            ),
        ]
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
        type ParseMethodReturn = r[FlextTypes.Scalar | t.StrSequence | None]
        type ParseMethod = Callable[
            [RecursiveContainer, str],
            ParseMethodReturn,
        ]
        type ParseMethodDecorator = Callable[[ParseMethod], ParseMethod]
        type WriteMethodArg = FlextTypes.Scalar | t.StrSequence | None
        type WriteMethodReturn = (
            FlextTypes.Scalar
            | t.StrSequence
            | None
            | r[FlextTypes.Scalar | t.StrSequence | None]
        )
        type WriteMethod = Callable[
            [RecursiveContainer, WriteMethodArg],
            WriteMethodReturn,
        ]
        type WriteMethodDecorator = Callable[[WriteMethod], WriteMethod]
        type SafeMethod = Callable[
            [RecursiveContainer, ParseMethodArg],
            FlextTypes.Scalar | t.StrSequence | None,
        ]
        type SafeMethodDecorator = Callable[[SafeMethod], SafeMethod]

        type SchemaExtensionsMapping = MutableMapping[
            str, MutableSequence[str] | str | bool | None
        ]

        type AttributeDict = t.StrSequenceMapping
        type AttributeDictGeneric = Mapping[str, t.StrSequence | str]

        type TemplateValue = FlextTypes.Scalar | None
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
