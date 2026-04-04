"""Base LDIF type aliases without protocol dependencies."""

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
from typing import Annotated

from pydantic import BaseModel, StringConstraints, TypeAdapter

from flext_core import FlextTypes, r


class FlextLdifTypesBase:
    """Base LDIF aliases for recursive containers and raw LDIF payloads."""

    type Scalar = FlextTypes.Primitives | None
    type MetadataLeaf = FlextTypes.Primitives | datetime | None
    type MetadataNode = (
        MetadataLeaf | Sequence[MetadataLeaf] | Mapping[str, MetadataLeaf]
    )
    type MetadataValue = (
        MetadataLeaf | Sequence[MetadataNode] | Mapping[str, MetadataNode]
    )
    type ContainerLeaf = FlextTypes.Primitives | BaseModel | datetime | None
    type ContainerNode = (
        ContainerLeaf | Sequence[ContainerLeaf] | Mapping[str, ContainerLeaf]
    )
    type RecursiveContainer = (
        ContainerLeaf | Sequence[ContainerNode] | Mapping[str, ContainerNode]
    )
    type ValueType = Scalar | FlextTypes.StrSequence
    type ValueList = Sequence[ValueType]
    type AttributeValue = str | bytes
    type EntryAttributesDict = FlextTypes.StrSequenceMapping
    type MutableEntryAttributesDict = FlextTypes.MutableStrSequenceMapping
    type RawEntryDict = Mapping[str, str | FlextTypes.StrSequence | AbstractSet[str]]
    type MutableRawEntryDict = MutableMapping[
        str,
        str | MutableSequence[str] | AbstractSet[str],
    ]
    type SchemaExtensionsMapping = MutableMapping[
        str,
        MutableSequence[str] | str | bool | None,
    ]
    type AttributeDict = FlextTypes.StrSequenceMapping
    type AttributeDictGeneric = Mapping[str, FlextTypes.StrSequence | str]
    type DistributionDict = FlextTypes.IntMapping
    type TemplateValue = FlextTypes.Scalar | None
    type DN = str
    type ParseMethodArg = str
    type ParseMethodReturn = r[FlextTypes.Scalar | FlextTypes.StrSequence | None]
    type ParseMethod = Callable[[RecursiveContainer, str], ParseMethodReturn]
    type ParseMethodDecorator = Callable[[ParseMethod], ParseMethod]
    type WriteMethodArg = FlextTypes.Scalar | FlextTypes.StrSequence | None
    type WriteMethodReturn = (
        FlextTypes.Scalar
        | FlextTypes.StrSequence
        | r[FlextTypes.Scalar | FlextTypes.StrSequence | None]
        | None
    )
    type WriteMethod = Callable[[RecursiveContainer, WriteMethodArg], WriteMethodReturn]
    type WriteMethodDecorator = Callable[[WriteMethod], WriteMethod]
    type SafeMethod = Callable[
        [RecursiveContainer, ParseMethodArg],
        FlextTypes.Scalar | FlextTypes.StrSequence | None,
    ]
    type SafeMethodDecorator = Callable[[SafeMethod], SafeMethod]
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
        StringConstraints(min_length=2, pattern=r"^[a-zA-Z0-9-]+=[^,]+$"),
    ]
    type Rfc2849AttributeValue = Annotated[
        str,
        StringConstraints(max_length=4096),
    ]
    RFC4512_DESCRIPTOR_ADAPTER: TypeAdapter[Rfc4512Descriptor] = TypeAdapter(
        Rfc4512Descriptor,
    )
    RFC4514_DN_COMPONENT_ADAPTER: TypeAdapter[Rfc4514DnComponent] = TypeAdapter(
        Rfc4514DnComponent,
    )
    RFC2849_ATTRIBUTE_VALUE_ADAPTER: TypeAdapter[Rfc2849AttributeValue] = TypeAdapter(
        Rfc2849AttributeValue,
    )


__all__ = ["FlextLdifTypesBase"]
