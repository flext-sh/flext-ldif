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
from typing import Annotated

from flext_cli import m, r, t


class FlextLdifTypesBase:
    """Base LDIF aliases for recursive containers and raw LDIF payloads."""

    type Scalar = t.Primitives | None
    type MetadataInputValue = t.JsonValue
    type MetadataInputMapping = Mapping[str, MetadataInputValue]
    type MutableMetadataInputMapping = MutableMapping[str, MetadataInputValue]
    type MetadataMapping = Mapping[str, t.JsonValue]
    type MutableMetadataMapping = MutableMapping[str, t.JsonValue]
    type MetadataCarrierValue = MetadataInputValue
    type ValueType = Scalar | t.StrSequence
    type ValueList = Sequence[ValueType]
    type AttributeValue = str | bytes
    type EntryAttributesDict = t.StrSequenceMapping
    type MutableEntryAttributesDict = t.MutableStrSequenceMapping
    type RawEntryDict = Mapping[str, str | t.StrSequence | AbstractSet[str]]
    type MutableRawEntryDict = MutableMapping[
        str,
        str | MutableSequence[str] | AbstractSet[str],
    ]
    type UnconvertedAttributeValue = str | MutableSequence[str] | bytes
    type UnconvertedAttributes = MutableMapping[str, UnconvertedAttributeValue]
    type SchemaExtensionsMapping = MutableMapping[
        str,
        MutableSequence[str] | str | bool | None,
    ]
    type AttributeDict = t.StrSequenceMapping
    type AttributeDictGeneric = Mapping[str, t.StrSequence | str]
    type DistributionDict = t.IntMapping
    type TemplateValue = t.Scalar | None
    type DN = str
    type ParseMethodArg = str
    type ParseMethodReturn = r[t.Scalar | t.StrSequence | None]
    type ParseMethod = Callable[[t.JsonValue, str], ParseMethodReturn]
    type ParseMethodDecorator = Callable[[ParseMethod], ParseMethod]
    type WriteMethodArg = t.Scalar | t.StrSequence | None
    type WriteMethodReturn = (
        t.Scalar | t.StrSequence | r[t.Scalar | t.StrSequence | None] | None
    )
    type WriteMethod = Callable[[t.JsonValue, WriteMethodArg], WriteMethodReturn]
    type WriteMethodDecorator = Callable[[WriteMethod], WriteMethod]
    type SafeMethod = Callable[
        [t.JsonValue, ParseMethodArg],
        t.Scalar | t.StrSequence | None,
    ]
    type SafeMethodDecorator = Callable[[SafeMethod], SafeMethod]
    type Rfc4512Descriptor = Annotated[
        str,
        t.StringConstraints(
            min_length=1,
            max_length=64,
            pattern=r"^[a-zA-Z0-9-]+$",
            strip_whitespace=True,
        ),
    ]
    type Rfc4514DnComponent = Annotated[
        str,
        t.StringConstraints(min_length=2, pattern=r"^[a-zA-Z0-9-]+=[^,]+$"),
    ]
    type Rfc2849AttributeValue = Annotated[
        str,
        t.StringConstraints(max_length=4096),
    ]
    RFC4512_DESCRIPTOR_ADAPTER: m.TypeAdapter[Rfc4512Descriptor] = m.TypeAdapter(
        Rfc4512Descriptor,
    )
    RFC4514_DN_COMPONENT_ADAPTER: m.TypeAdapter[Rfc4514DnComponent] = m.TypeAdapter(
        Rfc4514DnComponent,
    )
    RFC2849_ATTRIBUTE_VALUE_ADAPTER: m.TypeAdapter[Rfc2849AttributeValue] = (
        m.TypeAdapter(Rfc2849AttributeValue)
    )


__all__: list[str] = ["FlextLdifTypesBase"]
