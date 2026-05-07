"""Base LDIF type aliases without protocol dependencies."""

from __future__ import annotations

from collections.abc import (
    MutableMapping,
)
from typing import Annotated

from flext_cli import m, r, t


class FlextLdifTypesBase:
    """Base LDIF aliases for recursive containers and raw LDIF payloads."""

    @staticmethod
    def _coerce_normalized_str_frozenset(
        value: t.JsonValue | t.StrSequence | None,
    ) -> frozenset[str]:
        match value:
            case None:
                return frozenset()
            case str():
                return frozenset((value,))
            case tuple() | list() | set() | frozenset():
                return frozenset(str(item) for item in value)
            case _:
                return frozenset((str(value),))

    type RegexPattern = t.RegexPattern
    type RegexMatch = t.RegexMatch
    type Scalar = t.Primitives | None
    type MetadataInputValue = t.JsonValue
    type MetadataInputMapping = t.MappingKV[str, MetadataInputValue]
    type MutableMetadataInputMapping = MutableMapping[str, MetadataInputValue]
    type MutableMetadataMapping = t.MutableJsonMapping
    type MetadataCarrierValue = MetadataInputValue
    type ValueType = Scalar | t.StrSequence
    type AttributeValue = str | bytes
    type MutableEntryAttributesDict = t.MutableStrSequenceMapping
    type UnconvertedAttributeValue = str | t.MutableSequenceOf[str] | bytes
    type UnconvertedAttributes = MutableMapping[str, UnconvertedAttributeValue]
    type SchemaExtensionsMapping = MutableMapping[
        str,
        t.MutableSequenceOf[str] | str | bool | None,
    ]
    type AttributeDict = t.StrSequenceMapping
    type DN = str
    type ParseMethodArg = str
    type ParseMethodReturn = r[Scalar | t.StrSequence | None]
    type WriteMethodArg = Scalar | t.StrSequence | None
    type WriteMethodReturn = (
        Scalar | t.StrSequence | r[Scalar | t.StrSequence | None] | None
    )
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
    type NormalizedStrFrozenset = Annotated[
        frozenset[str],
        m.BeforeValidator(_coerce_normalized_str_frozenset),
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
