"""Base LDIF type aliases without protocol dependencies."""

from __future__ import annotations

from collections.abc import (
    Mapping,
    MutableMapping,
    MutableSequence,
)
from typing import Annotated

from flext_cli import m, r, t


class FlextLdifTypesBase:
    """Base LDIF aliases for recursive containers and raw LDIF payloads."""

    type Scalar = t.Primitives | None
    type MetadataInputValue = t.JsonValue
    type MetadataInputMapping = Mapping[str, MetadataInputValue]
    type MutableMetadataInputMapping = MutableMapping[str, MetadataInputValue]
    type MutableMetadataMapping = MutableMapping[str, t.JsonValue]
    type MetadataCarrierValue = MetadataInputValue
    type ValueType = Scalar | t.StrSequence
    type AttributeValue = str | bytes
    type MutableEntryAttributesDict = t.MutableStrSequenceMapping
    type UnconvertedAttributeValue = str | MutableSequence[str] | bytes
    type UnconvertedAttributes = MutableMapping[str, UnconvertedAttributeValue]
    type SchemaExtensionsMapping = MutableMapping[
        str,
        MutableSequence[str] | str | bool | None,
    ]
    type AttributeDict = t.StrSequenceMapping
    type DN = str
    type ParseMethodArg = str
    type ParseMethodReturn = r[t.Ldif.Scalar | t.StrSequence | None]
    type WriteMethodArg = t.Ldif.Scalar | t.StrSequence | None
    type WriteMethodReturn = (
        t.Ldif.Scalar | t.StrSequence | r[t.Ldif.Scalar | t.StrSequence | None] | None
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
