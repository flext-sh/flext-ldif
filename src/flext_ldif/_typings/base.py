"""Base LDIF type aliases without protocol dependencies.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import Mapping, MutableMapping, MutableSequence, Sequence
from typing import Annotated

from flext_core import m, r, t


class FlextLdifTypesBase:
    """Base LDIF aliases for recursive containers and raw LDIF payloads."""

    @staticmethod
    def _coerce_normalized_str_frozenset(
        value: t.JsonValue | Sequence[str] | set[str] | frozenset[str] | None,
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
    type MetadataInputMapping = Mapping[str, MetadataInputValue]
    type MutableMetadataInputMapping = MutableMapping[str, MetadataInputValue]
    type MutableMetadataMapping = t.MutableJsonMapping
    type MetadataCarrierValue = MetadataInputValue
    type MetadataAnalysisDetail = MutableMapping[str, t.JsonValue | t.JsonMapping]
    type ValueType = Scalar | Sequence[str]
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
    type ParseMethodReturn = r[Scalar | Sequence[str] | None]
    type WriteMethodArg = Scalar | Sequence[str] | None
    type WriteMethodReturn = (
        Scalar | Sequence[str] | r[Scalar | Sequence[str] | None] | None
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
    type Rfc2849AttributeValue = Annotated[str, t.StringConstraints(max_length=4096)]
    type NormalizedStrFrozenset = Annotated[
        frozenset[str],
        m.BeforeValidator(_coerce_normalized_str_frozenset),
    ]


__all__: list[str] = ["FlextLdifTypesBase"]
