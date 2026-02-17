"""FLEXT LDIF Types - Pure type definitions only.

Tier 0 module: ZERO internal imports. Only flext_core allowed.
All model-based unions belong in consuming modules, NOT here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping
from typing import Literal, TypeAlias, TypeVar

from flext_core import FlextResult as r, FlextTypes


class FlextLdifTypes(FlextTypes):
    """LDIF domain types extending flext-core FlextTypes."""

    class Ldif:
        """LDIF domain type namespace."""

        type MetadataAttributeValue = FlextTypes.MetadataAttributeValue
        type ScalarValue = FlextTypes.ScalarValue
        type JsonValue = FlextTypes.JsonValue

        ValueType: TypeAlias = str | bytes | int | float | bool | list[str] | None
        ValueList: TypeAlias = list[ValueType]
        AttributeValue: TypeAlias = str | bytes

        DnString: TypeAlias = str
        RdnString: TypeAlias = str

        ServerType: TypeAlias = str
        MetadataKey: TypeAlias = str

        ProcessingMode: TypeAlias = Literal["strict", "relaxed", "auto"]
        ValidationLevel: TypeAlias = Literal["none", "basic", "full"]

        AttributesDict: TypeAlias = Mapping[str, list[AttributeValue]]
        NormalizedAttributesDict: TypeAlias = dict[str, list[str]]

        class Extensions:
            """Extension-related type aliases for schema parsing."""

            ExtensionsDict: TypeAlias = Mapping[str, list[str]]
            ExtensionValue: TypeAlias = str | list[str]
            ExtensionKey: TypeAlias = str

        class ModelMetadata:
            """Metadata type aliases for parsed schema objects."""

            ParsedAttributeDict: TypeAlias = Mapping[str, FlextTypes.GeneralValueType]
            ParsedObjectClassDict: TypeAlias = Mapping[str, FlextTypes.GeneralValueType]
            ParsedSchemaDict: TypeAlias = Mapping[
                str, list[FlextTypes.GeneralValueType]
            ]

        class Decorators:
            """Decorator-related type aliases for quirk server decorators.

            The `self` parameter in wrapped methods is typed as `object` because
            these decorators apply to methods across diverse server classes
            (OID, OUD, RFC, etc.) with no shared base in the type system.
            Runtime isinstance checks narrow types inside the decorator bodies.
            """

            ParseMethodArg: TypeAlias = str
            ParseMethodReturn: TypeAlias = r[
                str | int | float | bool | list[str] | None
            ]
            ParseMethod: TypeAlias = Callable[
                [object, str],
                ParseMethodReturn,
            ]
            ParseMethodDecorator: TypeAlias = Callable[[ParseMethod], ParseMethod]

            WriteMethodArg: TypeAlias = str | int | float | bool | list[str] | None
            WriteMethodReturn: TypeAlias = str | int | float | bool | list[str] | None
            WriteMethod: TypeAlias = Callable[
                [object, WriteMethodArg],
                WriteMethodReturn,
            ]
            WriteMethodDecorator: TypeAlias = Callable[[WriteMethod], WriteMethod]

            SafeMethod: TypeAlias = Callable[
                [object, ParseMethodArg],
                str | int | float | bool | list[str] | None,
            ]
            SafeMethodDecorator: TypeAlias = Callable[[SafeMethod], SafeMethod]

        class CommonDict:
            """Common dictionary type aliases used across modules."""

            DistributionDict: TypeAlias = MutableMapping[str, int]
            AttributeDict: TypeAlias = Mapping[str, list[str]]
            AttributeDictGeneric: TypeAlias = Mapping[str, list[str] | str]

        MetadataDictMutable: TypeAlias = MutableMapping[
            str,
            str | int | float | bool | list[str] | None,
        ]

        TemplateValue: TypeAlias = str | int | float | bool | None

        T: TypeVar = TypeVar("T")
        TEntry: TypeVar = TypeVar("TEntry")
        TAttribute: TypeVar = TypeVar("TAttribute")
        TSchema: TypeVar = TypeVar("TSchema")


t = FlextLdifTypes


__all__ = [
    "FlextLdifTypes",
    "t",
]
