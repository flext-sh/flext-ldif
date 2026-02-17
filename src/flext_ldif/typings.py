"""FLEXT LDIF Types - Pure type definitions only."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal, TypeAlias, TypeVar

from flext_core import FlextResult as r, FlextTypes


class FlextLdifTypes(FlextTypes):
    """LDIF domain types extending flext-core FlextTypes."""

    class Ldif:
        """LDIF domain type namespace."""

        type MetadataAttributeValue = FlextTypes.MetadataAttributeValue
        type ScalarValue = FlextTypes.ScalarValue

        ValueType: TypeAlias = str | bytes | int | float | bool | list[str] | None
        ValueList: TypeAlias = list[ValueType]
        AttributeValue: TypeAlias = str | bytes

        DnString: TypeAlias = str
        RdnString: TypeAlias = str

        ServerType: TypeAlias = str
        MetadataKey: TypeAlias = str

        MetadataType: TypeAlias = dict[str, str | int | float | bool | list[str] | None]

        AttributesDict: TypeAlias = dict[str, list[AttributeValue]]

        NormalizedAttributesDict: TypeAlias = dict[str, list[str]]

        SchemaAttributeDict: TypeAlias = dict[str, FlextTypes.GeneralValueType]
        SchemaObjectClassDict: TypeAlias = dict[str, FlextTypes.GeneralValueType]

        AclPermission: TypeAlias = str
        AclTarget: TypeAlias = str
        AclSubject: TypeAlias = str

        Metadata: TypeAlias = dict[str, str | int | float | bool | list[str] | None]

        ConfigSection: TypeAlias = str
        ConfigValue: TypeAlias = str | int | float | bool | list[str]

        ProcessingMode: TypeAlias = Literal["strict", "relaxed", "auto"]
        ValidationLevel: TypeAlias = Literal["none", "basic", "full"]

        class Entry:
            """Entry-related type definitions."""

            EntryDict: TypeAlias = dict[str, list[str]]
            EntryAttributes: TypeAlias = dict[str, list[str]]
            EntryMetadata: TypeAlias = dict[str, FlextTypes.GeneralValueType]

        class Attribute:
            """Attribute-related type definitions."""

            AttributeList: TypeAlias = list[str]
            AttributeOptions: TypeAlias = dict[str, str]
            AttributeMetadata: TypeAlias = dict[str, FlextTypes.GeneralValueType]

        class Schema:
            """Schema-related type definitions."""

            SchemaDict: TypeAlias = dict[str, FlextTypes.GeneralValueType]
            SchemaElements: TypeAlias = dict[
                str, dict[str, FlextTypes.GeneralValueType]
            ]
            SchemaMetadata: TypeAlias = dict[str, FlextTypes.GeneralValueType]

        class Extensions:
            """Extension-related type aliases for schema parsing."""

            ExtensionsDict: TypeAlias = dict[str, list[str]]
            ExtensionValue: TypeAlias = str | list[str]
            ExtensionKey: TypeAlias = str

        class ModelMetadata:
            """Metadata type aliases for parsed schema objects."""

            ParsedAttributeDict: TypeAlias = dict[str, FlextTypes.GeneralValueType]
            ParsedObjectClassDict: TypeAlias = dict[str, FlextTypes.GeneralValueType]
            ParsedSchemaDict: TypeAlias = dict[str, list[FlextTypes.GeneralValueType]]

        class Decorators:
            """Decorator-related type aliases."""

            ParseMethodArg: TypeAlias = str
            ParseMethodReturn: TypeAlias = r[object]
            ParseMethod: TypeAlias = Callable[[object, str], r[object]]
            ParseMethodDecorator: TypeAlias = Callable[[ParseMethod], ParseMethod]

            WriteMethodArg: TypeAlias = object
            WriteMethodReturn: TypeAlias = object
            WriteMethod: TypeAlias = Callable[
                [object, WriteMethodArg],
                WriteMethodReturn,
            ]
            WriteMethodDecorator: TypeAlias = Callable[[WriteMethod], WriteMethod]

            SafeMethod: TypeAlias = Callable[[object, ParseMethodArg], object]
            SafeMethodDecorator: TypeAlias = Callable[[SafeMethod], SafeMethod]

            ProtocolType: TypeAlias = object

        class CommonDict:
            """Common dictionary type aliases used across modules."""

            DistributionDict: TypeAlias = dict[str, int]

            AttributeDict: TypeAlias = dict[str, list[str]]
            AttributeDictGeneric: TypeAlias = dict[str, list[str] | str]

        AclOrString: TypeAlias = str | object

        SchemaModelOrString: TypeAlias = str | object
        ConvertibleModel: TypeAlias = object

        MetadataDictMutable: TypeAlias = dict[
            str,
            str | int | float | bool | list[str] | None,
        ]
        FlexibleKwargsMutable: TypeAlias = dict[str, FlextTypes.GeneralValueType]

        TemplateValue: TypeAlias = str | int | float | bool | None

        TransformationInfo: TypeAlias = dict[str, FlextTypes.GeneralValueType]

        T = TypeVar("T")
        TEntry = TypeVar("TEntry")
        TAttribute = TypeVar("TAttribute")
        TSchema = TypeVar("TSchema")


t = FlextLdifTypes


__all__ = [
    "FlextLdifTypes",
    "t",
]
