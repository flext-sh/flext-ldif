"""FLEXT LDIF Types - Pure type definitions only.

Tier 0 module: ZERO internal imports. Only flext_core allowed.
All model-based unions belong in consuming modules, NOT here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping
from typing import Annotated, Literal, TypeAlias, TypeVar

from flext_core import FlextResult, FlextTypes
from pydantic import StringConstraints

from flext_ldif import c


class FlextLdifTypes(FlextTypes):
    """LDIF domain types extending flext-core FlextTypes."""

    class Ldif:
        """LDIF domain type namespace."""

        ValueType: TypeAlias = str | bytes | int | float | bool | list[str] | None
        ValueList: TypeAlias = list[ValueType]
        AttributeValue: TypeAlias = str | bytes
        DnString: TypeAlias = str
        RdnString: TypeAlias = str
        ServerType: TypeAlias = str
        MetadataKey: TypeAlias = str
        ProcessingMode: TypeAlias = Literal["strict", "relaxed", "auto"]
        ValidationLevel: TypeAlias = Literal["none", "basic", "full"]
        EntryAttributesDict: TypeAlias = dict[str, list[str]]
        RawEntryDict: TypeAlias = dict[str, str | list[str] | set[str]]

        class Rfc:
            """RFC-compliant annotated types (moved from _models/rfc_validation_types.py)."""

            type Rfc4512Descriptor = Annotated[
                str,
                StringConstraints(
                    min_length=c.Ldif.LdifValidation.MIN_ATTRIBUTE_NAME_LENGTH,
                    max_length=c.Ldif.LdifValidation.MAX_ATTRIBUTE_NAME_LENGTH,
                    pattern=c.Ldif.LdifValidation.RFC4512_DESCRIPTOR_PATTERN,
                    strip_whitespace=True,
                ),
            ]
            type Rfc4514DnComponent = Annotated[
                str,
                StringConstraints(
                    min_length=2,
                    pattern=c.Ldif.LdifValidation.RFC4514_DN_COMPONENT_PATTERN,
                ),
            ]
            type Rfc2849AttributeValue = Annotated[
                str,
                StringConstraints(
                    max_length=c.Ldif.ValidationRules.DEFAULT_MAX_ATTR_VALUE_LENGTH
                ),
            ]

        class Extensions:
            """Extension-related type aliases for schema parsing."""

            ExtensionValue: TypeAlias = str | list[str]
            ExtensionKey: TypeAlias = str

        class Decorators:
            """Decorator-related type aliases for quirk server decorators.

            The `self` parameter in wrapped methods is typed as `object` because
            these decorators apply to methods across diverse server classes
            (OID, OUD, RFC, etc.) with no shared base in the type system.
            Runtime isinstance checks narrow types inside the decorator bodies.
            """

            ParseMethodArg: TypeAlias = str
            ParseMethodReturn: TypeAlias = FlextResult[
                FlextTypes.Scalar | list[str] | None
            ]
            ParseMethod: TypeAlias = Callable[[object, str], ParseMethodReturn]
            ParseMethodDecorator: TypeAlias = Callable[[ParseMethod], ParseMethod]
            WriteMethodArg: TypeAlias = FlextTypes.Scalar | list[str] | None
            WriteMethodReturn: TypeAlias = (
                FlextTypes.Scalar
                | list[str]
                | None
                | FlextResult[FlextTypes.Scalar | list[str] | None]
            )
            WriteMethod: TypeAlias = Callable[
                [object, WriteMethodArg], WriteMethodReturn
            ]
            WriteMethodDecorator: TypeAlias = Callable[[WriteMethod], WriteMethod]
            SafeMethod: TypeAlias = Callable[
                [object, ParseMethodArg], FlextTypes.Scalar | list[str] | None
            ]
            SafeMethodDecorator: TypeAlias = Callable[[SafeMethod], SafeMethod]

        class CommonDict:
            """Common dictionary type aliases used across modules."""

            DistributionDict: TypeAlias = MutableMapping[str, int]
            AttributeDict: TypeAlias = Mapping[str, list[str]]
            AttributeDictGeneric: TypeAlias = Mapping[str, list[str] | str]

        TemplateValue: TypeAlias = FlextTypes.Scalar | None
        T = TypeVar("T")
        TEntry = TypeVar("TEntry")
        TAttribute = TypeVar("TAttribute")
        TSchema = TypeVar("TSchema")


__all__ = ["FlextLdifTypes"]
