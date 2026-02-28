from __future__ import annotations

from typing import Annotated, Final

from pydantic import StringConstraints, TypeAdapter, ValidationError

from flext_ldif import c

RFC4512_DESCRIPTOR_PATTERN: Final[str] = r"^[A-Za-z][A-Za-z0-9-]{0,126}$"
RFC4514_DN_COMPONENT_PATTERN: Final[str] = (
    r"^(?:[A-Za-z][A-Za-z0-9-]{0,126})=(?:[^\\,]|\\.)*$"
)

type Rfc4512Descriptor = Annotated[
    str,
    StringConstraints(
        min_length=c.Ldif.LdifValidation.MIN_ATTRIBUTE_NAME_LENGTH,
        max_length=c.Ldif.LdifValidation.MAX_ATTRIBUTE_NAME_LENGTH,
        pattern=RFC4512_DESCRIPTOR_PATTERN,
        strip_whitespace=True,
    ),
]

type Rfc4514DnComponent = Annotated[
    str,
    StringConstraints(min_length=2, pattern=RFC4514_DN_COMPONENT_PATTERN),
]

type Rfc2849AttributeValue = Annotated[
    str,
    StringConstraints(max_length=c.Ldif.ValidationRules.DEFAULT_MAX_ATTR_VALUE_LENGTH),
]

_DESCRIPTOR_ADAPTER: Final[TypeAdapter[Rfc4512Descriptor]] = TypeAdapter(
    Rfc4512Descriptor,
)
_DN_COMPONENT_ADAPTER: Final[TypeAdapter[Rfc4514DnComponent]] = TypeAdapter(
    Rfc4514DnComponent,
)
_ATTRIBUTE_VALUE_ADAPTER: Final[TypeAdapter[Rfc2849AttributeValue]] = TypeAdapter(
    Rfc2849AttributeValue,
)


def is_valid_rfc4512_descriptor(value: str) -> bool:
    try:
        _ = _DESCRIPTOR_ADAPTER.validate_python(value)
        return True
    except ValidationError:
        return False


def is_valid_rfc4514_dn_component(attribute_name: str, value: str) -> bool:
    try:
        _ = _DN_COMPONENT_ADAPTER.validate_python(f"{attribute_name}={value}")
        return True
    except ValidationError:
        return False


def is_valid_rfc2849_attribute_value(value: str) -> bool:
    try:
        _ = _ATTRIBUTE_VALUE_ADAPTER.validate_python(value)
        return True
    except ValidationError:
        return False


__all__ = [
    "RFC4512_DESCRIPTOR_PATTERN",
    "RFC4514_DN_COMPONENT_PATTERN",
    "Rfc2849AttributeValue",
    "Rfc4512Descriptor",
    "Rfc4514DnComponent",
    "is_valid_rfc2849_attribute_value",
    "is_valid_rfc4512_descriptor",
    "is_valid_rfc4514_dn_component",
]
