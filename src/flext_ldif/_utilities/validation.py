from __future__ import annotations

from typing import Final

from flext_core import r, u
from pydantic import TypeAdapter, ValidationError

from flext_ldif import p, t


class FlextLdifUtilitiesValidation(u):
    @staticmethod
    def validate(value: t.Container, *validators: p.ValidatorSpec) -> r[t.Container]:
        del validators
        return r[t.Container].ok(value)

    class Rfc:
        """RFC validation helpers."""

        _DESCRIPTOR_ADAPTER: Final[TypeAdapter[t.Ldif.Rfc.Rfc4512Descriptor]] = (
            TypeAdapter(t.Ldif.Rfc.Rfc4512Descriptor)
        )
        _DN_COMPONENT_ADAPTER: Final[TypeAdapter[t.Ldif.Rfc.Rfc4514DnComponent]] = (
            TypeAdapter(t.Ldif.Rfc.Rfc4514DnComponent)
        )
        _ATTRIBUTE_VALUE_ADAPTER: Final[
            TypeAdapter[t.Ldif.Rfc.Rfc2849AttributeValue]
        ] = TypeAdapter(t.Ldif.Rfc.Rfc2849AttributeValue)

        @classmethod
        def is_valid_rfc2849_attribute_value(cls, value: str) -> bool:
            try:
                _ = cls._ATTRIBUTE_VALUE_ADAPTER.validate_python(value)
                return True
            except ValidationError:
                return False

        @classmethod
        def is_valid_rfc4512_descriptor(cls, value: str) -> bool:
            try:
                _ = cls._DESCRIPTOR_ADAPTER.validate_python(value)
                return True
            except ValidationError:
                return False

        @classmethod
        def is_valid_rfc4514_dn_component(cls, attribute_name: str, value: str) -> bool:
            try:
                _ = cls._DN_COMPONENT_ADAPTER.validate_python(
                    f"{attribute_name}={value}",
                )
                return True
            except ValidationError:
                return False


__all__ = ["FlextLdifUtilitiesValidation"]
