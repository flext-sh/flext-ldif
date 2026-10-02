from __future__ import annotations

from flext_core import m, r, u
from flext_ldif import p, t


class FlextLdifUtilitiesValidation:
    @staticmethod
    def validate_value(
        value: t.JsonValue, *validators: p.ValidatorSpec
    ) -> p.Result[t.JsonValue]:
        del validators
        return r[t.JsonValue].ok(value)

    class Rfc:
        """RFC validation helpers."""

        RFC2849_ATTRIBUTE_VALUE_ADAPTER: m.TypeAdapter[t.Ldif.Rfc2849AttributeValue] = (
            u.type_adapter(t.Ldif.Rfc2849AttributeValue)
        )
        RFC4512_DESCRIPTOR_ADAPTER: m.TypeAdapter[t.Ldif.Rfc4512Descriptor] = (
            u.type_adapter(t.Ldif.Rfc4512Descriptor)
        )
        RFC4514_DN_COMPONENT_ADAPTER: m.TypeAdapter[t.Ldif.Rfc4514DnComponent] = (
            u.type_adapter(t.Ldif.Rfc4514DnComponent)
        )

        @classmethod
        def is_valid_rfc2849_attribute_value(cls, value: str) -> bool:
            return u.validate_value(cls.RFC2849_ATTRIBUTE_VALUE_ADAPTER, value).success

        @classmethod
        def is_valid_rfc4512_descriptor(cls, value: str) -> bool:
            return u.validate_value(cls.RFC4512_DESCRIPTOR_ADAPTER, value).success

        @classmethod
        def is_valid_rfc4514_dn_component(cls, attribute_name: str, value: str) -> bool:
            return u.validate_value(
                cls.RFC4514_DN_COMPONENT_ADAPTER, f"{attribute_name}={value}"
            ).success


__all__: list[str] = ["FlextLdifUtilitiesValidation"]
