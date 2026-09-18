from __future__ import annotations

from flext_core import r, u
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

        @classmethod
        def is_valid_rfc2849_attribute_value(cls, value: str) -> bool:
            return u.validate_value(
                t.Ldif.RFC2849_ATTRIBUTE_VALUE_ADAPTER, value
            ).success

        @classmethod
        def is_valid_rfc4512_descriptor(cls, value: str) -> bool:
            return u.validate_value(t.Ldif.RFC4512_DESCRIPTOR_ADAPTER, value).success

        @classmethod
        def is_valid_rfc4514_dn_component(cls, attribute_name: str, value: str) -> bool:
            return u.validate_value(
                t.Ldif.RFC4514_DN_COMPONENT_ADAPTER, f"{attribute_name}={value}"
            ).success


__all__: list[str] = ["FlextLdifUtilitiesValidation"]
