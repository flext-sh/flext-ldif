from __future__ import annotations

from pydantic import ValidationError

from flext_core import r
from flext_ldif import FlextLdifProtocols as p, t


class FlextLdifUtilitiesValidation:
    @staticmethod
    def validate_value(
        value: t.Container,
        *validators: p.ValidatorSpec,
    ) -> r[t.Container]:
        del validators
        return r[t.Container].ok(value)

    class Rfc:
        """RFC validation helpers."""

        @classmethod
        def is_valid_rfc2849_attribute_value(cls, value: str) -> bool:
            try:
                _ = t.Ldif.RFC2849_ATTRIBUTE_VALUE_ADAPTER.validate_python(value)
                return True
            except ValidationError:
                return False

        @classmethod
        def is_valid_rfc4512_descriptor(cls, value: str) -> bool:
            try:
                _ = t.Ldif.RFC4512_DESCRIPTOR_ADAPTER.validate_python(value)
                return True
            except ValidationError:
                return False

        @classmethod
        def is_valid_rfc4514_dn_component(cls, attribute_name: str, value: str) -> bool:
            try:
                _ = t.Ldif.RFC4514_DN_COMPONENT_ADAPTER.validate_python(
                    f"{attribute_name}={value}",
                )
                return True
            except ValidationError:
                return False


__all__: list[str] = ["FlextLdifUtilitiesValidation"]
