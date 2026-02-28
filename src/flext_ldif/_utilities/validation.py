from __future__ import annotations

from flext_core import FlextUtilities, r

from flext_ldif import p, t


class FlextLdifUtilitiesValidation(FlextUtilities):
    @staticmethod
    def validate(
        value: t.Ldif.JsonValue,
        *validators: p.ValidatorSpec,
    ) -> r[t.Ldif.JsonValue]:
        del validators
        return r[t.Ldif.JsonValue].ok(value)


__all__ = ["FlextLdifUtilitiesValidation"]
