from __future__ import annotations

from flext_core import FlextUtilities, r

from flext_ldif import p, t


class FlextLdifUtilitiesValidation(FlextUtilities):
    @staticmethod
    def validate(
        value: t.JsonValue,
        *validators: p.ValidatorSpec,
    ) -> r[t.JsonValue]:
        del validators
        return r[t.JsonValue].ok(value)


__all__ = ["FlextLdifUtilitiesValidation"]
