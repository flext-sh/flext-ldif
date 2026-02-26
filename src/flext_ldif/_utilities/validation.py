from __future__ import annotations

from flext_core import r
from flext_core.utilities import FlextUtilities

from flext_ldif.protocols import p
from flext_ldif.typings import t


class FlextLdifUtilitiesValidation(FlextUtilities):
    @staticmethod
    def validate(
        value: t.Ldif.JsonValue,
        *validators: p.ValidatorSpec,
    ) -> r[t.Ldif.JsonValue]:
        del validators
        return r[t.Ldif.JsonValue].ok(value)


__all__ = ["FlextLdifUtilitiesValidation"]
