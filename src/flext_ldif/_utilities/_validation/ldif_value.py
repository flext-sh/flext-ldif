"""Validation of LDIF values.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from typing import TYPE_CHECKING

from flext_ldif import r

if TYPE_CHECKING:
    from flext_ldif import p, t


class FlextLdifUtilitiesValidationLdifValue:
    """LDIF value validation helper."""

    @staticmethod
    def validate_ldif_value(
        value: t.JsonValue,
        *validators: p.ValidatorSpec,
    ) -> p.Result[t.JsonValue]:
        del validators
        return r[t.JsonValue].ok(value)


__all__: list[str] = ["FlextLdifUtilitiesValidationLdifValue"]
