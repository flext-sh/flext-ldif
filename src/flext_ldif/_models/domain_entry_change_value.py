"""RFC 2849 modify-operation value model for LDIF entries.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, ClassVar

from flext_core import FlextUtilities as u, m
from flext_ldif import c


class FlextLdifModelsDomainEntryValue(m.Value):
    """Shared RFC 2849 value contract for entry and control payloads.

    Owns the ``value`` / ``value_origin`` / ``raw_value`` fields once so the
    modify-operation value and the control line compose into the ``Ldif``
    namespace through a single compatible definition instead of two conflicting
    sibling overrides.
    """

    model_config: ClassVar[m.ConfigDict] = m.Value.model_config

    value: Annotated[
        str | None,
        u.Field(description="Decoded value payload, absent when the spec omits it"),
    ] = None
    value_origin: Annotated[
        c.Ldif.ValueOrigin | None,
        u.Field(description="Original LDIF encoding/source for this value"),
    ] = None
    raw_value: Annotated[
        str | None,
        u.Field(description="Original serialized value payload before decoding"),
    ] = None


class FlextLdifModelsDomainEntryChangeOperationValue(FlextLdifModelsDomainEntryValue):
    """Single value captured inside a modify operation block."""


__all__: list[str] = ["FlextLdifModelsDomainEntryChangeOperationValue"]
