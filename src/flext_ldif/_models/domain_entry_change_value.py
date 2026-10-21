"""RFC 2849 modify-operation value model for LDIF entries.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, ClassVar

from flext_cli import m

from flext_ldif import c


class FlextLdifModelsDomainEntryChangeOperationValue(m.Value):
    """Single value captured inside a modify operation block."""

    model_config: ClassVar[m.ConfigDict] = m.ConfigDict(use_enum_values=False)

    value: Annotated[
        str,
        m.Field(description="Decoded value used by the operation"),
    ]
    value_origin: Annotated[
        c.Ldif.ValueOrigin,
        m.Field(description="Original LDIF encoding/source for this value"),
    ] = c.Ldif.ValueOrigin.PLAIN
    raw_value: Annotated[
        str | None,
        m.Field(description="Original serialized value payload before decoding"),
    ] = None


__all__: list[str] = ["FlextLdifModelsDomainEntryChangeOperationValue"]
