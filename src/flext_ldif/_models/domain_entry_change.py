"""RFC 2849 control and change-operation models for LDIF entries.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated

from flext_core import FlextUtilities as u, m
from flext_ldif import c, t


class FlextLdifModelsDomainEntryControl(m.Value):
    """Structured RFC 2849 control line."""

    control_type: Annotated[
        str,
        u.Field(description="LDAP control OID or descriptor"),
    ]
    criticality: Annotated[
        bool | None,
        u.Field(description="Optional criticality flag from control line"),
    ] = None
    value: Annotated[str | None, u.Field(description="Optional control value")] = None
    value_origin: Annotated[
        c.Ldif.ValueOrigin | None,
        u.Field(description="Original control value encoding/source"),
    ] = None
    raw_value: Annotated[
        str | None,
        u.Field(description="Original serialized control payload"),
    ] = None


class FlextLdifModelsDomainEntryChangeOperationValue(m.Value):
    """Single value captured inside a modify operation block."""

    value: Annotated[
        str,
        u.Field(description="Decoded value used by the operation"),
    ]
    value_origin: Annotated[
        c.Ldif.ValueOrigin,
        u.Field(description="Original LDIF encoding/source for this value"),
    ] = c.Ldif.ValueOrigin.PLAIN
    raw_value: Annotated[
        str | None,
        u.Field(description="Original serialized value payload before decoding"),
    ] = None


class FlextLdifModelsDomainEntryChangeOperation(m.Value):
    """Structured RFC 2849 modify operation block."""

    operation: Annotated[
        c.Ldif.ChangeOperation,
        u.Field(description="Modify operation name"),
    ]
    attribute: Annotated[
        str,
        u.Field(description="Target attribute for the modify block"),
    ]
    values: Annotated[
        t.MutableSequenceOf[FlextLdifModelsDomainEntryChangeOperationValue],
        u.Field(description="Decoded values in the block"),
    ] = u.Field(default_factory=list)


__all__: list[str] = [
    "FlextLdifModelsDomainEntryChangeOperation",
    "FlextLdifModelsDomainEntryChangeOperationValue",
    "FlextLdifModelsDomainEntryControl",
]
