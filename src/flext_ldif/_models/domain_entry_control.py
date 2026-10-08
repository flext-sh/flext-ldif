"""RFC 2849 control-line model for LDIF entries.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated

from flext_core import FlextUtilities as u, m
from flext_ldif import c


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


__all__: list[str] = ["FlextLdifModelsDomainEntryControl"]
