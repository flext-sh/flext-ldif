"""RFC 2849 change-operation model for LDIF entries.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated

from flext_core import FlextUtilities as u, m
from flext_ldif import c, t
from flext_ldif._models.domain_entry_change_value import (
    FlextLdifModelsDomainEntryChangeOperationValue,
)


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


__all__: list[str] = ["FlextLdifModelsDomainEntryChangeOperation"]
