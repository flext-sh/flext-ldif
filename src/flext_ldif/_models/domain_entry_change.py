"""RFC 2849 change-operation model for LDIF entries.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, ClassVar

from flext_cli import m

from flext_ldif import c, t
from flext_ldif._models import FlextLdifModelsDomainEntryChangeOperationValue


class FlextLdifModelsDomainEntryChangeOperation:
    """Compose the operation model into the public namespace through MRO."""

    class ChangeOperation(m.Value):
        """Structured RFC 2849 modify operation block."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(use_enum_values=False)

        operation: Annotated[
            c.Ldif.ChangeOperation,
            m.Field(description="Modify operation name"),
        ]
        attribute: Annotated[
            str,
            m.Field(description="Target attribute for the modify block"),
        ]
        values: t.MutableSequenceOf[
            FlextLdifModelsDomainEntryChangeOperationValue.ChangeOperationValue
        ] = m.Field(
            default_factory=list[
                FlextLdifModelsDomainEntryChangeOperationValue.ChangeOperationValue
            ],
            description="Decoded values in the block",
        )


__all__: list[str] = ["FlextLdifModelsDomainEntryChangeOperation"]
