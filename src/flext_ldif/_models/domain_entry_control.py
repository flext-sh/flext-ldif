"""RFC 2849 control-line model for LDIF entries.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, ClassVar

from flext_core import FlextUtilities as u, m
from flext_ldif._models.domain_entry_change_value import FlextLdifModelsDomainEntryValue


class FlextLdifModelsDomainEntryControl(FlextLdifModelsDomainEntryValue):
    """Structured RFC 2849 control line.

    Inherits the shared RFC 2849 ``value`` / ``value_origin`` / ``raw_value``
    contract from its value base; a control line's value stays optional.
    """

    model_config: ClassVar[m.ConfigDict] = m.Value.model_config

    control_type: Annotated[
        str,
        u.Field(description="LDAP control OID or descriptor"),
    ]
    criticality: Annotated[
        bool | None,
        u.Field(description="Optional criticality flag from control line"),
    ] = None


__all__: list[str] = ["FlextLdifModelsDomainEntryControl"]
