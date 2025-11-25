"""LDIF type definitions for flext-ldif domain.

Type aliases and type variables for LDIF processing.
All types organized under single FlextLdifTypes class per FLEXT standardization.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TypeAlias

from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifTypes:
    """LDIF type definitions extending flext-core FlextTypes.

    Unified namespace class that aggregates all LDIF type definitions.
    Provides a single access point for all LDIF types while maintaining
    modular organization.
    """

    # Type alias for auto-execute kwargs
    AutoExecuteKwargs: TypeAlias = dict[str, object]

    # Union type for quirk instances
    QuirkInstanceType: TypeAlias = (
        FlextLdifServersRfc.Schema
        | FlextLdifServersRfc.Entry
        | FlextLdifServersRfc.Acl
        | FlextLdifServersBase.Schema
        | FlextLdifServersBase.Entry
        | FlextLdifServersBase.Acl
    )
