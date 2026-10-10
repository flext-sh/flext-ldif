"""Typings module.

Copyright (c) 2026 FLEXT Team. All rights reserved.
tests/unit/services/typings
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.servers import (
    FlextLdifServersOid,
    FlextLdifServersOud,
    FlextLdifServersRfc,
)

type ServerClass = type[FlextLdifServersRfc | FlextLdifServersOid | FlextLdifServersOud]
