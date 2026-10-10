"""Typings module.

Copyright (c) 2026 FLEXT Team. All rights reserved.
tests/unit/services/typings
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.servers import FlextLdifServersOid
from flext_ldif.servers import FlextLdifServersOud
from flext_ldif.servers import FlextLdifServersRfc

type ServerClass = type[FlextLdifServersRfc | FlextLdifServersOid | FlextLdifServersOud]
