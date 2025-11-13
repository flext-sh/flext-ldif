"""FLEXT-LDIF Services - Internal Business Logic Layer.

Internal services for FLEXT-LDIF operations. These services are NOT part of
the public API and should NOT be imported directly by external consumers.

Use the FlextLdif facade for all LDIF operations instead.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.services.dn import FlextLdifDn
from flext_ldif.services.statistics import FlextLdifStatistics

# Export services for internal testing only
# External consumers should use FlextLdif facade: from flext_ldif import FlextLdif
__all__: list[str] = [
    "FlextLdifDn",
    "FlextLdifStatistics",
]
