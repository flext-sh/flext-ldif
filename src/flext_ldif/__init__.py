"""FLEXT-LDIF - RFC-First LDIF Processing Library.

LDIF processing library with RFC 2849/4512 compliance and server-specific quirks
for the FLEXT ecosystem.

Single Entry Point Architecture:
    This module enforces a single entry point pattern. ALL LDIF operations must
    go through the FlextLdif class. Internal modules (quirks, services, parsers,
    writers) are NOT part of the public API and should not be imported directly
    by consumers.

    Correct usage:
        from flext_ldif import FlextLdif
        ldif = FlextLdif()
        result = ldif.parse(data)

    Incorrect usage (bypasses single entry point):
        from flext_ldif.services.server import FlextLdifServer  # ❌ WRONG
        from flext_ldif.services import FlextLdifAcl  # ❌ WRONG

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.api import FlextLdif
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

__email__ = "dev@flext.com"

__all__ = [
    "FlextLdif",  # ✅ Facade (single entry point)
    "FlextLdifConfig",  # ✅ Configuration
    "FlextLdifConstants",  # ✅ Constants
    "FlextLdifMigrationPipeline",  # ✅ High-level service (OK to expose)
    "FlextLdifModels",  # ✅ Domain models
    "FlextLdifTypes",  # ✅ Type definitions
    "FlextLdifUtilities",  # ✅ Public helpers
]
