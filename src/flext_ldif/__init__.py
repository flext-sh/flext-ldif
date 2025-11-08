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
from flext_ldif.services.dn import FlextLdifDn as Dn
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from flext_ldif.services.validation import (
    FlextLdifValidation as Validation,
)
from flext_ldif.typings import FlextLdifTypes

# Note: model_rebuild removed - Pydantic v2 handles forward references automatically

__email__ = "dev@flext.com"

__all__ = [
    "Dn",
    "FlextLdif",
    "FlextLdifConfig",
    "FlextLdifConstants",
    "FlextLdifMigrationPipeline",
    "FlextLdifModels",
    "FlextLdifTypes",
    "Validation",
]
