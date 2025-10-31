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
        from flext_ldif.services.registry import FlextLdifRegistry  # ❌ WRONG
        from flext_ldif.services import FlextLdifAclService  # ❌ WRONG

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import base64

# Python 3.13 Compatibility: base64.decodestring was removed in Python 3.9
# but ldif3 still uses it. Patch it here before any ldif3 imports.
if not hasattr(base64, "decodestring"):
    base64.decodestring = base64.decodebytes

from flext_ldif.api import FlextLdif
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.dn import FlextLdifDnService as DnService
from flext_ldif.services.filters import EntryFilterBuilder
from flext_ldif.services.validation import (
    FlextLdifValidationService as ValidationService,
)

__email__ = "dev@flext.com"

__all__ = [
    "DnService",
    "EntryFilterBuilder",
    "FlextLdif",
    "FlextLdifConfig",
    "FlextLdifConstants",
    "FlextLdifModels",
    "ValidationService",
]
