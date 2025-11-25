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
from flext_ldif.base import FlextLdifServiceBase, LdifServiceBase
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.services.categorization import FlextLdifCategorization
from flext_ldif.services.conversion import FlextLdifConversion
from flext_ldif.services.detector import FlextLdifDetector
from flext_ldif.services.entry_manipulation import EntryManipulationServices
from flext_ldif.services.filters import FlextLdifFilters
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.sorting import FlextLdifSorting
from flext_ldif.services.writer import FlextLdifWriter
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities

__email__ = "dev@flext.com"

__all__ = [
    # ✅ Entry manipulation service (required by flext-ldap)
    "EntryManipulationServices",
    "FlextLdif",  # ✅ Facade (single entry point) - supports monadic methods and builder
    "FlextLdifCategorization",  # ✅ Categorization service (public API)
    "FlextLdifConfig",  # ✅ Configuration (namespace registered)
    "FlextLdifConstants",  # ✅ Constants
    "FlextLdifConversion",  # ✅ Conversion service (public API)
    "FlextLdifDetector",  # ✅ Detector service (required by flext-ldap)
    "FlextLdifFilters",  # ✅ Filters service (public API)
    "FlextLdifMigrationPipeline",  # ✅ High-level service (OK to expose)
    "FlextLdifModels",  # ✅ Domain models
    "FlextLdifParser",  # ✅ Parser service (required by flext-ldap)
    "FlextLdifProtocols",  # ✅ Protocols and type definitions
    "FlextLdifServiceBase",  # ✅ Base class for services (alias for LdifServiceBase)
    "FlextLdifSorting",  # ✅ Sorting service (public API)
    "FlextLdifTypes",  # ✅ Type definitions
    "FlextLdifUtilities",  # ✅ Public helpers
    "FlextLdifWriter",  # ✅ Writer service (public API)
    "LdifServiceBase",  # ✅ Base class for services with typed config
]
