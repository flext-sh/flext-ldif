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

from flext_core import d, e, h, r

from flext_ldif.api import FlextLdif
from flext_ldif.base import FlextLdifServiceBase, s
from flext_ldif.constants import FlextLdifConstants, c
from flext_ldif.models import FlextLdifModels, m
from flext_ldif.protocols import FlextLdifProtocols, p
from flext_ldif.services.categorization import FlextLdifCategorization
from flext_ldif.services.conversion import FlextLdifConversion
from flext_ldif.services.detector import FlextLdifDetector
from flext_ldif.services.entries import FlextLdifEntries
from flext_ldif.services.filters import FlextLdifFilters
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.sorting import FlextLdifSorting
from flext_ldif.services.writer import FlextLdifWriter
from flext_ldif.settings import FlextLdifSettings
from flext_ldif.typings import FlextLdifTypes, t
from flext_ldif.utilities import FlextLdifUtilities, u

__email__ = "dev@flext.com"

__all__ = [
    # Classes (sorted alphabetically)
    "FlextLdif",
    "FlextLdifCategorization",
    "FlextLdifConstants",
    "FlextLdifConversion",
    "FlextLdifDetector",
    "FlextLdifEntries",
    "FlextLdifFilters",
    "FlextLdifMigrationPipeline",
    "FlextLdifModels",
    "FlextLdifParser",
    "FlextLdifProtocols",
    "FlextLdifServiceBase",
    "FlextLdifSettings",
    "FlextLdifSorting",
    "FlextLdifTypes",
    "FlextLdifUtilities",
    "FlextLdifWriter",
    # Convenience aliases (sorted)
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
]

# Pydantic v2 with `from __future__ import annotations` resolves forward references
# automatically - no model_rebuild() needed when using root namespace imports
