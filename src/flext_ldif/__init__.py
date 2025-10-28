"""FLEXT-LDIF - RFC-First LDIF Processing Library.

LDIF processing library with RFC 2849/4512 compliance and server-specific quirks
for the FLEXT ecosystem.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.models import FlextLdifModels
from flext_ldif.api import FlextLdif
from flext_ldif.categorized_pipeline import FlextLdifCategorizedMigrationPipeline
from flext_ldif.client import FlextLdifClient
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.entry_builder import FlextLdifEntryBuilder
from flext_ldif.filters import EntryFilterBuilder, FlextLdifFilters
from flext_ldif.migration_pipeline import FlextLdifMigrationPipeline
from flext_ldif.objectclass_manager import FlextLdifObjectClassManager
from flext_ldif.quirks.conversion_matrix import FlextLdifQuirksConversionMatrix
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.rfc_ldif_writer import FlextLdifRfcLdifWriter
from flext_ldif.services import (
    FlextLdifAclParser,
    FlextLdifAclService,
    FlextLdifDnService,
    FlextLdifFileWriterService,
    FlextLdifSchemaBuilder,
    FlextLdifSchemaValidator,
    FlextLdifStatisticsService,
    FlextLdifValidationService,
)
from flext_ldif.typings import FlextLdifTypes

__email__ = "dev@flext.com"

__all__ = [
    "EntryFilterBuilder",
    "FlextLdif",
    "FlextLdifAclParser",
    "FlextLdifAclService",
    "FlextLdifCategorizedMigrationPipeline",
    "FlextLdifClient",
    "FlextLdifConfig",
    "FlextLdifConstants",
    "FlextLdifDnService",
    "FlextLdifEntryBuilder",
    "FlextLdifFileWriterService",
    "FlextLdifFilters",
    "FlextLdifMigrationPipeline",
    "FlextLdifModels",
    "FlextLdifObjectClassManager",
    "FlextLdifQuirksConversionMatrix",
    "FlextLdifQuirksRegistry",
    "FlextLdifRfcLdifWriter",
    "FlextLdifSchemaBuilder",
    "FlextLdifSchemaValidator",
    "FlextLdifStatisticsService",
    "FlextLdifTypes",
    "FlextLdifValidationService",
]
