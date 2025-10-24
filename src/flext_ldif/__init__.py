"""FLEXT-LDIF - RFC-First LDIF Processing Library.

LDIF processing library with RFC 2849/4512 compliance and server-specific quirks
for the FLEXT ecosystem.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.acl_parser import FlextLdifAclParser
from flext_ldif.acl_service import FlextLdifAclService
from flext_ldif.api import FlextLdif
from flext_ldif.categorized_pipeline import FlextLdifCategorizedMigrationPipeline
from flext_ldif.client import FlextLdifClient
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.dn_service import FlextLdifDnService
from flext_ldif.entry_builder import FlextLdifEntryBuilder
from flext_ldif.filters import FlextLdifFilters
from flext_ldif.migration_pipeline import FlextLdifMigrationPipeline
from flext_ldif.models import FlextLdifModels
from flext_ldif.objectclass_manager import FlextLdifObjectClassManager
from flext_ldif.quirks.conversion_matrix import FlextLdifQuirksConversionMatrix
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.rfc_ldif_writer import FlextLdifRfcLdifWriter
from flext_ldif.schema_builder import FlextLdifSchemaBuilder
from flext_ldif.schema_validator import FlextLdifSchemaValidator
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.validation_service import FlextLdifValidationService

__email__ = "dev@flext.com"

__all__ = [
    "FlextLdif",
    "FlextLdifAclParser",
    "FlextLdifAclService",
    "FlextLdifCategorizedMigrationPipeline",
    "FlextLdifClient",
    "FlextLdifConfig",
    "FlextLdifConstants",
    "FlextLdifDnService",
    "FlextLdifEntryBuilder",
    "FlextLdifFilters",
    "FlextLdifMigrationPipeline",
    "FlextLdifModels",
    "FlextLdifObjectClassManager",
    "FlextLdifQuirksConversionMatrix",
    "FlextLdifQuirksRegistry",
    "FlextLdifRfcLdifWriter",
    "FlextLdifSchemaBuilder",
    "FlextLdifSchemaValidator",
    "FlextLdifTypes",
    "FlextLdifValidationService",
]
