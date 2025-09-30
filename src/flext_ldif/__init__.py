"""FLEXT-LDIF - RFC-First LDIF Processing Library.

This library provides RFC-compliant LDIF processing with composable server-specific quirks.

Architecture:
- RFC Layer: Pure RFC 2849/4512 parsers and writers
- Quirks System: Server-specific extensions (OID, OUD, OpenLDAP, etc.)
- Migration Pipeline: Generic LDIF migration between any servers
- Models: Pydantic data models for type safety

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# Core Infrastructure
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants

# OID-Specific Parser (Uses RFC + quirks)
from flext_ldif.entry.oid_ldif_parser import OidLdifParserService
from flext_ldif.exceptions import FlextLdifExceptions

# Migration Pipeline (Generic server-agnostic migration)
from flext_ldif.migration_pipeline import LdifMigrationPipelineService
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols

# Quirks System (Server-specific extensions)
from flext_ldif.quirks.registry import QuirkRegistryService, get_global_quirk_registry
from flext_ldif.quirks.servers.oid_quirks import OidAclQuirk, OidSchemaQuirk
from flext_ldif.quirks.servers.oud_quirks import (
    OudAclQuirk,
    OudEntryQuirk,
    OudSchemaQuirk,
)

# RFC Layer (Core LDIF/Schema parsers and writers)
from flext_ldif.rfc.rfc_ldif_parser import RfcLdifParserService
from flext_ldif.rfc.rfc_ldif_writer import RfcLdifWriterService
from flext_ldif.rfc.rfc_schema_parser import RfcSchemaParserService
from flext_ldif.typings import FlextLdifTypes

__all__ = [
    # Core Infrastructure
    "FlextLdifConfig",
    "FlextLdifConstants",
    "FlextLdifExceptions",
    "FlextLdifModels",
    "FlextLdifProtocols",
    "FlextLdifTypes",
    # Migration Pipeline
    "LdifMigrationPipelineService",
    # Quirks System
    "OidAclQuirk",
    "OidSchemaQuirk",
    "OudAclQuirk",
    "OudEntryQuirk",
    "OudSchemaQuirk",
    "QuirkRegistryService",
    "get_global_quirk_registry",
    # OID Parser
    "OidLdifParserService",
    # RFC Layer
    "RfcLdifParserService",
    "RfcLdifWriterService",
    "RfcSchemaParserService",
]

# Version information
__version__ = "0.9.0"
__author__ = "FLEXT Development Team"
__email__ = "dev@flext.com"
__license__ = "MIT"
