"""FLEXT-LDIF Services - Business Logic Layer.

This package contains all service classes for FLEXT-LDIF operations:
- Parser: LDIF file parsing with auto-detection and relaxed mode
- Validation: RFC 2849/4512 compliant validation
- DN: Distinguished Name operations
- ACL: Access Control List processing
- Schema: Schema building and validation
- File Writer: LDIF file writing operations
- Statistics: Pipeline statistics and metrics generation
- Server Detection: LDAP server type detection

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.services.acl import FlextLdifAclParser, FlextLdifAclService
from flext_ldif.services.dn import FlextLdifDnService
from flext_ldif.services.entry_builder import FlextLdifEntryBuilder
from flext_ldif.services.entry_quirks import FlextLdifEntrys
from flext_ldif.services.manager import FlextLdifQuirksManager
from flext_ldif.services.parser import FlextLdifParserService
from flext_ldif.services.registry import FlextLdifRegistry
from flext_ldif.services.schema import FlextLdifSchemaBuilder, FlextLdifSchemaValidator
from flext_ldif.services.statistics import FlextLdifStatisticsService
from flext_ldif.services.validation import FlextLdifValidationService
from flext_ldif.services.writer import FlextLdifWriterService

__all__ = [
    "FlextLdifAclParser",
    "FlextLdifAclService",
    "FlextLdifDnService",
    "FlextLdifEntryBuilder",
    "FlextLdifEntrys",
    "FlextLdifParserService",
    "FlextLdifQuirksManager",
    "FlextLdifRegistry",
    "FlextLdifSchemaBuilder",
    "FlextLdifSchemaValidator",
    "FlextLdifStatisticsService",
    "FlextLdifValidationService",
    "FlextLdifWriterService",
]
