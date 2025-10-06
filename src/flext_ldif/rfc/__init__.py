"""RFC-Compliant LDIF/LDAP Base Implementations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

This module provides RFC-compliant base implementations for LDIF and LDAP operations.
All implementations strictly follow IETF RFC standards:
- RFC 2849: LDIF format specification
- RFC 4512: LDAP Directory Information Models
- RFC 4516: LDAP Search Filters and ACLs
- RFC 4517: LDAP Syntaxes and Matching Rules

Server-specific extensions should be implemented as quirks, not in this base layer.
"""

from __future__ import annotations

from flext_ldif.rfc.rfc_ldif_parser import FlextLdifRfcLdifParser, RfcLdifParserService
from flext_ldif.rfc.rfc_ldif_writer import FlextLdifRfcLdifWriter, RfcLdifWriterService
from flext_ldif.rfc.rfc_schema_parser import FlextLdifRfcSchemaParser

__all__ = [
    "FlextLdifRfcLdifParser",
    "FlextLdifRfcLdifWriter",
    "FlextLdifRfcSchemaParser",
    "RfcLdifParserService",
    "RfcLdifWriterService",
]
