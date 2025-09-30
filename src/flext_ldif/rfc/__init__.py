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

__all__ = [
    "RfcAclParser",
    "RfcEntryProcessor",
    "RfcLdifParser",
    "RfcSchemaParser",
]


def __getattr__(name: str) -> type:
    """Lazy import for RFC parsers."""
    if name == "RfcLdifParser":
        from flext_ldif.rfc.rfc_ldif_parser import RfcLdifParserService

        return RfcLdifParserService

    if name == "RfcSchemaParser":
        from flext_ldif.rfc.rfc_schema_parser import RfcSchemaParserService

        return RfcSchemaParserService

    if name == "RfcAclParser":
        from flext_ldif.rfc.rfc_acl_parser import RfcAclParserService

        return RfcAclParserService

    if name == "RfcEntryProcessor":
        from flext_ldif.rfc.rfc_entry_processor import RfcEntryProcessorService

        return RfcEntryProcessorService

    msg = f"module '{__name__}' has no attribute '{name}'"
    raise AttributeError(msg)
