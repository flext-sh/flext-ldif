"""FLEXT LDIF Server Quirks - Unified server-specific handling.

This module provides unified server quirks management for schemas, ACLs, and entries
across different LDAP server implementations (OpenLDAP, 389 Directory Server,
Oracle OID/OUD, Active Directory).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.quirks.conversion_matrix import QuirksConversionMatrix
from flext_ldif.quirks.entry_quirks import FlextLdifEntryQuirks
from flext_ldif.quirks.manager import FlextLdifQuirksManager
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry

__all__ = [
    "FlextLdifEntryQuirks",
    "FlextLdifQuirksManager",
    "FlextLdifQuirksRegistry",
    "QuirksConversionMatrix",
]
