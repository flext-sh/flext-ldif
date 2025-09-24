"""FLEXT LDIF Server Quirks - Unified server-specific handling.

This module provides unified server quirks management for schemas, ACLs, and entries
across different LDAP server implementations (OpenLDAP, 389 Directory Server,
Oracle OID/OUD, Active Directory).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from flext_ldif.quirks import constants
from flext_ldif.quirks.adapter import FlextLdifQuirksAdapter
from flext_ldif.quirks.entry_quirks import FlextLdifEntryQuirks
from flext_ldif.quirks.manager import FlextLdifQuirksManager

__all__ = [
    "FlextLdifEntryQuirks",
    "FlextLdifQuirksAdapter",
    "FlextLdifQuirksManager",
    "constants",
]
