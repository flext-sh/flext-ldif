"""Server-Specific Quirks for LDIF/LDAP Parsing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

This module contains server-specific quirks that extend RFC-compliant
LDIF/LDAP parsing with vendor-specific features.

Available server quirks:
- OID (Oracle Internet Directory)
- OUD (Oracle Unified Directory)
- OpenLDAP (future)
- Active Directory (future)
"""

from __future__ import annotations

from flext_ldif.quirks.servers.oid_quirks import OidAclQuirk, OidSchemaQuirk
from flext_ldif.quirks.servers.oud_quirks import (
    OudAclQuirk,
    OudEntryQuirk,
    OudSchemaQuirk,
)

__all__ = [
    "OidAclQuirk",
    "OidSchemaQuirk",
    "OudAclQuirk",
    "OudEntryQuirk",
    "OudSchemaQuirk",
]
