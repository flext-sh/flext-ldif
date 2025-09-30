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

__all__ = [
    "OidAclQuirk",
    "OidSchemaQuirk",
]


def __getattr__(name: str) -> type:
    """Lazy import for server quirks."""
    if name == "OidSchemaQuirk":
        from flext_ldif.quirks.servers.oid_quirks import OidSchemaQuirk

        return OidSchemaQuirk

    if name == "OidAclQuirk":
        from flext_ldif.quirks.servers.oid_quirks import OidAclQuirk

        return OidAclQuirk

    msg = f"module '{__name__}' has no attribute '{name}'"
    raise AttributeError(msg)
