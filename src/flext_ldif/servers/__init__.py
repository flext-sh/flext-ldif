"""Server-Specific Quirks for LDIF/LDAP Parsing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

This module contains server-specific quirks that extend RFC-compliant
LDIF/LDAP parsing with vendor-specific features.

Available server quirks:
- OID (Oracle Internet Directory) - Complete
- OUD (Oracle Unified Directory) - Complete
- OpenLDAP 2.x (cn=config) - Complete
- OpenLDAP 1.x (slapd.conf legacy) - Complete
- Relaxed Mode (lenient parsing for broken/non-compliant LDIF) - Complete
- Active Directory (stub)
- Apache Directory Server (stub)
- 389 Directory Server (stub)
- Novell eDirectory (stub)
- IBM Tivoli Directory Server (stub)
"""

from __future__ import annotations

from flext_ldif.servers.ad import FlextLdifServersAd
from flext_ldif.servers.apache import FlextLdifServersApache
from flext_ldif.servers.ds389 import FlextLdifServersDs389
from flext_ldif.servers.novell import FlextLdifServersNovell
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.openldap import FlextLdifServersOpenldap
from flext_ldif.servers.openldap1 import FlextLdifServersOpenldap1
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.servers.tivoli import FlextLdifServersTivoli
from flext_ldif.typings import FlextLdifTypes

__all__ = [
    "FlextLdifServersAd",
    "FlextLdifServersApache",
    "FlextLdifServersDs389",
    "FlextLdifServersNovell",
    "FlextLdifServersOid",
    "FlextLdifServersOpenldap",
    "FlextLdifServersOpenldap1",
    "FlextLdifServersOud",
    "FlextLdifServersRelaxed",
    "FlextLdifServersRelaxedAcl",
    "FlextLdifServersRelaxedEntry",
    "FlextLdifServersRelaxedSchema",
    "FlextLdifServersRfc",
    "FlextLdifServersTivoli",
    "FlextLdifTypes",
]
