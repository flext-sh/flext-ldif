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
- Active Directory (stub)
- Apache Directory Server (stub)
- 389 Directory Server (stub)
- Novell eDirectory (stub)
- IBM Tivoli Directory Server (stub)
"""

from __future__ import annotations

from flext_ldif.quirks.servers.ad_quirks import FlextLdifQuirksServersAd
from flext_ldif.quirks.servers.apache_quirks import FlextLdifQuirksServersApache
from flext_ldif.quirks.servers.ds389_quirks import FlextLdifQuirksServersDs389
from flext_ldif.quirks.servers.novell_quirks import FlextLdifQuirksServersNovell
from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid
from flext_ldif.quirks.servers.openldap1_quirks import FlextLdifQuirksServersOpenldap1
from flext_ldif.quirks.servers.openldap_quirks import FlextLdifQuirksServersOpenldap
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud
from flext_ldif.quirks.servers.tivoli_quirks import FlextLdifQuirksServersTivoli

__all__ = [
    "FlextLdifQuirksServersAd",
    "FlextLdifQuirksServersApache",
    "FlextLdifQuirksServersDs389",
    "FlextLdifQuirksServersNovell",
    "FlextLdifQuirksServersOid",
    "FlextLdifQuirksServersOpenldap",
    "FlextLdifQuirksServersOpenldap1",
    "FlextLdifQuirksServersOud",
    "FlextLdifQuirksServersTivoli",
]
