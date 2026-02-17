"""Server-Specific Quirks for LDIF/LDAP Parsing."""

from __future__ import annotations

from flext_ldif.servers.ad import FlextLdifServersAd
from flext_ldif.servers.apache import FlextLdifServersApache
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.servers.ds389 import FlextLdifServersDs389
from flext_ldif.servers.novell import FlextLdifServersNovell
from flext_ldif.servers.oid import FlextLdifServersOid
from flext_ldif.servers.openldap import FlextLdifServersOpenldap
from flext_ldif.servers.openldap1 import FlextLdifServersOpenldap1
from flext_ldif.servers.oud import FlextLdifServersOud
from flext_ldif.servers.relaxed import FlextLdifServersRelaxed
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.servers.tivoli import FlextLdifServersTivoli

FlextLdifServer = FlextLdifServersBase

__all__ = [
    "FlextLdifServer",
    "FlextLdifServersAd",
    "FlextLdifServersApache",
    "FlextLdifServersBase",
    "FlextLdifServersDs389",
    "FlextLdifServersNovell",
    "FlextLdifServersOid",
    "FlextLdifServersOpenldap",
    "FlextLdifServersOpenldap1",
    "FlextLdifServersOud",
    "FlextLdifServersRelaxed",
    "FlextLdifServersRfc",
    "FlextLdifServersTivoli",
]
