"""Oracle Internet Directory (OID) Quirks."""

from __future__ import annotations

from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry
from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOid(FlextLdifServersRfc):
    """Oracle OID server quirks - implements t.RecursiveContainer."""

    class Constants(FlextLdifServersOidConstants):
        """OID server constants."""

    class Acl(FlextLdifServersOidAcl):
        """OID ACL quirk."""

    class Schema(FlextLdifServersOidSchema):
        """OID Schema quirk."""

    class Entry(FlextLdifServersOidEntry):
        """OID Entry quirk."""
