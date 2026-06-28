"""Oracle Internet Directory (OID) Servers."""

from __future__ import annotations

from flext_ldif import FlextLdifServersRfc
from flext_ldif.servers._oid.acl import FlextLdifServersOidAcl
from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants
from flext_ldif.servers._oid.entry import FlextLdifServersOidEntry
from flext_ldif.servers._oid.schema import FlextLdifServersOidSchema


class FlextLdifServersOid(FlextLdifServersRfc):
    """Oracle OID server servers - implements t.JsonValue."""

    class Constants(FlextLdifServersOidConstants):
        """OID server constants."""

    class Acl(FlextLdifServersOidAcl):
        """OID ACL server."""

    class Schema(FlextLdifServersOidSchema):
        """OID Schema server."""

    class Entry(FlextLdifServersOidEntry):
        """OID Entry server."""
