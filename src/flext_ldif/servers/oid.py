"""Oracle Internet Directory (OID) Servers."""

from __future__ import annotations

from flext_ldif import (
    FlextLdifServersOidAcl,
    FlextLdifServersOidConstants,
    FlextLdifServersOidEntry,
    FlextLdifServersOidSchema,
    FlextLdifServersRfc,
)


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
