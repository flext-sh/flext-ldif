"""Oracle Internet Directory (OID) Quirks."""

from __future__ import annotations

from flext_ldif import (
    FlextLdifServersOidAcl,
    FlextLdifServersOidConstants,
    FlextLdifServersOidEntry,
    FlextLdifServersOidSchema,
    FlextLdifServersRfc,
)


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
