"""RFC 4512 Compliant Server Quirks - Base LDAP Schema/ACL/Entry Implementation."""

from __future__ import annotations

from flext_ldif.servers._rfc.acl import FlextLdifServersRfcAcl
from flext_ldif.servers._rfc.constants import FlextLdifServersRfcConstants
from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry
from flext_ldif.servers._rfc.schema import FlextLdifServersRfcSchema
from flext_ldif.servers.base import FlextLdifServersBase


class FlextLdifServersRfc(FlextLdifServersBase):
    """RFC-Compliant LDAP Server Implementation - STRICT Baseline."""

    class Constants(FlextLdifServersRfcConstants):
        """RFC baseline constants (RFC 4512 compliant)."""

    class Acl(FlextLdifServersRfcAcl):
        """Aclbaseline constants (RFC 4512 compliant)."""

    class Schema(FlextLdifServersRfcSchema):
        """RFC baseline constants (RFC 4512 compliant)."""

    class Entry(FlextLdifServersRfcEntry):
        """RFC baseline constants (RFC 4512 compliant)."""


__all__: list[str] = ["FlextLdifServersRfc"]
