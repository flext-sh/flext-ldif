"""RFC 4512 Compliant Server Servers - Base LDAP Schema/ACL/Entry Implementation."""

from __future__ import annotations

from ..._constants.servers import FlextLdifConstantsServers
from .._base.server_constants import FlextLdifServersBaseConstants


class FlextLdifServersRfcConstants(
    FlextLdifConstantsServers.Rfc, FlextLdifServersBaseConstants
):
    """Thin inheritor: declarations live in _constants parts."""
