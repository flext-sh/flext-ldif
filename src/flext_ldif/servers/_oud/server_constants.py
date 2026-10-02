"""Oracle Unified Directory (OUD) Servers."""

from __future__ import annotations

from flext_ldif.servers.rfc import FlextLdifServersRfc

from ..._constants.servers import FlextLdifConstantsServers


class FlextLdifServersOudConstants(
    FlextLdifConstantsServers.Oud, FlextLdifServersRfc.Constants
):
    """Thin inheritor: declarations live in _constants parts."""
