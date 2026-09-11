"""Oracle Unified Directory (OUD) Servers."""

from __future__ import annotations

from flext_ldif.servers.rfc import FlextLdifServersRfc

from ._oud.acl import FlextLdifServersOudAcl
from ._oud.constants import FlextLdifServersOudConstants
from ._oud.entry import FlextLdifServersOudEntry
from ._oud.schema import FlextLdifServersOudSchema


class FlextLdifServersOud(FlextLdifServersRfc):
    """Oracle Unified Directory (OUD) Server Implementation."""

    class Constants(FlextLdifServersOudConstants):
        """OUD server constants."""

    class Acl(FlextLdifServersOudAcl):
        """OUD ACL server."""

    class Schema(FlextLdifServersOudSchema):
        """OUD Schema server."""

    class Entry(FlextLdifServersOudEntry):
        """OUD Entry server."""


__all__: list[str] = ["FlextLdifServersOud"]
