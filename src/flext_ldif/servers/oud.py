"""Oracle Unified Directory (OUD) Quirks."""

from __future__ import annotations

from flext_core import FlextLogger

from flext_ldif.servers._oud import (
    FlextLdifServersOudAcl,
    FlextLdifServersOudConstants,
    FlextLdifServersOudEntry,
    FlextLdifServersOudSchema,
)
from flext_ldif.servers.rfc import FlextLdifServersRfc

logger = FlextLogger(__name__)


class FlextLdifServersOud(FlextLdifServersRfc):
    """Oracle Unified Directory (OUD) Server Implementation."""

    class Constants(FlextLdifServersOudConstants):
        """OUD server constants."""

    class Acl(FlextLdifServersOudAcl):
        """OUD ACL quirk."""

    class Schema(FlextLdifServersOudSchema):
        """OUD Schema quirk."""

    class Entry(FlextLdifServersOudEntry):
        """OUD Entry quirk."""


__all__ = ["FlextLdifServersOud"]
