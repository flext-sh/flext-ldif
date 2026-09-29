"""FlextLdifConstantsServers - composer for the server-family part modules.

ENFORCE-079 owner surface for the ``servers/*`` family: the four part modules
carry the declarations; this composer re-exports them as nested names so
consumers keep the ``FlextLdifConstantsServers.<Family>`` path and the server
constants classes stay thin MRO inheritors.
"""

from __future__ import annotations

from .servers_base import FlextLdifConstantsServersBase
from .servers_oid import FlextLdifConstantsServersOid
from .servers_oud import FlextLdifConstantsServersOud
from .servers_rfc import FlextLdifConstantsServersRfc


class FlextLdifConstantsServers:
    """Server-family constants composed into the server constants classes."""

    Base = FlextLdifConstantsServersBase
    Rfc = FlextLdifConstantsServersRfc
    Oid = FlextLdifConstantsServersOid
    Oud = FlextLdifConstantsServersOud


__all__: list[str] = [
    "FlextLdifConstantsServers",
    "FlextLdifConstantsServersBase",
    "FlextLdifConstantsServersOid",
    "FlextLdifConstantsServersOud",
    "FlextLdifConstantsServersRfc",
]
