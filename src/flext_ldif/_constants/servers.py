"""FlextLdifConstantsServers - composer for the server-family part modules.

ENFORCE-079 owner surface for the ``servers/*`` family: the part modules
carry the declarations; this composer re-exports them as nested names so
consumers keep the ``FlextLdifConstantsServers.<Family>`` path and the server
constants classes stay thin MRO inheritors.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_ldif._constants.servers_base import FlextLdifConstantsServersBase
from flext_ldif._constants.servers_oid import FlextLdifConstantsServersOid
from flext_ldif._constants.servers_oud import FlextLdifConstantsServersOud
from flext_ldif._constants.servers_relaxed import FlextLdifConstantsServersRelaxed
from flext_ldif._constants.servers_rfc import FlextLdifConstantsServersRfc


class FlextLdifConstantsServers:
    """Server-family constants composed into the server constants classes."""

    Base: ClassVar[type[FlextLdifConstantsServersBase]] = FlextLdifConstantsServersBase
    Rfc: ClassVar[type[FlextLdifConstantsServersRfc]] = FlextLdifConstantsServersRfc
    Oid: ClassVar[type[FlextLdifConstantsServersOid]] = FlextLdifConstantsServersOid
    Oud: ClassVar[type[FlextLdifConstantsServersOud]] = FlextLdifConstantsServersOud
    Relaxed: ClassVar[type[FlextLdifConstantsServersRelaxed]] = (
        FlextLdifConstantsServersRelaxed
    )


__all__: list[str] = [
    "FlextLdifConstantsServers",
    "FlextLdifConstantsServersBase",
    "FlextLdifConstantsServersOid",
    "FlextLdifConstantsServersOud",
    "FlextLdifConstantsServersRelaxed",
    "FlextLdifConstantsServersRfc",
]
