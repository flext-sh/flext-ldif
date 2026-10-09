"""LDIF protocol facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

from flext_ldif._protocols import (
    FlextLdifProtocolsBase,
    FlextLdifProtocolsClient,
    FlextLdifProtocolsDomain,
    FlextLdifProtocolsLdap3,
    FlextLdifProtocolsValues,
)


class FlextLdifProtocols(FlextCliProtocols):
    """Unified LDIF protocol facade."""

    @runtime_checkable
    class Ldif(
        FlextLdifProtocolsDomain,
        FlextLdifProtocolsBase,
        FlextLdifProtocolsLdap3,
        FlextLdifProtocolsValues,
        FlextLdifProtocolsClient,
        Protocol,
    ):
        """LDIF-specific structural protocol namespace.

        ``LdifSettings``, ``Settings``, and ``ServerResolutionService`` have a
        single owner in ``FlextLdifProtocolsClient`` and are inherited unchanged.
        """


p = FlextLdifProtocols

__all__: list[str] = ["FlextLdifProtocols", "p"]
