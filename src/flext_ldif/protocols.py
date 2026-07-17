"""LDIF protocol facade."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_cli import p
from flext_ldif._protocols.base import FlextLdifProtocolsBase
from flext_ldif._protocols.client import FlextLdifProtocolsClient
from flext_ldif._protocols.domain import FlextLdifProtocolsDomain
from flext_ldif._protocols.values import FlextLdifProtocolsValues


class FlextLdifProtocols(p):
    """Unified LDIF protocol facade."""

    @runtime_checkable
    class Ldif(
        FlextLdifProtocolsClient,
        FlextLdifProtocolsDomain,
        FlextLdifProtocolsValues,
        FlextLdifProtocolsBase,
        Protocol,
    ):
        """LDIF-specific structural protocol namespace."""

        # NOTE (multi-agent, mro-0ftd.3.7.2): declaration ownership is split
        # base <- domain <- client; this public facade only composes the DAG.


p = FlextLdifProtocols

__all__: list[str] = ["FlextLdifProtocols", "p"]
