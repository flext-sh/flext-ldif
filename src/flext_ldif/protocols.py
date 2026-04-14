"""LDIF protocol facade."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_cli import FlextCliProtocols
from flext_ldif import FlextLdifProtocolsBase, FlextLdifProtocolsDomain


class FlextLdifProtocols(FlextCliProtocols):
    """Unified LDIF protocol facade."""

    @runtime_checkable
    class Ldif(FlextLdifProtocolsDomain, FlextLdifProtocolsBase, Protocol):
        """LDIF-specific structural protocol namespace."""


p = FlextLdifProtocols

__all__: list[str] = ["FlextLdifProtocols", "p"]
