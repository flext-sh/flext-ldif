"""LDIF protocol facade."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_core import FlextProtocols
from flext_ldif._protocols.base import FlextLdifProtocolsBase
from flext_ldif._protocols.domain import FlextLdifProtocolsDomain


class FlextLdifProtocols(FlextProtocols):
    """Unified LDIF protocol facade."""

    @runtime_checkable
    class Ldif(FlextLdifProtocolsDomain, FlextLdifProtocolsBase, Protocol):
        """LDIF-specific structural protocol namespace."""


p = FlextLdifProtocols

__all__ = ["FlextLdifProtocols", "p"]
