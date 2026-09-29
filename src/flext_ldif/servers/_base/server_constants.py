"""Base Constants for Server Servers."""

from __future__ import annotations

from ..._constants.servers import FlextLdifConstantsServers


class FlextLdifServersBaseConstants(FlextLdifConstantsServers.Base):
    """Base class for server constants."""


__all__: list[str] = ["FlextLdifServersBaseConstants"]
