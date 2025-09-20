"""FLEXT LDIF Services - Compatibility layer for legacy service pattern.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextDomainService, FlextResult

from .api import FlextLdifAPI
from .config import FlextLdifConfig


class FlextLdifServices(FlextDomainService[dict[str, object]]):
    """Compatibility services container for legacy test patterns.

    Provides access to individual service components through a unified API
    while maintaining compatibility with existing test infrastructure.
    Uses FlextLdifAPI internally and exposes service-like interfaces.
    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize services container with API backend."""
        super().__init__()
        self._api = FlextLdifAPI(config=config)

    @property
    def parser(self) -> FlextLdifAPI:
        """Get parser service (delegates to API)."""
        return self._api

    @property
    def writer(self) -> FlextLdifAPI:
        """Get writer service (delegates to API)."""
        return self._api

    @property
    def validator(self) -> FlextLdifAPI:
        """Get validator service (delegates to API)."""
        return self._api

    @property
    def repository(self) -> FlextLdifAPI:
        """Get repository service (delegates to API)."""
        return self._api

    @property
    def analytics(self) -> FlextLdifAPI:
        """Get analytics service (delegates to API)."""
        return self._api

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute health check - required by FlextDomainService."""
        return self._api.health_check()


__all__ = ["FlextLdifServices"]
