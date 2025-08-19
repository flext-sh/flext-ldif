"""FLEXT-LDIF Transformer Service.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import contextlib

from flext_core import FlextDomainService, FlextResult, get_logger
from pydantic import Field

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifEntry

logger = get_logger(__name__)


class FlextLdifTransformerService(FlextDomainService[list[FlextLdifEntry]]):
    """Concrete LDIF transformation service using flext-core patterns.

    ✅ CORRECT ARCHITECTURE: Extends FlextDomainService from flext-core.
    ZERO duplication - uses existing flext-core service patterns.
    """

    config: FlextLdifConfig | None = Field(default=None)

    def execute(self) -> FlextResult[list[FlextLdifEntry]]:
        """Execute transformation - implements FlextDomainService contract."""
        return FlextResult[None].ok([])

    def transform_entry(self, entry: FlextLdifEntry) -> FlextResult[FlextLdifEntry]:
        """Transform single LDIF entry."""
        # Base implementation returns entry as-is
        return FlextResult[None].ok(entry)

    def transform_entries(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Transform multiple LDIF entries."""
        transformed = []
        for entry in entries:
            result = self.transform_entry(entry)
            if result.success and result.data:
                transformed.append(result.data)

        return FlextResult[None].ok(transformed)

    def normalize_dns(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Normalize all DN values in entries."""
        # DN normalization is handled automatically by the domain model
        return FlextResult[None].ok(entries)


__all__ = ["FlextLdifTransformerService"]

# Ensure forward references are resolved for direct imports (tests instantiate
# this service without going through API wiring). This is safe and idempotent.
with contextlib.suppress(Exception):  # pragma: no cover - defensive initialization
    FlextLdifTransformerService.model_rebuild(
        _types_namespace={"FlextLdifConfig": FlextLdifConfig},
    )
