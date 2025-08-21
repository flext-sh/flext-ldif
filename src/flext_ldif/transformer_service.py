"""FLEXT-LDIF Transformer Service.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import override

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

    @override
    def execute(self) -> FlextResult[list[FlextLdifEntry]]:
        """Execute transformation - implements FlextDomainService contract."""
        return FlextResult[list[FlextLdifEntry]].ok([])

    def transform_entry(self, entry: FlextLdifEntry) -> FlextResult[FlextLdifEntry]:
        """Transform single LDIF entry."""
        # Base implementation returns entry as-is
        return FlextResult[FlextLdifEntry].ok(entry)

    def transform_entries(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Transform multiple LDIF entries."""
        transformed: list[FlextLdifEntry] = []
        for entry in entries:
            result = self.transform_entry(entry)
            transformed_entry = result.value if result.is_success else None
            if transformed_entry:
                transformed.append(transformed_entry)

        return FlextResult[list[FlextLdifEntry]].ok(transformed)

    def normalize_dns(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Normalize all DN values in entries."""
        # DN normalization is handled automatically by the domain model
        return FlextResult[list[FlextLdifEntry]].ok(entries)


__all__ = ["FlextLdifTransformerService"]

# Forward references resolved through API initialization - no fallback needed
FlextLdifTransformerService.model_rebuild(
    _types_namespace={"FlextLdifConfig": FlextLdifConfig},
)
