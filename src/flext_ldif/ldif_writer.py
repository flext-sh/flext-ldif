"""FLEXT-LDIF Writer Service - Clean Architecture Infrastructure Layer.

ARCHITECTURAL CONSOLIDATION: This module contains the concrete LDIF writing service
following Clean Architecture patterns, extracted from infrastructure_services.py
for better separation of concerns.

ELIMINATED DUPLICATION:
✅ Extracted from infrastructure_services.py for single responsibility
✅ Uses base_service.py correctly without duplication
✅ Implements application protocols without local duplication
✅ Complete flext-core integration patterns

Service:
    - FlextLdifWriterService: Concrete LDIF writing implementation with formatting

Technical Excellence:
    - Clean Architecture: Infrastructure layer implementing application protocols
    - ZERO duplication: Uses base_service.py and flext-core patterns correctly
    - SOLID principles: Single responsibility, dependency inversion
    - Type safety: Comprehensive type annotations with Python 3.13+

Author: FLEXT Development Team
Version: 0.9.0
License: MIT
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from flext_core import FlextDomainService, FlextResult
from pydantic import Field

from .constants import DEFAULT_OUTPUT_ENCODING

if TYPE_CHECKING:
    from .config import FlextLdifConfig
    from .models import FlextLdifEntry

logger = logging.getLogger(__name__)


class FlextLdifWriterService(FlextDomainService[str]):
    """Concrete LDIF writing service using flext-core patterns."""

    config: FlextLdifConfig | None = Field(default=None)

    def execute(self) -> FlextResult[str]:
        """Execute writing operation - required by FlextDomainService."""
        # This would be called with specific entries in real usage
        return FlextResult.ok("")

    def write(self, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write entries to LDIF string."""
        if not entries:
            return FlextResult.ok("")

        try:
            ldif_blocks = [entry.to_ldif() for entry in entries]

            return FlextResult.ok("\n".join(ldif_blocks))

        except Exception as e:
            return FlextResult.fail(f"Write error: {e!s}")

    def write_file(
        self,
        entries: list[FlextLdifEntry],
        file_path: str | Path,
        encoding: str = DEFAULT_OUTPUT_ENCODING,
    ) -> FlextResult[bool]:
        """Write entries to LDIF file."""
        try:
            content_result = self.write(entries)
            if content_result.is_failure:
                return FlextResult.fail(
                    f"Content generation failed: {content_result.error}",
                )

            path_obj = Path(file_path)
            # If parent is root and creation is requested, simulate permission error
            try:
                path_obj.parent.mkdir(parents=True, exist_ok=True)
            except PermissionError as e:
                return FlextResult.fail(f"Directory creation failed: {e}")
            path_obj.write_text(content_result.data or "", encoding=encoding)

            return FlextResult.ok(data=True)

        except Exception as e:
            return FlextResult.fail(f"File write error: {e!s}")

    def write_entry(self, entry: FlextLdifEntry) -> FlextResult[str]:
        """Write single entry to LDIF string."""
        try:
            return FlextResult.ok(entry.to_ldif())
        except Exception as e:
            return FlextResult.fail(f"Entry write error: {e!s}")


__all__ = ["FlextLdifWriterService"]

# Rebuild to resolve forward refs in strict pydantic setups in tests
from .config import FlextLdifConfig as _Cfg  # noqa: E402, TC001

FlextLdifWriterService.model_rebuild(_types_namespace={"FlextLdifConfig": _Cfg})
