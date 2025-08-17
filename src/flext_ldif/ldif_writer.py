"""FLEXT-LDIF Writer Service.

LDIF writing implementation using flext-core patterns.
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextDomainService, FlextResult, get_logger
from pydantic import Field

from flext_ldif.config import FlextLdifConfig  # noqa: TC001
from flext_ldif.constants import (
    DEFAULT_OUTPUT_ENCODING,
    FlextLdifCoreMessages,
)

from .models import FlextLdifEntry  # noqa: TC001

logger = get_logger(__name__)


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
          return FlextResult.fail(
              FlextLdifCoreMessages.WRITE_FAILED.format(error=str(e)),
          )

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
                  FlextLdifCoreMessages.CONTENT_GENERATION_FAILED.format(
                      count=len(entries),
                      error=content_result.error,
                  ),
              )

          path_obj = Path(file_path)
          # If parent is root and creation is requested, simulate permission error
          try:
              path_obj.parent.mkdir(parents=True, exist_ok=True)
          except PermissionError as e:
              return FlextResult.fail(
                  FlextLdifCoreMessages.FILE_WRITE_FAILED.format(error=str(e)),
              )
          path_obj.write_text(content_result.data or "", encoding=encoding)

          return FlextResult.ok(data=True)

      except Exception as e:
          return FlextResult.fail(
              FlextLdifCoreMessages.FILE_WRITE_FAILED.format(error=str(e)),
          )

    def write_entry(self, entry: FlextLdifEntry) -> FlextResult[str]:
      """Write single entry to LDIF string."""
      try:
          return FlextResult.ok(entry.to_ldif())
      except Exception as e:
          return FlextResult.fail(
              FlextLdifCoreMessages.WRITE_FAILED.format(error=str(e)),
          )


__all__ = ["FlextLdifWriterService"]

# Rebuild to resolve forward refs with explicit namespace in strict setups
# Note: model_rebuild() is called in api.py to avoid circular imports
