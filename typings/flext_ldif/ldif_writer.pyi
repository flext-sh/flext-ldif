from pathlib import Path

from flext_core import FlextDomainService, FlextResult

from flext_ldif.config import FlextLdifConfig

from .models import FlextLdifEntry

__all__ = ["FlextLdifWriterService"]

class FlextLdifWriterService(FlextDomainService[str]):
    config: FlextLdifConfig | None
    def execute(self) -> FlextResult[str]: ...
    def write(self, entries: list[FlextLdifEntry]) -> FlextResult[str]: ...
    def write_file(
        self, entries: list[FlextLdifEntry], file_path: str | Path, encoding: str = ...
    ) -> FlextResult[bool]: ...
    def write_entry(self, entry: FlextLdifEntry) -> FlextResult[str]: ...
