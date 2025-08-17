from pathlib import Path

from flext_core import FlextDomainService, FlextResult

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifEntry

__all__ = ["FlextLdifParserService"]

class FlextLdifParserService(FlextDomainService[list[FlextLdifEntry]]):
    config: FlextLdifConfig | None
    def execute(self) -> FlextResult[list[FlextLdifEntry]]: ...
    def parse(self, content: str | object) -> FlextResult[list[FlextLdifEntry]]: ...
    def parse_ldif_file(
        self, file_path: str | Path, encoding: str = ...
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def parse_entries_from_string(
        self, ldif_string: str
    ) -> FlextResult[list[FlextLdifEntry]]: ...
