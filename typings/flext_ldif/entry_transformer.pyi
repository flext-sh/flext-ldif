from flext_core import FlextDomainService, FlextResult

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifEntry

__all__ = ["FlextLdifTransformerService"]

class FlextLdifTransformerService(FlextDomainService[list[FlextLdifEntry]]):
    config: FlextLdifConfig | None
    def execute(self) -> FlextResult[list[FlextLdifEntry]]: ...
    def transform_entry(self, entry: FlextLdifEntry) -> FlextResult[FlextLdifEntry]: ...
    def transform_entries(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def normalize_dns(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[list[FlextLdifEntry]]: ...
