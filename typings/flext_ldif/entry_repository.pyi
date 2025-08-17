from flext_core import FlextDomainService, FlextResult

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifEntry

__all__ = ["FlextLdifRepositoryService"]

class FlextLdifRepositoryService(FlextDomainService[dict[str, int]]):
    config: FlextLdifConfig | None
    def execute(self) -> FlextResult[dict[str, int]]: ...
    def find_by_dn(
        self, entries: list[FlextLdifEntry], dn: str
    ) -> FlextResult[FlextLdifEntry | None]: ...
    def filter_by_objectclass(
        self, entries: list[FlextLdifEntry], objectclass: str
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def filter_by_attribute(
        self, entries: list[FlextLdifEntry], attribute: str, value: str
    ) -> FlextResult[list[FlextLdifEntry]]: ...
    def get_statistics(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[dict[str, int]]: ...
