from flext_core import FlextDomainService, FlextResult

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifEntry

__all__ = ["FlextLdifAnalyticsService"]

class FlextLdifAnalyticsService(FlextDomainService[dict[str, int]]):
    config: FlextLdifConfig
    def execute(self) -> FlextResult[dict[str, int]]: ...
    def analyze_entry_patterns(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[dict[str, int]]: ...
    def get_objectclass_distribution(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[dict[str, int]]: ...
    def get_dn_depth_analysis(
        self, entries: list[FlextLdifEntry]
    ) -> FlextResult[dict[str, int]]: ...
