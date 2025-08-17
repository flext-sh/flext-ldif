import pytest

from flext_ldif import FlextLdifAPI

class TestAdvancedAPIFeatures:
    @pytest.fixture
    def api_with_config(self) -> FlextLdifAPI: ...
    def test_api_with_large_entries(self, api_with_config: FlextLdifAPI) -> None: ...
    def test_api_error_handling_edge_cases(
        self, api_with_config: FlextLdifAPI
    ) -> None: ...
    def test_api_filtering_capabilities(
        self, api_with_config: FlextLdifAPI
    ) -> None: ...
    def test_api_file_operations_advanced(
        self, api_with_config: FlextLdifAPI
    ) -> None: ...
    def test_api_performance_monitoring(
        self, api_with_config: FlextLdifAPI
    ) -> None: ...
