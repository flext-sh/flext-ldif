"""Unit tests for flext_ldif.api module."""

from unittest.mock import MagicMock, patch

from flext_core import FlextResult
from flext_ldif import FlextLdifAPI, FlextLdifConfig, FlextLdifTypes


class TestFlextLdifAPI:
    """Test cases for FlextLdifAPI class."""

    def test_init_default_config(self) -> None:
        """Test initialization with default config."""
        api = FlextLdifAPI()
        assert api._config is not None
        assert isinstance(api._config, FlextLdifConfig)

    def test_init_custom_config(self) -> None:
        """Test initialization with custom config."""
        config = FlextLdifConfig()
        api = FlextLdifAPI(config=config)
        assert api._config is config

    @patch("flext_ldif.api.FlextLdifProcessor")
    def test_init_processor_failure(self, mock_processor: MagicMock) -> None:
        """Test processor initialization failure."""
        mock_processor.side_effect = Exception("Init failed")
        api = FlextLdifAPI()
        result = api._processor_result
        assert result.is_failure
        assert "Failed to initialize LDIF processor" in result.error

    def test_execute_calls_health_check(self) -> None:
        """Test execute method calls health_check."""
        api = FlextLdifAPI()
        with patch.object(api, "health_check") as mock_health:
            mock_health.return_value = FlextResult[FlextLdifTypes.HealthStatusDict].ok({"status": "ok"})
            result = api.execute()
            mock_health.assert_called_once()
            assert result.is_success

    # Add more tests for other methods as needed to cover uncovered lines
