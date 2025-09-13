"""Tests to cover error handling paths in FlextLDIFServices.

These tests specifically target uncovered error handling paths to achieve 100% coverage.
"""

from __future__ import annotations

from unittest.mock import patch

from flext_ldif import FlextLDIFModels
from flext_ldif.services import FlextLDIFServices


class TestServicesErrorCoverage:
    """Test error handling paths in FlextLDIFServices."""

    def test_services_init_config_failure(self) -> None:
        """Test services initialization with invalid config."""
        # Test with invalid config that should still work
        invalid_config = FlextLDIFModels.Config()
        services = FlextLDIFServices(config=invalid_config)

        # Services should still initialize successfully
        assert services.parser is not None
        assert services.validator is not None
        assert services.writer is not None
        assert services.repository is not None
        assert services.analytics is not None

    def test_validate_ldif_syntax_empty_content(self) -> None:
        """Test validate_ldif_syntax with empty content."""
        services = FlextLDIFServices()
        parser = services.parser

        result = parser.validate_ldif_syntax("")
        assert result.is_failure
        assert "Empty LDIF content" in result.error

    def test_validate_ldif_syntax_no_lines(self) -> None:
        """Test validate_ldif_syntax with content that produces no lines."""
        services = FlextLDIFServices()
        parser = services.parser

        # Test with content that produces no lines after stripping
        result = parser.validate_ldif_syntax("   \n  \n  ")
        assert result.is_failure
        assert "Empty LDIF content" in result.error

    def test_validate_ldif_syntax_exception(self) -> None:
        """Test validate_ldif_syntax with exception during processing."""
        services = FlextLDIFServices()
        parser = services.parser

        # Mock the content to cause an exception during processing
        with patch.object(parser, "_format_handler") as mock_handler:
            mock_handler.parse_ldif.side_effect = Exception("Test exception")
            result = parser.parse_content("test content")
            assert result.is_failure
            assert "Parse failed" in result.error
