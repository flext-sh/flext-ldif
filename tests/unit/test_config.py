"""Unit tests for FLEXT-LDIF configuration."""

from __future__ import annotations

from flext_ldif import FlextLdifConfig


class TestFlextLdifConfig:
    """Test configuration functionality."""

    def test_config_initialization_default(self) -> None:
        """Test config initialization with default values."""
        config = FlextLdifConfig()
        assert config is not None

    def test_config_initialization_with_params(self) -> None:
        """Test config initialization with custom parameters."""
        config = FlextLdifConfig(
            max_entries=1000,
            strict_validation=True,
            sort_attributes=False,
        )
        assert config.max_entries == 1000
        assert config.strict_validation is True
        assert config.sort_attributes is False

    def test_config_validation(self) -> None:
        """Test config validation."""
        # Test valid config
        config = FlextLdifConfig(max_entries=100)
        assert config.max_entries == 100

        # Test boundary values are accepted
        config_zero = FlextLdifConfig(max_entries=1)
        assert config_zero.max_entries == 1

        config_large = FlextLdifConfig(max_entries=100000)
        assert config_large.max_entries == 100000

    def test_config_properties(self) -> None:
        """Test config properties are accessible."""
        config = FlextLdifConfig()

        # Test that properties exist and have reasonable defaults
        assert hasattr(config, "max_entries")
        assert hasattr(config, "strict_validation")
        assert hasattr(config, "sort_attributes")

        assert isinstance(config.max_entries, int)
        assert isinstance(config.strict_validation, bool)
        assert isinstance(config.sort_attributes, bool)
