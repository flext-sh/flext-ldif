"""Tests for FlextLdifConfig - LDIF-specific configuration management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif.config import FlextLdifConfig


class TestFlextLdifConfig:
    """Test FlextLdifConfig functionality."""

    def setup_method(self) -> None:
        """Set up test environment."""
        FlextLdifConfig.reset_global_ldif_config()

    def teardown_method(self) -> None:
        """Clean up test environment."""
        FlextLdifConfig.reset_global_ldif_config()

    def test_config_initialization_default(self) -> None:
        """Test default configuration initialization."""
        result = FlextLdifConfig.initialize_global_ldif_config()
        assert result.is_success
        config = result.unwrap()

        # Check default values
        assert config.ldif_max_entries == 1000000
        assert config.ldif_strict_validation is True
        assert config.ldif_encoding == "utf-8"
        assert config.ldif_parallel_processing is False
        assert config.ldif_max_workers == 4

    def test_config_initialization_custom(self) -> None:
        """Test configuration initialization with custom parameters."""
        result = FlextLdifConfig.initialize_global_ldif_config(
            ldif_max_entries=50000,
            ldif_strict_validation=False,
            ldif_parallel_processing=True,
            ldif_max_workers=8,
        )
        assert result.is_success
        config = result.unwrap()

        # Check custom values
        assert config.ldif_max_entries == 50000
        assert config.ldif_strict_validation is False
        assert config.ldif_parallel_processing is True
        assert config.ldif_max_workers == 8

    def test_config_singleton_pattern(self) -> None:
        """Test singleton pattern implementation."""
        # Initialize first time
        result1 = FlextLdifConfig.initialize_global_ldif_config(ldif_max_entries=1000)
        assert result1.is_success
        config1 = result1.unwrap()

        # Initialize second time (should return same instance)
        result2 = FlextLdifConfig.initialize_global_ldif_config(ldif_max_entries=2000)
        assert result2.is_success
        config2 = result2.unwrap()

        # Should be the same instance
        assert config1 is config2
        assert config1.ldif_max_entries == 1000  # First value should be preserved

    def test_get_global_instance(self) -> None:
        """Test getting global configuration instance."""
        # Should fail if not initialized
        with pytest.raises(
            RuntimeError, match="Global instance is not a FlextLdifConfig instance",
        ):
            FlextLdifConfig.get_global_ldif_config()

        # Initialize and get instance
        FlextLdifConfig.initialize_global_ldif_config()
        config = FlextLdifConfig.get_global_ldif_config()
        assert isinstance(config, FlextLdifConfig)

    def test_configuration_dictionaries(self) -> None:
        """Test getting configuration dictionaries."""
        FlextLdifConfig.initialize_global_ldif_config()
        config = FlextLdifConfig.get_global_ldif_config()

        # Test processing config
        processing_config = config.get_ldif_processing_config()
        assert "max_entries" in processing_config
        assert "encoding" in processing_config
        assert "parallel_processing" in processing_config

        # Test validation config
        validation_config = config.get_ldif_validation_config()
        assert "strict_validation" in validation_config
        assert "allow_empty_values" in validation_config
        assert "validate_dn_format" in validation_config

        # Test analytics config
        analytics_config = config.get_ldif_analytics_config()
        assert "enable_analytics" in analytics_config
        assert "cache_size" in analytics_config

    def test_business_rules_validation(self) -> None:
        """Test business rules validation."""
        FlextLdifConfig.initialize_global_ldif_config()
        config = FlextLdifConfig.get_global_ldif_config()

        # Test with valid configuration
        result = config.validate_ldif_business_rules()
        assert result.is_success

        # Test with invalid configuration (too low max entries)
        # Create a new config with invalid values instead of modifying existing one
        FlextLdifConfig.reset_global_ldif_config()
        init_result = FlextLdifConfig.initialize_global_ldif_config(
            ldif_max_entries=500,
        )
        if init_result.is_success:
            config = init_result.unwrap()
            validation_result = config.validate_ldif_business_rules()
            assert validation_result.is_failure
            error_message = validation_result.error
            assert error_message is not None
            assert "Maximum entries too low" in error_message

    def test_configuration_overrides(self) -> None:
        """Test applying configuration overrides."""
        FlextLdifConfig.initialize_global_ldif_config()
        config = FlextLdifConfig.get_global_ldif_config()

        # Apply valid overrides
        overrides: dict[str, object] = {
            "ldif_max_entries": 200000,
            "ldif_chunk_size": 5000,
            "ldif_analytics_cache_size": 15000,
        }

        result = config.apply_ldif_overrides(overrides)
        assert result.is_success

        # Check values were updated
        assert config.ldif_max_entries == 200000
        assert config.ldif_chunk_size == 5000
        assert config.ldif_analytics_cache_size == 15000

    def test_configuration_overrides_invalid(self) -> None:
        """Test applying invalid configuration overrides."""
        FlextLdifConfig.initialize_global_ldif_config()
        config = FlextLdifConfig.get_global_ldif_config()

        # Apply invalid overrides (chunk size > max entries)
        overrides: dict[str, object] = {
            "ldif_chunk_size": 2000,
            "ldif_max_entries": 1000,
        }

        result = config.apply_ldif_overrides(overrides)
        assert result.is_failure
        error_message = result.error
        assert error_message is not None
        assert "Chunk size cannot exceed maximum entries" in error_message

    def test_encoding_validation(self) -> None:
        """Test encoding validation."""
        # Reset configuration first
        FlextLdifConfig.reset_global_ldif_config()

        # Test valid encoding
        result = FlextLdifConfig.initialize_global_ldif_config(ldif_encoding="utf-8")
        assert result.is_success

        # Reset configuration again
        FlextLdifConfig.reset_global_ldif_config()

        # Test invalid encoding
        result = FlextLdifConfig.initialize_global_ldif_config(
            ldif_encoding="invalid-encoding",
        )
        assert result.is_failure
        error_message = result.error
        assert error_message is not None
        assert "Unsupported encoding" in error_message

    def test_model_validator(self) -> None:
        """Test model validator for configuration consistency."""
        # Test valid configuration
        result = FlextLdifConfig.initialize_global_ldif_config(
            ldif_parallel_processing=True,
            ldif_max_workers=4,
            ldif_chunk_size=1000,
        )
        assert result.is_success

        # Reset config first to ensure clean state
        FlextLdifConfig.reset_global_ldif_config()

        # Test invalid configuration (parallel processing with 1 worker)
        # Need to reset config first to ensure clean state
        FlextLdifConfig.reset_global_ldif_config()
        result = FlextLdifConfig.initialize_global_ldif_config(
            ldif_parallel_processing=True,
            ldif_max_workers=1,
        )
        assert result.is_failure
        error_message = result.error
        assert error_message is not None
        assert "Parallel processing requires at least 2 workers" in error_message

        # Test invalid configuration (chunk size > max entries)
        result = FlextLdifConfig.initialize_global_ldif_config(
            ldif_chunk_size=5000,
            ldif_max_entries=1000,
        )
        assert result.is_failure
        error_message = result.error
        assert error_message is not None
        assert "Chunk size cannot exceed maximum entries" in error_message

    def test_flext_core_inheritance(self) -> None:
        """Test LDIF-specific configuration properties."""
        FlextLdifConfig.initialize_global_ldif_config()
        config = FlextLdifConfig.get_global_ldif_config()

        # Test LDIF-specific properties
        assert hasattr(config, "ldif_max_entries")
        assert hasattr(config, "ldif_encoding")
        assert hasattr(config, "ldif_parallel_processing")
        assert hasattr(config, "ldif_max_workers")

        # Test LDIF-specific methods
        processing_config = config.get_ldif_processing_config()
        assert isinstance(processing_config, dict)
        assert "max_entries" in processing_config
        assert "encoding" in processing_config

    def test_reset_global_config(self) -> None:
        """Test resetting global configuration."""
        # Initialize configuration
        FlextLdifConfig.initialize_global_ldif_config()
        config1 = FlextLdifConfig.get_global_ldif_config()

        # Reset configuration
        FlextLdifConfig.reset_global_ldif_config()

        # Initialize again
        FlextLdifConfig.initialize_global_ldif_config()
        config2 = FlextLdifConfig.get_global_ldif_config()

        # Should be different instances
        assert config1 is not config2

    def test_configuration_sealing(self) -> None:
        """Test configuration sealing behavior."""
        FlextLdifConfig.initialize_global_ldif_config()
        config = FlextLdifConfig.get_global_ldif_config()

        # Seal configuration
        config.seal()

        # Try to apply overrides (should fail)
        overrides: dict[str, object] = {"ldif_max_entries": 50000}
        result = config.apply_ldif_overrides(overrides)
        assert result.is_failure
        error_message = result.error
        assert error_message is not None
        assert "sealed configuration" in error_message

    def test_environment_variable_support(self) -> None:
        """Test configuration parameter support."""
        # Initialize configuration with specific parameters
        result = FlextLdifConfig.initialize_global_ldif_config(
            ldif_max_entries=75000, ldif_strict_validation=False,
        )
        assert result.is_success
        config = result.unwrap()

        # Check parameters were applied
        assert config.ldif_max_entries == 75000
        assert config.ldif_strict_validation is False
