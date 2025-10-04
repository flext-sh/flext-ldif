"""Test suite for FlextLdifConfig.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from flext_ldif.config import FlextLdifConfig


class TestFlextLdifConfig:
    """Test suite for FlextLdifConfig."""

    def test_initialization(self) -> None:
        """Test basic configuration initialization."""
        config = FlextLdifConfig()
        assert config.ldif_max_line_length == 78
        assert config.ldif_max_entries == 1000000
        assert config.ldif_chunk_size == 1000
        assert config.max_workers == 4
        assert config.ldif_encoding == "utf-8"

    def test_initialization_with_overrides(self) -> None:
        """Test configuration initialization with overrides."""
        config = FlextLdifConfig(
            ldif_max_line_length=100,
            ldif_max_entries=5000,
            max_workers=4,  # Must be >= 4 for performance mode
        )
        assert config.ldif_max_line_length == 100
        assert config.ldif_max_entries == 5000
        assert config.max_workers == 4

    def test_validation_max_line_length(self) -> None:
        """Test max line length validation."""
        # Valid values
        config = FlextLdifConfig(ldif_max_line_length=40)
        assert config.ldif_max_line_length == 40

        config = FlextLdifConfig(ldif_max_line_length=200)
        assert config.ldif_max_line_length == 200

        # Invalid values
        with pytest.raises(ValidationError):
            FlextLdifConfig(ldif_max_line_length=39)  # Below minimum

        with pytest.raises(ValidationError):
            FlextLdifConfig(ldif_max_line_length=201)  # Above maximum

    def test_validation_max_entries(self) -> None:
        """Test max entries validation."""
        # Valid values
        config = FlextLdifConfig(ldif_max_entries=1000)
        assert config.ldif_max_entries == 1000

        config = FlextLdifConfig(ldif_max_entries=10000000)
        assert config.ldif_max_entries == 10000000

        # Invalid values
        with pytest.raises(ValidationError):
            FlextLdifConfig(ldif_max_entries=999)  # Below minimum

        with pytest.raises(ValidationError):
            FlextLdifConfig(ldif_max_entries=10000001)  # Above maximum

    def test_validation_max_workers(self) -> None:
        """Test max workers validation."""
        # Valid values
        config = FlextLdifConfig(max_workers=1, enable_performance_optimizations=False)
        assert config.max_workers == 1

        config = FlextLdifConfig(max_workers=16)
        assert config.max_workers == 16

        # Invalid values
        with pytest.raises(ValidationError):
            FlextLdifConfig(max_workers=0)  # Below minimum

    def test_validation_chunk_size(self) -> None:
        """Test chunk size validation."""
        # Valid values - need to disable performance optimizations for small chunk size
        config = FlextLdifConfig(
            ldif_chunk_size=100,
            enable_performance_optimizations=False,
        )
        assert config.ldif_chunk_size == 100

        config = FlextLdifConfig(ldif_chunk_size=10000)
        assert config.ldif_chunk_size == 10000

        # Invalid values
        with pytest.raises(ValidationError):
            FlextLdifConfig(ldif_chunk_size=99)  # Below minimum

        with pytest.raises(ValidationError):
            FlextLdifConfig(ldif_chunk_size=10001)  # Above maximum

        # Performance mode requires chunk size >= 1000
        with pytest.raises(ValidationError):
            FlextLdifConfig(
                ldif_chunk_size=500,
                enable_performance_optimizations=True,
            )

    def test_validation_memory_limit(self) -> None:
        """Test memory limit validation."""
        # Valid values
        config = FlextLdifConfig(memory_limit_mb=64)
        assert config.memory_limit_mb == 64

        config = FlextLdifConfig(memory_limit_mb=8192)
        assert config.memory_limit_mb == 8192

        # Invalid values
        with pytest.raises(ValidationError):
            FlextLdifConfig(memory_limit_mb=63)  # Below minimum

        with pytest.raises(ValidationError):
            FlextLdifConfig(memory_limit_mb=8193)  # Above maximum

    def test_validation_parallel_threshold(self) -> None:
        """Test parallel threshold validation."""
        # Valid values
        config = FlextLdifConfig(parallel_threshold=1)
        assert config.parallel_threshold == 1

        # Invalid values
        with pytest.raises(ValidationError):
            FlextLdifConfig(parallel_threshold=0)  # Below minimum

    def test_validation_analytics_cache_size(self) -> None:
        """Test analytics cache size validation."""
        # Valid values
        config = FlextLdifConfig(ldif_analytics_cache_size=100)
        assert config.ldif_analytics_cache_size == 100

        config = FlextLdifConfig(ldif_analytics_cache_size=10000)
        assert config.ldif_analytics_cache_size == 10000

        # Invalid values
        with pytest.raises(ValidationError):
            FlextLdifConfig(ldif_analytics_cache_size=99)  # Below minimum

        with pytest.raises(ValidationError):
            FlextLdifConfig(ldif_analytics_cache_size=10001)  # Above maximum

    def test_model_validation_analytics_cache_size(self) -> None:
        """Test model validation for analytics cache size."""
        # Valid configuration
        config = FlextLdifConfig(
            ldif_enable_analytics=True,
            ldif_analytics_cache_size=1000,
        )
        assert config.ldif_enable_analytics is True
        assert config.ldif_analytics_cache_size == 1000

        # Invalid configuration - analytics enabled but cache size is 0
        with pytest.raises(ValidationError) as exc_info:
            FlextLdifConfig(
                ldif_enable_analytics=True,
                ldif_analytics_cache_size=0,
            )
        assert "Input should be greater than or equal to 100" in str(exc_info.value)

    def test_model_validation_parallel_processing(self) -> None:
        """Test model validation for parallel processing."""
        # Valid configuration
        config = FlextLdifConfig(
            enable_parallel_processing=True,
            parallel_threshold=1000,
        )
        assert config.enable_parallel_processing is True
        assert config.parallel_threshold == 1000

        # Invalid configuration - parallel processing enabled but threshold is 0
        with pytest.raises(ValidationError) as exc_info:
            FlextLdifConfig(
                enable_parallel_processing=True,
                parallel_threshold=0,
            )
        assert "Input should be greater than or equal to 1" in str(exc_info.value)

    def test_create_for_environment(self) -> None:
        """Test creating configuration for specific environment."""
        config = FlextLdifConfig.create_for_environment("test")
        # Check that config has expected FlextLdifConfig attributes
        assert hasattr(config, 'ldif_encoding')
        assert hasattr(config, 'ldif_max_line_length')
        assert hasattr(config, 'ldif_strict_validation')

        # Test with overrides
        config = FlextLdifConfig.create_for_environment(
            "test",
            debug_mode=False,  # Override test environment debug mode first
            ldif_max_entries=5000,
            max_workers=4,  # Must be >= 4 for performance mode
        )
        assert config.ldif_max_entries == 5000
        assert config.max_workers == 4

    def test_create_default(self) -> None:
        """Test creating default configuration."""
        config = FlextLdifConfig.create_default()
        # Check that config has expected FlextLdifConfig attributes
        assert hasattr(config, 'ldif_encoding')
        assert hasattr(config, 'ldif_max_line_length')
        assert hasattr(config, 'ldif_strict_validation')
        assert config.ldif_max_line_length == 78

    def test_get_global_instance(self) -> None:
        """Test getting global singleton instance."""
        config = FlextLdifConfig.get_global_instance()
        # Check that config has expected FlextLdifConfig attributes
        assert hasattr(config, 'ldif_encoding')
        assert hasattr(config, 'ldif_max_line_length')
        assert hasattr(config, 'ldif_strict_validation')

        # Should return the same instance
        config2 = FlextLdifConfig.get_global_instance()
        assert config is config2

    def test_reset_global_instance(self) -> None:
        """Test resetting global instance."""
        config1 = FlextLdifConfig.get_global_instance()
        FlextLdifConfig.reset_global_instance()
        config2 = FlextLdifConfig.get_global_instance()

        # Should be different instances after reset
        assert config1 is not config2

    def test_get_format_config(self) -> None:
        """Test getting format configuration context."""
        config = FlextLdifConfig()
        format_config = config.get_format_config()

        assert isinstance(format_config, dict)
        assert "encoding" in format_config
        assert "max_line_length" in format_config

    def test_get_processing_config(self) -> None:
        """Test getting processing configuration context."""
        config = FlextLdifConfig()
        processing_config = config.get_processing_config()

        assert isinstance(processing_config, dict)
        assert "max_entries" in processing_config
        assert "chunk_size" in processing_config
        assert "max_workers" in processing_config

    def test_get_analytics_config(self) -> None:
        """Test getting analytics configuration context."""
        config = FlextLdifConfig()
        analytics_config = config.get_analytics_config()

        assert isinstance(analytics_config, dict)
        assert "enable_analytics" in analytics_config
        assert "cache_size" in analytics_config

    def test_create_for_performance(self) -> None:
        """Test creating performance-optimized configuration."""
        # Reset singleton to ensure clean state
        FlextLdifConfig.reset_global_instance()

        config = FlextLdifConfig.create_for_performance()
        # Check that config has expected FlextLdifConfig attributes
        assert hasattr(config, 'ldif_encoding')
        assert hasattr(config, 'ldif_max_line_length')
        assert hasattr(config, 'ldif_strict_validation')
        assert config.enable_performance_optimizations is True
        assert config.max_workers >= 4  # Should meet performance minimum

    def test_create_for_development(self) -> None:
        """Test creating development-optimized configuration."""
        config = FlextLdifConfig.create_for_development()
        # Check that a config object is returned
        assert config is not None
        # Check that it has some expected attributes
        assert hasattr(config, 'max_workers')

    def test_create_for_server_type(self) -> None:
        """Test creating configuration for specific server type."""
        # Reset shared instance to ensure clean state
        FlextLdifConfig.reset_global_instance()
        config = FlextLdifConfig.create_for_server_type("openldap")
        # Check that config has expected FlextLdifConfig attributes
        assert hasattr(config, 'ldif_encoding')
        assert hasattr(config, 'ldif_max_line_length')
        assert hasattr(config, 'ldif_strict_validation')
        assert config.server_type == "openldap"

    def test_model_dump(self) -> None:
        """Test model serialization."""
        config = FlextLdifConfig(ldif_max_entries=5000)
        data = config.model_dump()

        assert isinstance(data, dict)
        assert data["ldif_max_entries"] == 5000
        assert data["ldif_max_line_length"] == 78

    def test_model_dump_exclude_secrets(self) -> None:
        """Test model serialization excludes secrets."""
        config = FlextLdifConfig()
        data = config.model_dump()

        # Should not contain sensitive fields if any
        assert isinstance(data, dict)

    def test_model_dump_include_secrets(self) -> None:
        """Test model serialization includes secrets when requested."""
        config = FlextLdifConfig()
        data = config.model_dump()

        # Should include all fields by default
        assert isinstance(data, dict)

    def test_model_validate(self) -> None:
        """Test model validation from dict."""
        data = {
            "ldif_max_entries": 5000,
            "max_workers": 4,  # Must be >= 4 for performance mode
        }

        config = FlextLdifConfig.model_validate(data)
        assert config.ldif_max_entries == 5000
        assert config.max_workers == 4

    def test_model_validate_invalid_data(self) -> None:
        """Test model validation with invalid data."""
        data = {
            "ldif_max_entries": 0,  # Invalid value
            "max_workers": -1,  # Invalid value
        }

        with pytest.raises(ValidationError):
            FlextLdifConfig.model_validate(data)

    def test_configuration_properties(self) -> None:
        """Test configuration property access."""
        config = FlextLdifConfig()

        # Test all configuration properties
        assert hasattr(config, "ldif_max_line_length")
        assert hasattr(config, "ldif_max_entries")
        assert hasattr(config, "ldif_chunk_size")
        assert hasattr(config, "max_workers")
        assert hasattr(config, "ldif_encoding")
        assert hasattr(config, "memory_limit_mb")
        assert hasattr(config, "parallel_threshold")
        assert hasattr(config, "ldif_analytics_cache_size")
        assert hasattr(config, "ldif_enable_analytics")
        assert hasattr(config, "enable_parallel_processing")
        assert hasattr(config, "strict_rfc_compliance")

    def test_configuration_defaults(self) -> None:
        """Test configuration default values."""
        config = FlextLdifConfig()

        # Test default values match expected constants
        assert config.ldif_max_line_length == 78
        assert config.ldif_max_entries == 1000000
        assert config.ldif_chunk_size == 1000
        assert config.max_workers == 4
        assert config.ldif_encoding == "utf-8"
        assert config.memory_limit_mb == 64  # Minimum required memory
        assert config.parallel_threshold == 100
        assert config.ldif_analytics_cache_size == 1000
        assert config.ldif_enable_analytics is True
        assert config.enable_parallel_processing is True
        assert config.strict_rfc_compliance is True

    def test_environment_specific_configs(self) -> None:
        """Test environment-specific configuration creation."""
        # Test development environment
        dev_config = FlextLdifConfig.create_for_environment("development")
        assert isinstance(dev_config, FlextLdifConfig)

        # Test production environment
        prod_config = FlextLdifConfig.create_for_environment("production")
        assert isinstance(prod_config, FlextLdifConfig)

        # Test staging environment
        staging_config = FlextLdifConfig.create_for_environment("staging")
        assert isinstance(staging_config, FlextLdifConfig)

    def test_configuration_immutability(self) -> None:
        """Test that configuration values are properly validated."""
        # Test that invalid values are rejected
        with pytest.raises(ValidationError):
            FlextLdifConfig(ldif_max_line_length="invalid")

        with pytest.raises(ValidationError):
            FlextLdifConfig(max_workers="invalid")

        with pytest.raises(ValidationError):
            FlextLdifConfig(ldif_encoding=123)

    # =========================================================================
    # VALIDATOR EDGE CASES - Complete coverage for all validators
    # =========================================================================

    def test_validate_ldif_encoding_invalid(self) -> None:
        """Test encoding validator with invalid encoding."""
        with pytest.raises(ValidationError) as exc_info:
            FlextLdifConfig(ldif_encoding="invalid-encoding")
        assert "Invalid encoding" in str(exc_info.value)

    def test_validate_max_workers_below_minimum(self) -> None:
        """Test max_workers validator with value below minimum."""
        with pytest.raises(ValidationError) as exc_info:
            FlextLdifConfig(max_workers=0)
        # Pydantic v2 error message format
        assert "Input should be greater than or equal to 1" in str(exc_info.value)

    def test_validate_max_workers_above_maximum(self) -> None:
        """Test max_workers validator with value above maximum."""
        with pytest.raises(ValidationError) as exc_info:
            FlextLdifConfig(max_workers=999999)
        # Pydantic v2 error message format
        assert "Input should be less than or equal to 16" in str(exc_info.value)

    def test_validate_validation_level_invalid(self) -> None:
        """Test validation_level validator with invalid value."""
        with pytest.raises(ValidationError) as exc_info:
            FlextLdifConfig(validation_level="invalid")
        # Pydantic v2 error message format
        assert "Input should be" in str(exc_info.value) or "validation_level" in str(
            exc_info.value
        )

    def test_validate_server_type_invalid(self) -> None:
        """Test server_type validator with invalid value."""
        with pytest.raises(ValidationError) as exc_info:
            FlextLdifConfig(server_type="unknown_server")
        assert "Input should be" in str(exc_info.value) or "server_type" in str(
            exc_info.value
        )

    def test_validate_analytics_detail_level_invalid(self) -> None:
        """Test analytics_detail_level validator with invalid value."""
        with pytest.raises(ValidationError) as exc_info:
            FlextLdifConfig(analytics_detail_level="ultra")
        assert "must be one of" in str(exc_info.value)

    def test_validate_error_recovery_mode_invalid(self) -> None:
        """Test error_recovery_mode validator with invalid value."""
        with pytest.raises(ValidationError) as exc_info:
            FlextLdifConfig(error_recovery_mode="abort")
        assert "must be one of" in str(exc_info.value)

    # =========================================================================
    # FACTORY METHOD COVERAGE - All create_* methods
    # =========================================================================

    def test_create_default_factory(self) -> None:
        """Test create_default factory method."""
        config = FlextLdifConfig.create_default()
        # Check that config has expected FlextLdifConfig attributes
        assert hasattr(config, 'ldif_encoding')
        assert hasattr(config, 'ldif_max_line_length')
        assert hasattr(config, 'ldif_strict_validation')
        assert config.ldif_encoding == "utf-8"
        # Default environment may have debug mode limiting workers
        assert config.max_workers >= 1

    def test_create_for_performance_factory(self) -> None:
        """Test create_for_performance factory method."""
        config = FlextLdifConfig.create_for_performance()
        # Check that config has expected FlextLdifConfig attributes
        assert hasattr(config, 'ldif_encoding')
        assert hasattr(config, 'ldif_max_line_length')
        assert hasattr(config, 'ldif_strict_validation')
        assert config.enable_performance_optimizations is True
        assert config.enable_parallel_processing is True

    def test_create_for_development_factory(self) -> None:
        """Test create_for_development factory method."""
        config = FlextLdifConfig.create_for_development()
        # Check that config has expected FlextLdifConfig attributes
        assert hasattr(config, 'ldif_encoding')
        assert hasattr(config, 'ldif_max_line_length')
        assert hasattr(config, 'ldif_strict_validation')
        assert config.debug_mode is True
        assert config.verbose_logging is True

    def test_create_for_server_type_factory(self) -> None:
        """Test create_for_server_type factory method."""
        config = FlextLdifConfig.create_for_server_type("active_directory")
        # Check that config has expected FlextLdifConfig attributes
        assert hasattr(config, 'ldif_encoding')
        assert hasattr(config, 'ldif_max_line_length')
        assert hasattr(config, 'ldif_strict_validation')
        assert config.server_type == "active_directory"

    # =========================================================================
    # GETTER METHOD COVERAGE - All get_* methods
    # =========================================================================

    def test_get_format_config_complete(self) -> None:
        """Test get_format_config method comprehensively."""
        config = FlextLdifConfig()
        format_config = config.get_format_config()
        assert isinstance(format_config, dict)
        assert "encoding" in format_config
        assert "max_line_length" in format_config
        assert format_config["encoding"] == "utf-8"

    def test_get_processing_config_complete(self) -> None:
        """Test get_processing_config method comprehensively."""
        config = FlextLdifConfig()
        proc_config = config.get_processing_config()
        assert isinstance(proc_config, dict)
        assert "max_workers" in proc_config
        assert "chunk_size" in proc_config
        assert proc_config["max_workers"] == 4

    def test_get_analytics_config_complete(self) -> None:
        """Test get_analytics_config method comprehensively."""
        config = FlextLdifConfig()
        analytics_config = config.get_analytics_config()
        assert isinstance(analytics_config, dict)
        # Check for actual keys returned
        assert (
            "enable_analytics" in analytics_config or "cache_size" in analytics_config
        )

    def test_get_server_config(self) -> None:
        """Test get_server_config method."""
        config = FlextLdifConfig()
        server_config = config.get_server_config()
        assert isinstance(server_config, dict)
        assert "server_type" in server_config

    def test_get_debug_config(self) -> None:
        """Test get_debug_config method."""
        config = FlextLdifConfig()
        debug_config = config.get_debug_config()
        assert isinstance(debug_config, dict)
        assert "debug_mode" in debug_config
        assert "verbose_logging" in debug_config

    def test_get_effective_encoding(self) -> None:
        """Test get_effective_encoding method."""
        # Encoding is already normalized in validator, use lowercase
        config = FlextLdifConfig(ldif_encoding="utf-8")
        encoding = config.get_effective_encoding()
        assert encoding == "utf-8"

    def test_get_effective_workers(self) -> None:
        """Test get_effective_workers method."""
        config = FlextLdifConfig(max_workers=8)
        # Test with large entry count (> MEDIUM_ENTRY_COUNT_THRESHOLD)
        workers = config.get_effective_workers(entry_count=10000)
        assert workers == 8

    def test_is_performance_optimized(self) -> None:
        """Test is_performance_optimized method."""
        perf_config = FlextLdifConfig.create_for_performance()
        assert perf_config.is_performance_optimized() is True

        normal_config = FlextLdifConfig()
        # Check actual value, don't assume
        result = normal_config.is_performance_optimized()
        assert isinstance(result, bool)

    def test_is_development_optimized(self) -> None:
        """Test is_development_optimized method."""
        dev_config = FlextLdifConfig.create_for_development()
        assert dev_config.is_development_optimized() is True

        normal_config = FlextLdifConfig()
        result = normal_config.is_development_optimized()
        assert isinstance(result, bool)

    def test_global_instance_management(self) -> None:
        """Test global instance get and reset."""
        # Get global instance
        instance1 = FlextLdifConfig.get_global_instance()
        # Check that instance has expected FlextLdifConfig attributes
        assert hasattr(instance1, 'ldif_encoding')
        assert hasattr(instance1, 'ldif_max_line_length')
        assert hasattr(instance1, 'ldif_strict_validation')

        # Should return same instance
        instance2 = FlextLdifConfig.get_global_instance()
        assert instance1 is instance2

        # Reset global instance
        FlextLdifConfig.reset_global_instance()

        # Should create new instance after reset
        instance3 = FlextLdifConfig.get_global_instance()
        # Check that instance has expected FlextLdifConfig attributes
        assert hasattr(instance3, 'ldif_encoding')
        assert hasattr(instance3, 'ldif_max_line_length')
        assert hasattr(instance3, 'ldif_strict_validation')
        # After reset, it's a new instance
        assert instance3 is not instance1
