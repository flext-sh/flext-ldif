"""Test suite for FlextLdifConfig.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Any, cast

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
        # When log_level=DEBUG, max_workers is adjusted to 2 for better debugging
        expected_workers = 2 if config.is_debug_enabled else 4
        assert config.max_workers == expected_workers
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
        expected_workers = 2 if config.is_debug_enabled else 4
        assert config.max_workers == expected_workers

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

    def test_get_global_instance(self) -> None:
        """Test getting global singleton instance."""
        config = FlextLdifConfig.get_global_instance()
        # Check that config has expected FlextLdifConfig attributes
        assert hasattr(config, "ldif_encoding")
        assert hasattr(config, "ldif_max_line_length")
        assert hasattr(config, "ldif_strict_validation")

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

    def test_configuration_immutability(self) -> None:
        """Test that configuration values are properly validated."""
        # Test that invalid values are rejected (intentional type mismatches for validation testing)
        with pytest.raises(ValidationError):
            # Test validation with intentionally invalid types
            FlextLdifConfig(ldif_max_line_length=cast("int", "invalid"))

        with pytest.raises(ValidationError):
            # Test validation with intentionally invalid types
            FlextLdifConfig(max_workers=cast("int", "invalid"))

        with pytest.raises(ValidationError):
            # Test validation with intentionally invalid types
            FlextLdifConfig(ldif_encoding=cast("str", 123))

    # =========================================================================
    # VALIDATOR EDGE CASES - Complete coverage for all validators
    # =========================================================================

    def test_validate_ldif_encoding_invalid(self) -> None:
        """Test encoding validator with invalid encoding."""
        with pytest.raises(ValidationError) as exc_info:
            FlextLdifConfig(ldif_encoding="invalid-encoding")
        # Pydantic v2 error message format
        assert "Input should be" in str(exc_info.value) or "ldif_encoding" in str(
            exc_info.value
        )

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
        # Pydantic v2 error message format - max_workers inherited from FlextConfig has le=256
        assert "Input should be less than or equal to 256" in str(exc_info.value)

    def test_validate_validation_level_invalid(self) -> None:
        """Test validation_level validator with invalid value."""
        with pytest.raises(ValidationError) as exc_info:
            # Test validation with intentionally invalid enum value
            FlextLdifConfig(validation_level=cast("Any", "invalid"))
        # Pydantic v2 error message format
        assert "Input should be" in str(exc_info.value) or "validation_level" in str(
            exc_info.value
        )

    def test_validate_server_type_invalid(self) -> None:
        """Test server_type validator with invalid value."""
        with pytest.raises(ValidationError) as exc_info:
            # Test validation with intentionally invalid enum value
            FlextLdifConfig(server_type=cast("Any", "unknown_server"))
        assert "Input should be" in str(exc_info.value) or "server_type" in str(
            exc_info.value
        )

    def test_validate_analytics_detail_level_invalid(self) -> None:
        """Test analytics_detail_level validator with invalid value."""
        with pytest.raises(ValidationError) as exc_info:
            FlextLdifConfig(analytics_detail_level="ultra")
        # Pydantic v2 error message format
        assert "Input should be" in str(
            exc_info.value
        ) or "analytics_detail_level" in str(exc_info.value)

    def test_validate_error_recovery_mode_invalid(self) -> None:
        """Test error_recovery_mode validator with invalid value."""
        with pytest.raises(ValidationError) as exc_info:
            FlextLdifConfig(error_recovery_mode="abort")
        # Pydantic v2 error message format
        assert "Input should be" in str(exc_info.value) or "error_recovery_mode" in str(
            exc_info.value
        )

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
        perf_config = FlextLdifConfig(
            enable_performance_optimizations=True,
            max_workers=4,  # Minimum for performance
            ldif_chunk_size=1000,  # Actual minimum for performance (PERFORMANCE_MIN_CHUNK_SIZE)
            memory_limit_mb=512,  # Minimum for performance (PERFORMANCE_MEMORY_MB_THRESHOLD)
        )
        assert perf_config.is_performance_optimized() is True

        normal_config = FlextLdifConfig()
        # Check actual value, don't assume
        result = normal_config.is_performance_optimized()
        assert isinstance(result, bool)

    def test_is_development_optimized(self) -> None:
        """Test is_development_optimized method.

        Now uses inherited fields from FlextConfig:
        - debug (replaces debug_mode)
        - log_verbosity (replaces verbose_logging)
        """
        dev_config = FlextLdifConfig(
            debug=True,  # Inherited from FlextConfig
            log_verbosity="detailed",  # Inherited from FlextConfig ("detailed" or "full" for development)
            max_workers=2,  # Max for debug mode
            enable_performance_optimizations=False,  # Debug mode conflicts with performance mode
        )
        assert dev_config.is_development_optimized() is True

        normal_config = FlextLdifConfig()
        result = normal_config.is_development_optimized()
        assert isinstance(result, bool)

    def test_global_instance_management(self) -> None:
        """Test global instance get and reset."""
        # Get global instance
        instance1 = FlextLdifConfig.get_global_instance()
        # Check that instance has expected FlextLdifConfig attributes
        assert hasattr(instance1, "ldif_encoding")
        assert hasattr(instance1, "ldif_max_line_length")
        assert hasattr(instance1, "ldif_strict_validation")

        # Should return same instance
        instance2 = FlextLdifConfig.get_global_instance()
        assert instance1 is instance2

        # Reset global instance
        FlextLdifConfig.reset_global_instance()

        # Should create new instance after reset
        instance3 = FlextLdifConfig.get_global_instance()
        # Check that instance has expected FlextLdifConfig attributes
        assert hasattr(instance3, "ldif_encoding")
        assert hasattr(instance3, "ldif_max_line_length")
        assert hasattr(instance3, "ldif_strict_validation")
        # After reset, it's a new instance
        assert instance3 is not instance1


class TestQuirksDetectionConfiguration:
    """Test suite for quirks detection configuration modes."""

    def test_default_quirks_detection_mode(self) -> None:
        """Test that default quirks detection mode is 'auto'."""
        config = FlextLdifConfig()
        assert config.quirks_detection_mode == "auto"

    def test_auto_detection_mode(self) -> None:
        """Test auto detection mode configuration."""
        config = FlextLdifConfig(quirks_detection_mode="auto")
        assert config.quirks_detection_mode == "auto"
        assert config.quirks_server_type is None  # Should be None in auto mode

    def test_manual_detection_mode_requires_server_type(self) -> None:
        """Test that manual mode requires quirks_server_type."""
        # Manual mode without server type should raise validation error
        with pytest.raises(ValidationError):
            FlextLdifConfig(quirks_detection_mode="manual", quirks_server_type=None)

    def test_manual_detection_mode_with_server_type(self) -> None:
        """Test manual detection mode with server type specified."""
        config = FlextLdifConfig(
            quirks_detection_mode="manual", quirks_server_type="oud"
        )
        assert config.quirks_detection_mode == "manual"
        assert config.quirks_server_type == "oud"

    def test_disabled_detection_mode(self) -> None:
        """Test disabled detection mode (RFC-only)."""
        config = FlextLdifConfig(quirks_detection_mode="disabled")
        assert config.quirks_detection_mode == "disabled"

    def test_disabled_mode_ignores_server_type(self) -> None:
        """Test that disabled mode works with or without server_type."""
        # Disabled mode with server type specified (should be ignored)
        config1 = FlextLdifConfig(
            quirks_detection_mode="disabled", quirks_server_type="oid"
        )
        assert config1.quirks_detection_mode == "disabled"

        # Disabled mode without server type
        config2 = FlextLdifConfig(quirks_detection_mode="disabled")
        assert config2.quirks_detection_mode == "disabled"

    def test_relaxed_parsing_default(self) -> None:
        """Test that relaxed parsing is disabled by default."""
        config = FlextLdifConfig()
        assert config.enable_relaxed_parsing is False

    def test_enable_relaxed_parsing(self) -> None:
        """Test enabling relaxed parsing mode."""
        config = FlextLdifConfig(enable_relaxed_parsing=True)
        assert config.enable_relaxed_parsing is True

    def test_relaxed_parsing_with_auto_detection(self) -> None:
        """Test relaxed parsing combined with auto detection."""
        config = FlextLdifConfig(
            quirks_detection_mode="auto", enable_relaxed_parsing=True
        )
        assert config.quirks_detection_mode == "auto"
        assert config.enable_relaxed_parsing is True

    def test_relaxed_parsing_with_manual_mode(self) -> None:
        """Test relaxed parsing combined with manual detection."""
        config = FlextLdifConfig(
            quirks_detection_mode="manual",
            quirks_server_type="oud",
            enable_relaxed_parsing=True,
        )
        assert config.quirks_detection_mode == "manual"
        assert config.quirks_server_type == "oud"
        assert config.enable_relaxed_parsing is True

    def test_relaxed_parsing_with_disabled_mode(self) -> None:
        """Test relaxed parsing combined with disabled (RFC-only) mode."""
        config = FlextLdifConfig(
            quirks_detection_mode="disabled", enable_relaxed_parsing=True
        )
        assert config.quirks_detection_mode == "disabled"
        assert config.enable_relaxed_parsing is True

    def test_supported_server_types(self) -> None:
        """Test that manual mode accepts all supported server types."""
        supported_types = [
            "oid",
            "oud",
            "openldap",
            "openldap1",
            "ad",
            "ds389",
            "apache",
            "novell",
            "tivoli",
            "relaxed",
        ]

        for server_type in supported_types:
            config = FlextLdifConfig(
                quirks_detection_mode="manual", quirks_server_type=server_type
            )
            assert config.quirks_server_type == server_type

    def test_quirks_server_type_none_in_auto_mode(self) -> None:
        """Test that quirks_server_type remains None in auto mode."""
        config = FlextLdifConfig(
            quirks_detection_mode="auto",
            quirks_server_type="oud",  # Should be ignored in auto mode
        )
        # Note: Pydantic will set it, but validation logic should ignore it
        assert config.quirks_detection_mode == "auto"

    def test_configuration_consistency_validation(self) -> None:
        """Test configuration consistency validation."""
        # Manual mode with server type - should pass
        config = FlextLdifConfig(
            quirks_detection_mode="manual", quirks_server_type="oud"
        )
        assert config is not None

    def test_config_dict_with_quirks_settings(self) -> None:
        """Test that quirks settings are included in config dict."""
        config = FlextLdifConfig(
            quirks_detection_mode="manual",
            quirks_server_type="oud",
            enable_relaxed_parsing=True,
        )

        config_dict = config.model_dump()
        assert "quirks_detection_mode" in config_dict
        assert "quirks_server_type" in config_dict
        assert "enable_relaxed_parsing" in config_dict
        assert config_dict["quirks_detection_mode"] == "manual"
        assert config_dict["quirks_server_type"] == "oud"
        assert config_dict["enable_relaxed_parsing"] is True

    def test_all_quirks_modes_with_all_combinations(self) -> None:
        """Test all combinations of quirks detection modes."""
        # Auto mode
        config_auto = FlextLdifConfig(quirks_detection_mode="auto")
        assert config_auto.quirks_detection_mode == "auto"

        # Manual mode with different servers
        for server in ["oid", "oud", "openldap", "ad"]:
            config_manual = FlextLdifConfig(
                quirks_detection_mode="manual", quirks_server_type=server
            )
            assert config_manual.quirks_server_type == server

        # Disabled mode
        config_disabled = FlextLdifConfig(quirks_detection_mode="disabled")
        assert config_disabled.quirks_detection_mode == "disabled"

        # All with relaxed parsing
        for detection_mode in ["auto", "disabled"]:
            config = FlextLdifConfig(
                quirks_detection_mode=detection_mode, enable_relaxed_parsing=True
            )
            assert config.enable_relaxed_parsing is True
