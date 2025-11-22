"""Test suite for FlextLdifConfig.

Tests the nested configuration pattern where FlextLdifConfig is a BaseModel
registered as 'ldif' namespace in FlextConfig. Root config fields like
max_workers, debug, trace belong to FlextConfig (parent), not FlextLdifConfig.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from flext_ldif import FlextLdifConfig, FlextLdifConstants


class TestFlextLdifConfig:
    """Test suite for FlextLdifConfig nested configuration."""

    def test_initialization(self) -> None:
        """Test basic configuration initialization with LDIF-specific fields."""
        config = FlextLdifConfig()
        assert config.ldif_max_line_length == 78
        assert config.ldif_max_entries == 1000000
        assert config.ldif_chunk_size == 1000
        assert config.ldif_encoding == "utf-8"
        assert config.memory_limit_mb == FlextLdifConstants.MIN_MEMORY_MB

    def test_initialization_with_overrides(self) -> None:
        """Test configuration initialization with field overrides."""
        config = FlextLdifConfig(
            ldif_max_line_length=100,
            ldif_max_entries=5000,
            ldif_chunk_size=500,
        )
        assert config.ldif_max_line_length == 100
        assert config.ldif_max_entries == 5000
        assert config.ldif_chunk_size == 500

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

    def test_validation_chunk_size(self) -> None:
        """Test chunk size validation."""
        # Valid values
        config = FlextLdifConfig(ldif_chunk_size=100)
        assert config.ldif_chunk_size == 100

        config = FlextLdifConfig(ldif_chunk_size=10000)
        assert config.ldif_chunk_size == 10000

        # Invalid values
        with pytest.raises(ValidationError):
            FlextLdifConfig(ldif_chunk_size=99)  # Below minimum

        with pytest.raises(ValidationError):
            FlextLdifConfig(ldif_chunk_size=10001)  # Above maximum

    def test_validation_memory_limit(self) -> None:
        """Test memory limit validation."""
        # Valid values
        config = FlextLdifConfig(memory_limit_mb=64)
        assert config.memory_limit_mb == 64

        config = FlextLdifConfig(memory_limit_mb=1024)
        assert config.memory_limit_mb == 1024

        # Invalid values
        with pytest.raises(ValidationError):
            FlextLdifConfig(memory_limit_mb=63)  # Below MIN_MEMORY_MB=64

        with pytest.raises(ValidationError):
            FlextLdifConfig(memory_limit_mb=8193)  # Above MAX_MEMORY_MB=8192

    def test_validation_analytics_cache_size(self) -> None:
        """Test analytics cache size validation."""
        # Valid values
        config = FlextLdifConfig(ldif_analytics_cache_size=100)
        assert config.ldif_analytics_cache_size == 100

        config = FlextLdifConfig(ldif_analytics_cache_size=10000)
        assert config.ldif_analytics_cache_size == 10000

        # Invalid values
        with pytest.raises(ValidationError):
            FlextLdifConfig(
                ldif_analytics_cache_size=99,
            )  # Below MIN_ANALYTICS_CACHE_SIZE=100

        with pytest.raises(ValidationError):
            FlextLdifConfig(
                ldif_analytics_cache_size=10001,
            )  # Above MAX_ANALYTICS_CACHE_SIZE=10000

    def test_singleton_pattern(self) -> None:
        """Test singleton pattern via get_instance."""
        # Reset to ensure clean state
        FlextLdifConfig._reset_instance()

        instance1 = FlextLdifConfig.get_instance()
        instance2 = FlextLdifConfig.get_instance()

        assert instance1 is instance2

        # Cleanup
        FlextLdifConfig._reset_instance()

    def test_reset_instance(self) -> None:
        """Test singleton reset for testing."""
        # Get first instance
        instance1 = FlextLdifConfig.get_instance()

        # Reset
        FlextLdifConfig._reset_instance()

        # Get new instance
        instance2 = FlextLdifConfig.get_instance()

        # Should be different objects
        assert instance1 is not instance2

        # Cleanup
        FlextLdifConfig._reset_instance()

    def test_model_dump(self) -> None:
        """Test Pydantic v2 model_dump serialization."""
        config = FlextLdifConfig()
        data = config.model_dump()

        assert isinstance(data, dict)
        assert "ldif_encoding" in data
        assert "ldif_max_line_length" in data
        assert "ldif_chunk_size" in data

    def test_model_validate(self) -> None:
        """Test Pydantic v2 model_validate deserialization."""
        data = {
            "ldif_max_line_length": 100,
            "ldif_max_entries": 5000,
            "ldif_chunk_size": 500,
        }

        config = FlextLdifConfig.model_validate(data)

        assert config.ldif_max_line_length == 100
        assert config.ldif_max_entries == 5000
        assert config.ldif_chunk_size == 500

    def test_model_validate_invalid_data(self) -> None:
        """Test model_validate with invalid data."""
        data = {
            "ldif_max_line_length": 10,  # Below minimum
        }

        with pytest.raises(ValidationError):
            FlextLdifConfig.model_validate(data)

    def test_configuration_properties(self) -> None:
        """Test that expected LDIF-specific properties exist."""
        config = FlextLdifConfig()

        # LDIF-specific fields must exist
        assert hasattr(config, "ldif_encoding")
        assert hasattr(config, "ldif_max_line_length")
        assert hasattr(config, "ldif_chunk_size")
        assert hasattr(config, "ldif_max_entries")
        assert hasattr(config, "memory_limit_mb")
        assert hasattr(config, "ldif_enable_analytics")
        assert hasattr(config, "server_type")
        assert hasattr(config, "validation_level")

    def test_configuration_defaults(self) -> None:
        """Test default values from constants."""
        config = FlextLdifConfig()

        assert config.ldif_encoding == "utf-8"
        assert config.ldif_max_line_length == FlextLdifConstants.Format.MAX_LINE_LENGTH
        assert config.ldif_chunk_size == FlextLdifConstants.DEFAULT_BATCH_SIZE
        assert config.server_type == "generic"
        assert config.validation_level == "strict"

    def test_validate_ldif_encoding_invalid(self) -> None:
        """Test invalid ldif_encoding value."""
        with pytest.raises(ValidationError):
            FlextLdifConfig(ldif_encoding="invalid-encoding")

    def test_validate_validation_level_invalid(self) -> None:
        """Test invalid validation_level value."""
        with pytest.raises(ValidationError):
            FlextLdifConfig(validation_level="invalid")

    def test_validate_server_type_invalid(self) -> None:
        """Test invalid server_type value."""
        with pytest.raises(ValidationError):
            FlextLdifConfig(server_type="invalid-server")

    def test_validate_analytics_detail_level_invalid(self) -> None:
        """Test invalid analytics_detail_level value."""
        with pytest.raises(ValidationError):
            FlextLdifConfig(analytics_detail_level="invalid")

    def test_validate_error_recovery_mode_invalid(self) -> None:
        """Test invalid error_recovery_mode value."""
        with pytest.raises(ValidationError):
            FlextLdifConfig(error_recovery_mode="invalid")

    def test_get_effective_encoding(self) -> None:
        """Test get_effective_encoding method."""
        config = FlextLdifConfig()
        encoding = config.get_effective_encoding()
        assert encoding == "utf-8"

        # AD server uses utf-16
        ad_config = FlextLdifConfig(server_type="ad")
        ad_encoding = ad_config.get_effective_encoding()
        assert ad_encoding == "utf-16"


class TestQuirksDetectionConfiguration:
    """Test quirks detection configuration options."""

    def test_defaults_detection_mode(self) -> None:
        """Test default quirks detection mode is auto."""
        config = FlextLdifConfig()
        assert config.quirks_detection_mode == "auto"

    def test_auto_detection_mode(self) -> None:
        """Test auto detection mode configuration."""
        config = FlextLdifConfig(quirks_detection_mode="auto")
        assert config.quirks_detection_mode == "auto"

    def test_manual_detection_mode_requires_server_type(self) -> None:
        """Test manual mode requires quirks_server_type."""
        with pytest.raises(ValidationError):
            FlextLdifConfig(quirks_detection_mode="manual")

    def test_manual_detection_mode_with_server_type(self) -> None:
        """Test manual mode with server type specified."""
        config = FlextLdifConfig(
            quirks_detection_mode="manual",
            quirks_server_type="oud",
        )
        assert config.quirks_detection_mode == "manual"
        assert config.quirks_server_type == "oud"

    def test_disabled_detection_mode(self) -> None:
        """Test disabled detection mode for RFC-only parsing."""
        config = FlextLdifConfig(quirks_detection_mode="disabled")
        assert config.quirks_detection_mode == "disabled"

    def test_disabled_mode_ignores_server_type(self) -> None:
        """Test disabled mode can have server type (ignored during parsing)."""
        config = FlextLdifConfig(
            quirks_detection_mode="disabled",
            quirks_server_type="oud",
        )
        assert config.quirks_detection_mode == "disabled"
        assert config.quirks_server_type == "oud"

    def test_relaxed_parsing_default(self) -> None:
        """Test relaxed parsing is disabled by default."""
        config = FlextLdifConfig()
        assert config.enable_relaxed_parsing is False

    def test_enable_relaxed_parsing(self) -> None:
        """Test enabling relaxed parsing mode."""
        config = FlextLdifConfig(enable_relaxed_parsing=True)
        assert config.enable_relaxed_parsing is True

    def test_relaxed_parsing_with_auto_detection(self) -> None:
        """Test relaxed parsing with auto detection mode."""
        config = FlextLdifConfig(
            quirks_detection_mode="auto",
            enable_relaxed_parsing=True,
        )
        assert config.quirks_detection_mode == "auto"
        assert config.enable_relaxed_parsing is True

    def test_relaxed_parsing_with_manual_mode(self) -> None:
        """Test relaxed parsing with manual mode."""
        config = FlextLdifConfig(
            quirks_detection_mode="manual",
            quirks_server_type="oud",
            enable_relaxed_parsing=True,
        )
        assert config.quirks_detection_mode == "manual"
        assert config.quirks_server_type == "oud"
        assert config.enable_relaxed_parsing is True

    def test_relaxed_parsing_with_disabled_mode(self) -> None:
        """Test relaxed parsing with disabled mode (RFC only + relaxed)."""
        config = FlextLdifConfig(
            quirks_detection_mode="disabled",
            enable_relaxed_parsing=True,
        )
        assert config.quirks_detection_mode == "disabled"
        assert config.enable_relaxed_parsing is True

    def test_supported_server_types(self) -> None:
        """Test all supported server types can be configured."""
        # Use canonical server type values from FlextLdifConstants.LiteralTypes.ServerType
        server_types = [
            "generic",
            "rfc",
            "oid",
            "oud",
            "openldap",
            "openldap1",
            "openldap2",
            "active_directory",
            "apache_directory",
            "389ds",
            "novell_edirectory",
            "ibm_tivoli",
            "relaxed",
        ]

        for server_type in server_types:
            # Type ignore: Testing all valid server types dynamically
            config = FlextLdifConfig(server_type=server_type)
            assert config.server_type == server_type

    def test_configuration_consistency_validation(self) -> None:
        """Test configuration consistency validation."""
        # Valid: auto mode without server type
        config = FlextLdifConfig(quirks_detection_mode="auto")
        assert config.quirks_detection_mode == "auto"

        # Valid: manual mode with server type
        config = FlextLdifConfig(
            quirks_detection_mode="manual",
            quirks_server_type="oud",
        )
        assert config.quirks_detection_mode == "manual"

    def test_all_modes_with_all_combinations(self) -> None:
        """Test all detection modes with various combinations."""
        # Auto mode
        config = FlextLdifConfig(
            quirks_detection_mode="auto",
            enable_relaxed_parsing=False,
        )
        assert config.quirks_detection_mode == "auto"

        # Manual mode with server
        config = FlextLdifConfig(
            quirks_detection_mode="manual",
            quirks_server_type="openldap",
            enable_relaxed_parsing=True,
        )
        assert config.quirks_detection_mode == "manual"
        assert config.quirks_server_type == "openldap"

        # Disabled mode
        config = FlextLdifConfig(
            quirks_detection_mode="disabled",
            enable_relaxed_parsing=False,
        )
        assert config.quirks_detection_mode == "disabled"


class TestAnalyticsConfiguration:
    """Test analytics-related configuration."""

    def test_analytics_enabled_by_default(self) -> None:
        """Test analytics is enabled by default."""
        config = FlextLdifConfig()
        assert config.ldif_enable_analytics is True

    def test_disable_analytics(self) -> None:
        """Test disabling analytics."""
        config = FlextLdifConfig(ldif_enable_analytics=False)
        assert config.ldif_enable_analytics is False

    def test_analytics_cache_size_default(self) -> None:
        """Test default analytics cache size."""
        config = FlextLdifConfig()
        assert config.ldif_analytics_cache_size == FlextLdifConstants.DEFAULT_BATCH_SIZE

    def test_analytics_detail_levels(self) -> None:
        """Test analytics detail level options."""
        for level in ["low", "medium", "high"]:
            config = FlextLdifConfig(analytics_detail_level=level)
            assert config.analytics_detail_level == level


class TestProcessingConfiguration:
    """Test processing-related configuration."""

    def test_batch_size_default(self) -> None:
        """Test default batch size."""
        config = FlextLdifConfig()
        assert config.ldif_batch_size == FlextLdifConstants.DEFAULT_BATCH_SIZE

    def test_fail_on_warnings_default(self) -> None:
        """Test fail_on_warnings is disabled by default."""
        config = FlextLdifConfig()
        assert config.ldif_fail_on_warnings is False

    def test_enable_fail_on_warnings(self) -> None:
        """Test enabling fail_on_warnings."""
        config = FlextLdifConfig(ldif_fail_on_warnings=True)
        assert config.ldif_fail_on_warnings is True

    def test_strict_rfc_compliance_default(self) -> None:
        """Test strict RFC compliance is enabled by default."""
        config = FlextLdifConfig()
        assert config.strict_rfc_compliance is True

    def test_disable_strict_rfc_compliance(self) -> None:
        """Test disabling strict RFC compliance."""
        config = FlextLdifConfig(strict_rfc_compliance=False)
        assert config.strict_rfc_compliance is False


class TestValidationConfiguration:
    """Test validation-related configuration."""

    def test_validation_level_options(self) -> None:
        """Test validation level options."""
        # Use canonical values from FlextLdifConstants.LiteralTypes.VALIDATION_LEVELS
        for level in ["strict", "moderate", "lenient"]:
            config = FlextLdifConfig(validation_level=level)
            assert config.validation_level == level

    def test_error_recovery_modes(self) -> None:
        """Test error recovery mode options."""
        for mode in ["continue", "stop", "skip"]:
            config = FlextLdifConfig(error_recovery_mode=mode)
            assert config.error_recovery_mode == mode


class TestNestedConfigPattern:
    """Test the nested configuration pattern behavior."""

    def test_no_root_config_fields(self) -> None:
        """Test that root config fields do NOT exist in nested config.

        FlextLdifConfig is a NESTED config (AutoConfig), not a root config.
        Fields like max_workers, debug, trace belong to FlextConfig parent.
        """
        config = FlextLdifConfig()

        # These fields should NOT exist in nested config
        assert not hasattr(config, "max_workers")
        assert not hasattr(config, "debug")
        assert not hasattr(config, "trace")
        assert not hasattr(config, "log_level")
        assert not hasattr(config, "log_verbosity")

    def test_extra_fields_ignored(self) -> None:
        """Test that extra fields are ignored (extra='ignore' in model_config)."""
        # Should not raise even with unknown fields
        config = FlextLdifConfig.model_validate({
            "ldif_encoding": "utf-8",
            "unknown_field": "ignored",
        })
        assert config.ldif_encoding == "utf-8"
        assert not hasattr(config, "unknown_field")


__all__ = [
    "TestAnalyticsConfiguration",
    "TestFlextLdifConfig",
    "TestNestedConfigPattern",
    "TestProcessingConfiguration",
    "TestQuirksDetectionConfiguration",
    "TestValidationConfiguration",
]
