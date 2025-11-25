"""Test suite for FlextLdifConfig.

Modules tested: FlextLdifConfig
Scope: Initialization, validation, singleton, serialization, quirks detection, analytics, processing, nested pattern

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import dataclasses
from enum import StrEnum

import pytest
from pydantic import ValidationError

from flext_ldif import FlextLdifConfig, FlextLdifConstants


@pytest.fixture
def default_config() -> FlextLdifConfig:
    """Fixture for default configuration."""
    return FlextLdifConfig()


@pytest.fixture
def validation_ranges() -> tuple[ValidationRange, ...]:
    """Fixture for validation ranges test data."""
    return VALIDATION_RANGES


@dataclasses.dataclass(frozen=True)
class ValidationRange:
    """Numeric validation range specification."""

    field_name: str
    min_value: int
    max_value: int
    valid_values: list[int]
    invalid_below: int
    invalid_above: int


class ServerTypes(StrEnum):
    """Supported server types for configuration testing."""

    GENERIC = "generic"
    RFC = "rfc"
    OID = "oid"
    OUD = "oud"
    OPENLDAP = "openldap"
    OPENLDAP1 = "openldap1"
    OPENLDAP2 = "openldap2"
    ACTIVE_DIRECTORY = "active_directory"
    APACHE_DIRECTORY = "apache_directory"
    DS389 = "389ds"
    NOVELL_EDIRECTORY = "novell_edirectory"
    IBM_TIVOLI = "ibm_tivoli"
    RELAXED = "relaxed"


class ValidationLevels(StrEnum):
    """Supported validation levels."""

    STRICT = "strict"
    MODERATE = "moderate"
    LENIENT = "lenient"


class ErrorRecoveryModes(StrEnum):
    """Supported error recovery modes."""

    CONTINUE = "continue"
    STOP = "stop"
    SKIP = "skip"


class AnalyticsDetailLevels(StrEnum):
    """Supported analytics detail levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class QuirksDetectionModes(StrEnum):
    """Supported quirks detection modes."""

    AUTO = "auto"
    MANUAL = "manual"
    DISABLED = "disabled"


# Test data mapping - DRY principle for validation ranges
VALIDATION_RANGES = (
    ValidationRange(
        field_name="ldif_max_line_length",
        min_value=40,
        max_value=200,
        valid_values=[40, 78, 200],
        invalid_below=39,
        invalid_above=201,
    ),
    ValidationRange(
        field_name="ldif_max_entries",
        min_value=1000,
        max_value=10000000,
        valid_values=[1000, 1000000, 10000000],
        invalid_below=999,
        invalid_above=10000001,
    ),
    ValidationRange(
        field_name="ldif_chunk_size",
        min_value=100,
        max_value=10000,
        valid_values=[100, 1000, 10000],
        invalid_below=99,
        invalid_above=10001,
    ),
    ValidationRange(
        field_name="memory_limit_mb",
        min_value=FlextLdifConstants.MIN_MEMORY_MB,
        max_value=FlextLdifConstants.MAX_MEMORY_MB,
        valid_values=[64, 512, 4096],
        invalid_below=63,
        invalid_above=8193,
    ),
    ValidationRange(
        field_name="ldif_analytics_cache_size",
        min_value=100,
        max_value=10000,
        valid_values=[100, 1000, 10000],
        invalid_below=99,
        invalid_above=10001,
    ),
)


class TestFlextLdifConfig:
    """Test suite for FlextLdifConfig nested configuration."""

    def test_default_initialization(self, default_config: FlextLdifConfig) -> None:
        """Test basic configuration initialization with LDIF-specific fields."""
        config = default_config
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

    class Validation:
        """Test configuration field validation."""

        @pytest.mark.parametrize("validation_range", VALIDATION_RANGES)
        def test_numeric_validation_valid_values(
            self,
            validation_range: ValidationRange,
        ) -> None:
            """Test numeric validation with valid values."""
            for valid_value in validation_range.valid_values:
                kwargs: dict[str, object] = {
                    validation_range.field_name: valid_value,
                }
                config = FlextLdifConfig(**kwargs)  # type: ignore[arg-type]
                assert getattr(config, validation_range.field_name) == valid_value

        @pytest.mark.parametrize("validation_range", VALIDATION_RANGES)
        def test_numeric_validation_below_minimum(
            self,
            validation_range: ValidationRange,
        ) -> None:
            """Test numeric validation with value below minimum."""
            kwargs: dict[str, object] = {
                validation_range.field_name: validation_range.invalid_below,
            }
            with pytest.raises(ValidationError):
                FlextLdifConfig(**kwargs)  # type: ignore[arg-type]

        @pytest.mark.parametrize("validation_range", VALIDATION_RANGES)
        def test_numeric_validation_above_maximum(
            self,
            validation_range: ValidationRange,
        ) -> None:
            """Test numeric validation with value above maximum."""
            kwargs: dict[str, object] = {
                validation_range.field_name: validation_range.invalid_above,
            }
            with pytest.raises(ValidationError):
                FlextLdifConfig(**kwargs)  # type: ignore[arg-type]

    class Singleton:
        """Test singleton pattern and instance management."""

        def test_singleton_pattern(self) -> None:
            """Test singleton pattern via get_instance."""
            FlextLdifConfig._reset_instance()  # type: ignore[attr-defined]
            instance1 = FlextLdifConfig.get_instance()  # type: ignore[attr-defined]
            instance2 = FlextLdifConfig.get_instance()  # type: ignore[attr-defined]
            assert instance1 is instance2
            FlextLdifConfig._reset_instance()  # type: ignore[attr-defined]

        def test_reset_instance(self) -> None:
            """Test singleton reset creates new instance."""
            instance1 = FlextLdifConfig.get_instance()  # type: ignore[attr-defined]
            FlextLdifConfig._reset_instance()  # type: ignore[attr-defined]
            instance2 = FlextLdifConfig.get_instance()  # type: ignore[attr-defined]
            assert instance1 is not instance2
            FlextLdifConfig._reset_instance()  # type: ignore[attr-defined]

    class Serialization:
        """Test Pydantic v2 model operations."""

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
            data = {"ldif_max_line_length": 10}
            with pytest.raises(ValidationError):
                FlextLdifConfig.model_validate(data)

    class Properties:
        """Test configuration properties and defaults."""

        def test_configuration_properties_exist(self) -> None:
            """Test that expected LDIF-specific properties exist."""
            config = FlextLdifConfig()
            required_properties = [
                "ldif_encoding",
                "ldif_max_line_length",
                "ldif_chunk_size",
                "ldif_max_entries",
                "memory_limit_mb",
                "ldif_enable_analytics",
                "server_type",
                "validation_level",
            ]
            for prop in required_properties:
                assert hasattr(config, prop)

        def test_configuration_defaults(self) -> None:
            """Test default values from constants."""
            config = FlextLdifConfig()
            assert config.ldif_encoding == "utf-8"
            assert (
                config.ldif_max_line_length == FlextLdifConstants.Format.MAX_LINE_LENGTH
            )
            assert config.ldif_chunk_size == FlextLdifConstants.DEFAULT_BATCH_SIZE
            assert config.server_type == "generic"
            assert config.validation_level == "strict"

    class StringValidation:
        """Test string field validation."""

        def test_ldif_encoding_valid(self) -> None:
            """Test valid ldif_encoding values."""
            config = FlextLdifConfig(ldif_encoding="utf-8")
            assert config.ldif_encoding == "utf-8"

        def test_ldif_encoding_invalid(self) -> None:
            """Test invalid ldif_encoding value."""
            with pytest.raises(ValidationError):
                FlextLdifConfig(ldif_encoding="invalid-encoding")

        @pytest.mark.parametrize("level", [v.value for v in ValidationLevels])
        def test_validation_level_valid(self, level: str) -> None:
            """Test valid validation_level values."""
            config = FlextLdifConfig(validation_level=level)  # type: ignore[arg-type]
            assert config.validation_level == level

        def test_validation_level_invalid(self) -> None:
            """Test invalid validation_level value."""
            with pytest.raises(ValidationError):
                FlextLdifConfig(validation_level="invalid")  # type: ignore[arg-type]

        @pytest.mark.parametrize("server_type", [v.value for v in ServerTypes])
        def test_server_type_valid(self, server_type: str) -> None:
            """Test valid server_type values."""
            config = FlextLdifConfig(server_type=server_type)
            assert config.server_type == server_type

        def test_server_type_invalid(self) -> None:
            """Test invalid server_type value."""
            with pytest.raises(ValidationError):
                FlextLdifConfig(server_type="invalid-server")

        @pytest.mark.parametrize(
            "detail_level",
            [v.value for v in AnalyticsDetailLevels],
        )
        def test_analytics_detail_level_valid(self, detail_level: str) -> None:
            """Test valid analytics_detail_level values."""
            config = FlextLdifConfig(
                analytics_detail_level=detail_level,  # type: ignore[arg-type]
            )
            assert config.analytics_detail_level == detail_level

        def test_analytics_detail_level_invalid(self) -> None:
            """Test invalid analytics_detail_level value."""
            with pytest.raises(ValidationError):
                FlextLdifConfig(
                    analytics_detail_level="invalid",  # type: ignore[arg-type]
                )

        @pytest.mark.parametrize("mode", [v.value for v in ErrorRecoveryModes])
        def test_error_recovery_mode_valid(self, mode: str) -> None:
            """Test valid error_recovery_mode values."""
            config = FlextLdifConfig(error_recovery_mode=mode)  # type: ignore[arg-type]
            assert config.error_recovery_mode == mode

        def test_error_recovery_mode_invalid(self) -> None:
            """Test invalid error_recovery_mode value."""
            with pytest.raises(ValidationError):
                FlextLdifConfig(
                    error_recovery_mode="invalid",  # type: ignore[arg-type]
                )

    class Encoding:
        """Test encoding-related functionality."""

        def test_get_effective_encoding_default(self) -> None:
            """Test get_effective_encoding for default configuration."""
            config = FlextLdifConfig()
            assert config.get_effective_encoding() == "utf-8"

        def test_get_effective_encoding_active_directory(self) -> None:
            """Test get_effective_encoding returns utf-16 for AD server."""
            ad_config = FlextLdifConfig(
                server_type="active_directory",
            )
            assert ad_config.get_effective_encoding() == "utf-16"


class TestQuirksDetectionConfiguration:
    """Test quirks detection configuration options."""

    class DetectionModes:
        """Test quirks detection mode configurations."""

        def test_defaults_detection_mode(self) -> None:
            """Test default quirks detection mode is auto."""
            config = FlextLdifConfig()
            assert config.quirks_detection_mode == "auto"

        @pytest.mark.parametrize("mode", [v.value for v in QuirksDetectionModes])
        def test_detection_mode_valid(self, mode: str) -> None:
            """Test valid detection modes can be configured."""
            if mode == "manual":
                config = FlextLdifConfig(
                    quirks_detection_mode=mode,  # type: ignore[arg-type]
                    quirks_server_type="oud",
                )
            else:
                config = FlextLdifConfig(
                    quirks_detection_mode=mode,  # type: ignore[arg-type]
                )
            assert config.quirks_detection_mode == mode

        def test_manual_detection_mode_requires_server_type(self) -> None:
            """Test manual mode requires quirks_server_type."""
            with pytest.raises(ValidationError):
                FlextLdifConfig(quirks_detection_mode="manual")

    class RelaxedParsing:
        """Test relaxed parsing configuration."""

        def test_relaxed_parsing_default_disabled(self) -> None:
            """Test relaxed parsing is disabled by default."""
            config = FlextLdifConfig()
            assert config.enable_relaxed_parsing is False

        def test_enable_relaxed_parsing(self) -> None:
            """Test enabling relaxed parsing mode."""
            config = FlextLdifConfig(enable_relaxed_parsing=True)
            assert config.enable_relaxed_parsing is True

        def test_relaxed_parsing_combinations(self) -> None:
            """Test relaxed parsing with all detection mode combinations."""
            # Auto mode with relaxed
            config = FlextLdifConfig(
                quirks_detection_mode="auto",
                enable_relaxed_parsing=True,
            )
            assert config.quirks_detection_mode == "auto"
            assert config.enable_relaxed_parsing is True

            # Manual mode with relaxed
            config = FlextLdifConfig(
                quirks_detection_mode="manual",
                quirks_server_type="oud",
                enable_relaxed_parsing=True,
            )
            assert config.quirks_detection_mode == "manual"
            assert config.enable_relaxed_parsing is True

            # Disabled mode with relaxed
            config = FlextLdifConfig(
                quirks_detection_mode="disabled",
                enable_relaxed_parsing=True,
            )
            assert config.quirks_detection_mode == "disabled"
            assert config.enable_relaxed_parsing is True

    class ConsistencyValidation:
        """Test configuration consistency and validation."""

        def test_manual_mode_with_server_type(self) -> None:
            """Test manual mode with server type specified."""
            config = FlextLdifConfig(
                quirks_detection_mode="manual",
                quirks_server_type="oud",
            )
            assert config.quirks_detection_mode == "manual"
            assert config.quirks_server_type == "oud"

        def test_disabled_mode_with_server_type(self) -> None:
            """Test disabled mode can have server type (ignored during parsing)."""
            config = FlextLdifConfig(
                quirks_detection_mode="disabled",
                quirks_server_type="oud",
            )
            assert config.quirks_detection_mode == "disabled"
            assert config.quirks_server_type == "oud"


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

    @pytest.mark.parametrize("level", [v.value for v in AnalyticsDetailLevels])
    def test_analytics_detail_levels(self, level: str) -> None:
        """Test analytics detail level options."""
        config = FlextLdifConfig(
            analytics_detail_level=level,  # type: ignore[arg-type]
        )
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


class TestNestedConfigPattern:
    """Test the nested configuration pattern behavior."""

    def test_no_root_config_fields(self) -> None:
        """Test that root config fields do NOT exist in nested config.

        FlextLdifConfig is a NESTED config (AutoConfig), not a root config.
        Fields like max_workers, debug, trace belong to FlextConfig parent.
        """
        config = FlextLdifConfig()
        disallowed_fields = [
            "max_workers",
            "debug",
            "trace",
            "log_level",
            "log_verbosity",
        ]
        for field in disallowed_fields:
            assert not hasattr(config, field)

    def test_extra_fields_ignored(self) -> None:
        """Test that extra fields are ignored (extra='ignore' in model_config)."""
        config = FlextLdifConfig.model_validate({
            "ldif_encoding": "utf-8",
            "unknown_field": "ignored",
        })
        assert config.ldif_encoding == "utf-8"
        assert not hasattr(config, "unknown_field")


__all__ = [
    "AnalyticsDetailLevels",
    "ErrorRecoveryModes",
    "QuirksDetectionModes",
    "ServerTypes",
    "TestAnalyticsConfiguration",
    "TestFlextLdifConfig",
    "TestNestedConfigPattern",
    "TestProcessingConfiguration",
    "TestQuirksDetectionConfiguration",
    "ValidationLevels",
    "ValidationRange",
]
