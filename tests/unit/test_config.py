"""Tests for FlextLdif configuration validation.

This module tests the FlextLdifConfig model and its validation rules
for LDIF processing configuration.
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from typing import cast

import pytest
from pydantic import ValidationError

from flext_ldif import FlextLdifConfig
from flext_ldif.constants import c as lib_c
from tests import s


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


# Test constants organized as module-level constants
VALIDATION_RANGES: tuple[ValidationRange, ...] = (
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
        min_value=lib_c.LdifProcessing.MIN_MEMORY_MB,
        max_value=lib_c.LdifProcessing.MAX_MEMORY_MB,
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

REQUIRED_PROPERTIES: list[str] = [
    "ldif_encoding",
    "ldif_max_line_length",
    "ldif_chunk_size",
    "ldif_max_entries",
    "memory_limit_mb",
    "ldif_enable_analytics",
    "server_type",
    "validation_level",
]

DISALLOWED_ROOT_FIELDS: list[str] = [
    "max_workers",
    "debug",
    "trace",
    "log_level",
    "log_verbosity",
]


class TestsTestFlextLdifConfig(s):
    """Test suite for FlextLdifConfig nested configuration.

    Organized as single class with nested classes for test organization.
    Uses factories, constants, and parametrization to reduce code duplication.
    """

    class Helpers:
        """Helper methods organized as nested class."""

        __test__ = False

        @staticmethod
        def create_config_with_field(field_name: str, value: object) -> FlextLdifConfig:
            """Create config with single field override."""
            kwargs: dict[str, object] = {field_name: value}
            # Type narrowing: use type: ignore for dynamic field assignment in tests
            # In test context, we know values are valid for their respective fields
            # Pydantic will validate at runtime
            return FlextLdifConfig(**kwargs)

        @staticmethod
        def assert_config_field(
            config: FlextLdifConfig,
            field_name: str,
            expected_value: object,
        ) -> None:
            """Assert config field has expected value."""
            assert getattr(config, field_name) == expected_value

    def test_default_initialization(self) -> None:
        """Test basic configuration initialization with LDIF-specific fields."""
        config = FlextLdifConfig()
        assert config.ldif_max_line_length == 199
        assert config.ldif_max_entries == 1000000
        assert config.ldif_chunk_size == 1000
        assert config.ldif_encoding == "utf-8"
        assert config.memory_limit_mb == lib_c.LdifProcessing.MIN_MEMORY_MB

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
                config = TestsTestFlextLdifConfig.Helpers.create_config_with_field(
                    validation_range.field_name,
                    valid_value,
                )
                TestsTestFlextLdifConfig.Helpers.assert_config_field(
                    config,
                    validation_range.field_name,
                    valid_value,
                )

        @pytest.mark.parametrize("validation_range", VALIDATION_RANGES)
        def test_numeric_validation_below_minimum(
            self,
            validation_range: ValidationRange,
        ) -> None:
            """Test numeric validation with value below minimum."""
            with pytest.raises(ValidationError):
                TestsTestFlextLdifConfig.Helpers.create_config_with_field(
                    validation_range.field_name,
                    validation_range.invalid_below,
                )

        @pytest.mark.parametrize("validation_range", VALIDATION_RANGES)
        def test_numeric_validation_above_maximum(
            self,
            validation_range: ValidationRange,
        ) -> None:
            """Test numeric validation with value above maximum."""
            with pytest.raises(ValidationError):
                TestsTestFlextLdifConfig.Helpers.create_config_with_field(
                    validation_range.field_name,
                    validation_range.invalid_above,
                )

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
            for prop in REQUIRED_PROPERTIES:
                assert hasattr(config, prop)

        def test_configuration_defaults(self) -> None:
            """Test default values from constants."""
            config = FlextLdifConfig()
            assert config.ldif_encoding == "utf-8"
            assert (
                config.ldif_max_line_length == lib_c.Ldif.LdifFormatting.MAX_LINE_WIDTH
            )
            assert config.ldif_chunk_size == 1000  # Default from ConfigDefaults
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
                # Type narrowing: cast invalid value for runtime validation test
                FlextLdifConfig(
                    ldif_encoding=cast(
                        "lib_c.Ldif.LiteralTypes.EncodingLiteral",
                        "invalid-encoding",
                    ),
                )

        @pytest.mark.parametrize(
            "level",
            [member.value for member in ValidationLevels.__members__.values()],
        )
        def test_validation_level_valid(self, level: str) -> None:
            """Test valid validation_level values."""
            # Type narrowing: cast str to Literal for type checker
            config = FlextLdifConfig(
                validation_level=cast(
                    "lib_c.Ldif.LiteralTypes.ValidationLevelLiteral",
                    level,
                ),
            )
            assert config.validation_level == level

        def test_validation_level_invalid(self) -> None:
            """Test invalid validation_level value."""
            with pytest.raises(ValidationError):
                # Type narrowing: cast invalid value for runtime validation test
                FlextLdifConfig(
                    validation_level=cast(
                        "lib_c.Ldif.LiteralTypes.ValidationLevelLiteral",
                        "invalid",
                    ),
                )

        @pytest.mark.parametrize(
            "server_type",
            [member.value for member in ServerTypes.__members__.values()],
        )
        def test_server_type_valid(self, server_type: str) -> None:
            """Test valid server_type values."""
            # Normalize and cast: use normalize_server_type to ensure valid ServerTypeLiteral
            normalized = lib_c.normalize_server_type(server_type)
            config = FlextLdifConfig(server_type=normalized)
            assert config.server_type == normalized

        def test_server_type_invalid(self) -> None:
            """Test invalid server_type value."""
            with pytest.raises(ValidationError):
                # Type narrowing: cast invalid value for runtime validation test
                FlextLdifConfig(
                    server_type=cast(
                        "lib_c.Ldif.LiteralTypes.ServerTypeLiteral",
                        "invalid-server",
                    ),
                )

        @pytest.mark.parametrize(
            "detail_level",
            [member.value for member in AnalyticsDetailLevels.__members__.values()],
        )
        def test_analytics_detail_level_valid(self, detail_level: str) -> None:
            """Test valid analytics_detail_level values."""
            # Type narrowing: cast str to Literal for type checker
            config = FlextLdifConfig(
                analytics_detail_level=cast(
                    "lib_c.Ldif.LiteralTypes.AnalyticsDetailLevelLiteral",
                    detail_level,
                ),
            )
            assert config.analytics_detail_level == detail_level

        def test_analytics_detail_level_invalid(self) -> None:
            """Test invalid analytics_detail_level value."""
            with pytest.raises(ValidationError):
                # Type narrowing: cast invalid value for runtime validation test
                FlextLdifConfig(
                    analytics_detail_level=cast(
                        "lib_c.Ldif.LiteralTypes.AnalyticsDetailLevelLiteral",
                        "invalid",
                    ),
                )

        @pytest.mark.parametrize(
            "mode",
            [member.value for member in ErrorRecoveryModes.__members__.values()],
        )
        def test_error_recovery_mode_valid(self, mode: str) -> None:
            """Test valid error_recovery_mode values."""
            # Type narrowing: cast str to Literal for type checker
            config = FlextLdifConfig(
                error_recovery_mode=cast(
                    "lib_c.Ldif.LiteralTypes.ErrorRecoveryModeLiteral",
                    mode,
                ),
            )
            assert config.error_recovery_mode == mode

        def test_error_recovery_mode_invalid(self) -> None:
            """Test invalid error_recovery_mode value."""
            with pytest.raises(ValidationError):
                # Type narrowing: cast invalid value for runtime validation test
                FlextLdifConfig(
                    error_recovery_mode=cast(
                        "lib_c.Ldif.LiteralTypes.ErrorRecoveryModeLiteral",
                        "invalid",
                    ),
                )

    class Encoding:
        """Test encoding-related functionality."""

        def test_get_effective_encoding_default(self) -> None:
            """Test get_effective_encoding for default configuration."""
            config = FlextLdifConfig()
            assert config.get_effective_encoding() == "utf-8"

        def test_get_effective_encoding_active_directory(self) -> None:
            """Test get_effective_encoding returns utf-16 for AD server."""
            # Type narrowing: cast str to Literal for type checker
            ad_config = FlextLdifConfig(
                server_type=cast(
                    "lib_c.Ldif.LiteralTypes.ServerTypeLiteral",
                    "active_directory",
                ),
            )
            assert ad_config.get_effective_encoding() == "utf-16"

    class QuirksDetection:
        """Test quirks detection configuration options."""

        def test_defaults_detection_mode(self) -> None:
            """Test default quirks detection mode is auto."""
            config = FlextLdifConfig()
            assert config.quirks_detection_mode == "auto"

        @pytest.mark.parametrize(
            "mode",
            [member.value for member in QuirksDetectionModes.__members__.values()],
        )
        def test_detection_mode_valid(self, mode: str) -> None:
            """Test valid detection modes can be configured."""
            # Type narrowing: cast str to Literal for type checker
            mode_literal = cast(
                "lib_c.Ldif.LiteralTypes.DetectionModeLiteral",
                mode,
            )
            if mode == "manual":
                config = FlextLdifConfig(
                    quirks_detection_mode=mode_literal,
                    quirks_server_type=cast(
                        "lib_c.Ldif.LiteralTypes.ServerTypeLiteral",
                        "oud",
                    ),
                )
            else:
                config = FlextLdifConfig(quirks_detection_mode=mode_literal)
            assert config.quirks_detection_mode == mode

        def test_manual_detection_mode_requires_server_type(self) -> None:
            """Test manual mode requires quirks_server_type."""
            with pytest.raises(ValidationError):
                FlextLdifConfig(quirks_detection_mode="manual")

        def test_relaxed_parsing_default_disabled(self) -> None:
            """Test relaxed parsing is disabled by default."""
            config = FlextLdifConfig()
            assert config.enable_relaxed_parsing is False

        def test_enable_relaxed_parsing(self) -> None:
            """Test enabling relaxed parsing mode."""
            config = FlextLdifConfig(enable_relaxed_parsing=True)
            assert config.enable_relaxed_parsing is True

        @pytest.mark.parametrize(
            "mode",
            [member.value for member in QuirksDetectionModes.__members__.values()],
        )
        def test_relaxed_parsing_combinations(self, mode: str) -> None:
            """Test relaxed parsing with all detection mode combinations."""
            # Type narrowing: cast str to Literal for type checker
            mode_literal = cast(
                "lib_c.Ldif.LiteralTypes.DetectionModeLiteral",
                mode,
            )
            if mode == "manual":
                config = FlextLdifConfig(
                    quirks_detection_mode=mode_literal,
                    quirks_server_type=cast(
                        "lib_c.Ldif.LiteralTypes.ServerTypeLiteral",
                        "oud",
                    ),
                    enable_relaxed_parsing=True,
                )
            else:
                config = FlextLdifConfig(
                    quirks_detection_mode=mode_literal,
                    enable_relaxed_parsing=True,
                )
            assert config.quirks_detection_mode == mode
            assert config.enable_relaxed_parsing is True

        def test_manual_mode_with_server_type(self) -> None:
            """Test manual mode with server type specified."""
            config = FlextLdifConfig(
                quirks_detection_mode=cast(
                    "lib_c.Ldif.LiteralTypes.DetectionModeLiteral",
                    "manual",
                ),
                quirks_server_type=cast(
                    "lib_c.Ldif.LiteralTypes.ServerTypeLiteral",
                    "oud",
                ),
            )
            assert config.quirks_detection_mode == "manual"
            assert config.quirks_server_type == "oud"

        def test_disabled_mode_with_server_type(self) -> None:
            """Test disabled mode can have server type (ignored during parsing)."""
            config = FlextLdifConfig(
                quirks_detection_mode=cast(
                    "lib_c.Ldif.LiteralTypes.DetectionModeLiteral",
                    "disabled",
                ),
                quirks_server_type=cast(
                    "lib_c.Ldif.LiteralTypes.ServerTypeLiteral",
                    "oud",
                ),
            )
            assert config.quirks_detection_mode == "disabled"
            assert config.quirks_server_type == "oud"

    class Analytics:
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
            assert (
                config.ldif_analytics_cache_size == 1000  # Default from ConfigDefaults
            )

        @pytest.mark.parametrize(
            "level",
            [member.value for member in AnalyticsDetailLevels.__members__.values()],
        )
        def test_analytics_detail_levels(self, level: str) -> None:
            """Test analytics detail level options."""
            # Type narrowing: cast str to Literal for type checker
            config = FlextLdifConfig(
                analytics_detail_level=cast(
                    "lib_c.Ldif.LiteralTypes.AnalyticsDetailLevelLiteral",
                    level,
                ),
            )
            assert config.analytics_detail_level == level

    class Processing:
        """Test processing-related configuration."""

        def test_batch_size_default(self) -> None:
            """Test default batch size."""
            config = FlextLdifConfig()
            assert config.ldif_batch_size == lib_c.DEFAULT_BATCH_SIZE

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

    class NestedPattern:
        """Test the nested configuration pattern behavior."""

        def test_no_root_config_fields(self) -> None:
            """Test that root config fields do NOT exist in nested config.

            FlextLdifConfig is a NESTED config (AutoConfig), not a root config.
            Fields like max_workers, debug, trace belong to FlextConfig parent.
            """
            config = FlextLdifConfig()
            for field in DISALLOWED_ROOT_FIELDS:
                assert not hasattr(config, field)

        def test_extra_fields_ignored(self) -> None:
            """Test that extra fields are ignored (extra='ignore' in model_config)."""
            config = FlextLdifConfig.model_validate({
                "ldif_encoding": "utf-8",
                "unknown_field": "ignored",
            })
            assert config.ldif_encoding == "utf-8"
            assert not hasattr(config, "unknown_field")
