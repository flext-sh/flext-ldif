"""Comprehensive tests for FlextLdifConfig to achieve 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdifConfig, FlextLdifConstants


class TestConfigValidation:
    """Tests for config validation to achieve complete coverage."""

    def test_validate_analytics_cache_size_below_minimum_raises_error(self) -> None:
        """Test that analytics cache size below minimum raises ValueError (lines 193-194)."""
        with pytest.raises(ValueError) as exc_info:
            FlextLdifConfig(
                ldif_enable_analytics=True,
                ldif_analytics_cache_size=50,  # Below MIN_ANALYTICS_CACHE_SIZE (100)
            )

        error_msg = str(exc_info.value)
        assert (
            "Analytics cache size must be at least 100" in error_msg
            or "greater than or equal to 100" in error_msg
        )

    def test_validate_analytics_cache_size_at_minimum_success(self) -> None:
        """Test that analytics cache size at minimum succeeds."""
        config = FlextLdifConfig(
            ldif_enable_analytics=True,
            ldif_analytics_cache_size=FlextLdifConstants.Processing.MIN_ANALYTICS_CACHE_SIZE,
        )

        assert (
            config.ldif_analytics_cache_size
            == FlextLdifConstants.Processing.MIN_ANALYTICS_CACHE_SIZE
        )

    def test_validate_analytics_cache_size_above_minimum_success(self) -> None:
        """Test that analytics cache size above minimum succeeds."""
        config = FlextLdifConfig(
            ldif_enable_analytics=True,
            ldif_analytics_cache_size=200,
        )

        assert config.ldif_analytics_cache_size == 200

    def test_validate_analytics_disabled_with_valid_cache_size(self) -> None:
        """Test that analytics can be disabled with valid cache size."""
        config = FlextLdifConfig(
            ldif_enable_analytics=False,
            ldif_analytics_cache_size=100,  # Must still be valid
        )

        assert config.ldif_enable_analytics is False
        assert config.ldif_analytics_cache_size == 100


class TestBusinessRuleValidation:
    """Tests for business rule validation."""

    def test_validate_ldif_business_rules_success(self) -> None:
        """Test validate_ldif_business_rules success path."""
        config = FlextLdifConfig()
        result = config.validate_ldif_business_rules()
        assert result.is_success


class TestConfigOverrides:
    """Tests for configuration override functionality."""

    def test_apply_ldif_overrides_validation_error_coverage(self) -> None:
        """Test apply_ldif_overrides with validation error (lines 340-341)."""
        config = FlextLdifConfig()

        overrides: dict[str, object] = {
            "ldif_enable_analytics": True,
            "ldif_analytics_cache_size": 50,  # Below minimum, will cause validation error
        }

        result = config.apply_ldif_overrides(overrides)

        assert result.is_failure
        assert result.error is not None and (
            "Analytics cache size must be at least 100" in result.error
            or "greater than or equal to 100" in result.error
        )

    def test_apply_ldif_overrides_success(self) -> None:
        """Test apply_ldif_overrides with valid overrides."""
        config = FlextLdifConfig()

        overrides: dict[str, object] = {
            "ldif_enable_analytics": True,
            "ldif_analytics_cache_size": 200,
        }

        result = config.apply_ldif_overrides(overrides)

        assert result.is_success
        assert config.ldif_enable_analytics is True
        assert config.ldif_analytics_cache_size == 200

    def test_apply_ldif_overrides_sealed_config(self) -> None:
        """Test that overrides cannot be applied to sealed configuration."""
        config = FlextLdifConfig()
        config.seal()

        overrides: dict[str, object] = {"ldif_enable_analytics": False}

        result = config.apply_ldif_overrides(overrides)

        assert result.is_failure
        assert (
            result.error is not None
            and "Cannot apply overrides to sealed configuration" in result.error
        )

    def test_apply_ldif_overrides_ignores_unknown_keys(self) -> None:
        """Test that unknown keys in overrides are ignored."""
        config = FlextLdifConfig()

        overrides: dict[str, object] = {
            "unknown_key": "some_value",
            "ldif_enable_analytics": True,
        }

        result = config.apply_ldif_overrides(overrides)

        assert result.is_success
        assert config.ldif_enable_analytics is True
        assert not hasattr(config, "unknown_key")
