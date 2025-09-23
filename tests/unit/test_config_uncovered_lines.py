"""Tests to cover remaining config.py uncovered lines.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif.config import FlextLdifConfig


class TestConfigUncoveredLines:
    """Tests targeting specific uncovered lines in config.py."""

    @staticmethod
    def test_analytics_cache_size_validation() -> None:
        """Test lines 195-196: analytics cache size validation."""
        from pydantic_core import ValidationError

        with pytest.raises(ValidationError, match="greater than or equal to 100"):
            FlextLdifConfig(
                ldif_enable_analytics=True,
                ldif_analytics_cache_size=50,
            )

    @staticmethod
    def test_business_rule_validation_success() -> None:
        """Test business rule validation with no errors - covers lines 295-300."""
        config = FlextLdifConfig()

        result = config.validate_ldif_business_rules()
        assert result.is_success

    @staticmethod
    def test_apply_overrides_validation_error() -> None:
        """Test lines 324-325: override validation error handling."""
        from pydantic_core import ValidationError

        config = FlextLdifConfig()

        invalid_overrides: dict[str, object] = {
            "ldif_enable_analytics": True,
            "ldif_analytics_cache_size": 10,
        }

        try:
            result = config.apply_ldif_overrides(invalid_overrides)
            assert result.is_failure
        except ValidationError:
            pass

    @staticmethod
    def test_analytics_disabled_default_cache() -> None:
        """Test analytics disabled uses default cache size."""
        config = FlextLdifConfig(
            ldif_enable_analytics=False,
        )
        assert config.ldif_analytics_cache_size >= 100

    @staticmethod
    def test_apply_overrides_success_path() -> None:
        """Test successful override application with revalidation."""
        config = FlextLdifConfig()

        valid_overrides: dict[str, object] = {
            "ldif_max_entries": 5000,
            "ldif_strict_validation": False,
        }

        result = config.apply_ldif_overrides(valid_overrides)
        assert result.is_success
        assert config.ldif_max_entries == 5000
        assert config.ldif_strict_validation is False
