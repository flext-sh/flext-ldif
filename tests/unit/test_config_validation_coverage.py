"""Additional tests for config.py validation to achieve higher coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from flext_ldif.config import FlextLdifConfig


class TestConfigValidationCoverage:
    """Tests to cover validation paths in config.py."""

    @staticmethod
    def test_analytics_cache_size_below_minimum() -> None:
        """Test analytics cache size validation below minimum."""
        with pytest.raises(ValidationError) as exc_info:
            FlextLdifConfig(
                ldif_enable_analytics=True,
                ldif_analytics_cache_size=50,  # Below MIN of 100
            )
        # Pydantic error message format
        assert "greater than or equal to 100" in str(exc_info.value)

    @staticmethod
    def test_business_rules_max_entries_too_low() -> None:
        """Test business rules when max entries is too low for production."""
        config = FlextLdifConfig(
            ldif_max_entries=500,  # Below MIN_PRODUCTION_ENTRIES (1000)
            ldif_chunk_size=250,  # Must be less than max_entries
        )
        result = config.validate_ldif_business_rules()
        assert result.is_failure
        assert "Too few entries for production use" in (result.error or "")

    @staticmethod
    def test_business_rules_buffer_size_too_small() -> None:
        """Test business rules when buffer size is exactly at minimum."""
        # Pydantic enforces ge=1024, so business rule at line 268 is unreachable
        # This test documents that the business rule is redundant with Pydantic validation
        config = FlextLdifConfig(
            ldif_buffer_size=1024,  # At MIN_BUFFER_SIZE, passes Pydantic
        )
        result = config.validate_ldif_business_rules()
        # Business rule check is redundant, will pass
        assert result.is_success

    @staticmethod
    def test_business_rules_too_many_workers() -> None:
        """Test business rules when worker count is too high."""
        config = FlextLdifConfig(
            ldif_parallel_processing=True,
            ldif_max_workers=9,  # Above MAX_WORKERS_LIMIT (8)
        )
        result = config.validate_ldif_business_rules()
        assert result.is_failure
        assert "Workers exceeds maximum limit" in (result.error or "")

    @staticmethod
    def test_apply_overrides_with_invalid_value() -> None:
        """Test applying overrides with invalid value that fails validation."""
        config = FlextLdifConfig()
        # Try to set analytics cache size below minimum via override
        result = config.apply_ldif_overrides({
            "ldif_enable_analytics": True,
            "ldif_analytics_cache_size": 50,
        })
        assert result.is_failure
        # Pydantic error message varies, just check it failed with validation error
        assert result.error is not None

    @staticmethod
    def test_apply_overrides_on_sealed_config() -> None:
        """Test applying overrides to sealed configuration."""
        config = FlextLdifConfig()
        config.seal()
        result = config.apply_ldif_overrides({"ldif_max_entries": 5000})
        assert result.is_failure
        assert "sealed" in (result.error or "").lower()

    @staticmethod
    def test_init_global_with_invalid_attribute() -> None:
        """Test initializing global config with attribute that doesn't exist."""
        # Reset any existing global config first
        FlextLdifConfig.reset_global_ldif_config()

        # Try to set an attribute that doesn't exist
        result = FlextLdifConfig.initialize_global_ldif_config(
            nonexistent_attribute="value"
        )
        # Should succeed and ignore the invalid attribute
        assert result.is_success
