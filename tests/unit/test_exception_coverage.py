"""Tests to achieve 100% coverage for exception handling paths.

This module contains targeted tests for exception handlers in api.py,
config.py, models.py, and processor.py that were previously uncovered.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

import pytest
from pydantic_core import ValidationError

from flext_ldif import FlextLdifConfig, FlextLdifModels


class TestConfigExceptionCoverage:
    """Tests for config exception handling paths."""

    @staticmethod
    def test_analytics_cache_size_validation_error() -> None:
        """Test analytics cache size validation with value below minimum."""
        with pytest.raises(ValidationError):
            FlextLdifConfig(
                ldif_enable_analytics=True,
                ldif_analytics_cache_size=50,  # Below minimum of 100
            )

    @staticmethod
    def test_business_rules_analytics_cache_too_large() -> None:
        """Test business rules when analytics cache is too large."""
        config = FlextLdifConfig(
            ldif_enable_analytics=True,
            ldif_analytics_cache_size=20000,  # Above MAX_ANALYTICS_CACHE_SIZE (10000)
        )
        result = config.validate_ldif_business_rules()
        assert result.is_failure
        assert "Analytics cache size too large for memory efficiency" in str(
            result.error
        )


class TestModelsExceptionCoverage:
    """Tests for models exception handling paths."""

    @staticmethod
    def test_ldif_attributes_validation_type_error() -> None:
        """Test LdifAttributes validation when data is not a dict."""
        with pytest.raises(ValidationError):
            FlextLdifModels.LdifAttributes(
                data=cast("dict[str, list[str]]", "not_a_dict")
            )

    @staticmethod
    def test_ldif_attributes_validation_attribute_values_not_list() -> None:
        """Test LdifAttributes validation when attribute values are not a list."""
        invalid_attrs = {"cn": cast("list[str]", "not_a_list")}
        with pytest.raises(ValidationError):
            FlextLdifModels.LdifAttributes(data=invalid_attrs)

    @staticmethod
    def test_ldif_attributes_validation_attribute_value_not_string() -> None:
        """Test LdifAttributes validation when attribute value is not a string."""
        invalid_attrs = {"cn": [cast("str", 123)]}
        with pytest.raises(ValidationError):
            FlextLdifModels.LdifAttributes(data=invalid_attrs)

    @staticmethod
    def test_distinguished_name_validation_error() -> None:
        """Test DistinguishedName with invalid DN format."""
        with pytest.raises(ValidationError):
            FlextLdifModels.DistinguishedName(value="invalid-dn-format")

    @staticmethod
    def test_entry_create_exception_during_instantiation() -> None:
        """Test Entry.create when instantiation fails due to invalid data."""
        # Pass invalid DN data to trigger exception during entry creation
        invalid_entry_data = {
            "dn": 123,  # Invalid: DN must be string
            "attributes": {"cn": ["test"]},
        }

        result = FlextLdifModels.create_entry(
            cast("dict[str, object]", invalid_entry_data)
        )
        assert result.is_failure
        # Should contain error message about DN validation
        assert result.error is not None


class TestProcessorExceptionCoverage:
    """Tests for processor exception handling paths."""

    @staticmethod
    def test_empty_dn_validation_via_pydantic() -> None:
        """Test that empty DN is rejected by Pydantic validation."""
        with pytest.raises(ValidationError):
            FlextLdifModels.DistinguishedName(value="")

    @staticmethod
    def test_analytics_empty_entries() -> None:
        """Test analytics calculation with empty entries list."""
        from flext_ldif.processor import FlextLdifProcessor

        processor = FlextLdifProcessor()
        stats = processor._AnalyticsHelper.calculate_entry_statistics([])

        assert stats["total_entries"] == 0
        assert stats["unique_dns"] == 0
        assert stats["attribute_diversity"] == 0
