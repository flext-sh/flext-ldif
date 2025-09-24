"""Comprehensive tests for FlextLdifMixins to achieve 100% coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif.mixins import FlextLdifMixins


class TestValidationMixin:
    """Tests for ValidationMixin to achieve complete coverage."""

    def test_validate_string_not_empty_success(self) -> None:
        """Test validate_string_not_empty with valid input."""
        result = FlextLdifMixins.ValidationMixin.validate_string_not_empty(
            "valid value", "test_field"
        )
        assert result == "valid value"

    def test_validate_string_not_empty_strips_whitespace(self) -> None:
        """Test that validate_string_not_empty strips whitespace."""
        result = FlextLdifMixins.ValidationMixin.validate_string_not_empty(
            "  value  ", "test_field"
        )
        assert result == "value"

    def test_validate_string_not_empty_empty_raises_error(self) -> None:
        """Test validate_string_not_empty with empty string raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            FlextLdifMixins.ValidationMixin.validate_string_not_empty("", "test_field")

        assert "test_field cannot be empty" in str(exc_info.value)

    def test_validate_string_not_empty_whitespace_only_raises_error(self) -> None:
        """Test validate_string_not_empty with whitespace-only string raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            FlextLdifMixins.ValidationMixin.validate_string_not_empty(
                "   ", "test_field"
            )

        assert "test_field cannot be empty" in str(exc_info.value)

    def test_validate_string_not_empty_none_raises_error(self) -> None:
        """Test validate_string_not_empty with None raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            FlextLdifMixins.ValidationMixin.validate_string_not_empty(
                None, "test_field"
            )

        assert "test_field cannot be empty" in str(exc_info.value)
