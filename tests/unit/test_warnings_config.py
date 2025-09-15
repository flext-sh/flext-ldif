"""Tests for warnings configuration module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import warnings
from unittest.mock import patch

from flext_ldif.warnings_config import configure_warnings


class TestWarningsConfig:
    """Test warnings configuration functionality."""

    def test_configure_warnings_sets_filters(self) -> None:
        """Test that configure_warnings sets appropriate warning filters."""
        # Clear existing filters
        warnings.resetwarnings()
        initial_count = len(warnings.filters)

        # Configure warnings
        configure_warnings()

        # Check that filters are set
        filters = warnings.filters
        assert len(filters) > initial_count

    def test_configure_warnings_multiple_calls(self) -> None:
        """Test that multiple calls to configure_warnings work correctly."""
        # First call
        configure_warnings()
        initial_count = len(warnings.filters)

        # Second call
        configure_warnings()
        final_count = len(warnings.filters)

        # Should have more filters after second call
        assert final_count >= initial_count

    def test_configure_warnings_with_mock(self) -> None:
        """Test configure_warnings with mocked warnings module."""
        with patch("flext_ldif.warnings_config.warnings") as mock_warnings:
            configure_warnings()

            # Verify filterwarnings was called multiple times
            assert mock_warnings.filterwarnings.call_count >= 4

            # Check that calls were made with expected patterns
            calls = mock_warnings.filterwarnings.call_args_list
            call_args = [call[0] for call in calls]

            # Should have calls with "ignore" action
            assert any("ignore" in args for args in call_args)

            # Should have calls with pydantic module references
            call_strs = [str(args) for args in call_args]
            assert any("pydantic" in call_str for call_str in call_strs)

    def test_warnings_configuration_import(self) -> None:
        """Test that warnings configuration can be imported."""
        from flext_ldif.warnings_config import configure_warnings

        assert callable(configure_warnings)
        assert configure_warnings.__name__ == "configure_warnings"
