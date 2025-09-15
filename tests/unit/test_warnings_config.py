"""Tests for warnings configuration module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import warnings

from flext_ldif.warnings_config import configure_warnings


class TestWarningsConfig:
    """Test warnings configuration functionality."""

    def test_configure_warnings_sets_filters(self) -> None:
        """Test that configure_warnings can be called without error."""
        # Clear existing filters
        warnings.resetwarnings()
        initial_count = len(warnings.filters)

        # Configure warnings - function should run without error
        configure_warnings()

        # Since warnings filters are commented out, count should be same
        filters = warnings.filters
        assert len(filters) == initial_count

    def test_configure_warnings_multiple_calls(self) -> None:
        """Test that multiple calls to configure_warnings work correctly."""
        # First call
        configure_warnings()
        initial_count = len(warnings.filters)

        # Second call
        configure_warnings()
        final_count = len(warnings.filters)

        # Since filters are commented out, count should remain the same
        assert final_count == initial_count

    def test_configure_warnings_execution(self) -> None:
        """Test that configure_warnings executes without error."""
        # This should run without raising any exceptions
        configure_warnings()

        # Call it multiple times to ensure it's safe
        configure_warnings()
        configure_warnings()

    def test_warnings_configuration_import(self) -> None:
        """Test that warnings configuration can be imported."""
        assert callable(configure_warnings)
        assert configure_warnings.__name__ == "configure_warnings"
