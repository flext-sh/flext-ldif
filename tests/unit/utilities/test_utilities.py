"""Tests for LDIF processing using newer services (post-v0.10.0).

This file replaces the old test_utilities.py that tested removed utilities module.
Tests use newer service APIs directly:
- FlextLdifDn: DN and attribute normalization
- FlextLdifStatistics: Pipeline statistics
- FlextLdifModels: Direct model instantiation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services.dn import FlextLdifDn
from flext_ldif.services.statistics import FlextLdifStatistics


@pytest.mark.unit
class TestNewServiceAPIs:
    """Test that newer service APIs are available and work."""

    def test_dn_service_instantiation(self) -> None:
        """Test FlextLdifDn can be instantiated."""
        service = FlextLdifDn()
        assert service is not None

    def test_statistics_service_instantiation(self) -> None:
        """Test FlextLdifStatistics can be instantiated."""
        service = FlextLdifStatistics()
        assert service is not None

    def test_models_imported_correctly(self) -> None:
        """Test that FlextLdif models can be imported."""
        from flext_ldif import FlextLdifModels

        assert FlextLdifModels is not None

    def test_constants_available(self) -> None:
        """Test that constants are available."""
        assert hasattr(FlextLdifConstants, "ServerTypes")

    def test_utilities_module_exists(self) -> None:
        """Test that utilities module exists for newer functionality."""
        import importlib.util

        # Module should be found in the package for newer functionality
        spec = importlib.util.find_spec("flext_ldif.utilities")
        assert spec is not None, "utilities module should exist for newer functionality"

    def test_services_module_exists(self) -> None:
        """Test that services module structure is correct."""
        from flext_ldif import services

        assert hasattr(services, "FlextLdifDn")
        assert hasattr(services, "FlextLdifStatistics")

    def test_configuration_imports(self) -> None:
        """Test that configuration can be imported."""
        from flext_ldif import FlextLdifConfig

        config = FlextLdifConfig()
        assert config is not None
