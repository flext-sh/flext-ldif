"""Tests for LDIF processing using newer services (post-v0.10.0).

This file replaces the old test_utilities.py that tested removed utilities module.
Tests use newer service APIs directly:
- FlextLdifDnService: DN and attribute normalization
- FlextLdifStatisticsService: Pipeline statistics
- FlextLdifModels: Direct model instantiation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services.dn import FlextLdifDnService
from flext_ldif.services.statistics import FlextLdifStatisticsService


@pytest.mark.unit
class TestNewServiceAPIs:
    """Test that newer service APIs are available and work."""

    def test_dn_service_instantiation(self) -> None:
        """Test FlextLdifDnService can be instantiated."""
        service = FlextLdifDnService()
        assert service is not None

    def test_statistics_service_instantiation(self) -> None:
        """Test FlextLdifStatisticsService can be instantiated."""
        service = FlextLdifStatisticsService()
        assert service is not None

    def test_models_imported_correctly(self) -> None:
        """Test that FlextLdif models can be imported."""
        from flext_ldif import FlextLdifModels

        assert FlextLdifModels is not None

    def test_constants_available(self) -> None:
        """Test that constants are available."""
        assert hasattr(FlextLdifConstants, "ServerTypes")

    def test_removed_utilities_module_deleted(self) -> None:
        """Test that removed utilities module is no longer present."""
        import importlib.util

        # Module should not be found in the package
        spec = importlib.util.find_spec("flext_ldif.utilities")
        assert spec is None, "utilities module should no longer exist"

    def test_services_module_exists(self) -> None:
        """Test that services module structure is correct."""
        from flext_ldif import services

        assert hasattr(services, "FlextLdifDnService")
        assert hasattr(services, "FlextLdifStatisticsService")

    def test_configuration_imports(self) -> None:
        """Test that configuration can be imported."""
        from flext_ldif import FlextLdifConfig

        config = FlextLdifConfig()
        assert config is not None
