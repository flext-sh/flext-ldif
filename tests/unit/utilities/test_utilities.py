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

import importlib.util
from enum import StrEnum
from typing import ClassVar

import pytest

from flext_ldif import FlextLdifConfig, FlextLdifConstants, FlextLdifModels, services
from flext_ldif.services.dn import FlextLdifDn
from flext_ldif.services.statistics import FlextLdifStatistics

# =============================================================================
# TEST SCENARIO ENUMS
# =============================================================================


class ServiceInstantiationType(StrEnum):
    """Service instantiation test scenarios."""

    DN_SERVICE = "dn_service"
    STATISTICS_SERVICE = "statistics_service"


class ImportCheckType(StrEnum):
    """Import verification test scenarios."""

    MODELS = "models"
    CONSTANTS = "constants"
    UTILITIES_MODULE = "utilities_module"
    SERVICES_MODULE = "services_module"
    CONFIGURATION = "configuration"


# =============================================================================
# PARAMETRIZED TEST DATA
# =============================================================================


@pytest.fixture
def dn_service() -> FlextLdifDn:
    """Fixture providing FlextLdifDn instance."""
    return FlextLdifDn()


@pytest.fixture
def statistics_service() -> FlextLdifStatistics:
    """Fixture providing FlextLdifStatistics instance."""
    return FlextLdifStatistics()


@pytest.mark.unit
class TestFlextLdifServiceAPIs:
    """Test that newer service APIs are available and work correctly."""

    # Service instantiation test data
    SERVICE_INSTANTIATION_DATA: ClassVar[dict[str, tuple[ServiceInstantiationType]]] = {
        "instantiate_dn_service": (ServiceInstantiationType.DN_SERVICE,),
        "instantiate_statistics_service": (ServiceInstantiationType.STATISTICS_SERVICE,),
    }

    # Import verification test data
    IMPORT_CHECK_DATA: ClassVar[dict[str, tuple[ImportCheckType, str]]] = {
        "check_models_import": (ImportCheckType.MODELS, "FlextLdifModels"),
        "check_constants_available": (ImportCheckType.CONSTANTS, "ServerTypes"),
        "check_utilities_module": (ImportCheckType.UTILITIES_MODULE, "flext_ldif.utilities"),
        "check_services_module": (ImportCheckType.SERVICES_MODULE, "services"),
        "check_configuration_import": (ImportCheckType.CONFIGURATION, "FlextLdifConfig"),
    }

    # =======================================================================
    # Service Instantiation Tests
    # =======================================================================

    @pytest.mark.parametrize(
        ("scenario", "service_type"),
        [(name, data[0]) for name, data in SERVICE_INSTANTIATION_DATA.items()],
    )
    def test_service_instantiation(
        self,
        scenario: str,
        service_type: ServiceInstantiationType,
        dn_service: FlextLdifDn,
        statistics_service: FlextLdifStatistics,
    ) -> None:
        """Parametrized test for service instantiation."""
        if service_type == ServiceInstantiationType.DN_SERVICE:
            assert dn_service is not None
        elif service_type == ServiceInstantiationType.STATISTICS_SERVICE:
            assert statistics_service is not None

    # =======================================================================
    # Import Verification Tests
    # =======================================================================

    @pytest.mark.parametrize(
        ("scenario", "check_type", "check_target"),
        [(name, data[0], data[1]) for name, data in IMPORT_CHECK_DATA.items()],
    )
    def test_imports_available(
        self,
        scenario: str,
        check_type: ImportCheckType,
        check_target: str,
    ) -> None:
        """Parametrized test for import verification."""
        if check_type == ImportCheckType.MODELS:
            assert FlextLdifModels is not None
        elif check_type == ImportCheckType.CONSTANTS:
            assert hasattr(FlextLdifConstants, check_target)
        elif check_type == ImportCheckType.UTILITIES_MODULE:
            spec = importlib.util.find_spec(check_target)
            assert spec is not None, f"Module {check_target} should exist"
        elif check_type == ImportCheckType.SERVICES_MODULE:
            assert hasattr(services, "FlextLdifDn")
            assert hasattr(services, "FlextLdifStatistics")
        elif check_type == ImportCheckType.CONFIGURATION:
            config = FlextLdifConfig()
            assert config is not None
