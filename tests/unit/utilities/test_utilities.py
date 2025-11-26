"""Tests for LDIF processing using newer services (post-v0.10.0).

Tests validate that:
1. Service APIs are available and work correctly
2. Core modules can be imported
3. Services can be instantiated
4. Configuration service works
5. Constants module is accessible

Modules tested:
- flext_ldif.services.dn.FlextLdifDn (DN and attribute normalization service)
- flext_ldif.services.statistics.FlextLdifStatistics (Pipeline statistics service)
- flext_ldif.models.FlextLdifModels (Direct model instantiation)
- flext_ldif.config.FlextLdifConfig (Configuration service)
- flext_ldif.constants.FlextLdifConstants (Constants module)

Scope:
- Service API availability and instantiation
- Import verification for core modules
- Module structure validation
- Configuration service initialization

Test Coverage:
- Service instantiation (DN and Statistics services)
- Import availability checks (Models, Constants, Utilities, Services, Configuration)
- Module specification validation

Uses factories, helpers, and constants to reduce code duplication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import importlib.util
from enum import StrEnum

import pytest

from flext_ldif import FlextLdifConfig, FlextLdifConstants, FlextLdifModels, services
from flext_ldif.services.dn import FlextLdifDn
from flext_ldif.services.statistics import FlextLdifStatistics


class TestFlextLdifServiceAPIs:
    """Test that newer service APIs are available and work correctly.

    Tests service instantiation and import availability using parametrized tests
    and nested class organization for better code organization.
    """

    class ServiceType(StrEnum):
        """Service instantiation test scenarios organized as nested enum."""

        DN_SERVICE = "dn_service"
        STATISTICS_SERVICE = "statistics_service"

    class ImportCheck(StrEnum):
        """Import verification test scenarios organized as nested enum."""

        MODELS = "models"
        CONSTANTS = "constants"
        UTILITIES_MODULE = "utilities_module"
        SERVICES_MODULE = "services_module"
        CONFIGURATION = "configuration"

    class Constants:
        """Test constants organized as nested class."""

        MODULE_UTILITIES: str = "flext_ldif.utilities"
        SERVICE_DN: str = "FlextLdifDn"
        SERVICE_STATISTICS: str = "FlextLdifStatistics"
        CONSTANT_SERVER_TYPES: str = "ServerTypes"

    class Helpers:
        """Helper methods organized as nested class."""

        @staticmethod
        def get_service(
            service_type: TestFlextLdifServiceAPIs.ServiceType,
            dn_service: FlextLdifDn,
            statistics_service: FlextLdifStatistics,
        ) -> FlextLdifDn | FlextLdifStatistics:
            """Get service instance based on type."""
            if service_type == TestFlextLdifServiceAPIs.ServiceType.DN_SERVICE:
                return dn_service
            return statistics_service

        @staticmethod
        def verify_import(
            check_type: TestFlextLdifServiceAPIs.ImportCheck,
            check_target: str,
        ) -> None:
            """Verify import availability based on check type."""
            match check_type:
                case TestFlextLdifServiceAPIs.ImportCheck.MODELS:
                    assert FlextLdifModels is not None, (
                        "FlextLdifModels should be available"
                    )
                case TestFlextLdifServiceAPIs.ImportCheck.CONSTANTS:
                    assert hasattr(
                        FlextLdifConstants,
                        check_target,
                    ), f"FlextLdifConstants should have {check_target}"
                case TestFlextLdifServiceAPIs.ImportCheck.UTILITIES_MODULE:
                    spec = importlib.util.find_spec(check_target)
                    assert spec is not None, f"Module {check_target} should exist"
                case TestFlextLdifServiceAPIs.ImportCheck.SERVICES_MODULE:
                    assert hasattr(
                        services,
                        TestFlextLdifServiceAPIs.Constants.SERVICE_DN,
                    ), (
                        f"services should have {TestFlextLdifServiceAPIs.Constants.SERVICE_DN}"
                    )
                    assert hasattr(
                        services,
                        TestFlextLdifServiceAPIs.Constants.SERVICE_STATISTICS,
                    ), (
                        f"services should have {TestFlextLdifServiceAPIs.Constants.SERVICE_STATISTICS}"
                    )
                case TestFlextLdifServiceAPIs.ImportCheck.CONFIGURATION:
                    config = FlextLdifConfig()
                    assert config is not None, "FlextLdifConfig should instantiate"

    @pytest.fixture
    def dn_service(self) -> FlextLdifDn:
        """Fixture providing FlextLdifDn instance."""
        return FlextLdifDn()

    @pytest.fixture
    def statistics_service(self) -> FlextLdifStatistics:
        """Fixture providing FlextLdifStatistics instance."""
        return FlextLdifStatistics()

    @pytest.mark.parametrize(
        "service_type",
        [ServiceType.DN_SERVICE, ServiceType.STATISTICS_SERVICE],
    )
    def test_service_instantiation(
        self,
        service_type: ServiceType,
        dn_service: FlextLdifDn,
        statistics_service: FlextLdifStatistics,
    ) -> None:
        """Test service instantiation with parametrized test cases."""
        service = self.Helpers.get_service(service_type, dn_service, statistics_service)
        assert service is not None, (
            f"Service {service_type.value} should be instantiated"
        )

    @pytest.mark.parametrize(
        ("check_type", "check_target"),
        [
            (ImportCheck.MODELS, "FlextLdifModels"),
            (ImportCheck.CONSTANTS, Constants.CONSTANT_SERVER_TYPES),
            (ImportCheck.UTILITIES_MODULE, Constants.MODULE_UTILITIES),
            (ImportCheck.SERVICES_MODULE, "services"),
            (ImportCheck.CONFIGURATION, "FlextLdifConfig"),
        ],
    )
    def test_imports_available(
        self,
        check_type: ImportCheck,
        check_target: str,
    ) -> None:
        """Test import availability with parametrized test cases."""
        self.Helpers.verify_import(check_type, check_target)
