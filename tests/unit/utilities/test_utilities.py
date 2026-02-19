"""Tests for LDIF service APIs and module imports.

This module tests newer service APIs including FlextLdifDn and FlextLdifStatistics services,
validating service instantiation, method availability, and proper import paths for models,
constants, utilities, and services modules in the FlextLdif ecosystem.
"""

from __future__ import annotations

import importlib.util
from enum import StrEnum
from typing import ClassVar

import pytest
from flext_ldif import FlextLdifConstants, FlextLdifModels, FlextLdifSettings, services
from flext_ldif.services.dn import FlextLdifDn
from flext_ldif.services.statistics import FlextLdifStatistics
from tests import s


class TestsTestFlextLdifServiceAPIs(s):
    """Test that newer service APIs are available and work correctly.

    Tests service instantiation and import availability using parametrized tests
    and nested class organization for better code organization.
    """

    dn_service: ClassVar[FlextLdifDn]  # pytest fixture
    statistics_service: ClassVar[FlextLdifStatistics]  # pytest fixture

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
        # FLEXT namespace: ServerTypes is inside Ldif namespace
        CONSTANT_LDIF_NAMESPACE: str = "Ldif"

    class Helpers:
        """Helper methods organized as nested class."""

        @staticmethod
        def get_service(
            service_type: TestsTestFlextLdifServiceAPIs.ServiceType,
            dn_service: FlextLdifDn,
            statistics_service: FlextLdifStatistics,
        ) -> FlextLdifDn | FlextLdifStatistics:
            """Get service instance based on type."""
            if service_type == TestsTestFlextLdifServiceAPIs.ServiceType.DN_SERVICE:
                return dn_service
            return statistics_service

        @staticmethod
        def verify_import(
            check_type: TestsTestFlextLdifServiceAPIs.ImportCheck,
            check_target: str,
        ) -> None:
            """Verify import availability based on check type."""
            match check_type:
                case TestsTestFlextLdifServiceAPIs.ImportCheck.MODELS:
                    assert FlextLdifModels is not None, (
                        "FlextLdifModels should be available"
                    )
                case TestsTestFlextLdifServiceAPIs.ImportCheck.CONSTANTS:
                    assert hasattr(
                        FlextLdifConstants,
                        check_target,
                    ), f"FlextLdifConstants should have {check_target}"
                case TestsTestFlextLdifServiceAPIs.ImportCheck.UTILITIES_MODULE:
                    spec = importlib.util.find_spec(check_target)
                    assert spec is not None, f"Module {check_target} should exist"
                case TestsTestFlextLdifServiceAPIs.ImportCheck.SERVICES_MODULE:
                    assert hasattr(
                        services,
                        TestsTestFlextLdifServiceAPIs.Constants.SERVICE_DN,
                    ), (
                        f"services should have {TestsTestFlextLdifServiceAPIs.Constants.SERVICE_DN}"
                    )
                    assert hasattr(
                        services,
                        TestsTestFlextLdifServiceAPIs.Constants.SERVICE_STATISTICS,
                    ), (
                        f"services should have {TestsTestFlextLdifServiceAPIs.Constants.SERVICE_STATISTICS}"
                    )
                case TestsTestFlextLdifServiceAPIs.ImportCheck.CONFIGURATION:
                    config = FlextLdifSettings()
                    assert config is not None, "FlextLdifSettings should instantiate"

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
            (ImportCheck.CONSTANTS, Constants.CONSTANT_LDIF_NAMESPACE),
            (ImportCheck.UTILITIES_MODULE, Constants.MODULE_UTILITIES),
            (ImportCheck.SERVICES_MODULE, "services"),
            (ImportCheck.CONFIGURATION, "FlextLdifSettings"),
        ],
    )
    def test_imports_available(
        self,
        check_type: ImportCheck,
        check_target: str,
    ) -> None:
        """Test import availability with parametrized test cases."""
        self.Helpers.verify_import(check_type, check_target)
