"""Tests for LDIF service APIs and module imports.

This module tests newer service APIs including FlextLdifDn and FlextLdifStatistics services,
validating service instantiation, method availability, and proper import paths for models,
constants, utilities, and services modules in the FlextLdif ecosystem.
"""

from __future__ import annotations

import importlib.util
from enum import StrEnum, unique

import pytest
from flext_tests import tm

from flext_ldif import (
    FlextLdifDn,
    FlextLdifSettings,
    FlextLdifStatistics,
    services,
)
from tests import c, m


class TestsTestFlextLdifServiceAPIs:
    """Test that newer service APIs are available and work correctly.

    Tests service instantiation and import availability using parametrized tests
    and nested class organization for better code organization.
    """

    @unique
    class ServiceType(StrEnum):
        """Service instantiation test scenarios organized as nested enum."""

        DN_SERVICE = "dn_service"
        STATISTICS_SERVICE = "statistics_service"

    @unique
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
                    _ = tm.that(m, none=False)
                case TestsTestFlextLdifServiceAPIs.ImportCheck.CONSTANTS:
                    _ = tm.that(hasattr(c, check_target), eq=True)
                case TestsTestFlextLdifServiceAPIs.ImportCheck.UTILITIES_MODULE:
                    spec = importlib.util.find_spec(check_target)
                    _ = tm.that(spec is not None, eq=True)
                case TestsTestFlextLdifServiceAPIs.ImportCheck.SERVICES_MODULE:
                    _ = tm.that(
                        hasattr(
                            services,
                            TestsTestFlextLdifServiceAPIs.Constants.SERVICE_DN,
                        ),
                        eq=True,
                    )
                    _ = tm.that(
                        hasattr(
                            services,
                            TestsTestFlextLdifServiceAPIs.Constants.SERVICE_STATISTICS,
                        ),
                        eq=True,
                    )
                case TestsTestFlextLdifServiceAPIs.ImportCheck.CONFIGURATION:
                    config = FlextLdifSettings()
                    _ = tm.that(config, none=False)

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
        _ = tm.that(service, none=False)

    @pytest.mark.parametrize(
        ("check_type", "check_target"),
        [
            (ImportCheck.MODELS, "m"),
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
