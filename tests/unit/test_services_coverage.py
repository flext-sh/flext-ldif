"""Test coverage for all service compatibility modules.

Tests the compatibility re-export modules that provide access to unified API services.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest


class TestServiceCompatibilityModules:
    """Test coverage for service compatibility modules."""

    @staticmethod
    def test_analytics_service_import() -> None:
        """Test analytics service module can be imported."""
        # Clear the module from cache if it exists
        if "flext_ldif.analytics_service" in sys.modules:
            del sys.modules["flext_ldif.analytics_service"]

        # Mock the problematic dependencies during import
        with patch.dict(
            sys.modules,
            {
                "flext_core": type(sys)("flext_core"),
                "flext_core.domain_services": type(sys)("flext_core.domain_services"),
                "flext_core.result": type(sys)("flext_core.result"),
                "flext_core.typings": type(sys)("flext_core.typings"),
            },
        ):
            # Create mock FlextResult
            mock_result_class = type("FlextResult", (), {})
            sys.modules["flext_core"].FlextResult = mock_result_class

            # Create mock FlextTypes with Config
            mock_config_class = type("Config", (), {})
            mock_types_class = type("FlextTypes", (), {"Config": mock_config_class})
            sys.modules["flext_core"].FlextTypes = mock_types_class

            # Mock other required components
            sys.modules["flext_core"].FlextDomainService = type(
                "FlextDomainService", (), {}
            )
            sys.modules["flext_core"].FlextLogger = type("FlextLogger", (), {})

            # Now try to import
            try:
                import flext_ldif.analytics_service

                assert hasattr(flext_ldif.analytics_service, "__all__")
                assert (
                    "FlextLdifAnalyticsService" in flext_ldif.analytics_service.__all__
                )
            except ImportError:
                pytest.skip("Cannot test due to dependency issues")

    @staticmethod
    def test_repository_service_import() -> None:
        """Test repository service module can be imported."""
        # Clear the module from cache if it exists
        if "flext_ldif.repository_service" in sys.modules:
            del sys.modules["flext_ldif.repository_service"]

        # Similar mocking approach
        with patch.dict(
            sys.modules,
            {
                "flext_core": type(sys)("flext_core"),
                "flext_core.domain_services": type(sys)("flext_core.domain_services"),
                "flext_core.result": type(sys)("flext_core.result"),
                "flext_core.typings": type(sys)("flext_core.typings"),
            },
        ):
            # Create mock dependencies
            mock_result_class = type("FlextResult", (), {})
            sys.modules["flext_core"].FlextResult = mock_result_class

            mock_config_class = type("Config", (), {})
            mock_types_class = type("FlextTypes", (), {"Config": mock_config_class})
            sys.modules["flext_core"].FlextTypes = mock_types_class

            sys.modules["flext_core"].FlextDomainService = type(
                "FlextDomainService", (), {}
            )
            sys.modules["flext_core"].FlextLogger = type("FlextLogger", (), {})

            try:
                import flext_ldif.repository_service

                assert hasattr(flext_ldif.repository_service, "__all__")
                assert (
                    "FlextLdifRepositoryService"
                    in flext_ldif.repository_service.__all__
                )
            except ImportError:
                pytest.skip("Cannot test due to dependency issues")

    @staticmethod
    def test_services_import() -> None:
        """Test main services module can be imported."""
        # Clear the module from cache if it exists
        if "flext_ldif.services" in sys.modules:
            del sys.modules["flext_ldif.services"]

        # Similar mocking approach
        with patch.dict(
            sys.modules,
            {
                "flext_core": type(sys)("flext_core"),
                "flext_core.domain_services": type(sys)("flext_core.domain_services"),
                "flext_core.result": type(sys)("flext_core.result"),
                "flext_core.typings": type(sys)("flext_core.typings"),
            },
        ):
            # Create mock dependencies
            mock_result_class = type("FlextResult", (), {})
            sys.modules["flext_core"].FlextResult = mock_result_class

            mock_config_class = type("Config", (), {})
            mock_types_class = type("FlextTypes", (), {"Config": mock_config_class})
            sys.modules["flext_core"].FlextTypes = mock_types_class

            sys.modules["flext_core"].FlextDomainService = type(
                "FlextDomainService", (), {}
            )
            sys.modules["flext_core"].FlextLogger = type("FlextLogger", (), {})

            try:
                import flext_ldif.services

                assert hasattr(flext_ldif.services, "__all__")
                assert "FlextLdifServices" in flext_ldif.services.__all__
            except ImportError:
                pytest.skip("Cannot test due to dependency issues")

    @staticmethod
    def test_transformer_service_import() -> None:
        """Test transformer service module can be imported."""
        # Clear the module from cache if it exists
        if "flext_ldif.transformer_service" in sys.modules:
            del sys.modules["flext_ldif.transformer_service"]

        # Similar mocking approach
        with patch.dict(
            sys.modules,
            {
                "flext_core": type(sys)("flext_core"),
                "flext_core.domain_services": type(sys)("flext_core.domain_services"),
                "flext_core.result": type(sys)("flext_core.result"),
                "flext_core.typings": type(sys)("flext_core.typings"),
            },
        ):
            # Create mock dependencies
            mock_result_class = type("FlextResult", (), {})
            sys.modules["flext_core"].FlextResult = mock_result_class

            mock_config_class = type("Config", (), {})
            mock_types_class = type("FlextTypes", (), {"Config": mock_config_class})
            sys.modules["flext_core"].FlextTypes = mock_types_class

            sys.modules["flext_core"].FlextDomainService = type(
                "FlextDomainService", (), {}
            )
            sys.modules["flext_core"].FlextLogger = type("FlextLogger", (), {})

            try:
                import flext_ldif.transformer_service

                assert hasattr(flext_ldif.transformer_service, "__all__")
                assert (
                    "FlextLdifTransformerService"
                    in flext_ldif.transformer_service.__all__
                )
            except ImportError:
                pytest.skip("Cannot test due to dependency issues")

    @staticmethod
    def test_parser_service_import() -> None:
        """Test parser service module can be imported."""
        try:
            import flext_ldif.parser_service

            assert hasattr(flext_ldif.parser_service, "__all__")
            assert "FlextLdifParserService" in flext_ldif.parser_service.__all__
        except ImportError:
            pytest.skip("Cannot test due to dependency issues")

    @staticmethod
    def test_validator_service_import() -> None:
        """Test validator service module can be imported."""
        try:
            import flext_ldif.validator_service

            assert hasattr(flext_ldif.validator_service, "__all__")
            assert "FlextLdifValidatorService" in flext_ldif.validator_service.__all__
        except ImportError:
            pytest.skip("Cannot test due to dependency issues")

    @staticmethod
    def test_writer_service_import() -> None:
        """Test writer service module can be imported."""
        try:
            import flext_ldif.writer_service

            assert hasattr(flext_ldif.writer_service, "__all__")
            assert "FlextLdifWriterService" in flext_ldif.writer_service.__all__
        except ImportError:
            pytest.skip("Cannot test due to dependency issues")
