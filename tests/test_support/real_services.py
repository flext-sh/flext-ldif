"""Real Service Factory for Testing.

Creates real service instances for functional testing without mocks.
All services are properly configured and use real implementations.


Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextTypes

# object is built-in, no need to import
from flext_ldif import (
    FlextLDIFAPI,
    FlextLDIFModels,
    FlextLDIFServices,
)


class RealServiceFactory:
    """Factory for creating real service instances for testing."""

    @staticmethod
    def create_api(config: FlextTypes.Core.Dict | None = None) -> FlextLDIFAPI:
        """Create a real LDIF API instance."""
        if config is None:
            config = {}

        # Create proper config object
        ldif_config = FlextLDIFModels.Config(
            encoding=config.get("encoding", "utf-8"),
            strict_parsing=config.get("strict_parsing", True),
            validate_dn=config.get("validate_dn", True),
            max_entries=config.get("max_entries", 10000),
            max_line_length=config.get("max_line_length", 76),
        )

        return FlextLDIFAPI(config=ldif_config)

    @staticmethod
    def create_parser(
        config: FlextTypes.Core.Dict | None = None,
    ) -> FlextLDIFServices.ParserService:
        """Create a real parser service."""
        if config is None:
            config = {}

        # Use default configuration or create from provided values
        ldif_config = FlextLDIFModels.Config(
            encoding=config.get("encoding", "utf-8"),
            strict_parsing=config.get("strict_parsing", True),
            validate_dn=config.get("validate_dn", True),
        )

        return FlextLDIFServices(config=ldif_config)

    @staticmethod
    def create_validator(config: FlextTypes.Core.Dict | None = None) -> object:
        """Create a real validator service."""
        if config is None:
            config = {}

        # Create validator with proper configuration
        ldif_config = FlextLDIFModels.Config(
            validate_dn=config.get("validate_dn", True),
            validate_attributes=config.get("validate_attributes", True),
            strict_validation=config.get("strict_validation", True),
        )

        return FlextLDIFServices(config=ldif_config)

    @staticmethod
    def create_writer(config: FlextTypes.Core.Dict | None = None) -> object:
        """Create a real writer service."""
        if config is None:
            config = {}

        ldif_config = FlextLDIFModels.Config(
            encoding=config.get("encoding", "utf-8"),
            max_line_length=config.get("max_line_length", 76),
        )

        return FlextLDIFServices.WriterService(config=ldif_config)

    @classmethod
    def create_configured_api(
        cls,
        *,
        strict_parsing: bool = True,
        validate_dn: bool = True,
        max_entries: int = 10000,
        encoding: str = "utf-8",
        max_line_length: int = 76,
    ) -> FlextLDIFAPI:
        """Create API with specific configuration."""
        config = {
            "strict_parsing": strict_parsing,
            "validate_dn": validate_dn,
            "max_entries": max_entries,
            "encoding": encoding,
            "max_line_length": max_line_length,
        }
        return cls.create_api(config)

    @classmethod
    def create_lenient_api(cls) -> FlextLDIFAPI:
        """Create API with lenient parsing for error testing."""
        return cls.create_configured_api(
            strict_parsing=False,
            validate_dn=False,
        )

    @classmethod
    def create_strict_api(cls) -> FlextLDIFAPI:
        """Create API with strict parsing and validation."""
        return cls.create_configured_api(
            strict_parsing=True,
            validate_dn=True,
        )

    @classmethod
    def create_performance_api(cls, max_entries: int = 100000) -> FlextLDIFAPI:
        """Create API optimized for performance testing."""
        return cls.create_configured_api(
            max_entries=max_entries,
            strict_parsing=False,  # Faster parsing
        )

    @staticmethod
    def create_test_config(
        *,
        encoding: str = "utf-8",
        strict_parsing: bool = True,
        validate_dn: bool = True,
        max_entries: int = 10000,
        max_line_length: int = 76,
        **kwargs: object,
    ) -> FlextLDIFModels.Config:
        """Create a test configuration object."""
        return FlextLDIFModels.Config(
            encoding=encoding,
            strict_parsing=strict_parsing,
            validate_dn=validate_dn,
            max_entries=max_entries,
            max_line_length=max_line_length,
            **kwargs,
        )

    @classmethod
    def services_for_integration_test(cls) -> FlextTypes.Core.Dict:
        """Create all services configured for integration testing."""
        config = cls.create_test_config()

        services = FlextLDIFServices(config=config)
        return {
            "api": FlextLDIFAPI(config=config),
            "parser": services.parser,
            "validator": services.validator,
            "writer": services.writer,
            "config": config,
        }

    @classmethod
    def minimal_services(cls) -> FlextTypes.Core.Dict:
        """Create minimal service set for basic testing."""
        return {
            "api": cls.create_api(),
            "parser": cls.create_parser(),
        }
