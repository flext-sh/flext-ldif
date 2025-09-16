"""Real service factory for testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextTypes

from flext_ldif import (
    FlextLDIFAPI,
    FlextLDIFServices,
)
from flext_ldif.config import FlextLDIFConfig
from flext_ldif.parser_service import FlextLDIFParserService
from flext_ldif.validator_service import FlextLDIFValidatorService
from flext_ldif.writer_service import FlextLDIFWriterService


class RealServiceFactory:
    """Factory for creating real service instances for testing."""

    @staticmethod
    def create_api(config: FlextTypes.Core.Dict | None = None) -> FlextLDIFAPI:
        """Create a real LDIF API instance."""
        if config is None:
            config = {}

        # Create proper config object
        ldif_config = FlextLDIFConfig(
            ldif_encoding=config.get("encoding", "utf-8"),
            ldif_strict_validation=config.get("strict_parsing", True),
            ldif_validate_dn_format=config.get("validate_dn", True),
            ldif_max_entries=config.get("max_entries", 10000),
            ldif_max_line_length=config.get("max_line_length", 76),
        )

        return FlextLDIFAPI(config=ldif_config)

    @staticmethod
    def create_parser(
        config: FlextTypes.Core.Dict | None = None,
    ) -> FlextLDIFParserService:
        """Create a real parser service."""
        if config is None:
            config = {}

        # Use default configuration or create from provided values
        # Configuration is handled internally by the service
        return FlextLDIFParserService()

    @staticmethod
    def create_validator(
        config: FlextTypes.Core.Dict | None = None,
    ) -> FlextLDIFValidatorService:
        """Create a real validator service."""
        if config is None:
            config = {}

        # Create validator with proper configuration
        # Configuration is handled internally by the service
        return FlextLDIFValidatorService()

    @staticmethod
    def create_writer(
        config: FlextTypes.Core.Dict | None = None,
    ) -> FlextLDIFWriterService:
        """Create a real writer service."""
        if config is None:
            config = {}

        # Configuration is handled internally by the service
        return FlextLDIFWriterService()

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
    ) -> FlextLDIFConfig:
        """Create a test configuration object."""
        # Map old parameter names to new FlextLDIFConfig parameter names
        return FlextLDIFConfig(
            ldif_encoding=encoding,
            ldif_strict_validation=strict_parsing,
            ldif_validate_dn_format=validate_dn,
            ldif_max_entries=max_entries,
            ldif_max_line_length=max_line_length,
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
