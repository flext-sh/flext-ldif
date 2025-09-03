"""Real Service Factory for Testing.

Creates real service instances for functional testing without mocks.
All services are properly configured and use real implementations.
"""

from __future__ import annotations

from typing import Any

from flext_ldif import (
    FlextLDIFAPI,
    FlextLDIFConfig,
    FlextLDIFParserService,
    FlextLDIFServices,
    FlextLDIFValidatorService,
    FlextLDIFWriterService,
)


class RealServiceFactory:
    """Factory for creating real service instances for testing."""

    @staticmethod
    def create_api(config: dict[str, Any] | None = None) -> FlextLDIFAPI:
        """Create a real LDIF API instance."""
        if config is None:
            config = {}

        # Create proper config object
        ldif_config = FlextLDIFConfig(
            encoding=config.get("encoding", "utf-8"),
            strict_parsing=config.get("strict_parsing", True),
            validate_dn=config.get("validate_dn", True),
            max_entries=config.get("max_entries", 10000),
            max_line_length=config.get("max_line_length", 76),
        )

        return FlextLDIFAPI(config=ldif_config)

    @staticmethod
    def create_parser(config: dict[str, Any] | None = None) -> FlextLDIFServices.ParserService:
        """Create a real parser service."""
        if config is None:
            config = {}

        # Use default configuration or create from provided values
        ldif_config = FlextLDIFConfig(
            encoding=config.get("encoding", "utf-8"),
            strict_parsing=config.get("strict_parsing", True),
            validate_dn=config.get("validate_dn", True),
        )

        return FlextLDIFParserService(config=ldif_config)

    @staticmethod
    def create_validator(config: dict[str, Any] | None = None):
        """Create a real validator service."""
        if config is None:
            config = {}

        # Create validator with proper configuration
        ldif_config = FlextLDIFConfig(
            validate_dn=config.get("validate_dn", True),
            validate_attributes=config.get("validate_attributes", True),
            strict_validation=config.get("strict_validation", True),
        )

        return FlextLDIFServices.ValidatorService(config=ldif_config)

    @staticmethod
    def create_writer(config: dict[str, Any] | None = None):
        """Create a real writer service."""
        if config is None:
            config = {}

        ldif_config = FlextLDIFConfig(
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
        **kwargs: Any,
    ) -> FlextLDIFConfig:
        """Create a test configuration object."""
        return FlextLDIFConfig(
            encoding=encoding,
            strict_parsing=strict_parsing,
            validate_dn=validate_dn,
            max_entries=max_entries,
            max_line_length=max_line_length,
            **kwargs,
        )

    @classmethod
    def services_for_integration_test(cls) -> dict[str, Any]:
        """Create all services configured for integration testing."""
        config = cls.create_test_config()

        return {
            "api": FlextLDIFAPI(config=config),
            "parser": FlextLDIFParserService(config=config),
            "validator": FlextLDIFValidatorService(config=config),
            "writer": FlextLDIFWriterService(config=config),
            "config": config,
        }

    @classmethod
    def minimal_services(cls) -> dict[str, Any]:
        """Create minimal service set for basic testing."""
        return {
            "api": cls.create_api(),
            "parser": cls.create_parser(),
        }
