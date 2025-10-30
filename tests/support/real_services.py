"""Real service factory for testing - RFC-first architecture.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.config import FlextLdifConfig
from flext_ldif.services.migration_pipeline import FlextLdifMigrationPipeline
from flext_ldif.services.parser import FlextLdifParserService
from flext_ldif.services.registry import FlextLdifRegistry
from flext_ldif.services.writer import FlextLdifWriterService


class FlextLdifTestServiceFactory:
    """Unified test service factory - FLEXT pattern compliant.

    Provides RFC-first parsers and services for testing with
    various configuration options.
    """

    class _RfcParserFactory:
        """Nested RFC parser factory."""

        @staticmethod
        def create_ldif_parser(
            params: dict[str, object] | None = None,
        ) -> FlextLdifParserService:
            """Create unified LDIF parser service with optional config."""
            config = FlextLdifConfig() if params is None else FlextLdifConfig(**params)
            return FlextLdifParserService(config=config)

        @staticmethod
        def create_schema_parser(
            params: dict[str, object] | None = None,
        ) -> FlextLdifParserService:
            """Create unified LDIF parser service with schema support.

            Note: Schema parsing is now handled by FlextLdifParserService.SchemaParser nested class.
            This method returns the same parser for backward compatibility with tests.
            """
            config = FlextLdifConfig() if params is None else FlextLdifConfig(**params)
            return FlextLdifParserService(config=config)

        @staticmethod
        def create_ldif_writer(
            quirk_registry: FlextLdifRegistry | None = None,
        ) -> FlextLdifWriterService:
            """Create unified LDIF writer with mandatory quirk registry."""
            if quirk_registry is None:
                quirk_registry = FlextLdifRegistry()
            config = FlextLdifConfig()
            return FlextLdifWriterService(config=config, quirk_registry=quirk_registry)

        @staticmethod
        def create_migration_pipeline(
            params: dict[str, object] | None = None,
            source_server_type: str = "oid",
            target_server_type: str = "oud",
        ) -> FlextLdifMigrationPipeline:
            """Create migration pipeline service."""
            return FlextLdifMigrationPipeline(
                params=params or {},
                source_server_type=source_server_type,
                target_server_type=target_server_type,
            )

    class _ConfigFactory:
        """Nested configuration factory."""

        @staticmethod
        def create_strict_config() -> dict[str, object]:
            """Create strict parsing configuration."""
            return {
                "strict_parsing": True,
                "validate_dn": True,
                "max_entries": 10000,
                "encoding": "utf-8",
                "max_line_length": 76,
            }

        @staticmethod
        def create_lenient_config() -> dict[str, object]:
            """Create lenient parsing configuration."""
            return {
                "strict_parsing": False,
                "validate_dn": False,
                "max_entries": 100000,
                "encoding": "utf-8",
                "max_line_length": 1000,
            }

        @staticmethod
        def create_performance_config(max_entries: int = 100000) -> dict[str, object]:
            """Create performance-optimized configuration."""
            return {
                "strict_parsing": False,
                "validate_dn": False,
                "max_entries": max_entries,
                "encoding": "utf-8",
                "max_line_length": 1000,
            }

        @staticmethod
        def create_test_config(
            *,
            encoding: str = "utf-8",
            strict_parsing: bool = True,
            validate_dn: bool = True,
            max_entries: int = 10000,
            max_line_length: int = 76,
        ) -> dict[str, object]:
            """Create custom test configuration."""
            return {
                "encoding": encoding,
                "strict_parsing": strict_parsing,
                "validate_dn": validate_dn,
                "max_entries": max_entries,
                "max_line_length": max_line_length,
            }

    @classmethod
    def create_test_services(
        cls,
        config_type: str = "strict",
        quirk_registry: FlextLdifRegistry | None = None,
    ) -> dict[str, object]:
        """Create complete service set for testing.

        Args:
            config_type: 'strict', 'lenient', or 'performance'
            quirk_registry: Quirk registry for RFC-first architecture (auto-created if None)

        Returns:
            Dict with parsers, writers, and configuration

        """
        if config_type == "strict":
            config = cls._ConfigFactory.create_strict_config()
        elif config_type == "lenient":
            config = cls._ConfigFactory.create_lenient_config()
        elif config_type == "performance":
            config = cls._ConfigFactory.create_performance_config()
        else:
            config = cls._ConfigFactory.create_strict_config()

        if quirk_registry is None:
            quirk_registry = FlextLdifRegistry()

        return {
            "ldif_parser": cls._RfcParserFactory.create_ldif_parser(config),
            "schema_parser": cls._RfcParserFactory.create_schema_parser(config),
            "ldif_writer": cls._RfcParserFactory.create_ldif_writer(
                config, quirk_registry
            ),
            "config": config,
            "quirk_registry": quirk_registry,
        }

    @classmethod
    def create_api(
        cls,
        config: dict[str, object] | None = None,
        quirk_registry: FlextLdifRegistry | None = None,
    ) -> dict[str, object]:
        """Create unified service API for backward compatibility.

        Args:
            config: Configuration dict[str, object] (auto-created if None)
            quirk_registry: Quirk registry for RFC-first architecture (auto-created if None)

        Returns:
            Dict with all services (ldif_parser, schema_parser, writer)

        """
        if config is None:
            config = cls._ConfigFactory.create_strict_config()

        if quirk_registry is None:
            quirk_registry = FlextLdifRegistry()

        return {
            "ldif_parser": cls._RfcParserFactory.create_ldif_parser(config),
            "schema_parser": cls._RfcParserFactory.create_schema_parser(config),
            "ldif_writer": cls._RfcParserFactory.create_ldif_writer(
                config, quirk_registry
            ),
            "migration_pipeline": cls._RfcParserFactory.create_migration_pipeline(
                config
            ),
            "quirk_registry": quirk_registry,
            "config": config,
        }

    @classmethod
    def create_parser(
        cls,
        config: dict[str, object] | None = None,
        _quirk_registry: FlextLdifRegistry | None = None,
    ) -> FlextLdifParserService:
        """Create parser service with optional config."""
        return cls._RfcParserFactory.create_ldif_parser(config)

    @classmethod
    def create_validator(
        cls,
        config: dict[str, object] | None = None,
        _quirk_registry: FlextLdifRegistry | None = None,
    ) -> FlextLdifParserService:
        """Create validator service (schema parser) with optional config.

        Note: Schema parsing is now integrated into FlextLdifParserService.
        """
        return cls._RfcParserFactory.create_schema_parser(config)

    @classmethod
    def create_writer(
        cls,
        config: dict[str, object] | None = None,
        quirk_registry: FlextLdifRegistry | None = None,
    ) -> FlextLdifWriterService:
        """Create writer service with quirk registry."""
        return cls._RfcParserFactory.create_ldif_writer(quirk_registry)

    @classmethod
    def create_configured_api(
        cls,
        *,
        strict_parsing: bool = True,
        validate_dn: bool = True,
        max_entries: int = 10000,
        encoding: str = "utf-8",
        max_line_length: int = 76,
    ) -> dict[str, object]:
        """Create API with specific configuration."""
        config = cls._ConfigFactory.create_test_config(
            encoding=encoding,
            strict_parsing=strict_parsing,
            validate_dn=validate_dn,
            max_entries=max_entries,
            max_line_length=max_line_length,
        )
        return cls.create_api(config)

    @classmethod
    def create_lenient_api(
        cls, quirk_registry: FlextLdifRegistry | None = None
    ) -> dict[str, object]:
        """Create API with lenient parsing."""
        return cls.create_api(
            cls._ConfigFactory.create_lenient_config(), quirk_registry
        )

    @classmethod
    def create_strict_api(
        cls, quirk_registry: FlextLdifRegistry | None = None
    ) -> dict[str, object]:
        """Create API with strict parsing and validation."""
        return cls.create_api(cls._ConfigFactory.create_strict_config(), quirk_registry)

    @classmethod
    def create_performance_api(
        cls,
        max_entries: int = 100000,
        quirk_registry: FlextLdifRegistry | None = None,
    ) -> dict[str, object]:
        """Create API optimized for performance testing."""
        return cls.create_api(
            cls._ConfigFactory.create_performance_config(max_entries), quirk_registry
        )

    @classmethod
    def create_test_config(
        cls,
        *,
        encoding: str = "utf-8",
        strict_parsing: bool = True,
        validate_dn: bool = True,
        max_entries: int = 10000,
        max_line_length: int = 76,
    ) -> dict[str, object]:
        """Create test configuration object."""
        return cls._ConfigFactory.create_test_config(
            encoding=encoding,
            strict_parsing=strict_parsing,
            validate_dn=validate_dn,
            max_entries=max_entries,
            max_line_length=max_line_length,
        )

    @classmethod
    def services_for_integration_test(
        cls, quirk_registry: FlextLdifRegistry | None = None
    ) -> dict[str, object]:
        """Create all services configured for integration testing."""
        config = cls.create_test_config()

        if quirk_registry is None:
            quirk_registry = FlextLdifRegistry()

        return {
            "api": cls.create_api(config, quirk_registry),
            "parser": cls.create_parser(config, quirk_registry),
            "validator": cls.create_validator(config, quirk_registry),
            "writer": cls.create_writer(config, quirk_registry),
            "config": config,
            "quirk_registry": quirk_registry,
        }

    @classmethod
    def minimal_services(
        cls, quirk_registry: FlextLdifRegistry | None = None
    ) -> dict[str, object]:
        """Create minimal service set for basic testing."""
        if quirk_registry is None:
            quirk_registry = FlextLdifRegistry()

        return {
            "api": cls.create_api(quirk_registry=quirk_registry),
            "parser": cls.create_parser(quirk_registry=quirk_registry),
            "quirk_registry": quirk_registry,
        }


# Backward compatibility: expose old name
RealServiceFactory = FlextLdifTestServiceFactory
