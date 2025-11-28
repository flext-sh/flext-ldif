"""Real service factory for testing - RFC-first architecture.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import tempfile
from pathlib import Path

from flext_ldif import (
    FlextLdifMigrationPipeline,
    FlextLdifParser,
    FlextLdifWriter,
)
from flext_ldif.services.server import FlextLdifServer
from tests.fixtures.typing import GenericFieldsDict


class FlextLdifTestFactory:
    """Unified test service factory - FLEXT pattern compliant.

    Provides RFC-first parsers and services for testing with
    various configuration options.
    """

    class _RfcParserFactory:
        """Nested RFC parser factory."""

        @staticmethod
        def create_ldif_parser(
            params: GenericFieldsDict | None = None,
        ) -> FlextLdifParser:
            """Create unified LDIF parser service.

            Config is accessed via FlextLdifServiceBase.config.ldif (singleton pattern).
            """
            # Note: params ignored - config is accessed via self.config.ldif
            _ = params  # Unused, kept for signature compatibility
            return FlextLdifParser()

        @staticmethod
        def create_schema_parser(
            params: GenericFieldsDict | None = None,
        ) -> FlextLdifParser:
            """Create unified LDIF parser service with schema support.

            Note: Schema parsing is now handled by FlextLdifParser.SchemaParser nested class.
            This method returns the same parser for backward compatibility with tests.
            Config is accessed via FlextLdifServiceBase.config.ldif (singleton pattern).
            """
            # Note: params ignored - config is accessed via self.config.ldif
            _ = params  # Unused, kept for signature compatibility
            return FlextLdifParser()

        @staticmethod
        def create_ldif_writer(
            config: GenericFieldsDict | None = None,
            quirk_registry: FlextLdifServer | None = None,
        ) -> FlextLdifWriter:
            """Create unified LDIF writer service."""
            # WriterService is stateless and uses global registry
            # Config and quirk_registry are fetched at runtime via singletons
            return FlextLdifWriter()

        @staticmethod
        def create_migration_pipeline(
            params: GenericFieldsDict | None = None,
            source_server_type: str = "oid",
            target_server_type: str = "oud",
        ) -> FlextLdifMigrationPipeline:
            """Create migration pipeline service."""
            # Create temporary directories for testing
            temp_dir = Path(tempfile.gettempdir())
            input_dir = temp_dir / "ldif_input"
            output_dir = temp_dir / "ldif_output"
            input_dir.mkdir(exist_ok=True)
            output_dir.mkdir(exist_ok=True)

            return FlextLdifMigrationPipeline(
                input_dir=input_dir,
                output_dir=output_dir,
                mode="simple",
                source_server=source_server_type,
                target_server=target_server_type,
            )

    class _ConfigFactory:
        """Nested configuration factory."""

        @staticmethod
        def create_strict_config() -> GenericFieldsDict:
            """Create strict parsing configuration."""
            return {
                "strict_parsing": True,
                "validate_dn": True,
                "max_entries": 10000,
                "encoding": "utf-8",
                "max_line_length": 76,
            }

        @staticmethod
        def create_lenient_config() -> GenericFieldsDict:
            """Create lenient parsing configuration."""
            return {
                "strict_parsing": False,
                "validate_dn": False,
                "max_entries": 100000,
                "encoding": "utf-8",
                "max_line_length": 1000,
            }

        @staticmethod
        def create_performance_config(max_entries: int = 100000) -> GenericFieldsDict:
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
        ) -> GenericFieldsDict:
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
        quirk_registry: FlextLdifServer | None = None,
    ) -> GenericFieldsDict:
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
            quirk_registry = FlextLdifServer()

        return {
            "ldif_parser": cls._RfcParserFactory.create_ldif_parser(config),
            "schema_parser": cls._RfcParserFactory.create_schema_parser(config),
            "ldif_writer": cls._RfcParserFactory.create_ldif_writer(
                config,
                quirk_registry,
            ),
            "config": config,
            "quirk_registry": quirk_registry,
        }

    @classmethod
    def create_api(
        cls,
        config: GenericFieldsDict | None = None,
        quirk_registry: FlextLdifServer | None = None,
    ) -> GenericFieldsDict:
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
            quirk_registry = FlextLdifServer()

        return {
            "ldif_parser": cls._RfcParserFactory.create_ldif_parser(config),
            "schema_parser": cls._RfcParserFactory.create_schema_parser(config),
            "ldif_writer": cls._RfcParserFactory.create_ldif_writer(
                None,
                quirk_registry,
            ),
            "migration_pipeline": cls._RfcParserFactory.create_migration_pipeline(
                config,
            ),
            "quirk_registry": quirk_registry,
            "config": config,
        }

    @classmethod
    def create_parser(
        cls,
        config: GenericFieldsDict | None = None,
        _registry: FlextLdifServer | None = None,
    ) -> FlextLdifParser:
        """Create parser service with optional config."""
        return cls._RfcParserFactory.create_ldif_parser(config)

    @classmethod
    def create_validator(
        cls,
        config: GenericFieldsDict | None = None,
        _registry: FlextLdifServer | None = None,
    ) -> FlextLdifParser:
        """Create validator service (schema parser) with optional config.

        Note: Schema parsing is now integrated into FlextLdifParser.
        """
        return cls._RfcParserFactory.create_schema_parser(config)

    @classmethod
    def create_writer(
        cls,
        config: GenericFieldsDict | None = None,
        quirk_registry: FlextLdifServer | None = None,
    ) -> FlextLdifWriter:
        """Create writer service with config and quirk registry."""
        return cls._RfcParserFactory.create_ldif_writer(config, quirk_registry)

    @classmethod
    def create_configured_api(
        cls,
        *,
        strict_parsing: bool = True,
        validate_dn: bool = True,
        max_entries: int = 10000,
        encoding: str = "utf-8",
        max_line_length: int = 76,
    ) -> GenericFieldsDict:
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
        cls,
        quirk_registry: FlextLdifServer | None = None,
    ) -> GenericFieldsDict:
        """Create API with lenient parsing."""
        return cls.create_api(
            cls._ConfigFactory.create_lenient_config(),
            quirk_registry,
        )

    @classmethod
    def create_strict_api(
        cls,
        quirk_registry: FlextLdifServer | None = None,
    ) -> GenericFieldsDict:
        """Create API with strict parsing and validation."""
        return cls.create_api(cls._ConfigFactory.create_strict_config(), quirk_registry)

    @classmethod
    def create_performance_api(
        cls,
        max_entries: int = 100000,
        quirk_registry: FlextLdifServer | None = None,
    ) -> GenericFieldsDict:
        """Create API optimized for performance testing."""
        return cls.create_api(
            cls._ConfigFactory.create_performance_config(max_entries),
            quirk_registry,
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
    ) -> GenericFieldsDict:
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
        cls,
        quirk_registry: FlextLdifServer | None = None,
    ) -> GenericFieldsDict:
        """Create all services configured for integration testing."""
        config = cls.create_test_config()

        if quirk_registry is None:
            quirk_registry = FlextLdifServer()

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
        cls,
        quirk_registry: FlextLdifServer | None = None,
    ) -> GenericFieldsDict:
        """Create minimal service set for basic testing."""
        if quirk_registry is None:
            quirk_registry = FlextLdifServer()

        return {
            "api": cls.create_api(quirk_registry=quirk_registry),
            "parser": cls.create_parser(_registry=quirk_registry),
            "quirk_registry": quirk_registry,
        }


# Backward compatibility: expose old name
RealServiceFactory = FlextLdifTestFactory
