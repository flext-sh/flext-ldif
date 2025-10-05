"""FLEXT-LDIF Client - Main Implementation for LDIF Operations.

This module contains the core implementation logic for LDIF processing,
extracted from the thin facade API. It provides the actual business logic
for parsing, writing, validation, migration, and analysis operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

from flext_core import (
    FlextBus,
    FlextContainer,
    FlextContext,
    FlextLogger,
    FlextResult,
    FlextService,
    FlextTypes,
)

from flext_ldif.config import FlextLdifConfig
from flext_ldif.handlers import FlextLdifHandlers
from flext_ldif.migration_pipeline import LdifMigrationPipelineService
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.registry import QuirkRegistryService
from flext_ldif.quirks.servers import (
    AdSchemaQuirk,
    ApacheSchemaQuirk,
    Ds389SchemaQuirk,
    NovellSchemaQuirk,
    OidSchemaQuirk,
    OpenLdap1SchemaQuirk,
    OpenLdapSchemaQuirk,
    OudSchemaQuirk,
    TivoliSchemaQuirk,
)
from flext_ldif.rfc.rfc_ldif_parser import RfcLdifParserService
from flext_ldif.rfc.rfc_ldif_writer import RfcLdifWriterService
from flext_ldif.rfc.rfc_schema_parser import RfcSchemaParserService
from flext_ldif.schema.validator import FlextLdifSchemaValidator


class FlextLdifClient(FlextService[FlextTypes.Dict]):
    """Main client implementation for LDIF processing operations.

    This class contains all the actual business logic for LDIF operations,
    providing a clean separation between the thin API facade and the
    implementation details.

    The client manages:
    - Service initialization and dependency injection
    - CQRS handler setup and orchestration
    - Default quirk registration
    - Business logic delegation to appropriate services

    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize LDIF client with optional configuration.

        Args:
            config: Optional LDIF configuration. If not provided,
                   uses global singleton instance.

        """
        super().__init__()
        self._config = config or FlextLdifConfig()
        self._container = FlextContainer.get_global()
        # FlextContext expects dict, not FlextLdifConfig directly
        self._context = FlextContext({"config": self._config})
        self._bus = FlextBus()
        self._logger = FlextLogger(__name__)

        # Ensure components are not None for type safety
        if self._container is None:
            msg = "FlextContainer must be initialized"
            raise RuntimeError(msg)
        if self._context is None:
            msg = "FlextContext must be initialized"
            raise RuntimeError(msg)
        if self._bus is None:
            msg = "FlextBus must be initialized"
            raise RuntimeError(msg)
        if self._logger is None:
            msg = "FlextLogger must be initialized"
            raise RuntimeError(msg)

        # Register services in container for DI
        self._setup_services()

        # Register default quirks for all servers
        self._register_default_quirks()

        # Initialize CQRS handlers
        self._handlers = self._initialize_handlers()

        logger = cast("FlextLogger", self._logger)
        logger.info(
            "Initialized FlextLdif client with CQRS handlers and default quirks"
        )

    def execute(self) -> FlextResult[FlextTypes.Dict]:
        """Execute client self-check and return status.

        Returns:
            FlextResult containing client status and configuration

        """
        try:
            config = cast("FlextLdifConfig", self._config)
            return FlextResult[FlextTypes.Dict].ok({
                "status": "initialized",
                "handlers": list(self._handlers.keys()),
                "config": {"default_encoding": config.ldif_encoding},
            })
        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(f"Client status check failed: {e}")

    # =========================================================================
    # PRIVATE: Service Setup and Handler Initialization
    # =========================================================================

    def _setup_services(self) -> None:
        """Register all services in the dependency injection container with instances."""
        container = cast("FlextContainer", self._container)

        # Register quirk registry FIRST (required by RFC parsers/writers)
        quirk_registry = QuirkRegistryService()
        container.register("quirk_registry", quirk_registry)

        # Register RFC-first parser instance (quirks handle server-specific behavior)
        rfc_parser = RfcLdifParserService(params={}, quirk_registry=quirk_registry)
        container.register("rfc_parser", rfc_parser)

        # Register RFC writer instance
        rfc_writer = RfcLdifWriterService(params={}, quirk_registry=quirk_registry)
        container.register("rfc_writer", rfc_writer)

        # Register schema services
        rfc_schema_parser = RfcSchemaParserService(
            params={}, quirk_registry=quirk_registry
        )
        container.register("rfc_schema_parser", rfc_schema_parser)
        container.register("schema_validator", FlextLdifSchemaValidator())

        # Register migration pipeline (params provided at call time by handlers)
        container.register(
            "migration_pipeline",
            lambda params=None,
            source="oid",
            target="oud": LdifMigrationPipelineService(
                params=params or {},
                source_server_type=source,
                target_server_type=target,
            ),
        )

    def _register_default_quirks(self) -> None:
        """Auto-register all default server quirks."""
        container = cast("FlextContainer", self._container)
        logger = cast("FlextLogger", self._logger)

        # Get quirk registry from container
        registry_result = container.get("quirk_registry")
        if registry_result.is_failure:
            logger.warning(
                "Quirk registry not available, skipping default quirk registration"
            )
            return

        registry = registry_result.unwrap()
        if not isinstance(registry, QuirkRegistryService):
            logger.warning(
                "Quirk registry not available, skipping default quirk registration"
            )
            return

        # Register complete implementations
        complete_quirks = [
            OidSchemaQuirk(server_type="oid", priority=10),
            OudSchemaQuirk(server_type="oud", priority=10),
            OpenLdapSchemaQuirk(server_type="openldap2", priority=10),
            OpenLdap1SchemaQuirk(server_type="openldap1", priority=20),
        ]

        # Register stub implementations (for future completion)
        stub_quirks = [
            AdSchemaQuirk(server_type="active_directory", priority=15),
            ApacheSchemaQuirk(server_type="apache_directory", priority=15),
            Ds389SchemaQuirk(server_type="389ds", priority=15),
            NovellSchemaQuirk(server_type="novell_edirectory", priority=15),
            TivoliSchemaQuirk(server_type="ibm_tivoli", priority=15),
        ]

        all_quirks = complete_quirks + stub_quirks

        # Register schema quirks and their nested ACL/Entry quirks
        for schema_quirk in all_quirks:
            # Register schema quirk
            schema_result = registry.register_schema_quirk(schema_quirk)
            if schema_result.is_failure:
                logger.error(f"Failed to register schema quirk: {schema_result.error}")
                continue

            # Register nested ACL quirk if it exists
            if hasattr(schema_quirk, "AclQuirk"):
                try:
                    acl_quirk = schema_quirk.AclQuirk(
                        server_type=schema_quirk.server_type,
                        priority=schema_quirk.priority,
                    )
                    acl_result = registry.register_acl_quirk(acl_quirk)
                    if acl_result.is_failure:
                        logger.error(
                            f"Failed to register ACL quirk: {acl_result.error}"
                        )
                except Exception:
                    logger.exception("Failed to instantiate ACL quirk")

            # Register nested Entry quirk if it exists
            if hasattr(schema_quirk, "EntryQuirk"):
                try:
                    entry_quirk = schema_quirk.EntryQuirk(
                        server_type=schema_quirk.server_type,
                        priority=schema_quirk.priority,
                    )
                    entry_result = registry.register_entry_quirk(entry_quirk)
                    if entry_result.is_failure:
                        logger.error(
                            f"Failed to register entry quirk: {entry_result.error}"
                        )
                except Exception:
                    logger.exception("Failed to instantiate entry quirk")

        logger.info(
            f"Registered {len(complete_quirks)} complete quirks and {len(stub_quirks)} stub quirks"
        )

    def _initialize_handlers(self) -> FlextTypes.Dict:
        """Initialize CQRS handlers using FlextRegistry.

        Returns:
            Dictionary mapping operation names to handler instances

        """
        context = cast("FlextContext", self._context)
        container = cast("FlextContainer", self._container)
        bus = cast("FlextBus", self._bus)
        logger = cast("FlextLogger", self._logger)

        # Register all handlers using FlextRegistry
        registration_result = FlextLdifHandlers.register_all_handlers(
            context, container, bus
        )

        if registration_result.is_success:
            summary = registration_result.unwrap()
            logger.info(
                f"Registered {summary['handlers_registered']} CQRS handlers via FlextRegistry"
            )

        # Return initialized handler instances
        return {
            "parse": FlextLdifHandlers.ParseQueryHandler(context, container, bus),
            "validate": FlextLdifHandlers.ValidateQueryHandler(context, container, bus),
            "analyze": FlextLdifHandlers.AnalyzeQueryHandler(context, container, bus),
            "write": FlextLdifHandlers.WriteCommandHandler(context, container, bus),
            "migrate": FlextLdifHandlers.MigrateCommandHandler(context, container, bus),
            "register_quirk": FlextLdifHandlers.RegisterQuirkCommandHandler(
                context, container, bus
            ),
        }

    # =========================================================================
    # BUSINESS LOGIC METHODS
    # =========================================================================

    def parse_ldif(
        self, source: str | Path, server_type: str = "rfc"
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        r"""Parse LDIF from file or content string.

        Args:
            source: Either a file path (Path object) or LDIF content string
            server_type: Server type for quirk selection ("rfc", "oid", "oud", etc.)

        Returns:
            FlextResult with list of parsed Entry models

        """
        # Create query and delegate to handler
        # Convert Path to string if necessary
        source_str = str(source) if isinstance(source, Path) else source
        query = FlextLdifModels.ParseQuery(
            source=source_str,
            format=server_type if server_type in {"rfc", "oid", "auto"} else "auto",
            encoding="utf-8",
            strict=True,
        )
        handler = cast("FlextLdifHandlers.ParseQueryHandler", self._handlers["parse"])
        return handler.handle(query)

    def write_ldif(
        self,
        entries: list[FlextLdifModels.Entry],
        output_path: Path | None = None,
    ) -> FlextResult[str]:
        """Write entries to LDIF format string or file.

        Args:
            entries: List of LDIF entries to write
            output_path: Optional path to write LDIF file. If None, returns LDIF string.

        Returns:
            FlextResult containing LDIF content as string (if output_path is None)
            or success message (if output_path provided)

        """
        # Create command and delegate to handler
        command = FlextLdifModels.WriteCommand(
            entries=entries,
            format="rfc",
            output=str(output_path) if output_path else None,
            line_width=76,
        )
        handler = cast("FlextLdifHandlers.WriteCommandHandler", self._handlers["write"])
        return handler.handle(command)

    def validate_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[FlextTypes.Dict]:
        """Validate LDIF entries against RFC and business rules.

        Args:
            entries: List of entries to validate

        Returns:
            FlextResult containing validation report with details

        """
        # Create query and delegate to handler
        query = FlextLdifModels.ValidateQuery(
            entries=entries, schema_config=None, strict=True
        )
        handler = cast(
            "FlextLdifHandlers.ValidateQueryHandler", self._handlers["validate"]
        )
        result = handler.handle(query)

        # Return validation result as dictionary for consistent API
        if result.is_success:
            validation_result = result.unwrap()
            return FlextResult[FlextTypes.Dict].ok({
                "is_valid": validation_result.is_valid,
                "total_entries": len(entries),
                "valid_entries": len(entries) - len(validation_result.errors),
                "invalid_entries": len(validation_result.errors),
                "errors": validation_result.errors,
            })
        return FlextResult[FlextTypes.Dict].fail(result.error or "Validation failed")

    def migrate_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        from_server: str,
        to_server: str,
    ) -> FlextResult[FlextTypes.Dict]:
        """Migrate LDIF entries between different server types.

        Args:
            entries: List of entries to migrate
            from_server: Source server type ("oid", "oud", "openldap", etc.)
            to_server: Target server type

        Returns:
            FlextResult containing migration statistics

        """
        # Create command and delegate to handler
        command = FlextLdifModels.MigrateCommand(
            entries=entries,
            source_format=from_server,
            target_format=to_server,
            options=None,
        )
        handler = cast(
            "FlextLdifHandlers.MigrateCommandHandler", self._handlers["migrate"]
        )
        return handler.handle(command)

    def migrate_files(
        self,
        input_dir: Path,
        output_dir: Path,
        from_server: str,
        to_server: str,
        *,
        process_schema: bool = True,
        process_entries: bool = True,
    ) -> FlextResult[FlextTypes.Dict]:
        """Migrate LDIF data between different LDAP server types from files.

        Args:
            input_dir: Directory containing source LDIF files
            output_dir: Directory for migrated LDIF files
            from_server: Source server type ("oid", "oud", "openldap", etc.)
            to_server: Target server type
            process_schema: Whether to process schema files
            process_entries: Whether to process entry files

        Returns:
            FlextResult containing migration statistics and output files

        """
        try:
            params = {
                "input_dir": str(input_dir),
                "output_dir": str(output_dir),
                "process_schema": process_schema,
                "process_entries": process_entries,
            }

            pipeline = LdifMigrationPipelineService(
                params=params,
                source_server_type=from_server,
                target_server_type=to_server,
            )

            migration_result = pipeline.execute()

            if migration_result.is_failure:
                return FlextResult[FlextTypes.Dict].fail(
                    migration_result.error or "Migration failed"
                )

            return FlextResult[FlextTypes.Dict].ok(migration_result.unwrap())

        except Exception as e:
            logger = cast("FlextLogger", self._logger)
            logger.exception("Migration failed")
            return FlextResult[FlextTypes.Dict].fail(f"Migration failed: {e}")

    def analyze_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[FlextTypes.Dict]:
        """Analyze LDIF entries and generate statistics.

        Args:
            entries: List of entries to analyze

        Returns:
            FlextResult containing analysis statistics

        """
        # Create query and delegate to handler
        query = FlextLdifModels.AnalyzeQuery(
            entries=entries, metrics=None, include_patterns=True
        )
        handler = cast(
            "FlextLdifHandlers.AnalyzeQueryHandler", self._handlers["analyze"]
        )
        result = handler.handle(query)

        # Return analytics result as dictionary for consistent API
        if result.is_success:
            analytics = result.unwrap()
            return FlextResult[FlextTypes.Dict].ok({
                "total_entries": analytics.total_entries,
                "object_class_distribution": analytics.object_class_distribution,
                "patterns_detected": analytics.patterns_detected,
            })
        return FlextResult[FlextTypes.Dict].fail(result.error or "Analysis failed")

    def filter_by_objectclass(
        self, entries: list[FlextLdifModels.Entry], objectclass: str
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries by object class.

        Args:
            entries: List of LDIF entries to filter
            objectclass: Object class to filter by

        Returns:
            FlextResult containing filtered entries

        """
        try:
            filtered = [
                entry
                for entry in entries
                if any(
                    attr.lower() == "objectclass" and objectclass.lower() in values
                    for attr, values in entry.attributes.items()
                )
            ]
            return FlextResult[list[FlextLdifModels.Entry]].ok(filtered)
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Filter failed: {e}")

    def filter_persons(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Filter entries to get only person entries.

        Args:
            entries: List of LDIF entries to filter

        Returns:
            FlextResult containing person entries

        """
        return self.filter_by_objectclass(entries, "person")

    # =========================================================================
    # QUIRKS MANAGEMENT
    # =========================================================================

    def register_quirk(
        self,
        quirk: object,
        quirk_type: str = "schema",
    ) -> FlextResult[None]:
        """Register a custom quirk for server-specific processing.

        Args:
            quirk: Quirk instance to register
            quirk_type: Type of quirk ("schema", "acl", "entry")

        Returns:
            FlextResult indicating success or failure

        """
        # Validate quirk_type
        if quirk_type not in {"schema", "acl", "entry"}:
            return FlextResult[None].fail(f"Invalid quirk type: {quirk_type}")

        # Create command and delegate to handler
        # Cast quirk_type to string for command (validated above)
        command = FlextLdifModels.RegisterQuirkCommand(
            quirk_type=str(quirk_type),
            quirk_impl=quirk,
            override=False,
        )
        handler = cast(
            "FlextLdifHandlers.RegisterQuirkCommandHandler",
            self._handlers["register_quirk"],
        )
        return handler.handle(command)

    # =========================================================================
    # INFRASTRUCTURE ACCESS
    # =========================================================================

    @property
    def config(self) -> FlextLdifConfig:
        """Access to LDIF configuration instance."""
        return cast("FlextLdifConfig", self._config)

    @property
    def handlers(self) -> FlextTypes.Dict:
        """Access to initialized CQRS handlers."""
        return self._handlers

    @property
    def container(self) -> FlextContainer:
        """Access to dependency injection container."""
        return cast("FlextContainer", self._container)

    @property
    def context(self) -> FlextContext:
        """Access to execution context."""
        return cast("FlextContext", self._context)

    @property
    def bus(self) -> FlextBus:
        """Access to event bus."""
        return cast("FlextBus", self._bus)

    @property
    def logger(self) -> FlextLogger:
        """Access to logger."""
        return cast("FlextLogger", self._logger)
