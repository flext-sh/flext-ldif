"""FLEXT LDIF API - Main Facade for all LDIF Operations.

This module provides the primary entry point for all LDIF processing operations.
The FlextLdif class serves as a thin facade exposing all functionality through
a clean, unified interface.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import cast, override

from flext_core import (
    FlextBus,
    FlextContainer,
    FlextContext,
    FlextLogger,
    FlextResult,
    FlextService,
)
from flext_ldif.acl.service import FlextLdifAclService
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.entry.builder import FlextLdifEntryBuilder
from flext_ldif.exceptions import FlextLdifExceptions
from flext_ldif.handlers import FlextLdifHandlers
from flext_ldif.migration_pipeline import LdifMigrationPipelineService
from flext_ldif.mixins import FlextLdifMixins
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
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
from flext_ldif.schema.builder import FlextLdifSchemaBuilder
from flext_ldif.schema.validator import FlextLdifSchemaValidator
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdif(FlextService[dict[str, object]]):
    r"""Main facade for all LDIF processing operations.

    Provides unified access to:
    - RFC-compliant LDIF parsing and writing
    - Server-specific quirks and migrations
    - Validation and analytics
    - All infrastructure (Models, Config, Constants, etc.)

    This class follows the Facade pattern, providing a simplified interface
    to the complex subsystem of LDIF processing services.

    Example:
        # Basic usage
        ldif = FlextLdif()

        # Parse LDIF content
        result = ldif.parse("dn: cn=test,dc=example,dc=com\ncn: test\n")
        if result.is_success:
            entries = result.unwrap()

        # Write LDIF entries
        write_result = ldif.write(entries)

        # Migrate between servers
        migration_result = ldif.migrate(
            entries=entries,
            from_server="oid",
            to_server="oud"
        )

        # Access infrastructure
        config = ldif.Config
        models = ldif.Models
        entry = ldif.Models.Entry(dn="cn=test", attributes={})

    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize LDIF facade with optional configuration.

        Args:
            config: Optional LDIF configuration. If not provided,
                   uses global singleton instance.

        """
        super().__init__()
        self._config = config or FlextLdifConfig.get_global_instance()
        self._container = FlextContainer.get_global()
        # FlextContext expects dict, not FlextLdifConfig directly
        self._context = FlextContext({"config": self._config})
        self._bus = FlextBus()
        self._logger = FlextLogger(__name__)

        # Register services in container for DI
        self._setup_services()

        # Register default quirks for all servers
        self._register_default_quirks()

        # Initialize CQRS handlers
        self._handlers = self._initialize_handlers()

        self._logger.info(
            "Initialized FlextLdif facade with CQRS handlers and default quirks"
        )

    @override
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute facade self-check and return status.

        FlextLdif is a facade, not a typical service. This execute method
        performs a self-check and returns configuration status.

        Returns:
            FlextResult containing facade status and configuration

        """
        try:
            return FlextResult[dict[str, object]].ok({
                "status": "initialized",
                "handlers": list(self._handlers.keys()),
                "config": {"default_encoding": self._config.ldif_encoding},
            })
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Facade status check failed: {e}"
            )

    # =========================================================================
    # PRIVATE: Service Setup and Handler Initialization
    # =========================================================================

    def _setup_services(self) -> None:
        """Register all services in the dependency injection container with instances."""
        # Register quirk registry FIRST (required by RFC parsers/writers)
        quirk_registry = QuirkRegistryService()
        self._container.register("quirk_registry", quirk_registry)

        # Register RFC-first parser instance (quirks handle server-specific behavior)
        rfc_parser = RfcLdifParserService(params={}, quirk_registry=quirk_registry)
        self._container.register("rfc_parser", rfc_parser)

        # Register RFC writer instance
        rfc_writer = RfcLdifWriterService(params={}, quirk_registry=quirk_registry)
        self._container.register("rfc_writer", rfc_writer)

        # Register schema services
        rfc_schema_parser = RfcSchemaParserService(
            params={}, quirk_registry=quirk_registry
        )
        self._container.register("rfc_schema_parser", rfc_schema_parser)
        self._container.register("schema_validator", FlextLdifSchemaValidator())

        # Register migration pipeline (params provided at call time by handlers)
        self._container.register(
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
        # Get quirk registry from container
        registry_result = self._container.get("quirk_registry")
        if registry_result.is_failure:
            self._logger.warning(
                "Quirk registry not available, skipping default quirk registration"
            )
            return

        registry = registry_result.unwrap()
        if not isinstance(registry, QuirkRegistryService):
            self._logger.warning(
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
                self._logger.error(
                    f"Failed to register schema quirk: {schema_result.error}"
                )
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
                        self._logger.error(
                            f"Failed to register ACL quirk: {acl_result.error}"
                        )
                except Exception:
                    self._logger.exception("Failed to instantiate ACL quirk")

            # Register nested Entry quirk if it exists
            if hasattr(schema_quirk, "EntryQuirk"):
                try:
                    entry_quirk = schema_quirk.EntryQuirk(
                        server_type=schema_quirk.server_type,
                        priority=schema_quirk.priority,
                    )
                    entry_result = registry.register_entry_quirk(entry_quirk)
                    if entry_result.is_failure:
                        self._logger.error(
                            f"Failed to register entry quirk: {entry_result.error}"
                        )
                except Exception:
                    self._logger.exception("Failed to instantiate entry quirk")

        self._logger.info(
            f"Registered {len(complete_quirks)} complete quirks and {len(stub_quirks)} stub quirks"
        )

    def _initialize_handlers(self) -> dict[str, object]:
        """Initialize CQRS handlers using FlextRegistry.

        Returns:
            Dictionary mapping operation names to handler instances

        """
        # Register all handlers using FlextRegistry
        registration_result = FlextLdifHandlers.register_all_handlers(
            self._context, self._container, self._bus
        )

        if registration_result.is_success:
            summary = registration_result.unwrap()
            self._logger.info(
                f"Registered {summary['handlers_registered']} CQRS handlers via FlextRegistry"
            )

        # Return initialized handler instances
        return {
            "parse": FlextLdifHandlers.ParseQueryHandler(
                self._context, self._container, self._bus
            ),
            "validate": FlextLdifHandlers.ValidateQueryHandler(
                self._context, self._container, self._bus
            ),
            "analyze": FlextLdifHandlers.AnalyzeQueryHandler(
                self._context, self._container, self._bus
            ),
            "write": FlextLdifHandlers.WriteCommandHandler(
                self._context, self._container, self._bus
            ),
            "migrate": FlextLdifHandlers.MigrateCommandHandler(
                self._context, self._container, self._bus
            ),
            "register_quirk": FlextLdifHandlers.RegisterQuirkCommandHandler(
                self._context, self._container, self._bus
            ),
        }

    def parse(
        self, source: str | Path, server_type: str = "rfc"
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        r"""Parse LDIF from file or content string.

        Args:
            source: Either a file path (Path object) or LDIF content string
            server_type: Server type for quirk selection ("rfc", "oid", "oud", etc.)

        Returns:
            FlextResult with list of parsed Entry models

        Example:
            # Parse from string
            result = ldif.parse("dn: cn=test\ncn: test\n")

            # Parse from file
            result = ldif.parse(Path("data.ldif"))

            # Parse with server-specific quirks
            result = ldif.parse(Path("oid.ldif"), server_type="oid")

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

    def write(
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

        Example:
            # Write to string
            result = ldif.write(entries)
            if result.is_success:
                ldif_content = result.unwrap()

            # Write to file
            result = ldif.write(entries, Path("output.ldif"))

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
    ) -> FlextResult[dict[str, object]]:
        """Validate LDIF entries against RFC and business rules.

        Args:
            entries: List of entries to validate

        Returns:
            FlextResult containing validation report with details

        Example:
            result = ldif.validate_entries(entries)
            if result.is_success:
                report = result.unwrap()
                print(f"Valid: {report['is_valid']}")
                print(f"Errors: {report['errors']}")

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
            return FlextResult[dict[str, object]].ok({
                "is_valid": validation_result.is_valid,
                "total_entries": len(entries),
                "valid_entries": len(entries) - len(validation_result.errors),
                "invalid_entries": len(validation_result.errors),
                "errors": validation_result.errors,
            })
        return FlextResult[dict[str, object]].fail(result.error or "Validation failed")

    def migrate(
        self,
        input_dir: Path,
        output_dir: Path,
        from_server: str,
        to_server: str,
        *,
        process_schema: bool = True,
        process_entries: bool = True,
    ) -> FlextResult[dict[str, object]]:
        """Migrate LDIF data between different LDAP server types.

        Args:
            input_dir: Directory containing source LDIF files
            output_dir: Directory for migrated LDIF files
            from_server: Source server type ("oid", "oud", "openldap", etc.)
            to_server: Target server type
            process_schema: Whether to process schema files
            process_entries: Whether to process entry files

        Returns:
            FlextResult containing migration statistics and output files

        Example:
            result = ldif.migrate(
                input_dir=Path("data/oid"),
                output_dir=Path("data/oud"),
                from_server="oid",
                to_server="oud",
                process_schema=True,
                process_entries=True
            )
            if result.is_success:
                stats = result.unwrap()
                print(f"Migrated {stats['total_entries']} entries")

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
                return FlextResult[dict[str, object]].fail(
                    migration_result.error or "Migration failed"
                )

            return FlextResult[dict[str, object]].ok(migration_result.unwrap())

        except Exception as e:
            self._logger.exception("Migration failed")
            return FlextResult[dict[str, object]].fail(f"Migration failed: {e}")

    def analyze(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[dict[str, object]]:
        """Analyze LDIF entries and generate statistics.

        Args:
            entries: List of entries to analyze

        Returns:
            FlextResult containing analysis statistics

        Example:
            result = ldif.analyze(entries)
            if result.is_success:
                stats = result.unwrap()
                print(f"Total entries: {stats['total_entries']}")
                print(f"Entry types: {stats['entry_types']}")

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
            return FlextResult[dict[str, object]].ok({
                "total_entries": analytics.total_entries,
                "object_class_distribution": analytics.object_class_distribution,
                "patterns_detected": analytics.patterns_detected,
            })
        return FlextResult[dict[str, object]].fail(result.error or "Analysis failed")

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

        Example:
            custom_quirk = MyCustomQuirk()
            result = ldif.register_quirk(custom_quirk, quirk_type="schema")

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
    # BUILDERS & SERVICES (Direct Access)
    # =========================================================================

    @property
    def EntryBuilder(self) -> type[FlextLdifEntryBuilder]:
        """Access to LDIF entry builder for constructing entries.

        Returns:
            FlextLdifEntryBuilder class for creating person, group, OU, and custom entries

        Example:
            builder = ldif.EntryBuilder()
            person = builder.build_person_entry(
                cn="John Doe",
                sn="Doe",
                base_dn="ou=people,dc=example,dc=com",
                mail="john@example.com"
            )

        """
        return FlextLdifEntryBuilder

    @property
    def SchemaBuilder(self) -> type[FlextLdifSchemaBuilder]:
        """Access to LDIF schema builder for constructing schemas.

        Returns:
            FlextLdifSchemaBuilder class for building schema definitions

        Example:
            builder = ldif.SchemaBuilder(server_type="rfc")
            builder.add_attribute("cn", "commonName")
            schema = builder.build()

        """
        return FlextLdifSchemaBuilder

    @property
    def AclService(self) -> type[FlextLdifAclService]:
        """Access to ACL service for extracting and processing ACLs.

        Returns:
            FlextLdifAclService class for ACL operations

        Example:
            acl_service = ldif.AclService()
            acls = acl_service.extract_acls_from_entry(entry)

        """
        return FlextLdifAclService

    @property
    def SchemaValidator(self) -> type[FlextLdifSchemaValidator]:
        """Access to schema validator for validating entries.

        Returns:
            FlextLdifSchemaValidator class for schema validation

        Example:
            validator = ldif.SchemaValidator()
            result = validator.execute({"entries": entries})

        """
        return FlextLdifSchemaValidator

    # =========================================================================
    # INFRASTRUCTURE ACCESS (Properties)
    # =========================================================================

    @property
    def Models(self) -> type[FlextLdifModels]:
        """Access to all LDIF Pydantic models.

        Returns:
            FlextLdifModels class containing all LDIF domain models

        Example:
            entry = ldif.Models.Entry(dn="cn=test", attributes={})
            schema = ldif.Models.SchemaObjectClass(name="person")

        """
        return FlextLdifModels

    @property
    def Config(self) -> FlextLdifConfig:
        """Access to LDIF configuration instance.

        Returns:
            Current FlextLdifConfig instance

        Example:
            encoding = ldif.Config.ldif_encoding
            max_workers = ldif.Config.max_workers

        """
        return self._config

    @property
    def Constants(self) -> type[FlextLdifConstants]:
        """Access to LDIF constants.

        Returns:
            FlextLdifConstants class containing all constant values

        Example:
            max_line = ldif.Constants.Format.MAX_LINE_LENGTH
            encoding = ldif.Constants.Encoding.UTF8

        """
        return FlextLdifConstants

    @property
    def Types(self) -> type[FlextLdifTypes]:
        """Access to LDIF type definitions.

        Returns:
            FlextLdifTypes class containing all type aliases

        Example:
            # Use types for type hints
            entry_config: ldif.Types.Entry.EntryConfiguration = {}

        """
        return FlextLdifTypes

    @property
    def Protocols(self) -> type[FlextLdifProtocols]:
        """Access to LDIF protocols for duck typing.

        Returns:
            FlextLdifProtocols class containing all protocol definitions

        Example:
            def process(processor: ldif.Protocols.LdifProcessorProtocol):
                result = processor.parse(content)

        """
        return FlextLdifProtocols

    @property
    def Exceptions(self) -> type[FlextLdifExceptions]:
        """Access to LDIF exception factory methods.

        Returns:
            FlextLdifExceptions class with error creation methods

        Example:
            error = ldif.Exceptions.validation_error("Invalid DN")
            parse_error = ldif.Exceptions.parse_error("Malformed LDIF")

        """
        return FlextLdifExceptions

    @property
    def Mixins(self) -> type[FlextLdifMixins]:
        """Access to LDIF mixins for reusable functionality.

        Returns:
            FlextLdifMixins class containing all mixin classes

        Example:
            validator = ldif.Mixins.ValidationMixin()
            is_valid = validator.validate_dn_format("cn=test")

        """
        return FlextLdifMixins

    @property
    def Utilities(self) -> type[FlextLdifUtilities]:
        """Access to LDIF utility functions.

        Returns:
            FlextLdifUtilities class containing all utility methods

        Example:
            timestamp = ldif.Utilities.TimeUtilities.get_timestamp()
            size = ldif.Utilities.TextUtilities.format_byte_size(1024)

        """
        return FlextLdifUtilities

    @property
    def Processors(self) -> type[FlextLdifUtilities.Processors]:
        """Access to LDIF processing utilities using FlextProcessors.

        Returns:
            FlextLdifUtilities.Processors class with processing methods

        Example:
            # Create processor and register function
            processors = ldif.Processors.create_processor()

            def validate_entry(entry: dict) -> dict:
                # Validation logic
                return entry

            result = ldif.Processors.register_processor(
                "validate", validate_entry, processors
            )

            # Batch processing with registered processor
            batch_result = ldif.Processors.process_entries_batch(
                "validate", entries, processors
            )

            # Parallel processing with registered processor
            parallel_result = ldif.Processors.process_entries_parallel(
                "validate", entries, processors
            )

        """
        return FlextLdifUtilities.Processors

    # =========================================================================
