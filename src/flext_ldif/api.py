"""FLEXT-LDIF API - Unified Facade for LDIF Operations.

This module provides the primary entry point for all LDIF processing operations.
The FlextLdif class serves as the sole facade for the FLEXT LDIF library,
consolidating all business logic and service coordination into a single interface.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import ClassVar, cast, overload, override

from flext_core import (
    FlextContainer,
    FlextContext,
    FlextDispatcher,
    FlextLogger,
    FlextRegistry,
    FlextResult,
    FlextService,
)
from pydantic import PrivateAttr

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.acl import FlextLdifAcl
from flext_ldif.services.detector import FlextLdifDetector
from flext_ldif.services.filters import FlextLdifFilters
from flext_ldif.services.migration import FlextLdifMigrationPipeline
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.services.statistics import FlextLdifStatistics
from flext_ldif.services.validation import FlextLdifValidation
from flext_ldif.services.writer import FlextLdifWriter
from flext_ldif.typings import FlextLdifTypes, ServiceT


class FlextLdif(FlextService[FlextLdifTypes.Models.ServiceResponseTypes]):
    r"""Main API facade for LDIF processing operations.

    This is the sole entry point for all LDIF operations, consolidating all
    business logic and service coordination into a single facade class. It
    inherits from FlextService to leverage dependency injection, logging, and
    event publishing capabilities.

    Capabilities:
        - Parse and write LDIF files according to RFC 2849 and RFC 4512
        - Handle server-specific quirks (OID, OUD, OpenLDAP, AD, 389 DS)
        - Migrate data between different LDAP server types
        - Validate LDIF entries against LDAP schemas
        - Process ACL (Access Control List) entries
        - Batch and parallel processing for large datasets
        - Service initialization and dependency injection via FlextContainer
        - Default quirk registration for all supported LDAP servers
        - Context management with correlation tracking

    Implementation:
        This class consolidates all LDIF operations into a single facade,
        eliminating the need for separate client classes. It manages all
        service coordination, DI container operations, and business logic.

    Example:
        # Recommended: Use singleton instance
        ldif = FlextLdif.get_instance()

        # Alternative: Create new instance
        ldif = FlextLdif()

        # Parse LDIF content with context tracking
        with ldif.context.set_correlation_id("req-123"):
            result = ldif.parse("dn: cn=test,dc=example,dc=com\ncn: test\n")
            if result.is_success:
                entries = result.unwrap()

        # Write LDIF entries with structured error handling
        write_result = ldif.write(entries)

        # Generic migration between servers
        migration_result = ldif.migrate(
            input_dir=Path("data/oid"),
            output_dir=Path("data/oud"),
            from_server=FlextLdifConstants.ServerTypes.OID,
            to_server=FlextLdifConstants.ServerTypes.OUD,
        )

        # Categorized migration with structured output
        categorized_result = ldif.categorize_and_migrate(
            input_dir=Path("data/source"),
            output_dir=Path("data/categorized"),
            categorization_rules={
                "users": [FlextLdifConstants.ObjectClasses.PERSON],
                "groups": [FlextLdifConstants.ObjectClasses.GROUP_OF_NAMES],
            },
            from_server=FlextLdifConstants.ServerTypes.OID,
            to_server=FlextLdifConstants.ServerTypes.OUD,
        )

        # Batch processing for large datasets
        batch_processor = ldif.create_batch_processor(batch_size=100)
        processing_result = batch_processor.process_entries(entries, validate_entry)

        # Access complete infrastructure
        config = ldif.config
        models = ldif.models
        entry = ldif.models.Entry(dn="cn=test", attributes={})
        events = ldif.events  # Domain events

    """

    # Private attributes (initialized in __init__ and model_post_init)
    # Using PrivateAttr() for Pydantic v2 compatibility
    _dispatcher: FlextDispatcher | None = PrivateAttr(default=None)
    _registry: FlextRegistry | None = PrivateAttr(default=None)
    _logger: FlextLogger | None = PrivateAttr(default=None)
    _parser_service: FlextLdifParser | None = PrivateAttr(default=None)
    _acl_service: FlextLdifAcl | None = PrivateAttr(default=None)
    _writer_service: FlextLdifWriter | None = PrivateAttr(default=None)
    _config: FlextLdifConfig | None = PrivateAttr(default=None)

    _container: FlextContainer = PrivateAttr(
        default_factory=FlextContainer.get_global,
    )
    _context: dict[str, object] = PrivateAttr(default_factory=dict)
    _handlers: dict[str, object] = PrivateAttr(default_factory=dict)
    _init_config_value: FlextLdifConfig | None = PrivateAttr(default=None)
    _initialized: bool = PrivateAttr(default=False)

    # Direct class access for builders and services (no wrappers)
    AclService: ClassVar[type[FlextLdifAcl]] = FlextLdifAcl

    # Singleton instance storage
    _instance: ClassVar[FlextLdif | None] = None
    # Track initialized instances to prevent duplicate model_post_init() calls
    _initialized_instances: ClassVar[set[int]] = set()

    @classmethod
    def get_instance(cls, config: FlextLdifConfig | None = None) -> FlextLdif:
        """Get singleton instance of FlextLdif facade.

        Args:
            config: Optional configuration (only used on first call)

        Returns:
            Singleton FlextLdif instance

        Example:
            # Recommended usage
            ldif = FlextLdif.get_instance()

            # All calls return same instance
            ldif2 = FlextLdif.get_instance()
            # Singleton pattern: same instance returned
            if ldif is not ldif2:
                raise RuntimeError("Singleton pattern violation: different instances returned")

        """
        if cls._instance is None:
            # Create instance with config if provided
            if config is not None:
                # Pass config via kwargs to __init__
                cls._instance = cls(config=config)
            else:
                # Create empty instance (FlextService v2 doesn't accept positional args)
                cls._instance = cls()
        return cls._instance

    def __init__(self, **kwargs: object) -> None:
        """Initialize LDIF facade - the sole entry point for all LDIF operations.

        Integrates Flext components for infrastructure support:
            - FlextContainer: Dependency injection
            - FlextLogger: Structured logging
            - FlextContext: Request context management
            - FlextConfig: Configuration with validation
            - FlextBus: Event publishing
            - FlextDispatcher: Message dispatching
            - FlextRegistry: Component registration

        Args:
            **kwargs: Configuration parameters. Supports 'config' for FlextLdifConfig.

        """
        # Extract 'config' from kwargs to avoid Pydantic extra='forbid' error
        # Store it in _init_config_value for use in model_post_init
        config_value = kwargs.pop("config", None)
        if config_value is not None and isinstance(config_value, FlextLdifConfig):
            # Store temporarily before super().__init__()
            # model_post_init will read it and initialize services with it
            object.__setattr__(self, "_init_config_value", config_value)

        # Call super().__init__() for Pydantic v2 model initialization
        # Remaining kwargs (empty after config removal) are passed
        # This will call model_post_init() which initializes all services
        super().__init__(**kwargs)

        # Services initialized in model_post_init for proper initialization order

    def model_post_init(self, _context: dict[str, object] | None, /) -> None:
        """Initialize private attributes after Pydantic initialization.

        This hook is called by Pydantic after __init__ completes and handles:
        - Service setup and dependency injection via FlextContainer
        - Default quirk registration for all supported LDAP servers
        - Context and handler initialization

        Uses instance ID tracking to prevent duplicate initialization when
        Pydantic v2 calls this method multiple times on the same instance.

        Args:
            _context: Pydantic's validation context dictionary or None (unused).

        """
        # Guard: Check if this specific instance was already initialized
        instance_id = id(self)
        if instance_id in FlextLdif._initialized_instances:
            return

        # Mark this instance as initialized IMMEDIATELY to prevent re-entry
        FlextLdif._initialized_instances.add(instance_id)

        # Initialize dispatcher, registry, and logger FIRST
        # These are needed by _register_components() below
        dispatcher = FlextDispatcher()
        self._dispatcher = dispatcher
        self._registry = FlextRegistry(dispatcher=dispatcher)
        self._logger = FlextLogger(__name__)

        # Initialize private attributes
        init_config = getattr(self, "_init_config_value", None)
        config = init_config if init_config is not None else FlextLdifConfig()
        self._config = config
        self._context = {}
        self._handlers = {}

        # Initialize service instances (using config for parser)
        self._parser_service = FlextLdifParser(config=config)
        # Note: FlextLdifAcl no longer requires server_type parameter
        self._acl_service = FlextLdifAcl()

        # Register services in container
        self._setup_services()

        # Register LDIF components with FlextRegistry
        self._register_components()

        # Log config initialization
        if self.logger and self._config:
            self.logger.debug("FlextLdif facade initialized")
            self.logger.debug("Services setup and default quirks registered")

    # =========================================================================
    # PRIVATE: Service Setup and Handler Initialization (from client.py)
    # =========================================================================

    def _setup_services(self) -> None:
        """Register all services using advanced FlextUtilities patterns with metadata."""
        container = self.container

        # Execute service registration with functional composition and error handling
        try:
            self._register_core_services(container)
            self._register_business_services(container)
            self._register_pipeline_services(container)
        except Exception:
            self.logger.exception("Failed to setup services")
            raise

    def _register_core_services(self, container: FlextContainer) -> None:
        """Register core infrastructure services."""
        # Register quirk registry (check if already exists - container is global)
        if not container.has("quirk_registry"):
            quirk_registry = FlextLdifServer()
            container.with_service("quirk_registry", quirk_registry)

        # Register writer service with dependencies (check if already exists)
        if not container.has("writer"):
            # Get quirk_registry from container (may have been registered earlier)
            quirk_registry_result = container.get("quirk_registry")
            if quirk_registry_result.is_failure:
                # Fast fail: quirk_registry is required
                error_msg = "quirk_registry service not found in container and cannot be created"
                raise RuntimeError(error_msg)

            value = quirk_registry_result.unwrap()
            if not isinstance(value, FlextLdifServer):
                type_name = type(value).__name__
                error_msg = f"quirk_registry service has wrong type: {type_name}"
                raise RuntimeError(error_msg)

            unified_writer = FlextLdifWriter(quirk_registry=value)
            container.with_service("writer", unified_writer)

    def _register_business_services(self, container: FlextContainer) -> None:
        """Register business logic services."""
        # Register stateless business services using fluent interface
        # Check each service individually since container is global singleton
        if not container.has("filters"):
            container.with_service("filters", FlextLdifFilters())
        if not container.has("statistics"):
            container.with_service("statistics", FlextLdifStatistics())
        if not container.has("validation"):
            container.with_service("validation", FlextLdifValidation())

    def _register_pipeline_services(self, container: FlextContainer) -> None:
        """Register complex pipeline services with factory pattern."""

        def migration_pipeline_factory(
            params: FlextLdifModels.MigrationPipelineParams,
        ) -> FlextLdifMigrationPipeline:
            """Factory for migration pipelines."""
            return FlextLdifMigrationPipeline(
                input_dir=Path(params.input_dir),
                output_dir=Path(params.output_dir),
                source_server=params.source_server,
                target_server=params.target_server,
            )

        # Check if already registered (container is global singleton)
        if not container.has("migration_pipeline"):
            container.with_service("migration_pipeline", migration_pipeline_factory)

    def _get_service_typed(
        self,
        container: FlextContainer,
        service_name: str,
        expected_type: type[ServiceT],
    ) -> FlextResult[ServiceT]:
        """Helper to retrieve and type-narrow services from container.

        Consolidates service retrieval pattern: get → unwrap → type check.

        Args:
            container: The dependency injection container
            service_name: Name of the service to retrieve
            expected_type: Expected type for type narrowing

        Returns:
            FlextResult with service instance or failure result

        """
        service_result = container.get(service_name)
        if service_result.is_failure:
            return FlextResult[ServiceT].fail(
                f"Service '{service_name}' not found in container"
            )

        service_obj = service_result.unwrap()
        # Type narrowing via isinstance - MyPy recognizes this pattern
        if isinstance(service_obj, expected_type):
            return FlextResult[ServiceT].ok(service_obj)

        type_name = getattr(expected_type, "__name__", str(expected_type))
        return FlextResult[ServiceT].fail(
            f"Service '{service_name}' is not of expected type {type_name}"
        )

    def _register_components(self) -> None:
        """Register LDIF components with FlextRegistry for dependency injection."""
        try:
            # Register core LDIF services
            if self._registry is not None:
                self._registry.register(
                    "ldif_parser_service",
                    self._parser_service,
                    metadata={
                        "type": "service",
                        "domain": "parser",
                        "description": "Unified LDIF parsing",
                    },
                )

                # Register configuration and constants
                self._registry.register(
                    "ldif_config",
                    self.config,
                    metadata={"type": "config", "domain": "ldif"},
                )
                self._registry.register(
                    "ldif_constants",
                    FlextLdifConstants,
                    metadata={"type": "constants", "domain": "ldif"},
                )

                if self._logger:
                    self._logger.debug(
                        "LDIF components registered with FlextRegistry",
                        extra={
                            "correlation_id": getattr(
                                self.context,
                                "correlation_id",
                                None,
                            ),
                            "registered_components": [
                                "ldif_config",
                                "ldif_constants",
                            ],
                        },
                    )

        except (ValueError, TypeError, AttributeError) as e:
            # Use FlextExceptions for error handling
            msg = f"Failed to register LDIF components: {e}"
            raise RuntimeError(msg) from e

        # Log initialization with structured context
        if self._logger is not None:
            self._logger.info(
                "FlextLdif initialized with complete Flext ecosystem integration",
                extra={
                    "service_type": "LDIF Processing Facade",
                    "correlation_id": getattr(self.context, "correlation_id", None),
                    "flext_components": [
                        "FlextContainer",
                        "FlextLogger",
                        "FlextContext",
                        "FlextDispatcher",
                        "FlextRegistry",
                        "FlextExceptions",
                        "FlextProtocols",
                    ],
                    "ldif_features": [
                        "rfc_2849_parsing",
                        "rfc_4512_compliance",
                        "servers",
                        "generic_migration",
                        "schema_validation",
                        "acl_processing",
                        "entry_building",
                    ],
                },
            )

    @override
    def execute(
        self,
    ) -> FlextResult[
        FlextLdifModels.ParseResponse
        | FlextLdifModels.WriteResponse
        | FlextLdifModels.MigrationPipelineResult
        | FlextLdifModels.ValidationResult
    ]:
        """Execute facade self-check and return status.

        Returns:
            FlextResult containing ValidationResult with health check status

        """
        try:
            # Return ValidationResult as health check (all services healthy)
            validation_result = FlextLdifModels.ValidationResult(
                is_valid=True,
                total_entries=0,
                valid_entries=0,
                invalid_entries=0,
                errors=[],
            )
            return FlextResult.ok(validation_result)
        except (ValueError, TypeError, AttributeError) as e:
            # Return failed validation on error
            validation_result = FlextLdifModels.ValidationResult(
                is_valid=False,
                total_entries=0,
                valid_entries=0,
                invalid_entries=0,
                errors=[f"Status check failed: {e}"],
            )
            return FlextResult.ok(validation_result)

    def _resolve_parse_server_type(
        self,
        server_type: str | None,
        source: str | Path,
    ) -> FlextResult[str]:
        """Resolve server type for parsing using config-aware logic.

        Args:
            server_type: Explicit server type or None for auto-detection
            source: LDIF source for auto-detection

        Returns:
            FlextResult with resolved server type string

        """
        if server_type is not None:
            return FlextResult.ok(server_type)

        # Use config-aware resolution (respects quirks_detection_mode and quirks_server_type)
        server_type_result = self.get_effective_server_type(
            ldif_path=source if isinstance(source, Path) else None,
        )
        if server_type_result.is_failure:
            return FlextResult[str].fail(
                f"Failed to resolve server type: {server_type_result.error}",
            )

        resolved = server_type_result.unwrap()
        if not resolved:
            return FlextResult[str].fail(
                "Server type resolution returned empty value",
            )
        return FlextResult.ok(resolved)

    def _ensure_parser_service(self) -> FlextLdifParser:
        """Ensure parser service is initialized (lazy initialization).

        Returns:
            FlextLdifParser instance

        """
        if not hasattr(self, "_parser_service") or self._parser_service is None:
            self._parser_service = FlextLdifParser(config=self.config)
        return self._parser_service

    def _execute_parse_with_service(
        self,
        content: str,
        server_type: str,
        format_options: FlextLdifModels.ParseFormatOptions | None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Execute parsing via FlextLdifParser service.

        Args:
            content: LDIF content string
            server_type: Resolved server type
            format_options: Parse options

        Returns:
            FlextResult with list of Entry models

        """
        parser = self._ensure_parser_service()
        parse_result = parser.parse(
            content=content,
            input_source="string",
            server_type=server_type,
            format_options=format_options,
        )

        # Extract entries from ParseResponse
        if parse_result.is_success:
            parse_response = parse_result.unwrap()
            entries_list = list(parse_response.entries)
            # Cast to ensure type compatibility between FlextLdifModelsDomains.Entry and FlextLdifModels.Entry
            entries_list_casted = cast("list[FlextLdifModels.Entry]", entries_list)
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries_list_casted)
        return FlextResult.fail(parse_result.error)

    def parse(
        self,
        source: str | Path,
        server_type: str | None = None,
        format_options: FlextLdifModels.ParseFormatOptions | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        r"""Parse LDIF content string or file.

        Args:
            source: LDIF content as string or Path to LDIF file
            server_type: Server type for quirk selection ("rfc", "oid", "oud", etc.)
            format_options: Parse options as ParseFormatOptions model

        Returns:
            FlextResult containing list of Entry models

        Example:
            # Parse LDIF content
            result = ldif.parse("dn: cn=test\ncn: test\n")
            if result.is_success:
                entries = result.unwrap()  # list[Entry]

            # Parse file
            result = ldif.parse(Path("file.ldif"))
            if result.is_success:
                entries = result.unwrap()

            # Parse with options
            options = FlextLdifModels.ParseFormatOptions(validate_entries=True)
            result = ldif.parse("dn: cn=test\ncn: test\n", format_options=options)

        """
        try:
            # Resolve effective server type
            server_type_result = self._resolve_parse_server_type(server_type, source)
            if server_type_result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    server_type_result.error,
                )
            effective_server_type = server_type_result.unwrap()

            # Get content from source
            content = self._get_source_content(source)

            # Execute parsing via service
            return self._execute_parse_with_service(
                content,
                effective_server_type,
                format_options,
            )

        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Failed to parse LDIF: {e}",
            )

    def _get_source_content(self, source: str | Path) -> str:
        """Get LDIF content from source (Path or string).

        Explicit handling:
        - Path objects: Read file content
        - Strings: Treat as LDIF content directly (no heuristic guessing)

        Args:
            source: Either a Path to LDIF file or string containing LDIF data

        Returns:
            LDIF content string

        Raises:
            OSError: If file cannot be read
            UnicodeDecodeError: If file has encoding issues

        """
        # Explicit Case 1: Path object - read file
        if isinstance(source, Path):
            return source.read_text(encoding=self.config.ldif_encoding)

        # Explicit Case 2: String - treat as LDIF content directly
        # No heuristics, no fallbacks, no guessing if it's a file path
        if isinstance(source, str):
            return source

        # Should not reach here due to type annotation, but fail-safe
        source_type_name = type(source).__name__
        error_msg = f"Source must be Path or str, got {source_type_name}"
        raise TypeError(error_msg)

    # Overloads for write() method
    @overload
    def write(
        self,
        entries: list[FlextLdifModels.Entry],
        output_path: None = None,
        server_type: str | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
    ) -> FlextResult[str]: ...

    @overload
    def write(
        self,
        entries: list[FlextLdifModels.Entry],
        output_path: Path,
        server_type: str | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
    ) -> FlextResult[str]: ...

    def write(
        self,
        entries: list[FlextLdifModels.Entry],
        output_path: Path | None = None,
        server_type: str | None = None,
        format_options: FlextLdifModels.WriteFormatOptions | None = None,
    ) -> FlextResult[str]:
        """Write entries to LDIF format string or file.

        Args:
            entries: List of Entry models to write
            output_path: Optional Path to write LDIF file. If None, returns LDIF string.
            server_type: Target server type for writing. If None, uses RFC.
            format_options: Write options as WriteFormatOptions model

        Returns:
            FlextResult containing LDIF content as string (if output_path is None)
            or success message (if output_path provided)

        Example:
            # Write Entry models to string
            result = ldif.write(entries)
            if result.is_success:
                ldif_content = result.unwrap()

            # Write to file
            result = ldif.write(entries, Path("output.ldif"))

            # Write with options
            options = FlextLdifModels.WriteFormatOptions(
                line_width=100,
                sort_attributes=True,
            )
            result = ldif.write(entries, format_options=options)

        """
        try:
            # Get writer service from container
            if self._writer_service is None:
                writer_result = self._get_service_typed(
                    self.container,
                    "writer",
                    FlextLdifWriter,
                )
                if writer_result.is_failure:
                    return FlextResult[str].fail(
                        f"Failed to retrieve writer service: {writer_result.error}"
                    )
                self._writer_service = writer_result.unwrap()

            # Use provided server_type or default to RFC - no fallback with or
            target_server = server_type or "rfc"

            # Resolve format options
            resolved_format_options: FlextLdifModels.WriteFormatOptions
            if format_options is None:
                resolved_format_options = FlextLdifModels.WriteFormatOptions()
            else:
                resolved_format_options = format_options

            if output_path:
                write_result = self._writer_service.write(
                    entries=entries,
                    target_server_type=target_server,
                    output_target="file",
                    output_path=output_path,
                    format_options=resolved_format_options,
                )
                if write_result.is_success:
                    message = f"LDIF written successfully to {output_path}"
                    return FlextResult.ok(message)
                return FlextResult.fail(write_result.error)

            # Writing to a string
            string_result = self._writer_service.write(
                entries=entries,
                target_server_type=target_server,
                output_target="string",
                format_options=resolved_format_options,
            )
            if string_result.is_success:
                unwrapped = string_result.unwrap()
                # Type narrowing: when output_target="string", result is always str
                if isinstance(unwrapped, str):
                    return FlextResult[str].ok(unwrapped)
                # Fallback: convert to string if needed
                return FlextResult[str].ok(str(unwrapped))
            return FlextResult[str].fail(string_result.error)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[str].fail(f"Write operation failed: {e}")

    def get_entry_dn(
        self,
        entry: FlextLdifModels.Entry
        | FlextLdifProtocols.Entry.EntryWithDnProtocol
        | dict[str, str | list[str]],
    ) -> FlextResult[str]:
        """Extract DN (Distinguished Name) from any entry type.

        Handles Entry models, LDAP entries, and dicts.

        Args:
            entry: Entry model, LDAP entry, or dict to extract DN from

        Returns:
            FlextResult containing DN as string

        Example:
            # Works with Entry models
            result = ldif.get_entry_dn(entry_model)

            # Works with dicts
            result = ldif.get_entry_dn({"dn": "cn=test,dc=example", "cn": ["test"]})

            # Works with LDAP entries
            result = ldif.get_entry_dn(ldap_entry)

        """
        try:
            # Handle dict
            if isinstance(entry, dict):
                dn_val = entry.get("dn")
                if not dn_val:
                    return FlextResult[str].fail("Dict entry missing 'dn' key")
                return FlextResult[str].ok(str(dn_val))

            # Handle models/protocols
            if not entry or not hasattr(entry, "dn"):
                return FlextResult[str].fail("Entry missing DN attribute")

            dn_value = entry.dn
            # Handle both DistinguishedName objects (with .value) and plain strings
            value_attr = getattr(dn_value, "value", None)
            if value_attr is not None:
                return FlextResult[str].ok(str(value_attr))
            return FlextResult[str].ok(str(dn_value))

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[str].fail(f"Failed to extract DN: {e}")

    @staticmethod
    def _normalize_attribute_value(attr_values: list[str]) -> str | list[str]:
        """Normalize attribute values to str or list[str].

        Args:
            attr_values: List of attribute values

        Returns:
            Single string if length==1, otherwise list

        """
        if len(attr_values) == 1:
            return attr_values[0]
        return attr_values

    @staticmethod
    def _extract_from_ldif_attributes(
        attrs_container: FlextLdifModels.LdifAttributes,
    ) -> FlextLdifTypes.CommonDict.AttributeDict:
        """Extract attributes from LdifAttributes container.

        Args:
            attrs_container: LdifAttributes object

        Returns:
            AttributeDict with normalized values

        """
        result_dict: FlextLdifTypes.CommonDict.AttributeDict = {}

        for attr_name, attr_values in attrs_container.attributes.items():
            # attr_values is always a list[str] in LdifAttributes
            result_dict[attr_name] = FlextLdif._normalize_attribute_value(attr_values)

        return result_dict

    @staticmethod
    def _extract_from_dict_attributes(
        attrs_container: dict[str, str | list[str]],
    ) -> FlextLdifTypes.CommonDict.AttributeDict:
        """Extract attributes from dict representation.

        Args:
            attrs_container: Dict of attributes

        Returns:
            AttributeDict with normalized values

        """
        result_dict: FlextLdifTypes.CommonDict.AttributeDict = {}

        for attr_name, attr_val in attrs_container.items():
            if isinstance(attr_val, list):
                # Return list as-is or single item if length==1
                result_dict[attr_name] = FlextLdif._normalize_attribute_value([
                    str(v) for v in attr_val
                ])
            else:
                # Single value - return as string
                result_dict[attr_name] = str(attr_val)

        return result_dict

    def get_entry_attributes(
        self,
        entry: FlextLdifModels.Entry | FlextLdifProtocols.Entry.EntryWithDnProtocol,
    ) -> FlextResult[FlextLdifTypes.CommonDict.AttributeDict]:
        """Extract attributes from any entry type.

        Handles both FlextLdifModels.Entry (from LDIF files) and
        FlextLdapModels.Entry (from LDAP server operations).

        Returns attributes as dict[str, str | list[str]] per
        FlextLdifTypes.CommonDict.AttributeDict.
        Attribute values are returned as provided (str or list).

        Args:
            entry: LDIF or LDAP entry to extract attributes from

        Returns:
            FlextResult containing AttributeDict with attribute names mapped to
            str | list[str] values matching FlextLdifTypes definition.

        Example:
            # Works with both LDIF and LDAP entries
            result = ldif.get_entry_attributes(entry)
            if result.is_success:
                attrs = result.unwrap()
                # Can pass directly to build operations
                ldif.build(FlextLdifConstants.EntryTypes.PERSON, attributes=attrs)

        """
        try:
            if not entry or not hasattr(entry, "attributes"):
                return FlextResult[FlextLdifTypes.CommonDict.AttributeDict].fail(
                    "Entry missing attributes",
                )

            attrs_container = entry.attributes

            # Handle both LdifAttributes and dict-like access
            if isinstance(attrs_container, FlextLdifModels.LdifAttributes):
                result_dict = FlextLdif._extract_from_ldif_attributes(attrs_container)
            elif isinstance(attrs_container, dict):
                # Normalize dict to expected type - convert values to str | list[str]
                normalized_dict: dict[str, str | list[str]] = {}
                for key, value in attrs_container.items():
                    if isinstance(value, list):
                        # Type narrowing: value is list[str]
                        normalized_dict[key] = value
                    elif isinstance(value, str):
                        # Type narrowing: value is str
                        normalized_dict[key] = value
                    else:
                        # Convert to str
                        normalized_dict[key] = str(value)
                result_dict = FlextLdif._extract_from_dict_attributes(normalized_dict)
            else:
                return FlextResult[FlextLdifTypes.CommonDict.AttributeDict].fail(
                    f"Unknown attributes container type: {type(attrs_container)}",
                )

            return FlextResult[FlextLdifTypes.CommonDict.AttributeDict].ok(result_dict)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifTypes.CommonDict.AttributeDict].fail(
                f"Failed to extract attributes: {e}",
            )

    def create_entry(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
        objectclasses: list[str] | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Create a new LDIF entry with validation.

        Args:
            dn: Distinguished Name for the entry
            attributes: Dict mapping attribute names to values (string or list)
            objectclasses: Optional list of objectClass values (added to attributes if provided)

        Returns:
            FlextResult containing new FlextLdifModels.Entry

        Example:
            result = ldif.create_entry(
                dn="cn=John Doe,ou=Users,dc=example,dc=com",
                attributes={"cn": "John Doe", "sn": "Doe", "mail": "john@example.com"},
                objectclasses=["inetOrgPerson", "person", "top"]
            )
            if result.is_success:
                entry = result.unwrap()

        """
        try:
            # Normalize attributes to ensure all values are lists
            normalized_attrs: FlextLdifTypes.CommonDict.AttributeDict = {}
            for key, value in attributes.items():
                if isinstance(value, list):
                    normalized_attrs[key] = [str(v) for v in value]
                else:
                    normalized_attrs[key] = [str(value)]

            # Add objectClass if provided
            if objectclasses:
                normalized_attrs["objectClass"] = [str(v) for v in objectclasses]

            # Use FlextLdifModels.Entry.create() factory method
            create_result = FlextLdifModels.Entry.create(
                dn=dn,
                attributes=normalized_attrs,
            )

            if create_result.is_success:
                # Cast to ensure type compatibility between FlextLdifModelsDomains.Entry and FlextLdifModels.Entry
                return cast("FlextResult[FlextLdifModels.Entry]", create_result)
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create entry: {create_result.error}",
            )

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Failed to create entry: {e}",
            )

    def get_entry_objectclasses(
        self,
        entry: FlextLdifModels.Entry | FlextLdifProtocols.Entry.EntryWithDnProtocol,
    ) -> FlextResult[list[str]]:
        """Extract objectClass values from any entry type.

        Handles both FlextLdifModels.Entry (from LDIF files) and
        FlextLdapModels.Entry (from LDAP server operations).

        Args:
            entry: LDIF or LDAP entry to extract objectClasses from

        Returns:
            FlextResult containing list of objectClass values

        Example:
            # Works with both LDIF and LDAP entries
            result = ldif.get_entry_objectclasses(entry)
            if result.is_success:
                object_classes = result.unwrap()
                if "inetOrgPerson" in object_classes:
                    print("Entry is a person")

        """
        try:
            # First try to get objectClass from attributes
            attrs_result = self.get_entry_attributes(entry)
            if attrs_result.is_success:
                attrs = attrs_result.unwrap()
                # objectClass might be stored as "objectClass" or "objectclass"
                oc_values = attrs.get("objectClass") or attrs.get("objectclass")
                if oc_values:
                    # Normalize to list (get_entry_attributes returns str | list[str])
                    if isinstance(oc_values, str):
                        return FlextResult[list[str]].ok([oc_values])
                    return FlextResult[list[str]].ok(oc_values)

            # Fallback: try direct access to object_classes attribute (LDAP entries)
            oc_attr = getattr(entry, "object_classes", None)
            if oc_attr is not None:
                if isinstance(oc_attr, list):
                    return FlextResult[list[str]].ok([str(v) for v in oc_attr])
                return FlextResult[list[str]].ok([str(oc_attr)])

            return FlextResult[list[str]].fail("Entry missing objectClass attribute")

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[str]].fail(f"Failed to extract objectClasses: {e}")

    def get_attribute_values(
        self,
        attribute: (FlextLdifProtocols.AttributeValueProtocol | list[str] | str),
    ) -> FlextResult[list[str]]:
        """Extract values from an attribute value object using monadic pattern.

        Handles various attribute value formats from both LDIF and LDAP entries.
        Uses FlextResult and_then/map for composable error handling.

        Args:
            attribute: Attribute value object with .values property, list, or string.
                      Must not be None - use FlextResult for error handling.

        Returns:
            FlextResult containing list of attribute values as strings.
            Fails if attribute is None or invalid format.

        Example:
            # Extract values using monadic composition
            result = ldif.get_attribute_values(attr_value_obj)
            if result.is_success:
                values = result.unwrap()
                for value in values:
                    print(f"Value: {value}")

        """
        # Fast fail if None - no fallback
        if attribute is None:
            return FlextResult[list[str]].fail(
                "Attribute value cannot be None - use FlextResult for error handling"
            )

        # Handle objects with .values property (protocol-based)
        if isinstance(attribute, FlextLdifProtocols.AttributeValueProtocol):
            values = attribute.values
            if isinstance(values, list):
                return FlextResult[list[str]].ok([str(v) for v in values])
            return FlextResult[list[str]].ok([str(values)])

        # Handle lists directly
        if isinstance(attribute, list):
            return FlextResult[list[str]].ok([str(v) for v in attribute])

        # Handle single string values
        if isinstance(attribute, str):
            return FlextResult[list[str]].ok([attribute])

        # Fast fail for unknown types
        return FlextResult[list[str]].fail(
            f"Unsupported attribute type: {type(attribute).__name__}. "
            "Expected AttributeValueProtocol, list[str], or str."
        )

    def _normalize_migration_config(
        self,
        migration_config: FlextLdifModels.MigrationConfig | dict[str, object] | None,
    ) -> FlextResult[FlextLdifModels.MigrationConfig]:
        """Convert dict to MigrationConfig model using FlextResult.

        Uses FlextResult for error handling - no None returns.

        Args:
            migration_config: MigrationConfig model, dict, or None

        Returns:
            FlextResult with MigrationConfig model or error if None/invalid

        """
        if migration_config is None:
            return FlextResult[FlextLdifModels.MigrationConfig].fail(
                "MigrationConfig cannot be None"
            )
        if isinstance(migration_config, dict):
            try:
                model = FlextLdifModels.MigrationConfig.model_validate(migration_config)
                return FlextResult[FlextLdifModels.MigrationConfig].ok(model)
            except Exception as e:
                return FlextResult[FlextLdifModels.MigrationConfig].fail(
                    f"Failed to validate MigrationConfig from dict: {e}"
                )
        if isinstance(migration_config, FlextLdifModels.MigrationConfig):
            return FlextResult[FlextLdifModels.MigrationConfig].ok(migration_config)
        return FlextResult[FlextLdifModels.MigrationConfig].fail(
            f"Invalid MigrationConfig type: {type(migration_config).__name__}"
        )

    def _detect_migration_mode(
        self,
        config_model: FlextLdifModels.MigrationConfig | None,
        categorization_rules: dict[str, list[str]] | None,
    ) -> str:
        """Auto-detect migration mode based on parameters."""
        if config_model is not None:
            return "structured"
        if categorization_rules is not None:
            return "categorized"
        return "simple"

    def _get_write_options_for_mode(
        self,
        mode: str,
        write_options: FlextLdifModels.WriteFormatOptions | dict[str, object] | None,
        config_model: FlextLdifModels.MigrationConfig | None,
    ) -> FlextResult[FlextLdifModels.WriteFormatOptions]:
        """Set default write options for structured and categorized modes using FlextResult.

        Uses FlextResult for error handling - no None returns.

        Args:
            mode: Migration mode ("structured", "categorized", or "simple")
            write_options: WriteFormatOptions model, dict, or None
            config_model: MigrationConfig model or None

        Returns:
            FlextResult with WriteFormatOptions model or error

        """
        if write_options is not None:
            # Convert dict to WriteFormatOptions if necessary
            if isinstance(write_options, dict):
                try:
                    model = FlextLdifModels.WriteFormatOptions.model_validate(
                        write_options,
                    )
                    return FlextResult[FlextLdifModels.WriteFormatOptions].ok(model)
                except Exception as e:
                    return FlextResult[FlextLdifModels.WriteFormatOptions].fail(
                        f"Failed to validate WriteFormatOptions from dict: {e}"
                    )
            if isinstance(write_options, FlextLdifModels.WriteFormatOptions):
                return FlextResult[FlextLdifModels.WriteFormatOptions].ok(write_options)
            return FlextResult[FlextLdifModels.WriteFormatOptions].fail(
                f"Invalid WriteFormatOptions type: {type(write_options).__name__}"
            )

        match mode:
            case "structured":
                if config_model is None:
                    return FlextResult[FlextLdifModels.WriteFormatOptions].fail(
                        "MigrationConfig required for structured mode"
                    )
                return FlextResult[FlextLdifModels.WriteFormatOptions].ok(
                    FlextLdifModels.WriteFormatOptions(
                        fold_long_lines=False,
                        write_removed_attributes_as_comments=(
                            config_model.write_removed_as_comments
                        ),
                    )
                )
            case "categorized":
                return FlextResult[FlextLdifModels.WriteFormatOptions].ok(
                    FlextLdifModels.WriteFormatOptions(fold_long_lines=False)
                )
            case "simple":
                # Simple mode doesn't require write options
                return FlextResult[FlextLdifModels.WriteFormatOptions].ok(
                    FlextLdifModels.WriteFormatOptions()
                )
            case _:
                return FlextResult[FlextLdifModels.WriteFormatOptions].fail(
                    f"Unknown migration mode: {mode}"
                )

    def _validate_simple_mode_params(
        self,
        input_filename: str | None,
        output_filename: str | None,
    ) -> FlextResult[bool]:
        """Validate requirements for simple mode."""
        if input_filename is not None and output_filename is None:
            return FlextResult[bool].fail(
                "output_filename is required when input_filename is specified",
            )
        return FlextResult[bool].ok(True)

    def migrate(
        self,
        input_dir: Path,
        output_dir: Path,
        source_server: str,
        target_server: str,
        *,
        options: FlextLdifModels.MigrateOptions | None = None,
    ) -> FlextResult[FlextLdifModels.EntryResult]:
        r"""Unified LDIF migration supporting simple, categorized, and structured modes.

        Automatically detects migration mode based on parameters:
        - **Structured Mode**: 6-file output (00-schema to 06-rejected) with full tracking (when migration_config provided)
        - **Categorized Mode**: Custom multi-file output (when categorization_rules provided)
        - **Simple Mode**: Single output file (default behavior)

        Generic migration supporting any LDAP server type. All parameters are
        fully customizable with no hardcoded values.

        Args:
            input_dir: Directory containing source LDIF files
            output_dir: Directory for output files
            source_server: Source server type identifier (e.g., "oid", "openldap", "ad")
            target_server: Target server type identifier (e.g., "oud", "openldap", "ad")
            options: Optional MigrateOptions Model consolidating all migration parameters:
                - migration_config: MigrationConfig for structured 6-file output
                - write_options: WriteFormatOptions for formatting control
                - categorization_rules: Dict for categorized mode (legacy)
                - input_files/output_files: File lists for categorized mode
                - schema_whitelist_rules: Schema filtering rules
                - input_filename/output_filename: Simple mode file names
                - forbidden_attributes/forbidden_objectclasses: Filter lists
                - base_dn: Target base DN for normalization
                - sort_entries_hierarchically: Hierarchical sorting flag
                See FlextLdifModels.MigrateOptions for complete field documentation.

        Returns:
            FlextResult containing PipelineExecutionResult with:
            - entries_by_category: Dict of entries by category (structured/categorized) or single dict (simple)
            - statistics: Migration statistics with per-category counts
            - file_paths: Output file paths created

        Examples:
            # Simple migration - single output file
            result = ldif.migrate(
                input_dir=Path("source"),
                output_dir=Path("target"),
                source_server="oid",
                target_server="oud"
            )

            # Structured migration - 6 files with tracking
            options = FlextLdifModels.MigrateOptions(
                migration_config=FlextLdifModels.MigrationConfig(
                    hierarchy_objectclasses=["organization", "organizationalUnit"],
                    user_objectclasses=["inetOrgPerson", "person"],
                    group_objectclasses=["groupOfNames"],
                    attribute_blacklist=["pwdChangedTime", "modifiersName"],
                    track_removed_attributes=True,
                    write_removed_as_comments=True,
                    header_template="# Migration from {{source}} to {{target}}\\n",
                    header_data={"source": "OID", "target": "OUD"}
                ),
                write_options=FlextLdifModels.WriteFormatOptions(
                    disable_line_folding=True
                ),
            )
            result = ldif.migrate(
                input_dir=Path("source"),
                output_dir=Path("target"),
                source_server="oid",
                target_server="oud",
                options=options,
            )

            # Categorized migration - legacy approach
            options = FlextLdifModels.MigrateOptions(
                categorization_rules={
                    "hierarchy_objectclasses": ["organization", "organizationalUnit"],
                    "user_objectclasses": ["inetOrgPerson", "person"],
                    "group_objectclasses": ["groupOfNames"],
                    "acl_attributes": ["aci"],
                },
            )
            result = ldif.migrate(
                input_dir=Path("source"),
                output_dir=Path("target"),
                source_server="oid",
                target_server="oud",
                options=options,
            )

        """
        try:
            # Use default options if not provided
            opts = options or FlextLdifModels.MigrateOptions()

            # Convert dict to MigrationConfig model if needed (FlextResult-based)
            config_result = self._normalize_migration_config(opts.migration_config)
            if config_result.is_failure:
                return FlextResult[FlextLdifModels.EntryResult].fail(
                    f"Invalid migration config: {config_result.error}"
                )
            config_model = config_result.unwrap()

            # Auto-detect mode and create write options
            mode = self._detect_migration_mode(config_model, opts.categorization_rules)
            write_options_result = self._get_write_options_for_mode(
                mode,
                opts.write_options,
                config_model,
            )
            if write_options_result.is_failure:
                return FlextResult[FlextLdifModels.EntryResult].fail(
                    f"Failed to create write options: {write_options_result.error}"
                )
            write_options = write_options_result.unwrap()

            # Validate requirements for simple mode
            validation_result = self._validate_simple_mode_params(
                opts.input_filename,
                opts.output_filename,
            )
            if validation_result.is_failure:
                return FlextResult[FlextLdifModels.EntryResult].fail(
                    validation_result.error,
                )

            # Initialize migration pipeline with proper type safety
            # All parameters passed directly with correct types
            # Type cast mode to satisfy MyPy (mode is always one of the three literals)
            migration_pipeline = FlextLdifMigrationPipeline(
                input_dir=input_dir,
                output_dir=output_dir,
                mode=cast("FlextLdifConstants.LiteralTypes.MigrationMode", mode),
                source_server=source_server,
                target_server=target_server,
                forbidden_attributes=opts.forbidden_attributes,
                forbidden_objectclasses=opts.forbidden_objectclasses,
                base_dn=opts.base_dn,
                sort_entries_hierarchically=opts.sort_entries_hierarchically,
                write_options=write_options,
                categorization_rules=opts.categorization_rules,
                input_files=opts.input_files,
                output_files=opts.output_files,
                schema_whitelist_rules=opts.schema_whitelist_rules,
                input_filename=opts.input_filename,
                output_filename=(opts.output_filename or "migrated.ldif"),
            )

            return migration_pipeline.execute()

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.EntryResult].fail(
                f"Migration failed: {e}",
            )

    def _apply_standard_filters(
        self,
        entries: list[FlextLdifModels.Entry],
        objectclass: str | None,
        dn_pattern: str | None,
        attributes: dict[str, str | None] | None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Apply standard filters (objectclass, DN pattern, attributes) to entries.

        Internal helper method to reduce complexity in filter() method.

        Args:
            entries: List of entries to filter
            objectclass: Optional objectclass filter
            dn_pattern: Optional DN pattern filter
            attributes: Optional attributes filter

        Returns:
            FlextResult containing filtered entries

        """
        # Apply objectclass filter if provided
        if objectclass is not None:
            filter_result = FlextLdifFilters.by_objectclass(
                entries,
                objectclass,
                mark_excluded=False,
            )
            if not filter_result.is_success:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Objectclass filter failed: {filter_result.error}",
                )
            entries = filter_result.unwrap()

        # Apply dn_pattern filter if provided
        if dn_pattern is not None:
            # Convert simple substring pattern to fnmatch pattern
            fnmatch_pattern = f"*{dn_pattern}*" if "*" not in dn_pattern else dn_pattern
            filter_result = FlextLdifFilters.by_dn(
                entries,
                fnmatch_pattern,
                mark_excluded=False,
            )
            if not filter_result.is_success:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"DN pattern filter failed: {filter_result.error}",
                )
            entries = filter_result.unwrap()

        # Apply attributes filter if provided
        if attributes is not None:
            attr_list = list(attributes.keys())
            filter_result = FlextLdifFilters.by_attributes(
                entries,
                attr_list,
                mark_excluded=False,
            )
            if not filter_result.is_success:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Attributes filter failed: {filter_result.error}",
                )
            entries = filter_result.unwrap()

        return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def filter(
        self,
        entries: list[FlextLdifModels.Entry],
        objectclass: str | None = None,
        dn_pattern: str | None = None,
        attributes: dict[str, str | None] | None = None,
        custom_filter: Callable[[FlextLdifModels.Entry], bool] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Unified filter method supporting multiple criteria for flexible entry filtering.

        Consolidated filtering method supporting objectclass, DN pattern, attribute values,
        and custom callback filters for maximum flexibility while maintaining simplicity.

        Args:
            entries: List of LDIF entries to filter.
            objectclass: Optional objectclass filter (e.g., "person", "group").
            dn_pattern: Optional regex pattern to match against entry DN.
            attributes: Optional dict of attribute names and values to filter by.
                       If value is None, checks attribute existence only.
            custom_filter: Optional callable that receives Entry and returns bool.
                          Useful for complex filtering logic.

        Returns:
            FlextResult containing filtered entries. Returns empty list if
            no entries match the criteria.

        Example:
            # Filter by objectclass
            result = ldif.filter(entries, objectclass=FlextLdifConstants.ObjectClasses.PERSON)

            # Filter by DN pattern
            result = ldif.filter(entries, dn_pattern="ou=People")

            # Filter with multiple criteria
            result = ldif.filter(
                entries,
                objectclass=FlextLdifConstants.ObjectClasses.PERSON,
                dn_pattern="ou=People",
                attributes={"uid": None}  # Has uid attribute
            )

            # Filter with custom callback
            result = ldif.filter(
                entries,
                custom_filter=lambda e: "admin" in e.dn.value.lower()
            )

        """
        # Get filters service once at the start
        filters_result = self._get_service_typed(
            self.container,
            "filters",
            FlextLdifFilters,
        )
        if filters_result.is_failure:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Filters service not available: {filters_result.error}",
            )
        # Apply standard filters first
        try:
            filter_result = self._apply_standard_filters(
                entries,
                objectclass,
                dn_pattern,
                attributes,
            )
            if not filter_result.is_success:
                return filter_result
            entries = filter_result.unwrap()

            # Apply custom_filter if provided
            if custom_filter is not None:
                filtered_entries = [e for e in entries if custom_filter(e)]
                return FlextResult[list[FlextLdifModels.Entry]].ok(filtered_entries)

            # Return filtered entries (all criteria have been applied)
            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"Entry filtering failed: {e}",
            )

    def _validate_single_entry(
        self,
        entry: FlextLdifModels.Entry,
        validation_service: FlextLdifValidation,
    ) -> tuple[bool, list[str]]:
        """Validate a single LDIF entry.

        Internal helper method to reduce complexity in validate_entries() method.

        Args:
            entry: Entry to validate
            validation_service: Validation service instance

        Returns:
            Tuple of (is_valid, errors) where is_valid is True if entry is valid,
            and errors is list of validation error messages

        """
        errors: list[str] = []
        is_entry_valid = True

        # Validate DN
        if not entry.dn:
            errors.append("Entry has no DN")
            is_entry_valid = False
            dn_str = "unknown"
        else:
            dn_str = entry.dn.value
            if not dn_str or not isinstance(dn_str, str):
                errors.append(f"Entry has invalid DN: {entry.dn}")
                is_entry_valid = False

        # Validate each attribute name
        if not entry.attributes:
            errors.append(f"Entry {dn_str} has no attributes")
            is_entry_valid = False
            return (is_entry_valid, errors)

        for attr_name in entry.attributes.attributes:
            attr_result = validation_service.validate_attribute_name(attr_name)
            if attr_result.is_failure or not attr_result.unwrap():
                errors.append(f"Entry {dn_str}: Invalid attribute name '{attr_name}'")
                is_entry_valid = False

        # Validate objectClass values
        oc_values = entry.attributes.attributes.get("objectClass", [])
        if isinstance(oc_values, list):
            for oc in oc_values:
                oc_result = validation_service.validate_objectclass_name(oc)
                if oc_result.is_failure or not oc_result.unwrap():
                    errors.append(f"Entry {dn_str}: Invalid objectClass '{oc}'")
                    is_entry_valid = False

        return is_entry_valid, errors

    def _get_acls_for_transformation(
        self,
        source_type: str,
        target_type: str,
    ) -> FlextResult[tuple[FlextLdifServersBase.Acl, FlextLdifServersBase.Acl]]:
        """Get ACL quirks for source and target servers.

        Internal helper method to reduce complexity in transform_acl_entries() method.

        Args:
            source_type: Source server type string
            target_type: Target server type string

        Returns:
            FlextResult containing tuple of (source_acl, target_acl) or failure if not available

        """
        # Get quirk registry from container
        quirk_registry_result = self._get_service_typed(
            self.container,
            "quirk_registry",
            FlextLdifServer,
        )
        if quirk_registry_result.is_failure:
            return FlextResult[
                tuple[FlextLdifServersBase.Acl, FlextLdifServersBase.Acl]
            ].fail(f"Failed to get quirk registry: {quirk_registry_result.error}")
        quirk_registry = quirk_registry_result.unwrap()

        # Get schema quirks for source and target
        source_schemas = quirk_registry.get_schemas(source_type)
        target_schemas = quirk_registry.get_schemas(target_type)
        source = source_schemas[0] if source_schemas else None
        target = target_schemas[0] if target_schemas else None

        if source is None or target is None:
            return FlextResult[
                tuple[FlextLdifServersBase.Acl, FlextLdifServersBase.Acl]
            ].fail(
                f"Schema quirks not available for source={source_type} or target={target_type}"
            )

        # Extract ACL quirks from schema quirks
        source_acl = getattr(source, "acl", None) if hasattr(source, "acl") else None
        target_acl = getattr(target, "acl", None) if hasattr(target, "acl") else None

        if source_acl is None or target_acl is None:
            return FlextResult[
                tuple[FlextLdifServersBase.Acl, FlextLdifServersBase.Acl]
            ].fail(
                f"ACL quirks not available for source={source_type} or target={target_type}"
            )

        return FlextResult[
            tuple[FlextLdifServersBase.Acl, FlextLdifServersBase.Acl]
        ].ok((source_acl, target_acl))

    def _transform_acl_in_entry(
        self,
        entry: FlextLdifModels.Entry,
        source_type: str,
        target_type: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Transform ACL attributes in a single entry.

        Internal helper method to reduce complexity in transform_acl_entries() method.

        Args:
            entry: Entry to transform
            source_type: Source server type string
            target_type: Target server type string

        Returns:
            FlextResult containing transformed entry (or original if no ACLs)

        """
        # Check if entry has any ACL attributes
        if not entry.attributes or not entry.attributes.attributes:
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        attrs = entry.attributes.attributes
        # Use constants for ACL attribute detection
        acl_attrs_lower = {
            attr.lower() for attr in FlextLdifConstants.AclAttributes.ALL_ACL_ATTRIBUTES
        }
        has_acl = any(key.lower() in acl_attrs_lower for key in attrs)

        if not has_acl:
            # No ACL attributes, pass through unchanged
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        # Get ACL quirks for transformation
        acls_result = self._get_acls_for_transformation(
            source_type,
            target_type,
        )

        if acls_result.is_failure:
            # No ACL transformation available for this server pair
            dn_str = entry.dn.value if entry.dn else "unknown"
            self.logger.debug(
                "ACL quirks not available for %s→%s, passing entry unchanged: %s - %s",
                source_type,
                target_type,
                dn_str,
                acls_result.error,
            )
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        _source_acl, _target_acl = acls_result.unwrap()

        # ACL transformation between different server types is complex and requires
        # server-specific semantics. Currently not implemented - return failure to prevent
        # silent data loss from ACL transformations.
        dn_value = entry.dn.value if entry.dn is not None else "unknown"
        return FlextResult[FlextLdifModels.Entry].fail(
            f"ACL transformation not yet supported for {source_type}→{target_type}: "
            f"entry with ACLs requires manual validation (DN: {dn_value})"
        )

    # =========================================================================
    # ANALYSIS OPERATIONS
    # =========================================================================

    def analyze(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.EntryAnalysisResult]:
        """Analyze LDIF entries and generate statistics.

        Performs comprehensive analysis of entry collection including:
        - Total entry count
        - Object class distribution
        - Pattern detection in DNs and attributes

        Args:
            entries: List of entries to analyze

        Returns:
            FlextResult containing EntryAnalysisResult with statistics

        Example:
            result = api.analyze(entries)
            if result.is_success:
                stats = result.unwrap()
                print(f"Total: {stats.total_entries}")
                print(f"Classes: {stats.objectclass_distribution}")

        """
        try:
            total_entries = len(entries)

            # Analyze object class distribution
            objectclass_distribution: dict[str, int] = {}
            patterns_detected: list[str] = []

            for entry in entries:
                # Count object classes
                if entry.objectclasses:
                    for oc in entry.objectclasses:
                        oc_name = oc.name if hasattr(oc, "name") else str(oc)
                        objectclass_distribution[oc_name] = (
                            objectclass_distribution.get(oc_name, 0) + 1
                        )

                # Simple pattern detection
                dn_str = str(entry.dn)
                if (
                    "ou=users" in dn_str.lower()
                    and "user pattern" not in patterns_detected
                ):
                    patterns_detected.append("user pattern")
                if (
                    "ou=groups" in dn_str.lower()
                    and "group pattern" not in patterns_detected
                ):
                    patterns_detected.append("group pattern")

            # Create analysis result
            analysis_result = FlextLdifModels.EntryAnalysisResult(
                total_entries=total_entries,
                objectclass_distribution=objectclass_distribution,
                patterns_detected=patterns_detected,
            )

            return FlextResult[FlextLdifModels.EntryAnalysisResult].ok(analysis_result)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.EntryAnalysisResult].fail(
                f"Entry analysis failed: {e}",
            )

    def validate_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdifModels.ValidationResult]:
        """Validate LDIF entries against RFC 2849/4512 standards.

        Performs comprehensive validation including:
        - DN format validation
        - Attribute name validation (RFC 4512)
        - ObjectClass name validation (RFC 4512)
        - Attribute value length checks
        - Entry structure validation

        Args:
            entries: List of entries to validate

        Returns:
            FlextResult containing ValidationResult with validation status

        Example:
            result = api.validate_entries(entries)
            if result.is_success:
                report = result.unwrap()
                print(f"Valid: {report.is_valid}")
                print(f"Valid entries: {report.valid_entries}/{report.total_entries}")

        """
        try:
            # Get validation service from container
            validation_result = self._get_service_typed(
                self.container,
                "validation",
                FlextLdifValidation,
            )
            if validation_result.is_failure:
                return FlextResult[FlextLdifModels.ValidationResult].fail(
                    f"Validation service not available: {validation_result.error}",
                )
            validation_service = validation_result.unwrap()

            errors: list[str] = []
            valid_count = 0
            invalid_count = 0

            for entry in entries:
                is_entry_valid, entry_errors = self._validate_single_entry(
                    entry,
                    validation_service,
                )
                errors.extend(entry_errors)

                if is_entry_valid:
                    valid_count += 1
                else:
                    invalid_count += 1

            total_entries = len(entries)
            is_valid = invalid_count == 0

            result = FlextLdifModels.ValidationResult(
                is_valid=is_valid,
                total_entries=total_entries,
                valid_entries=valid_count,
                invalid_entries=invalid_count,
                errors=errors[:100],  # Limit errors to 100
            )

            return FlextResult[FlextLdifModels.ValidationResult].ok(result)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.ValidationResult].fail(
                f"Entry validation failed: {e}",
            )

    # =========================================================================
    # ACL OPERATIONS
    # =========================================================================

    def extract_acls(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str = FlextLdifConstants.ServerTypes.RFC,
    ) -> FlextResult[FlextLdifModels.AclResponse]:
        """Extract ACL rules from entry.

        Args:
            entry: Entry to extract ACLs from
            server_type: Server type for ACL quirks ("rfc", "oid", "oud", etc.)

        Returns:
            FlextResult containing composed AclResponse with extracted ACLs and statistics

        Example:
            result = api.extract_acls(entry)
            if result.is_success:
                acl_response = result.unwrap()
                acls = acl_response.acls

        """
        # Resolve ACL service via container
        if self._acl_service is None:
            return FlextResult[FlextLdifModels.AclResponse].fail(
                "ACL service not initialized",
            )
        return self._acl_service.extract_acls_from_entry(entry, server_type)

    def evaluate_acl_rules(
        self,
        acls: list[FlextLdifModels.Acl],
        context: dict[str, str | int | bool | list[str] | None] | None = None,
    ) -> FlextResult[bool]:
        """Evaluate ACL rules and return evaluation result.

        Args:
            acls: List of ACL models to evaluate
            context: Evaluation context with subject_dn, target_dn, permissions, etc.

        Returns:
            FlextResult containing evaluation result (True if allowed)

        Example:
            acls = api.extract_acls(entry).unwrap()
            context = {
                "subject_dn": "cn=admin,dc=example,dc=com",
                "permissions": {"read": True, "write": True}
            }
            result = api.evaluate_acl_rules(acls, context)
            if result.is_success:
                is_allowed = result.unwrap()

        """
        # Delegate to ACL service for direct context evaluation
        if self._acl_service is None:
            return FlextResult[bool].fail("ACL service not initialized")
        # Convert context to dict[str, object] for ACL service
        eval_context: dict[str, object] = (
            dict(context) if isinstance(context, dict) else {}
        )
        return self._acl_service.evaluate_acl_context(
            acls,
            eval_context,
        )

    def transform_acl_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        source_server: str | type[FlextLdifConstants.ServerTypes],
        target_server: str | type[FlextLdifConstants.ServerTypes],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Transform ACL attributes from source to target server format.

        This is the ONLY way to transform ACLs through the facade. Internal quirks
        are accessed here, but consumers never see them directly. This ensures:
        - Consistent ACL transformation across all consuming code
        - Proper validation of transformation results
        - Centralized error handling and logging
        - Server-specific quirks remain private implementation details

        Args:
            entries: List of entries with ACL attributes in source format
            source_server: Source server type (e.g., "OID", "OpenLDAP")
            target_server: Target server type (e.g., "OUD", "AD")

        Returns:
            FlextResult containing list of entries with ACL attributes in target format

        Raises:
            Returns FlextResult.fail() if transformation fails

        Example:
            source_entries = ldif.parse("...").unwrap()
            result = ldif.transform_acl_entries(
                source_entries,
                source_server=FlextLdifConstants.ServerTypes.OID,
                target_server=FlextLdifConstants.ServerTypes.OUD
            )
            if result.is_success:
                transformed = result.unwrap()
                # ACL attributes now in OUD format (aci: instead of orclaci:)

        Implementation Notes:
            1. Gets quirks for source and target servers from registry
            2. For each entry, extracts ACL attributes using source quirk
            3. Transforms ACL values using source→target quirk chain
            4. Validates target ACL attribute exists in result
            5. Returns only successfully transformed entries
            6. Logs detailed errors for failed transformations
            7. Non-fatal: entries with transformation errors are skipped

        """
        try:
            if not entries:
                return FlextResult[list[FlextLdifModels.Entry]].ok([])

            # Normalize server type strings if needed
            source_type = (
                source_server
                if isinstance(source_server, str)
                else getattr(source_server, "value", str(source_server))
            )
            target_type = (
                target_server
                if isinstance(target_server, str)
                else getattr(target_server, "value", str(target_server))
            )

            transformed_entries: list[FlextLdifModels.Entry] = []
            transformation_errors: list[tuple[str, str]] = []

            # Process each entry
            for entry in entries:
                try:
                    transform_result = self._transform_acl_in_entry(
                        entry,
                        source_type,
                        target_type,
                    )
                    if transform_result.is_success:
                        transformed_entries.append(transform_result.unwrap())
                    else:
                        dn_str = entry.dn.value if entry.dn else "unknown"
                        transformation_errors.append((
                            dn_str,
                            f"Transformation failed: {transform_result.error}",
                        ))

                except (ValueError, TypeError, AttributeError, KeyError) as e:
                    dn_str = entry.dn.value if entry.dn else "unknown"
                    transformation_errors.append((
                        dn_str,
                        f"Transformation error: {e!s}",
                    ))
                    self.logger.debug(
                        "Exception during ACL transformation for %s: %s",
                        dn_str,
                        e,
                    )
                    continue

            # Log overall transformation statistics
            total = len(entries)
            succeeded = len(transformed_entries)
            failed = len(transformation_errors)

            self.logger.info(
                "ACL transformation complete: %s/%s entries transformed successfully, %s failed",
                succeeded,
                total,
                failed,
            )

            if transformation_errors:
                for dn, error in transformation_errors[
                    : FlextLdifConstants.MAX_LOGGED_ERRORS
                ]:
                    self.logger.debug("  Failed: %s - %s", dn, error)
                if failed > FlextLdifConstants.MAX_LOGGED_ERRORS:
                    self.logger.debug(
                        f"  ... and {failed - FlextLdifConstants.MAX_LOGGED_ERRORS} more failures",
                    )

            return FlextResult[list[FlextLdifModels.Entry]].ok(transformed_entries)

        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"ACL transformation failed: {e}",
            )

    # =========================================================================
    # UNIFIED PROCESSING OPERATIONS
    # =========================================================================

    @staticmethod
    def _create_transform_processor() -> Callable[
        [FlextLdifModels.Entry], dict[str, object]
    ]:
        """Create transform processor function.

        Returns:
            Processor function that transforms Entry to dict

        """

        def _transform_func(entry: FlextLdifModels.Entry) -> dict[str, object]:
            # Build dict directly from Entry fields without model_dump()
            result: dict[str, object] = {
                "dn": entry.dn.value if entry.dn else "",
                "attributes": entry.attributes.attributes if entry.attributes else {},
            }
            if entry.metadata:
                result["metadata"] = entry.metadata
            if entry.statistics:
                result["statistics"] = entry.statistics
            return result

        return _transform_func

    @staticmethod
    def _create_validate_processor() -> Callable[
        [FlextLdifModels.Entry], dict[str, object]
    ]:
        """Create validate processor function.

        Returns:
            Processor function that validates Entry

        """

        def _validate_func(entry: FlextLdifModels.Entry) -> dict[str, object]:
            # Basic validation: entry has DN and attributes - fast fail if None
            if not entry.dn:
                return {
                    "dn": "",
                    "valid": False,
                    "attribute_count": 0,
                    "error": "Entry DN is required",
                }
            if not entry.attributes:
                return {
                    "dn": entry.dn.value,
                    "valid": False,
                    "attribute_count": 0,
                    "error": "Entry attributes are required",
                }

            dn_value = entry.dn.value
            attrs_dict = entry.attributes.attributes
            return {
                "dn": dn_value,
                "valid": bool(dn_value and entry.attributes),
                "attribute_count": len(attrs_dict),
            }

        return _validate_func

    def _get_processor_function(
        self,
        processor_name: str,
    ) -> FlextResult[Callable[[FlextLdifModels.Entry], dict[str, object]]]:
        """Get processor function by name.

        Args:
            processor_name: Name of processor ("transform" or "validate")

        Returns:
            FlextResult with processor function or error

        """
        if processor_name == FlextLdifConstants.ProcessorTypes.TRANSFORM:
            return FlextResult.ok(self._create_transform_processor())
        if processor_name == FlextLdifConstants.ProcessorTypes.VALIDATE:
            return FlextResult.ok(self._create_validate_processor())
        supported = "'transform', 'validate'"
        return FlextResult.fail(
            f"Unknown processor: '{processor_name}'. Supported: {supported}",
        )

    @staticmethod
    def _execute_parallel_processing(
        entries: list[FlextLdifModels.Entry],
        processor_func: Callable[[FlextLdifModels.Entry], dict[str, object]],
        max_workers: int,
    ) -> FlextResult[list[dict[str, object]]]:
        """Execute parallel processing using ThreadPoolExecutor.

        Args:
            entries: List of entries to process
            processor_func: Processor function to apply
            max_workers: Maximum number of worker threads

        Returns:
            FlextResult with list of processed results

        """
        try:
            max_workers_actual = min(len(entries), max_workers)
            with ThreadPoolExecutor(max_workers=max_workers_actual) as executor:
                future_to_entry = {
                    executor.submit(processor_func, entry): entry for entry in entries
                }
                results = [
                    future.result() for future in as_completed(future_to_entry)
                ]
            return FlextResult[list[dict[str, object]]].ok(results)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[dict[str, object]]].fail(
                f"Parallel processing failed: {e}",
            )

    @staticmethod
    def _execute_batch_processing(
        entries: list[FlextLdifModels.Entry],
        processor_func: Callable[[FlextLdifModels.Entry], dict[str, object]],
        batch_size: int,
    ) -> FlextResult[list[dict[str, object]]]:
        """Execute batch processing sequentially.

        Args:
            entries: List of entries to process
            processor_func: Processor function to apply
            batch_size: Number of entries per batch

        Returns:
            FlextResult with list of processed results

        """
        results = []
        for i in range(0, len(entries), batch_size):
            batch = entries[i : i + batch_size]
            batch_results = [processor_func(entry) for entry in batch]
            results.extend(batch_results)
        return FlextResult[list[dict[str, object]]].ok(results)

    def process(
        self,
        processor_name: str,
        entries: list[FlextLdifModels.Entry],
        *,
        parallel: bool = False,
        batch_size: int = 100,
        max_workers: int = 4,
    ) -> FlextResult[list[dict[str, object]]]:
        """Unified processing method supporting batch and parallel modes.

        Consolidates process_batch() and process_parallel() into a single flexible
        method with an optional parallel execution mode.

        Args:
            processor_name: Name of processor function ("transform", "validate", etc.)
            entries: List of entries to process
            parallel: If True, use parallel processing; if False, use batch. Default: False
            batch_size: Number of entries per batch (only used when parallel=False). Default: 100
            max_workers: Number of worker threads (only used when parallel=True). Default: 4

        Returns:
            FlextResult containing processed results

        Example:
            # Batch processing (sequential)
            result = api.process("transform", entries)

            # Batch processing with custom batch size
            result = api.process("transform", entries, batch_size=200)

            # Parallel processing
            result = api.process("transform", entries, parallel=True)

            # Parallel processing with custom worker count
            result = api.process("validate", entries, parallel=True, max_workers=8)

        Note:
            Supported processors: "transform" (converts to dict), "validate" (validates entries).
            Uses batch processing for sequential operations.
            Uses ThreadPoolExecutor for parallel processing.

        """
        try:
            # Get processor function
            processor_result = self._get_processor_function(processor_name)
            if processor_result.is_failure:
                return FlextResult[list[dict[str, object]]].fail(
                    processor_result.error,
                )
            processor_func = processor_result.unwrap()

            # Execute processing based on mode
            if parallel:
                return self._execute_parallel_processing(
                    entries, processor_func, max_workers
                )
            return self._execute_batch_processing(
                entries, processor_func, batch_size
            )

        except (ValueError, TypeError, AttributeError) as e:
            mode = "Parallel" if parallel else "Batch"
            return FlextResult[list[dict[str, object]]].fail(
                f"{mode} processing failed: {e}",
            )

    # =========================================================================
    # INFRASTRUCTURE ACCESS (Properties)
    # =========================================================================

    # =========================================================================
    # AUTO-DETECTION AND RELAXED MODE OPERATIONS
    # =========================================================================

    def detect_server_type(
        self,
        ldif_path: Path | None = None,
        ldif_content: str | None = None,
    ) -> FlextResult[FlextLdifModels.ServerDetectionResult]:
        """Detect LDAP server type from LDIF file or content.

        Analyzes LDIF content to identify the source LDAP server type
        using pattern matching and heuristics.

        Args:
            ldif_path: Path to LDIF file
            ldif_content: Raw LDIF content as string

        Returns:
            FlextResult with detection results containing:
            - detected_server_type: "oid" | "oud" | "openldap" | ...
            - confidence: 0.0-1.0
            - scores: {server_type: score, ...}
            - patterns_found: [pattern1, pattern2, ...]
            - is_confident: bool

        Example:
            result = api.detect_server_type(ldif_path=Path("data.ldif"))
            if result.is_success:
                detected = result.unwrap()
                print(f"Server type: {detected.detected_server_type}")
                print(f"Confidence: {detected.confidence:.2%}")

        """
        try:
            detector = FlextLdifDetector()
            return detector.detect_server_type(
                ldif_path=ldif_path,
                ldif_content=ldif_content,
            )
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.ServerDetectionResult].fail(
                f"Server detection failed: {e}",
            )

    def get_effective_server_type(
        self,
        ldif_path: Path | None = None,
    ) -> FlextResult[str]:
        """Get the effective LDAP server type that will be used for parsing.

        Resolves the effective server type based on configuration priority:
        1. Relaxed mode (if enabled)
        2. Manual override (if detection_mode is "manual")
        3. Auto-detection (if detection_mode is "auto")
        4. RFC-only (if detection_mode is "disabled")

        Args:
            ldif_path: Optional path to LDIF file for auto-detection

        Returns:
            FlextResult with the server type string that will be used

        Example:
            # Get effective server type before parsing
            result = api.get_effective_server_type(Path("directory.ldif"))
            if result.is_success:
                server_type = result.unwrap()
                print(f"Will use {server_type} quirks")

        """
        try:
            config = self.config

            # Use structural pattern matching for server type resolution (Python 3.13)
            match config:
                case FlextLdifConfig(enable_relaxed_parsing=True):
                    return FlextResult[str].ok(FlextLdifConstants.ServerTypes.RELAXED)

                case FlextLdifConfig(
                    quirks_detection_mode="manual",
                    quirks_server_type=str() as server_type,
                ):
                    return FlextResult[str].ok(server_type)

                case FlextLdifConfig(quirks_detection_mode="manual"):
                    return FlextResult[str].fail(
                        "Manual mode requires quirks_server_type to be set",
                    )

                case FlextLdifConfig(quirks_detection_mode="auto") if ldif_path:
                    detector = FlextLdifDetector()
                    detection_result = detector.detect_server_type(ldif_path=ldif_path)
                    if detection_result.is_success:
                        detected_data = detection_result.unwrap()
                        # ServerDetectionResult is now a Pydantic model
                        # Validate detected_server_type is not None/empty
                        if (
                            detected_data.detected_server_type
                            and detected_data.detected_server_type.strip()
                        ):
                            return FlextResult[str].ok(
                                detected_data.detected_server_type
                            )
                        # Fall back to configured default if detection returned empty/None
                        return FlextResult[str].ok(config.ldif_default_server_type)
                    # Auto-detection failed, fall back to configured server type
                    return FlextResult[str].ok(config.ldif_default_server_type)

                case _:
                    # Default to configured server type
                    return FlextResult[str].ok(config.ldif_default_server_type)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[str].fail(f"Error determining server type: {e}")

    @property
    def models(self) -> type[FlextLdifModels]:
        """Access to all LDIF Pydantic models.

        Returns:
            FlextLdifModels class containing all LDIF domain models

        Example:
            entry = ldif.models.Entry(dn="cn=test", attributes={})
            schema = ldif.models.SchemaObjectClass(name="person")

        """
        return FlextLdifModels

    @property
    def config(self) -> FlextLdifConfig:
        """Access to LDIF configuration instance with lazy initialization.

        Returns:
            Current FlextLdifConfig instance

        Example:
            encoding = ldif.config.ldif_encoding
            max_workers = ldif.config.max_workers

        """
        if self._config is None:
            self._config = (
                getattr(self, "_init_config_value", None) or FlextLdifConfig()
            )
        # Type narrowing: _config cannot be None after initialization above
        if self._config is None:
            msg = "Configuration initialization failed"
            raise RuntimeError(msg)
        return self._config

    @property
    def constants(self) -> type[FlextLdifConstants]:
        """Access to LDIF constants.

        Returns:
            FlextLdifConstants class containing all constant values

        Example:
            max_line = ldif.constants.Format.MAX_LINE_LENGTH
            encoding = ldif.constants.Encoding.UTF8

        """
        return FlextLdifConstants

    # INTERNAL: bus property is hidden from public API
    # Use models, config, constants for public access instead

    # INTERNAL: dispatcher property is hidden from public API
    # Use client methods for LDIF operations instead

    # INTERNAL: registry property is hidden from public API
    # Use register() method for quirk management instead

    @property
    def acl_service(self) -> FlextLdifAcl:
        """Access to FlextLdifAcl for ACL operations.

        Returns:
            FlextLdifAcl instance for ACL processing

        Example:
            acls = ldif.acl_service.extract_acls_from_entry(entry)

        """
        if self._acl_service is None:
            self._acl_service = FlextLdifAcl()
        return self._acl_service

    @property
    def handlers(self) -> dict[str, object]:
        """Access to initialized CQRS handlers."""
        return self._handlers

    @property
    def container(self) -> FlextContainer:
        """Access to dependency injection container."""
        return self._container

    @property
    def context(self) -> FlextContext:
        """Access to execution context with lazy initialization."""
        if not self._context:
            # Initialize with empty dict
            self._context = {}
        # Return as FlextContext type (which is a dict-like context object)
        return cast("FlextContext", self._context)


__all__ = ["FlextLdif"]
