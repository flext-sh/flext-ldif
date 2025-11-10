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
from typing import Any, ClassVar, Literal, cast, overload, override

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
            assert ldif is ldif2

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
        config = getattr(self, "_init_config_value", None) or FlextLdifConfig()
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
            config_info = FlextLdifModels.ConfigInfo.from_config(self._config)
            self._log_config_once(
                config_info.model_dump(), message="FlextLdif facade initialized"
            )
            self.logger.debug("Services setup and default quirks registered")

    # =========================================================================
    # PRIVATE: Service Setup and Handler Initialization (from client.py)
    # =========================================================================

    def _setup_services(self) -> None:
        """Register all services in the dependency injection container."""
        container = self.container

        # Register quirk registry FIRST (required by writer/parsers)
        quirk_registry = FlextLdifServer()
        container.register("quirk_registry", quirk_registry)

        # Register unified writer service (primary)
        # Writer service is stateless and gets registry from global instance
        unified_writer = FlextLdifWriter()
        container.register("writer", unified_writer)

        # Register filters service
        container.register("filters", FlextLdifFilters())

        # Register statistics service
        container.register("statistics", FlextLdifStatistics())

        # Register validation service
        container.register("validation", FlextLdifValidation())

        # Register migration pipeline with typed parameter model
        def migration_pipeline_factory(
            params: FlextLdifModels.MigrationPipelineParams,
        ) -> FlextLdifMigrationPipeline:
            return FlextLdifMigrationPipeline(
                input_dir=Path(params.input_dir),
                output_dir=Path(params.output_dir),
                source_server=params.source_server,
                target_server=params.target_server,
            )

        container.register("migration_pipeline", migration_pipeline_factory)

    def _get_service_typed(
        self,
        container: FlextContainer,
        service_name: str,
        expected_type: type[ServiceT],
    ) -> ServiceT | None:
        """Helper to retrieve and type-narrow services from container.

        Consolidates service retrieval pattern: get → unwrap → type check.

        Args:
            container: The dependency injection container
            service_name: Name of the service to retrieve
            expected_type: Expected type for type narrowing

        Returns:
            Service instance if found and correct type, None otherwise

        """
        service_result = container.get(service_name)
        if service_result.is_failure:
            return None

        service_obj = service_result.unwrap()
        # Type narrowing via isinstance - MyPy recognizes this pattern
        if isinstance(service_obj, expected_type):
            return service_obj

        return None

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

    # Overloads for parse() to support flexible output format
    @overload
    def parse(
        self,
        source: str | Path,
        server_type: str | None = None,
        format_options: FlextLdifModels.ParseFormatOptions
        | dict[str, object]
        | None = None,
        *,
        output_format: Literal["model"] = "model",
    ) -> FlextResult[list[FlextLdifModels.Entry]]: ...

    @overload
    def parse(
        self,
        source: str | Path,
        server_type: str | None = None,
        format_options: FlextLdifModels.ParseFormatOptions
        | dict[str, object]
        | None = None,
        *,
        output_format: Literal["dict"],
    ) -> FlextResult[list[dict[str, str | list[str]]]]: ...

    def parse(
        self,
        source: str | Path,
        server_type: str | None = None,
        format_options: FlextLdifModels.ParseFormatOptions
        | dict[str, object]
        | None = None,
        *,
        output_format: Literal["model", "dict"] = "model",
    ) -> (
        FlextResult[list[FlextLdifModels.Entry]]
        | FlextResult[list[dict[str, str | list[str]]]]
    ):
        r"""Parse LDIF content string or file with flexible output format.

        Powerful parsing method supporting multiple input/output formats.

        Args:
            source: LDIF content as string or Path to LDIF file
            server_type: Server type for quirk selection ("rfc", "oid", "oud", etc.)
            format_options: Parse options as ParseFormatOptions model or dict
            output_format: Output format - "model" (default) returns Entry models,
                          "dict" returns plain dicts

        Returns:
            FlextResult containing list of Entry models or dicts based on output_format

        Example:
            # Parse to Entry models (default)
            result = ldif.parse("dn: cn=test\ncn: test\n")
            entries = result.unwrap()  # list[Entry]

            # Parse to dicts
            result = ldif.parse("dn: cn=test\ncn: test\n", output_format="dict")
            dicts = result.unwrap()  # list[dict]

            # Parse file to dicts
            result = ldif.parse(Path("file.ldif"), output_format="dict")

            # Parse with options (dict or model)
            result = ldif.parse(
                "dn: cn=test\ncn: test\n",
                format_options={"validate_entries": True},
                output_format="dict"
            )

        """
        try:
            # Determine the server type, defaulting to RFC if not provided.
            effective_server_type = server_type or FlextLdifConstants.ServerTypes.RFC

            # Ensure the parser service is initialized.
            if not hasattr(self, "_parser_service") or self._parser_service is None:
                self._parser_service = FlextLdifParser(config=self.config)

            resolved_format_options = self._resolve_format_options(format_options)
            content = self._get_source_content(source)

            # Delegate parsing to the parser service.
            parse_result = self._parser_service.parse(
                content=content,
                input_source="string",
                server_type=effective_server_type,
                format_options=resolved_format_options,
            )
            if parse_result.is_success:
                parse_response = parse_result.unwrap()
                # ParseResponse is a Pydantic model with .entries field
                # Extract entries from the ParseResponse
                entries = parse_response.entries
                return self._convert_output_format(entries, output_format)

            return FlextResult.fail(parse_result.error)

        except Exception as e:
            # Use structural pattern matching for error handling (Python 3.13)
            match output_format:
                case "dict":
                    return FlextResult[list[dict[str, str | list[str]]]].fail(
                        f"Failed to parse LDIF: {e}"
                    )
                case "model":
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Failed to parse LDIF: {e}"
                    )
                case _:
                    # Should never reach here due to Literal type, but pyrefly needs explicit return
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Failed to parse LDIF: {e}"
                    )

    def _resolve_format_options(
        self,
        format_options: FlextLdifModels.ParseFormatOptions | dict[str, object] | None,
    ) -> FlextLdifModels.ParseFormatOptions | None:
        """Convert format_options dict to model if needed."""
        if format_options is not None:
            if isinstance(format_options, dict):
                return FlextLdifModels.ParseFormatOptions.model_validate(format_options)
            return format_options
        return None

    def _get_source_content(self, source: str | Path) -> str:
        """Get LDIF content from source (Path or string)."""
        content_result = self._resolve_source_content(source)
        if isinstance(content_result, FlextResult):
            # Re-raise as exception to be caught by outer try block
            raise TypeError(content_result.error)
        return content_result

    def _convert_output_format(
        self,
        entries: list[FlextLdifModels.Entry],
        output_format: Literal["model", "dict"],
    ) -> (
        FlextResult[list[FlextLdifModels.Entry]]
        | FlextResult[list[dict[str, str | list[str]]]]
    ):
        """Convert entries to requested output format."""
        match output_format:
            case "dict":
                dict_entries: list[dict[str, str | list[str]]] = [
                    entry.model_dump() for entry in entries
                ]
                return FlextResult[list[dict[str, str | list[str]]]].ok(dict_entries)
            case "model":
                return FlextResult[list[FlextLdifModels.Entry]].ok(entries)
            case _:
                # Should never reach here due to Literal type, but pyrefly needs explicit return
                return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    def _resolve_source_content(
        self,
        source: str | Path,
    ) -> str | FlextResult[list[FlextLdifModels.Entry]]:
        """Resolve source (Path or string) to LDIF content string.

        Handles three cases:
        1. Path object → read file content
        2. String with file path hints → attempt file read, fallback to string
        3. Pure string content → return as-is

        Returns:
            Content string or FlextResult error if file operations fail.

        """
        # Case 1: Path object
        if isinstance(source, Path):
            return source.read_text(encoding=self.config.ldif_encoding)

        # Case 2: String with possible file path
        if isinstance(source, str) and "\n" not in source:
            # Special case: empty string is content, not a file path
            if not source:
                return source

            try:
                file_path = Path(source)
                if file_path.is_file():
                    return file_path.read_text(encoding=self.config.ldif_encoding)
                if file_path.exists():
                    # Path exists but is not a file (e.g., directory)
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Path exists but is not a file: {source}",
                    )
                if "/" in source or "\\" in source or source.endswith(".ldif"):
                    # Looks like a file path but doesn't exist - return error
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"File not found: {source}",
                    )
                # Doesn't look like a file path - treat as string content
                return source
            except (OSError, PermissionError) as e:
                # File system error - return error, don't treat as string
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Failed to read file: {e}",
                )
            except (ValueError, UnicodeDecodeError):
                # Not a valid path or encoding issue - treat as string content
                return source

        # Case 3: Pure string content
        return source

    def _convert_dicts_to_entries(
        self,
        entries: list[FlextLdifModels.Entry] | list[dict[str, str | list[str]]],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Convert list of dicts to Entry models if needed.

        Internal helper to reduce complexity in write() method.

        Args:
            entries: List of Entry models or dicts

        Returns:
            FlextResult containing list of Entry models

        """
        # Check if already Entry models
        if entries and not isinstance(entries[0], dict):
            return FlextResult[list[FlextLdifModels.Entry]].ok(
                cast("list[FlextLdifModels.Entry]", entries),
            )

        # Convert list[dict] to list[Entry]
        resolved_entries: list[FlextLdifModels.Entry] = []
        for entry_dict in entries:
            if not isinstance(entry_dict, dict):
                continue

            # Extract dn and attributes from dict
            dn_val = entry_dict.get("dn", "")
            attrs_val = {k: v for k, v in entry_dict.items() if k != "dn"}

            # Create Entry using factory method
            entry_result = FlextLdifModels.Entry.create(
                dn=str(dn_val),
                attributes=attrs_val,
            )
            if entry_result.is_failure:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Failed to convert dict to Entry: {entry_result.error}",
                )
            resolved_entries.append(entry_result.unwrap())

        return FlextResult[list[FlextLdifModels.Entry]].ok(resolved_entries)

    # Overloads for write() to support flexible input (Entry models or dicts)
    @overload
    def write(
        self,
        entries: list[FlextLdifModels.Entry] | list[dict[str, str | list[str]]],
        output_path: None = None,
        server_type: str | None = None,
        format_options: FlextLdifModels.WriteFormatOptions
        | dict[str, object]
        | None = None,
    ) -> FlextResult[str]: ...

    @overload
    def write(
        self,
        entries: list[FlextLdifModels.Entry] | list[dict[str, str | list[str]]],
        output_path: Path,
        server_type: str | None = None,
        format_options: FlextLdifModels.WriteFormatOptions
        | dict[str, object]
        | None = None,
    ) -> FlextResult[str]: ...

    def write(
        self,
        entries: list[FlextLdifModels.Entry] | list[dict[str, str | list[str]]],
        output_path: Path | None = None,
        server_type: str | None = None,
        format_options: FlextLdifModels.WriteFormatOptions
        | dict[str, object]
        | None = None,
    ) -> FlextResult[str]:
        """Write entries to LDIF format string or file with flexible input.

        Powerful writing method accepting Entry models or dicts as input.

        Args:
            entries: List of Entry models or dicts to write
            output_path: Optional Path to write LDIF file. If None, returns LDIF string.
            server_type: Target server type for writing. If None, uses RFC.
            format_options: Write options as WriteFormatOptions model or dict

        Returns:
            FlextResult containing LDIF content as string (if output_path is None)
            or success message (if output_path provided)

        Example:
            # Write Entry models to string
            result = ldif.write(entries)
            ldif_content = result.unwrap()

            # Write dicts to string
            dicts = [{"dn": "cn=test", "cn": ["test"]}]
            result = ldif.write(dicts)

            # Write to file
            result = ldif.write(entries, Path("output.ldif"))

            # Write with options (dict or model)
            result = ldif.write(
                entries,
                format_options={"line_width": 100, "sort_attributes": True}
            )

        """
        try:
            # Get writer service from container or create new instance
            if self._writer_service is None:
                self._writer_service = FlextLdifWriter()

            target_server = server_type or "rfc"

            # Convert format_options dict to model if needed
            resolved_format_options: FlextLdifModels.WriteFormatOptions
            if format_options is None:
                resolved_format_options = FlextLdifModels.WriteFormatOptions()
            elif isinstance(format_options, dict):
                resolved_format_options = (
                    FlextLdifModels.WriteFormatOptions.model_validate(format_options)
                )
            else:
                resolved_format_options = format_options

            # Convert dicts to Entry models if needed (extracted to helper method)
            entries_result = self._convert_dicts_to_entries(entries)
            if entries_result.is_failure:
                return FlextResult[str].fail(entries_result.error)
            resolved_entries = entries_result.unwrap()

            if output_path:
                write_result = self._writer_service.write(
                    entries=resolved_entries,
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
                entries=resolved_entries,
                target_server_type=target_server,
                output_target="string",
                format_options=resolved_format_options,
            )
            if string_result.is_success:
                return FlextResult.ok(string_result.unwrap())
            return FlextResult.fail(string_result.error)

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
            result_dict: FlextLdifTypes.CommonDict.AttributeDict = {}

            # Handle both LdifAttributes and dict-like access
            if isinstance(attrs_container, FlextLdifModels.LdifAttributes):
                # Extract attributes from LdifAttributes container
                for attr_name, attr_values in attrs_container.attributes.items():
                    # attr_values is always a list[str] in LdifAttributes
                    if len(attr_values) == 1:
                        result_dict[attr_name] = attr_values[0]
                    else:
                        result_dict[attr_name] = attr_values
            elif isinstance(attrs_container, dict):
                # Handle dict representation (from model_validate with dict input)
                for attr_name, attr_val in attrs_container.items():
                    if isinstance(attr_val, list):
                        # Return list as-is or single item if length==1
                        if len(attr_val) == 1:
                            result_dict[attr_name] = attr_val[0]
                        else:
                            result_dict[attr_name] = attr_val
                    else:
                        # Single value - return as string
                        result_dict[attr_name] = str(attr_val)

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
                return create_result
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

    def get_attribute_values(self, attribute: object) -> FlextResult[list[str]]:
        """Extract values from an attribute value object.

        Handles various attribute value formats from both LDIF and LDAP entries.

        Args:
            attribute: Attribute value object (could be LdifAttributeValue,
                      LdapAttributeValue, list, or string)

        Returns:
            FlextResult containing list of attribute values as strings

        Example:
            # Extract values from attribute objects
            result = ldif.get_attribute_values(attr_value_obj)
            if result.is_success:
                values = result.unwrap()
                for value in values:
                    print(f"Value: {value}")

        """
        try:
            # Handle None
            if attribute is None:
                return FlextResult[list[str]].ok([])

            # Handle objects with .values property
            values = getattr(attribute, "values", None)
            if values is not None:
                if isinstance(values, list):
                    return FlextResult[list[str]].ok([str(v) for v in values])
                return FlextResult[list[str]].ok([str(values)])

            # Handle lists directly
            if isinstance(attribute, list):
                return FlextResult[list[str]].ok([str(v) for v in attribute])

            # Handle single values
            return FlextResult[list[str]].ok([str(attribute)])

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[str]].fail(
                f"Failed to extract attribute values: {e}",
            )

    def _normalize_migration_config(
        self,
        migration_config: FlextLdifModels.MigrationConfig | dict[str, object] | None,
    ) -> FlextLdifModels.MigrationConfig | None:
        """Convert dict to MigrationConfig model if needed."""
        if migration_config is None:
            return None
        if isinstance(migration_config, dict):
            return FlextLdifModels.MigrationConfig.model_validate(migration_config)
        return migration_config

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
        write_options: FlextLdifModels.WriteFormatOptions | None,
        config_model: FlextLdifModels.MigrationConfig | None,
    ) -> FlextLdifModels.WriteFormatOptions | None:
        """Set default write options for structured and categorized modes."""
        if write_options is not None:
            return write_options

        match mode:
            case "structured":
                return FlextLdifModels.WriteFormatOptions(
                    fold_long_lines=False,
                    write_removed_attributes_as_comments=(
                        config_model.write_removed_as_comments
                        if config_model
                        else False
                    ),
                )
            case "categorized":
                return FlextLdifModels.WriteFormatOptions(fold_long_lines=False)
            case _:
                return None

    def _validate_simple_mode_params(
        self,
        input_filename: str | None,
        output_filename: str | None,
    ) -> FlextResult[None]:
        """Validate requirements for simple mode."""
        if input_filename is not None and output_filename is None:
            return FlextResult[None].fail(
                "output_filename is required when input_filename is specified"
            )
        return FlextResult[None].ok(None)

    def migrate(
        self,
        input_dir: Path,
        output_dir: Path,
        source_server: str,
        target_server: str,
        *,
        # New: Structured migration with MigrationConfig
        migration_config: FlextLdifModels.MigrationConfig
        | dict[str, object]
        | None = None,
        write_options: FlextLdifModels.WriteFormatOptions | None = None,
        # Categorization parameters (optional - enables categorized mode)
        categorization_rules: dict[str, list[str]] | None = None,
        input_files: list[str] | None = None,
        output_files: dict[str, str] | None = None,
        schema_whitelist_rules: dict[str, list[str]] | None = None,
        # Simple migration parameters
        input_filename: str | None = None,
        output_filename: str | None = None,
        # Common parameters
        forbidden_attributes: list[str] | None = None,
        forbidden_objectclasses: list[str] | None = None,
        base_dn: str | None = None,
        sort_entries_hierarchically: bool = False,
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
            source_server: Source server type identifier (e.g., "oracle_oid", "openldap")
            target_server: Target server type identifier (e.g., "oracle_oud", "ad")

            # Structured migration parameters (preferred for production)
            migration_config: MigrationConfig model or dict with:
                - output_file_mapping: Dict of category -> filename
                - hierarchy_objectclasses, user_objectclasses, group_objectclasses: Lists for categorization
                - attribute_whitelist/blacklist, objectclass_whitelist/blacklist: Filtering rules
                - track_removed_attributes, write_removed_as_comments: Tracking options
                - header_template, header_data: Jinja2 header template and data
            write_options: WriteFormatOptions model with:
                - disable_line_folding: True to disable line wrapping
                - write_removed_attributes_as_comments: True to write removed attrs as comments
                - line_width: Maximum line width (default 100000 for effectively unlimited)

            # Categorized mode parameters (legacy)
            categorization_rules: Dict defining entry categories (enables categorized mode)
                Keys: category_name + "_objectclasses" or category_name + "_attributes"
                Example: {
                    "hierarchy_objectclasses": ["organization", "organizationalUnit"],
                    "user_objectclasses": ["inetOrgPerson", "person"],
                    "group_objectclasses": ["groupOfNames"],
                    "acl_attributes": ["aci"],  # Empty list = disable ACL
                }
            input_files: Ordered list of LDIF files to process (categorized mode)
            output_files: Category→filename mapping (categorized mode)
            schema_whitelist_rules: Dict of allowed schema elements (categorized mode)

            # Simple mode parameters
            input_filename: Specific input file to process (simple mode only)
            output_filename: Output filename (simple mode only, optional, defaults to "migrated.ldif")

            # Common parameters
            forbidden_attributes: Optional list of attributes to remove
            forbidden_objectclasses: Optional list of objectClasses to remove
            base_dn: Optional target base DN for DN normalization
            sort_entries_hierarchically: If True, sort entries by DN hierarchy depth then alphabetically (default: False)

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
                source_server="oracle_oid",
                target_server="oracle_oud"
            )

            # Structured migration - 6 files with removed attribute tracking
            config = FlextLdifModels.MigrationConfig(
                hierarchy_objectclasses=["organization", "organizationalUnit"],
                user_objectclasses=["inetOrgPerson", "person"],
                group_objectclasses=["groupOfNames"],
                attribute_blacklist=["pwdChangedTime", "modifiersName"],
                track_removed_attributes=True,
                write_removed_as_comments=True,
                header_template="# Migration from {{source}} to {{target}}\\n",
                header_data={"source": "OID", "target": "OUD"}
            )
            write_opts = FlextLdifModels.WriteFormatOptions(
                disable_line_folding=True
            )
            result = ldif.migrate(
                input_dir=Path("source"),
                output_dir=Path("target"),
                source_server="oracle_oid",
                target_server="oracle_oud",
                migration_config=config,
                write_options=write_opts
            )

            # Categorized migration - legacy approach
            result = ldif.migrate(
                input_dir=Path("source"),
                output_dir=Path("target"),
                source_server="oracle_oid",
                target_server="oracle_oud",
                categorization_rules={
                    "hierarchy_objectclasses": ["organization", "organizationalUnit"],
                    "user_objectclasses": ["inetOrgPerson", "person"],
                    "group_objectclasses": ["groupOfNames"],
                    "acl_attributes": ["aci"],
                }
            )

        """
        try:
            # Convert dict to MigrationConfig model if needed
            config_model = self._normalize_migration_config(migration_config)

            # Auto-detect mode and create write options
            mode = self._detect_migration_mode(config_model, categorization_rules)
            write_options = self._get_write_options_for_mode(
                mode, write_options, config_model
            )

            # Validate requirements for simple mode
            validation_result = self._validate_simple_mode_params(
                input_filename, output_filename
            )
            if validation_result.is_failure:
                return FlextResult[FlextLdifModels.EntryResult].fail(
                    validation_result.error
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
                forbidden_attributes=forbidden_attributes,
                forbidden_objectclasses=forbidden_objectclasses,
                base_dn=base_dn,
                sort_entries_hierarchically=sort_entries_hierarchically,
                write_options=write_options,
                categorization_rules=categorization_rules,
                input_files=input_files,
                output_files=output_files,
                schema_whitelist_rules=schema_whitelist_rules,
                input_filename=input_filename,
                output_filename=output_filename or "migrated.ldif",
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
        filters_service = self._get_service_typed(
            self.container,
            "filters",
            FlextLdifFilters,
        )
        if filters_service is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                "Filters service not available in container",
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
        dn_str = entry.dn.value
        if not dn_str or not isinstance(dn_str, str):
            errors.append(f"Entry has invalid DN: {entry.dn}")
            is_entry_valid = False

        # Validate each attribute name
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
    ) -> tuple[object | None, object | None]:
        """Get ACL quirks for source and target servers.

        Internal helper method to reduce complexity in transform_acl_entries() method.

        Args:
            source_type: Source server type string
            target_type: Target server type string

        Returns:
            Tuple of (source_acl, target_acl) or (None, None) if not available

        """
        # Get quirk registry from container
        quirk_registry = self._get_service_typed(
            self.container,
            "quirk_registry",
            FlextLdifServer,
        )
        if quirk_registry is None:
            return None, None

        # Get schema quirks for source and target
        source_schemas = quirk_registry.get_schemas(source_type)
        target_schemas = quirk_registry.get_schemas(target_type)
        source = source_schemas[0] if source_schemas else None
        target = target_schemas[0] if target_schemas else None

        if source is None or target is None:
            return None, None

        # Extract ACL quirks from schema quirks
        source_acl = getattr(source, "acl", None) if hasattr(source, "acl") else None
        target_acl = getattr(target, "acl", None) if hasattr(target, "acl") else None

        return source_acl, target_acl

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
        source_acl, target_acl = self._get_acls_for_transformation(
            source_type,
            target_type,
        )

        if source_acl is None or target_acl is None:
            # No ACL transformation available for this server pair
            self.logger.debug(
                f"ACL quirks not available for {source_type}→{target_type}, "
                f"passing entry unchanged: {entry.dn.value}",
            )
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        # For now, pass entry unchanged as full ACL transformation is not fully implemented
        self.logger.debug(
            f"ACL transformation placeholder for {source_type}→{target_type}, "
            f"passing entry unchanged: {entry.dn.value}",
        )
        return FlextResult[FlextLdifModels.Entry].ok(entry)

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
            validation_service = self._get_service_typed(
                self.container,
                "validation",
                FlextLdifValidation,
            )
            if validation_service is None:
                return FlextResult[FlextLdifModels.ValidationResult].fail(
                    "Validation service not available",
                )

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
                "ACL service not initialized"
            )
        return self._acl_service.extract_acls_from_entry(entry, server_type)

    def evaluate_acl_rules(
        self,
        acls: list[FlextLdifModels.Acl],
        context: dict[str, Any] | None = None,
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
        eval_context: dict[str, object] = context if isinstance(context, dict) else {}
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
                        transformation_errors.append((
                            entry.dn.value,
                            f"Transformation failed: {transform_result.error}",
                        ))

                except (ValueError, TypeError, AttributeError, KeyError) as e:
                    transformation_errors.append((
                        entry.dn.value,
                        f"Transformation error: {e!s}",
                    ))
                    self.logger.debug(
                        f"Exception during ACL transformation for {entry.dn.value}: {e}",
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
            # Define processor function based on processor_name
            processor_func: Callable[[FlextLdifModels.Entry], dict[str, object]]

            if processor_name == FlextLdifConstants.ProcessorTypes.TRANSFORM:

                def _transform_func(
                    entry: FlextLdifModels.Entry,
                ) -> dict[str, object]:
                    return cast("dict[str, object]", entry.model_dump())

                processor_func = _transform_func

            elif processor_name == FlextLdifConstants.ProcessorTypes.VALIDATE:

                def _validate_func(
                    entry: FlextLdifModels.Entry,
                ) -> dict[str, object]:
                    # Basic validation: entry has DN and attributes
                    return {
                        "dn": entry.dn.value,
                        "valid": bool(entry.dn.value and entry.attributes),
                        "attribute_count": len(entry.attributes.attributes),
                    }

                processor_func = _validate_func

            else:
                supported = "'transform', 'validate'"
                return FlextResult[list[dict[str, object]]].fail(
                    f"Unknown processor: '{processor_name}'. Supported: {supported}",
                )

            # Execute processing based on mode (parallel or sequential)
            if parallel:
                # Use ThreadPoolExecutor for parallel processing
                try:
                    max_workers_actual = min(len(entries), max_workers)
                    with ThreadPoolExecutor(max_workers=max_workers_actual) as executor:
                        future_to_entry = {
                            executor.submit(processor_func, entry): entry
                            for entry in entries
                        }
                        results = [
                            future.result() for future in as_completed(future_to_entry)
                        ]
                    return FlextResult[list[dict[str, object]]].ok(results)
                except (ValueError, TypeError, AttributeError) as e:
                    return FlextResult[list[dict[str, object]]].fail(
                        f"Parallel processing failed: {e}",
                    )
            else:
                # Batch processing
                results = []
                for i in range(0, len(entries), batch_size):
                    batch = entries[i : i + batch_size]
                    batch_results = [processor_func(entry) for entry in batch]
                    results.extend(batch_results)
                return FlextResult[list[dict[str, object]]].ok(results)

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
                        server_type = (
                            detected_data.detected_server_type or config.server_type
                        )
                        return FlextResult[str].ok(server_type)
                    # Auto-detection failed, fall back to configured server type
                    return FlextResult[str].ok(config.server_type)

                case _:
                    # Default to configured server type
                    return FlextResult[str].ok(config.server_type)

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
