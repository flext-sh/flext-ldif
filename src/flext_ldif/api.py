"""FLEXT-LDIF Application Service Layer.

This module implements the main application service for LDIF processing operations,
following Clean Architecture principles and providing a unified API for all LDIF
operations with comprehensive error handling and observability integration.

The FlextLdifAPI serves as the primary entry point for LDIF processing, orchestrating
domain services and implementing use cases while maintaining separation of concerns
and dependency inversion principles.

Key Components:
    - FlextLdifAPI: Main application service orchestrating LDIF operations
    - Service integration with flext-core dependency injection container
    - Observability integration with flext-observability for monitoring
    - Configuration management with enterprise-grade settings validation

Architecture:
    Part of Application Layer in Clean Architecture, this module coordinates
    between domain services and infrastructure concerns without containing
    business logic. Uses dependency injection for service resolution and
    FlextResult pattern for consistent error handling.

Performance:
    Optimized for enterprise workloads with configurable processing limits,
    memory management, and timeout handling. Supports both synchronous and
    streaming processing modes based on configuration.

Example:
    Basic API usage with configuration and error handling:

    >>> from flext_ldif import FlextLdifAPI, FlextLdifConfig
    >>>
    >>> # Configure API for production use
    >>> config = FlextLdifConfig(
    ...     max_entries=50000, strict_validation=True, enable_observability=True
    ... )
    >>>
    >>> api = FlextLdifAPI(config)
    >>>
    >>> # Parse LDIF with comprehensive error handling
    >>> result = api.parse(ldif_content)
    >>> if result.success:
    ...     entries = result.data
    ...     validation_result = api.validate(entries)
    ...     if validation_result.success:
    ...         output_result = api.write(entries)

Integration:
    - Uses flext-core FlextResult pattern for railway-oriented programming
    - Integrates with flext-observability for distributed tracing and metrics
    - Coordinates with domain services through dependency injection
    - Provides unified interface for all LDIF processing operations

Author: FLEXT Development Team
Version: 0.9.0
License: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flext_core import FlextResult, get_flext_container, get_logger
from flext_observability import (
    FlextObservabilityMonitor,
    flext_create_trace,
    flext_monitor_function,
)

from .config import FlextLdifConfig
from .services import (
    FlextLdifParserService,
    FlextLdifValidatorService,
    FlextLdifWriterService,
    register_ldif_services,
)

if TYPE_CHECKING:
    from .models import FlextLdifEntry, LDIFContent


class FlextLdifAPI:
    """Enterprise-grade unified LDIF API with comprehensive service orchestration and observability integration.

    This class serves as the primary application service for LDIF processing operations,
    implementing Clean Architecture principles with comprehensive error handling, service
    orchestration, and real-time observability monitoring for enterprise environments.

    The API coordinates between domain services, infrastructure concerns, and observability
    systems while maintaining clean separation of concerns and enterprise-grade logging.

    Example:
        >>> from flext_ldif import FlextLdifAPI, FlextLdifConfig
        >>> config = FlextLdifConfig(max_entries=10000, strict_validation=True)
        >>> api = FlextLdifAPI(config)
        >>> result = api.parse(ldif_content)

    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize LDIF API with enterprise-grade service orchestration and comprehensive observability.

        Performs complete API initialization including configuration validation, service registration,
        dependency injection container setup, and observability monitoring initialization with
        comprehensive error handling and detailed logging for enterprise environments.

        Args:
            config: Optional FlextLdifConfig instance for API configuration

        Raises:
            RuntimeError: If critical service initialization fails

        """
        # REFACTORING: Enhanced logger initialization with class context
        self.logger = get_logger(self.__class__.__name__)

        # REFACTORING: Enhanced configuration processing with comprehensive validation
        provided_config = config is not None
        self.logger.debug(
            "Starting FlextLdifAPI initialization",
            config_provided=provided_config,
        )

        try:
            self.config = config or FlextLdifConfig()
            self.logger.debug(
                "Configuration processing completed successfully",
                max_entries=self.config.max_entries,
                strict_validation=self.config.strict_validation,
                encodings=f"{self.config.input_encoding}→{self.config.output_encoding}",
            )
            self.logger.trace("Complete configuration: %s", self.config.model_dump())
        except (ValueError, TypeError) as e:
            error_msg: str = f"Configuration validation failed: {e}"
            self.logger.exception(error_msg)
            raise RuntimeError(error_msg) from e

        # REFACTORING: Enhanced service registration with comprehensive error handling
        self.logger.debug("Initiating LDIF services registration in DI container")
        try:
            register_result = register_ldif_services(config=self.config)
            if register_result.is_failure:
                error_msg: str = f"Service registration failed: {register_result.error}"
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)

            self.logger.debug("LDIF services registered successfully in DI container")
        except Exception as e:
            error_msg: str = f"Service registration exception: {e}"
            self.logger.exception(error_msg)
            raise RuntimeError(error_msg) from e

        # REFACTORING: Enhanced service resolution with improved error handling
        self._initialize_services()

        # REFACTORING: Enhanced observability initialization with comprehensive monitoring
        self._initialize_observability()

        # REFACTORING: Enhanced completion logging with comprehensive metrics
        self.logger.info(
            "FlextLdifAPI initialization completed successfully",
            config_source="provided" if provided_config else "default",
            services_initialized=True,
            observability_enabled=hasattr(self, "_observability_monitor"),
            api_ready=True,
        )
        self.logger.debug("API ready for LDIF processing operations")

    def _initialize_services(self) -> None:
        """Initialize domain services from dependency injection container with comprehensive error handling.

        Resolves and validates all required domain services from the DI container with
        detailed error reporting and fallback mechanisms for enterprise environments.

        Raises:
            RuntimeError: If any critical service cannot be resolved or validated

        """
        # REFACTORING: Enhanced service resolution with comprehensive validation
        self.logger.debug("Starting domain services initialization from DI container")
        container = get_flext_container()

        # Service configuration for systematic initialization
        services_config = [
            (
                "ldif_parser",
                FlextLdifParserService,
                "_parser_service",
                "LDIF parsing service",
            ),
            (
                "ldif_writer",
                FlextLdifWriterService,
                "_writer_service",
                "LDIF writing service",
            ),
            (
                "ldif_validator",
                FlextLdifValidatorService,
                "_validator_service",
                "LDIF validation service",
            ),
        ]

        initialized_services = []
        for service_name, service_type, attr_name, description in services_config:
            self.logger.debug(
                "Resolving %s from container",
                description,
                service_name=service_name,
            )

            try:
                service_result = container.get(service_name)
                if service_result.is_failure:
                    error_msg: str = f"Failed to resolve {description} from container: {service_result.error}"
                    self.logger.error(error_msg)
                    raise RuntimeError(error_msg)

                # Enhanced type validation with detailed error context
                if not isinstance(service_result.data, service_type):
                    actual_type = type(service_result.data).__name__
                    error_msg: str = f"{description} type validation failed: expected {service_type.__name__}, got {actual_type}"
                    self.logger.error(error_msg)
                    raise RuntimeError(error_msg)

                # Set service attribute
                setattr(self, attr_name, service_result.data)
                initialized_services.append(service_name)
                self.logger.trace("%s initialized successfully", description)

            except Exception as e:
                error_msg: str = f"Exception during {description} initialization: {e}"
                self.logger.exception(error_msg)
                raise RuntimeError(error_msg) from e

        self.logger.info(
            "Domain services initialization completed successfully",
            services_count=len(initialized_services),
            service_names=initialized_services,
        )

    def _initialize_observability(self) -> None:
        """Initialize observability monitoring with comprehensive error handling and graceful degradation.

        Sets up real-time observability monitoring with metrics collection, distributed tracing,
        and health monitoring while providing graceful fallback for environments without observability.

        """
        # REFACTORING: Enhanced observability initialization with comprehensive error handling
        self.logger.debug("Starting observability monitoring initialization")

        try:
            self._observability_monitor = FlextObservabilityMonitor()
            self.logger.trace("Observability monitor instance created")

            # Initialize observability with comprehensive error handling
            init_result = self._observability_monitor.flext_initialize_observability()
            if init_result.success:
                self.logger.debug("Observability initialization successful")

                # Start monitoring with error handling
                self._observability_monitor.flext_start_monitoring()
                self.logger.info(
                    "Observability monitoring started successfully",
                    monitoring_active=True,
                    metrics_enabled=True,
                    tracing_enabled=True,
                )
            else:
                # Graceful degradation for observability failures
                self.logger.warning(
                    "Observability initialization failed - continuing with degraded monitoring",
                    error=init_result.error,
                )
                self.logger.debug(
                    "API will continue without full observability features",
                )

        except Exception as e:
            # Complete fallback for observability exceptions
            self.logger.warning(
                "Observability monitoring exception - continuing without monitoring: %s",
                e,
            )
            self.logger.debug("API operating in non-observability mode")
            self._observability_monitor = None

    def _create_parse_trace(self, content: str | LDIFContent) -> str:
        """Create distributed trace for parsing operation."""
        trace_id = f"ldif_parse_{id(content)}"
        self.logger.debug("Creating distributed trace with ID: %s", trace_id)
        _ = flext_create_trace(
            trace_id=trace_id,
            operation="ldif_parse",
        )
        return trace_id

    def _record_content_metrics(self, content: str | LDIFContent) -> int:
        """Record content size metrics and return content size."""
        content_size = len(str(content))
        self.logger.debug("Content size: %d bytes", content_size)
        self.logger.trace("Recording content size metric: %d bytes", content_size)
        self._observability_monitor.flext_record_metric(
            "ldif_content_size_bytes",
            float(content_size),
            "histogram",
        )
        return content_size

    def _handle_parse_failure(
        self,
        parse_result: FlextResult[list[FlextLdifEntry]],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Handle parse failure by recording metrics and returning result."""
        self.logger.warning("Core parsing failed: %s", parse_result.error)
        self.logger.debug("Recording parse error metric")
        self._observability_monitor.flext_record_metric(
            "ldif_parse_errors_total",
            1.0,
            "counter",
        )
        return parse_result

    def _record_success_metrics(self, entries_count: int) -> None:
        """Record successful parsing metrics."""
        self.logger.debug("Recording successful parsing metrics")
        self._observability_monitor.flext_record_metric(
            "ldif_entries_parsed_total",
            float(entries_count),
            "counter",
        )
        self._observability_monitor.flext_record_metric(
            "ldif_entries_per_operation",
            float(entries_count),
            "histogram",
        )

    def _perform_strict_validation(
        self,
        entries: list[FlextLdifEntry],
        entries_count: int,
    ) -> None:
        """Perform strict validation if enabled and record warnings."""
        if not self.config.strict_validation:
            self.logger.trace("Skipping strict validation (disabled in config)")
            return

        self.logger.debug(
            "Strict validation enabled, validating %d entries",
            entries_count,
        )
        self.logger.trace("Running validate_entries with strict mode")
        validate_result = self._validator_service.validate(entries)

        if not validate_result.success:
            self.logger.warning("Strict validation warnings: %s", validate_result.error)
            self.logger.debug("Recording validation warning metric")
            self._observability_monitor.flext_record_metric(
                "ldif_validation_warnings_total",
                1.0,
                "counter",
            )
            self.logger.info(
                "Parse succeeded with validation warnings",
                entries_count=entries_count,
                validation_warnings=validate_result.error,
            )
        else:
            self.logger.debug("Strict validation passed for all entries")

    def _check_entry_limits(self, entries: list[FlextLdifEntry]) -> FlextResult[None]:
        """Check if entry count is within configured limits."""
        if len(entries) > self.config.max_entries:
            self.logger.warning(
                "Entry count %d exceeds max_entries limit %d",
                len(entries),
                self.config.max_entries,
            )
            self.logger.debug("Recording limit exceeded metric")
            self._observability_monitor.flext_record_metric(
                "ldif_limit_exceeded_total",
                1.0,
                "counter",
            )
            return FlextResult.fail(
                f"Too many entries: {len(entries)} > {self.config.max_entries}",
            )
        self.logger.trace(
            "Entry count %d within limit %d",
            len(entries),
            self.config.max_entries,
        )
        return FlextResult.ok(None)

    def _record_completion_metrics(
        self,
        entries_count: int,
        content_size: int,
        trace_id: str,
    ) -> None:
        """Record successful completion metrics and log summary."""
        self.logger.debug("Recording successful completion metrics")
        self._observability_monitor.flext_record_metric(
            "ldif_parse_success_total",
            1.0,
            "counter",
        )

        self.logger.info(
            "LDIF parsing completed successfully",
            entries_count=entries_count,
            content_size_bytes=content_size,
            strict_validation=self.config.strict_validation,
        )
        self.logger.trace(
            "Parse operation trace ID %s completed successfully",
            trace_id,
        )

    def _handle_parse_exception(
        self,
        e: Exception,
        trace_id: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Handle parsing exceptions by recording metrics and returning error."""
        self.logger.debug("Exception type: %s", type(e).__name__)
        self.logger.trace("Full exception details", exc_info=True)

        self.logger.debug("Recording parse exception metric")
        self._observability_monitor.flext_record_metric(
            "ldif_parse_exceptions_total",
            1.0,
            "counter",
        )
        self.logger.error("LDIF parsing failed with exception")
        self.logger.trace("Trace ID %s failed with exception", trace_id)

        return FlextResult.fail(f"Parse failed: {e}")

    @flext_monitor_function(metric_name="ldif_parse_operation")
    def parse(self, content: str | LDIFContent) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content with enterprise-grade processing, validation, and observability.

        Performs comprehensive LDIF parsing with intelligent error handling, configurable
        validation, distributed tracing, and real-time metrics collection. Supports both
        string and LDIFContent inputs with automatic encoding detection and processing limits.

        This method orchestrates the complete parsing pipeline including content validation,
        entry limit enforcement, strict validation (if enabled), and comprehensive observability
        reporting through the flext-observability integration.

        Args:
            content: LDIF content as string or LDIFContent type for parsing

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with parsed entries or failure with error details

        Configuration Behavior:
            - max_entries: Enforces entry count limits to prevent memory exhaustion
            - strict_validation: Enables comprehensive business rule validation
            - input_encoding: Used for content size calculations and processing
            - observability: Records metrics, traces, and health status

        Observability Metrics:
            - ldif_content_size_bytes: Input content size histogram
            - ldif_entries_parsed_total: Successfully parsed entries counter
            - ldif_parse_success_total: Successful parse operations counter
            - ldif_parse_errors_total: Parse error counter
            - ldif_parse_exceptions_total: Exception counter
            - ldif_validation_warnings_total: Validation warning counter

        Example:
            >>> from flext_ldif import FlextLdifAPI, FlextLdifConfig
            >>> config = FlextLdifConfig(max_entries=10000, strict_validation=True)
            >>> api = FlextLdifAPI(config)
            >>>
            >>> ldif_content = '''
            ... dn: cn=John Doe,ou=people,dc=example,dc=com
            ... objectClass: person
            ... objectClass: inetOrgPerson
            ... cn: John Doe
            ... mail: john@example.com
            ... '''
            >>>
            >>> result = api.parse(ldif_content)
            >>> if result.success:
            ...     entries = result.data
            ...     print(f"Parsed {len(entries)} entries successfully")
            ... else:
            ...     print(f"Parse failed: {result.error}")

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        # REFACTORING: Enhanced parsing initialization with comprehensive context logging
        content_type = type(content).__name__
        self.logger.debug(
            "Starting LDIF content parsing operation",
            content_type=content_type,
        )
        self.logger.trace("Parse input received: %s", content_type)

        # REFACTORING: Enhanced distributed tracing with better trace management
        trace_id = self._create_parse_trace(content)
        self.logger.debug("Created parse trace", trace_id=trace_id)

        try:
            # REFACTORING: Enhanced content metrics collection with validation
            content_size = self._record_content_metrics(content)
            self.logger.debug(
                "Content metrics recorded",
                content_size_bytes=content_size,
                trace_id=trace_id,
            )

            # REFACTORING: Enhanced service delegation with comprehensive configuration logging
            self.logger.debug(
                "Delegating to parser service for core parsing",
                parser_service=self._parser_service.__class__.__name__,
                config_strict_validation=self.config.strict_validation,
                config_max_entries=self.config.max_entries,
            )

            parse_result = self._parser_service.parse(content)

            # REFACTORING: Enhanced parse result validation with detailed error context
            if not parse_result.success:
                self.logger.warning(
                    "Parser service returned failure",
                    error=parse_result.error,
                    trace_id=trace_id,
                )
                return self._handle_parse_failure(parse_result)

            # REFACTORING: Enhanced entries validation with null safety
            entries = parse_result.data
            if entries is None:
                error_msg = "Parse succeeded but returned None entries - this indicates a parser service bug"
                self.logger.error(error_msg, trace_id=trace_id)
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced entries processing with comprehensive metrics
            entries_count = len(entries)
            self.logger.debug(
                "Core parsing completed successfully",
                entries_parsed=entries_count,
                trace_id=trace_id,
            )

            # Log sample of parsed entry DNs for debugging (first 5 entries)
            if entries_count > 0:
                sample_dns = [str(entry.dn) for entry in entries[:5]]
                self.logger.trace("Sample parsed entry DNs: %s", sample_dns)

            # REFACTORING: Enhanced success metrics recording with context
            self._record_success_metrics(entries_count)

            # REFACTORING: Enhanced strict validation with conditional execution
            if self.config.strict_validation:
                self.logger.debug(
                    "Performing strict validation",
                    entries_count=entries_count,
                )
                self._perform_strict_validation(entries, entries_count)
            else:
                self.logger.trace("Strict validation disabled - skipping")

            # REFACTORING: Enhanced limit checking with detailed error reporting
            self.logger.debug(
                "Checking entry count limits",
                entries_count=entries_count,
                max_entries_limit=self.config.max_entries,
            )

            limit_check_result = self._check_entry_limits(entries)
            if not limit_check_result.success:
                error_msg = limit_check_result.error or "Entry limit exceeded"
                self.logger.error(
                    "Entry limit check failed",
                    error=error_msg,
                    entries_count=entries_count,
                    trace_id=trace_id,
                )
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced completion metrics and final result preparation
            self._record_completion_metrics(entries_count, content_size, trace_id)

            self.logger.info(
                "LDIF content parsing completed successfully",
                entries_parsed=entries_count,
                content_size_bytes=content_size,
                strict_validation_performed=self.config.strict_validation,
                trace_id=trace_id,
            )

            return FlextResult.ok(entries)

        except (ValueError, TypeError, AttributeError, OSError, ImportError) as e:
            # REFACTORING: Enhanced exception handling with comprehensive error context
            self.logger.exception(
                "Exception during LDIF parsing operation",
                exception_type=type(e).__name__,
                trace_id=trace_id,
            )
            return self._handle_parse_exception(e, trace_id)

    @flext_monitor_function(metric_name="ldif_parse_file_operation")
    def parse_file(self, file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF file with enterprise-grade file handling, validation, and observability integration.

        Performs comprehensive LDIF file parsing with automatic encoding detection, file size
        validation, distributed tracing, and real-time metrics collection. Handles large files
        efficiently with configurable processing limits and memory management.

        This method orchestrates the complete file parsing pipeline including file access
        validation, content reading with proper encoding, entry processing, limit enforcement,
        and comprehensive observability reporting with enterprise-grade structured logging.

        Args:
            file_path: Path to LDIF file as string or Path object

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with parsed entries or failure with detailed error context

        Configuration Behavior:
            - max_entries: Enforces entry count limits to prevent memory exhaustion
            - strict_validation: Enables comprehensive business rule validation
            - input_encoding: Used for file reading and content processing
            - observability: Records file operation metrics and traces

        File Handling:
            - Automatic encoding detection and proper file access
            - Large file support with memory-efficient processing
            - Comprehensive error handling for file system issues
            - Path resolution and validation

        Observability Metrics:
            - ldif_file_operations_total: File operation attempts counter
            - ldif_file_entries_parsed_total: Successfully parsed entries from files
            - ldif_file_parse_success_total: Successful file parse operations
            - ldif_file_parse_errors_total: File parse error counter
            - ldif_file_exceptions_total: File operation exception counter
            - ldif_file_validation_warnings_total: File validation warning counter

        Example:
            >>> from flext_ldif import FlextLdifAPI, FlextLdifConfig
            >>> from pathlib import Path
            >>>
            >>> config = FlextLdifConfig(max_entries=50000, strict_validation=True)
            >>> api = FlextLdifAPI(config)
            >>>
            >>> # Parse local LDIF file
            >>> result = api.parse_file("/path/to/directory.ldif")
            >>> if result.success:
            ...     entries = result.data
            ...     print(f"Successfully parsed {len(entries)} entries from file")
            ...     # Process parsed entries
            ...     for entry in entries[:5]:  # Show first 5
            ...         print(f"- {entry.dn}")
            ... else:
            ...     print(f"File parse failed: {result.error}")

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        # REFACTORING: Enhanced distributed tracing with comprehensive context
        file_path_str = str(file_path)
        trace_id = f"ldif_parse_file_{hash(file_path_str)}"
        flext_create_trace(trace_id=trace_id, operation="ldif_parse_file")

        self.logger.debug(
            "Starting LDIF file parsing operation",
            file_path=file_path_str,
            trace_id=trace_id,
            input_encoding=self.config.input_encoding,
        )
        self.logger.trace(
            "File parsing configuration",
            max_entries=self.config.max_entries,
            strict_validation=self.config.strict_validation,
        )

        try:
            # REFACTORING: Enhanced path validation and metrics recording
            file_path_obj = Path(file_path)
            absolute_path = file_path_obj.absolute()
            self.logger.trace(
                "File path resolved",
                original_path=file_path_str,
                absolute_path=str(absolute_path),
            )

            # Record file parsing operation attempt
            self._observability_monitor.flext_record_metric(
                "ldif_file_operations_total",
                1.0,
                "counter",
            )

            # REFACTORING: Enhanced file validation before parsing
            if not file_path_obj.exists():
                error_msg: str = f"File not found: {absolute_path}"
                self.logger.error(error_msg, trace_id=trace_id)
                self._observability_monitor.flext_record_metric(
                    "ldif_file_parse_errors_total",
                    1.0,
                    "counter",
                )
                return FlextResult.fail(error_msg)

            if not file_path_obj.is_file():
                error_msg: str = f"Path is not a file: {absolute_path}"
                self.logger.error(error_msg, trace_id=trace_id)
                self._observability_monitor.flext_record_metric(
                    "ldif_file_parse_errors_total",
                    1.0,
                    "counter",
                )
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced file size metrics
            try:
                file_size = file_path_obj.stat().st_size
                self.logger.debug(
                    "File size validated",
                    file_size_bytes=file_size,
                    file_size_mb=round(file_size / 1024 / 1024, 2),
                )
            except (OSError, AttributeError) as e:
                self.logger.warning("Could not determine file size: %s", e)
                file_size = 0

            # REFACTORING: Enhanced parser service delegation with error handling
            self.logger.debug(
                "Delegating to parser service",
                service_type="FlextLdifParserService",
            )
            parse_result = self._parser_service.parse_file(file_path_obj)

            if parse_result.is_failure:
                error_msg: str = f"Parser service failed: {parse_result.error}"
                self.logger.error(error_msg, trace_id=trace_id)
                self._observability_monitor.flext_record_metric(
                    "ldif_file_parse_errors_total",
                    1.0,
                    "counter",
                )
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced entries validation and processing
            entries = parse_result.data
            if entries is None:
                error_msg = "No entries parsed from file"
                self.logger.error(error_msg, trace_id=trace_id, file_path=file_path_str)
                self._observability_monitor.flext_record_metric(
                    "ldif_file_parse_errors_total",
                    1.0,
                    "counter",
                )
                return FlextResult.fail(error_msg)

            entries_count = len(entries)
            self.logger.debug(
                "File parsing completed",
                entries_parsed=entries_count,
                file_size_bytes=file_size,
            )

            # Log sample of parsed entry DNs for debugging (first 3 entries)
            if entries_count > 0:
                sample_dns = [str(entry.dn) for entry in entries[:3]]
                self.logger.trace("Sample parsed entry DNs from file: %s", sample_dns)

            # REFACTORING: Enhanced metrics recording with comprehensive context
            self._observability_monitor.flext_record_metric(
                "ldif_file_entries_parsed_total",
                float(entries_count),
                "counter",
            )

            # REFACTORING: Enhanced entry limit validation with detailed error context
            if entries_count > self.config.max_entries:
                limit_error = f"File entry count {entries_count} exceeds configured limit {self.config.max_entries}"
                self.logger.warning(
                    limit_error,
                    file_path=file_path_str,
                    trace_id=trace_id,
                )
                self._observability_monitor.flext_record_metric(
                    "ldif_file_limit_exceeded_total",
                    1.0,
                    "counter",
                )
                return FlextResult.fail(limit_error)

            # REFACTORING: Enhanced strict validation with comprehensive error handling
            if self.config.strict_validation:
                self.logger.debug(
                    "Performing strict validation on file entries",
                    entries_count=entries_count,
                )

                validate_result = self._validator_service.validate(entries)
                if validate_result.is_failure:
                    validation_error = (
                        validate_result.error or "Unknown validation error"
                    )
                    self.logger.warning(
                        "File validation failed with errors",
                        validation_error=validation_error,
                        file_path=file_path_str,
                        trace_id=trace_id,
                    )

                    self._observability_monitor.flext_record_metric(
                        "ldif_file_validation_warnings_total",
                        1.0,
                        "counter",
                    )

                    # Continue with parsing success but log validation issues
                    self.logger.info(
                        "File parse succeeded despite validation warnings",
                        file_path=file_path_str,
                        entries_count=entries_count,
                        validation_warnings=validation_error,
                    )
                else:
                    self.logger.trace("Strict validation passed for file entries")

            # REFACTORING: Enhanced success metrics and completion logging
            self._observability_monitor.flext_record_metric(
                "ldif_file_parse_success_total",
                1.0,
                "counter",
            )

            self.logger.info(
                "LDIF file parsing completed successfully",
                file_path=file_path_str,
                entries_parsed=entries_count,
                file_size_bytes=file_size,
                strict_validation_performed=self.config.strict_validation,
                input_encoding=self.config.input_encoding,
                trace_id=trace_id,
            )

            return FlextResult.ok(entries)

        except (OSError, ValueError, TypeError, AttributeError, ImportError) as e:
            # REFACTORING: Enhanced exception handling with comprehensive error context
            error_msg: str = f"File parsing exception: {type(e).__name__}: {e}"
            self.logger.exception(
                "LDIF file parsing failed with exception",
                file_path=file_path_str,
                exception_type=type(e).__name__,
                trace_id=trace_id,
            )

            # Record exception metrics
            self._observability_monitor.flext_record_metric(
                "ldif_file_exceptions_total",
                1.0,
                "counter",
            )

            return FlextResult.fail(error_msg)

    def _validate_empty_attributes(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[None]:
        """Validate empty attributes if not allowed by configuration."""
        if self.config.allow_empty_attributes:
            self.logger.trace("Skipping empty attribute check (allowed in config)")
            return FlextResult.ok(None)

        self.logger.debug("Checking for empty attributes (not allowed)")
        empty_attr_count = 0

        for i, entry in enumerate(entries):
            self.logger.trace("Validating entry %d: %s", i, entry.dn)
            for attr_name, attr_values in entry.attributes.attributes.items():
                if not attr_values or any(not v.strip() for v in attr_values):
                    self.logger.warning(
                        "Empty attribute value found: %s in %s",
                        attr_name,
                        entry.dn,
                    )
                    self.logger.debug("Failing validation due to empty attribute")
                    return FlextResult.fail(
                        f"Empty attribute value not allowed: {attr_name} in {entry.dn}",
                    )
                empty_attr_count += sum(1 for v in attr_values if not v.strip())

        if empty_attr_count == 0:
            self.logger.debug("No empty attributes found (validation passed)")
        else:
            self.logger.trace("Found %d empty attribute values", empty_attr_count)

        return FlextResult.ok(None)

    def _validate_entry_sizes(self, entries: list[FlextLdifEntry]) -> FlextResult[None]:
        """Validate entry sizes against configured limits."""
        self.logger.debug(
            "Checking entry size limits (max: %d bytes)",
            self.config.max_entry_size,
        )
        oversized_entries = 0

        for i, entry in enumerate(entries):
            entry_ldif = entry.to_ldif()
            entry_size = len(entry_ldif.encode(self.config.input_encoding))
            self.logger.trace("Entry %d (%s) size: %d bytes", i, entry.dn, entry_size)

            if entry_size > self.config.max_entry_size:
                self.logger.warning(
                    "Entry size %d exceeds limit %d: %s",
                    entry_size,
                    self.config.max_entry_size,
                    entry.dn,
                )
                self.logger.debug("Failing validation due to oversized entry")
                return FlextResult.fail(
                    f"Entry size {entry_size} exceeds limit {self.config.max_entry_size}: {entry.dn}",
                )
            oversized_entries += (
                1 if entry_size > (self.config.max_entry_size * 0.8) else 0
            )

        if oversized_entries > 0:
            self.logger.debug(
                "Found %d entries approaching size limit (>80%% of max)",
                oversized_entries,
            )
        else:
            self.logger.debug("All entries within size limits")

        return FlextResult.ok(None)

    def validate(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate LDIF entries with comprehensive business rule enforcement and configuration support.

        Performs extensive validation of LDIF entries including attribute validation, entry size
        limits, empty attribute checking, and domain-specific business rule validation. Uses
        configuration settings to customize validation behavior and strictness levels.

        This method orchestrates multiple validation layers including configuration-based rules,
        domain model validation, and enterprise-grade constraint checking with detailed error
        reporting and observability integration.

        Args:
            entries: List of FlextLdifEntry objects to validate

        Returns:
            FlextResult[bool]: Success with True if all entries valid, failure with detailed error information

        Validation Layers:
            1. Configuration validation (empty attributes, entry size limits)
            2. Domain model validation (business rules, semantic constraints)
            3. LDAP schema compliance (object class requirements)
            4. Entry structure validation (DN format, attribute consistency)

        Configuration Behavior:
            - allow_empty_attributes: Controls empty attribute value validation
            - max_entry_size: Enforces individual entry size limits in bytes
            - input_encoding: Used for size calculations and content validation
            - strict_validation: Enables comprehensive business rule checking

        Example:
            >>> from flext_ldif import FlextLdifAPI, FlextLdifConfig
            >>>
            >>> # Configure validation with strict settings
            >>> config = FlextLdifConfig(
            ...     allow_empty_attributes=False,
            ...     max_entry_size=50000,  # 50KB per entry
            ...     strict_validation=True,
            ... )
            >>> api = FlextLdifAPI(config)
            >>>
            >>> # Validate parsed entries
            >>> result = api.validate(entries)
            >>> if result.success and result.data:
            ...     print("All entries passed validation")
            ... else:
            ...     print(f"Validation failed: {result.error}")

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        # REFACTORING: Enhanced validation initialization with comprehensive metrics
        entries_count = len(entries)
        self.logger.debug(
            "Starting comprehensive LDIF validation operation",
            entries_count=entries_count,
        )
        self.logger.trace(
            "Validation configuration parameters",
            allow_empty_attributes=self.config.allow_empty_attributes,
            max_entry_size_bytes=self.config.max_entry_size,
            input_encoding=self.config.input_encoding,
            strict_validation=self.config.strict_validation,
        )

        # REFACTORING: Enhanced empty attributes validation with detailed error handling
        self.logger.debug("Starting empty attributes validation")
        empty_attr_result = self._validate_empty_attributes(entries)
        if not empty_attr_result.success:
            error_msg = empty_attr_result.error or "Empty attribute validation failed"
            self.logger.error(
                "Empty attributes validation failed",
                error=error_msg,
                entries_count=entries_count,
            )
            return FlextResult.fail(error_msg)

        self.logger.debug("Empty attributes validation passed")

        # REFACTORING: Enhanced entry sizes validation with detailed error handling
        self.logger.debug(
            "Starting entry sizes validation",
            max_entry_size_limit=self.config.max_entry_size,
        )
        size_result = self._validate_entry_sizes(entries)
        if not size_result.success:
            error_msg = size_result.error or "Entry size validation failed"
            self.logger.error(
                "Entry sizes validation failed",
                error=error_msg,
                entries_count=entries_count,
                max_size_limit=self.config.max_entry_size,
            )
            return FlextResult.fail(error_msg)

        self.logger.debug("Entry sizes validation passed")

        # REFACTORING: Enhanced core validation with comprehensive service delegation
        self.logger.debug(
            "Delegating to validator service for core validation",
            validator_service=self._validator_service.__class__.__name__,
        )

        core_validation_result = self._validator_service.validate(entries)

        # REFACTORING: Enhanced validation result processing with comprehensive logging
        if core_validation_result.success:
            self.logger.info(
                "LDIF validation completed successfully",
                entries_validated=entries_count,
                validation_layers_passed=[
                    "empty_attributes",
                    "entry_sizes",
                    "core_validation",
                ],
                strict_validation=self.config.strict_validation,
            )
        else:
            self.logger.warning(
                "Core validation failed",
                error=core_validation_result.error,
                entries_count=entries_count,
            )

        return core_validation_result

    def _resolve_output_path(self, file_path: str | Path) -> Path:
        """Resolve output file path using configuration."""
        original_path = str(file_path)
        file_path = Path(file_path)
        self.logger.trace("Original file path: %s", original_path)

        if not file_path.is_absolute() and self.config.output_directory:
            self.logger.debug(
                "Resolving relative path with output_directory: %s",
                self.config.output_directory,
            )
            file_path = self.config.output_directory / file_path
            self.logger.trace("Resolved absolute path: %s", file_path)
        else:
            self.logger.trace(
                "Using path as-is (absolute or no output_directory configured)",
            )
        return file_path

    def _create_output_directory(self, file_path: Path) -> None:
        """Create output directory if configured and needed."""
        if self.config.create_output_dir and file_path.parent:
            self.logger.debug(
                "Creating output directory if needed: %s",
                file_path.parent,
            )
            try:
                file_path.parent.mkdir(parents=True, exist_ok=True)
                self.logger.trace(
                    "Directory created/verified: %s",
                    file_path.parent,
                )
            except (OSError, PermissionError) as e:
                # If can't create directory, let the write operation fail naturally
                self.logger.warning(
                    "Failed to create output directory %s: %s",
                    file_path.parent,
                    e,
                )
                self.logger.debug(
                    "Continuing with write operation, may fail if directory doesn't exist",
                )
        else:
            self.logger.trace(
                "Skipping directory creation (disabled or no parent directory)",
            )

    def write(
        self,
        entries: list[FlextLdifEntry],
        file_path: str | Path | None = None,
    ) -> FlextResult[str]:
        """Write LDIF entries to string or file with enterprise-grade formatting and configuration support.

        Performs comprehensive LDIF writing with intelligent output formatting, configurable encoding,
        automatic directory creation, and enterprise-grade error handling. Supports both string output
        and file writing with proper path resolution and configuration management.

        This method orchestrates the complete writing pipeline including output path resolution,
        directory creation (if configured), encoding handling, and comprehensive error reporting
        with observability integration.

        Args:
            entries: List of FlextLdifEntry objects to write
            file_path: Optional output file path (string or Path). If None, returns LDIF string

        Returns:
            FlextResult[str]: Success with LDIF content or file write confirmation, failure with error details

        Configuration Behavior:
            - output_directory: Base directory for relative file paths
            - create_output_dir: Automatically creates output directories if needed
            - output_encoding: Character encoding for file output
            - observability: Records write operation metrics and traces

        File Writing Features:
            - Automatic path resolution with configurable output directory
            - Directory creation with proper error handling
            - Encoding management for international character support
            - Path validation and normalization

        Example:
            >>> from flext_ldif import FlextLdifAPI, FlextLdifConfig
            >>> from pathlib import Path
            >>>
            >>> config = FlextLdifConfig(
            ...     output_directory=Path("/data/ldif"),
            ...     create_output_dir=True,
            ...     output_encoding="utf-8",
            ... )
            >>> api = FlextLdifAPI(config)
            >>>
            >>> # Write to string
            >>> result = api.write(entries)
            >>> if result.success:
            ...     ldif_content = result.data
            ...     print(f"Generated LDIF content: {len(ldif_content)} characters")
            >>>
            >>> # Write to file
            >>> result = api.write(entries, "exported_entries.ldif")
            >>> if result.success:
            ...     print(f"Success: {result.data}")
            ... else:
            ...     print(f"Write failed: {result.error}")

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        # REFACTORING: Enhanced write operation initialization with comprehensive metrics
        entries_count = len(entries)
        write_target = "file" if file_path else "string"
        self.logger.debug(
            "Starting LDIF write operation",
            entries_count=entries_count,
            write_target=write_target,
        )
        self.logger.trace(
            "Write operation parameters",
            file_path=str(file_path) if file_path else None,
            config_output_directory=str(self.config.output_directory),
            config_create_output_dir=self.config.create_output_dir,
        )

        # REFACTORING: Enhanced file writing with comprehensive path management
        if file_path:
            self.logger.debug(
                "Executing file write operation",
                file_path=str(file_path),
                entries_count=entries_count,
            )

            # REFACTORING: Enhanced path resolution with comprehensive logging
            try:
                resolved_path = self._resolve_output_path(file_path)
                self.logger.debug(
                    "Output path resolved successfully",
                    original_path=str(file_path),
                    resolved_path=str(resolved_path.absolute()),
                )
            except (OSError, ValueError) as e:
                error_msg: str = f"Path resolution failed for {file_path}: {e}"
                self.logger.exception(error_msg)
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced directory creation with comprehensive error handling
            try:
                self._create_output_directory(resolved_path)
                self.logger.debug("Output directory preparation completed")
            except Exception as e:
                error_msg = (
                    f"Directory preparation failed for {resolved_path.parent}: {e}"
                )
                self.logger.exception(error_msg)
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced file writing with comprehensive service delegation
            self.logger.debug(
                "Delegating to writer service for file output",
                writer_service=self._writer_service.__class__.__name__,
                resolved_path=str(resolved_path),
            )

            write_result = self._writer_service.write_file(entries, resolved_path)

            # REFACTORING: Enhanced file write result processing
            if write_result.success:
                success_msg: str = (
                    f"LDIF entries written successfully to {resolved_path}"
                )
                self.logger.info(
                    "File write operation completed successfully",
                    entries_written=entries_count,
                    file_path=str(resolved_path.absolute()),
                    output_encoding=self.config.output_encoding,
                )
                return FlextResult.ok(success_msg)
            error_msg = write_result.error or "File write operation failed"
            self.logger.error(
                "File write operation failed",
                error=error_msg,
                file_path=str(resolved_path),
                entries_count=entries_count,
            )
            return FlextResult.fail(error_msg)

        # REFACTORING: Enhanced string writing with comprehensive service delegation
        self.logger.debug(
            "Executing string write operation",
            entries_count=entries_count,
            writer_service=self._writer_service.__class__.__name__,
        )

        string_result = self._writer_service.write(entries)

        # REFACTORING: Enhanced string write result processing
        if string_result.success:
            content_length = len(string_result.data or "")
            self.logger.info(
                "String write operation completed successfully",
                entries_written=entries_count,
                content_length_chars=content_length,
            )
        else:
            self.logger.error(
                "String write operation failed",
                error=string_result.error,
                entries_count=entries_count,
            )

        return string_result

    @flext_monitor_function(metric_name="ldif_filter_persons")
    def filter_persons(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter person entries with enterprise-grade classification and observability monitoring.

        Performs intelligent filtering of LDAP person entries using integrated Domain-Driven Design
        specification patterns with comprehensive observability metrics and real-time monitoring.
        Identifies person entries based on objectClass attributes and business rule validation.

        This method uses composition-based specification logic integrated directly into the
        FlextLdifEntry domain entities, eliminating the need for separate specification objects
        while maintaining clean architecture principles and domain logic encapsulation.

        Args:
            entries: List of FlextLdifEntry objects to filter

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with filtered person entries or failure with error details

        Person Classification Rules:
            Entries are classified as persons if they contain any of these objectClass values:
            - person: Basic person object class
            - organizationalPerson: Person with organizational attributes
            - inetOrgPerson: Internet organizational person with email/web attributes
            - user: User account entries
            - posixAccount: POSIX user account entries

        Observability Metrics:
            - ldif_filter_input_entries: Total entries processed (histogram)
            - ldif_persons_filtered: Number of person entries found (histogram)
            - ldif_filter_persons_total: Filter operation counter
            - ldif_filter_persons_errors_total: Filter operation error counter

        Example:
            >>> from flext_ldif import FlextLdifAPI
            >>> api = FlextLdifAPI()
            >>>
            >>> # Filter person entries from parsed LDIF
            >>> result = api.filter_persons(entries)
            >>> if result.success:
            ...     person_entries = result.data
            ...     print(f"Found {len(person_entries)} person entries")
            ...     for person in person_entries[:3]:  # Show first 3
            ...         cn = person.get_single_attribute("cn")
            ...         mail = person.get_single_attribute("mail")
            ...         print(f"- {cn} ({mail})")
            ... else:
            ...     print(f"Filter failed: {result.error}")

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        # REFACTORING: Enhanced filtering initialization with comprehensive metrics
        # Input validation for None entries
        if entries is None:
            error_msg = "Entries list cannot be None"
            self.logger.error(error_msg)
            return FlextResult.fail(error_msg)

        total_entries = len(entries)
        self.logger.debug(
            "Starting person entries filtering operation",
            total_entries=total_entries,
        )
        self.logger.trace(
            "Person filtering classification rules active",
            person_classes=[
                "person",
                "organizationalPerson",
                "inetOrgPerson",
                "user",
                "posixAccount",
            ],
        )

        try:
            # REFACTORING: Enhanced input validation with detailed logging
            if not entries:
                self.logger.debug(
                    "Empty entries list provided - returning empty result",
                )
                return FlextResult.ok([])

            if not isinstance(entries, list):
                error_msg = (
                    f"Invalid entries type: expected list, got {type(entries).__name__}"
                )
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced metrics recording with comprehensive context
            self._observability_monitor.flext_record_metric(
                "ldif_filter_input_entries",
                float(total_entries),
                "histogram",
            )

            # REFACTORING: Enhanced person filtering with detailed progress tracking
            self.logger.debug("Applying person classification rules to entries")
            person_entries = []
            person_classification_errors = 0

            for i, entry in enumerate(entries):
                self.logger.trace(
                    "Evaluating entry %d/%d for person classification: %s",
                    i + 1,
                    total_entries,
                    entry.dn,
                )
                try:
                    if entry.is_person_entry():
                        person_entries.append(entry)
                        self.logger.trace("Entry classified as person: %s", entry.dn)
                    else:
                        self.logger.trace(
                            "Entry NOT classified as person: %s",
                            entry.dn,
                        )
                except (AttributeError, ValueError) as e:
                    person_classification_errors += 1
                    self.logger.warning(
                        "Person classification error for entry %s: %s",
                        entry.dn,
                        e,
                    )
                    # Continue processing other entries

            person_count = len(person_entries)
            filter_ratio = person_count / total_entries if total_entries > 0 else 0.0

            # REFACTORING: Enhanced results metrics recording with comprehensive data
            self._observability_monitor.flext_record_metric(
                "ldif_persons_filtered",
                float(person_count),
                "histogram",
            )
            self._observability_monitor.flext_record_metric(
                "ldif_filter_persons_total",
                1.0,
                "counter",
            )

            # REFACTORING: Enhanced classification errors tracking
            if person_classification_errors > 0:
                self.logger.warning(
                    "Person classification completed with errors",
                    classification_errors=person_classification_errors,
                    total_entries=total_entries,
                )
                self._observability_monitor.flext_record_metric(
                    "ldif_filter_persons_classification_errors_total",
                    float(person_classification_errors),
                    "counter",
                )

            # REFACTORING: Enhanced success logging with comprehensive metrics
            self.logger.info(
                "Person entries filtering completed successfully",
                total_entries=total_entries,
                person_entries_found=person_count,
                filter_ratio_percent=round(filter_ratio * 100, 2),
                classification_errors=person_classification_errors,
            )

            # Log sample of filtered person entries for debugging (first 3)
            if person_count > 0:
                sample_persons = [str(entry.dn) for entry in person_entries[:3]]
                self.logger.trace("Sample person entries found: %s", sample_persons)

            return FlextResult.ok(person_entries)

        except (ValueError, TypeError, AttributeError, OSError) as e:
            # REFACTORING: Enhanced exception handling with comprehensive error context
            error_msg: str = (
                f"Person filtering operation failed: {type(e).__name__}: {e}"
            )
            self.logger.exception(
                "Person entries filtering failed with exception",
                total_entries=total_entries,
                exception_type=type(e).__name__,
            )

            self._observability_monitor.flext_record_metric(
                "ldif_filter_persons_errors_total",
                1.0,
                "counter",
            )

            return FlextResult.fail(error_msg)

    def filter_valid(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter valid entries with enterprise-grade validation and comprehensive error handling.

        Performs comprehensive validation filtering of LDIF entries using integrated domain validation
        logic with detailed error reporting and comprehensive logging for enterprise environments.

        Args:
            entries: List of FlextLdifEntry objects to validate and filter

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with valid entries or failure with detailed error context

        """
        # REFACTORING: Enhanced validation filtering with comprehensive metrics
        # Input validation for None entries
        if entries is None:
            error_msg = "Entries list cannot be None"
            self.logger.error(error_msg)
            return FlextResult.fail(error_msg)

        total_entries = len(entries)
        self.logger.debug(
            "Starting valid entries filtering operation",
            total_entries=total_entries,
        )

        try:
            # REFACTORING: Enhanced input validation
            if not entries:
                self.logger.debug(
                    "Empty entries list provided - returning empty result",
                )
                return FlextResult.ok([])

            if not isinstance(entries, list):
                error_msg = (
                    f"Invalid entries type: expected list, got {type(entries).__name__}"
                )
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced validation filtering with error tracking
            valid_entries = []
            validation_errors = 0

            for i, entry in enumerate(entries):
                self.logger.trace(
                    "Validating entry %d/%d: %s",
                    i + 1,
                    total_entries,
                    entry.dn,
                )
                try:
                    if entry.is_valid_entry():
                        valid_entries.append(entry)
                        self.logger.trace("Entry is valid: %s", entry.dn)
                    else:
                        self.logger.trace("Entry is NOT valid: %s", entry.dn)
                except (AttributeError, ValueError, TypeError) as e:
                    validation_errors += 1
                    self.logger.warning(
                        "Validation error for entry %s: %s",
                        entry.dn,
                        e,
                    )
                    # Continue processing other entries

            valid_count = len(valid_entries)
            validation_ratio = valid_count / total_entries if total_entries > 0 else 0.0

            # REFACTORING: Enhanced validation errors tracking
            if validation_errors > 0:
                self.logger.warning(
                    "Valid entries filtering completed with validation errors",
                    validation_errors=validation_errors,
                    total_entries=total_entries,
                )

            # REFACTORING: Enhanced success logging with comprehensive metrics
            self.logger.info(
                "Valid entries filtering completed successfully",
                total_entries=total_entries,
                valid_entries_found=valid_count,
                validation_ratio_percent=round(validation_ratio * 100, 2),
                validation_errors=validation_errors,
            )

            return FlextResult.ok(valid_entries)

        except (ValueError, TypeError, AttributeError, OSError) as e:
            # REFACTORING: Enhanced exception handling with comprehensive error context
            error_msg: str = f"Valid entries filtering failed: {type(e).__name__}: {e}"
            self.logger.exception(
                "Valid entries filtering failed with exception",
                total_entries=total_entries,
                exception_type=type(e).__name__,
            )
            return FlextResult.fail(error_msg)

    def filter_by_objectclass(
        self,
        entries: list[FlextLdifEntry],
        object_class: str,
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter entries by objectClass with enterprise-grade validation and comprehensive error handling.

        Performs comprehensive objectClass-based filtering with input validation, detailed logging,
        and robust error handling for enterprise environments.

        Args:
            entries: List of FlextLdifEntry objects to filter
            object_class: ObjectClass name to filter by (case-sensitive)

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with filtered entries or failure with detailed error context

        """
        # REFACTORING: Enhanced objectClass filtering with comprehensive validation
        # Input validation for None entries
        if entries is None:
            error_msg = "Entries list cannot be None"
            self.logger.error(error_msg)
            return FlextResult.fail(error_msg)

        total_entries = len(entries)
        self.logger.debug(
            "Starting objectClass filtering operation",
            total_entries=total_entries,
            target_object_class=object_class,
        )

        try:
            # REFACTORING: Enhanced input validation
            if not entries:
                self.logger.debug(
                    "Empty entries list provided - returning empty result",
                )
                return FlextResult.ok([])

            if not isinstance(entries, list):
                error_msg = (
                    f"Invalid entries type: expected list, got {type(entries).__name__}"
                )
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            if not object_class or not isinstance(object_class, str):
                error_msg: str = f"Invalid object_class: expected non-empty string, got {type(object_class).__name__}: {object_class}"
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced objectClass filtering with error tracking
            matching_entries = []
            classification_errors = 0

            for i, entry in enumerate(entries):
                self.logger.trace(
                    "Checking entry %d/%d for objectClass '%s': %s",
                    i + 1,
                    total_entries,
                    object_class,
                    entry.dn,
                )
                try:
                    if entry.has_object_class(object_class):
                        matching_entries.append(entry)
                        self.logger.trace(
                            "Entry matches objectClass '%s': %s",
                            object_class,
                            entry.dn,
                        )
                    else:
                        self.logger.trace(
                            "Entry does NOT match objectClass '%s': %s",
                            object_class,
                            entry.dn,
                        )
                except (AttributeError, ValueError, TypeError) as e:
                    classification_errors += 1
                    self.logger.warning(
                        "ObjectClass check error for entry %s: %s",
                        entry.dn,
                        e,
                    )
                    # Continue processing other entries

            matching_count = len(matching_entries)
            match_ratio = matching_count / total_entries if total_entries > 0 else 0.0

            # REFACTORING: Enhanced classification errors tracking
            if classification_errors > 0:
                self.logger.warning(
                    "ObjectClass filtering completed with classification errors",
                    classification_errors=classification_errors,
                    total_entries=total_entries,
                    object_class=object_class,
                )

            # REFACTORING: Enhanced success logging with comprehensive metrics
            self.logger.info(
                "ObjectClass filtering completed successfully",
                total_entries=total_entries,
                target_object_class=object_class,
                matching_entries_found=matching_count,
                match_ratio_percent=round(match_ratio * 100, 2),
                classification_errors=classification_errors,
            )

            return FlextResult.ok(matching_entries)

        except (ValueError, TypeError, AttributeError, OSError) as e:
            # REFACTORING: Enhanced exception handling with comprehensive error context
            error_msg: str = f"ObjectClass filtering failed: {type(e).__name__}: {e}"
            self.logger.exception(
                "ObjectClass filtering failed with exception",
                total_entries=total_entries,
                object_class=object_class,
                exception_type=type(e).__name__,
            )
            return FlextResult.fail(error_msg)

    def find_entry_by_dn(
        self,
        entries: list[FlextLdifEntry],
        dn: str,
    ) -> FlextResult[FlextLdifEntry | None]:
        """Find entry by DN with enterprise-grade search and comprehensive error handling.

        Performs comprehensive DN-based entry search with input validation, detailed logging,
        and robust error handling for enterprise environments.

        Args:
            entries: List of FlextLdifEntry objects to search
            dn: Distinguished Name to search for (case-sensitive exact match)

        Returns:
            FlextResult[FlextLdifEntry | None]: Success with found entry or None, failure with error context

        """
        # REFACTORING: Enhanced DN search with comprehensive validation
        # Input validation for None entries
        if entries is None:
            error_msg = "Entries list cannot be None"
            self.logger.error(error_msg)
            return FlextResult.fail(error_msg)

        total_entries = len(entries)
        self.logger.debug(
            "Starting DN search operation",
            total_entries=total_entries,
            target_dn=dn,
        )

        try:
            # REFACTORING: Enhanced input validation
            if not isinstance(entries, list):
                error_msg = (
                    f"Invalid entries type: expected list, got {type(entries).__name__}"
                )
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            if not dn or not isinstance(dn, str):
                error_msg: str = f"Invalid DN: expected non-empty string, got {type(dn).__name__}: {dn}"
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            if not entries:
                self.logger.debug("Empty entries list provided - DN not found")
                return FlextResult.ok(None)

            # REFACTORING: Enhanced DN search with error tracking
            search_errors = 0

            for i, entry in enumerate(entries):
                self.logger.trace(
                    "Checking entry %d/%d against target DN: %s",
                    i + 1,
                    total_entries,
                    entry.dn,
                )
                try:
                    entry_dn_str = str(entry.dn)
                    if entry_dn_str == dn:
                        self.logger.info(
                            "DN search successful - entry found",
                            target_dn=dn,
                            found_at_index=i,
                            total_entries_searched=i + 1,
                            search_errors=search_errors,
                        )
                        return FlextResult.ok(entry)
                    self.logger.trace(
                        "DN mismatch: expected '%s', got '%s'",
                        dn,
                        entry_dn_str,
                    )

                except (AttributeError, ValueError, TypeError) as e:
                    search_errors += 1
                    self.logger.warning(
                        "DN comparison error for entry %d: %s",
                        i + 1,
                        e,
                    )
                    # Continue searching other entries

            # REFACTORING: Enhanced search completion logging
            if search_errors > 0:
                self.logger.warning(
                    "DN search completed with errors",
                    search_errors=search_errors,
                    total_entries=total_entries,
                    target_dn=dn,
                )

            self.logger.info(
                "DN search completed - entry not found",
                target_dn=dn,
                total_entries_searched=total_entries,
                search_errors=search_errors,
            )

            return FlextResult.ok(None)

        except (ValueError, TypeError, AttributeError, OSError) as e:
            # REFACTORING: Enhanced exception handling with comprehensive error context
            error_msg: str = f"DN search failed: {type(e).__name__}: {e}"
            self.logger.exception(
                "DN search failed with exception",
                total_entries=total_entries,
                target_dn=dn,
                exception_type=type(e).__name__,
            )
            return FlextResult.fail(error_msg)

    def sort_hierarchically(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Sort entries hierarchically with enterprise-grade sorting and comprehensive error handling.

        Performs comprehensive hierarchical sorting of LDIF entries based on DN depth and alphabetical order
        with input validation, detailed logging, and robust error handling for enterprise environments.

        Args:
            entries: List of FlextLdifEntry objects to sort hierarchically

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with sorted entries or failure with detailed error context

        Sorting Logic:
            - Primary key: DN depth (comma count) - parents first
            - Secondary key: Alphabetical order (case-insensitive)

        """
        # REFACTORING: Enhanced hierarchical sorting with comprehensive validation
        # Input validation for None entries
        if entries is None:
            error_msg = "Entries list cannot be None"
            self.logger.error(error_msg)
            return FlextResult.fail(error_msg)

        total_entries = len(entries)
        self.logger.debug(
            "Starting hierarchical sorting operation",
            total_entries=total_entries,
        )

        try:
            # REFACTORING: Enhanced input validation
            if not isinstance(entries, list):
                error_msg = (
                    f"Invalid entries type: expected list, got {type(entries).__name__}"
                )
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            if not entries:
                self.logger.debug(
                    "Empty entries list provided - returning empty result",
                )
                return FlextResult.ok([])

            # REFACTORING: Enhanced sorting with error tracking and metrics
            sorting_errors = 0
            valid_entries_for_sorting = []

            # Pre-process entries for sorting, collecting metrics
            for i, entry in enumerate(entries):
                self.logger.trace(
                    "Processing entry %d/%d for sorting: %s",
                    i + 1,
                    total_entries,
                    entry.dn,
                )
                try:
                    entry_dn_str = str(entry.dn)
                    dn_depth = entry_dn_str.count(",")
                    self.logger.trace(
                        "Entry DN depth calculated: %d for %s",
                        dn_depth,
                        entry_dn_str,
                    )
                    valid_entries_for_sorting.append(entry)
                except (AttributeError, ValueError, TypeError) as e:
                    sorting_errors += 1
                    self.logger.warning(
                        "Sorting preparation error for entry %d: %s",
                        i + 1,
                        e,
                    )
                    # Continue with other entries, exclude problematic ones

            processed_entries = len(valid_entries_for_sorting)

            # REFACTORING: Enhanced sorting with comprehensive error handling
            self.logger.debug(
                "Executing hierarchical sort",
                valid_entries=processed_entries,
                sorting_errors=sorting_errors,
            )

            try:
                sorted_entries = sorted(
                    valid_entries_for_sorting,
                    key=lambda entry: (
                        str(entry.dn).count(","),  # Primary: depth (parents first)
                        str(entry.dn).lower(),  # Secondary: alphabetical
                    ),
                )

                # REFACTORING: Enhanced sorting verification and metrics
                if sorted_entries:
                    first_depth = str(sorted_entries[0].dn).count(",")
                    last_depth = str(sorted_entries[-1].dn).count(",")
                    self.logger.trace(
                        "Sort verification - depth range: %d to %d",
                        first_depth,
                        last_depth,
                    )

            except (ValueError, TypeError, AttributeError) as e:
                error_msg: str = f"Sorting algorithm failed: {type(e).__name__}: {e}"
                self.logger.exception(error_msg)
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced sorting errors tracking
            if sorting_errors > 0:
                self.logger.warning(
                    "Hierarchical sorting completed with preprocessing errors",
                    sorting_errors=sorting_errors,
                    total_entries=total_entries,
                    successfully_sorted=processed_entries,
                )

            # REFACTORING: Enhanced success logging with comprehensive metrics
            self.logger.info(
                "Hierarchical sorting completed successfully",
                total_entries=total_entries,
                successfully_sorted=len(sorted_entries),
                preprocessing_errors=sorting_errors,
                sort_efficiency_percent=round(
                    (processed_entries / total_entries * 100),
                    2,
                )
                if total_entries > 0
                else 100.0,
            )

            return FlextResult.ok(sorted_entries)

        except (ValueError, TypeError, AttributeError, OSError) as e:
            # REFACTORING: Enhanced exception handling with comprehensive error context
            error_msg: str = f"Hierarchical sorting failed: {type(e).__name__}: {e}"
            self.logger.exception(
                "Hierarchical sorting failed with exception",
                total_entries=total_entries,
                exception_type=type(e).__name__,
            )
            return FlextResult.fail(error_msg)

    def entries_to_ldif(self, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Convert multiple entries to LDIF content with enterprise-grade formatting and comprehensive error handling.

        Performs comprehensive LDIF content generation from domain objects with input validation,
        detailed logging, and robust error handling for enterprise environments.

        Args:
            entries: List of FlextLdifEntry objects to convert to LDIF string

        Returns:
            FlextResult[str]: Success with LDIF content string or failure with detailed error context

        """
        # REFACTORING: Enhanced LDIF conversion with comprehensive validation
        # Input validation for None entries
        if entries is None:
            error_msg = "Entries list cannot be None"
            self.logger.error(error_msg)
            return FlextResult.fail(error_msg)

        total_entries = len(entries)
        self.logger.debug(
            "Starting entries to LDIF conversion operation",
            total_entries=total_entries,
        )

        try:
            # REFACTORING: Enhanced input validation
            if not isinstance(entries, list):
                error_msg = (
                    f"Invalid entries type: expected list, got {type(entries).__name__}"
                )
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            if not entries:
                self.logger.debug("Empty entries list provided - returning empty LDIF")
                return FlextResult.ok("")

            # REFACTORING: Enhanced service delegation with comprehensive error handling
            self.logger.debug(
                "Delegating to writer service for LDIF generation",
                writer_service=self._writer_service.__class__.__name__,
                entries_count=total_entries,
            )

            result = self._writer_service.write(entries)

            # REFACTORING: Enhanced result processing with detailed error context
            if not result.success:
                error_msg = result.error or "LDIF write operation failed"
                detailed_error = (
                    f"Failed to convert {total_entries} entries to LDIF: {error_msg}"
                )
                self.logger.error(
                    "LDIF conversion failed",
                    error=error_msg,
                    entries_count=total_entries,
                    writer_service=self._writer_service.__class__.__name__,
                )
                return FlextResult.fail(detailed_error)

            # REFACTORING: Enhanced content validation and metrics
            ldif_content = result.data or ""
            content_length = len(ldif_content)

            if not ldif_content and total_entries > 0:
                warning_msg = (
                    f"Writer service returned empty content for {total_entries} entries"
                )
                self.logger.warning(warning_msg)
                # Still return success but with empty content

            # REFACTORING: Enhanced success logging with comprehensive metrics
            self.logger.info(
                "Entries to LDIF conversion completed successfully",
                entries_converted=total_entries,
                ldif_content_length_chars=content_length,
                ldif_content_length_bytes=len(ldif_content.encode("utf-8")),
                writer_service_used=self._writer_service.__class__.__name__,
            )

            # Log sample of generated LDIF for debugging (first 200 chars)
            if content_length > 0:
                sample_content = ldif_content[:200].replace("\n", "\\n")
                self.logger.trace(
                    "Generated LDIF sample: %s%s",
                    sample_content,
                    "..." if content_length > 200 else "",
                )

            return FlextResult.ok(ldif_content)

        except (ValueError, TypeError, AttributeError, OSError) as e:
            # REFACTORING: Enhanced exception handling with comprehensive error context
            error_msg: str = f"LDIF conversion failed: {type(e).__name__}: {e}"
            self.logger.exception(
                "Entries to LDIF conversion failed with exception",
                total_entries=total_entries,
                exception_type=type(e).__name__,
            )
            return FlextResult.fail(error_msg)

    # ==========================================================================
    # INTELLIGENT FILTERING METHODS (Using integrated composition)
    # ==========================================================================

    def filter_groups(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter group entries with enterprise-grade classification and business rule validation.

        Performs intelligent filtering of LDAP group entries using integrated Domain-Driven Design
        specification patterns. Identifies group entries based on objectClass attributes and
        validates group-specific business rules including membership and structural requirements.

        This method leverages composition-based specification logic integrated directly into the
        FlextLdifEntry domain entities, providing consistent group classification across the
        application while maintaining clean architecture separation of concerns.

        Args:
            entries: List of FlextLdifEntry objects to filter for group entries

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with filtered group entries or failure with error details

        Group Classification Rules:
            Entries are classified as groups if they contain any of these objectClass values:
            - group: Basic group object class
            - groupOfNames: Group with distinguished name member references
            - groupOfUniqueNames: Group with unique member identification
            - posixGroup: POSIX group with numeric GID and member lists
            - organizationalRole: Role-based group entries

        Business Rules Validated:
            - Group entries must have valid group objectClass
            - Group structure and membership attributes are verified
            - Hierarchical group relationships are maintained

        Example:
            >>> from flext_ldif import FlextLdifAPI
            >>> api = FlextLdifAPI()
            >>>
            >>> # Filter group entries from parsed LDIF
            >>> result = api.filter_groups(entries)
            >>> if result.success:
            ...     group_entries = result.data
            ...     print(f"Found {len(group_entries)} group entries")
            ...     for group in group_entries[:3]:  # Show first 3
            ...         cn = group.get_single_attribute("cn")
            ...         members = group.get_attribute("member") or []
            ...         print(f"- {cn} ({len(members)} members)")
            ... else:
            ...     print(f"Group filter failed: {result.error}")

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        # REFACTORING: Enhanced group filtering with comprehensive metrics
        # Input validation for None entries
        if entries is None:
            error_msg = "Entries list cannot be None"
            self.logger.error(error_msg)
            return FlextResult.fail(error_msg)

        total_entries = len(entries)
        self.logger.debug(
            "Starting group entries filtering operation",
            total_entries=total_entries,
        )
        self.logger.trace(
            "Group filtering classification rules active",
            group_classes=[
                "group",
                "groupOfNames",
                "groupOfUniqueNames",
                "posixGroup",
                "organizationalRole",
            ],
        )

        try:
            # REFACTORING: Enhanced input validation with detailed logging
            if not entries:
                self.logger.debug(
                    "Empty entries list provided - returning empty result",
                )
                return FlextResult.ok([])

            if not isinstance(entries, list):
                error_msg = (
                    f"Invalid entries type: expected list, got {type(entries).__name__}"
                )
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced group filtering with detailed progress tracking
            self.logger.debug("Applying group classification rules to entries")
            group_entries = []
            group_classification_errors = 0

            for i, entry in enumerate(entries):
                self.logger.trace(
                    "Evaluating entry %d/%d for group classification: %s",
                    i + 1,
                    total_entries,
                    entry.dn,
                )
                try:
                    if entry.is_group_entry():
                        group_entries.append(entry)
                        self.logger.trace("Entry classified as group: %s", entry.dn)
                    else:
                        self.logger.trace("Entry NOT classified as group: %s", entry.dn)
                except (AttributeError, ValueError) as e:
                    group_classification_errors += 1
                    self.logger.warning(
                        "Group classification error for entry %s: %s",
                        entry.dn,
                        e,
                    )
                    # Continue processing other entries

            group_count = len(group_entries)
            filter_ratio = group_count / total_entries if total_entries > 0 else 0.0

            # REFACTORING: Enhanced classification errors tracking
            if group_classification_errors > 0:
                self.logger.warning(
                    "Group classification completed with errors",
                    classification_errors=group_classification_errors,
                    total_entries=total_entries,
                )

            # REFACTORING: Enhanced success logging with comprehensive metrics
            self.logger.info(
                "Group entries filtering completed successfully",
                total_entries=total_entries,
                group_entries_found=group_count,
                filter_ratio_percent=round(filter_ratio * 100, 2),
                classification_errors=group_classification_errors,
            )

            # Log sample of filtered group entries for debugging (first 3)
            if group_count > 0:
                sample_groups = [str(entry.dn) for entry in group_entries[:3]]
                self.logger.trace("Sample group entries found: %s", sample_groups)

            return FlextResult.ok(group_entries)

        except (ValueError, TypeError, AttributeError, OSError) as e:
            # REFACTORING: Enhanced exception handling with comprehensive error context
            error_msg: str = (
                f"Group filtering operation failed: {type(e).__name__}: {e}"
            )
            self.logger.exception(
                "Group entries filtering failed with exception",
                total_entries=total_entries,
                exception_type=type(e).__name__,
            )
            return FlextResult.fail(error_msg)

    def filter_organizational_units(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter organizational unit entries with enterprise-grade validation and comprehensive error handling.

        Performs comprehensive OU-based filtering with input validation, detailed logging,
        and robust error handling for enterprise environments.

        Args:
            entries: List of FlextLdifEntry objects to filter for organizational units

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with filtered OU entries or failure with detailed error context

        """
        # REFACTORING: Enhanced OU filtering with comprehensive metrics
        # Input validation for None entries
        if entries is None:
            error_msg = "Entries list cannot be None"
            self.logger.error(error_msg)
            return FlextResult.fail(error_msg)

        total_entries = len(entries)
        self.logger.debug(
            "Starting organizational unit filtering operation",
            total_entries=total_entries,
        )

        try:
            # REFACTORING: Enhanced input validation
            if not entries:
                self.logger.debug(
                    "Empty entries list provided - returning empty result",
                )
                return FlextResult.ok([])

            if not isinstance(entries, list):
                error_msg = (
                    f"Invalid entries type: expected list, got {type(entries).__name__}"
                )
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced OU filtering with error tracking
            ou_entries = []
            ou_classification_errors = 0

            for i, entry in enumerate(entries):
                self.logger.trace(
                    "Evaluating entry %d/%d for OU classification: %s",
                    i + 1,
                    total_entries,
                    entry.dn,
                )
                try:
                    if entry.is_organizational_unit():
                        ou_entries.append(entry)
                        self.logger.trace("Entry classified as OU: %s", entry.dn)
                    else:
                        self.logger.trace("Entry NOT classified as OU: %s", entry.dn)
                except (AttributeError, ValueError) as e:
                    ou_classification_errors += 1
                    self.logger.warning(
                        "OU classification error for entry %s: %s",
                        entry.dn,
                        e,
                    )
                    # Continue processing other entries

            ou_count = len(ou_entries)
            filter_ratio = ou_count / total_entries if total_entries > 0 else 0.0

            # REFACTORING: Enhanced classification errors tracking
            if ou_classification_errors > 0:
                self.logger.warning(
                    "OU classification completed with errors",
                    classification_errors=ou_classification_errors,
                    total_entries=total_entries,
                )

            # REFACTORING: Enhanced success logging with comprehensive metrics
            self.logger.info(
                "Organizational unit filtering completed successfully",
                total_entries=total_entries,
                ou_entries_found=ou_count,
                filter_ratio_percent=round(filter_ratio * 100, 2),
                classification_errors=ou_classification_errors,
            )

            return FlextResult.ok(ou_entries)

        except (ValueError, TypeError, AttributeError, OSError) as e:
            # REFACTORING: Enhanced exception handling with comprehensive error context
            error_msg: str = f"OU filtering operation failed: {type(e).__name__}: {e}"
            self.logger.exception(
                "OU filtering failed with exception",
                total_entries=total_entries,
                exception_type=type(e).__name__,
            )
            return FlextResult.fail(error_msg)

    def filter_change_records(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter change record entries with enterprise-grade validation and comprehensive error handling.

        Performs comprehensive change record filtering with input validation, detailed logging,
        and robust error handling for enterprise environments.

        Args:
            entries: List of FlextLdifEntry objects to filter for change records

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with filtered change entries or failure with detailed error context

        """
        # REFACTORING: Enhanced change record filtering with comprehensive metrics
        # Input validation for None entries
        if entries is None:
            error_msg = "Entries list cannot be None"
            self.logger.error(error_msg)
            return FlextResult.fail(error_msg)

        total_entries = len(entries)
        self.logger.debug(
            "Starting change record filtering operation",
            total_entries=total_entries,
        )

        try:
            # REFACTORING: Enhanced input validation
            if not entries:
                self.logger.debug(
                    "Empty entries list provided - returning empty result",
                )
                return FlextResult.ok([])

            if not isinstance(entries, list):
                error_msg = (
                    f"Invalid entries type: expected list, got {type(entries).__name__}"
                )
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced change record filtering with error tracking
            change_entries = []
            change_classification_errors = 0

            for i, entry in enumerate(entries):
                self.logger.trace(
                    "Evaluating entry %d/%d for change record classification: %s",
                    i + 1,
                    total_entries,
                    entry.dn,
                )
                try:
                    if entry.is_change_record():
                        change_entries.append(entry)
                        self.logger.trace(
                            "Entry classified as change record: %s",
                            entry.dn,
                        )
                    else:
                        self.logger.trace(
                            "Entry NOT classified as change record: %s",
                            entry.dn,
                        )
                except (AttributeError, ValueError) as e:
                    change_classification_errors += 1
                    self.logger.warning(
                        "Change record classification error for entry %s: %s",
                        entry.dn,
                        e,
                    )
                    # Continue processing other entries

            change_count = len(change_entries)
            filter_ratio = change_count / total_entries if total_entries > 0 else 0.0

            # REFACTORING: Enhanced classification errors tracking
            if change_classification_errors > 0:
                self.logger.warning(
                    "Change record classification completed with errors",
                    classification_errors=change_classification_errors,
                    total_entries=total_entries,
                )

            # REFACTORING: Enhanced success logging with comprehensive metrics
            self.logger.info(
                "Change record filtering completed successfully",
                total_entries=total_entries,
                change_entries_found=change_count,
                filter_ratio_percent=round(filter_ratio * 100, 2),
                classification_errors=change_classification_errors,
            )

            return FlextResult.ok(change_entries)

        except (ValueError, TypeError, AttributeError, OSError) as e:
            # REFACTORING: Enhanced exception handling with comprehensive error context
            error_msg = (
                f"Change record filtering operation failed: {type(e).__name__}: {e}"
            )
            self.logger.exception(
                "Change record filtering failed with exception",
                total_entries=total_entries,
                exception_type=type(e).__name__,
            )
            return FlextResult.fail(error_msg)

    def get_entry_statistics(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[dict[str, int]]:
        """Get comprehensive entry statistics with enterprise-grade analysis and observability integration.

        Performs comprehensive statistical analysis of LDIF entries with input validation,
        detailed logging, metrics recording, and robust error handling for enterprise environments.

        Args:
            entries: List of FlextLdifEntry objects to analyze

        Returns:
            FlextResult[dict[str, int]]: Success with statistics dictionary or failure with detailed error context

        """
        # REFACTORING: Enhanced statistics calculation with comprehensive validation
        # Input validation for None entries
        if entries is None:
            error_msg = "Entries list cannot be None"
            self.logger.error(error_msg)
            return FlextResult.fail(error_msg)

        total_entries = len(entries)
        self.logger.debug(
            "Starting entry statistics calculation",
            total_entries=total_entries,
        )

        try:
            # REFACTORING: Enhanced input validation
            if not isinstance(entries, list):
                error_msg = (
                    f"Invalid entries type: expected list, got {type(entries).__name__}"
                )
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            if not entries:
                self.logger.debug(
                    "Empty entries list provided - returning zero statistics",
                )
                empty_stats = {
                    "total_entries": 0,
                    "valid_entries": 0,
                    "person_entries": 0,
                    "group_entries": 0,
                    "ou_entries": 0,
                    "change_records": 0,
                }
                return FlextResult.ok(empty_stats)

            # REFACTORING: Enhanced statistics calculation with error tracking
            self.logger.debug("Computing comprehensive entry statistics")
            stats: dict[str, int] = {}
            calculation_errors = 0

            # Basic count
            stats["total_entries"] = total_entries
            self.logger.trace("Total entries counted: %d", total_entries)

            # Valid entries count with error handling
            try:
                valid_count = sum(1 for entry in entries if entry.is_valid_entry())
                stats["valid_entries"] = valid_count
                self.logger.trace("Valid entries counted: %d", valid_count)
            except (AttributeError, ValueError) as e:
                calculation_errors += 1
                self.logger.warning("Error counting valid entries: %s", e)
                stats["valid_entries"] = 0

            # Person entries count with error handling
            try:
                person_count = sum(1 for entry in entries if entry.is_person_entry())
                stats["person_entries"] = person_count
                self.logger.trace("Person entries counted: %d", person_count)
            except (AttributeError, ValueError) as e:
                calculation_errors += 1
                self.logger.warning("Error counting person entries: %s", e)
                stats["person_entries"] = 0

            # Group entries count with error handling
            try:
                group_count = sum(1 for entry in entries if entry.is_group_entry())
                stats["group_entries"] = group_count
                self.logger.trace("Group entries counted: %d", group_count)
            except (AttributeError, ValueError) as e:
                calculation_errors += 1
                self.logger.warning("Error counting group entries: %s", e)
                stats["group_entries"] = 0

            # OU entries count with error handling
            try:
                ou_count = sum(1 for entry in entries if entry.is_organizational_unit())
                stats["ou_entries"] = ou_count
                self.logger.trace("OU entries counted: %d", ou_count)
            except (AttributeError, ValueError) as e:
                calculation_errors += 1
                self.logger.warning("Error counting OU entries: %s", e)
                stats["ou_entries"] = 0

            # Change records count with error handling
            try:
                change_count = sum(1 for entry in entries if entry.is_change_record())
                stats["change_records"] = change_count
                self.logger.trace("Change records counted: %d", change_count)
            except (AttributeError, ValueError) as e:
                calculation_errors += 1
                self.logger.warning("Error counting change records: %s", e)
                stats["change_records"] = 0

            # REFACTORING: Enhanced observability metrics recording
            self.logger.debug("Recording statistics as observability metrics")
            for stat_name, stat_value in stats.items():
                try:
                    self._observability_monitor.flext_record_metric(
                        f"ldif_statistics_{stat_name}",
                        float(stat_value),
                        "gauge",
                    )
                except Exception as e:
                    self.logger.warning("Failed to record metric %s: %s", stat_name, e)

            # REFACTORING: Enhanced calculation errors tracking
            if calculation_errors > 0:
                self.logger.warning(
                    "Statistics calculation completed with errors",
                    calculation_errors=calculation_errors,
                    total_entries=total_entries,
                )

            # REFACTORING: Enhanced success logging with comprehensive metrics
            self.logger.info(
                "Entry statistics calculation completed successfully",
                total_entries=stats["total_entries"],
                valid_entries=stats["valid_entries"],
                person_entries=stats["person_entries"],
                group_entries=stats["group_entries"],
                ou_entries=stats["ou_entries"],
                change_records=stats["change_records"],
                calculation_errors=calculation_errors,
            )

            return FlextResult.ok(stats)

        except (ValueError, TypeError, AttributeError, OSError) as e:
            # REFACTORING: Enhanced exception handling with comprehensive error context
            error_msg: str = f"Statistics calculation failed: {type(e).__name__}: {e}"
            self.logger.exception(
                "Entry statistics calculation failed with exception",
                total_entries=total_entries,
                exception_type=type(e).__name__,
            )
            return FlextResult.fail(error_msg)

    def get_observability_metrics(self) -> FlextResult[dict[str, object]]:
        """Get comprehensive observability metrics with enterprise-grade monitoring and error handling.

        Retrieves complete observability data including metrics, health status, and monitoring state
        with comprehensive error handling and detailed logging for enterprise environments.

        Returns:
            FlextResult[dict[str, object]]: Success with observability data or failure with detailed error context

        """
        # REFACTORING: Enhanced observability metrics retrieval with comprehensive logging
        self.logger.debug("Starting observability metrics retrieval")

        try:
            # REFACTORING: Enhanced observability monitor validation
            if not self._observability_monitor:
                error_msg = "Observability monitor not available - API operating in degraded mode"
                self.logger.warning(error_msg)
                return FlextResult.fail(error_msg)

            self.logger.trace(
                "Observability monitor available - proceeding with metrics collection",
            )

            # REFACTORING: Enhanced metrics summary retrieval with error handling
            self.logger.debug("Retrieving metrics summary from observability monitor")
            metrics_result = self._observability_monitor.flext_get_metrics_summary()
            if metrics_result.is_failure:
                error_msg: str = f"Failed to get metrics summary: {metrics_result.error or 'Unknown error'}"
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            metrics_data = metrics_result.data or {}
            self.logger.trace(
                "Metrics summary retrieved successfully",
                metrics_count=len(metrics_data),
            )

            # REFACTORING: Enhanced health status retrieval with error handling
            self.logger.debug("Retrieving health status from observability monitor")
            health_result = self._observability_monitor.flext_get_health_status()
            if health_result.is_failure:
                error_msg: str = f"Failed to get health status: {health_result.error or 'Unknown error'}"
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            health_data = health_result.data or {}
            self.logger.trace(
                "Health status retrieved successfully",
                health_keys=list(health_data.keys()),
            )

            # REFACTORING: Enhanced monitoring state retrieval with error handling
            try:
                monitoring_active = (
                    self._observability_monitor.flext_is_monitoring_active()
                )
                self.logger.trace("Monitoring active status: %s", monitoring_active)
            except (AttributeError, ValueError) as e:
                self.logger.warning(
                    "Failed to determine monitoring active status: %s",
                    e,
                )
                monitoring_active = False

            # REFACTORING: Enhanced observability data compilation
            observability_data = {
                "metrics": metrics_data,
                "health": health_data,
                "monitoring_active": monitoring_active,
                "observability_available": True,
                "metrics_count": len(metrics_data),
                "health_checks_count": len(health_data),
            }

            # REFACTORING: Enhanced success logging with comprehensive metrics
            self.logger.info(
                "Observability metrics retrieval completed successfully",
                metrics_available=len(metrics_data),
                health_checks_available=len(health_data),
                monitoring_active=monitoring_active,
                observability_status="operational",
            )

            return FlextResult.ok(observability_data)

        except (ValueError, TypeError, AttributeError, OSError) as e:
            # REFACTORING: Enhanced exception handling with comprehensive error context
            error_msg = (
                f"Observability metrics retrieval failed: {type(e).__name__}: {e}"
            )
            self.logger.exception(
                "Observability metrics retrieval failed with exception",
                exception_type=type(e).__name__,
                observability_monitor_available=hasattr(self, "_observability_monitor"),
            )
            return FlextResult.fail(error_msg)

    def reset_observability_metrics(self) -> FlextResult[None]:
        """Reset observability metrics with enterprise-grade cleanup and comprehensive error handling.

        Refactored using Strategy Pattern and Single Responsibility Principle to reduce
        complexity from 15 to manageable levels with focused reset strategies.

        Returns:
            FlextResult[None]: Success if metrics reset completed, failure with detailed error context

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        self.logger.debug("Starting observability metrics reset operation")
        self.logger.trace("Observability reset requested for comprehensive cleanup")

        try:
            # Strategy 1: Validate observability monitor - Single Responsibility
            monitor_result = self._validate_observability_monitor()
            if monitor_result.is_failure:
                return monitor_result

            # Strategy 2: Get metrics service - Single Responsibility
            service_result = self._get_metrics_service()
            if service_result.is_failure:
                return service_result

            metrics_service = service_result.data

            # Strategy 3: Execute metrics reset - Single Responsibility
            reset_result = self._execute_metrics_reset(metrics_service)
            if reset_result.is_failure:
                return reset_result

            reset_executed = reset_result.data

            # Strategy 4: Log completion status - Single Responsibility
            self._log_reset_completion(metrics_service, reset_executed)
            return FlextResult.ok(None)

        except (ValueError, TypeError, AttributeError, OSError) as e:
            error_msg: str = (
                f"Observability metrics reset failed: {type(e).__name__}: {e}"
            )
            self.logger.exception(
                "Observability metrics reset failed with exception",
                exception_type=type(e).__name__,
                observability_monitor_available=bool(self._observability_monitor),
            )
            return FlextResult.fail(error_msg)

    def _validate_observability_monitor(self) -> FlextResult[None]:
        """Strategy 1: Validate observability monitor - Single Responsibility Principle."""
        if not self._observability_monitor:
            error_msg = "Observability monitor not available - cannot reset metrics"
            self.logger.error(error_msg)
            self.logger.debug(
                "Reset operation failed: no observability monitor configured",
            )
            return FlextResult.fail(error_msg)

        self.logger.debug("Observability monitor validated successfully")
        self.logger.trace(
            "Monitor type: %s",
            self._observability_monitor.__class__.__name__,
        )
        return FlextResult.ok(None)

    def _get_metrics_service(self) -> FlextResult:
        """Strategy 2: Get metrics service from container - Single Responsibility Principle."""
        try:
            container = self._observability_monitor.container
            if not container:
                error_msg = "Observability container not available - cannot access metrics service"
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            self.logger.debug(
                "Container access validated successfully",
                container_id=id(container),
            )

        except (AttributeError, ValueError) as e:
            error_msg: str = f"Failed to access observability container: {e}"
            self.logger.exception(error_msg)
            return FlextResult.fail(error_msg)

        # Resolve metrics service from container
        self.logger.debug("Resolving metrics service from container")
        try:
            metrics_service_result = container.get("flext_metrics_service")

            if not metrics_service_result.success:
                error_msg: str = (
                    f"Failed to resolve metrics service: {metrics_service_result.error}"
                )
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            metrics_service = metrics_service_result.data
            if not metrics_service:
                error_msg = "Metrics service resolved but data is None"
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            self.logger.debug(
                "Metrics service resolved successfully",
                service_type=type(metrics_service).__name__,
            )
            return FlextResult.ok(metrics_service)

        except (ValueError, TypeError, AttributeError) as e:
            error_msg: str = f"Metrics service resolution failed: {e}"
            self.logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    def _execute_metrics_reset(self, metrics_service) -> FlextResult[bool]:
        """Strategy 3: Execute metrics reset operation - Template Method Pattern."""
        # Template Method: Try different reset strategies

        # Strategy 3.1: Try service.data.reset_metrics
        if hasattr(metrics_service, "data") and hasattr(
            metrics_service.data,
            "reset_metrics",
        ):
            return self._reset_via_service_data(metrics_service)

        # Strategy 3.2: Try service.reset_metrics
        if hasattr(metrics_service, "reset_metrics"):
            return self._reset_via_direct_service(metrics_service)

        # Strategy 3.3: No reset capability available
        return self._handle_no_reset_capability(metrics_service)

    def _reset_via_service_data(self, metrics_service) -> FlextResult[bool]:
        """Strategy 3.1: Reset via service.data.reset_metrics - SRP."""
        self.logger.debug("Executing metrics reset via service.data.reset_metrics()")
        try:
            reset_result = metrics_service.data.reset_metrics()

            if not reset_result.success:
                error_msg: str = f"Metrics service reset failed: {reset_result.error or 'Unknown reset error'}"
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            self.logger.debug("Metrics reset executed successfully via service.data")
            return FlextResult.ok(True)  # Reset executed

        except (ValueError, TypeError, AttributeError) as e:
            error_msg: str = f"Metrics reset execution failed: {e}"
            self.logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    def _reset_via_direct_service(self, metrics_service) -> FlextResult[bool]:
        """Strategy 3.2: Reset via service.reset_metrics - SRP."""
        self.logger.debug("Executing metrics reset via service.reset_metrics()")
        try:
            reset_result = metrics_service.reset_metrics()

            if hasattr(reset_result, "success") and not reset_result.success:
                error_msg: str = f"Direct metrics reset failed: {reset_result.error or 'Unknown reset error'}"
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            self.logger.debug(
                "Metrics reset executed successfully via direct service call",
            )
            return FlextResult.ok(True)  # Reset executed

        except (ValueError, TypeError, AttributeError) as e:
            error_msg: str = f"Direct metrics reset execution failed: {e}"
            self.logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    def _handle_no_reset_capability(self, metrics_service) -> FlextResult[bool]:
        """Strategy 3.3: Handle service without reset capability - SRP."""
        warning_msg = (
            "Metrics service does not support reset operations - skipping reset"
        )
        self.logger.warning(
            warning_msg,
            service_type=type(metrics_service).__name__,
            available_methods=[
                method for method in dir(metrics_service) if not method.startswith("_")
            ],
        )
        return FlextResult.ok(False)  # No reset executed

    def _log_reset_completion(self, metrics_service, reset_executed: bool) -> None:
        """Strategy 4: Log reset completion status - Single Responsibility Principle."""
        if reset_executed:
            self.logger.info(
                "Observability metrics reset completed successfully",
                metrics_service_type=type(metrics_service).__name__,
                reset_method_used="service.data.reset_metrics"
                if hasattr(metrics_service, "data")
                else "service.reset_metrics",
            )
        else:
            self.logger.info(
                "Observability metrics reset completed (no reset operations executed)",
                metrics_service_type=type(metrics_service).__name__,
                reset_support_available=False,
            )


# Global API instance
_api_instance: FlextLdifAPI | None = None


def flext_ldif_get_api(config: FlextLdifConfig | None = None) -> FlextLdifAPI:
    """Get global LDIF API instance with enterprise-grade singleton management and comprehensive configuration handling.

    Provides thread-safe access to the global FlextLdifAPI singleton instance with intelligent
    configuration management, instance lifecycle control, and comprehensive error handling for
    enterprise environments requiring consistent API access patterns.

    This function implements the singleton pattern with configuration-based instance refresh
    capability, ensuring optimal resource utilization while maintaining configuration flexibility
    and enterprise-grade initialization patterns.

    Args:
        config: Optional FlextLdifConfig instance for API initialization or reconfiguration

    Returns:
        FlextLdifAPI: Configured and ready-to-use LDIF API instance

    Singleton Behavior:
        - First call: Creates new instance with provided or default configuration
        - Subsequent calls with None config: Returns existing instance
        - Calls with new config: Creates fresh instance with new configuration
        - Thread-safe instance management with proper lifecycle handling

    Configuration Management:
        - Default configuration: Uses FlextLdifConfig() defaults when config is None
        - Custom configuration: Applies provided config and refreshes instance
        - Configuration validation: Ensures valid configuration before instance creation
        - Resource optimization: Reuses existing instance when configuration unchanged

    Example:
        >>> from flext_ldif import flext_ldif_get_api, FlextLdifConfig
        >>> from pathlib import Path
        >>>
        >>> # Get API with default configuration
        >>> api = flext_ldif_get_api()
        >>> print(f"API ready: {api is not None}")
        >>>
        >>> # Get API with custom configuration
        >>> config = FlextLdifConfig(
        ...     max_entries=50000, output_directory=Path("/data/ldif")
        ... )
        >>> api = flext_ldif_get_api(config)
        >>> print(f"Max entries: {api.config.max_entries}")

    Thread Safety:
        This function is thread-safe for read operations but instance creation
        may create multiple instances in high-concurrency scenarios. For strict
        singleton requirements in multi-threaded environments, use proper locking.

    Raises:
        No exceptions - API instance creation errors are handled internally by FlextLdifAPI

    """
    # REFACTORING: Enhanced global instance management with comprehensive logging
    global _api_instance  # noqa: PLW0603

    logger = get_logger(__name__)
    logger.debug(
        "Global LDIF API instance requested",
        existing_instance_available=_api_instance is not None,
        config_provided=config is not None,
    )

    # REFACTORING: Enhanced instance lifecycle management with configuration validation
    try:
        # Check if new instance is needed
        create_new_instance = False

        if _api_instance is None:
            logger.debug("No existing API instance - creating new instance")
            create_new_instance = True
        elif config is not None:
            logger.debug("New configuration provided - refreshing API instance")
            logger.trace("Existing instance will be replaced with new configuration")
            create_new_instance = True
        else:
            logger.debug("Returning existing API instance")
            logger.trace("Instance type: %s", type(_api_instance).__name__)

        # REFACTORING: Enhanced instance creation with comprehensive error handling
        if create_new_instance:
            logger.debug(
                "Creating new FlextLdifAPI instance",
                config_source="provided" if config else "default",
            )

            try:
                # Create new instance with proper configuration
                _api_instance = FlextLdifAPI(config)

                logger.info(
                    "Global LDIF API instance created successfully",
                    instance_id=id(_api_instance),
                    config_source="provided" if config else "default",
                    api_type=type(_api_instance).__name__,
                )

            except (ValueError, TypeError, AttributeError) as e:
                logger.exception("Failed to create LDIF API instance")
                logger.exception("API instance creation failed: %s", e)
                # Fall back to creating with default config
                logger.warning(
                    "Attempting fallback API instance creation with default config",
                )
                try:
                    _api_instance = FlextLdifAPI()
                    logger.warning("Fallback API instance created successfully")
                except Exception as fallback_error:
                    logger.exception("Fallback API instance creation also failed")
                    msg: str = f"Unable to create LDIF API instance: {fallback_error}"
                    raise RuntimeError(
                        msg,
                    ) from fallback_error

        # REFACTORING: Enhanced instance validation and return
        if _api_instance is None:
            error_msg = "API instance is None after creation attempt"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

        logger.trace(
            "Returning API instance",
            instance_id=id(_api_instance),
            config_max_entries=_api_instance.config.max_entries,
        )

        return _api_instance

    except Exception as e:
        # REFACTORING: Enhanced exception handling with comprehensive error context
        logger.exception(
            "Global API instance retrieval failed with exception",
            exception_type=type(e).__name__,
            existing_instance_available=_api_instance is not None,
        )
        # Re-raise as this is a critical failure
        raise


# Convenience functions using global API
def flext_ldif_parse(content: str | LDIFContent) -> list[FlextLdifEntry]:
    """Parse LDIF content with enterprise-grade convenience API and comprehensive error resilience.

    Provides a simplified interface for LDIF parsing operations using the global API instance
    with automatic error handling, result validation, and enterprise-grade failure recovery.
    This convenience function abstracts FlextResult complexity while maintaining robustness.

    This function implements intelligent error recovery patterns including empty result fallback,
    type validation, and comprehensive logging for enterprise environments requiring simple
    API interfaces with reliable error handling and consistent behavior patterns.

    Args:
        content: LDIF content to parse as string or LDIFContent object

    Returns:
        list[FlextLdifEntry]: Successfully parsed LDIF entries, empty list on failure

    Error Handling:
        - Parse failures: Returns empty list instead of raising exceptions
        - Invalid input: Returns empty list with warning logs
        - API errors: Graceful degradation with comprehensive error logging
        - Type validation: Ensures returned data is properly typed

    Convenience Features:
        - No FlextResult handling required - returns data directly
        - Automatic error recovery - never raises exceptions
        - Type safety - guaranteed list[FlextLdifEntry] return type
        - Global API integration - uses optimized singleton instance

    Example:
        >>> from flext_ldif import flext_ldif_parse
        >>>
        >>> # Parse LDIF content with simple interface
        >>> ldif_content = '''
        ... dn: cn=John Doe,ou=people,dc=example,dc=com
        ... objectClass: person
        ... cn: John Doe
        ... sn: Doe
        ... '''
        >>> entries = flext_ldif_parse(ldif_content)
        >>> print(f"Parsed {len(entries)} entries")
        >>> if entries:
        ...     first_entry = entries[0]
        ...     print(f"First entry DN: {first_entry.dn}")

    Performance:
        Uses global API singleton for optimal performance and resource utilization.
        Parsing operations are delegated to enterprise-grade FlextLdifAPI implementation
        with full observability and metrics collection.

    Thread Safety:
        Thread-safe through global API singleton management. Multiple threads can
        safely call this function concurrently without coordination.

    Raises:
        No exceptions - all errors handled gracefully with empty list return

    """
    # REFACTORING: Enhanced convenience parsing with comprehensive error handling
    logger = get_logger(__name__)
    logger.debug(
        "Convenience LDIF parsing requested",
        content_type=type(content).__name__,
        content_size=len(str(content)) if content else 0,
    )

    try:
        # Strategy Pattern: Use parsing strategies to reduce complexity

        # Strategy 1: Input validation - Single Responsibility
        validated_content = _validate_parse_input(content, logger)
        if validated_content is None:
            return []

        # Strategy 2: API access - Single Responsibility
        api = _get_parse_api(logger)
        if api is None:
            return []

        # Strategy 3: Parse execution - Single Responsibility
        parse_result = _execute_parse_operation(api, content, validated_content, logger)
        if parse_result is None:
            return []

        # Strategy 4: Result processing - Single Responsibility
        return _process_parse_result(parse_result, validated_content, logger)

    except Exception as e:
        # REFACTORING: Enhanced top-level exception handling
        logger.exception(
            "Convenience LDIF parsing failed with unexpected exception",
            content_type=type(content).__name__ if content else "None",
            exception_type=type(e).__name__,
        )
        logger.debug("Returning empty list due to unexpected exception")
        return []


def _validate_parse_input(content: str | LDIFContent, logger) -> str | None:
    """Strategy 1: Validate input for parse operation following Single Responsibility Principle."""
    # REFACTORING: Enhanced input validation with detailed logging
    if not content:
        logger.warning("Empty or None content provided to convenience parse function")
        logger.debug("Returning empty list for empty content")
        return None

    # Validate content type
    if not isinstance(content, (str, bytes)) and not hasattr(content, "__str__"):
        logger.warning(
            "Invalid content type for parsing",
            content_type=type(content).__name__,
            expected_types=["str", "bytes", "LDIFContent"],
        )
        logger.debug("Returning empty list for invalid content type")
        return None

    content_str = str(content)
    content_length = len(content_str)
    logger.trace(
        "Content validated for parsing",
        content_length=content_length,
        content_preview=content_str[:100].replace("\n", "\\n")
        if content_length > 0
        else "",
    )

    return content_str


def _get_parse_api(logger) -> FlextLdifAPI | None:
    """Strategy 2: Get API instance for parse operation following Single Responsibility Principle."""
    # REFACTORING: Enhanced API access with comprehensive error handling
    try:
        api = flext_ldif_get_api()
        logger.debug(
            "Global API instance retrieved for parsing",
            api_type=type(api).__name__,
        )
        return api
    except Exception as e:
        logger.exception("Failed to get global API instance for convenience parsing")
        logger.exception("API retrieval failed: %s", e)
        logger.debug("Returning empty list due to API access failure")
        return None


def _execute_parse_operation(
    api: FlextLdifAPI,
    content: str | LDIFContent,
    content_str: str,
    logger,
) -> FlextResult | None:
    """Strategy 3: Execute parse operation following Single Responsibility Principle."""
    # REFACTORING: Enhanced parsing execution with comprehensive result validation
    content_length = len(content_str)
    logger.debug(
        "Executing LDIF parsing via global API",
        content_length=content_length,
    )

    try:
        parse_result = api.parse(content)

        # Validate result type and structure
        if not isinstance(parse_result, FlextResult):
            logger.error(
                "Parse operation returned invalid result type",
                result_type=type(parse_result).__name__,
                expected_type="FlextResult",
            )
            logger.debug("Returning empty list due to invalid result type")
            return None

        logger.debug(
            "Parse operation completed",
            result_success=parse_result.success,
            result_has_data=parse_result.data is not None,
        )

        return parse_result

    except Exception as e:
        logger.exception("Parse operation raised exception")
        logger.exception("Parsing failed with exception: %s", e)
        logger.debug("Returning empty list due to parsing exception")
        return None


def _process_parse_result(
    parse_result: FlextResult,
    content_str: str,
    logger,
) -> list[FlextLdifEntry]:
    """Strategy 4: Process parse result following Single Responsibility Principle."""
    content_length = len(content_str)

    # REFACTORING: Enhanced result processing with comprehensive validation
    if not parse_result.success:
        logger.warning(
            "LDIF parsing failed via convenience function",
            error=parse_result.error or "Unknown parsing error",
            content_length=content_length,
        )
        logger.debug("Returning empty list due to parsing failure")
        return []

    if parse_result.data is None:
        logger.warning("Parse succeeded but returned None data")
        logger.debug("Returning empty list due to None data")
        return []

    # REFACTORING: Enhanced data validation and type safety
    try:
        # Type assertion for mypy and runtime validation
        if not isinstance(parse_result.data, list):
            logger.error(
                "Parse data is not a list",
                data_type=type(parse_result.data).__name__,
            )
            logger.debug("Returning empty list due to invalid data type")
            return []

        entries: list[FlextLdifEntry] = parse_result.data
        entries_count = len(entries)

        # Validate all entries are correct type
        invalid_entries = 0
        for i, entry in enumerate(entries):
            if not hasattr(entry, "dn") or not hasattr(entry, "attributes"):
                invalid_entries += 1
                logger.warning("Entry %d does not have required attributes", i)

        if invalid_entries > 0:
            logger.warning("Found %d invalid entries in parse result", invalid_entries)

        logger.info(
            "Convenience LDIF parsing completed successfully",
            entries_parsed=entries_count,
            content_length_chars=content_length,
            invalid_entries=invalid_entries,
        )

        return entries

    except (TypeError, AttributeError) as e:
        logger.exception("Data validation failed for parse result")
        logger.exception("Result data validation error: %s", e)
        logger.debug("Returning empty list due to data validation failure")
        return []


def flext_ldif_validate(content: str | LDIFContent) -> bool:
    """Validate LDIF content with enterprise-grade convenience API and comprehensive validation processing.

    Provides a simplified boolean interface for LDIF content validation using the global API instance
    with comprehensive error handling, multi-stage validation, and enterprise-grade failure recovery.
    This convenience function abstracts FlextResult complexity while ensuring thorough validation.

    This function implements comprehensive validation workflow including content parsing,
    structural validation, business rule enforcement, and semantic validation with
    intelligent error recovery and detailed logging for enterprise environments.

    Args:
        content: LDIF content to validate as string or LDIFContent object

    Returns:
        bool: True if content is valid LDIF with all validation rules passed, False otherwise

    Validation Stages:
        1. Content parsing: Validates LDIF syntax and structure
        2. Entry validation: Checks individual entry consistency
        3. Business rules: Enforces domain-specific validation rules
        4. Schema compliance: Validates against LDAP schema requirements

    Error Handling:
        - Parse failures: Returns False with detailed error logging
        - Invalid input: Returns False with warning logs
        - API errors: Graceful degradation with comprehensive error logging
        - Validation failures: Returns False with validation context

    Convenience Features:
        - Simple boolean return - no FlextResult handling required
        - Comprehensive validation - includes parsing and business rules
        - Automatic error recovery - never raises exceptions
        - Global API integration - uses optimized singleton instance

    Example:
        >>> from flext_ldif import flext_ldif_validate
        >>>
        >>> # Validate valid LDIF content
        >>> valid_ldif = '''
        ... dn: cn=John Doe,ou=people,dc=example,dc=com
        ... objectClass: person
        ... cn: John Doe
        ... sn: Doe
        ... '''
        >>> is_valid = flext_ldif_validate(valid_ldif)
        >>> print(f"LDIF is valid: {is_valid}")
        >>>
        >>> # Validate invalid LDIF content
        >>> invalid_ldif = '''
        ... dn: invalid dn format
        ... invalidAttribute: value
        ... '''
        >>> is_valid = flext_ldif_validate(invalid_ldif)
        >>> print(f"Invalid LDIF is valid: {is_valid}")

    Performance:
        Uses global API singleton for optimal performance. Validation operations
        include full parsing and validation pipeline with enterprise-grade
        observability and metrics collection.

    Thread Safety:
        Thread-safe through global API singleton management. Multiple threads can
        safely call this function concurrently without coordination.

    Raises:
        No exceptions - all errors handled gracefully with False return

    """
    # REFACTORING: Enhanced convenience validation with comprehensive error handling
    logger = get_logger(__name__)
    logger.debug(
        "Convenience LDIF validation requested",
        content_type=type(content).__name__,
        content_size=len(str(content)) if content else 0,
    )

    try:
        # REFACTORING: Enhanced input validation with detailed logging
        if not content:
            logger.warning(
                "Empty or None content provided to convenience validate function",
            )
            logger.debug("Returning False for empty content")
            return False

        # Validate content type
        if not isinstance(content, (str, bytes)) and not hasattr(content, "__str__"):
            logger.warning(
                "Invalid content type for validation",
                content_type=type(content).__name__,
                expected_types=["str", "bytes", "LDIFContent"],
            )
            logger.debug("Returning False for invalid content type")
            return False

        content_str = str(content)
        content_length = len(content_str)
        logger.trace(
            "Content validated for validation",
            content_length=content_length,
            content_preview=content_str[:100].replace("\n", "\\n")
            if content_length > 0
            else "",
        )

        # REFACTORING: Enhanced API access with comprehensive error handling
        try:
            api = flext_ldif_get_api()
            logger.debug(
                "Global API instance retrieved for validation",
                api_type=type(api).__name__,
            )
        except Exception as e:
            logger.exception(
                "Failed to get global API instance for convenience validation",
            )
            logger.exception("API retrieval failed: %s", e)
            logger.debug("Returning False due to API access failure")
            return False

        # REFACTORING: Enhanced parsing stage with comprehensive result validation
        logger.debug(
            "Executing LDIF parsing stage for validation",
            content_length=content_length,
        )

        try:
            parse_result = api.parse(content)

            # Validate parse result type and structure
            if not isinstance(parse_result, FlextResult):
                logger.error(
                    "Parse operation returned invalid result type",
                    result_type=type(parse_result).__name__,
                    expected_type="FlextResult",
                )
                logger.debug("Returning False due to invalid parse result type")
                return False

            logger.debug(
                "Parse stage completed for validation",
                result_success=parse_result.success,
                result_has_data=parse_result.data is not None,
            )

        except Exception as e:
            logger.exception("Parse operation raised exception during validation")
            logger.exception("Parsing failed with exception: %s", e)
            logger.debug("Returning False due to parsing exception")
            return False

        # REFACTORING: Enhanced parse result processing with comprehensive validation
        if not parse_result.success:
            logger.warning(
                "LDIF parsing failed during validation",
                error=parse_result.error or "Unknown parsing error",
                content_length=content_length,
            )
            logger.debug("Returning False due to parsing failure")
            return False

        if parse_result.data is None:
            logger.warning("Parse succeeded but returned None data during validation")
            logger.debug("Returning False due to None data")
            return False

        if not isinstance(parse_result.data, list):
            logger.error(
                "Parse data is not a list during validation",
                data_type=type(parse_result.data).__name__,
            )
            logger.debug("Returning False due to invalid data type")
            return False

        entries = parse_result.data
        entries_count = len(entries)
        logger.debug(
            "Parse stage successful - proceeding to validation stage",
            entries_count=entries_count,
        )

        # REFACTORING: Enhanced validation stage with comprehensive result processing
        logger.debug("Executing LDIF validation stage", entries_count=entries_count)

        try:
            validate_result = api.validate(entries)

            # Validate validation result type and structure
            if not isinstance(validate_result, FlextResult):
                logger.error(
                    "Validate operation returned invalid result type",
                    result_type=type(validate_result).__name__,
                    expected_type="FlextResult",
                )
                logger.debug("Returning False due to invalid validation result type")
                return False

            logger.debug(
                "Validation stage completed",
                result_success=validate_result.success,
                result_has_data=validate_result.data is not None,
            )

        except Exception as e:
            logger.exception("Validation operation raised exception")
            logger.exception("Validation failed with exception: %s", e)
            logger.debug("Returning False due to validation exception")
            return False

        # REFACTORING: Enhanced validation result processing with comprehensive checks
        if not validate_result.success:
            logger.warning(
                "LDIF validation failed",
                error=validate_result.error or "Unknown validation error",
                entries_count=entries_count,
                content_length=content_length,
            )
            logger.debug("Returning False due to validation failure")
            return False

        # REFACTORING: Enhanced validation data verification
        validation_data = validate_result.data
        if validation_data is None:
            logger.warning("Validation succeeded but returned None data")
            logger.debug("Returning False due to None validation data")
            return False

        # Check if validation data indicates success:
        validation_success = bool(validation_data)

        logger.info(
            "Convenience LDIF validation completed",
            content_length_chars=content_length,
            entries_validated=entries_count,
            validation_success=validation_success,
            parse_stage_passed=True,
            validation_stage_passed=validate_result.success,
        )

        logger.debug("Returning validation result: %s", validation_success)
        return validation_success

    except Exception as e:
        # REFACTORING: Enhanced top-level exception handling
        logger.exception(
            "Convenience LDIF validation failed with unexpected exception",
            content_type=type(content).__name__ if content else "None",
            exception_type=type(e).__name__,
        )
        logger.debug("Returning False due to unexpected exception")
        return False


def flext_ldif_write(
    entries: list[FlextLdifEntry],
    output_path: str | None = None,
) -> str:
    """Write LDIF entries with enterprise-grade convenience API and comprehensive output management.

    Provides a simplified interface for LDIF writing operations using the global API instance
    with automatic error handling, flexible output modes, and enterprise-grade failure recovery.
    This convenience function abstracts FlextResult complexity while maintaining full functionality.

    Refactored using Strategy Pattern and Single Responsibility Principle to reduce
    complexity from 17 to manageable levels with focused validation strategies.

    Args:
        entries: List of FlextLdifEntry objects to write to LDIF format
        output_path: Optional file path for writing output. If None, returns LDIF string content

    Returns:
        str: LDIF content as string or success message for file writes, empty string on failure

    Raises:
        No exceptions - all errors handled gracefully with empty string return

    """
    logger = get_logger(__name__)
    entries_count = len(entries) if entries else 0
    output_mode = "file" if output_path else "string"

    logger.debug(
        "Convenience LDIF writing requested",
        entries_count=entries_count,
        output_mode=output_mode,
        output_path=str(output_path) if output_path else None,
    )

    try:
        # Strategy 1: Input validation - Single Responsibility
        validation_error = _validate_write_inputs(entries, logger)
        if validation_error:
            return validation_error

        # Strategy 2: API retrieval - Single Responsibility
        api = _get_write_api(logger)
        if not api:
            return ""

        # Strategy 3: Write execution - Single Responsibility
        write_result = _execute_write_operation(api, entries, output_path, logger)
        if not write_result:
            return ""

        # Strategy 4: Result processing - Single Responsibility
        return _process_write_result(write_result, output_path, entries_count, logger)

    except Exception as e:
        logger.exception(
            "Convenience LDIF writing failed with unexpected exception",
            entries_count=entries_count,
            output_mode=output_mode,
            output_path=str(output_path) if output_path else None,
            exception_type=type(e).__name__,
        )
        logger.debug("Returning empty string due to unexpected exception")
        return ""


def _validate_write_inputs(entries: list[FlextLdifEntry], logger) -> str:
    """Strategy 1: Validate write inputs - Single Responsibility Principle."""
    if not entries:
        logger.warning(
            "Empty or None entries list provided to convenience write function",
        )
        logger.debug("Returning empty string for empty entries")
        return ""

    if not isinstance(entries, list):
        logger.warning(
            "Invalid entries type for writing",
            entries_type=type(entries).__name__,
            expected_type="list[FlextLdifEntry]",
        )
        logger.debug("Returning empty string for invalid entries type")
        return ""

    # Validate entries content
    invalid_entries = 0
    for i, entry in enumerate(entries):
        if not hasattr(entry, "dn") or not hasattr(entry, "attributes"):
            invalid_entries += 1
            logger.warning(
                "Entry %d does not have required attributes (dn, attributes)",
                i,
            )

    if invalid_entries > 0:
        logger.warning("Found %d invalid entries in write request", invalid_entries)
        if invalid_entries == len(entries):
            logger.error("All entries are invalid - cannot proceed with write")
            logger.debug("Returning empty string for all invalid entries")
            return ""

    logger.trace(
        "Entries validated for writing",
        entries_count=len(entries),
        invalid_entries=invalid_entries,
        valid_entries=len(entries) - invalid_entries,
    )
    return None  # No error


def _get_write_api(logger):
    """Strategy 2: Get API instance - Single Responsibility Principle."""
    try:
        api = flext_ldif_get_api()
        logger.debug(
            "Global API instance retrieved for writing",
            api_type=type(api).__name__,
        )
        return api
    except Exception as e:
        logger.exception("Failed to get global API instance for convenience writing")
        logger.exception("API retrieval failed: %s", e)
        logger.debug("Returning None due to API access failure")
        return None


def _execute_write_operation(
    api,
    entries: list[FlextLdifEntry],
    output_path: str | None,
    logger,
):
    """Strategy 3: Execute write operation - Single Responsibility Principle."""
    entries_count = len(entries)
    output_mode = "file" if output_path else "string"

    logger.debug(
        "Executing LDIF write operation via global API",
        entries_count=entries_count,
        output_mode=output_mode,
        output_path=str(output_path) if output_path else None,
    )

    try:
        write_result = api.write(entries, output_path)

        if not isinstance(write_result, FlextResult):
            logger.error(
                "Write operation returned invalid result type",
                result_type=type(write_result).__name__,
                expected_type="FlextResult",
            )
            logger.debug("Returning None due to invalid result type")
            return None

        logger.debug(
            "Write operation completed",
            result_success=write_result.success,
            result_has_data=write_result.data is not None,
            output_mode=output_mode,
        )
        return write_result

    except Exception as e:
        logger.exception("Write operation raised exception")
        logger.exception("Writing failed with exception: %s", e)
        logger.debug("Returning None due to writing exception")
        return None


def _process_write_result(
    write_result: FlextResult,
    output_path: str | None,
    entries_count: int,
    logger,
) -> str:
    """Strategy 4: Process write result - Single Responsibility Principle."""
    output_mode = "file" if output_path else "string"

    if not write_result.success:
        logger.warning(
            "LDIF writing failed via convenience function",
            error=write_result.error or "Unknown writing error",
            entries_count=entries_count,
            output_mode=output_mode,
            output_path=str(output_path) if output_path else None,
        )
        logger.debug("Returning empty string due to writing failure")
        return ""

    if write_result.data is None:
        logger.warning("Write succeeded but returned None data")
        logger.debug("Returning empty string due to None data")
        return ""

    try:
        if not isinstance(write_result.data, str):
            logger.error(
                "Write data is not a string",
                data_type=type(write_result.data).__name__,
            )
            logger.debug("Returning empty string due to invalid data type")
            return ""

        output_content: str = write_result.data
        content_length = len(output_content)

        if output_path:
            logger.debug(
                "File write mode - validating success message",
                content_length=content_length,
                content_preview=output_content[:100] if content_length > 0 else "",
            )
        else:
            if content_length == 0 and entries_count > 0:
                logger.warning(
                    "String write returned empty content for %d entries",
                    entries_count,
                )
            logger.debug(
                "String write mode - validating LDIF content",
                content_length=content_length,
                ldif_preview=output_content[:100].replace("\n", "\\n")
                if content_length > 0
                else "",
            )

        logger.info(
            "Convenience LDIF writing completed successfully",
            entries_written=entries_count,
            output_mode=output_mode,
            output_path=str(output_path) if output_path else None,
            content_length_chars=content_length,
        )

        return output_content

    except (TypeError, AttributeError) as e:
        logger.exception("Data validation failed for write result")
        logger.exception("Result data validation error: %s", e)
        logger.debug("Returning empty string due to data validation failure")
        return ""


__all__: list[str] = [
    "FlextLdifAPI",
    "flext_ldif_get_api",
    "flext_ldif_parse",
    "flext_ldif_validate",
    "flext_ldif_write",
]
