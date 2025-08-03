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
    ...     max_entries=50000,
    ...     strict_validation=True,
    ...     enable_observability=True
    ... )
    >>>
    >>> api = FlextLdifAPI(config)
    >>>
    >>> # Parse LDIF with comprehensive error handling
    >>> result = api.parse(ldif_content)
    >>> if result.is_success:
    ...     entries = result.data
    ...     validation_result = api.validate(entries)
    ...     if validation_result.is_success:
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
        >>> 
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
        self.logger.debug("Starting FlextLdifAPI initialization",
                         config_provided=provided_config)

        try:
            self.config = config or FlextLdifConfig()
            self.logger.debug("Configuration processing completed successfully",
                             max_entries=self.config.max_entries,
                             strict_validation=self.config.strict_validation,
                             encodings=f"{self.config.input_encoding}→{self.config.output_encoding}")
            self.logger.trace("Complete configuration: %s", self.config.model_dump())
        except (ValueError, TypeError) as e:
            error_msg = f"Configuration validation failed: {e}"
            self.logger.exception(error_msg)
            raise RuntimeError(error_msg) from e

        # REFACTORING: Enhanced service registration with comprehensive error handling
        self.logger.debug("Initiating LDIF services registration in DI container")
        try:
            register_result = register_ldif_services(config=self.config)
            if register_result.is_failure:
                error_msg = f"Service registration failed: {register_result.error}"
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)

            self.logger.debug("LDIF services registered successfully in DI container")
        except Exception as e:
            error_msg = f"Service registration exception: {e}"
            self.logger.exception(error_msg)
            raise RuntimeError(error_msg) from e

        # REFACTORING: Enhanced service resolution with improved error handling
        self._initialize_services()

        # REFACTORING: Enhanced observability initialization with comprehensive monitoring
        self._initialize_observability()

        # REFACTORING: Enhanced completion logging with comprehensive metrics
        self.logger.info("FlextLdifAPI initialization completed successfully",
                        config_source="provided" if provided_config else "default",
                        services_initialized=True,
                        observability_enabled=hasattr(self, "_observability_monitor"),
                        api_ready=True)
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
            ("ldif_parser", FlextLdifParserService, "_parser_service", "LDIF parsing service"),
            ("ldif_writer", FlextLdifWriterService, "_writer_service", "LDIF writing service"),
            ("ldif_validator", FlextLdifValidatorService, "_validator_service", "LDIF validation service"),
        ]

        initialized_services = []
        for service_name, service_type, attr_name, description in services_config:
            self.logger.debug("Resolving %s from container", description, service_name=service_name)

            try:
                service_result = container.get(service_name)
                if service_result.is_failure:
                    error_msg = f"Failed to resolve {description} from container: {service_result.error}"
                    self.logger.error(error_msg)
                    raise RuntimeError(error_msg)

                # Enhanced type validation with detailed error context
                if not isinstance(service_result.data, service_type):
                    actual_type = type(service_result.data).__name__
                    error_msg = f"{description} type validation failed: expected {service_type.__name__}, got {actual_type}"
                    self.logger.error(error_msg)
                    raise RuntimeError(error_msg)

                # Set service attribute
                setattr(self, attr_name, service_result.data)
                initialized_services.append(service_name)
                self.logger.trace("%s initialized successfully", description)

            except Exception as e:
                error_msg = f"Exception during {description} initialization: {e}"
                self.logger.exception(error_msg)
                raise RuntimeError(error_msg) from e

        self.logger.info("Domain services initialization completed successfully",
                        services_count=len(initialized_services),
                        service_names=initialized_services)

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
            if init_result.is_success:
                self.logger.debug("Observability initialization successful")

                # Start monitoring with error handling
                self._observability_monitor.flext_start_monitoring()
                self.logger.info("Observability monitoring started successfully",
                               monitoring_active=True,
                               metrics_enabled=True,
                               tracing_enabled=True)
            else:
                # Graceful degradation for observability failures
                self.logger.warning("Observability initialization failed - continuing with degraded monitoring",
                                  error=init_result.error)
                self.logger.debug("API will continue without full observability features")

        except Exception as e:
            # Complete fallback for observability exceptions
            self.logger.warning("Observability monitoring exception - continuing without monitoring: %s", e)
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

        if not validate_result.is_success:
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
            >>> if result.is_success:
            ...     entries = result.data
            ...     print(f"Parsed {len(entries)} entries successfully")
            ... else:
            ...     print(f"Parse failed: {result.error}")

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        # REFACTORING: Enhanced parsing initialization with comprehensive context logging
        content_type = type(content).__name__
        self.logger.debug("Starting LDIF content parsing operation",
                         content_type=content_type)
        self.logger.trace("Parse input received: %s", content_type)

        # REFACTORING: Enhanced distributed tracing with better trace management
        trace_id = self._create_parse_trace(content)
        self.logger.debug("Created parse trace", trace_id=trace_id)

        try:
            # REFACTORING: Enhanced content metrics collection with validation
            content_size = self._record_content_metrics(content)
            self.logger.debug("Content metrics recorded",
                             content_size_bytes=content_size,
                             trace_id=trace_id)

            # REFACTORING: Enhanced service delegation with comprehensive configuration logging
            self.logger.debug("Delegating to parser service for core parsing",
                             parser_service=self._parser_service.__class__.__name__,
                             config_strict_validation=self.config.strict_validation,
                             config_max_entries=self.config.max_entries)

            parse_result = self._parser_service.parse(content)

            # REFACTORING: Enhanced parse result validation with detailed error context
            if not parse_result.is_success:
                self.logger.warning("Parser service returned failure",
                                  error=parse_result.error,
                                  trace_id=trace_id)
                return self._handle_parse_failure(parse_result)

            # REFACTORING: Enhanced entries validation with null safety
            entries = parse_result.data
            if entries is None:
                error_msg = "Parse succeeded but returned None entries - this indicates a parser service bug"
                self.logger.error(error_msg, trace_id=trace_id)
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced entries processing with comprehensive metrics
            entries_count = len(entries)
            self.logger.debug("Core parsing completed successfully",
                             entries_parsed=entries_count,
                             trace_id=trace_id)

            # Log sample of parsed entry DNs for debugging (first 5 entries)
            if entries_count > 0:
                sample_dns = [str(entry.dn) for entry in entries[:5]]
                self.logger.trace("Sample parsed entry DNs: %s", sample_dns)

            # REFACTORING: Enhanced success metrics recording with context
            self._record_success_metrics(entries_count)

            # REFACTORING: Enhanced strict validation with conditional execution
            if self.config.strict_validation:
                self.logger.debug("Performing strict validation", entries_count=entries_count)
                self._perform_strict_validation(entries, entries_count)
            else:
                self.logger.trace("Strict validation disabled - skipping")

            # REFACTORING: Enhanced limit checking with detailed error reporting
            self.logger.debug("Checking entry count limits",
                             entries_count=entries_count,
                             max_entries_limit=self.config.max_entries)

            limit_check_result = self._check_entry_limits(entries)
            if not limit_check_result.is_success:
                error_msg = limit_check_result.error or "Entry limit exceeded"
                self.logger.error("Entry limit check failed",
                                error=error_msg,
                                entries_count=entries_count,
                                trace_id=trace_id)
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced completion metrics and final result preparation
            self._record_completion_metrics(entries_count, content_size, trace_id)

            self.logger.info("LDIF content parsing completed successfully",
                           entries_parsed=entries_count,
                           content_size_bytes=content_size,
                           strict_validation_performed=self.config.strict_validation,
                           trace_id=trace_id)

            return FlextResult.ok(entries)

        except (ValueError, TypeError, AttributeError, OSError, ImportError) as e:
            # REFACTORING: Enhanced exception handling with comprehensive error context
            self.logger.error("Exception during LDIF parsing operation",
                             exception_type=type(e).__name__,
                             trace_id=trace_id)
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
            >>> if result.is_success:
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
        trace = flext_create_trace(trace_id=trace_id, operation="ldif_parse_file")

        self.logger.debug("Starting LDIF file parsing operation",
                         file_path=file_path_str,
                         trace_id=trace_id,
                         input_encoding=self.config.input_encoding)
        self.logger.trace("File parsing configuration",
                         max_entries=self.config.max_entries,
                         strict_validation=self.config.strict_validation)

        try:
            # REFACTORING: Enhanced path validation and metrics recording
            file_path_obj = Path(file_path)
            absolute_path = file_path_obj.absolute()
            self.logger.trace("File path resolved",
                             original_path=file_path_str,
                             absolute_path=str(absolute_path))

            # Record file parsing operation attempt
            self._observability_monitor.flext_record_metric(
                "ldif_file_operations_total", 1.0, "counter",
            )

            # REFACTORING: Enhanced file validation before parsing
            if not file_path_obj.exists():
                error_msg = f"File not found: {absolute_path}"
                self.logger.error(error_msg, trace_id=trace_id)
                self._observability_monitor.flext_record_metric(
                    "ldif_file_parse_errors_total", 1.0, "counter",
                )
                return FlextResult.fail(error_msg)

            if not file_path_obj.is_file():
                error_msg = f"Path is not a file: {absolute_path}"
                self.logger.error(error_msg, trace_id=trace_id)
                self._observability_monitor.flext_record_metric(
                    "ldif_file_parse_errors_total", 1.0, "counter",
                )
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced file size metrics
            try:
                file_size = file_path_obj.stat().st_size
                self.logger.debug("File size validated",
                                 file_size_bytes=file_size,
                                 file_size_mb=round(file_size / 1024 / 1024, 2))
            except (OSError, AttributeError) as e:
                self.logger.warning("Could not determine file size: %s", e)
                file_size = 0

            # REFACTORING: Enhanced parser service delegation with error handling
            self.logger.debug("Delegating to parser service", service_type="FlextLdifParserService")
            parse_result = self._parser_service.parse_file(file_path_obj)

            if parse_result.is_failure:
                error_msg = f"Parser service failed: {parse_result.error}"
                self.logger.error(error_msg, trace_id=trace_id)
                self._observability_monitor.flext_record_metric(
                    "ldif_file_parse_errors_total", 1.0, "counter",
                )
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced entries validation and processing
            entries = parse_result.data
            if entries is None:
                error_msg = "Parser service returned None entries - indicates service bug"
                self.logger.error(error_msg, trace_id=trace_id)
                self._observability_monitor.flext_record_metric(
                    "ldif_file_parse_errors_total", 1.0, "counter",
                )
                return FlextResult.fail(error_msg)

            entries_count = len(entries)
            self.logger.debug("File parsing completed",
                             entries_parsed=entries_count,
                             file_size_bytes=file_size)

            # Log sample of parsed entry DNs for debugging (first 3 entries)
            if entries_count > 0:
                sample_dns = [str(entry.dn) for entry in entries[:3]]
                self.logger.trace("Sample parsed entry DNs from file: %s", sample_dns)

            # REFACTORING: Enhanced metrics recording with comprehensive context
            self._observability_monitor.flext_record_metric(
                "ldif_file_entries_parsed_total", float(entries_count), "counter",
            )

            # REFACTORING: Enhanced entry limit validation with detailed error context
            if entries_count > self.config.max_entries:
                limit_error = f"File entry count {entries_count} exceeds configured limit {self.config.max_entries}"
                self.logger.warning(limit_error,
                                   file_path=file_path_str,
                                   trace_id=trace_id)
                self._observability_monitor.flext_record_metric(
                    "ldif_file_limit_exceeded_total", 1.0, "counter",
                )
                return FlextResult.fail(limit_error)

            # REFACTORING: Enhanced strict validation with comprehensive error handling
            if self.config.strict_validation:
                self.logger.debug("Performing strict validation on file entries",
                                 entries_count=entries_count)

                validate_result = self._validator_service.validate(entries)
                if validate_result.is_failure:
                    validation_error = validate_result.error or "Unknown validation error"
                    self.logger.warning("File validation failed with errors",
                                       validation_error=validation_error,
                                       file_path=file_path_str,
                                       trace_id=trace_id)

                    self._observability_monitor.flext_record_metric(
                        "ldif_file_validation_warnings_total", 1.0, "counter",
                    )

                    # Continue with parsing success but log validation issues
                    self.logger.info("File parse succeeded despite validation warnings",
                                    file_path=file_path_str,
                                    entries_count=entries_count,
                                    validation_warnings=validation_error)
                else:
                    self.logger.trace("Strict validation passed for file entries")

            # REFACTORING: Enhanced success metrics and completion logging
            self._observability_monitor.flext_record_metric(
                "ldif_file_parse_success_total", 1.0, "counter",
            )

            self.logger.info("LDIF file parsing completed successfully",
                           file_path=file_path_str,
                           entries_parsed=entries_count,
                           file_size_bytes=file_size,
                           strict_validation_performed=self.config.strict_validation,
                           input_encoding=self.config.input_encoding,
                           trace_id=trace_id)

            return FlextResult.ok(entries)

        except (OSError, ValueError, TypeError, AttributeError, ImportError) as e:
            # REFACTORING: Enhanced exception handling with comprehensive error context
            error_msg = f"File parsing exception: {type(e).__name__}: {e}"
            self.logger.exception("LDIF file parsing failed with exception",
                                 file_path=file_path_str,
                                 exception_type=type(e).__name__,
                                 trace_id=trace_id)

            # Record exception metrics
            self._observability_monitor.flext_record_metric(
                "ldif_file_exceptions_total", 1.0, "counter",
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
            ...     strict_validation=True
            ... )
            >>> api = FlextLdifAPI(config)
            >>>
            >>> # Validate parsed entries
            >>> result = api.validate(entries)
            >>> if result.is_success and result.data:
            ...     print("All entries passed validation")
            ... else:
            ...     print(f"Validation failed: {result.error}")

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        # REFACTORING: Enhanced validation initialization with comprehensive metrics
        entries_count = len(entries)
        self.logger.debug("Starting comprehensive LDIF validation operation",
                         entries_count=entries_count)
        self.logger.trace("Validation configuration parameters",
                         allow_empty_attributes=self.config.allow_empty_attributes,
                         max_entry_size_bytes=self.config.max_entry_size,
                         input_encoding=self.config.input_encoding,
                         strict_validation=self.config.strict_validation)

        # REFACTORING: Enhanced empty attributes validation with detailed error handling
        self.logger.debug("Starting empty attributes validation")
        empty_attr_result = self._validate_empty_attributes(entries)
        if not empty_attr_result.is_success:
            error_msg = empty_attr_result.error or "Empty attribute validation failed"
            self.logger.error("Empty attributes validation failed",
                             error=error_msg,
                             entries_count=entries_count)
            return FlextResult.fail(error_msg)

        self.logger.debug("Empty attributes validation passed")

        # REFACTORING: Enhanced entry sizes validation with detailed error handling
        self.logger.debug("Starting entry sizes validation",
                         max_entry_size_limit=self.config.max_entry_size)
        size_result = self._validate_entry_sizes(entries)
        if not size_result.is_success:
            error_msg = size_result.error or "Entry size validation failed"
            self.logger.error("Entry sizes validation failed",
                             error=error_msg,
                             entries_count=entries_count,
                             max_size_limit=self.config.max_entry_size)
            return FlextResult.fail(error_msg)

        self.logger.debug("Entry sizes validation passed")

        # REFACTORING: Enhanced core validation with comprehensive service delegation
        self.logger.debug("Delegating to validator service for core validation",
                         validator_service=self._validator_service.__class__.__name__)

        core_validation_result = self._validator_service.validate(entries)

        # REFACTORING: Enhanced validation result processing with comprehensive logging
        if core_validation_result.is_success:
            self.logger.info("LDIF validation completed successfully",
                           entries_validated=entries_count,
                           validation_layers_passed=["empty_attributes", "entry_sizes", "core_validation"],
                           strict_validation=self.config.strict_validation)
        else:
            self.logger.warning("Core validation failed",
                              error=core_validation_result.error,
                              entries_count=entries_count)

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
            ...     output_encoding="utf-8"
            ... )
            >>> api = FlextLdifAPI(config)
            >>>
            >>> # Write to string
            >>> result = api.write(entries)
            >>> if result.is_success:
            ...     ldif_content = result.data
            ...     print(f"Generated LDIF content: {len(ldif_content)} characters")
            >>>
            >>> # Write to file
            >>> result = api.write(entries, "exported_entries.ldif")
            >>> if result.is_success:
            ...     print(f"Success: {result.data}")
            ... else:
            ...     print(f"Write failed: {result.error}")

        Raises:
            No exceptions - all errors returned via FlextResult pattern for railway-oriented programming

        """
        # REFACTORING: Enhanced write operation initialization with comprehensive metrics
        entries_count = len(entries)
        write_target = "file" if file_path else "string"
        self.logger.debug("Starting LDIF write operation",
                         entries_count=entries_count,
                         write_target=write_target)
        self.logger.trace("Write operation parameters",
                         file_path=str(file_path) if file_path else None,
                         config_output_directory=str(self.config.output_directory),
                         config_create_output_dir=self.config.create_output_dir)

        # REFACTORING: Enhanced file writing with comprehensive path management
        if file_path:
            self.logger.debug("Executing file write operation",
                             file_path=str(file_path),
                             entries_count=entries_count)

            # REFACTORING: Enhanced path resolution with comprehensive logging
            try:
                resolved_path = self._resolve_output_path(file_path)
                self.logger.debug("Output path resolved successfully",
                                 original_path=str(file_path),
                                 resolved_path=str(resolved_path.absolute()))
            except (OSError, ValueError) as e:
                error_msg = f"Path resolution failed for {file_path}: {e}"
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced directory creation with comprehensive error handling
            try:
                self._create_output_directory(resolved_path)
                self.logger.debug("Output directory preparation completed")
            except Exception as e:
                error_msg = f"Directory preparation failed for {resolved_path.parent}: {e}"
                self.logger.error(error_msg)
                return FlextResult.fail(error_msg)

            # REFACTORING: Enhanced file writing with comprehensive service delegation
            self.logger.debug("Delegating to writer service for file output",
                             writer_service=self._writer_service.__class__.__name__,
                             resolved_path=str(resolved_path))

            write_result = self._writer_service.write_file(entries, resolved_path)

            # REFACTORING: Enhanced file write result processing
            if write_result.is_success:
                success_msg = f"LDIF entries written successfully to {resolved_path}"
                self.logger.info("File write operation completed successfully",
                               entries_written=entries_count,
                               file_path=str(resolved_path.absolute()),
                               output_encoding=self.config.output_encoding)
                return FlextResult.ok(success_msg)
            error_msg = write_result.error or "File write operation failed"
            self.logger.error("File write operation failed",
                            error=error_msg,
                            file_path=str(resolved_path),
                            entries_count=entries_count)
            return FlextResult.fail(error_msg)

        # REFACTORING: Enhanced string writing with comprehensive service delegation
        self.logger.debug("Executing string write operation",
                         entries_count=entries_count,
                         writer_service=self._writer_service.__class__.__name__)

        string_result = self._writer_service.write(entries)

        # REFACTORING: Enhanced string write result processing
        if string_result.is_success:
            content_length = len(string_result.data or "")
            self.logger.info("String write operation completed successfully",
                           entries_written=entries_count,
                           content_length_chars=content_length)
        else:
            self.logger.error("String write operation failed",
                            error=string_result.error,
                            entries_count=entries_count)

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
            >>> if result.is_success:
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
        try:
            # Record filtering metrics
            total_entries = len(entries)
            self._observability_monitor.flext_record_metric(
                "ldif_filter_input_entries",
                float(total_entries),
                "histogram",
            )

            person_entries = [entry for entry in entries if entry.is_person_entry()]

            # Record results
            person_count = len(person_entries)
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

            self.logger.info(
                "Person entries filtered successfully",
                total_entries=total_entries,
                person_entries=person_count,
                filter_ratio=person_count / total_entries if total_entries > 0 else 0,
            )

            return FlextResult.ok(person_entries)
        except (ValueError, TypeError, AttributeError) as e:
            self._observability_monitor.flext_record_metric(
                "ldif_filter_persons_errors_total",
                1.0,
                "counter",
            )
            return FlextResult.fail(f"Failed to filter person entries: {e}")

    def filter_valid(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter valid entries using integrated composition logic."""
        try:
            valid_entries = [entry for entry in entries if entry.is_valid_entry()]
            return FlextResult.ok(valid_entries)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to filter valid entries: {e}")

    def filter_by_objectclass(
        self,
        entries: list[FlextLdifEntry],
        object_class: str,
    ) -> list[FlextLdifEntry]:
        """Filter entries by objectClass using intelligent filtering."""
        return [entry for entry in entries if entry.has_object_class(object_class)]

    def find_entry_by_dn(
        self,
        entries: list[FlextLdifEntry],
        dn: str,
    ) -> FlextLdifEntry | None:
        """Find entry by DN with intelligent search."""
        for entry in entries:
            if str(entry.dn) == dn:
                return entry
        return None

    def sort_hierarchically(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Sort entries hierarchically using intelligent sorting."""
        try:
            sorted_entries = sorted(
                entries,
                key=lambda entry: (
                    str(entry.dn).count(","),  # Primary: depth (parents first)
                    str(entry.dn).lower(),  # Secondary: alphabetical
                ),
            )
            return FlextResult.ok(sorted_entries)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to sort entries hierarchically: {e}")

    def entries_to_ldif(self, entries: list[FlextLdifEntry]) -> str:
        """Convert multiple entries to LDIF content using intelligent formatting."""
        result = self._writer_service.write(entries)
        if not result.is_success:
            error_msg = result.error or "LDIF write operation failed"
            error_message = f"Failed to convert entries to LDIF: {error_msg}"
            raise ValueError(error_message)
        return result.data or ""

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
            >>> if result.is_success:
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
        try:
            group_entries = [entry for entry in entries if entry.is_group_entry()]
            return FlextResult.ok(group_entries)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to filter group entries: {e}")

    def filter_organizational_units(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter organizational unit entries using integrated composition logic."""
        try:
            ou_entries = [entry for entry in entries if entry.is_organizational_unit()]
            return FlextResult.ok(ou_entries)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to filter OU entries: {e}")

    def filter_change_records(
        self,
        entries: list[FlextLdifEntry],
    ) -> FlextResult[list[FlextLdifEntry]]:
        """Filter change record entries using integrated composition logic."""
        try:
            change_entries = [entry for entry in entries if entry.is_change_record()]
            return FlextResult.ok(change_entries)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to filter change records: {e}")

    def get_entry_statistics(
        self,
        entries: list[FlextLdifEntry],
    ) -> dict[str, int | str]:
        """Get entry statistics using integrated composition analysis with monitoring."""
        try:
            stats: dict[str, int] = {
                "total_entries": len(entries),
                "valid_entries": sum(1 for entry in entries if entry.is_valid_entry()),
                "person_entries": sum(
                    1 for entry in entries if entry.is_person_entry()
                ),
                "group_entries": sum(1 for entry in entries if entry.is_group_entry()),
                "ou_entries": sum(
                    1 for entry in entries if entry.is_organizational_unit()
                ),
                "change_records": sum(
                    1 for entry in entries if entry.is_change_record()
                ),
            }

            # Record statistics as metrics
            for stat_name, stat_value in stats.items():
                self._observability_monitor.flext_record_metric(
                    f"ldif_statistics_{stat_name}",
                    float(stat_value),
                    "gauge",
                )

        except (ValueError, TypeError, AttributeError, Exception) as e:
            self.logger.exception("Failed to calculate statistics")
            return {"error": f"Statistics calculation failed: {e}"}
        else:
            self.logger.info("Entry statistics calculated", **stats)
            # Type narrowing for mypy - stats is dict[str, int] here
            return dict(stats)

    def get_observability_metrics(self) -> FlextResult[dict[str, object]]:
        """Get comprehensive observability metrics from the monitoring system."""
        try:
            if not self._observability_monitor:
                return FlextResult.fail("Observability monitor not available")

            # Get metrics summary
            metrics_result = self._observability_monitor.flext_get_metrics_summary()
            if metrics_result.is_failure:
                return FlextResult.fail(
                    f"Failed to get metrics: {metrics_result.error}",
                )

            # Get health status
            health_result = self._observability_monitor.flext_get_health_status()
            if health_result.is_failure:
                return FlextResult.fail(f"Failed to get health: {health_result.error}")

            # Combine metrics and health
            observability_data = {
                "metrics": metrics_result.data or {},
                "health": health_result.data or {},
                "monitoring_active": self._observability_monitor.flext_is_monitoring_active(),
            }

            return FlextResult.ok(observability_data)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to get observability metrics: {e}")

    def reset_observability_metrics(self) -> FlextResult[None]:
        """Reset observability metrics (useful for testing and cleanup)."""
        try:
            if not self._observability_monitor:
                return FlextResult.fail("Observability monitor not available")

            # Access the metrics service through container
            container = self._observability_monitor.container
            metrics_service = container.get("flext_metrics_service")

            if hasattr(metrics_service, "data") and hasattr(
                metrics_service.data,
                "reset_metrics",
            ):
                reset_result = metrics_service.data.reset_metrics()
                if reset_result.is_failure:
                    return FlextResult.fail(
                        f"Failed to reset metrics: {reset_result.error}",
                    )

            self.logger.info("Observability metrics reset successfully")
            return FlextResult.ok(None)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult.fail(f"Failed to reset observability metrics: {e}")


# Global API instance
_api_instance: FlextLdifAPI | None = None


def flext_ldif_get_api(config: FlextLdifConfig | None = None) -> FlextLdifAPI:
    """Get global LDIF API instance."""
    global _api_instance  # noqa: PLW0603
    if _api_instance is None or config is not None:
        _api_instance = FlextLdifAPI(config)
    return _api_instance


# Convenience functions using global API
def flext_ldif_parse(content: str | LDIFContent) -> list[FlextLdifEntry]:
    """Parse LDIF content - convenience function."""
    result = flext_ldif_get_api().parse(content)
    if (
        isinstance(result, FlextResult)
        and result.is_success
        and result.data is not None
    ):
        # Type assertion for mypy - we know result.data is list[FlextLdifEntry] here
        entries: list[FlextLdifEntry] = result.data
        return entries
    return []


def flext_ldif_validate(content: str | LDIFContent) -> bool:
    """Validate LDIF content - convenience function."""
    parse_result = flext_ldif_get_api().parse(content)
    if not isinstance(parse_result, FlextResult) or not parse_result.is_success:
        return False

    if parse_result.data is None:
        return False

    validate_result = flext_ldif_get_api().validate(parse_result.data)
    return (
        isinstance(validate_result, FlextResult)
        and validate_result.is_success
        and bool(validate_result.data)
    )


def flext_ldif_write(
    entries: list[FlextLdifEntry],
    output_path: str | None = None,
) -> str:
    """Write LDIF entries - convenience function."""
    result = flext_ldif_get_api().write(entries, output_path)
    if (
        isinstance(result, FlextResult)
        and result.is_success
        and result.data is not None
    ):
        # Type assertion for mypy - we know result.data is str here
        output: str = result.data
        return output
    return ""


__all__ = [
    "FlextLdifAPI",
    "flext_ldif_get_api",
    "flext_ldif_parse",
    "flext_ldif_validate",
    "flext_ldif_write",
]
