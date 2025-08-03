"""FLEXT-LDIF Domain Services and Infrastructure Integration.

This module implements domain services for LDIF processing operations with
comprehensive dependency injection integration, protocol-based abstractions,
and enterprise-grade service implementations following Clean Architecture patterns.

The service layer provides the primary implementation of LDIF processing
operations while maintaining clean separation between domain logic and
infrastructure concerns through protocol-based interfaces and dependency injection.

Key Components:
    - Service Protocols: Abstract interfaces for parsing, validation, and writing
    - Service Implementations: Concrete implementations with business logic
    - Dependency Injection: Container-based service resolution and lifecycle management
    - Factory Functions: Simplified service creation and configuration

Architecture:
    Part of Infrastructure Layer in Clean Architecture, this module implements
    domain service interfaces while coordinating with technical infrastructure
    concerns and providing concrete implementations for application layer consumption.

Service Types:
    - FlextLdifParserService: LDIF parsing with validation and error handling
    - FlextLdifValidatorService: Business rule validation and compliance checking
    - FlextLdifWriterService: LDIF generation with formatting and optimization
    - Service registration: Dependency injection container integration

Example:
    Service usage with dependency injection and error handling:

    >>> from flext_core import get_flext_container
    >>> from flext_ldif.services import register_ldif_services, FlextLdifParserService
    >>>
    >>> # Register services in DI container
    >>> container = get_flext_container()
    >>> register_ldif_services(container)
    >>>
    >>> # Resolve services from container
    >>> parser = container.get(FlextLdifParserService)
    >>>
    >>> # Use service with proper error handling
    >>> result = parser.parse(ldif_content)
    >>> if result.is_success:
    ...     entries = result.data
    ...     print(f"Parsed {len(entries)} entries successfully")
    ... else:
    ...     print(f"Parse failed: {result.error}")

Integration:
    - Built on flext-core dependency injection container patterns
    - Implements protocol-based abstractions for testability and flexibility
    - Coordinates with domain entities and value objects for business logic
    - Provides observability integration with structured logging and metrics

Author: FLEXT Development Team
Version: 0.9.0
License: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from flext_core import (
    FlextContainer,
    FlextResult,
    get_flext_container,
    get_logger,
)

from .config import FlextLdifConfig
from .core import TLdif

if TYPE_CHECKING:
    from .models import LDIFContent

# Runtime import needed for service implementations
from .models import FlextLdifEntry  # noqa: TC001

logger = get_logger(__name__)


# =============================================================================
# DOMAIN SERVICE PROTOCOLS - Interface definitions
# =============================================================================


class IFlextLdifParser(Protocol):
    """Protocol for LDIF parsing service."""

    def parse(self, content: str | LDIFContent) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content."""
        ...

    def parse_file(self, file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF file."""
        ...


class IFlextLdifWriter(Protocol):
    """Protocol for LDIF writing service."""

    def write(self, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write entries to LDIF string."""
        ...

    def write_file(
        self,
        entries: list[FlextLdifEntry],
        file_path: str | Path,
    ) -> FlextResult[bool]:
        """Write entries to LDIF file."""
        ...


class IFlextLdifValidator(Protocol):
    """Protocol for LDIF validation service."""

    def validate(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate LDIF entries."""
        ...

    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate single LDIF entry."""
        ...


# =============================================================================
# DOMAIN SERVICE IMPLEMENTATIONS
# =============================================================================


class FlextLdifParserService:
    """Enterprise-grade domain service for LDIF parsing operations with configuration-driven processing.

    This service provides comprehensive LDIF parsing capabilities with configuration-based
    constraints, enterprise logging integration, and robust error handling. Implements
    Clean Architecture patterns with clear separation between domain logic and infrastructure concerns.

    The service orchestrates LDIF parsing operations while applying business rules, configuration
    constraints, and comprehensive error handling with detailed logging for enterprise environments.

    Example:
        >>> from flext_ldif.services import FlextLdifParserService
        >>> from flext_ldif.config import FlextLdifConfig
        >>> 
        >>> config = FlextLdifConfig(max_entries=1000)
        >>> parser = FlextLdifParserService(config)
        >>> result = parser.parse(ldif_content)
        >>> if result.is_success:
        ...     print(f"Parsed {len(result.data)} entries")

    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize parser service with enterprise configuration management.
        
        Args:
            config: Optional configuration object with parsing constraints and settings
            
        """
        # REFACTORING: Enhanced configuration initialization with validation
        self.config = config or FlextLdifConfig()
        logger.debug("FlextLdifParserService initialized",
                    max_entries=self.config.max_entries,
                    input_encoding=self.config.input_encoding)
        logger.trace("Parser service configuration: %s", self.config.model_dump())

    def parse(self, content: str | LDIFContent) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content with enterprise-grade configuration constraints and comprehensive error handling.

        Performs comprehensive LDIF content parsing with configuration-based limits,
        business rule validation, and detailed logging integration for enterprise environments.

        Args:
            content: LDIF content as string or LDIFContent type for parsing

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with parsed entries or failure with detailed error context

        """
        # REFACTORING: Enhanced content validation and metrics
        content_str = str(content)
        content_size = len(content_str)
        logger.debug("Starting LDIF content parsing", content_size_chars=content_size)
        logger.trace("Content preview: %s...", content_str[:100].replace("\n", "\\n"))

        # Delegate to core parser with enhanced error context
        result = TLdif.parse(content)

        if result.is_failure:
            error_msg = f"Core LDIF parsing failed: {result.error}"
            logger.error(error_msg)
            return FlextResult.fail(error_msg)

        entries = result.data or []
        entries_count = len(entries)

        # REFACTORING: Enhanced configuration limit validation with detailed context
        if entries_count > self.config.max_entries:
            limit_error = f"Entry count {entries_count} exceeds configured limit {self.config.max_entries}"
            logger.warning(limit_error)
            logger.debug("Configuration constraint violated - rejecting parse result")
            return FlextResult.fail(limit_error)

        # REFACTORING: Enhanced success logging with comprehensive metrics
        logger.info("LDIF content parsing completed successfully",
                   entries_parsed=entries_count,
                   content_size_chars=content_size,
                   max_entries_limit=self.config.max_entries)
        return FlextResult.ok(entries)

    def parse_file(self, file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF file with enterprise-grade encoding support and comprehensive file handling.

        Performs comprehensive LDIF file parsing with configuration-based encoding,
        file validation, business rule constraints, and detailed logging integration.

        Args:
            file_path: Path to LDIF file for parsing as string or Path object

        Returns:
            FlextResult[list[FlextLdifEntry]]: Success with parsed entries or failure with detailed error context

        """
        # REFACTORING: Enhanced file path validation and metrics
        file_path_obj = Path(file_path)
        absolute_path = file_path_obj.absolute()
        logger.debug("Starting LDIF file parsing",
                    file_path=str(absolute_path),
                    input_encoding=self.config.input_encoding)

        # Delegate to core parser with configuration-based encoding
        result = TLdif.read_file(file_path_obj, self.config.input_encoding)

        if result.is_failure:
            error_msg = f"Core LDIF file parsing failed for {absolute_path}: {result.error}"
            logger.error(error_msg)
            return FlextResult.fail(error_msg)

        entries = result.data or []
        entries_count = len(entries)

        # REFACTORING: Enhanced file-specific limit validation
        if entries_count > self.config.max_entries:
            limit_error = f"File entry count {entries_count} exceeds configured limit {self.config.max_entries} for {absolute_path}"
            logger.warning(limit_error)
            logger.debug("Configuration constraint violated for file parsing - rejecting result")
            return FlextResult.fail(limit_error)

        # REFACTORING: Enhanced file parsing success logging with file metrics
        logger.info("LDIF file parsing completed successfully",
                   entries_parsed=entries_count,
                   file_path=str(absolute_path),
                   input_encoding=self.config.input_encoding,
                   max_entries_limit=self.config.max_entries)
        return FlextResult.ok(entries)


class FlextLdifWriterService:
    """Enterprise-grade domain service for LDIF writing operations with advanced formatting and configuration management.

    This service provides comprehensive LDIF writing capabilities with configuration-driven
    formatting, attribute sorting, directory management, and robust error handling. Implements
    Clean Architecture patterns with enterprise-grade logging and observability integration.

    The service orchestrates LDIF writing operations while applying formatting rules, configuration
    constraints, and comprehensive error handling with detailed logging for enterprise environments.

    Example:
        >>> from flext_ldif.services import FlextLdifWriterService
        >>> from flext_ldif.config import FlextLdifConfig
        >>> 
        >>> config = FlextLdifConfig(sort_attributes=True, create_output_dir=True)
        >>> writer = FlextLdifWriterService(config)
        >>> result = writer.write_file(entries, "output/users.ldif")

    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize writer service with enterprise configuration management.
        
        Args:
            config: Optional configuration object with writing settings and formatting options
            
        """
        # REFACTORING: Enhanced configuration initialization with comprehensive logging
        self.config = config or FlextLdifConfig()
        logger.debug("FlextLdifWriterService initialized",
                    sort_attributes=self.config.sort_attributes,
                    output_encoding=self.config.output_encoding,
                    create_output_dir=self.config.create_output_dir)
        logger.trace("Writer service configuration: %s", self.config.model_dump())

    def write(self, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write entries to LDIF string with enterprise-grade formatting and configuration processing.

        Performs comprehensive LDIF string generation with configuration-driven attribute sorting,
        formatting optimization, and detailed logging integration for enterprise environments.

        Args:
            entries: List of FlextLdifEntry domain objects to serialize to LDIF string

        Returns:
            FlextResult[str]: Success with LDIF string content or failure with detailed error context

        """
        # REFACTORING: Enhanced entry validation and processing metrics
        entries_count = len(entries)
        logger.debug("Starting LDIF string writing operation", entries_count=entries_count)

        # REFACTORING: Enhanced attribute sorting with performance logging
        processed_entries = entries
        if self.config.sort_attributes:
            logger.debug("Applying attribute sorting to %d entries", entries_count)
            processed_entries = self._sort_entry_attributes(entries)
            logger.trace("Attribute sorting completed for all entries")

        # Delegate to core writer with enhanced error context
        result = TLdif.write(processed_entries)

        if result.is_failure:
            error_msg = f"Core LDIF string writing failed for {entries_count} entries: {result.error}"
            logger.error(error_msg)
            return FlextResult.fail(error_msg)

        # REFACTORING: Enhanced success logging with content metrics
        content_length = len(result.data or "")
        logger.info("LDIF string writing completed successfully",
                   entries_written=entries_count,
                   content_length_chars=content_length,
                   attributes_sorted=self.config.sort_attributes)
        return result

    def write_file(
        self,
        entries: list[FlextLdifEntry],
        file_path: str | Path,
    ) -> FlextResult[bool]:
        """Write entries to LDIF file with enterprise-grade path management and comprehensive file handling.

        Performs comprehensive LDIF file writing with configuration-based path resolution,
        automatic directory creation, encoding management, and detailed logging integration.

        Args:
            entries: List of FlextLdifEntry domain objects to write to file
            file_path: Target file path as string or Path object for LDIF output

        Returns:
            FlextResult[bool]: Success with True if file written successfully, failure with detailed error context

        """
        # REFACTORING: Enhanced file path processing and validation
        entries_count = len(entries)
        original_path = Path(file_path)
        logger.debug("Starting LDIF file writing operation",
                    entries_count=entries_count,
                    original_path=str(original_path))

        # REFACTORING: Enhanced path resolution with comprehensive logging
        resolved_path = original_path
        if not original_path.is_absolute() and self.config.output_directory:
            resolved_path = self.config.output_directory / original_path
            logger.debug("Resolved relative path to absolute",
                        original=str(original_path),
                        resolved=str(resolved_path.absolute()))

        # REFACTORING: Enhanced directory creation with detailed error handling
        if self.config.create_output_dir and resolved_path.parent:
            parent_dir = resolved_path.parent
            try:
                if not parent_dir.exists():
                    logger.debug("Creating output directory structure", parent_dir=str(parent_dir))
                    parent_dir.mkdir(parents=True, exist_ok=True)
                    logger.trace("Output directory created successfully")
                else:
                    logger.trace("Output directory already exists", parent_dir=str(parent_dir))
            except (OSError, PermissionError) as e:
                error_msg = f"Failed to create output directory {parent_dir}: {e}"
                logger.exception(error_msg)
                return FlextResult.fail(error_msg)

        # REFACTORING: Enhanced attribute sorting with performance tracking
        processed_entries = entries
        if self.config.sort_attributes:
            logger.debug("Applying attribute sorting before file write")
            processed_entries = self._sort_entry_attributes(entries)
            logger.trace("Attribute sorting completed for file output")

        # Delegate to core writer with configuration-based encoding
        result = TLdif.write_file(processed_entries, resolved_path, self.config.output_encoding)

        if result.is_failure:
            error_msg = f"Core LDIF file writing failed for {resolved_path.absolute()}: {result.error}"
            logger.error(error_msg)
            return FlextResult.fail(error_msg)

        # REFACTORING: Enhanced file writing success logging with comprehensive metrics
        logger.info("LDIF file writing completed successfully",
                   entries_written=entries_count,
                   file_path=str(resolved_path.absolute()),
                   output_encoding=self.config.output_encoding,
                   attributes_sorted=self.config.sort_attributes,
                   directory_created=self.config.create_output_dir)
        return result

    def _sort_entry_attributes(
        self,
        entries: list[FlextLdifEntry],
    ) -> list[FlextLdifEntry]:
        """Sort attributes within entries with optimized processing and comprehensive error handling.

        Performs efficient attribute sorting within LDIF entries with immutable object patterns,
        performance optimization for large datasets, and comprehensive error handling.

        Args:
            entries: List of FlextLdifEntry objects to process for attribute sorting

        Returns:
            list[FlextLdifEntry]: New list of entries with sorted attributes (immutable pattern)

        """
        # REFACTORING: Early return optimization for performance
        if not self.config.sort_attributes:
            logger.trace("Attribute sorting disabled - returning original entries")
            return entries

        # REFACTORING: Enhanced sorting with performance metrics and error handling
        entries_count = len(entries)
        logger.debug("Starting attribute sorting for %d entries", entries_count)

        sorted_entries = []
        try:
            for i, entry in enumerate(entries):
                logger.trace("Sorting attributes for entry %d: %s", i + 1, entry.dn)

                # Sort attribute names with case-insensitive ordering for better consistency
                sorted_attrs = dict(sorted(entry.attributes.attributes.items(), key=lambda x: x[0].lower()))

                # Create new entry with sorted attributes using immutable pattern
                new_attrs = entry.attributes.model_copy(update={"attributes": sorted_attrs})
                new_entry = entry.model_copy(update={"attributes": new_attrs})
                sorted_entries.append(new_entry)

            logger.debug("Attribute sorting completed successfully for %d entries", entries_count)
            return sorted_entries

        except (AttributeError, ValueError, TypeError) as e:
            logger.exception("Exception during attribute sorting - returning original entries")
            logger.error("Attribute sorting failed: %s", e)
            return entries  # Fallback to original entries on error


class FlextLdifValidatorService:
    """Enterprise-grade domain service for LDIF validation operations with comprehensive rule enforcement.

    This service provides comprehensive LDIF validation capabilities with configuration-driven
    business rules, size constraints, semantic validation, and robust error handling. Implements
    Clean Architecture patterns with enterprise-grade logging and detailed error reporting.

    The service orchestrates LDIF validation operations while applying business rules, configuration
    constraints, and comprehensive error handling with detailed logging for enterprise environments.

    Example:
        >>> from flext_ldif.services import FlextLdifValidatorService
        >>> from flext_ldif.config import FlextLdifConfig
        >>> 
        >>> config = FlextLdifConfig(max_entry_size=1048576, allow_empty_attributes=False)
        >>> validator = FlextLdifValidatorService(config)
        >>> result = validator.validate(entries)

    """

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize validator service with enterprise configuration management.
        
        Args:
            config: Optional configuration object with validation rules and constraints
            
        """
        # REFACTORING: Enhanced configuration initialization with comprehensive validation logging
        self.config = config or FlextLdifConfig()
        logger.debug("FlextLdifValidatorService initialized",
                    max_entries=self.config.max_entries,
                    max_entry_size=self.config.max_entry_size,
                    allow_empty_attributes=self.config.allow_empty_attributes)
        logger.trace("Validator service configuration: %s", self.config.model_dump())

    def validate(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries with enterprise-grade configuration rules and comprehensive error reporting.

        Performs comprehensive bulk validation of LDIF entries with configuration-based constraints,
        business rule enforcement, and detailed error reporting for enterprise environments.

        Args:
            entries: List of FlextLdifEntry domain objects to validate

        Returns:
            FlextResult[bool]: Success with True if all entries valid, failure with detailed error context

        """
        # REFACTORING: Enhanced entry count validation and metrics
        entries_count = len(entries)
        logger.debug("Starting bulk validation operation", entries_count=entries_count)

        # REFACTORING: Enhanced entry count limit validation with detailed context
        if entries_count > self.config.max_entries:
            limit_error = f"Entry count {entries_count} exceeds configured limit {self.config.max_entries}"
            logger.warning(limit_error)
            logger.debug("Configuration constraint violated - bulk validation rejected")
            return FlextResult.fail(limit_error)

        # REFACTORING: Enhanced individual entry validation with progress tracking
        logger.debug("Validating individual entries with configuration rules")
        for i, entry in enumerate(entries):
            logger.trace("Validating entry %d/%d: %s", i + 1, entries_count, entry.dn)

            result = self.validate_entry(entry)
            if result.is_failure:
                error_msg = f"Entry {i + 1} of {entries_count} validation failed ({entry.dn}): {result.error}"
                logger.error(error_msg)
                logger.debug("Bulk validation failed at entry %d - stopping validation", i + 1)
                return FlextResult.fail(error_msg)

        # REFACTORING: Enhanced success logging with comprehensive validation metrics
        logger.info("Bulk LDIF validation completed successfully",
                   entries_validated=entries_count,
                   max_entries_limit=self.config.max_entries,
                   max_entry_size_limit=self.config.max_entry_size,
                   empty_attributes_allowed=self.config.allow_empty_attributes)
        return FlextResult.ok(data=True)

    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate single LDIF entry with enterprise-grade rule enforcement and comprehensive error handling.

        Performs comprehensive validation of a single LDIF entry with core validation,
        configuration-based size constraints, attribute validation, and semantic rule enforcement.

        Args:
            entry: FlextLdifEntry domain object to validate

        Returns:
            FlextResult[bool]: Success with True if entry is valid, failure with detailed error context

        """
        # REFACTORING: Enhanced entry validation initialization with detailed context
        entry_dn = str(entry.dn)
        logger.debug("Starting single entry validation", entry_dn=entry_dn)
        logger.trace("Entry attributes count: %d", len(entry.attributes.attributes))

        # Core validation with enhanced error context
        result = TLdif.validate(entry)
        if result.is_failure:
            error_msg = f"Core validation failed for {entry_dn}: {result.error}"
            logger.warning(error_msg)
            return FlextResult.fail(error_msg)

        # REFACTORING: Enhanced entry size validation with detailed metrics
        try:
            entry_ldif = entry.to_ldif()
            entry_size = len(entry_ldif.encode(self.config.output_encoding))
            logger.trace("Entry size calculated",
                        entry_size_bytes=entry_size,
                        max_size_limit=self.config.max_entry_size,
                        encoding=self.config.output_encoding)

            if entry_size > self.config.max_entry_size:
                size_error = f"Entry size {entry_size} bytes exceeds configured limit {self.config.max_entry_size} bytes"
                logger.warning(size_error, entry_dn=entry_dn)
                return FlextResult.fail(size_error)
        except (UnicodeEncodeError, AttributeError) as e:
            encoding_error = f"Entry size validation failed due to encoding error: {e}"
            logger.error(encoding_error, entry_dn=entry_dn)
            return FlextResult.fail(encoding_error)

        # REFACTORING: Enhanced empty attributes validation with comprehensive checking
        if not self.config.allow_empty_attributes:
            logger.trace("Checking for empty attributes (not allowed by configuration)")
            for attr_name, attr_values in entry.attributes.attributes.items():
                logger.trace("Validating attribute: %s with %d values", attr_name, len(attr_values))

                if not attr_values:
                    empty_error = f"Empty attribute list not allowed: {attr_name}"
                    logger.warning(empty_error, entry_dn=entry_dn, attribute=attr_name)
                    return FlextResult.fail(empty_error)

                for j, value in enumerate(attr_values):
                    if not value.strip():
                        empty_value_error = f"Empty attribute value not allowed: {attr_name}[{j}]"
                        logger.warning(empty_value_error, entry_dn=entry_dn, attribute=attr_name, value_index=j)
                        return FlextResult.fail(empty_value_error)

        # REFACTORING: Enhanced semantic validation with detailed error context
        logger.trace("Performing semantic validation")
        semantic_result = entry.validate_semantic_rules()
        if semantic_result.is_failure:
            semantic_error = f"Semantic validation failed for {entry_dn}: {semantic_result.error or 'Unknown semantic validation error'}"
            logger.warning(semantic_error)
            return FlextResult.fail(semantic_error)

        # REFACTORING: Enhanced success logging with comprehensive entry metrics
        logger.debug("Single entry validation completed successfully",
                    entry_dn=entry_dn,
                    entry_size_bytes=entry_size,
                    attributes_count=len(entry.attributes.attributes),
                    empty_attributes_checked=not self.config.allow_empty_attributes)
        return FlextResult.ok(data=True)


# =============================================================================
# DEPENDENCY INJECTION SETUP
# =============================================================================


def register_ldif_services(
    container: FlextContainer | None = None,
    config: FlextLdifConfig | None = None,
) -> FlextResult[None]:
    """Register LDIF services in dependency injection container with comprehensive error handling and validation.

    Performs complete service registration including configuration setup, service instantiation,
    and container registration with detailed error handling and logging for enterprise environments.

    Args:
        container: Optional FlextContainer instance (uses global container if None)
        config: Optional FlextLdifConfig instance (creates default if None)

    Returns:
        FlextResult[None]: Success if all services registered, failure with detailed error context

    """
    # REFACTORING: Enhanced container and configuration initialization
    if container is None:
        container = get_flext_container()
        logger.debug("Using global FLEXT container for service registration")
    else:
        logger.debug("Using provided container for service registration")

    if config is None:
        config = FlextLdifConfig()
        logger.debug("Created default LDIF configuration for service registration")
    else:
        logger.debug("Using provided LDIF configuration for service registration")

    logger.debug("Starting LDIF services registration",
                container_id=id(container),
                config_hash=hash(str(config.model_dump())))

    # REFACTORING: Enhanced configuration registration with validation
    logger.trace("Registering LDIF configuration in container")
    config_result = container.register("ldif_config", config)
    if config_result.is_failure:
        error_msg = f"Failed to register LDIF configuration: {config_result.error}"
        logger.error(error_msg)
        return FlextResult.fail(error_msg)

    # REFACTORING: Enhanced service registration with detailed error handling
    services_config = [
        ("ldif_parser", FlextLdifParserService, "LDIF parsing service"),
        ("ldif_writer", FlextLdifWriterService, "LDIF writing service"),
        ("ldif_validator", FlextLdifValidatorService, "LDIF validation service"),
    ]

    registered_services = []
    for service_name, service_class, service_description in services_config:
        logger.debug("Registering %s", service_description, service_name=service_name)

        try:
            # Create service instance with configuration
            service_instance = service_class(config)
            logger.trace("Created %s instance", service_description)

            # Register in container
            result = container.register(service_name, service_instance)
            if result.is_failure:
                error_msg = f"Failed to register {service_description} ({service_name}): {result.error}"
                logger.error(error_msg)
                return FlextResult.fail(error_msg)

            registered_services.append(service_name)
            logger.trace("Successfully registered %s", service_description)

        except (TypeError, ValueError, AttributeError) as e:
            error_msg = f"Exception creating {service_description}: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    # REFACTORING: Enhanced success logging with comprehensive registration metrics
    logger.info("LDIF services registration completed successfully",
               services_registered=len(registered_services),
               service_names=registered_services,
               container_id=id(container))
    return FlextResult.ok(None)


def get_ldif_parser() -> FlextResult[FlextLdifParserService]:
    """Get LDIF parser service from dependency injection container with comprehensive error handling.

    Retrieves the LDIF parser service from the global container with type validation,
    error handling, and detailed logging for enterprise environments.

    Returns:
        FlextResult[FlextLdifParserService]: Success with parser service or failure with error context

    """
    # REFACTORING: Enhanced container retrieval and service resolution
    logger.debug("Retrieving LDIF parser service from container")
    container = get_flext_container()

    result = container.get("ldif_parser")
    if result.is_failure:
        error_msg = f"Failed to retrieve LDIF parser from container: {result.error}"
        logger.error(error_msg)
        return FlextResult.fail(error_msg)

    # REFACTORING: Enhanced type validation with detailed error context
    if not isinstance(result.data, FlextLdifParserService):
        actual_type = type(result.data).__name__
        error_msg = f"LDIF parser service type mismatch: expected FlextLdifParserService, got {actual_type}"
        logger.error(error_msg)
        return FlextResult.fail(error_msg)

    logger.debug("LDIF parser service retrieved successfully")
    return FlextResult.ok(result.data)


def get_ldif_writer() -> FlextResult[FlextLdifWriterService]:
    """Get LDIF writer service from dependency injection container with comprehensive error handling.

    Retrieves the LDIF writer service from the global container with type validation,
    error handling, and detailed logging for enterprise environments.

    Returns:
        FlextResult[FlextLdifWriterService]: Success with writer service or failure with error context

    """
    # REFACTORING: Enhanced container retrieval and service resolution
    logger.debug("Retrieving LDIF writer service from container")
    container = get_flext_container()

    result = container.get("ldif_writer")
    if result.is_failure:
        error_msg = f"Failed to retrieve LDIF writer from container: {result.error}"
        logger.error(error_msg)
        return FlextResult.fail(error_msg)

    # REFACTORING: Enhanced type validation with detailed error context
    if not isinstance(result.data, FlextLdifWriterService):
        actual_type = type(result.data).__name__
        error_msg = f"LDIF writer service type mismatch: expected FlextLdifWriterService, got {actual_type}"
        logger.error(error_msg)
        return FlextResult.fail(error_msg)

    logger.debug("LDIF writer service retrieved successfully")
    return FlextResult.ok(result.data)


def get_ldif_validator() -> FlextResult[FlextLdifValidatorService]:
    """Get LDIF validator service from dependency injection container with comprehensive error handling.

    Retrieves the LDIF validator service from the global container with type validation,
    error handling, and detailed logging for enterprise environments.

    Returns:
        FlextResult[FlextLdifValidatorService]: Success with validator service or failure with error context

    """
    # REFACTORING: Enhanced container retrieval and service resolution
    logger.debug("Retrieving LDIF validator service from container")
    container = get_flext_container()

    result = container.get("ldif_validator")
    if result.is_failure:
        error_msg = f"Failed to retrieve LDIF validator from container: {result.error}"
        logger.error(error_msg)
        return FlextResult.fail(error_msg)

    # REFACTORING: Enhanced type validation with detailed error context
    if not isinstance(result.data, FlextLdifValidatorService):
        actual_type = type(result.data).__name__
        error_msg = f"LDIF validator service type mismatch: expected FlextLdifValidatorService, got {actual_type}"
        logger.error(error_msg)
        return FlextResult.fail(error_msg)

    logger.debug("LDIF validator service retrieved successfully")
    return FlextResult.ok(result.data)


# =============================================================================
# EXPORTS
# =============================================================================


__all__ = [
    # Service classes
    "FlextLdifParserService",
    "FlextLdifValidatorService",
    "FlextLdifWriterService",
    # Protocols
    "IFlextLdifParser",
    "IFlextLdifValidator",
    "IFlextLdifWriter",
    # DI functions
    "get_ldif_parser",
    "get_ldif_validator",
    "get_ldif_writer",
    "register_ldif_services",
]
