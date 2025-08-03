"""FLEXT-LDIF Domain Services and Infrastructure Integration

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
    """Domain service for LDIF parsing operations."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize parser service with configuration."""
        self.config = config or FlextLdifConfig()
        logger.debug("FlextLdifParserService initialized with config: %s", self.config)

    def parse(self, content: str | LDIFContent) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF content with configuration constraints."""
        logger.debug("Parsing LDIF content")

        # Delegate to core parser
        result = TLdif.parse(content)

        if result.is_failure:
            logger.error("LDIF parsing failed: %s", result.error)
            return result

        entries = result.data or []

        # Apply configuration limits
        if len(entries) > self.config.max_entries:
            logger.warning(
                "Entry count %d exceeds limit %d",
                len(entries),
                self.config.max_entries,
            )
            return FlextResult.fail(
                f"Too many entries: {len(entries)} > {self.config.max_entries}",
            )

        logger.info("Successfully parsed %d LDIF entries", len(entries))
        return FlextResult.ok(entries)

    def parse_file(self, file_path: str | Path) -> FlextResult[list[FlextLdifEntry]]:
        """Parse LDIF file with encoding support."""
        logger.debug("Parsing LDIF file: %s", file_path)

        # Delegate to core parser with encoding
        result = TLdif.read_file(file_path, self.config.input_encoding)

        if result.is_failure:
            logger.error("LDIF file parsing failed: %s", result.error)
            return result

        entries = result.data or []

        # Apply configuration limits
        if len(entries) > self.config.max_entries:
            logger.warning(
                "File entry count %d exceeds limit %d",
                len(entries),
                self.config.max_entries,
            )
            return FlextResult.fail(
                f"Too many entries in file: {len(entries)} > {self.config.max_entries}",
            )

        logger.info(
            "Successfully parsed %d entries from file: %s",
            len(entries),
            file_path,
        )
        return FlextResult.ok(entries)


class FlextLdifWriterService:
    """Domain service for LDIF writing operations."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize writer service with configuration."""
        self.config = config or FlextLdifConfig()
        logger.debug("FlextLdifWriterService initialized with config: %s", self.config)

    def write(self, entries: list[FlextLdifEntry]) -> FlextResult[str]:
        """Write entries to LDIF string with formatting."""
        logger.debug("Writing %d entries to LDIF string", len(entries))

        # Apply sorting if configured
        if self.config.sort_attributes:
            entries = self._sort_entry_attributes(entries)

        # Delegate to core writer
        result = TLdif.write(entries)

        if result.is_failure:
            logger.error("LDIF writing failed: %s", result.error)
            return result

        logger.info("Successfully wrote %d entries to LDIF string", len(entries))
        return result

    def write_file(
        self,
        entries: list[FlextLdifEntry],
        file_path: str | Path,
    ) -> FlextResult[bool]:
        """Write entries to LDIF file with encoding."""
        logger.debug("Writing %d entries to file: %s", len(entries), file_path)

        # Resolve output path
        file_path = Path(file_path)
        if not file_path.is_absolute() and self.config.output_directory:
            file_path = self.config.output_directory / file_path

        # Create directory if configured
        if self.config.create_output_dir and file_path.parent:
            try:
                file_path.parent.mkdir(parents=True, exist_ok=True)
                logger.debug("Created output directory: %s", file_path.parent)
            except Exception as e:
                logger.exception("Failed to create output directory")
                return FlextResult.fail(f"Failed to create directory: {e}")

        # Apply sorting if configured
        if self.config.sort_attributes:
            entries = self._sort_entry_attributes(entries)

        # Delegate to core writer with encoding
        result = TLdif.write_file(entries, file_path, self.config.output_encoding)

        if result.is_failure:
            logger.error("LDIF file writing failed: %s", result.error)
            return result

        logger.info(
            "Successfully wrote %d entries to file: %s",
            len(entries),
            file_path,
        )
        return result

    def _sort_entry_attributes(
        self,
        entries: list[FlextLdifEntry],
    ) -> list[FlextLdifEntry]:
        """Sort attributes within entries if configured."""
        if not self.config.sort_attributes:
            return entries

        # Create new entries with sorted attributes
        sorted_entries = []
        for entry in entries:
            # Sort attribute names
            sorted_attrs = dict(sorted(entry.attributes.attributes.items()))

            # Create new entry with sorted attributes
            new_attrs = entry.attributes.model_copy(update={"attributes": sorted_attrs})
            new_entry = entry.model_copy(update={"attributes": new_attrs})
            sorted_entries.append(new_entry)

        return sorted_entries


class FlextLdifValidatorService:
    """Domain service for LDIF validation operations."""

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize validator service with configuration."""
        self.config = config or FlextLdifConfig()
        logger.debug(
            "FlextLdifValidatorService initialized with config: %s",
            self.config,
        )

    def validate(self, entries: list[FlextLdifEntry]) -> FlextResult[bool]:
        """Validate multiple LDIF entries with configuration rules."""
        logger.debug("Validating %d LDIF entries", len(entries))

        # Check entry count limit
        if len(entries) > self.config.max_entries:
            return FlextResult.fail(
                f"Too many entries: {len(entries)} > {self.config.max_entries}",
            )

        # Validate each entry
        for i, entry in enumerate(entries):
            result = self.validate_entry(entry)
            if result.is_failure:
                logger.error("Entry %d validation failed: %s", i, result.error)
                return FlextResult.fail(f"Entry {i}: {result.error}")

        logger.info("All %d entries validated successfully", len(entries))
        return FlextResult.ok(data=True)

    def validate_entry(self, entry: FlextLdifEntry) -> FlextResult[bool]:
        """Validate single LDIF entry with all rules."""
        logger.debug("Validating entry: %s", entry.dn)

        # Core validation
        result = TLdif.validate(entry)
        if result.is_failure:
            return result

        # Check entry size
        entry_size = len(entry.to_ldif().encode(self.config.output_encoding))
        if entry_size > self.config.max_entry_size:
            return FlextResult.fail(
                f"Entry size {entry_size} exceeds limit {self.config.max_entry_size}",
            )

        # Check empty attributes
        if not self.config.allow_empty_attributes:
            for attr_name, attr_values in entry.attributes.attributes.items():
                if not attr_values or any(not v.strip() for v in attr_values):
                    return FlextResult.fail(
                        f"Empty attribute value not allowed: {attr_name}",
                    )

        # Semantic validation
        semantic_result = entry.validate_semantic_rules()
        if semantic_result.is_failure:
            return FlextResult.fail(
                semantic_result.error or "Semantic validation failed",
            )

        logger.debug("Entry validated successfully: %s", entry.dn)
        return FlextResult.ok(data=True)


# =============================================================================
# DEPENDENCY INJECTION SETUP
# =============================================================================


def register_ldif_services(
    container: FlextContainer | None = None,
    config: FlextLdifConfig | None = None,
) -> FlextResult[None]:
    """Register LDIF services in DI container."""
    if container is None:
        container = get_flext_container()

    if config is None:
        config = FlextLdifConfig()

    logger.debug("Registering LDIF services in container")

    # Register configuration
    config_result = container.register("ldif_config", config)
    if config_result.is_failure:
        return config_result

    # Register services
    services = [
        ("ldif_parser", FlextLdifParserService(config)),
        ("ldif_writer", FlextLdifWriterService(config)),
        ("ldif_validator", FlextLdifValidatorService(config)),
    ]

    for service_name, service_instance in services:
        result = container.register(service_name, service_instance)
        if result.is_failure:
            logger.error("Failed to register %s: %s", service_name, result.error)
            return result

    logger.info("Successfully registered all LDIF services")
    return FlextResult.ok(None)


def get_ldif_parser() -> FlextResult[FlextLdifParserService]:
    """Get LDIF parser service from container."""
    container = get_flext_container()
    result = container.get("ldif_parser")
    if result.is_success and isinstance(result.data, FlextLdifParserService):
        return FlextResult.ok(result.data)
    return FlextResult.fail("Failed to get LDIF parser service")


def get_ldif_writer() -> FlextResult[FlextLdifWriterService]:
    """Get LDIF writer service from container."""
    container = get_flext_container()
    result = container.get("ldif_writer")
    if result.is_success and isinstance(result.data, FlextLdifWriterService):
        return FlextResult.ok(result.data)
    return FlextResult.fail("Failed to get LDIF writer service")


def get_ldif_validator() -> FlextResult[FlextLdifValidatorService]:
    """Get LDIF validator service from container."""
    container = get_flext_container()
    result = container.get("ldif_validator")
    if result.is_success and isinstance(result.data, FlextLdifValidatorService):
        return FlextResult.ok(result.data)
    return FlextResult.fail("Failed to get LDIF validator service")


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
