"""FLEXT-LDIF - Enterprise LDIF Processing Library.

This module provides enterprise-grade LDIF (LDAP Data Interchange Format) processing
capabilities built with Clean Architecture and Domain-Driven Design principles,
integrated seamlessly with the FLEXT ecosystem.

The library offers comprehensive LDIF parsing, validation, transformation, and
generation capabilities with railway-oriented programming patterns, strict type
safety, and production-ready error handling.

Key Components:
    - FlextLdifAPI: Main application service for unified LDIF operations
    - FlextLdifEntry: Domain entity representing LDIF entries with business logic
    - FlextLdifDistinguishedName: Value object for DN handling and validation
    - FlextLdifAttributes: Immutable attribute collection with business rules
    - Service Layer: Parsing, validation, and writing services with dependency injection

Architecture:
    Implements Clean Architecture with clear separation between domain, application,
    and infrastructure layers. Built on flext-core foundation patterns with
    FlextResult for error handling and enterprise configuration management.

Performance:
    Optimized for enterprise workloads with support for large LDIF files,
    streaming processing, memory-efficient operations, and comprehensive
    validation with configurable strictness levels.

Example:
    Basic LDIF processing with error handling:

    >>> from flext_ldif import FlextLdifAPI
    >>> api = FlextLdifAPI()
    >>>
    >>> # Parse LDIF content
    >>> ldif_content = '''
    ... dn: cn=John Doe,ou=people,dc=example,dc=com
    ... cn: John Doe
    ... objectClass: person
    ... objectClass: inetOrgPerson
    ... mail: john.doe@example.com
    ... '''
    >>>
    >>> result = api.parse(ldif_content)
    >>> if result.success:
    ...     entries = result.data
    ...     print(f"Parsed {len(entries)} entries successfully")
    ... else:
    ...     print(f"Parse failed: {result.error}")

Integration:
    - Built on flext-core foundation patterns and utilities
    - Integrates with flext-observability for monitoring and tracing
    - Compatible with flext-ldap for directory services integration
    - Supports Singer ecosystem for data pipeline integration
    - Enterprise configuration management with environment variable support

Version: 0.9.0
Author: FLEXT Development Team
License: MIT
Status: Production Ready

"""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import TYPE_CHECKING

# Core public API - Import from actual files
# Application layer API
from .api import FlextLdifAPI

# Configuration management
from .config import FlextLdifConfig

# Core processing functionality
from .core import TLdif

# Domain exceptions
from .exceptions import (
    FlextLdifEntryError,
    FlextLdifError,
    FlextLdifParseError,
    FlextLdifValidationError,
)

# Service classes
from .analytics_service import FlextLdifAnalyticsService
from .parser_service import FlextLdifParserService
from .repository_service import FlextLdifRepositoryService
from .transformer_service import FlextLdifTransformerService
from .validator_service import FlextLdifValidatorService
from .writer_service import FlextLdifWriterService

# Domain models and value objects
from .models import (
    FlextLdifAttributes,
    FlextLdifAttributesDict,
    FlextLdifDistinguishedName,
    FlextLdifDNDict,
    FlextLdifEntry,
    FlextLdifEntryDict,
    FlextLdifFactory,
    LDIFContent,
    LDIFLines,
)

# CLI functionality
from .cli_utils import display_entry_count  # Legacy path compatibility

if TYPE_CHECKING:
    from collections.abc import Callable

# CLI functionality - conditional import to avoid dependency issues
cli_main: Callable[[], None] | None
try:
    from .cli import main as cli_main
except Exception:
    # Catch all exceptions to make CLI truly optional
    cli_main = None

__version__ = "0.9.0"

# ⚠️ LEGACY COMPATIBILITY SECTION ⚠️
# These functions provide fallback interfaces with warnings


_GLOBAL_API_INSTANCE: FlextLdifAPI | None = None


def flext_ldif_get_api(config: FlextLdifConfig | None = None) -> FlextLdifAPI:
    """Legacy function - returns a global singleton API instance.

    Subsequent calls return the same instance; the first call can optionally
    receive a configuration that will be used to construct the singleton.
    """
    warnings.warn(
        "flext_ldif_get_api() is deprecated. Use FlextLdifAPI() directly.",
        DeprecationWarning,
        stacklevel=2,
    )
    global _GLOBAL_API_INSTANCE
    if _GLOBAL_API_INSTANCE is None:
        _GLOBAL_API_INSTANCE = FlextLdifAPI(config)
    elif config is not None:
        # Allow reconfiguration by replacing the singleton when config is provided
        _GLOBAL_API_INSTANCE = FlextLdifAPI(config)
    return _GLOBAL_API_INSTANCE


def flext_ldif_parse(content: str) -> list[FlextLdifEntry]:
    """Legacy function - use FlextLdifAPI().parse() for FlextResult."""
    warnings.warn(
        "flext_ldif_parse() is deprecated. Use FlextLdifAPI().parse() for proper error handling.",
        DeprecationWarning,
        stacklevel=2,
    )
    api = FlextLdifAPI()
    result = api.parse(content)
    if result.success and result.data is not None:
        return result.data
    # Return empty list for invalid content (legacy compatibility)
    return []


def flext_ldif_validate(entries: list[FlextLdifEntry] | str | Path) -> bool:
    """Legacy function - use FlextLdifAPI().validate() for FlextResult."""
    warnings.warn(
        "flext_ldif_validate() is deprecated. Use FlextLdifAPI().validate() for proper error handling.",
        DeprecationWarning,
        stacklevel=2,
    )
    api = FlextLdifAPI()

    # Handle string input by parsing first
    if isinstance(entries, str):
        parse_result = api.parse(entries)
        if parse_result.is_failure or not parse_result.data:
            return False  # Invalid LDIF content
        entries = parse_result.data
    # Handle Path input by parsing file
    elif isinstance(entries, Path):
        parse_result = api.parse_file(entries)
        if parse_result.is_failure or not parse_result.data:
            return False  # Invalid file or content
        entries = parse_result.data

    result = api.validate(entries)
    if result.success and result.data is not None:
        return result.data
    # Return False for validation failures (legacy compatibility)
    return False


def flext_ldif_write(entries: list[FlextLdifEntry], file_path: str | None = None) -> str:
    """Legacy function - use FlextLdifAPI().write() or write_file() for FlextResult."""
    warnings.warn(
        "flext_ldif_write() is deprecated. Use FlextLdifAPI().write() or write_file() for proper error handling.",
        DeprecationWarning,
        stacklevel=2,
    )
    api = FlextLdifAPI()

    if file_path:
        # Write to file
        result = api.write_file(entries, file_path)
        if result.success:
            return "File written successfully"
        error_msg = f"Write to file failed: {result.error or 'Unknown error'}"
        raise ValueError(error_msg)
    # Write to string
    write_result = api.write(entries)
    if write_result.success and write_result.data is not None:
        return write_result.data
    error_msg = f"Write failed: {result.error or 'Unknown error'}"
    raise ValueError(error_msg)


__all__: list[str] = [
    "annotations", "Path", "TYPE_CHECKING", "FlextLdifAPI", "FlextLdifConfig", "TLdif",
    "FlextLdifEntryError", "FlextLdifError", "FlextLdifParseError", "FlextLdifValidationError",
    "FlextLdifAnalyticsService", "FlextLdifParserService", "FlextLdifRepositoryService",
    "FlextLdifTransformerService", "FlextLdifValidatorService", "FlextLdifWriterService",
    "FlextLdifAttributes", "FlextLdifAttributesDict", "FlextLdifDistinguishedName", "FlextLdifDNDict",
    "FlextLdifEntry", "FlextLdifEntryDict", "FlextLdifFactory", "LDIFContent", "LDIFLines",
    "display_entry_count", "cli_main", "__version__", "flext_ldif_get_api", "flext_ldif_parse",
    "flext_ldif_validate", "flext_ldif_write",
] = [
    "FlextLdifAnalyticsService",
    "FlextLdifAPI",
    "FlextLdifAttributes",
    "FlextLdifAttributesDict",
    "FlextLdifConfig",
    "FlextLdifDNDict",
    "FlextLdifDistinguishedName",
    "FlextLdifEntry",
    "FlextLdifEntryDict",
    "FlextLdifEntryError",
    "FlextLdifError",
    "FlextLdifFactory",
    "FlextLdifParseError",
    "FlextLdifParserService",
    "FlextLdifRepositoryService",
    "FlextLdifTransformerService",
    "FlextLdifValidationError",
    "FlextLdifValidatorService",
    "FlextLdifWriterService",
    "LDIFContent",
    "LDIFLines",
    "TLdif",
    "__version__",
    "cli_main",
    "display_entry_count",
    "flext_ldif_get_api",
    "flext_ldif_parse",
    "flext_ldif_validate",
    "flext_ldif_write",
]
