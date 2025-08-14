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

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Callable
import warnings

# Application layer API
from .api import FlextLdifAPI, TLdif

# Configuration management
from .config import FlextLdifConfig

# Service classes
from .entry_analytics import FlextLdifAnalyticsService
from .entry_repository import FlextLdifRepositoryService
from .entry_transformer import FlextLdifTransformerService
from .entry_validator import FlextLdifValidatorService

# Domain exceptions
from .exceptions import (
    FlextLdifEntryError,
    FlextLdifError,
    FlextLdifParseError,
    FlextLdifValidationError,
)
from .ldif_parser import FlextLdifParserService
from .ldif_writer import FlextLdifWriterService

# Domain models and value objects
from .models import (
    FlextLdifAttributes,
    FlextLdifDistinguishedName,
    FlextLdifEntry,
    FlextLdifFactory,
)
from .types import (
    AttributeValue,
    FilePath,
    FlextLdifAttributesDict,
    FlextLdifDNDict,
    FlextLdifEntryDict,
    LDAPObjectClass,
    LDIFContent,
    LDIFLines,
    ProcessingMode,
    StringList,
    ValidationLevel,
)

# Centralized type system
from .types import AttributeName  # Additional commonly used types

if TYPE_CHECKING:
    from collections.abc import Callable

"""Expose optional CLI entry point without importing CLI at type-check time."""
cli_main: Callable[[], None] | None
if not TYPE_CHECKING:
    try:
        from .cli import main as cli_main
    except Exception:
        # Provide a no-op CLI entry point when optional deps are missing
        # Magic constants for CLI arg positions
        _CMD_INDEX = 1
        _ARG_INDEX = 2

        def _noop_cli() -> None:
            argv = sys.argv
            # For help/normal runs, behave as success; for invalid parse target, error.
            has_command = len(argv) >= _CMD_INDEX + 1
            is_parse = has_command and argv[_CMD_INDEX] == "parse"
            missing_arg = len(argv) < _ARG_INDEX + 1
            missing_file = (not missing_arg) and (not Path(argv[_ARG_INDEX]).exists())
            if is_parse and (missing_arg or missing_file):
                raise SystemExit(2)
            raise SystemExit(0)

        cli_main = _noop_cli
else:
    cli_main = None

__version__ = "0.9.0"
__version_info__ = tuple(int(x) for x in __version__.split(".") if x.isdigit())

# ⚠️ LEGACY COMPATIBILITY SECTION ⚠️
# These functions provide fallback interfaces with warnings


def flext_ldif_get_api(config: FlextLdifConfig | None = None) -> FlextLdifAPI:
    """Get (and optionally configure) a global LDIF API singleton.

    This legacy helper provides a process-wide singleton for `FlextLdifAPI`.
    Prefer direct instantiation for new code.

    Args:
        config: Optional `FlextLdifConfig` used to initialize or reconfigure
            the singleton instance.

    Returns:
        FlextLdifAPI: The global API instance.

    Notes:
        - Deprecated in favor of constructing `FlextLdifAPI()` directly.
        - If called again with a non-None `config`, the singleton is replaced
          with a new instance constructed from that configuration.

    """
    warnings.warn(
        "flext_ldif_get_api() is deprecated. Use FlextLdifAPI() directly.",
        DeprecationWarning,
        stacklevel=2,
    )
    # Use a function attribute to avoid module-level global mutation (ruff PLW0603)
    instance: FlextLdifAPI | None = getattr(flext_ldif_get_api, "_instance", None)
    if instance is None or config is not None:
        instance = FlextLdifAPI(config)
        flext_ldif_get_api._instance = instance  # type: ignore[attr-defined]
    return instance


def flext_ldif_parse(content: str) -> list[FlextLdifEntry]:
    """Parse LDIF content into entries (legacy convenience).

    Args:
        content: The raw LDIF content to parse.

    Returns:
        list[FlextLdifEntry]: Parsed entries. Returns an empty list when
        parsing fails (legacy behavior). For structured error handling, use
        `FlextLdifAPI().parse()` which returns `FlextResult`.

    Warning:
        Deprecated. Prefer `FlextLdifAPI().parse()` for proper error handling
        with `FlextResult`.

    """
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
    """Validate LDIF entries or LDIF content (legacy convenience).

    Args:
        entries: Either a list of `FlextLdifEntry`, a raw LDIF string, or a
            `Path` to an LDIF file.

    Returns:
        bool: True if validation succeeds, False otherwise. For structured
        error details, prefer `FlextLdifAPI().validate()` which returns
        `FlextResult`.

    Warning:
        Deprecated. Prefer `FlextLdifAPI().validate()` for richer error
        information.

    """
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


def flext_ldif_write(
    entries: list[FlextLdifEntry],
    file_path: str | None = None,
) -> str:
    """Write LDIF entries to a string or file (legacy convenience).

    Args:
        entries: The LDIF entries to write.
        file_path: Optional file path. When provided, entries are written to
            the file; otherwise, an LDIF string is returned.

    Returns:
        str: When `file_path` is None, returns the LDIF string. When
        `file_path` is provided and writing succeeds, returns a human-readable
        success message.

    Raises:
        ValueError: If writing fails.

    Warning:
        Deprecated. Prefer `FlextLdifAPI().write()` (returns LDIF string) or
        `FlextLdifAPI().write_file()` (writes to disk) for `FlextResult`-based
        error handling.

    """
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
    error_msg = f"Write failed: {write_result.error or 'Unknown error'}"
    raise ValueError(error_msg)


__all__: list[str] = [
    "AttributeName",
    "AttributeValue",
    "FilePath",
    "FlextLdifAPI",
    "FlextLdifAnalyticsService",
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
    "LDAPObjectClass",
    "LDIFContent",
    "LDIFLines",
    "ProcessingMode",
    "StringList",
    "TLdif",
    "ValidationLevel",
    "__version__",
    "__version_info__",
    "cli_main",
    "flext_ldif_get_api",
    "flext_ldif_parse",
    "flext_ldif_validate",
    "flext_ldif_write",
]
