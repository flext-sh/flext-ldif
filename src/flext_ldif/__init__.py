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

from typing import TYPE_CHECKING

# Unified API
from .api import (
    FlextLdifAPI,
    flext_ldif_get_api,
    flext_ldif_parse,
    flext_ldif_validate,
    flext_ldif_write,
)

# Configuration and models
from .config import FlextLdifConfig

# Core processing functionality
from .core import TLdif

# Exceptions
from .exceptions import (
    FlextLdifEntryError,
    FlextLdifError,
    FlextLdifParseError,
    FlextLdifValidationError,
)

# Models (consolidated specifications and values)
from .models import (
    FlextLdifAttributes,
    FlextLdifAttributesDict,
    FlextLdifDistinguishedName,
    FlextLdifDNDict,
    FlextLdifEntry,
    FlextLdifEntryDict,
    LDIFContent,
    LDIFLines,
)

if TYPE_CHECKING:
    from collections.abc import Callable

# Services
# CLI functionality - import directly since dependencies are required
from .cli import main as cli_main
from .services import (
    FlextLdifParserService,
    FlextLdifValidatorService,
    FlextLdifWriterService,
    get_ldif_parser,
    get_ldif_validator,
    get_ldif_writer,
    register_ldif_services,
)

__version__ = "0.9.0"

__all__: list[str] = [
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
    "FlextLdifParseError",
    "FlextLdifParserService",
    "FlextLdifValidationError",
    "FlextLdifValidatorService",
    "FlextLdifWriterService",
    "LDIFContent",
    "LDIFLines",
    "TLdif",
    "__version__",
    "cli_main",
    "flext_ldif_get_api",
    "flext_ldif_parse",
    "flext_ldif_validate",
    "flext_ldif_write",
    "get_ldif_parser",
    "get_ldif_validator",
    "get_ldif_writer",
    "register_ldif_services",
]
