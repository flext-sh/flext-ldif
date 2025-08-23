"""FLEXT-LDIF - LDIF Processing Library.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations


# Application layer API
from .api import FlextLdifAPI

# Configuration management
from .models import FlextLdifConfig

# Service classes
from .analytics_service import FlextLdifAnalyticsService
from .repository_service import FlextLdifRepositoryService
from .transformer_service import FlextLdifTransformerService
from .validator_service import FlextLdifValidatorService

# Protocols
from .protocols import (
    FlextLdifAnalyticsProtocol,
    FlextLdifParserProtocol,
    FlextLdifRepositoryProtocol,
    FlextLdifTransformerProtocol,
    FlextLdifValidatorProtocol,
    FlextLdifWriterProtocol,
)

# Domain exceptions
from .exceptions import (
    FlextLdifEntryError,
    FlextLdifError,
    FlextLdifParseError,
    FlextLdifValidationError,
)
from .parser_service import FlextLdifParserService
from .writer_service import FlextLdifWriterService

# Domain models and value objects
from .models import (
    FlextLdifAttributes,
    FlextLdifDistinguishedName,
    FlextLdifEntry,
    FlextLdifFactory,
)

# Centralized type system
from .typings import (
    AttributeName,
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

# Pydantic field definitions
from .fields import (
    FieldDefaults,
    attribute_name_field,
    attribute_value_field,
    dn_field,
    object_class_field,
)

# Constants for LDIF processing
from .constants import (
    LDAP_DN_ATTRIBUTES,
    LDAP_PERSON_CLASSES,
    LDAP_GROUP_CLASSES,
    LDAP_OU_CLASSES,
    MIN_DN_COMPONENTS,
    DEFAULT_LINE_WRAP_LENGTH,
    DEFAULT_INPUT_ENCODING,
    DEFAULT_OUTPUT_ENCODING,
)

# Core processing class
from .core import TLdif

# CLI entry point - fail fast if dependencies missing
from .cli import main as cli_main

__version__ = "0.9.0"
__version_info__ = tuple(int(x) for x in __version__.split(".") if x.isdigit())


# Convenience functions
def flext_ldif_get_api(config: FlextLdifConfig | None = None) -> FlextLdifAPI:
    """Get LDIF API instance with optional configuration."""
    return FlextLdifAPI(config)


def flext_ldif_parse(content: str) -> list[FlextLdifEntry]:
    """Parse LDIF content using default configuration."""

    def raise_parse_error(error: str) -> None:
        raise FlextLdifParseError(error or "Parse failed")

    return (
        flext_ldif_get_api().parse(content).tap_error(raise_parse_error).unwrap_or([])
    )


def flext_ldif_validate(entries: list[FlextLdifEntry]) -> bool:
    """Validate LDIF entries using default configuration."""

    def raise_validation_error(error: str) -> None:
        raise FlextLdifValidationError(error or "Validation failed")

    return (
        flext_ldif_get_api()
        .validate(entries)
        .tap_error(raise_validation_error)
        .unwrap_or(default=False)
    )


def flext_ldif_write(entries: list[FlextLdifEntry]) -> str:
    """Write LDIF entries to string using default configuration."""

    def raise_write_error(error: str) -> None:
        raise FlextLdifError(error or "Write failed")

    return (
        flext_ldif_get_api().write(entries).tap_error(raise_write_error).unwrap_or("")
    )


__all__: list[str] = [
    "AttributeName",
    "AttributeValue",
    "DEFAULT_INPUT_ENCODING",
    "DEFAULT_LINE_WRAP_LENGTH",
    "DEFAULT_OUTPUT_ENCODING",
    "FieldDefaults",
    "FilePath",
    "FlextLdifAPI",
    "FlextLdifAnalyticsProtocol",
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
    "FlextLdifParserProtocol",
    "FlextLdifParserService",
    "FlextLdifRepositoryProtocol",
    "FlextLdifRepositoryService",
    "FlextLdifTransformerProtocol",
    "FlextLdifTransformerService",
    "FlextLdifValidationError",
    "FlextLdifValidatorProtocol",
    "FlextLdifValidatorService",
    "FlextLdifWriterProtocol",
    "FlextLdifWriterService",
    "LDAP_DN_ATTRIBUTES",
    "LDAP_GROUP_CLASSES",
    "LDAP_OU_CLASSES",
    "LDAP_PERSON_CLASSES",
    "MIN_DN_COMPONENTS",
    "LDAPObjectClass",
    "LDIFContent",
    "LDIFLines",
    "ProcessingMode",
    "StringList",
    "TLdif",
    "ValidationLevel",
    "__version__",
    "__version_info__",
    "attribute_name_field",
    "attribute_value_field",
    "cli_main",
    "dn_field",
    "flext_ldif_get_api",
    "flext_ldif_parse",
    "flext_ldif_validate",
    "flext_ldif_write",
    "object_class_field",
]
