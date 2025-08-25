"""FLEXT-LDIF Library - Enterprise LDIF Processing.

Modern LDIF (LDAP Data Interchange Format) processing library built with
Clean Architecture and Domain-Driven Design principles using the flext-core foundation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# =============================================================================
# CONSOLIDATED CLASSES - Import consolidated classes FIRST
# =============================================================================

from .services import (
    # Consolidated services (FLEXT Pattern)
    FlextLdifAnalyticsService,
    FlextLdifParserService,
    FlextLdifRepositoryService,
    FlextLdifValidatorService,
    FlextLdifWriterService,
    # Field definitions
    FieldDefaults,
    attribute_name_field,
    attribute_value_field,
    dn_field,
    object_class_field,
)
from .utilities import (
    # Consolidated utilities and types (FLEXT Pattern)
    FlextLdifUtilities,
    # Type system from consolidated utilities
    AttributeName,
    AttributeValue,
    AttributeValueType,
    FilePath,
    FlextLdifAttributesDict,
    FlextLdifDNDict,
    FlextLdifEntryDict,
    LDAPObjectClass,
    LDIFContent,
    LDIFLines,
    MappingType,
    ProcessingMode,
    SequenceType,
    StringList,
    ValidationLevel,
)

# =============================================================================
# MAIN CLASSES - Import main implementation classes
# =============================================================================

from .models import (
    FlextLdifConfig,
    FlextLdifEntry,
    FlextLdifFactory,
    FlextLdifAttributes,
    FlextLdifDistinguishedName,
)

# =============================================================================
# UTILITIES - Import utility classes and functions
# =============================================================================

from .protocols import (
    FlextLdifAnalyticsProtocol,
    FlextLdifParserProtocol,
    FlextLdifRepositoryProtocol,
    FlextLdifTransformerProtocol,
    FlextLdifValidatorProtocol,
    FlextLdifWriterProtocol,
)

from .constants import (
    LDAP_DN_ATTRIBUTES,
    LDAP_GROUP_CLASSES,
    LDAP_PERSON_CLASSES,
    MIN_DN_COMPONENTS,
)

from .exceptions import (
    FlextLdifError,
    FlextLdifValidationError,
    FlextLdifParseError,
    FlextLdifEntryError,
    FlextLdifConfigurationError,
)

from .helpers import (
    flext_ldif_get_api,
    flext_ldif_parse,
    flext_ldif_validate,
    flext_ldif_write,
)

# Facade imports for backward compatibility
from .analytics_service import FlextLdifAnalyticsService as FacadeAnalyticsService
from .parser_service import FlextLdifParserService as FacadeParserService
from .repository_service import FlextLdifRepositoryService as FacadeRepositoryService
from .transformer_service import FlextLdifTransformerService
from .validator_service import FlextLdifValidatorService as FacadeValidatorService
from .writer_service import FlextLdifWriterService as FacadeWriterService

# CLI (optional import) - temporarily disabled due to flext-cli issue
try:
    # from .cli import main as cli_main
    cli_main: object | None = None
except ImportError:
    cli_main = None

# =============================================================================
# PUBLIC API DEFINITION - Define what gets exported
# =============================================================================

__all__ = [
    # Consolidated Classes (FLEXT Pattern) - PRIORITY
    "FlextLdifAnalyticsService",
    "FlextLdifParserService",
    "FlextLdifRepositoryService",
    "FlextLdifValidatorService",
    "FlextLdifWriterService",
    "FlextLdifUtilities",

    # Consolidated Fields and Defaults
    "FieldDefaults",
    "attribute_name_field",
    "attribute_value_field",
    "dn_field",
    "object_class_field",

    # Main Implementation Classes
    "FlextLdifConfig",
    "FlextLdifEntry",
    "FlextLdifFactory",
    "FlextLdifAttributes",
    "FlextLdifDistinguishedName",

    # Consolidated Type System
    "AttributeName",
    "AttributeValue",
    "AttributeValueType",
    "FilePath",
    "FlextLdifAttributesDict",
    "FlextLdifDNDict",
    "FlextLdifEntryDict",
    "LDAPObjectClass",
    "LDIFContent",
    "LDIFLines",
    "MappingType",
    "ProcessingMode",
    "SequenceType",
    "StringList",
    "ValidationLevel",

    # Utility Classes
    "FlextLdifAnalyticsProtocol",
    "FlextLdifParserProtocol",
    "FlextLdifRepositoryProtocol",
    "FlextLdifTransformerProtocol",
    "FlextLdifValidatorProtocol",
    "FlextLdifWriterProtocol",

    # Constants
    "LDAP_DN_ATTRIBUTES",
    "LDAP_GROUP_CLASSES",
    "LDAP_PERSON_CLASSES",
    "MIN_DN_COMPONENTS",

    # Exceptions
    "FlextLdifError",
    "FlextLdifValidationError",
    "FlextLdifParseError",
    "FlextLdifEntryError",
    "FlextLdifConfigurationError",

    # Helper Functions
    "flext_ldif_parse",
    "flext_ldif_validate",
    "flext_ldif_write",
    "flext_ldif_get_api",

    # CLI
    "cli_main",

    # Facade Services (backward compatibility)
    "FlextLdifTransformerService",
]

# =============================================================================
# FACADE CLASS - Import facade LAST (orchestration only)
# =============================================================================

from .api import FlextLdifAPI
__all__ += ["FlextLdifAPI"]

# Version information
__version__ = "0.9.0"
__author__ = "FLEXT Development Team"
__email__ = "dev@flext.com"
__license__ = "MIT"
