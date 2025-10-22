r"""FLEXT-LDIF - RFC-First LDIF Processing Library with flext-core 1.0.0 Integration.

FLEXT-LDIF is an enterprise-grade library for processing LDAP Data Interchange Format (LDIF)
files with full RFC 2849/4512 compliance. It provides a unified facade API leveraging
flext-core 1.0.0 patterns for enterprise-grade reliability and maintainability.

The library features:
    - Unified FlextLdif facade for all LDIF operations
    - RFC 2849/4512 compliant parsing and writing
    - Server-specific quirks system (OID, OUD, OpenLDAP, etc.)
    - Generic server-agnostic migration pipeline
    - Type-safe Pydantic v2 models with validation
    - FlextProcessors integration for batch and parallel processing
    - Railway-oriented error handling with FlextResult

Full flext-core 1.0.0 Integration:
    - FlextResult for monadic error composition
    - FlextProcessors for data transformations
    - FlextContainer for dependency injection
    - FlextBus for domain event emission
    - FlextLogger for structured logging

Args:
    None

Returns:
    None

Raises:
    ImportError: If required dependencies are not available.

Example:
    >>> from flext_ldif import FlextLdif
    >>> from pathlib import Path
    >>>
    >>> # Initialize LDIF API
    >>> ldif = FlextLdif()
    >>>
    >>> # Parse LDIF content
    >>> result = ldif.parse("dn: cn=test,dc=example,dc=com\ncn: test\n")
    >>> if result.is_success:
    >>>     entries = result.unwrap()
    >>>
    >>> # Write LDIF content
    >>> write_result = ldif.write(entries)
    >>>
    >>> # Migrate between servers
    >>> migration_result = ldif.migrate(
    >>>     input_dir=Path("data/oid"),
    >>>     output_dir=Path("data/oud"),
    >>>     from_server="oid",
    >>>     to_server="oud"
    >>> )
    >>>
    >>> # Access models and configuration
    >>> entry = ldif.Models.Entry(dn="cn=test", attributes={})
    >>> config = ldif.config
    >>> constants = ldif.Constants
    >>>
    >>> # Use processors for batch operations
    >>> processors = ldif.Processors.create_processor()
    >>>
    >>> def validate_entry(entry: dict) -> FlextLdifTypes.Models.CustomDataDict:
    >>>     return entry
    >>>
    >>> reg_result = ldif.Processors.register_processor(
    ...     "validate", validate_entry, processors
    ... )
    >>> batch_result = ldif.Processors.process_entries_batch(
    ...     "validate", entries, processors
    ... )

Note:
    This library requires Python 3.13+ and flext-core 1.0.0+ for full functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.__version__ import __version__, __version_info__
from flext_ldif.api import FlextLdif
from flext_ldif.client import FlextLdifClient
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.events import (
    LdifMigratedEvent,
    LdifParsedEvent,
    LdifValidatedEvent,
    LdifWrittenEvent,
)
from flext_ldif.filters import FlextLdifFilters
from flext_ldif.models import FlextLdifModels
from flext_ldif.pipelines.categorized_pipeline import (
    FlextLdifCategorizedMigrationPipeline,
)
from flext_ldif.pipelines.migration_pipeline import FlextLdifMigrationPipeline
from flext_ldif.processors.ldif_processor import (
    FlextLdifBatchProcessor,
    FlextLdifParallelProcessor,
)
from flext_ldif.quirks.conversion_matrix import FlextLdifQuirksConversionMatrix
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.services.dn_service import FlextLdifDnService
from flext_ldif.services.validation_service import FlextLdifValidationService
from flext_ldif.typings import FlextLdifTypes

__email__ = "dev@flext.com"

__all__ = [
    "FlextLdif",
    "FlextLdifBatchProcessor",
    "FlextLdifCategorizedMigrationPipeline",
    "FlextLdifClient",
    "FlextLdifConfig",
    "FlextLdifConstants",
    "FlextLdifDnService",
    "FlextLdifFilters",
    "FlextLdifMigrationPipeline",
    "FlextLdifModels",
    "FlextLdifParallelProcessor",
    "FlextLdifQuirksConversionMatrix",
    "FlextLdifQuirksRegistry",
    "FlextLdifTypes",
    "FlextLdifValidationService",
    "LdifMigratedEvent",
    "LdifParsedEvent",
    "LdifValidatedEvent",
    "LdifWrittenEvent",
    "__version__",
    "__version_info__",
]
