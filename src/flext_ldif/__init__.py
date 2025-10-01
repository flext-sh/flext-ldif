r"""FLEXT-LDIF - RFC-First LDIF Processing Library with flext-core 1.0.0 Integration.

This library provides RFC-compliant LDIF processing with a unified facade API,
leveraging flext-core 1.0.0 patterns for enterprise-grade reliability.

Main Features:
- Unified FlextLdif facade for all LDIF operations
- RFC 2849/4512 compliant parsing and writing
- Server-specific quirks system (OID, OUD, OpenLDAP, etc.)
- Generic server-agnostic migration pipeline
- Type-safe Pydantic v2 models
- CQRS pattern with FlextDispatcher and FlextRegistry
- FlextProcessors integration for batch and parallel processing
- Railway-oriented error handling with FlextResult

flext-core 1.0.0 Integration:
- FlextResult for monadic error composition
- FlextDispatcher for CQRS orchestration
- FlextRegistry for handler registration
- FlextProcessors for data transformations
- FlextContainer for dependency injection
- FlextBus for domain event emission
- FlextLogger for structured logging

Usage:
    from flext_ldif import FlextLdif
    from pathlib import Path

    # Initialize facade
    ldif = FlextLdif()

    # Parse LDIF with FlextResult
    result = ldif.parse("dn: cn=test,dc=example,dc=com\ncn: test\n")
    if result.is_success:
        entries = result.unwrap()

    # Write LDIF
    write_result = ldif.write(entries)

    # Migrate between servers
    migration_result = ldif.migrate(
        input_dir=Path("data/oid"),
        output_dir=Path("data/oud"),
        from_server="oid",
        to_server="oud"
    )

    # Access infrastructure
    entry = ldif.Models.Entry(dn="cn=test", attributes={})
    config = ldif.Config
    constants = ldif.Constants

    # FlextProcessors for batch processing
    processors = ldif.Processors.create_processor()

    def validate_entry(entry: dict) -> dict:
        # Validation logic
        return entry

    reg_result = ldif.Processors.register_processor("validate", validate_entry, processors)
    batch_result = ldif.Processors.process_entries_batch("validate", entries, processors)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# Main API Facade - Single Entry Point
from flext_ldif.api import FlextLdif
from flext_ldif.handlers import FlextLdifHandlers

# RFC-First Architecture Components
from flext_ldif.migration_pipeline import LdifMigrationPipelineService
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.registry import QuirkRegistryService

__all__ = [
    "FlextLdif",
    "FlextLdifHandlers",
    "FlextLdifModels",
    "LdifMigrationPipelineService",
    "QuirkRegistryService",
]

# Version information
__version__ = "0.9.0"
__author__ = "FLEXT Development Team"
__email__ = "dev@flext.com"
__license__ = "MIT"
