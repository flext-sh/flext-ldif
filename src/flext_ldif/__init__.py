"""FLEXT-LDIF - LDIF Processing Library.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextContainer, FlextResult
from flext_ldif import acl, entry, quirks, schema
from flext_ldif.acl import FlextLdifAclParser, FlextLdifAclService
from flext_ldif.acls_coordinator import FlextLdifAcls
from flext_ldif.api import FlextLdifAPI
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.entries_coordinator import FlextLdifEntries
from flext_ldif.entry import FlextLdifEntryBuilder
from flext_ldif.exceptions import FlextLdifExceptions
from flext_ldif.management import FlextLdifManagement
from flext_ldif.mixins import FlextLdifMixins
from flext_ldif.models import FlextLdifModels
from flext_ldif.parser import FlextLdifParser
from flext_ldif.processor import FlextLdifProcessor
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.quirks import (
    FlextLdifEntryQuirks,
    FlextLdifQuirksAdapter,
    FlextLdifQuirksManager,
    constants as quirks_constants,
)
from flext_ldif.quirks_coordinator import FlextLdifQuirks
from flext_ldif.schema import (
    FlextLdifObjectClassManager,
    FlextLdifSchemaBuilder,
    FlextLdifSchemaExtractor,
    FlextLdifSchemaValidator,
)
from flext_ldif.schemas_coordinator import FlextLdifSchemas
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


def configure_container() -> None:
    """Configure FlextContainer with all LDIF services and coordinators."""
    container = FlextContainer.get_global()

    # Register coordinators
    container.register("schemas", FlextLdifSchemas())
    container.register("entries", FlextLdifEntries())
    container.register("acls", FlextLdifAcls())
    container.register("quirks", FlextLdifQuirks())

    # Register management coordinator
    container.register("management", FlextLdifManagement())

    # Register processor
    container.register("processor", FlextLdifProcessor())

    # Register API
    container.register("api", FlextLdifAPI())


def get_ldif_management() -> object:
    """Get configured LDIF management instance via FlextContainer.

    Returns:
        Configured management coordinator

    """
    result: FlextResult[object] = FlextContainer.get_global().get("management")
    if result.is_success:
        return result.value
    error_msg = f"Failed to get management: {result.error}"
    raise RuntimeError(error_msg)


# Auto-configure container on module import
# Note: Disabled to avoid circular imports - call configure_container() explicitly if needed
# configure_container()


__all__ = [
    # === MAIN API ===
    "FlextLdifAPI",  # High-level API
    # === IMPLEMENTATION MODULES (from subdirectories) ===
    # ACL
    "FlextLdifAclParser",
    "FlextLdifAclService",
    # === COORDINATORS (Primary API) ===
    "FlextLdifAcls",  # ACL operations coordinator
    # === MODELS AND CONFIG ===
    "FlextLdifConfig",  # Configuration
    "FlextLdifConstants",  # Constants
    "FlextLdifEntries",  # Entry operations coordinator
    # Entry
    "FlextLdifEntryBuilder",
    # Quirks
    "FlextLdifEntryQuirks",
    # === UTILITIES ===
    "FlextLdifExceptions",
    "FlextLdifManagement",
    "FlextLdifMixins",
    "FlextLdifModels",  # Domain models
    # Schema
    "FlextLdifObjectClassManager",
    "FlextLdifParser",
    "FlextLdifProcessor",  # LDIF processor
    "FlextLdifProtocols",
    "FlextLdifQuirks",  # Quirks operations coordinator
    "FlextLdifQuirksAdapter",
    "FlextLdifQuirksManager",
    "FlextLdifSchemaBuilder",
    "FlextLdifSchemaExtractor",
    "FlextLdifSchemaValidator",
    "FlextLdifSchemas",  # Schema operations coordinator
    "FlextLdifTypes",  # Type definitions
    "FlextLdifUtilities",
    # === MODULE EXPORTS ===
    "acl",
    # === HELPER FUNCTIONS ===
    "configure_container",
    "entry",
    "get_ldif_management",
    "quirks",
    "quirks_constants",
    "schema",
]

# Version information
__version__ = "0.9.0"
__author__ = "FLEXT Development Team"
__email__ = "dev@flext.com"
__license__ = "MIT"
