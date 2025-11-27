"""LDIF Type Aliases and Definitions - Official type system for flext-ldif domain.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Defines FlextLdifTypes class containing all official type aliases for the flext-ldif domain.
These types are used throughout the codebase to reduce complexity and avoid type guards/casts.

Refactored to use:
- Python 3.13 `type` statement for type aliases
- flext-core TypeVars instead of local definitions
- Specific types instead of `object` violations

**Usage Pattern:**
    from flext_ldif import FlextLdifTypes
    def process(data: FlextLdifTypes.EntryQuirkInstance) -> None: ...
"""

from __future__ import annotations

from pathlib import Path

from flext_core import FlextResult
from flext_core.typings import T  # Reuse TypeVar from flext-core

from flext_ldif.protocols import FlextLdifProtocols


class FlextLdifTypes:
    """Official type aliases for flext-ldif domain.

    These aliases reduce code complexity by providing precise types instead of generic 'object'.
    They should be used in src/ code to avoid type guards and casts.

    Refactored with Python 3.13 type statement syntax.
    """

    # =========================================================================
    # QUIRK INSTANCE TYPES - For official quirk implementations
    # =========================================================================

    type SchemaQuirkInstance = FlextLdifProtocols.Quirks.SchemaProtocol
    """Type alias for schema quirk instances that satisfy SchemaProtocol."""

    type AclQuirkInstance = FlextLdifProtocols.Quirks.AclProtocol
    """Type alias for ACL quirk instances that satisfy AclProtocol."""

    type EntryQuirkInstance = FlextLdifProtocols.Quirks.EntryProtocol
    """Type alias for entry quirk instances that satisfy EntryProtocol."""

    type QuirkInstanceType = (
        FlextLdifProtocols.Quirks.SchemaProtocol
        | FlextLdifProtocols.Quirks.AclProtocol
        | FlextLdifProtocols.Quirks.EntryProtocol
    )
    """Type alias for quirk instance types.

    Uses Protocols instead of concrete classes to enable Dependency Injection:
    - Any implementation satisfying the protocol can be injected
    - Enables testing with mocks and stubs
    - Allows runtime substitution of implementations
    - Follows SOLID principles (Dependency Inversion)

    Usage in DI:
        def process(quirk: FlextLdifTypes.QuirkInstanceType) -> None:
            # Works with any quirk implementation (RFC, OID, OUD, etc.)
            result = quirk.parse(...)
    """

    # =========================================================================
    # TYPE ALIASES - From types.py consolidation
    # =========================================================================

    type AclQuirk = FlextLdifProtocols.Quirks.AclProtocol
    """Type alias for ACL quirk instances."""

    type EntryQuirk = FlextLdifProtocols.Quirks.EntryProtocol
    """Type alias for entry quirk instances."""

    type SchemaQuirk = FlextLdifProtocols.Quirks.SchemaProtocol
    """Type alias for schema quirk instances."""

    type ModelInstance = FlextLdifProtocols.Models.EntryProtocol
    """Type alias for model instances - uses EntryProtocol instead of object."""

    # =========================================================================
    # FLEXIBLE INPUT/OUTPUT TYPES - For API flexibility
    # =========================================================================

    type FlexibleParseInput = str | Path
    """Type alias for parse operation inputs."""

    type FlexibleWriteInput = (
        list[FlextLdifProtocols.Models.EntryProtocol]
        | FlextLdifProtocols.Models.EntryProtocol
    )
    """Type alias for write operation inputs."""

    type FlexibleParseOutput = list[FlextLdifProtocols.Models.EntryProtocol]
    """Type alias for parse operation outputs."""

    type FlexibleWriteOutput = str
    """Type alias for write operation outputs."""

    type AclOrString = str | FlextLdifProtocols.Models.AclProtocol
    """Type alias for ACL inputs that can be string or Acl model."""

    type EntryOrString = FlextLdifProtocols.Models.EntryProtocol | str
    """Type alias for entry or string input."""

    # =========================================================================
    # RESULT TYPE ALIASES - For common FlextResult return types
    # =========================================================================

    type ParseResult = FlextResult[
        FlextLdifProtocols.Models.EntryProtocol
        | list[FlextLdifProtocols.Models.EntryProtocol]
        | FlextLdifProtocols.Services.HasEntriesProtocol
        | str
    ]
    """Type alias for parse operation results."""

    type WriteResult = FlextResult[
        str | FlextLdifProtocols.Services.HasContentProtocol
    ]
    """Type alias for write operation results."""

    type UnifiedParseResult = FlextResult[
        FlextLdifProtocols.Services.UnifiedParseResultProtocol
    ]
    """Type alias for unified parse results that support get_entries()."""

    type UnifiedWriteResult = FlextResult[
        FlextLdifProtocols.Services.UnifiedWriteResultProtocol
    ]
    """Type alias for unified write results that support get_content()."""

    # =========================================================================
    # OPERATION RESULT TYPES - For operation unwrapping
    # =========================================================================

    type OperationUnwrappedResult = (
        FlextLdifProtocols.Models.SchemaAttributeProtocol
        | FlextLdifProtocols.Models.SchemaObjectClassProtocol
        | FlextLdifProtocols.Models.AclProtocol
        | list[FlextLdifProtocols.Models.EntryProtocol]
        | str
    )
    """Type alias for unwrapped operation results."""

    type ConversionUnwrappedResult = (
        FlextLdifProtocols.Models.SchemaAttributeProtocol
        | FlextLdifProtocols.Models.SchemaObjectClassProtocol
        | FlextLdifProtocols.Models.AclProtocol
        | FlextLdifProtocols.Models.EntryProtocol
        | str
    )
    """Type alias for unwrapped conversion results."""

    # =========================================================================
    # INPUT TYPES - For flexible API inputs
    # =========================================================================

    type SchemaModel = (
        FlextLdifProtocols.Models.SchemaAttributeProtocol
        | FlextLdifProtocols.Models.SchemaObjectClassProtocol
    )
    """Type alias for schema models (attribute or objectClass)."""

    type SchemaOrObjectClass = (
        FlextLdifProtocols.Models.SchemaAttributeProtocol
        | FlextLdifProtocols.Models.SchemaObjectClassProtocol
    )
    """Type alias for schema attribute or object class (alias for SchemaModel)."""

    type SchemaModelOrString = SchemaModel | str
    """Type alias for schema model or string."""

    type ConvertibleModel = (
        FlextLdifProtocols.Models.EntryProtocol
        | FlextLdifProtocols.Models.SchemaAttributeProtocol
        | FlextLdifProtocols.Models.SchemaObjectClassProtocol
        | FlextLdifProtocols.Models.AclProtocol
    )
    """Type alias for models that can be converted between servers."""

    type DnInput = str
    """Type alias for DN input strings."""

    type QuirksPort = FlextLdifProtocols.Quirks.QuirksPort
    """Type alias for the complete quirks port interface."""

    # =========================================================================
    # SERVICE RESPONSE TYPES - For service return types
    # =========================================================================

    class Models:
        """Nested class for model-related type aliases."""

        type ServiceResponseTypes = (
            FlextLdifProtocols.Services.UnifiedParseResultProtocol
            | FlextLdifProtocols.Services.UnifiedWriteResultProtocol
            | list[FlextLdifProtocols.Models.EntryProtocol]
            | str
        )
        """Type alias for service response types."""

    # =========================================================================
    # ENTRY TYPES - For entry-related operations
    # =========================================================================

    type EntryOrList = (
        FlextLdifProtocols.Models.EntryProtocol
        | list[FlextLdifProtocols.Models.EntryProtocol]
    )
    """Type alias for entry or list of entries."""

    # =========================================================================
    # COMMON DICT TYPES - For LDAP attribute dictionaries
    # =========================================================================

    class CommonDict:
        """Nested class for common dictionary type aliases."""

        type AttributeDict = dict[str, list[str]]
        """Type alias for LDAP attribute dictionaries."""

        type DistributionDict = dict[str, int]
        """Type alias for distribution dictionaries (e.g., objectClass counts)."""

    class Entry:
        """Nested class for entry-related type aliases."""

        type EntryCreateData = dict[str, str | list[str] | dict[str, list[str]]]
        """Type alias for entry creation data dictionaries.

        Changed from dict[str, object] to specific types.
        """

    # =========================================================================
    # METADATA TYPES - For model metadata
    # =========================================================================

    type MetadataValue = str | float | bool | list[str] | None
    """Type alias for dynamic metadata field values."""

    type AttributeMetadataDict = dict[str, str | list[str]]
    """Type alias for per-attribute metadata (status, deleted_at, etc.)."""

    type AttributeMetadataMap = dict[str, dict[str, str | list[str]]]
    """Type alias for attribute name -> metadata dict mapping."""

    type ConversionHistory = dict[str, str | int | list[str]]
    """Type alias for conversion history."""

    # =========================================================================
    # SERVER TYPES - For server initialization and configuration
    # =========================================================================

    class Server:
        """Nested class for server-related type aliases."""

        type ServerInitKwargs = dict[str, object]
        """Type alias for server initialization keyword arguments."""


# Re-export T from flext-core for backward compatibility
__all__ = ["FlextLdifTypes", "T"]
