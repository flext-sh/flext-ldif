"""LDIF Type Aliases and Definitions - Official type system for flext-ldif domain.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Defines FlextLdifTypes class containing all official type aliases for the flext-ldif domain.
These types are used throughout the codebase to reduce complexity and avoid type guards/casts.

**Usage Pattern:**
    from flext_ldif import FlextLdifTypes
    def process(data: FlextLdifTypes.EntryQuirkInstance) -> None: ...
"""

from __future__ import annotations

from pathlib import Path
from typing import TypeAlias

from flext_core import FlextResult

from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols


class FlextLdifTypes:
    """Official type aliases for flext-ldif domain.

    These aliases reduce code complexity by providing precise types instead of generic 'object'.
    They should be used in src/ code to avoid type guards and casts.
    """

    # =========================================================================
    # QUIRK INSTANCE TYPES - For official quirk implementations
    # =========================================================================

    SchemaQuirkInstance: TypeAlias = FlextLdifProtocols.Quirks.SchemaProtocol
    """Type alias for schema quirk instances that satisfy SchemaProtocol."""

    AclQuirkInstance: TypeAlias = FlextLdifProtocols.Quirks.AclProtocol
    """Type alias for ACL quirk instances that satisfy AclProtocol."""

    EntryQuirkInstance: TypeAlias = FlextLdifProtocols.Quirks.EntryProtocol
    """Type alias for entry quirk instances that satisfy EntryProtocol."""

    # Union type for quirk instances - Protocol-based for DI compatibility
    QuirkInstanceType: TypeAlias = (
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

    AclQuirk: TypeAlias = FlextLdifProtocols.Quirks.AclProtocol
    """Type alias for ACL quirk instances."""

    EntryQuirk: TypeAlias = FlextLdifProtocols.Quirks.EntryProtocol
    """Type alias for entry quirk instances."""

    ModelInstance: TypeAlias = object
    """Type alias for generic model instances."""

    SchemaQuirk: TypeAlias = FlextLdifProtocols.Quirks.SchemaProtocol
    """Type alias for schema quirk instances."""

    # =========================================================================
    # FLEXIBLE INPUT/OUTPUT TYPES - For API flexibility
    # =========================================================================

    FlexibleParseInput: TypeAlias = str | Path
    """Type alias for parse operation inputs."""

    FlexibleWriteInput: TypeAlias = list[FlextLdifModels.Entry] | FlextLdifModels.Entry
    """Type alias for write operation inputs."""

    FlexibleParseOutput: TypeAlias = list[FlextLdifModels.Entry]
    """Type alias for parse operation outputs."""

    FlexibleWriteOutput: TypeAlias = str
    """Type alias for write operation outputs."""

    AclOrString: TypeAlias = str | FlextLdifModels.Acl
    """Type alias for ACL inputs that can be string or Acl model."""

    EntryOrString: TypeAlias = FlextLdifModels.Entry | str
    """Type alias for entry or string input."""

    # =========================================================================
    # RESULT TYPE ALIASES - For common FlextResult return types
    # =========================================================================

    ParseResult: TypeAlias = FlextResult[
        FlextLdifModels.Entry
        | list[FlextLdifModels.Entry]
        | FlextLdifProtocols.Services.HasEntriesProtocol
        | str
    ]
    """Type alias for parse operation results."""

    WriteResult: TypeAlias = FlextResult[
        str | FlextLdifProtocols.Services.HasContentProtocol
    ]
    """Type alias for write operation results."""

    UnifiedParseResult: TypeAlias = FlextResult[
        FlextLdifProtocols.Services.UnifiedParseResultProtocol
    ]
    """Type alias for unified parse results that support get_entries()."""

    UnifiedWriteResult: TypeAlias = FlextResult[
        FlextLdifProtocols.Services.UnifiedWriteResultProtocol
    ]
    """Type alias for unified write results that support get_content()."""

    # =========================================================================
    # OPERATION RESULT TYPES - For operation unwrapping
    # =========================================================================

    OperationUnwrappedResult: TypeAlias = (
        FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | FlextLdifModels.Acl
        | list[FlextLdifModels.Entry]
        | str
    )
    """Type alias for unwrapped operation results."""

    ConversionUnwrappedResult: TypeAlias = (
        FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | FlextLdifModels.Acl
        | FlextLdifModels.Entry
        | str
    )
    """Type alias for unwrapped conversion results."""

    # =========================================================================
    # UTILITY FUNCTIONS - For type-safe result extraction
    # =========================================================================

    class ResultExtractors:
        """Utility functions for extracting data from various result types.

        Reduces isinstance checks and custom conversion code in tests and services.
        """

        @staticmethod
        def extract_entries(result: object) -> list[FlextLdifModels.Entry]:
            """Extract entries from any parse result type.

            Args:
                result: Parse result (ParseResponse, list[Entry], Entry, etc.)

            Returns:
                List of entries

            Raises:
                ValueError: If result type is not supported

            """
            if isinstance(
                result, FlextLdifProtocols.Services.UnifiedParseResultProtocol
            ):
                return result.get_entries()
            if isinstance(result, FlextLdifProtocols.Services.HasEntriesProtocol):
                return result.entries
            if isinstance(result, list):
                return [
                    entry
                    for entry in result
                    if isinstance(entry, FlextLdifModels.Entry)
                ]
            if isinstance(result, FlextLdifModels.Entry):
                return [result]
            msg = f"Unsupported result type for entry extraction: {type(result)}"
            raise ValueError(msg)

        @staticmethod
        def extract_content(result: object) -> str:
            """Extract content from any write result type.

            Args:
                result: Write result (WriteResponse, str, etc.)

            Returns:
                Written content as string

            Raises:
                ValueError: If result type is not supported

            """
            if isinstance(
                result, FlextLdifProtocols.Services.UnifiedWriteResultProtocol
            ):
                return result.get_content()
            if isinstance(result, FlextLdifProtocols.Services.HasContentProtocol):
                return result.content or ""
            if isinstance(result, str):
                return result
            msg = f"Unsupported result type for content extraction: {type(result)}"
            raise ValueError(msg)

    # =========================================================================
    # INPUT TYPES - For flexible API inputs
    # =========================================================================

    SchemaModel: TypeAlias = (
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
    )
    """Type alias for schema models (attribute or objectClass)."""

    SchemaOrObjectClass: TypeAlias = (
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
    )
    """Type alias for schema attribute or object class (alias for SchemaModel)."""

    SchemaModelOrString: TypeAlias = SchemaModel | str
    """Type alias for schema model or string."""

    ConvertibleModel: TypeAlias = (
        FlextLdifModels.Entry
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | FlextLdifModels.Acl
    )
    """Type alias for models that can be converted between servers."""

    DnInput: TypeAlias = str
    """Type alias for DN input strings."""

    QuirksPort: TypeAlias = FlextLdifProtocols.Quirks.QuirksPort
    """Type alias for the complete quirks port interface."""

    # =========================================================================
    # SERVICE RESPONSE TYPES - For service return types
    # =========================================================================

    class Models:
        """Nested class for model-related type aliases."""

        ServiceResponseTypes: TypeAlias = (
            FlextLdifModels.ParseResponse
            | FlextLdifModels.WriteResponse
            | FlextLdifModels.EntryResult
            | list[FlextLdifModels.Entry]
            | str
        )
        """Type alias for service response types."""

    # =========================================================================
    # ENTRY TYPES - For entry-related operations
    # =========================================================================

    EntryOrList: TypeAlias = FlextLdifModels.Entry | list[FlextLdifModels.Entry]
    """Type alias for entry or list of entries."""

    # =========================================================================
    # COMMON DICT TYPES - For LDAP attribute dictionaries
    # =========================================================================

    class CommonDict:
        """Nested class for common dictionary type aliases."""

        AttributeDict: TypeAlias = dict[str, list[str]]
        """Type alias for LDAP attribute dictionaries."""

        DistributionDict: TypeAlias = dict[str, int]
        """Type alias for distribution dictionaries (e.g., objectClass counts)."""

    class Entry:
        """Nested class for entry-related type aliases."""

        EntryCreateData: TypeAlias = dict[str, str | list[str] | dict[str, object]]
        """Type alias for entry creation data dictionaries."""
