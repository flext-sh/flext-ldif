"""LDIF Type Aliases and Definitions - Official type system for flext-ldif domain.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Defines FlextLdifTypes class containing all official type aliases for the
flext-ldif domain.
These types are used throughout the codebase to reduce complexity and avoid type guards.

Python 3.13+ strict features:
- PEP 695 type aliases (type keyword) - no TypeAlias
- collections.ABC for type hints (Mapping, Sequence, Callable)
- Specific types instead of `object` violations
- No backward compatibility with Python < 3.13

Refactored to use:
- Python 3.13 `type` statement for type aliases
- flext-core TypeVars instead of local definitions
- collections.ABC types (Mapping, Sequence) for read-only semantics
- Specific types instead of `object` violations

**Usage Pattern:**
    from flext_ldif import FlextLdifTypes
    from flext_ldif.protocols import p
    def process(data: p.Quirks.EntryProtocol) -> None: ...
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TypedDict, TypeVar

from flext_core import r, t as flext_core_t

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.protocols import p

# Temporary alias for flext_core_t used within class definitions below
# This is redefined at end of file as t = FlextLdifTypes for exports
# Use flext_core_t internally to reference base types from flext-core

# Model type aliases moved to nested classes to follow FLEXT standards

# =========================================================================
# MODEL TYPEVARS - For models with validation metadata (module-level)
# =========================================================================
# TypeVars must be at module level (not inside class) for proper generic usage

ModelT = TypeVar("ModelT", bound=p.Constants.ModelWithValidationMetadata)
"""TypeVar for models that have validation_metadata attribute.

Bound to ModelWithValidationMetadata protocol from protocols.py.
Used in metadata utilities for type-safe model operations.
"""


class FlextLdifTypes(flext_core_t):
    """Official type aliases for flext-ldif domain.

    Inherits from FlextTypes (t) to access all base types like:
    - t.GeneralValueType for generic recursive value types
    - t.ScalarValue for primitive scalar values
    - t.MetadataAttributeValue for metadata values
    - t.Metadata for metadata mappings

    These aliases reduce code complexity by providing precise types instead of
    generic 'object'. They should be used in src/ code to avoid type guards and
    casts.

    Architecture: Inheritance from FlextTypes
    - Inherits all base types from FlextTypes (MetadataAttributeValue,
      ScalarValue, etc.)
    - Extends with domain-specific types (LDIF quirks, entries, metadata)
    - All types organized in nested classes for better organization
    - Enables t.MetadataAttributeValue usage throughout flext-ldif

    Python 3.13+ strict features:
    - PEP 695 type aliases (type keyword)
    - collections.ABC types (Mapping, Sequence) for read-only semantics
    - No backward compatibility with Python < 3.13

    Usage Pattern:
        from flext_ldif.typings import t
        from flext_ldif.protocols import p
        # Access types directly via protocols for quirks
        def process(data: p.Quirks.EntryProtocol) -> None: ...
        def parse(metadata: t.MetadataAttributeValue) -> None: ...
        # Compose with t.GeneralValueType when needed
        from flext_core.typings import t as core_t
        def generic(value: core_t.GeneralValueType) -> None: ...
    """

    class Models:
        """Model type aliases using protocols to avoid circular imports.

        These aliases provide structural typing interfaces for domain models
        without depending on concrete model implementations.
        """

        # Protocol-based model aliases (avoid circular imports)
        type Entry = p.Models.EntryProtocol
        """Entry model protocol for structural typing."""

        type Acl = p.Models.AclProtocol
        """ACL model protocol for structural typing."""

        type SchemaAttribute = p.Models.SchemaAttributeProtocol
        """Schema attribute model protocol for structural typing."""

        type SchemaObjectClass = p.Models.SchemaObjectClassProtocol
        """Schema object class model protocol for structural typing."""

        type ServiceResponseTypes = (
            p.Services.UnifiedParseResultProtocol
            | p.Services.UnifiedWriteResultProtocol
            | p.Services.EntryResultProtocol
            | p.Services.HasEntriesProtocol
            | list[p.Models.EntryProtocol]
            | str
        )
        """Type alias for service response types.

        Business Rule: ServiceResponseTypes is a union type representing all valid
        response types from LDIF services. It includes:
        - UnifiedParseResultProtocol: Parse operations returning entries
        - UnifiedWriteResultProtocol: Write operations returning content string
        - EntryResultProtocol: Categorized entry results with statistics
        - HasEntriesProtocol: Simple entry containers
        - list[EntryProtocol]: Raw entry lists
        - str: Simple string responses

        Implication: Services should use this type for return values to ensure
        type-safe composition. EntryResult satisfies EntryResultProtocol through
        structural typing (duck typing).
        """

    # =========================================================================
    # QUIRK INSTANCE TYPES - Union type for DI flexibility
    # =========================================================================

    type QuirkInstanceType = (
        p.Quirks.SchemaProtocol | p.Quirks.AclProtocol | p.Quirks.EntryProtocol
    )
    """Union type for quirk instances enabling Dependency Injection.

    Uses Protocols instead of concrete classes to enable Dependency Injection:
    - Protocol-compliant implementations can be injected
    - Enables testing with mocks and stubs
    - Allows runtime substitution of implementations
    - Follows SOLID principles (Dependency Inversion)

    For specific quirk types, use the protocols directly:
    - p.Quirks.SchemaProtocol
    - p.Quirks.AclProtocol
    - p.Quirks.EntryProtocol

    Usage in DI:
        def process(quirk: FlextLdifTypes.QuirkInstanceType) -> None:
            # Works with any quirk implementation (RFC, OID, OUD, etc.)
            result = quirk.parse(...)
    """

    # Convenience type aliases for specific quirk protocols (used in services and tests)
    type SchemaQuirk = p.Quirks.SchemaProtocol
    """Type alias for schema quirk protocol."""

    type AclQuirk = p.Quirks.AclProtocol
    """Type alias for ACL quirk protocol."""

    type EntryQuirk = p.Quirks.EntryProtocol
    """Type alias for entry quirk protocol."""

    type SchemaQuirkInstance = p.Quirks.SchemaProtocol
    """Type alias for schema quirk instances (same as SchemaQuirk)."""

    type AclQuirkInstance = p.Quirks.AclProtocol
    """Type alias for ACL quirk instances (same as AclQuirk)."""

    type EntryQuirkInstance = p.Quirks.EntryProtocol
    """Type alias for entry quirk instances (same as EntryQuirk)."""

    # =========================================================================
    # FLEXIBLE INPUT/OUTPUT TYPES - For API flexibility
    # =========================================================================
    # Business context: LDIF API input/output flexibility (string, file, models)
    # Composes with t patterns for base types (str, Path)

    type FlexibleParseInput = str | Path
    """Type alias for parse operation inputs.

    Business context: LDIF parsing from string or file path.
    Composes with t patterns (str, Path from pathlib).
    """

    type FlexibleWriteInput = (
        list[FlextLdifTypes.Models.Entry] | "FlextLdifTypes.Models.Entry"
    )
    """Type alias for write operation inputs - concrete Entry models.

    Business context: LDIF writing from single entry or list of entries.
    Uses protocol-based Entry model for flexibility.
    """

    type FlexibleParseOutput = list[FlextLdifTypes.Models.Entry]
    """Type alias for parse operation outputs - concrete Entry models.

    Business context: LDIF parsing results (list of entries).
    """

    # FlexibleWriteOutput removed - use str directly per rule 12 (no simple aliases)

    type AclOrString = str | p.Models.AclProtocol
    """Type alias for ACL inputs that can be string or Acl model.

    Business context: ACL processing (parse from string or use Acl model).
    Uses AclProtocol to avoid circular imports with models.py.
    """

    type EntryOrString = FlextLdifTypes.Models.Entry | str
    """Type alias for entry or string - concrete Entry model.

    Business context: Entry processing (parse from string or use Entry model).
    """

    # =========================================================================
    # RESULT TYPE ALIASES - For common FlextResult return types
    # =========================================================================

    type ParseResult = r[
        "FlextLdifTypes.Models.Entry"
        | list[FlextLdifTypes.Models.Entry]
        | "p.Services.HasEntriesProtocol"
        | str
    ]
    """Type alias for parse operation results."""

    type WriteResult = r[str | p.Services.HasContentProtocol]
    """Type alias for write operation results."""

    type UnifiedParseResult = r[p.Services.UnifiedParseResultProtocol]
    """Type alias for unified parse results that support get_entries()."""

    type UnifiedWriteResult = r[p.Services.UnifiedWriteResultProtocol]
    """Type alias for unified write results that support get_content()."""

    # =========================================================================
    # OPERATION RESULT TYPES - For operation unwrapping
    # =========================================================================

    type OperationUnwrappedResult = (
        FlextLdifTypes.Models.SchemaAttribute
        | FlextLdifTypes.Models.SchemaObjectClass
        | FlextLdifTypes.Models.Acl
        | list[FlextLdifTypes.Models.Entry]
        | str
    )
    """Type alias for unwrapped operation results."""

    type ConversionUnwrappedResult = (
        FlextLdifTypes.Models.SchemaAttribute
        | FlextLdifTypes.Models.SchemaObjectClass
        | FlextLdifTypes.Models.Acl
        | FlextLdifTypes.Models.Entry
        | str
    )
    """Type alias for unwrapped conversion results."""

    # =========================================================================
    # INPUT TYPES - For flexible API inputs
    # =========================================================================

    type SchemaModel = (
        FlextLdifTypes.Models.SchemaAttribute | FlextLdifTypes.Models.SchemaObjectClass
    )
    """Type alias for schema models (attribute or objectClass)."""

    # SchemaOrObjectClass removed - use SchemaModel directly per rule 12 (no duplicates)

    type SchemaModelOrString = SchemaModel | str
    """Type alias for schema model or string."""

    type ConvertibleModel = (
        FlextLdifTypes.Models.Entry
        | FlextLdifTypes.Models.SchemaAttribute
        | FlextLdifTypes.Models.SchemaObjectClass
        | FlextLdifTypes.Models.Acl
    )
    """Type alias for models that can be converted between servers."""

    # DN.DnInput removed - use str directly per rule 12 (no simple aliases)

    # QuirksPort kept - domain-specific protocol interface
    type QuirksPort = p.Quirks.QuirksPort
    """Type alias for the complete quirks port interface."""

    # ServiceTypes class removed - use Models.ServiceResponseTypes directly
    # per rule 12 (no duplicates)

    # =========================================================================
    # ENTRY TYPES - For entry-related operations
    # =========================================================================

    class Entry:
        """Entry-related type aliases."""

        type EntryOrList = (
            "FlextLdifTypes.Models.Entry" | list[FlextLdifTypes.Models.Entry]
        )
        """Type alias for entry or list of entries."""

        type EntryAttrs = Mapping[str, list[str]]
        """Type alias for entry attributes dictionary (read-only Mapping).

        Business context: LDAP entry attribute structure used in parsing/writing.
        Format: {attribute_name: [value1, value2, ...]}
        Uses collections.ABC.Mapping for read-only semantics.
        """

        type EntryCreateData = dict[
            str,
            flext_core_t.ScalarValue | list[str] | dict[str, list[str]],
        ]
        """Type alias for entry creation data dictionaries.

        Composes with t.ScalarValue for primitive values.
        Extends with list[str] and nested dicts for entry-specific structures.
        """

    # =========================================================================
    # SCHEMA ELEMENT TYPES - For schema processing
    # =========================================================================

    class Schema:
        """Schema-related type aliases."""

        type SchemaElement = (
            p.Models.SchemaAttributeProtocol
            | p.Models.SchemaObjectClassProtocol
            | str
            | int
            | float
            | bool
            | None
        )
        """Type alias for schema elements that can be stored in schema maps.

        Uses protocol-based types to avoid circular imports with models.py.
        """

        type SchemaQuirkInstance = p.Quirks.SchemaProtocol
        """Type alias for schema quirk instances that satisfy SchemaProtocol."""

        class SchemaDict(TypedDict):
            """Type for schema extraction result dictionary.

            Replaces dict[str, object] with specific structure.
            Contains ATTRIBUTES and OBJECTCLASS keys from extract_schemas_from_ldif().
            """

            ATTRIBUTES: list[p.Models.SchemaAttributeProtocol]
            OBJECTCLASS: list[p.Models.SchemaObjectClassProtocol]

    # =========================================================================
    # COMMON DICT TYPES - For LDAP attribute dictionaries
    # =========================================================================

    class CommonDict:
        """Common dictionary type aliases for LDIF operations.

        Business context: LDAP attribute and distribution data structures used
        throughout LDIF processing. Reuses t.Types patterns for consistency.

        Uses collections.ABC types (Mapping, Sequence) for read-only semantics
        where appropriate (Python 3.13+ PEP 695 best practices).
        """

        type AttributeDict = dict[str, list[str]]
        """LDAP attribute dictionaries (mutable for compatibility).

        Business context: Core LDAP entry attribute structure used in parsing/writing.
        Format: {attribute_name: [value1, value2, ...]}
        """

        type AttributeDictReadOnly = Mapping[str, Sequence[str]]
        """Read-only attribute dictionary (Python 3.13+ collections.ABC).

        Business context: Function parameters that should not modify attributes.
        Reuses t.Types pattern (Mapping for read-only).
        Format: {attribute_name: [value1, value2, ...]}
        """

        type AttributeDictGeneric = Mapping[
            str,
            flext_core_t.ScalarValue
            | Sequence[str]
            | Sequence[flext_core_t.ScalarValue]
            | dict[str, flext_core_t.ScalarValue | Sequence[str]],
        ]
        """Generic read-only attribute dictionary for flexible attribute containers.

        Business context: Function parameters that accept various attribute formats
        (from LdifAttributes.attributes, dict-like containers, etc.).
        Replaces Mapping[str, object] with specific structure.
        Format: {attribute_name: value | [values] | {nested: values}}
        """

        type DistributionDict = dict[str, int]
        """Distribution dictionaries (e.g., objectClass counts).

        Business context: Statistical distributions used in LDIF analytics.
        Format: {category: count}
        """

        type DistributionDictReadOnly = Mapping[str, int]
        """Read-only distribution dictionary (Python 3.13+ collections.ABC).

        Business context: Function parameters that should not modify distributions.
        Reuses t.Types pattern (Mapping for read-only).
        Format: {category: count}
        """

    class Acl:
        """ACL-related type aliases."""

        type AclQuirkInstance = p.Quirks.AclProtocol
        """Type alias for ACL quirk instances that satisfy AclProtocol."""

        class PermissionsDict(TypedDict, total=False):
            """ACL permissions dictionary type."""

            read: bool
            write: bool
            add: bool
            delete: bool
            search: bool
            compare: bool
            self_write: bool
            proxy: bool
            browse: bool
            auth: bool
            all: bool

        class EvaluationContextDict(TypedDict, total=False):
            """ACL evaluation context dictionary type."""

            subject_dn: str
            target_dn: str
            operation: str
            attributes: list[str]

    # =========================================================================
    # METADATA TYPES - For model metadata
    # =========================================================================

    class TransformationInfo(TypedDict, total=False):
        """Transformation step information stored in metadata."""

        step: str
        server: str
        changes: list[str]

    # Nested metadata structures for conversion tracking (Python 3.13 type syntax)
    type BooleanConversionValue = dict[str, str | list[str]]
    """Type alias for boolean conversion entries.

    Format: {attr: {original: [...], converted: [...]}}
    """

    type BooleanConversionsMap = dict[str, BooleanConversionValue]
    """Type alias for full boolean conversions mapping {attr_name: {original:
    ..., converted: ...}}."""

    type AttributeNameConversionsMap = dict[str, str]
    """Type alias for attribute name conversions {original_name: target_name}."""

    type ConvertedAttributesData = dict[
        str,
        BooleanConversionsMap | AttributeNameConversionsMap | list[str],
    ]
    """Type alias for CONVERTED_ATTRIBUTES nested structure with multiple
    entry types."""

    type AttributeConflictEntry = dict[str, str | list[str]]
    """Type alias for attribute conflict entries."""

    # Metadata types - use t directly (no aliases per user requirement)
    # These are now defined generically in flext-core.t
    # Use t.MetadataAttributeValue and t.Metadata directly

    type MetadataDict = Mapping[str, flext_core_t.MetadataAttributeValue]
    """Type alias for metadata dictionaries using collections.ABC.Mapping (read-only).

    Use this for function parameters where metadata should not be modified.
    For mutable metadata, use dict[str, MetadataAttributeValue] instead.
    Uses t.MetadataAttributeValue directly (no alias).
    """

    type MetadataDictMutable = dict[str, flext_core_t.MetadataAttributeValue]
    """Type alias for mutable metadata dictionaries.

    Use this when metadata needs to be modified.
    For read-only metadata, use MetadataDict (Mapping) instead.
    Uses flext_core_t.MetadataAttributeValue directly (no alias).
    """

    type TemplateValue = flext_core_t.ScalarValue | list[str]
    """Type alias for template data values (header templates, etc.).

    Composes with t.ScalarValue for primitive types.
    Extends with list[str] for template-specific list values.
    """

    type AttributeMetadataDict = dict[str, str | list[str]]
    """Type alias for per-attribute metadata (status, deleted_at, etc.)."""

    type AttributeMetadataMap = dict[str, dict[str, str | list[str]]]
    """Type alias for attribute name -> metadata dict mapping."""

    type ConversionHistory = dict[str, flext_core_t.ScalarValue | list[str]]
    """Type alias for conversion history.

    Composes with t.ScalarValue for primitive values.
    Extends with list[str] for conversion-specific list values.
    """

    # =========================================================================
    # SERVER TYPES - For server initialization and configuration
    # =========================================================================

    class Server:
        """Nested class for server-related type aliases."""

        type ServerInitKwargs = dict[str, str | int | bool | list[str] | None]
        """Type alias for server initialization keyword arguments."""

    # =========================================================================
    # REGISTRY TYPES - For quirk registry operations
    # =========================================================================

    class Registry:
        """Nested class for registry-related type aliases."""

        type QuirksDict = dict[
            str,
            p.Quirks.SchemaProtocol
            | p.Quirks.AclProtocol
            | p.Quirks.EntryProtocol
            | None,
        ]
        """Type alias for quirks dictionary returned by get_all_quirks."""

        class QuirksByServerDict(TypedDict, total=False):
            """Type for quirks_by_server dictionary in registry stats."""

            schema: str | None
            acl: str | None
            entry: str | None

        class RegistryStatsDict(TypedDict):
            """Type for registry statistics dictionary.

            Replaces dict[str, object] with specific structure.
            """

            total_servers: int
            quirks_by_server: dict[str, FlextLdifTypes.Registry.QuirksByServerDict]
            server_priorities: dict[str, int]

    # Services class removed - use p.Services.* protocols directly per rule 12:
    # - p.Services.HasParseMethodProtocol for schema/entry/acl services
    # - p.Services.FilterServiceProtocol for filter services
    # - p.Services.CategorizationServiceProtocol for categorization services

    # =========================================================================
    # DN VALUE TYPES - For DN extraction and handling
    # =========================================================================

    # DnValue removed - use str directly per user requirement

    # =========================================================================
    # KWARGS TYPES - For flexible keyword arguments
    # =========================================================================

    type FlexibleKwargs = Mapping[str, str | int | float | bool | list[str] | None]
    """Type alias for flexible keyword arguments (read-only Mapping).

    Use this for function parameters that accept flexible configuration.
    For mutable kwargs, use FlexibleKwargsMutable.
    """

    type FlexibleKwargsMutable = dict[str, str | int | float | bool | list[str] | None]
    """Type alias for mutable flexible keyword arguments (dict).

    Use this for **kwargs parameters that need to be modified.
    For read-only kwargs, use FlexibleKwargs (Mapping).
    """

    # =========================================================================
    # MODEL METADATA TYPES - For parsing and writing context dicts
    # =========================================================================

    class ModelMetadata:
        """Nested class for model metadata type aliases used in parsing/writing."""

        class EntryParsingContext(TypedDict, total=False):
            """TypedDict for entry parsing context with specific fields.

            Uses TypedDict for type safety while maintaining dict flexibility.
            All fields are optional (total=False) to support incremental building.
            """

            original_entry_dn: str
            cleaned_dn: str
            original_dn_line: str | None
            original_attr_lines: list[str] | None
            dn_was_base64: bool
            original_attribute_case: dict[str, str] | None
            dn_differences: (
                dict[str, flext_core_t.MetadataAttributeValue]
                | dict[str, dict[str, flext_core_t.MetadataAttributeValue]]
                | None
            )
            attribute_differences: (
                dict[str, flext_core_t.MetadataAttributeValue]
                | dict[str, dict[str, flext_core_t.MetadataAttributeValue]]
                | None
            )
            original_attributes_complete: (
                dict[str, flext_core_t.MetadataAttributeValue] | None
            )

        class AttributeWriteContext(TypedDict, total=False):
            """TypedDict for attribute write context with specific fields.

            Uses TypedDict for type safety while maintaining dict flexibility.
            All fields are optional (total=False) to support incremental building.
            """

            attr_name: str
            attr_values: flext_core_t.GeneralValueType
            minimal_differences_attrs: dict[str, flext_core_t.MetadataAttributeValue]
            hidden_attrs: set[str]
            write_options: p.Models.WriteFormatOptionsProtocol

        type AclParseContext = dict[str, flext_core_t.ScalarValue | list[str]]
        """Type alias for ACL parsing context dictionaries.

        Composes with t.ScalarValue for primitive values.
        Extends with list[str] for ACL-specific list values.
        """

        type ParsedAttributeDict = dict[
            str,
            flext_core_t.ScalarValue
            | list[str]
            | dict[str, flext_core_t.ScalarValue | list[str]],
        ]
        """Type alias for parsed schema attribute dictionary.

        Composes with t.ScalarValue for primitive values.
        Extends with list[str] and nested dicts for schema-specific structures.
        Includes nested dicts for metadata_extensions and syntax_validation.
        """

        type ParsedObjectClassDict = dict[
            str,
            flext_core_t.ScalarValue
            | list[str]
            | dict[str, flext_core_t.ScalarValue | list[str]],
        ]
        """Type alias for parsed schema objectClass dictionary.

        Composes with t.ScalarValue for primitive values.
        Extends with list[str] and nested dicts for schema-specific structures.
        Includes nested dict for metadata_extensions.
        """

    # =========================================================================
    # EXTENSIONS AND METADATA TYPES - For quirk extensions and metadata
    # =========================================================================

    class Extensions:
        """Nested class for extension-related type aliases."""

        type ExtensionsDict = dict[str, flext_core_t.MetadataAttributeValue]
        """Type alias for quirk metadata extensions dictionary.

        Replaces dict[str, object] with specific MetadataAttributeValue type.
        Used in QuirkMetadata.extensions and server-specific extensions.
        Uses t.MetadataAttributeValue directly (no alias).
        """

        type ExtensionsDictMutable = dict[str, flext_core_t.MetadataAttributeValue]
        """Type alias for mutable extensions dictionary.

        Use this when extensions need to be modified.
        For read-only extensions, use ExtensionsDict (Mapping) instead.
        Uses t.MetadataAttributeValue directly (no alias).
        """

    # =========================================================================
    # SCHEMA TYPES - For schema extraction and processing
    # =========================================================================

    # =========================================================================
    # MIGRATION TYPES - For migration configuration and rules
    # =========================================================================

    class Migration:
        """Nested class for migration-related type aliases."""

        type MigrationConfigDict = dict[
            str,
            flext_core_t.ScalarValue
            | list[str]
            | dict[str, flext_core_t.ScalarValue | list[str]],
        ]
        """Type for MigrationConfig dictionary input.

        Replaces dict[str, object] with specific structure.
        Used when MigrationConfig is passed as dict for validation.
        """

        type CategoryRulesDict = dict[
            str,
            flext_core_t.ScalarValue
            | list[str]
            | frozenset[str]
            | dict[str, flext_core_t.ScalarValue | list[str] | frozenset[str]],
        ]
        """Type for CategoryRules dictionary input.

        Replaces dict[str, object] with specific structure.
        Used when CategoryRules is passed as dict for validation.
        """

        type WriteFormatOptionsDict = dict[
            str,
            flext_core_t.ScalarValue
            | list[str]
            | frozenset[str]
            | dict[str, flext_core_t.ScalarValue | list[str]],
        ]
        """Type for WriteFormatOptions dictionary input.

        Replaces dict[str, object] with specific structure.
        Used when WriteFormatOptions is passed as dict for validation.
        """

        type WhitelistRulesDict = dict[
            str,
            flext_core_t.ScalarValue
            | list[str]
            | frozenset[str]
            | dict[str, flext_core_t.ScalarValue | list[str] | frozenset[str]],
        ]
        """Type for WhitelistRules dictionary input.

        Replaces dict[str, object] with specific structure.
        Used when WhitelistRules is passed as dict for validation.
        """

    # =========================================================================
    # RESULT EXTRACTORS - Utility class for extracting data from FlextResult
    # =========================================================================

    class ResultExtractors:
        """Utility class for extracting data from unwrapped operation results.

        Uses protocol-based isinstance checks for proper type narrowing without casts.
        All protocols are runtime_checkable, enabling isinstance() validation.
        """

        @staticmethod
        def extract_entries(
            value: FlextLdifTypes.Models.Entry
            | list[FlextLdifTypes.Models.Entry]
            | p.Services.HasEntriesProtocol
            | str,
        ) -> list[FlextLdifTypes.Models.Entry]:
            """Extract entries from an unwrapped result value.

            Handles multiple result types:
            - Single Entry or list[Entry]
            - HasEntriesProtocol (with entries property)
            - String results (returns empty list)

            Args:
                value: Unwrapped result value containing entry data

            Returns:
                List of entries

            """
            if isinstance(value, str):
                return []

            if isinstance(value, list):
                return value

            # Use protocol-based isinstance check (all protocols are runtime_checkable)
            if isinstance(value, p.Services.HasEntriesProtocol):
                # Protocol guarantees entries property exists and returns
                # Sequence[EntryProtocol]
                # Since Models.Entry = EntryProtocol, Sequence[EntryProtocol]
                # is compatible with list[Models.Entry]
                protocol_value: p.Services.HasEntriesProtocol = value
                entries_sequence: Sequence[FlextLdifTypes.Models.Entry] = (
                    protocol_value.entries
                )
                # Convert Sequence to list
                return list(entries_sequence)

            # At this point, value must be Entry (type narrowed by elimination)
            # No cast needed - type checker knows this is Models.Entry
            return [value]

        @staticmethod
        def extract_content(
            value: str | p.Services.HasContentProtocol,
        ) -> str:
            """Extract content string from an unwrapped result value.

            Handles multiple result types:
            - String content directly
            - HasContentProtocol (with content property)

            Args:
                value: Unwrapped result value containing content data

            Returns:
                String content

            Raises:
                ValueError: If content cannot be extracted

            """
            if isinstance(value, str):
                return value

            # Type narrowed: value must be HasContentProtocol at this point
            # Protocol guarantees content property exists
            content = value.content
            # content can be str | None per protocol, handle None case
            if content is None:
                return ""
            return content

    class MetadataTypes:
        """Metadata-related type aliases for backward compatibility."""

        # Keep for existing code that expects these types
        type AttributeMetadataMap = dict[str, dict[str, str | list[str]]]
        type MetadataDictMutable = dict[str, flext_core_t.MetadataAttributeValue]

    class Conversion:
        """Conversion-related type aliases for conversion operations."""

        type ConversionHistory = dict[
            str,
            flext_core_t.ScalarValue
            | list[str]
            | dict[str, flext_core_t.ScalarValue | list[str]],
        ]
        """Type alias for conversion history tracking.

        Composes with t.ScalarValue for primitive values.
        Extends with list[str] and nested dicts for conversion-specific structures.
        Replaces dict[str, object] with specific structure.
        """

    # =========================================================================
    # LITERAL TYPES - Reusing constants from FlextLdifConstants.LiteralTypes
    # =========================================================================
    # Centralized reuse of Literal types from constants.py
    # All Literal types are derived from StrEnum values in constants.py
    # This ensures single source of truth and avoids duplication

    class LiteralTypes(FlextLdifConstants.LiteralTypes):
        """Literal type aliases reusing constants from FlextLdifConstants.LiteralTypes.

        Business Rule: All Literal types MUST be derived from StrEnum values
        defined in FlextLdifConstants. This ensures:
        - Single source of truth (constants.py)
        - Type safety through Literal types
        - Consistency across the codebase
        - Proper domain specialization (LDIF-specific types)

        Architecture: Inheritance pattern
        - Inherits all Literal types from FlextLdifConstants.LiteralTypes
        - No redeclaration - all types available through inheritance
        - Extends only if needed for domain-specific Literal types
        - Maintains proper domain boundaries (no duplication)

        Usage Pattern:
            from flext_ldif.typings import t
            def process(server_type: t.LiteralTypes.ServerTypeLiteral) -> None: ...
            def validate(level: t.LiteralTypes.ValidationLevelLiteral) -> None: ...
        """

        # All Literal types are inherited from FlextLdifConstants.LiteralTypes
        # No need to redeclare - they are all available through inheritance
        # Only add new Literal types here if they are LDIF-specific and not in constants


# Direct access: use FlextLdifTypes directly
# Short alias for FlextLdifTypes
t = FlextLdifTypes
__all__ = ["FlextLdifTypes", "ModelT", "t"]
