"""LDIF Type Aliases and Definitions - Official type system for flext-ldif domain.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Defines FlextLdifTypes class containing all official type aliases for the flext-ldif domain.
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
    def process(data: FlextLdifTypes.EntryQuirkInstance) -> None: ...
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TypedDict, TypeVar

from flext_core import FlextResult
from flext_core.typings import FlextTypes, T  # Reuse TypeVar from flext-core

# Import models facade for concrete types (avoiding circular imports via facade)
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols

# Model type aliases moved to nested classes to follow FLEXT standards

# =========================================================================
# MODEL TYPEVARS - For models with validation metadata (module-level)
# =========================================================================
# TypeVars must be at module level (not inside class) for proper generic usage

ModelT = TypeVar(
    "ModelT", bound=FlextLdifProtocols.Constants.ModelWithValidationMetadata
)
"""TypeVar for models that have validation_metadata attribute.

Bound to ModelWithValidationMetadata protocol from protocols.py.
Used in metadata utilities for type-safe model operations.
"""


class FlextLdifTypes:
    """Official type aliases for flext-ldif domain.

    Composes with FlextTypes base types (FlextTypes.GeneralValueType, ScalarValue, etc.)
    when appropriate, while maintaining domain-specific types aligned to business needs.

    These aliases reduce code complexity by providing precise types instead of generic 'object'.
    They should be used in src/ code to avoid type guards and casts.

    Architecture: Composition (not inheritance)
    - Composes with FlextTypes.GeneralValueType (imported from flext_core.typings) for generic recursive value types
    - Composes with FlextTypes.ScalarValue for primitive scalar values
    - Defines domain-specific types (LDIF quirks, entries, metadata) aligned to business logic
    - All types organized in nested classes for better organization
    - No inheritance - only composition to maintain separation of concerns

    Python 3.13+ strict features:
    - PEP 695 type aliases (type keyword)
    - collections.ABC types (Mapping, Sequence) for read-only semantics
    - No backward compatibility with Python < 3.13

    Usage Pattern:
        from flext_ldif.typings import FlextLdifTypes
        # Access types directly from class
        def process(data: FlextLdifTypes.EntryQuirkInstance) -> None: ...
        def parse(metadata: "FlextTypes.MetadataAttributeValue") -> None: ...
        # Compose with FlextTypes.GeneralValueType when needed
        from flext_core.typings import FlextTypes
        def generic(value: FlextTypes.GeneralValueType) -> None: ...
    """

    class Models:
        """Model type aliases using protocols to avoid circular imports.

        These aliases provide structural typing interfaces for domain models
        without depending on concrete model implementations.
        """

        # Protocol-based model aliases (avoid circular imports)
        type Entry = FlextLdifProtocols.Models.EntryProtocol
        """Entry model protocol for structural typing."""

        type Acl = FlextLdifProtocols.Models.AclProtocol
        """ACL model protocol for structural typing."""

        type SchemaAttribute = FlextLdifProtocols.Models.SchemaAttributeProtocol
        """Schema attribute model protocol for structural typing."""

        type SchemaObjectClass = FlextLdifProtocols.Models.SchemaObjectClassProtocol
        """Schema object class model protocol for structural typing."""

        type ServiceResponseTypes = (
            FlextLdifProtocols.Services.UnifiedParseResultProtocol
            | FlextLdifProtocols.Services.UnifiedWriteResultProtocol
            | FlextLdifProtocols.Services.EntryResultProtocol
            | FlextLdifProtocols.Services.HasEntriesProtocol
            | list[FlextLdifProtocols.Models.EntryProtocol]
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
    - Protocol-compliant implementations can be injected
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

    # ScalarValue removed - use FlextTypes.ScalarValue directly
    # This alias was removed per user requirement to eliminate simple aliases

    type AclQuirk = FlextLdifProtocols.Quirks.AclProtocol
    """Type alias for ACL quirk instances."""

    type EntryQuirk = FlextLdifProtocols.Quirks.EntryProtocol
    """Type alias for entry quirk instances."""

    type SchemaQuirk = FlextLdifProtocols.Quirks.SchemaProtocol
    """Type alias for schema quirk instances."""

    type ModelInstance = FlextLdifTypes.Models.Entry
    """Type alias for model instances - uses Entry instead of object."""

    # =========================================================================
    # FLEXIBLE INPUT/OUTPUT TYPES - For API flexibility
    # =========================================================================
    # Business context: LDIF API input/output flexibility (string, file, models)
    # Composes with FlextTypes patterns for base types (str, Path)

    type FlexibleParseInput = str | Path
    """Type alias for parse operation inputs.

    Business context: LDIF parsing from string or file path.
    Composes with FlextTypes patterns (str, Path from pathlib).
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

    type FlexibleWriteOutput = str
    """Type alias for write operation outputs.

    Business context: LDIF writing results (LDIF string format).
    Composes with FlextTypes.StringValue pattern.
    """

    type AclOrString = str | FlextLdifModels.Acl
    """Type alias for ACL inputs that can be string or Acl model.

    Business context: ACL processing (parse from string or use Acl model).
    Uses concrete Acl model (FlextLdifModels.Acl) for type safety and compatibility
    with base class method signatures.
    """

    type EntryOrString = FlextLdifTypes.Models.Entry | str
    """Type alias for entry or string - concrete Entry model.

    Business context: Entry processing (parse from string or use Entry model).
    """

    # =========================================================================
    # RESULT TYPE ALIASES - For common FlextResult return types
    # =========================================================================

    type ParseResult = FlextResult[
        "FlextLdifTypes.Models.Entry"
        | list[FlextLdifTypes.Models.Entry]
        | "FlextLdifProtocols.Services.HasEntriesProtocol"
        | str
    ]
    """Type alias for parse operation results."""

    type WriteResult = FlextResult[str | FlextLdifProtocols.Services.HasContentProtocol]
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

    type SchemaOrObjectClass = (
        FlextLdifTypes.Models.SchemaAttribute | FlextLdifTypes.Models.SchemaObjectClass
    )
    """Type alias for schema attribute or object class (alias for SchemaModel)."""

    type SchemaModelOrString = SchemaModel | str
    """Type alias for schema model or string."""

    type ConvertibleModel = (
        FlextLdifTypes.Models.Entry
        | FlextLdifTypes.Models.SchemaAttribute
        | FlextLdifTypes.Models.SchemaObjectClass
        | FlextLdifTypes.Models.Acl
    )
    """Type alias for models that can be converted between servers."""

    # =========================================================================
    # DN INPUT TYPES - For DN operations
    # =========================================================================

    class DN:
        """DN-related type aliases."""

        type DnInput = str
        """Type alias for DN input values (string representation)."""

    # QuirksPort kept - domain-specific protocol interface
    type QuirksPort = FlextLdifProtocols.Quirks.QuirksPort
    """Type alias for the complete quirks port interface."""

    # =========================================================================
    # SERVICE RESPONSE TYPES - For service return types
    # =========================================================================

    class ServiceTypes:
        """Nested class for service-related type aliases.

        Note: ServiceResponseTypes is also available in FlextLdifTypes.Models
        for backward compatibility. Prefer using FlextLdifTypes.Models.ServiceResponseTypes
        as the canonical location.
        """

        type ServiceResponseTypes = (
            FlextLdifProtocols.Services.UnifiedParseResultProtocol
            | FlextLdifProtocols.Services.UnifiedWriteResultProtocol
            | FlextLdifProtocols.Services.EntryResultProtocol
            | FlextLdifProtocols.Services.HasEntriesProtocol
            | list[FlextLdifProtocols.Models.EntryProtocol]
            | str
        )
        """Type alias for service response types (alias of Models.ServiceResponseTypes)."""

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
            FlextTypes.ScalarValue | list[str] | dict[str, list[str]],
        ]
        """Type alias for entry creation data dictionaries.

        Composes with FlextTypes.ScalarValue for primitive values.
        Extends with list[str] and nested dicts for entry-specific structures.
        """

    # =========================================================================
    # SCHEMA ELEMENT TYPES - For schema processing
    # =========================================================================

    class Schema:
        """Schema-related type aliases."""

        type SchemaElement = (
            FlextLdifProtocols.Models.SchemaAttributeProtocol
            | FlextLdifProtocols.Models.SchemaObjectClassProtocol
            | str
            | int
            | float
            | bool
            | None
        )
        """Type alias for schema elements that can be stored in schema maps.

        Uses protocol-based types to avoid circular imports with models.py.
        """

        type SchemaQuirkInstance = FlextLdifProtocols.Quirks.SchemaProtocol
        """Type alias for schema quirk instances that satisfy SchemaProtocol."""

        class SchemaDict(TypedDict):
            """Type for schema extraction result dictionary.

            Replaces dict[str, object] with specific structure.
            Contains ATTRIBUTES and OBJECTCLASS keys from extract_schemas_from_ldif().
            """

            ATTRIBUTES: list[FlextLdifProtocols.Models.SchemaAttributeProtocol]
            OBJECTCLASS: list[FlextLdifProtocols.Models.SchemaObjectClassProtocol]

    # =========================================================================
    # COMMON DICT TYPES - For LDAP attribute dictionaries
    # =========================================================================

    class CommonDict:
        """Common dictionary type aliases for LDIF operations.

        Business context: LDAP attribute and distribution data structures used
        throughout LDIF processing. Reuses FlextTypes.Types patterns for consistency.

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
        Reuses FlextTypes.Types pattern (Mapping for read-only).
        Format: {attribute_name: [value1, value2, ...]}
        """

        type AttributeDictGeneric = Mapping[
            str,
            FlextTypes.ScalarValue
            | Sequence[str]
            | Sequence[FlextTypes.ScalarValue]
            | dict[str, FlextTypes.ScalarValue | Sequence[str]],
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
        Reuses FlextTypes.Types pattern (Mapping for read-only).
        Format: {category: count}
        """

    class Acl:
        """ACL-related type aliases."""

        type AclQuirkInstance = FlextLdifProtocols.Quirks.AclProtocol
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
    """Type alias for boolean conversion entries {attr: {original: [...], converted: [...]}}."""

    type BooleanConversionsMap = dict[str, BooleanConversionValue]
    """Type alias for full boolean conversions mapping {attr_name: {original: ..., converted: ...}}."""

    type AttributeNameConversionsMap = dict[str, str]
    """Type alias for attribute name conversions {original_name: target_name}."""

    type ConvertedAttributesData = dict[
        str,
        BooleanConversionsMap | AttributeNameConversionsMap | list[str],
    ]
    """Type alias for CONVERTED_ATTRIBUTES nested structure with multiple entry types."""

    type AttributeConflictEntry = dict[str, str | list[str]]
    """Type alias for attribute conflict entries."""

    # Metadata types - use FlextTypes directly (no aliases per user requirement)
    # These are now defined generically in flext-core.FlextTypes
    # Use FlextTypes.MetadataAttributeValue and FlextTypes.Metadata directly

    type MetadataDict = Mapping[str, FlextTypes.MetadataAttributeValue]
    """Type alias for metadata dictionaries using collections.ABC.Mapping (read-only).

    Use this for function parameters where metadata should not be modified.
    For mutable metadata, use dict[str, MetadataAttributeValue] instead.
    Uses FlextTypes.MetadataAttributeValue directly (no alias).
    """

    type MetadataDictMutable = dict[str, FlextTypes.MetadataAttributeValue]
    """Type alias for mutable metadata dictionaries.

    Use this when metadata needs to be modified.
    For read-only metadata, use MetadataDict (Mapping) instead.
    Uses FlextTypes.MetadataAttributeValue directly (no alias).
    """

    type TemplateValue = FlextTypes.ScalarValue | list[str]
    """Type alias for template data values (header templates, etc.).

    Composes with FlextTypes.ScalarValue for primitive types.
    Extends with list[str] for template-specific list values.
    """

    type AttributeMetadataDict = dict[str, str | list[str]]
    """Type alias for per-attribute metadata (status, deleted_at, etc.)."""

    type AttributeMetadataMap = dict[str, dict[str, str | list[str]]]
    """Type alias for attribute name -> metadata dict mapping."""

    type ConversionHistory = dict[str, FlextTypes.ScalarValue | list[str]]
    """Type alias for conversion history.

    Composes with FlextTypes.ScalarValue for primitive values.
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
            FlextLdifProtocols.Quirks.SchemaProtocol
            | FlextLdifProtocols.Quirks.AclProtocol
            | FlextLdifProtocols.Quirks.EntryProtocol
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

    # =========================================================================
    # SERVICE TYPES - For service protocol types
    # =========================================================================

    class Services:
        """Nested class for service-related type aliases."""

        type SchemaService = FlextLdifProtocols.Services.HasParseMethodProtocol
        """Type alias for schema service protocol."""

        type EntryService = FlextLdifProtocols.Services.HasParseMethodProtocol
        """Type alias for entry service protocol."""

        type AclService = FlextLdifProtocols.Services.HasParseMethodProtocol
        """Type alias for ACL service protocol."""

        type FilterService = FlextLdifProtocols.Services.FilterServiceProtocol
        """Type alias for filter service protocol."""

        type CategorizationService = (
            FlextLdifProtocols.Services.CategorizationServiceProtocol
        )
        """Type alias for categorization service protocol."""

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
                dict[str, FlextTypes.MetadataAttributeValue]
                | dict[str, dict[str, FlextTypes.MetadataAttributeValue]]
                | None
            )
            attribute_differences: (
                dict[str, FlextTypes.MetadataAttributeValue]
                | dict[str, dict[str, FlextTypes.MetadataAttributeValue]]
                | None
            )
            original_attributes_complete: (
                dict[str, FlextTypes.MetadataAttributeValue] | None
            )

        class AttributeWriteContext(TypedDict, total=False):
            """TypedDict for attribute write context with specific fields.

            Uses TypedDict for type safety while maintaining dict flexibility.
            All fields are optional (total=False) to support incremental building.
            """

            attr_name: str
            attr_values: FlextTypes.GeneralValueType
            minimal_differences_attrs: dict[str, FlextTypes.MetadataAttributeValue]
            hidden_attrs: set[str]
            write_options: object  # WriteFormatOptions - avoid circular import

        type AclParseContext = dict[str, FlextTypes.ScalarValue | list[str]]
        """Type alias for ACL parsing context dictionaries.

        Composes with FlextTypes.ScalarValue for primitive values.
        Extends with list[str] for ACL-specific list values.
        """

        type ParsedAttributeDict = dict[
            str,
            FlextTypes.ScalarValue
            | list[str]
            | dict[str, FlextTypes.ScalarValue | list[str]],
        ]
        """Type alias for parsed schema attribute dictionary.

        Composes with FlextTypes.ScalarValue for primitive values.
        Extends with list[str] and nested dicts for schema-specific structures.
        Includes nested dicts for metadata_extensions and syntax_validation.
        """

        type ParsedObjectClassDict = dict[
            str,
            FlextTypes.ScalarValue
            | list[str]
            | dict[str, FlextTypes.ScalarValue | list[str]],
        ]
        """Type alias for parsed schema objectClass dictionary.

        Composes with FlextTypes.ScalarValue for primitive values.
        Extends with list[str] and nested dicts for schema-specific structures.
        Includes nested dict for metadata_extensions.
        """

    # =========================================================================
    # EXTENSIONS AND METADATA TYPES - For quirk extensions and metadata
    # =========================================================================

    class Extensions:
        """Nested class for extension-related type aliases."""

        type ExtensionsDict = dict[str, FlextTypes.MetadataAttributeValue]
        """Type alias for quirk metadata extensions dictionary.

        Replaces dict[str, object] with specific MetadataAttributeValue type.
        Used in QuirkMetadata.extensions and server-specific extensions.
        Uses FlextTypes.MetadataAttributeValue directly (no alias).
        """

        type ExtensionsDictMutable = dict[str, FlextTypes.MetadataAttributeValue]
        """Type alias for mutable extensions dictionary.

        Use this when extensions need to be modified.
        For read-only extensions, use ExtensionsDict (Mapping) instead.
        Uses FlextTypes.MetadataAttributeValue directly (no alias).
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
            FlextTypes.ScalarValue
            | list[str]
            | dict[str, FlextTypes.ScalarValue | list[str]],
        ]
        """Type for MigrationConfig dictionary input.

        Replaces dict[str, object] with specific structure.
        Used when MigrationConfig is passed as dict for validation.
        """

        type CategoryRulesDict = dict[
            str,
            FlextTypes.ScalarValue
            | list[str]
            | frozenset[str]
            | dict[str, FlextTypes.ScalarValue | list[str] | frozenset[str]],
        ]
        """Type for CategoryRules dictionary input.

        Replaces dict[str, object] with specific structure.
        Used when CategoryRules is passed as dict for validation.
        """

        type WriteFormatOptionsDict = dict[
            str,
            FlextTypes.ScalarValue
            | list[str]
            | frozenset[str]
            | dict[str, FlextTypes.ScalarValue | list[str]],
        ]
        """Type for WriteFormatOptions dictionary input.

        Replaces dict[str, object] with specific structure.
        Used when WriteFormatOptions is passed as dict for validation.
        """

        type WhitelistRulesDict = dict[
            str,
            FlextTypes.ScalarValue
            | list[str]
            | frozenset[str]
            | dict[str, FlextTypes.ScalarValue | list[str] | frozenset[str]],
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
            | FlextLdifProtocols.Services.HasEntriesProtocol
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
            if isinstance(value, FlextLdifProtocols.Services.HasEntriesProtocol):
                # Protocol guarantees entries property exists and returns Sequence[EntryProtocol]
                # Since Models.Entry = EntryProtocol, Sequence[EntryProtocol] is compatible with list[Models.Entry]
                protocol_value: FlextLdifProtocols.Services.HasEntriesProtocol = value
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
            value: str | FlextLdifProtocols.Services.HasContentProtocol,
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
        type MetadataDictMutable = dict[str, FlextTypes.MetadataAttributeValue]

    class Conversion:
        """Conversion-related type aliases for conversion operations."""

        type ConversionHistory = dict[
            str,
            FlextTypes.ScalarValue
            | list[str]
            | dict[str, FlextTypes.ScalarValue | list[str]],
        ]
        """Type alias for conversion history tracking.

        Composes with FlextTypes.ScalarValue for primitive values.
        Extends with list[str] and nested dicts for conversion-specific structures.
        Replaces dict[str, object] with specific structure.
        """


# Re-export T from flext-core for backward compatibility
__all__ = ["FlextLdifTypes", "ModelT", "T"]
