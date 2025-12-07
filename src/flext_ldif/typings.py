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
    from flext_ldif.protocols import FlextLdifProtocols
    def process(data: p.Ldif.Quirks.EntryProtocol) -> None: ...
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import ClassVar, TypedDict, TypeVar

from flext_core import FlextTypes, r

from flext_ldif.constants import c
from flext_ldif.protocols import p

# Use FlextTypes internally to reference base types from flext-core
# This is redefined at end of file as t = FlextLdifTypes for exports

# Model type aliases moved to nested classes to follow FLEXT standards

# =========================================================================
# MODEL TYPEVARS - For models with validation metadata (module-level)
# =========================================================================
# TypeVars must be at module level (not inside class) for proper generic usage

FlextLdifModelT = TypeVar(
    "FlextLdifModelT", bound=p.Ldif.Constants.ModelWithValidationMetadata
)
"""TypeVar for models that have validation_metadata attribute.

Bound to ModelWithValidationMetadata protocol from protocols.py.
Used in metadata utilities for type-safe model operations.
"""


class FlextLdifTypes(FlextTypes):
    """Official type aliases for flext-ldif domain.

    Inherits from FlextTypes to access all base types like:
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
        from flext_ldif.protocols import FlextLdifProtocols
        # Access types directly via protocols for quirks
        def process(data: p.Ldif.Quirks.EntryProtocol) -> None: ...
        def parse(metadata: t.MetadataAttributeValue) -> None: ...
        # Compose with t.GeneralValueType when needed
                from flext_core import FlextTypes as core_t
        def generic(value: core_t.GeneralValueType) -> None: ...
    """

    class Ldif:
        """LDIF types namespace for cross-project access.

        Provides organized access to all LDIF types for other FLEXT projects.
        Usage: Other projects can reference `t.Ldif.Models.Entry`, `t.Ldif.Entry.EntryAttrs`, etc.
        This enables consistent namespace patterns for cross-project type access.

        Examples:
            from flext_ldap.typings import t
            entry_type: t.Ldif.Models.Entry = ...
            attrs: t.Ldif.Entry.EntryAttrs = ...

        """

        class Models:
            """Model type aliases using protocols to avoid circular imports.

            These aliases provide structural typing interfaces for domain models
            without depending on concrete model implementations.

            For concrete model classes (LdifAttributes, DistinguishedName, etc.),
            use the aliases below which reference FlextLdifModels.
            These are assigned at module level after class definition to avoid
            circular imports.
            """

            # Protocol-based model aliases (avoid circular imports)
            type Entry = p.Ldif.Models.EntryProtocol
            """Entry model protocol for structural typing."""

            type Acl = p.Ldif.Models.AclProtocol
            """ACL model protocol for structural typing."""

            type SchemaAttribute = p.Ldif.Models.SchemaAttributeProtocol
            """Schema attribute model protocol for structural typing."""

            type SchemaObjectClass = p.Ldif.Models.SchemaObjectClassProtocol
            """Schema object class model protocol for structural typing."""

            type ServiceResponseTypes = (
                p.Ldif.Services.UnifiedParseResultProtocol
                | p.Ldif.Services.UnifiedWriteResultProtocol
                | p.Ldif.Services.EntryResultProtocol
                | p.Ldif.Services.HasEntriesProtocol
                | list[p.Ldif.Models.EntryProtocol]
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

            # Concrete model type aliases (assigned at module level after class definition)
            # These reference FlextLdifModels to avoid circular imports
            LdifAttributes: ClassVar[type]
            """LDIF attribute collection model."""

            DistinguishedName: ClassVar[type]
            """Distinguished name model."""

            QuirkMetadata: ClassVar[type]
            """Quirk metadata model."""

            ParseResponse: ClassVar[type]
            """Parse response model."""

        # =========================================================================
        # QUIRK INSTANCE TYPES - Union type for DI flexibility
        # =========================================================================

        type QuirkInstanceType = (
            p.Ldif.Quirks.SchemaProtocol
            | p.Ldif.Quirks.AclProtocol
            | p.Ldif.Quirks.EntryProtocol
        )
        """Union type for quirk instances enabling Dependency Injection.

        Uses Protocols instead of concrete classes to enable Dependency Injection:
        - Protocol-compliant implementations can be injected
        - Enables testing with mocks and stubs
        - Allows runtime substitution of implementations
        - Follows SOLID principles (Dependency Inversion)

        For specific quirk types, use the protocols directly:
        - p.Ldif.Quirks.SchemaProtocol
        - p.Ldif.Quirks.AclProtocol
        - p.Ldif.Quirks.EntryProtocol

        Usage in DI:
            def process(quirk: FlextLdifTypes.QuirkInstanceType) -> None:
                # Works with any quirk implementation (RFC, OID, OUD, etc.)
                result = quirk.parse(...)
        """

        # Convenience type aliases for specific quirk protocols (used in services and tests)
        type SchemaQuirk = p.Ldif.Quirks.SchemaProtocol
        """Type alias for schema quirk protocol.

        Use this type for schema quirk instances.
        """

        type AclQuirk = p.Ldif.Quirks.AclProtocol
        """Type alias for ACL quirk protocol.

        Use this type for ACL quirk instances.
        """

        type EntryQuirk = p.Ldif.Quirks.EntryProtocol
        """Type alias for entry quirk protocol.

        Use this type for entry quirk instances.
        """

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
            list[FlextLdifTypes.Ldif.Models.Entry] | "FlextLdifTypes.Ldif.Models.Entry"
        )
        """Type alias for write operation inputs - concrete Entry models.

        Business context: LDIF writing from single entry or list of entries.
        Uses protocol-based Entry model for flexibility.
        """

        type FlexibleParseOutput = list[FlextLdifTypes.Ldif.Models.Entry]
        """Type alias for parse operation outputs - concrete Entry models.

        Business context: LDIF parsing results (list of entries).
        """

        # FlexibleWriteOutput removed - use str directly per rule 12 (no simple aliases)

        type AclOrString = str | p.Ldif.Models.AclProtocol
        """Type alias for ACL inputs that can be string or Acl model.

        Business context: ACL processing (parse from string or use Acl model).
        Uses AclProtocol to avoid circular imports with models.py.
        """

        type EntryOrString = FlextLdifTypes.Ldif.Models.Entry | str
        """Type alias for entry or string - concrete Entry model.

        Business context: Entry processing (parse from string or use Entry model).
        """

        # =========================================================================
        # RESULT TYPE ALIASES - For common FlextResult return types
        # =========================================================================

        type ParseResult = r[
            "FlextLdifTypes.Ldif.Models.Entry"
            | list[FlextLdifTypes.Ldif.Models.Entry]
            | "p.Ldif.Services.HasEntriesProtocol"
            | str
        ]
        """Type alias for parse operation results."""

        type WriteResult = r[str | p.Ldif.Services.HasContentProtocol]
        """Type alias for write operation results."""

        type UnifiedParseResult = r[p.Ldif.Services.UnifiedParseResultProtocol]
        """Type alias for unified parse results that support get_entries()."""

        type UnifiedWriteResult = r[p.Ldif.Services.UnifiedWriteResultProtocol]
        """Type alias for unified write results that support get_content()."""

        # =========================================================================
        # OPERATION RESULT TYPES - For operation unwrapping
        # =========================================================================

        type OperationUnwrappedResult = (
            FlextLdifTypes.Ldif.Models.SchemaAttribute
            | FlextLdifTypes.Ldif.Models.SchemaObjectClass
            | FlextLdifTypes.Ldif.Models.Acl
            | list[FlextLdifTypes.Ldif.Models.Entry]
            | str
        )
        """Type alias for unwrapped operation results."""

        type ConversionUnwrappedResult = (
            FlextLdifTypes.Ldif.Models.SchemaAttribute
            | FlextLdifTypes.Ldif.Models.SchemaObjectClass
            | FlextLdifTypes.Ldif.Models.Acl
            | FlextLdifTypes.Ldif.Models.Entry
            | str
        )
        """Type alias for unwrapped conversion results."""

        # =========================================================================
        # INPUT TYPES - For flexible API inputs
        # =========================================================================

        type SchemaModel = (
            FlextLdifTypes.Ldif.Models.SchemaAttribute
            | FlextLdifTypes.Ldif.Models.SchemaObjectClass
        )
        """Type alias for schema models (attribute or objectClass)."""

        # SchemaOrObjectClass removed - use SchemaModel directly per rule 12 (no duplicates)

        type SchemaModelOrString = SchemaModel | str
        """Type alias for schema model or string."""

        type ConvertibleModel = (
            FlextLdifTypes.Ldif.Models.Entry
            | FlextLdifTypes.Ldif.Models.SchemaAttribute
            | FlextLdifTypes.Ldif.Models.SchemaObjectClass
            | FlextLdifTypes.Ldif.Models.Acl
        )
        """Type alias for models that can be converted between servers."""

        # DN.DnInput removed - use str directly per rule 12 (no simple aliases)

        # QuirksPort kept - domain-specific protocol interface
        type QuirksPort = p.Ldif.Quirks.QuirksPort
        """Type alias for the complete quirks port interface."""

        # ServiceTypes class removed - use Models.ServiceResponseTypes directly
        # per rule 12 (no duplicates)

        # =========================================================================
        # ENTRY TYPES - For entry-related operations
        # =========================================================================

        class Entry:
            """Entry-related type aliases."""

            type EntryOrList = (
                "FlextLdifTypes.Ldif.Models.Entry"
                | list[FlextLdifTypes.Ldif.Models.Entry]
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

            Composes with t.ScalarValue for primitive values.
            Extends with list[str] and nested dicts for entry-specific structures.
            """

        # =========================================================================
        # SCHEMA ELEMENT TYPES - For schema processing
        # =========================================================================

        class Schema:
            """Schema-related type aliases."""

            type SchemaElement = (
                p.Ldif.Models.SchemaAttributeProtocol
                | p.Ldif.Models.SchemaObjectClassProtocol
                | str
                | int
                | float
                | bool
                | None
            )
            """Type alias for schema elements that can be stored in schema maps.

            Uses protocol-based types to avoid circular imports with models.py.
            """

            class SchemaDict(TypedDict):
                """Type for schema extraction result dictionary.

                Replaces dict[str, object] with specific structure.
                Contains ATTRIBUTES and OBJECTCLASS keys from extract_schemas_from_ldif().
                """

                ATTRIBUTES: list[p.Ldif.Models.SchemaAttributeProtocol]
                OBJECTCLASS: list[p.Ldif.Models.SchemaObjectClassProtocol]

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
            Reuses t.Types pattern (Mapping for read-only).
            Format: {category: count}
            """

        class Acl:
            """ACL-related type aliases."""

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

        type MetadataDict = Mapping[str, FlextTypes.MetadataAttributeValue]
        """Type alias for metadata dictionaries using collections.ABC.Mapping (read-only).

        Use this for function parameters where metadata should not be modified.
        For mutable metadata, use dict[str, MetadataAttributeValue] instead.
        Uses t.MetadataAttributeValue directly (no alias).
        """

        type MetadataDictMutable = dict[str, FlextTypes.MetadataAttributeValue]
        """Type alias for mutable metadata dictionaries.

        Use this when metadata needs to be modified.
        For read-only metadata, use MetadataDict (Mapping) instead.
        Uses FlextTypes.MetadataAttributeValue directly (no alias).
        """

        type TemplateValue = FlextTypes.ScalarValue | list[str]
        """Type alias for template data values (header templates, etc.).

        Composes with t.ScalarValue for primitive types.
        Extends with list[str] for template-specific list values.
        """

        type AttributeMetadataDict = dict[str, str | list[str]]
        """Type alias for per-attribute metadata (status, deleted_at, etc.)."""

        type AttributeMetadataMap = dict[str, dict[str, str | list[str]]]
        """Type alias for attribute name -> metadata dict mapping."""

        type ConversionHistory = dict[str, FlextTypes.ScalarValue | list[str]]
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
                p.Ldif.Quirks.SchemaProtocol
                | p.Ldif.Quirks.AclProtocol
                | p.Ldif.Quirks.EntryProtocol
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
                quirks_by_server: dict[
                    str, FlextLdifTypes.Ldif.Registry.QuirksByServerDict
                ]
                server_priorities: dict[str, int]

        # Services class removed - use p.Ldif.Services.* protocols directly per rule 12:
        # - p.Ldif.Services.HasParseMethodProtocol for schema/entry/acl services
        # - p.Ldif.Services.FilterServiceProtocol for filter services
        # - p.Ldif.Services.CategorizationServiceProtocol for categorization services

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

        type FlexibleKwargsMutable = dict[
            str, str | int | float | bool | list[str] | None
        ]
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
                write_options: p.Ldif.Models.WriteFormatOptionsProtocol

            type AclParseContext = dict[str, FlextTypes.ScalarValue | list[str]]
            """Type alias for ACL parsing context dictionaries.

            Composes with t.ScalarValue for primitive values.
            Extends with list[str] for ACL-specific list values.
            """

            type ParsedAttributeDict = dict[
                str,
                FlextTypes.ScalarValue
                | list[str]
                | dict[str, FlextTypes.ScalarValue | list[str]],
            ]
            """Type alias for parsed schema attribute dictionary.

            Composes with t.ScalarValue for primitive values.
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

            Composes with t.ScalarValue for primitive values.
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
            Uses t.MetadataAttributeValue directly (no alias).
            """

            type ExtensionsDictMutable = dict[str, FlextTypes.MetadataAttributeValue]
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

        class Conversion:
            """Conversion-related type aliases for conversion operations."""

            type ConversionHistory = dict[
                str,
                FlextTypes.ScalarValue
                | list[str]
                | dict[str, FlextTypes.ScalarValue | list[str]],
            ]
            """Type alias for conversion history tracking.

            Composes with t.ScalarValue for primitive values.
            Extends with list[str] and nested dicts for conversion-specific structures.
            Replaces dict[str, object] with specific structure.
            """

        # =========================================================================
        # LITERAL TYPES - Reusing constants from c.LiteralTypes
        # =========================================================================
        # Centralized reuse of Literal types from constants.py
        # All Literal types are derived from StrEnum values in constants.py
        # This ensures single source of truth and avoids duplication

        class LiteralTypes(c.Ldif.LiteralTypes):
            """Literal type aliases reusing constants from c.Ldif.LiteralTypes.

            Business Rule: All Literal types MUST be derived from StrEnum values
            defined in c. This ensures:
            - Single source of truth (constants.py)
            - Type safety through Literal types
            - Consistency across the codebase
            - Proper domain specialization (LDIF-specific types)

            Architecture: Inheritance pattern
            - Inherits all Literal types from c.LiteralTypes
            - No redeclaration - all types available through inheritance
            - Extends only if needed for domain-specific Literal types
            - Maintains proper domain boundaries (no duplication)

            Usage Pattern:
                from flext_ldif.typings import t
                def process(server_type: t.LiteralTypes.ServerTypeLiteral) -> None: ...
                def validate(level: t.LiteralTypes.ValidationLevelLiteral) -> None: ...
            """

            # All Literal types are inherited from c.LiteralTypes
            # No need to redeclare - they are all available through inheritance
            # Only add new Literal types here if they are LDIF-specific and not in constants

        # =========================================================================
        # LDIF NAMESPACE - For cross-project access pattern consistency
        # =========================================================================
        # Provides a .Ldif. namespace class for accessing LDIF types from other projects
        # Similar pattern to flext-core's .Core. namespace
        # This enables consistent namespace patterns (e.g., .Ldif., .Ldap., .Core.)


t = FlextLdifTypes

__all__ = ["FlextLdifModelT", "FlextLdifTypes", "t"]
