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
    from flext_ldif.typings import FlextLdifTypes, t
    from flext_ldif.models import m  # Protocol types defined in models.py (Tier 1)
    # def process(data: m.Ldif.EntryProtocol) -> None: ...
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TypedDict

from flext_core import FlextTypes, r

# Use FlextTypes internally to reference base types from flext-core
# This is redefined at end of file as t = FlextLdifTypes for exports
#
# ARCHITECTURE NOTE: typings.py is Tier 0 (foundation) and cannot import from
# protocols.py (Tier 0) to avoid circular dependency. Instead:
# - typings.py defines base type aliases using strings (forward references)
# - protocols.py imports typings.py and defines protocol-based types
# - models.py (Tier 1) imports both typings.py and protocols.py and combines them

# Model type aliases moved to nested classes to follow FLEXT standards

# =========================================================================
# MODEL TYPEVARS - For models with validation metadata (module-level)
# =========================================================================
# TypeVars must be at module level (not inside class) for proper generic usage
# NOTE: TypeVar with protocol bounds is defined in models.py (Tier 1)
# because protocols.py is Tier 0 and cannot be imported here without circular deps


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
        from flext_ldif.models import m  # Protocol types defined in models.py (Tier 1)
        # Access types from models for quirks (protocols defined there)
        # def process(data: m.Ldif.EntryProtocol) -> None: ...
        def parse(metadata: t.MetadataAttributeValue) -> None: ...
        # Compose with t.GeneralValueType when needed
        from flext_core import FlextTypes as core_t
        def generic(value: core_t.GeneralValueType) -> None: ...
    """

    class Ldif:
        """LDIF types namespace for cross-project access.

        Provides organized access to all LDIF types for other FLEXT projects.
        Usage: Other projects can reference `t.Ldif.Entry`, `t.Ldif.Entry.EntryAttrs`, etc.
        This enables consistent namespace patterns for cross-project type access.

        Examples:
            from flext_ldap.typings import t
            entry_type: t.Ldif.Entry = ...
            attrs: t.Ldif.Entry.EntryAttrs = ...

        """

        # =========================================================================
        # QUIRK INSTANCE TYPES - Union type for DI flexibility
        # =========================================================================
        # NOTE: Protocol-based quirk types are defined in models.py (Tier 1)
        # because typings.py (Tier 0) cannot import protocols.py

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
            list[FlextLdifTypes.Ldif.Entry] | "FlextLdifTypes.Ldif.Entry"
        )
        """Type alias for write operation inputs - concrete Entry models.

        Business context: LDIF writing from single entry or list of entries.
        Uses protocol-based Entry model for flexibility.
        """

        type FlexibleParseOutput = list[FlextLdifTypes.Ldif.Entry]
        """Type alias for parse operation outputs - concrete Entry models.

        Business context: LDIF parsing results (list of entries).
        """

        # FlexibleWriteOutput removed - use str directly per rule 12 (no simple aliases)
        # AclOrString moved to models.py (Tier 1) to use protocol types

        type EntryOrString = FlextLdifTypes.Ldif.Entry | str
        """Type alias for entry or string - concrete Entry model.

        Business context: Entry processing (parse from string or use Entry model).
        """

        type AclOrString = object | str
        """Type alias for ACL or string - Acl model or raw ACL string.

        Business context: ACL processing (parse from string or use Acl model).
        NOTE: Uses object instead of concrete Acl type to avoid circular import.
        Concrete type alias available in models.py (Tier 1).
        """

        # =========================================================================
        # RESULT TYPE ALIASES - For common FlextResult return types
        # =========================================================================

        # Result types with protocol references moved to models.py (Tier 1)

        # =========================================================================
        # OPERATION RESULT TYPES - For operation unwrapping
        # =========================================================================

        type OperationUnwrappedResult = (
            FlextLdifTypes.Ldif.SchemaAttribute
            | FlextLdifTypes.Ldif.SchemaObjectClass
            | FlextLdifTypes.Ldif.Acl
            | list[FlextLdifTypes.Ldif.Entry]
            | str
        )
        """Type alias for unwrapped operation results."""

        type ConversionUnwrappedResult = (
            FlextLdifTypes.Ldif.SchemaAttribute
            | FlextLdifTypes.Ldif.SchemaObjectClass
            | FlextLdifTypes.Ldif.Acl
            | FlextLdifTypes.Ldif.Entry
            | str
        )
        """Type alias for unwrapped conversion results."""

        # =========================================================================
        # INPUT TYPES - For flexible API inputs
        # =========================================================================

        type SchemaModel = (
            FlextLdifTypes.Ldif.SchemaAttribute | FlextLdifTypes.Ldif.SchemaObjectClass
        )
        """Type alias for schema models (attribute or objectClass)."""

        # SchemaOrObjectClass removed - use SchemaModel directly per rule 12 (no duplicates)

        type SchemaModelOrString = SchemaModel | str
        """Type alias for schema model or string."""

        type ConvertibleModel = (
            FlextLdifTypes.Ldif.Entry
            | FlextLdifTypes.Ldif.SchemaAttribute
            | FlextLdifTypes.Ldif.SchemaObjectClass
            | FlextLdifTypes.Ldif.Acl
        )
        """Type alias for models that can be converted between servers."""

        # DN.DnInput removed - use str directly per rule 12 (no simple aliases)

        # QuirksPort type moved to models.py (Tier 1) - uses protocol references
        # per rule: Tier 0 cannot import protocols

        # ServiceTypes class removed - use Models.ServiceResponseTypes directly
        # per rule 12 (no duplicates)

        # =========================================================================
        # ENTRY TYPES - For entry-related operations
        # =========================================================================

        class Entry:
            """Entry-related type aliases."""

            type EntryOrList = (
                "FlextLdifTypes.Ldif.Entry" | list[FlextLdifTypes.Ldif.Entry]
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

            # SchemaElement type moved to models.py (Tier 1)
            # Uses protocol-based types defined there (to avoid circular imports)
            # Previously: SchemaAttributeProtocol | SchemaObjectClassProtocol | str | int | float | bool | None

            # SchemaDict moved to FlextLdifModels.Ldif.Types.SchemaDict (Pydantic model)
            # Use m.Ldif.Types.SchemaDict instead

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

            # PermissionsDict moved to FlextLdifModels.Ldif.Types.PermissionsDict (Pydantic model)
            # Use m.Ldif.Types.PermissionsDict instead

            # EvaluationContextDict moved to FlextLdifModels.Ldif.Types.EvaluationContextDict (Pydantic model)
            # Use m.Ldif.Types.EvaluationContextDict instead

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

        # AttributeMetadataMap moved to m.Ldif.Types.AttributeMetadataMap

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

            # QuirksDict type moved to models.py (Tier 1)
            # Previously: dict[str, SchemaProtocol | AclProtocol | EntryProtocol | None]

            # QuirksByServerDict moved to FlextLdifModels.Ldif.Types.QuirksByServerDict (Pydantic model)
            # Use m.Ldif.Types.QuirksByServerDict instead

            # RegistryStatsDict moved to FlextLdifModels.Ldif.Types.RegistryStatsDict (Pydantic model)
            # Use m.Ldif.Types.RegistryStatsDict instead

        # Services protocol types are defined in models.py (Tier 1):
        # - HasParseMethodProtocol for schema/entry/acl services
        # - FilterServiceProtocol for filter services
        # - CategorizationServiceProtocol for categorization services
        # See m.Ldif.Services in models.py for protocol type aliases

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
            str,
            str | int | float | bool | list[str] | None,
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

            # EntryParsingContext moved to FlextLdifModels.Ldif.Types.EntryParsingContext (Pydantic model)
            # Use m.Ldif.Types.EntryParsingContext instead

            # AttributeWriteContext moved to FlextLdifModels.Ldif.Types.AttributeWriteContext (Pydantic model)
            # Use m.Ldif.Types.AttributeWriteContext instead

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

            type ServerQuirkOrType = str
            """Type alias for server quirk instance or server type string.

            Business Rule: ServerQuirkOrType allows either a server quirk instance or a server type string.
            Implication: This enables flexible conversion APIs that accept both runtime instances
            and type identifiers. Use isinstance checks for type narrowing.
            Note: Using str only to avoid circular import with FlextLdifServersBase.
            """

            type ConvertibleModelUnion = (
                FlextLdifTypes.Ldif.Entry
                | FlextLdifTypes.Ldif.SchemaAttribute
                | FlextLdifTypes.Ldif.SchemaObjectClass
                | FlextLdifTypes.Ldif.Acl
            )
            """Type alias for convertible model union.

            Used in return types for conversion operations.
            Uses actual types from domain models for proper type checking.
            """

        class Utilities:
            """Utility-related type aliases for internal utilities."""

            type AclComponent = dict[str, str | FlextTypes.MetadataAttributeValue]
            """Type alias for parsed ACL components.

            Used in ACL parsing utilities for representing parsed ACL component structures.
            Uses t.MetadataAttributeValue for nested structures.
            """

        class Decorators:
            """Decorator-related type aliases for quirk metadata decorators."""

            # Protocol types for decorators moved to models.py (Tier 1)
            # Previously: ProtocolType = SchemaProtocol | AclProtocol | EntryProtocol
            # WriteMethodArg references protocol types that will be resolved at runtime from models

            # Method argument types for parse methods
            type ParseMethodArg = str | float | bool | None
            """Type alias for parse method arguments."""

            # Write method argument type - references protocol types from models.py runtime
            # Used by WriteMethod decorator type to specify argument types
            type WriteMethodArg = object
            """Type alias for write method arguments.

            At runtime, this resolves to protocol types from models.py.
            Used in decorator type signatures for write methods.
            """

            # Method types - using Callable directly (cannot use generics in nested type aliases)
            # Note: For generic method types, use Callable[..., r[T]] directly in code
            # These are non-generic aliases for documentation purposes
            type ParseMethod = Callable[..., r[object]]
            """Type alias for parse methods with variable arguments.

            Supports both single-arg (parse_attribute) and multi-arg (parse_entry) methods.
            For generic usage, use Callable[..., r[T]] directly in code.
            Usage: t.Ldif.Decorators.ParseMethod (non-generic)
            """

            # WriteMethod and SafeMethod moved to models.py (Tier 1) - use protocol types
            # Note: For generic method types, use Callable[..., r[T]] directly in code

            # Decorator types - decorators that return decorators (complex Callable types)
            type ParseMethodDecorator = Callable[[ParseMethod], ParseMethod]
            """Type alias for decorators that wrap parse methods.

            Generic type using TypeVar T from flext-core.
            Usage: t.Ldif.Decorators.ParseMethodDecorator (generic with T)
            """

            # WriteMethodDecorator and SafeMethodDecorator moved to models.py (Tier 1)
            # (they reference WriteMethod and SafeMethod which use protocol types)

        # =========================================================================
        # LITERAL TYPES - Reusing constants from c.Ldif.LiteralTypes
        # =========================================================================
        # Centralized reuse of Literal types from constants.py
        # All Literal types are derived from StrEnum values in constants.py
        # This ensures single source of truth and avoids duplication

        class LiteralTypes:
            """Literal type aliases reusing constants from c.Ldif.LiteralTypes.

            Business Rule: All Literal types MUST be derived from StrEnum values
            defined in constants.py. This ensures:
            - Single source of truth (constants.py)
            - Type safety through Literal types
            - Consistency across the codebase
            - Proper domain specialization (LDIF-specific types)

            Architecture: Namespace class (no inheritance due to Tier 0 rule)
            - References all Literal types from c.Ldif.LiteralTypes conceptually
            - No runtime inheritance to maintain Tier 0 isolation (zero internal imports)
            - Extends only if needed for domain-specific Literal types
            - Maintains proper domain boundaries (no duplication)

            Usage Pattern:
                from flext_ldif.typings import t
                from flext_ldif.constants import c
                # Use constants directly for Literal types
                def process(server_type: c.Ldif.LiteralTypes.ServerTypeLiteral) -> None: ...
                def validate(level: c.Ldif.LiteralTypes.ValidationLevelLiteral) -> None: ...
            """

            # All Literal types are available from c.Ldif.LiteralTypes (constants module)
            # No need to redeclare - import c separately when Literal types are needed
            # Only add new Literal types here if they are LDIF-specific and not in constants

        # =========================================================================
        # LDIF NAMESPACE - For cross-project access pattern consistency
        # =========================================================================
        # Provides a .Ldif. namespace class for accessing LDIF types from other projects
        # Similar pattern to flext-core's .Core. namespace
        # This enables consistent namespace patterns (e.g., .Ldif., .Ldap., .Core.)

    # =========================================================================
    # COMMON DICT TYPES - Root-level access (mirrors t.Ldif.CommonDict)
    # =========================================================================
    # Provides direct access to common dictionary types for simpler namespace
    # These types are also available as t.Ldif.CommonDict.* for nested access

    class CommonDict:
        """Common dictionary type aliases accessible at root level.

        Mirrors t.Ldif.CommonDict for simplified access patterns.
        All types are also available as t.Ldif.CommonDict.AttributeDict, etc.

        Business context: LDAP attribute and distribution data structures used
        throughout LDIF processing. Reuses t.Types patterns for consistency.

        Uses collections.ABC types (Mapping, Sequence) for read-only semantics
        where appropriate (Python 3.13+ PEP 695 best practices).
        """

        # Re-export type aliases from Ldif.CommonDict for root-level access
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


# Runtime alias for basic class (objetos nested sem aliases redundantes)
# Pattern: Classes básicas sempre com runtime alias, objetos nested sem aliases redundantes
t = FlextLdifTypes

# REMOVED: ServerInitKwargs alias - use t.Ldif.Server.ServerInitKwargs directly (no redundant aliases for nested objects)
# ServerInitKwargs = t.Ldif.Server.ServerInitKwargs

__all__ = ["FlextLdifTypes", "t"]
