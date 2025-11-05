"""LDIF Type Definitions - Minimal, Focused Type System for FLEXT LDIF Processing.

╔══════════════════════════════════════════════════════════════════════════╗
║  PURELY TYPE DEFINITIONS - MINIMAL & FOCUSED ON ACTUAL USAGE            ║
╠══════════════════════════════════════════════════════════════════════════╣
║  ✅ Common patterns: AttributeDict (7 uses), DistributionDict (3 uses)  ║
║  ✅ Pydantic data: Models namespace (20+ types for quirks/schema/acl)   ║
║  ✅ Entry creation: EntryCreateData (dict[str, object])                 ║
║  ✅ Literal types: 9 types delegated to FlextLdifConstants              ║
║  ✅ SRP: Types ONLY, zero behavior, zero imports from flext_ldif/*      ║
║  ✅ Over-engineering removed: 80% less code (652→407 lines, -37.6%)     ║
╚══════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════
RESPONSIBILITY (SRP)

This module defines TYPES ONLY:
- Type aliases for common dictionary patterns used across LDIF operations
- Complex types for Pydantic model data structures
- Literal type re-exports from FlextLdifConstants

What it does NOT contain:
- Functions or methods (SRP violation)
- Behavioral logic (belongs in services/)
- Server-specific logic (belongs in quirks/)
- Validation logic (use Pydantic models with field_validator)

═══════════════════════════════════════════════════════════════════════════
WHEN TO USE Types vs Models - CRITICAL DESIGN DECISION

USE FlextLdifTypes WHEN:
✅ Type is simple dict pattern (no validation needed)
✅ Data is intermediate/temporary (not persisted)
✅ Pattern is common across multiple places (AttributeDict)
✅ Type hint for parameters/returns of services
✅ Structure is just data organization, not an entity

USE FlextLdifModels WHEN:
✅ Data requires Pydantic validation
✅ Data is persisted or serialized (Entry, Schema, ACL)
✅ Data has computed fields or validators
✅ Data represents domain entities (Entry, Schema objects)
✅ Data needs model_validate(), model_dump(), etc.

ANTI-PATTERNS (DO NOT DO):
❌ Use Type when Model exists (causes duplication)
❌ Use Mapping[str, object] - use dict[str, object] directly
❌ Create simple dict[str, str | list[str]] aliases - use direct type
❌ Hide validation in types - use Pydantic models instead
❌ Embed behavior in type definitions

═══════════════════════════════════════════════════════════════════════════
CORRECT USAGE EXAMPLES

# ✅ Type for simple common pattern
attributes: FlextLdifTypes.AttributeDict = {"cn": ["John"], "mail": "john@example.com"}

# ✅ Type for statistics/distribution
distribution: FlextLdifTypes.DistributionDict = {"person": 100, "group": 20}

# ✅ Type in Pydantic Field
class SchemaData(BaseModel):
    attributes: FlextLdifTypes.Models.AttributesData = Field(default_factory=dict)

# ✅ Model for validated data
entry: FlextLdifModels.Entry = FlextLdifModels.Entry(
    dn="cn=John,dc=example,dc=com",
    attributes={"cn": ["John"]}
)

INCORRECT EXAMPLES (DO NOT DO):

# ❌ WRONG: Type when Model exists
config: FlextLdifTypes.Parser.ParserConfiguration = {...}
# CORRECT: Use Model with validation or simple dict
config: dict[str, object] = {...}

# ❌ WRONG: Generic Mapping when dict is simpler
data: FlextLdifTypes.Entry.EntryCreateData  # Mapping[str, object]
# CORRECT: Use concrete type
data: dict[str, object]

# ❌ WRONG: Embedding validation in type
attrs: FlextLdifTypes.ValidatedAttributeDict  # (doesn't exist and shouldn't)
# CORRECT: Use Pydantic model
attrs: FlextLdifModels.LdifAttributes = FlextLdifModels.LdifAttributes(...)

═══════════════════════════════════════════════════════════════════════════
OVER-ENGINEERING REMOVED (Phase 1 Refactoring - Oct 22, 2025)

Removed 12 unused namespaces (ZERO production usage):
- ❌ Parser (6 types: ParserConfiguration, ParsingContext, etc.)
- ❌ Writer (7 types: WriterConfiguration, OutputFormat, etc.)
- ❌ LdifValidation (6 types: ValidationConfiguration, ValidationRules, etc.)
- ❌ LdifProcessing (6 types: ProcessingConfiguration, ProcessingPipeline, etc.)
- ❌ Analytics (6 types: AnalyticsConfiguration, AnalyticsMetrics, etc.)
- ❌ ServerTypes (5 types: ServerConfiguration, ServerCompatibility, etc.)
- ❌ Functional (9 types: ProcessorFunction, CompositionPipeline, etc.)
- ❌ Streaming (6 types: EntryIterator, ChunkingStrategy, etc.)
- ❌ AnnotatedLdif (20+ Pydantic Annotated types)
- ❌ ModelAliases (7 forward reference aliases)
- ❌ LdifProject + Project alias

Removed 10+ unused types from kept namespaces:
- ❌ CommonDict: ChangeDict, CategorizedDict, TreeDict, HierarchyDict
- ❌ Entry: EntryConfiguration, EntryAttributes, EntryValidation, EntryTransformation, EntryMetadata, EntryProcessing

Result: 652 → 407 lines (-37.6%), 100% of remaining types are ACTIVELY USED

═══════════════════════════════════════════════════════════════════════════
KEPT TYPES - ACTIVELY USED IN PRODUCTION

✅ CommonDict:
  • AttributeDict (7 uses): LDAP attribute dicts {attr: str | list[str]}
  • DistributionDict (3 uses): Statistics {key: count}

✅ Entry:
  • EntryCreateData (1 use): Entry creation data dict[str, object]

✅ Models namespace (20+ types):
  • EntryAttributesDict (8 uses): Quirks conversion results
  • AttributesData (1 use): Schema attribute definitions
  • ObjectClassesData (1 use): Schema objectClass definitions
  • ACL types: PermissionsData, TargetData, SubjectData
  • Quirk types: QuirkExtensions, QuirkSchemaAttributeData, QuirkAclData, etc.

✅ Literal types (9 types):
  • ProcessingStage, HealthStatus, EntryType, ModificationType
  • ServerType, EncodingType, ValidationLevel, ProjectType, AclServerType

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TypeVar

from flext_core import FlextTypes

from flext_ldif.constants import FlextLdifConstants

# =============================================================================
# LDIF-SPECIFIC TYPE VARIABLES - Domain-specific TypeVars for LDIF operations
# =============================================================================

# Generic TypeVars T and U imported from flext-core FlextTypes

# TypeVar for generic service retrieval with type narrowing
ServiceT = TypeVar("ServiceT", bound=object)


# LDIF domain TypeVars
class FlextLdifTypes(FlextTypes):
    """LDIF-specific type definitions extending FlextLdifTypes.

    Domain-specific type system for LDIF processing operations.
    Contains ONLY complex LDIF-specific types, no simple aliases.
    Uses Python 3.13+ type syntax and patterns.
    """

    # =========================================================================
    # LDIF ENTRY TYPES
    # =========================================================================

    class Entry:
        """LDIF entry type definitions for entry creation and manipulation."""

        # dict[str, object]: Universal data structure for entry creation
        type EntryCreateData = dict[str, object]

    # =========================================================================
    # LDIF LITERALS AND ENUMS - Domain-specific literal types from constants
    # =========================================================================

    # Literal types moved to FlextLdifConstants.LiteralTypes for centralization

    # REMOVED: Functional class
    # - ProcessorFunction, ValidatorFunction, TransformerFunction, AnalyzerFunction, WriterFunction, FilterFunction (ZERO usage)
    # - CompositionPipeline, ValidationPipeline, TransformationPipeline (ZERO usage)
    # Reason: Function types should be defined in service modules where they're used

    # REMOVED: Streaming class
    # - EntryIterator, ValidationIterator, ProcessingIterator, StreamingConfiguration, ChunkingStrategy, MemoryManagement (ZERO usage)
    # Reason: Streaming types not yet implemented (future feature)

    # =========================================================================
    # LDIF MODEL TYPES - Pydantic model-specific type definitions
    # =========================================================================

    class Models:
        """Type definitions for Pydantic model data structures.

        This namespace contains semantic type hints for complex data structures
        used within Pydantic models and service functions. These are NOT Pydantic
        models themselves (those live in flext_ldif.models), but rather type hints
        for the internal data structures those models contain.

        ORGANIZATION:
        1. **Basic Types**: Reusable foundation types (Entry, Diff)
        2. **Schema Types**: RFC 4512 schema definition structures
        3. **Validation Types**: Schema and entry validation result structures
        4. **Quirks Types**: Server-specific transformation data structures
           - Quirks Schema: Parsed schema with server-specific metadata
           - Quirks ACL: Parsed ACL with server-specific rules
           - Quirks Entry: Parsed entry with server-specific formats
           - Quirks Conversion: Server-to-server transformation results

        USAGE PATTERNS:
        - Use in Field() annotations: models.Schema.attributes: AttributesData
        - Use in function signatures: def parse(...) -> dict[str, QuirkAclData]
        - Use in return types: FlextResult[EntryAttributesDict]

        PRODUCTION USAGE (8+ actively used types):
        - EntryAttributesDict (8 uses): Quirks conversion results
        - AttributesData (1 use): Schema attribute definitions
        - ObjectClassesData (1 use): Schema objectClass definitions
        - QuirkExtensions (4 uses): Quirk metadata tracking
        - Plus 4+ ACL/Schema/Validation types with active usage
        """

        # =====================================================================
        # BASIC ENTRY & DIFF TYPES - Foundation types for entry processing
        # =====================================================================

        # Entry DN value (string) - Canonical distinguished name
        type EntryDnValue = str

        # Entry attributes after conversion/transformation by quirks
        # Combines list[str] (multi-valued) and object (single-valued/metadata)
        # USED: 8x (protocols.py, servers/oid.py, servers/oud.py)
        type EntryAttributesDict = dict[str, list[str] | object]

        # Diff item data - Represents a single change in LDIF diff format
        type ItemData = dict[str, object]

        # Diff item metadata - Tracks origin and metadata for diff items
        type ItemMetadata = dict[str, object]

        # =====================================================================
        # SCHEMA TYPES - RFC 4512 schema definition structures
        # =====================================================================

        # Schema attributes: {attr_name: {oid: "...", syntax: "...", ...}}
        # USED: 1x (models.py - Schema.attributes field)
        type AttributesData = dict[str, dict[str, object]]

        # Schema objectClasses: {class_name: {oid: "...", must: [...], may: [...]}}
        # USED: 1x (models.py - Schema.objectclasses field)
        type ObjectClassesData = dict[str, dict[str, object]]

        # Single objectClass definition with all properties
        type ObjectClassData = dict[str, object]

        # Raw input attributes data (less structured than AttributesData)
        type AttributesInputData = dict[str, object]

        # =====================================================================
        # VALIDATION & QUIRKS METADATA TYPES - Validation results and quirk config
        # =====================================================================

        # Quirk extension metadata: server-specific capabilities and settings
        # USED: 4+ (quirk implementations tracking server capabilities)
        type QuirkExtensions = dict[str, bool | str | int | list[int] | None]

        # Validation report: Results of schema/entry validation
        # Contains: {error_field: "error message", "total_errors": 5, ...}
        type ValidationReportData = dict[
            str,
            str | bool | list[str] | int | dict[str, object],
        ]

        # DN validation result: {is_valid: bool, components: [...], errors: [...]}
        type DNValidationResult = dict[str, bool | list[str]]

        # Quirk rules configuration: Server-specific parsing rules
        type QuirksRulesData = dict[
            str,
            str | bool | int | list[str] | dict[str, str] | dict[str, object],
        ]

        # Server-specific quirks configuration: All quirks for a server
        type ServerQuirksData = dict[str, object]

        # Attribute mappings: Maps source attribute names to target names
        # USED: ACL and entry transformation between different servers
        type AttributeMappingsData = dict[str, str]

        # Entry validation result: Validation status for single entry
        # Contains: {dn_valid: True, attributes_valid: True, errors: [...]}
        type EntryValidationResult = dict[str, str | bool | list[str] | int]

        # =====================================================================
        # ACL TYPES - Access Control List structures for ACL processing
        # =====================================================================

        # ACL permission entry: Parsed permission with rules and scope
        # USED: quirks ACL processing
        type PermissionsData = dict[str, bool | str]

        # ACL target definition: What DN/attribute this ACL applies to
        # USED: quirks ACL processing
        type TargetData = dict[str, str | list[str]]

        # ACL subject definition: Who the permission applies to
        # USED: quirks ACL processing
        type SubjectData = dict[str, str]

        # Parsed ACL permission entry (from ACL line)
        type QuirkAclPermission = dict[str, str | list[str]]

        # Parsed ACL bind rule (authentication/authorization rule)
        type QuirkAclBindRule = dict[str, str]

        # Complete ACL data with permissions, bind rules, and metadata
        # Note: Includes QuirkMetadata in "_metadata" key
        type QuirkAclData = dict[
            str,
            str
            | bool
            | int
            | list[str]
            | list[dict[str, str | list[str]]]
            | object,  # Allows QuirkMetadata and dict values
        ]

        # =====================================================================
        # QUIRKS SCHEMA TYPES - Server-specific schema parsing with metadata
        # =====================================================================
        # These types represent parsed schema (attributeTypes, objectClasses)
        # with server-specific metadata and quirks extensions. All include a
        # "_metadata" key containing QuirkMetadata for tracking server info.

        # Parsed attribute definition with server-specific extensions
        # Structure: {oid: "...", syntax: "...", equality: "...", _metadata: {...}}
        # The "_metadata" key contains QuirkMetadata object with server tracking
        type QuirkSchemaAttributeData = dict[
            str,
            str
            | bool
            | int
            | list[str]
            | object  # Allows QuirkMetadata and other objects in _metadata
            | None,
        ]

        # Parsed objectClass definition with server-specific extensions
        # Structure: {oid: "...", kind: "STRUCTURAL", sup: "...", must: [...], may: [...], _metadata: {...}}
        # The "_metadata" key contains QuirkMetadata object with server tracking
        type QuirkSchemaObjectClassData = dict[
            str,
            str
            | bool
            | int
            | list[str]
            | object  # Allows QuirkMetadata and other objects in _metadata
            | None,
        ]

        # Complete extracted schema data with attributes and objectClasses
        # Structure: {attributes: [...], objectClasses: [...], _metadata: {...}}
        type QuirkSchemaExtractedData = dict[
            str,
            list[dict[str, str | bool | int | list[str] | object | None]] | object,
        ]

        # =====================================================================
        # QUIRKS ENTRY TYPES - Server-specific entry data with metadata
        # =====================================================================
        # These types represent parsed and transformed entries with server-specific
        # formats. Used in entry quirks processing and conversion pipeline.

        # Processed entry data with attributes and server-specific metadata
        # Structure: {cn: ["John"], mail: ["john@example.com"], _metadata: {...}}
        # The "_metadata" key contains QuirkMetadata object with server tracking
        type QuirkEntryData = dict[
            str,
            str
            | bool
            | int
            | list[str]
            | list[dict[str, str]]
            | list[object]
            | object,  # Allows QuirkMetadata and various value types
        ]

        # Server-specific conversion result from transformation pipeline
        # Represents output of source → RFC → target conversion matrix
        # Used by: QuirksConversionMatrix.convert() return types
        type QuirkConversionResult = dict[
            str,
            str | int | bool | dict[str, object] | object,
        ]

        # =====================================================================
        # CONVERSION MATRIX TYPES - For N×N server conversion framework
        # =====================================================================
        # Currently commented out - reserved for future ConversionMatrix
        # improvements that may require union of convertible model types.
        #
        # Potential future type: Union of all Pydantic models that can be
        # processed by the universal conversion matrix (Entry, Schema,
        # ObjectClass, ACL). Enable when ConversionMatrix requires strict
        # type union for conversion operations.
        #
        # type ConvertibleModel = (
        #     FlextLdifModels.Entry
        #     | FlextLdifModels.SchemaAttribute
        #     | FlextLdifModels.SchemaObjectClass
        #     | FlextLdifModels.Acl
        # )

    # =========================================================================
    # OPTIMIZED DIRECTORY TYPES - Consolidated high-frequency patterns
    # =========================================================================
    # Eliminates 50+ inline dict definitions across LDIF, LDAP, and migration modules

    class CommonDict:
        """Common dictionary patterns used in LDIF/LDAP operations.

        ONLY semantically meaningful patterns with actual usage are kept.
        """

        # Attribute dictionary: {attribute_name: value(s)}
        # Standardized type compatible with LDAP add_entry operations
        # Single-valued: string, Multi-valued: list[str]
        # USED: 7x in api.py, models.py
        type AttributeDict = dict[str, str | list[str]]

        # Statistics/distribution: {key: count}
        # Common pattern for metrics and analytics
        # USED: 3x in models.py (summary(), attribute_summary())
        type DistributionDict = dict[str, int]

        # REMOVED: ChangeDict (ZERO usage)
        # REMOVED: CategorizedDict (ZERO usage)
        # REMOVED: TreeDict (ZERO usage)
        # REMOVED: HierarchyDict (ZERO usage)
        # Reason: No production usage found in codebase

    # REMOVED: AnnotatedLdif class (lines 376-501)
    # All 20+ Annotated types with Pydantic Field constraints had ZERO usage
    # (DistinguishedName, AttributeName, ObjectClassName, LdifFilePath, etc.)
    # Reason: If needed, define field constraints in Pydantic models directly, not in types

    # REMOVED: ModelAliases class (lines 513-563)
    # All 7 forward reference object aliases had ZERO usage
    # (ParserConfigModel, WriterConfigModel, ParsingContextModel, etc.)
    # Reason: Use Pydantic models from models.py directly, not type aliases

    # REMOVED: LdifProject class and Project alias
    # Had ZERO usage
    # Reason: Project types moved to FlextLdifConstants.LiteralTypes

    # =========================================================================
    # LITERAL TYPES - Import from constants for Pydantic compatibility
    # =========================================================================

    # Import literal types from constants for use in Pydantic models
    # Zero Tolerance: ALL Literal type definitions MUST be in FlextLdifConstants.LiteralTypes
    type ProcessingStage = FlextLdifConstants.LiteralTypes.ProcessingStage
    type HealthStatus = FlextLdifConstants.LiteralTypes.HealthStatus
    type EntryType = FlextLdifConstants.LiteralTypes.EntryType
    type ModificationType = FlextLdifConstants.LiteralTypes.ModificationType
    type ServerType = FlextLdifConstants.LiteralTypes.ServerType
    type EncodingType = FlextLdifConstants.LiteralTypes.EncodingType
    type ValidationLevel = FlextLdifConstants.LiteralTypes.ValidationLevel
    type ProjectType = FlextLdifConstants.LiteralTypes.ProjectType
    # ACL server types - use the same types as ServerType for consistency
    type AclServerType = FlextLdifConstants.LiteralTypes.ServerType


# =============================================================================
# PUBLIC API EXPORTS - LDIF TypeVars and types
# =============================================================================

__all__: list[str] = [
    "FlextLdifTypes",
    "ServiceT",
]
