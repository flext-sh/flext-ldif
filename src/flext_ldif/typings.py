"""LDIF Type Definitions - Type System for FLEXT LDIF Processing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Literal, TypedDict as _TypedDict, TypeVar, Union

from flext_core import FlextTypes

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels

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
    # SERVICE RETURN TYPE ALIASES - Top-level types used by servers and services
    # =========================================================================

    type EntryOrString = FlextLdifModels.Entry | str
    type SchemaModel = (
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass
    )
    type SchemaModelOrString = (
        FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass | str
    )
    type DnInput = str | FlextLdifModels.DistinguishedName
    type AclOrString = FlextLdifModels.Acl | str
    type ConvertibleModel = (
        FlextLdifModels.Entry
        | FlextLdifModels.SchemaAttribute
        | FlextLdifModels.SchemaObjectClass
        | FlextLdifModels.Acl
    )

    # =============================================================================
    # METADATA EXTENSIONS TYPE HINTS - TypedDict for metadata.extensions (FASE 6)
    # =============================================================================

    class ValidationMetadataExtensions(_TypedDict, total=False):
        """Type hints for Entry validation metadata in metadata.extensions.

        Captura RFC violations, server-specific violations, e validation context
        para conversões bidirecionais (OID ↔ OUD ↔ OpenLDAP).
        """

        rfc_violations: list[str]
        server_specific_violations: list[str]
        validation_server_type: str
        validation_timestamp: str
        validators_executed: list[str]
        detection_confidence: float
        validation_context: dict[str, object]

    class QuirkMetadataExtensions(_TypedDict, total=False):
        """Type hints for QuirkMetadata.extensions para conversões entre servidores.

        Usado por servers/* quirks para transformações bidirecionais.
        """

        unconverted_attributes: dict[str, object]
        original_dn_case: str
        original_attribute_case: dict[str, str]
        quirk_transformations: list[str]
        conversion_metadata: dict[str, object]

    class CommonDict:
        """Common dictionary type definitions for LDIF processing."""

        AttributeDict = dict[str, list[str] | str]
        DistributionDict = dict[str, int]

    class Models:
        """Model type definitions for LDIF processing."""

        # Type aliases using forward references
        AclOrString = Union[str, "FlextLdifModels.Acl"]
        ConvertibleModel = Union[
            str, "FlextLdifModels.Entry", "FlextLdifModels.Acl", "dict[str, object]"
        ]
        ServiceResponseTypes = Union[
            "FlextLdifModels.ParseResponse",
            "FlextLdifModels.WriteResponse",
            "FlextLdifModels.MigrationPipelineResult",
            "FlextLdifModels.ValidationResult",
        ]

    # =========================================================================
    # METADATA EXTENSIONS TYPE HINTS - TypedDict for metadata.extensions
    # =========================================================================

    type MetadataExtensions = ValidationMetadataExtensions | QuirkMetadataExtensions

    # =========================================================================
    # API FLEXIBLE INPUT/OUTPUT TYPES - For FlextLdif public API methods
    # =========================================================================

    # Attribute input - accepts dict or LdifAttributes model
    type AttributeInput = dict[str, str | list[str]] | "FlextLdifModels.LdifAttributes"

    # Entry input - accepts Entry model or dict representation
    # Dict format: {"dn": str, "attribute_name": str | list[str], ...}
    type EntryInput = "FlextLdifModels.Entry" | dict[str, str | list[str]]

    # Entry dict representation (pure dict without models)
    type EntryDict = dict[str, str | list[str]]

    # Output format selection for API methods
    type OutputFormat = Literal["model", "dict"]

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

    # Literal types imported from FlextLdifConstants.LiteralTypes for centralization
    ProcessingStage = FlextLdifConstants.LiteralTypes.ProcessingStage
    HealthStatus = FlextLdifConstants.LiteralTypes.HealthStatus
    EntryType = FlextLdifConstants.LiteralTypes.EntryType
    ModificationType = FlextLdifConstants.LiteralTypes.ModificationType
    ServerType = FlextLdifConstants.LiteralTypes.ServerType
    EncodingType = FlextLdifConstants.LiteralTypes.EncodingType
    ValidationLevel = FlextLdifConstants.LiteralTypes.ValidationLevel
    ProjectType = FlextLdifConstants.LiteralTypes.ProjectType

    # ACL Server Type - subset of ServerType for ACL operations
    type AclServerType = Literal["oid", "oud", "openldap", "openldap1", "openldap2"]

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

    # Models class already defined above (line 91) - no need to redefine


# Clean up namespace - remove internal imports
del _TypedDict
