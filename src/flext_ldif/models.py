"""LDIF Domain Models - Unified Model Aggregation Layer.

This module provides a single FlextLdifModels class that aggregates all LDIF domain models,
events, configurations, and result types. It serves as the public API facade for all
LDIF data structures including entries, attributes, DNs, ACLs, and schema elements.

Scope:
- Domain Models: Core business entities (Entry, Schema, ACL, DN)
- Event Models: Processing events and logging structures
- Configuration Models: Operation parameters and settings
- Result Models: Operation outcomes and statistics
- DTO Models: Data transfer objects for service communication

Architecture:
- Single unified class with nested organization per FLEXT standards
- Extends flext-core FlextModels for consistency
- Uses Pydantic v2 with computed fields and validators
- All models are immutable by default (frozen=True where applicable)
- Server-specific quirk data preserved in extensions (t.MetadataAttributeValue)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# Standard library imports
import warnings
from typing import Literal, TypeAlias

# flext-core imports
from flext_core import FlextModels, FlextTypes
from flext_core._models.base import FlextModelsBase

# Third-party imports
from pydantic import Field

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.events import FlextLdifModelsEvents
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._models.processing import ProcessingResult
from flext_ldif._models.results import FlextLdifModelsResults, _FlexibleCategories
from flext_ldif._models.settings import (
    AclConversionConfig,
    AttrNormalizationConfig,
    DnNormalizationConfig,
    FilterConfig,
    FlextLdifModelsSettings,
    MetadataConfig,
    ProcessConfig,
    TransformConfig,
    ValidationConfig,
    WriteConfig,
)
from flext_ldif.constants import c
from flext_ldif.protocols import p

# Local imports - flext_ldif

LdifEntryAttributesDict = dict[str, list[str]]
LdifRawEntryDict = dict[str, str | list[str] | set[str]]


class FlextLdifModels(FlextModels):
    """LDIF domain models - DEPRECATED: Use FlextModels.Ldif instead.

    .. deprecated:: 1.0.0
        Use ``FlextModels.Ldif.*`` or ``m.Ldif.*`` instead of ``FlextLdifModels.*``.

    NAMESPACE HIERARCHY PADRAO:
    ───────────────────────────
    Classe unificada que agrega todos os modelos de dominio LDIF.
    Fornece um unico ponto de acesso para todos os modelos LDIF mantendo
    organizacao modular.

    Esta classe estende flext-core FlextModels e organiza modelos LDIF-specificos
    em sub-modulos focados para melhor manutenibilidade.

    PADRAO: Namespace hierarquico completo m.Ldif.Entry, m.Ldif.Attribute, etc.
    SEM duplicacao de declaracoes - heranca real de classes base.

    Migration Guide:
        Old: ``from flext_ldif import FlextLdifModels; entry = FlextLdifModels.Ldif.Entry(...)``
        New: ``from flext_core import FlextModels; entry = FlextModels.Ldif.Entry(...)``
        Or: ``from flext_core import m; entry = m.Ldif.Entry(...)``
    """

    # Direct aliases for simple access (remove subnamespaces as per FLEXT standards)
    Value = FlextModels.Value
    Entity = FlextModels.Entity
    AggregateRoot = FlextModels.AggregateRoot
    DomainEvent = FlextModels.DomainEvent
    Command = FlextModels.Command
    Query = FlextModels.Query
    Config = FlextModels.Config
    ProcessingRequest = FlextModels.ProcessingRequest
    BatchProcessingConfig = FlextModels.BatchProcessingConfig
    ValidationConfiguration = FlextModels.ValidationConfiguration
    Handler = FlextModels.Handler
    HandlerRegistration = FlextModels.HandlerRegistration
    HandlerExecutionConfig = FlextModels.HandlerExecutionConfig
    HandlerDecoratorConfig = FlextModels.HandlerDecoratorConfig
    HandlerFactoryDecoratorConfig = FlextModels.HandlerFactoryDecoratorConfig
    CqrsHandler = FlextModels.CqrsHandler
    ArbitraryTypesModel = FlextModels.ArbitraryTypesModel
    FrozenStrictModel = FlextModels.FrozenStrictModel
    IdentifiableMixin = FlextModels.IdentifiableMixin
    TimestampableMixin = FlextModels.TimestampableMixin
    TimestampedModel = FlextModels.TimestampedModel
    VersionableMixin = FlextModels.VersionableMixin
    CollectionsCategories = FlextModels.CollectionsCategories
    Pagination = FlextModels.Pagination
    Bus = FlextModels.Bus
    Metadata = FlextModels.Metadata

    # LDIF format option aliases for test convenience
    ParseFormatOptions = FlextLdifModelsSettings.ParseFormatOptions

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Warn when FlextLdifModels is subclassed directly."""
        super().__init_subclass__(**kwargs)
        warnings.warn(
            "Subclassing FlextLdifModels is deprecated. Use FlextModels.Ldif instead.",
            DeprecationWarning,
            stacklevel=2,
        )

    class Ldif:
        """LDIF namespace for cross-project access."""

        # Type aliases for LDIF domain - statically defined for type checkers
        EntryAttributesDict = dict[str, list[str]]
        RawEntryDict = dict[str, str | list[str] | set[str]]

        # =========================================================================
        # =========================================================================
        # DOMAIN MODELS - Core business entities
        # =========================================================================
        # Nested classes inheriting from _models classes (following flext-core pattern)

        class AttributeTransformation(FlextLdifModelsDomains.AttributeTransformation):
            """Detailed tracking of attribute transformation operations.

            Records complete transformation history for LDIF attribute conversions.
            """

        # Metadata models - real inheritance classes
        class DynamicMetadata(FlextLdifModelsMetadata.DynamicMetadata):
            """Model with extra="allow" for dynamic field storage.

            Replaces ALL dict[str, ...] patterns with proper Pydantic model.
            Extra fields stored in __pydantic_extra__ via Pydantic v2.
            """

        class EntryMetadata(FlextLdifModelsMetadata.EntryMetadata):
            """Model for entry processing metadata."""

        # Configuration models - real inheritance classes
        class LogContextExtras(FlextLdifModelsSettings.LogContextExtras):
            """Log context extras configuration."""

        class AclMetadataConfig(FlextLdifModelsSettings.AclMetadataConfig):
            """Configuration for ACL metadata extensions."""

        class AciParserConfig(FlextLdifModelsSettings.AciParserConfig):
            """ACI parser configuration."""

        class AciWriterConfig(FlextLdifModelsSettings.AciWriterConfig):
            """ACI writer configuration."""

        # Domain models - real inheritance classes
        class Entry(FlextLdifModelsDomains.Entry):
            """LDIF entry with DN and attributes."""

        class DN(FlextLdifModelsDomains.DN):
            """DN model."""

        class DnRegistry(FlextLdifModelsDomains.DnRegistry):
            """DN registry model."""

        class ErrorDetail(FlextLdifModelsDomains.ErrorDetail):
            """Error detail model."""

        # ACL models - real inheritance classes
        class AclPermissions(FlextLdifModelsDomains.AclPermissions):
            """ACL permissions model."""

        class AclTarget(FlextLdifModelsDomains.AclTarget):
            """ACL target model."""

        class AclSubject(FlextLdifModelsDomains.AclSubject):
            """ACL subject model."""

        class Acl(FlextLdifModelsDomains.Acl):
            """ACL model."""

        class AclWriteMetadata(FlextLdifModelsDomains.AclWriteMetadata):
            """ACL write metadata model."""

        # Quirk metadata models - real inheritance classes
        class QuirkMetadata(FlextLdifModelsDomains.QuirkMetadata):
            """Quirk metadata model."""

        # Schema models - real inheritance classes
        SchemaAttribute: TypeAlias = FlextLdifModelsDomains.SchemaAttribute
        SchemaObjectClass: TypeAlias = FlextLdifModelsDomains.SchemaObjectClass
        Syntax: TypeAlias = FlextLdifModelsDomains.Syntax
        Attributes: TypeAlias = FlextLdifModelsDomains.Attributes
        ProcessingResult: TypeAlias = ProcessingResult
        FormatDetails: TypeAlias = FlextLdifModelsDomains.FormatDetails
        SchemaFormatDetails: TypeAlias = FlextLdifModelsDomains.SchemaFormatDetails
        EntryStatistics: TypeAlias = FlextLdifModelsDomains.EntryStatistics
        DNStatistics: TypeAlias = FlextLdifModelsDomains.DNStatistics

        # Type aliases for compatibility

        # Configuration models - direct references
        ServerType = c.Ldif.ServerTypes
        SpaceHandlingOption = c.Ldif.SpaceHandlingOption
        EscapeHandlingOption = c.Ldif.EscapeHandlingOption
        SortOption = c.Ldif.SortOption
        OutputFormat: TypeAlias = c.Ldif.Domain.OutputFormat
        # ObsoleteField: TypeAlias = c.Ldif.ObsoleteField  # Commented out due to import issues
        DnNormalizationConfig = DnNormalizationConfig
        AttrNormalizationConfig = AttrNormalizationConfig
        AclConversionConfig = AclConversionConfig
        ValidationConfig = ValidationConfig
        MetadataConfig = MetadataConfig
        ProcessConfig: TypeAlias = ProcessConfig
        TransformConfig: TypeAlias = TransformConfig
        FilterConfig = FilterConfig
        ValidationBatchResult: TypeAlias = FlextLdifModelsResults.ValidationBatchResult
        EntryResult = FlextLdifModelsResults.EntryResult
        ParseResponse = FlextLdifModelsResults.ParseResponse
        WriteOptions: TypeAlias = FlextLdifModelsDomains.WriteOptions
        WriteOutputOptions: TypeAlias = FlextLdifModelsSettings.WriteOutputOptions
        WriteFormatOptions: TypeAlias = FlextLdifModelsSettings.WriteFormatOptions
        WriteConfig: TypeAlias = WriteConfig

        # Categorization and filtering models (direct aliases for convenience)
        CategoryRules = FlextLdifModelsSettings.CategoryRules
        WhitelistRules = FlextLdifModelsSettings.WhitelistRules
        TransformationTrackingConfig = (
            FlextLdifModelsSettings.TransformationTrackingConfig
        )
        SortConfig = FlextLdifModelsSettings.SortConfig

        # Format options models (direct aliases for test convenience)
        ParseFormatOptions = FlextLdifModelsSettings.ParseFormatOptions
        MigrateOptions: TypeAlias = FlextLdifModelsSettings.MigrateOptions
        PermissionMappingConfig: TypeAlias = FlextLdifModelsSettings.PermissionMappingConfig

        # Migration results (direct aliases for convenience)
        MigrationPipelineResult: TypeAlias = FlextLdifModelsResults.MigrationPipelineResult
        FlexibleCategories: TypeAlias = _FlexibleCategories

        # Event models - real inheritance classes
        class Events:
            """Extended event models namespace."""

            DnEvent: TypeAlias = FlextLdifModelsEvents.DnEvent
            DnEventConfig: TypeAlias = FlextLdifModelsEvents.DnEventConfig
            MigrationEvent = FlextLdifModelsEvents.MigrationEvent
            MigrationEventConfig = FlextLdifModelsEvents.MigrationEventConfig
            ConversionEvent = FlextLdifModelsEvents.ConversionEvent
            ConversionEventConfig = FlextLdifModelsEvents.ConversionEventConfig
            SchemaEvent = FlextLdifModelsEvents.SchemaEvent
            SchemaEventConfig = FlextLdifModelsEvents.SchemaEventConfig
            ParseEvent = FlextLdifModelsEvents.ParseEvent
            WriteEvent = FlextLdifModelsEvents.WriteEvent
            AclEvent = FlextLdifModelsEvents.AclEvent
            CategoryEvent = FlextLdifModelsEvents.CategoryEvent
            FilterEvent = FlextLdifModelsEvents.FilterEvent

        # Configuration models - extended set
        class Configuration:
            """Extended configuration models namespace."""

            EntryParseConfig = FlextLdifModelsSettings.EntryParseConfig
            EntryParseMetadataConfig = FlextLdifModelsSettings.EntryParseMetadataConfig
            EntryProcessingConfig = FlextLdifModelsSettings.EntryProcessingConfig
            EntryTransformConfig = FlextLdifModelsSettings.EntryTransformConfig
            EntryFilterConfig = FlextLdifModelsSettings.EntryFilterConfig
            EntryWriteConfig = FlextLdifModelsSettings.EntryWriteConfig
            ObjectClassParseConfig = FlextLdifModelsSettings.ObjectClassParseConfig
            LdifContentParseConfig = FlextLdifModelsSettings.LdifContentParseConfig
            ParserParams = FlextLdifModelsSettings.ParserParams
            WriterParams = FlextLdifModelsSettings.WriterParams
            ParseFormatOptions = FlextLdifModelsSettings.ParseFormatOptions
            BatchWriteConfig = FlextLdifModelsSettings.BatchWriteConfig
            AttributeNormalizeConfig = FlextLdifModelsSettings.AttributeNormalizeConfig
            AttributeDenormalizeConfig = FlextLdifModelsSettings.AttributeDenormalizeConfig
            RdnProcessingConfig = FlextLdifModelsSettings.RdnProcessingConfig
            DnCaseRules = FlextLdifModelsSettings.DnCaseRules
            EncodingRules = FlextLdifModelsSettings.EncodingRules
            AclFormatRules = FlextLdifModelsSettings.AclFormatRules
            MigrationPipelineParams = FlextLdifModelsSettings.MigrationPipelineParams
            MigrationConfig = FlextLdifModelsSettings.MigrationConfig
            ServerValidationRules = FlextLdifModelsSettings.ServerValidationRules
            ServerPatternsConfig = FlextLdifModelsSettings.ServerPatternsConfig
            AciLineFormatConfig = FlextLdifModelsSettings.AciLineFormatConfig
            FilterCriteria = FlextLdifModelsSettings.FilterCriteria
            MetadataTransformationConfig = FlextLdifModelsSettings.MetadataTransformationConfig
            ConfigInfo = FlextLdifModelsSettings.ConfigInfo
            PermissionMappingConfig = FlextLdifModelsSettings.PermissionMappingConfig
            SchemaConversionPipelineConfig = FlextLdifModelsSettings.SchemaConversionPipelineConfig
            MigrateOptions: TypeAlias = FlextLdifModelsSettings.MigrateOptions

        # Results models - extended set
        class Results:
            """Extended results models namespace."""

            # Statistics results
            Statistics = FlextLdifModelsResults.Statistics
            StatisticsResult = FlextLdifModelsResults.StatisticsResult
            StatisticsSummary = FlextLdifModelsResults.StatisticsSummary
            EntriesStatistics = FlextLdifModelsResults.EntriesStatistics
            MigrationSummary = FlextLdifModelsResults.MigrationSummary
            CategorizedEntries = FlextLdifModelsResults.CategorizedEntries

            # Analysis and detection results
            AnalysisResult = FlextLdifModelsResults.AnalysisResult
            EntryAnalysisResult: TypeAlias = FlextLdifModelsResults.EntryAnalysisResult
            ServerDetectionResult: TypeAlias = FlextLdifModelsResults.ServerDetectionResult

            # Parsing and writing results
            ParseResponse = FlextLdifModelsResults.ParseResponse
            WriteResponse = FlextLdifModelsResults.WriteResponse

            # Schema discovery and validation
            SchemaDiscoveryResult = FlextLdifModelsResults.SchemaDiscoveryResult
            SchemaBuilderResult = FlextLdifModelsResults.SchemaBuilderResult
            SyntaxLookupResult = FlextLdifModelsResults.SyntaxLookupResult

            # ACL-related results
            AclResponse = FlextLdifModelsResults.AclResponse
            AclEvaluationResult = FlextLdifModelsResults.AclEvaluationResult

            # Migration results
            MigrationEntriesResult = FlextLdifModelsResults.MigrationEntriesResult
            MigrationPipelineResult: TypeAlias = FlextLdifModelsResults.MigrationPipelineResult

            # Validation results
            ValidationResult = FlextLdifModelsResults.ValidationResult
            ValidationBatchResult = FlextLdifModelsResults.ValidationBatchResult
            LdifValidationResult = FlextLdifModelsResults.LdifValidationResult

            # Dynamic counts and categorization
            DynamicCounts = FlextLdifModelsResults.DynamicCounts
            FlexibleCategories: TypeAlias = _FlexibleCategories

            # Status models
            ClientStatus = FlextLdifModelsResults.ClientStatus
            ServiceStatus = FlextLdifModelsResults.ServiceStatus

            # Additional utility result models
            DictAccessibleValue = FlextLdifModelsResults.DictAccessibleValue
            BooleanFlags = FlextLdifModelsResults.BooleanFlags
            ConfigSettings = FlextLdifModelsResults.ConfigSettings
            CategoryPaths = FlextLdifModelsResults.CategoryPaths
            EventType = FlextLdifModelsResults.EventType

        # ═══════════════════════════════════════════════════════════════════════════
        # LdifResults - Alias namespace for backward compatibility with services
        # Services use m.Ldif.LdifResults.* pattern for access
        # ═══════════════════════════════════════════════════════════════════════════

        class LdifResults:
            """Backward-compatible namespace for result types.

            Services access results via m.Ldif.LdifResults.* pattern.
            This class provides aliases to the actual classes defined above.
            """

            # ACL-related results
            AclResponse = FlextLdifModelsResults.AclResponse
            AclEvaluationResult = FlextLdifModelsResults.AclEvaluationResult
            AclPermissions: TypeAlias = FlextLdifModelsDomains.AclPermissions

            # Statistics results
            Statistics = FlextLdifModelsResults.Statistics
            StatisticsResult = FlextLdifModelsResults.StatisticsResult
            StatisticsSummary = FlextLdifModelsResults.StatisticsSummary
            EntriesStatistics = FlextLdifModelsResults.EntriesStatistics

            # Service status aliases from _models/results.py
            StatisticsServiceStatus = FlextLdifModelsResults.StatisticsServiceStatus
            SchemaServiceStatus: TypeAlias = FlextLdifModelsResults.SchemaServiceStatus
            SyntaxServiceStatus: TypeAlias = FlextLdifModelsResults.SyntaxServiceStatus
            ValidationServiceStatus: TypeAlias = FlextLdifModelsResults.ValidationServiceStatus
            EntryAnalysisResult: TypeAlias = FlextLdifModelsResults.EntryAnalysisResult
            ServiceStatus = FlextLdifModelsResults.ServiceStatus
            CategoryPaths = FlextLdifModelsResults.CategoryPaths
            Syntax: TypeAlias = FlextLdifModelsDomains.Syntax

            # Parsing and writing results
            ParseResponse = FlextLdifModelsResults.ParseResponse
            WriteResponse = FlextLdifModelsResults.WriteResponse
            WriteOptions: TypeAlias = FlextLdifModelsDomains.WriteOptions
            WriteFormatOptions = FlextLdifModelsSettings.WriteFormatOptions

            # Schema discovery
            SchemaDiscoveryResult = FlextLdifModelsResults.SchemaDiscoveryResult
            SchemaBuilderResult = FlextLdifModelsResults.SchemaBuilderResult
            SyntaxLookupResult: TypeAlias = FlextLdifModelsResults.SyntaxLookupResult

            # Migration results
            MigrationEntriesResult = FlextLdifModelsResults.MigrationEntriesResult
            MigrationPipelineResult: TypeAlias = FlextLdifModelsResults.MigrationPipelineResult

            # Validation results
            ValidationResult = FlextLdifModelsResults.ValidationResult
            ValidationBatchResult = FlextLdifModelsResults.ValidationBatchResult
            LdifValidationResult = FlextLdifModelsResults.LdifValidationResult

            # Dynamic counts model
            DynamicCounts = FlextLdifModelsResults.DynamicCounts

            # Analysis and detection results
            ServerDetectionResult: TypeAlias = FlextLdifModelsResults.ServerDetectionResult
            AnalysisResult = FlextLdifModelsResults.AnalysisResult
            EntryResult = FlextLdifModelsResults.EntryResult

            # Categorization results
            FlexibleCategories: TypeAlias = _FlexibleCategories

            # Domain models
            # Entry and Syntax are defined as classes above

            # Event models
            DnEvent: TypeAlias = FlextLdifModelsEvents.DnEvent
            DnEventConfig: TypeAlias = FlextLdifModelsEvents.DnEventConfig

            # Categorization models
            CategoryRules = FlextLdifModelsSettings.CategoryRules
            WhitelistRules = FlextLdifModelsSettings.WhitelistRules
            SortConfig: TypeAlias = FlextLdifModelsSettings.SortConfig

            # Events namespace for nested access (m.Ldif.LdifResults.Events.*)
            class Events:
                """Events namespace for conversion events."""

                ConversionEventConfig = FlextLdifModelsEvents.ConversionEventConfig

        # ═══════════════════════════════════════════════════════════════════════════
        # TYPEDICT MODELS - Moved from typings.py as Pydantic models
        # ═══════════════════════════════════════════════════════════════════════════

        class Types:
            """Type models namespace - moved from typings.py TypedDict to Pydantic models."""

            class SchemaDict(FlextModelsBase.ArbitraryTypesModel):
                """Schema extraction result dictionary model.

                Replaces TypedDict from typings.py with Pydantic model.
                Contains ATTRIBUTES and OBJECTCLASS keys from extract_schemas_from_ldif().
                """

                ATTRIBUTES: list[SchemaAttribute] = Field(
                    default_factory=list,
                )
                OBJECTCLASS: list[SchemaObjectClass] = Field(
                    default_factory=list,
                )

            class PermissionsDict(FlextModelsBase.ArbitraryTypesModel):
                """ACL permissions dictionary model.

                Replaces TypedDict from typings.py with Pydantic model.
                All fields are optional to match TypedDict total=False behavior.
                """

                read: bool | None = Field(default=None)
                write: bool | None = Field(default=None)
                add: bool | None = Field(default=None)
                delete: bool | None = Field(default=None)
                search: bool | None = Field(default=None)
                compare: bool | None = Field(default=None)
                self_write: bool | None = Field(default=None)
                proxy: bool | None = Field(default=None)
                browse: bool | None = Field(default=None)
                auth: bool | None = Field(default=None)
                all: bool | None = Field(default=None)

            class EvaluationContextDict(FlextModelsBase.ArbitraryTypesModel):
                """ACL evaluation context dictionary model.

                Replaces TypedDict from typings.py with Pydantic model.
                All fields are optional to match TypedDict total=False behavior.
                """

                subject_dn: str | None = Field(default=None)
                target_dn: str | None = Field(default=None)
                operation: str | None = Field(default=None)
                attributes: list[str] | None = Field(default=None)

            class TransformationInfo(FlextModelsBase.ArbitraryTypesModel):
                """Transformation step information model.

                Replaces TypedDict from typings.py with Pydantic model.
                Stored in metadata for transformation tracking.
                All fields are optional to match TypedDict total=False behavior.
                """

                step: str | None = Field(default=None)
                server: str | None = Field(default=None)
                changes: list[str] | None = Field(default=None)

            class QuirksByServerDict(FlextModelsBase.ArbitraryTypesModel):
                """Quirks by server dictionary model.

                Replaces TypedDict from typings.py with Pydantic model.
                All fields are optional to match TypedDict total=False behavior.
                """

                schema_type: str | None = Field(
                    default=None,
                    alias="schema",
                    description="Schema quirk type",
                )
                acl_type: str | None = Field(
                    default=None,
                    alias="acl",
                    description="ACL quirk type",
                )
                entry_type: str | None = Field(
                    default=None,
                    alias="entry",
                    description="Entry quirk type",
                )

            class RegistryStatsDict(FlextModelsBase.ArbitraryTypesModel):
                """Registry statistics dictionary model.

                Replaces TypedDict from typings.py with Pydantic model.
                Replaces dict[str, object] with specific structure.
                """

                total_servers: int = Field(default=0)
                quirks_by_server: dict[
                    str,
                    FlextLdifModels.Ldif.Types.QuirksByServerDict,
                ] = Field(default_factory=dict)
                server_priorities: dict[str, int] = Field(default_factory=dict)

            class EntryParsingContext(FlextModelsBase.ArbitraryTypesModel):
                """Entry parsing context model.

                Replaces TypedDict from typings.py with Pydantic model.
                All fields are optional to match TypedDict total=False behavior.
                Used in parsing/writing operations for context tracking.
                """

                original_entry_dn: str | None = Field(default=None)
                cleaned_dn: str | None = Field(default=None)
                original_dn_line: str | None = Field(default=None)
                original_attr_lines: list[str] | None = Field(default=None)
                dn_was_base64: bool | None = Field(default=None)
                original_attribute_case: dict[str, str] | None = Field(default=None)
                dn_differences: (
                    dict[str, FlextTypes.MetadataAttributeValue]
                    | dict[str, dict[str, FlextTypes.MetadataAttributeValue]]
                    | None
                ) = Field(default=None)
                attribute_differences: (
                    dict[str, FlextTypes.MetadataAttributeValue]
                    | dict[str, dict[str, FlextTypes.MetadataAttributeValue]]
                    | None
                ) = Field(default=None)
                original_attributes_complete: (
                    dict[str, FlextTypes.MetadataAttributeValue] | None
                ) = Field(default=None)

            class AttributeWriteContext(FlextModelsBase.ArbitraryTypesModel):
                """Attribute write context model.

                Replaces TypedDict from typings.py with Pydantic model.
                All fields are optional to match TypedDict total=False behavior.
                Used in writing operations for context tracking.
                """

                attr_name: str | None = Field(default=None)
                attr_values: FlextTypes.GeneralValueType | None = Field(default=None)
                minimal_differences_attrs: dict[
                    str,
                    FlextTypes.MetadataAttributeValue,
                ] = Field(default_factory=dict)
                hidden_attrs: set[str] = Field(default_factory=set)
                # Note: write_options uses protocol type - keep as protocol reference
                # write_options: p.Ldif.WriteFormatOptionsProtocol

            # Type alias for boolean format literals.
            # Used in transformers for boolean value conversion between formats.
            type BooleanFormat = Literal["TRUE/FALSE", "true/false", "1/0", "yes/no"]

            # Type alias for attribute name -> metadata dict mapping.
            # Maps attribute names to their metadata dictionaries.
            # Used in metadata utilities for per-attribute tracking.
            type AttributeMetadataMap = dict[str, dict[str, str | list[str]]]

            # Type aliases for inline complex types - moved from various modules
            # These are defined as class attributes for MyPy compatibility

        class Schema:
            """Schema element type with protocol references."""

            type SchemaElement = (
                m.Ldif.SchemaAttribute
                | m.Ldif.SchemaObjectClass
                | str
                | int
                | float
                | bool
                | None
            )
            """Type alias for schema elements that can be stored in schema maps."""

        class Registry:
            """Registry-related type aliases using protocols."""

            type QuirksDict = dict[
                str,
                p.Ldif.SchemaQuirkProtocol
                | p.Ldif.AclQuirkProtocol
                | p.Ldif.EntryQuirkProtocol
                | None,
            ]
            """Type alias for quirks dictionary returned by get_all_quirks."""

        class ProcessingConfig:
            """Processing configuration models namespace."""

            EntryTransformConfig = FlextLdifModelsSettings.EntryTransformConfig
            EntryFilterConfig = FlextLdifModelsSettings.EntryFilterConfig
            CaseFoldOption = c.Ldif.CaseFoldOption

            # Type aliases for common types
            # ServerType removed to avoid import cycles


# =========================================================================
# NAMESPACE HIERARCHY - PADRAO CORRETO PARA FLEXT-LDIF
# =========================================================================
# Use namespace hierarquico completo: m.Ldif.Entry, m.Ldif.Attribute, m.Ldif.DN
# SEM duplicacao de declaracoes - heranca real de FlextModels
# SEM quebra de codigo - mantem compatibilidade backward
# =========================================================================

# Forward references resolved via imports at module top level
# FlextModelsEntity imported at top of _models/domain.py and _models/results.py
# This architectural approach avoids runtime model_rebuild() calls

m = FlextLdifModels

__all__ = ["FlextLdifModels", "m"]
