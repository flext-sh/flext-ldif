"""LDIF Domain Models - Unified Model Aggregation Layer."""

from __future__ import annotations

import warnings
from typing import Literal, TypeAlias

from flext_core import FlextModels, FlextTypes
from flext_core._models.base import FlextModelsBase
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

LdifEntryAttributesDict = dict[str, list[str]]
LdifRawEntryDict = dict[str, str | list[str] | set[str]]


class FlextLdifModels(FlextModels):
    """LDIF domain models - DEPRECATED: Use FlextModels.Ldif instead."""

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

        EntryAttributesDict = dict[str, list[str]]
        RawEntryDict = dict[str, str | list[str] | set[str]]

        class AttributeTransformation(FlextLdifModelsDomains.AttributeTransformation):
            """Detailed tracking of attribute transformation operations."""

        class DynamicMetadata(FlextLdifModelsMetadata.DynamicMetadata):
            """Model with extra="allow" for dynamic field storage."""

        class EntryMetadata(FlextLdifModelsMetadata.EntryMetadata):
            """Model for entry processing metadata."""

        class LogContextExtras(FlextLdifModelsSettings.LogContextExtras):
            """Log context extras configuration."""

        class AclMetadataConfig(FlextLdifModelsSettings.AclMetadataConfig):
            """Configuration for ACL metadata extensions."""

        class AciParserConfig(FlextLdifModelsSettings.AciParserConfig):
            """ACI parser configuration."""

        class AciWriterConfig(FlextLdifModelsSettings.AciWriterConfig):
            """ACI writer configuration."""

        class Entry(FlextLdifModelsDomains.Entry):
            """LDIF entry with DN and attributes."""

        class DN(FlextLdifModelsDomains.DN):
            """DN model."""

        class DnRegistry(FlextLdifModelsDomains.DnRegistry):
            """DN registry model."""

        class ErrorDetail(FlextLdifModelsDomains.ErrorDetail):
            """Error detail model."""

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

        class QuirkMetadata(FlextLdifModelsDomains.QuirkMetadata):
            """Quirk metadata model."""

        SchemaAttribute: TypeAlias = FlextLdifModelsDomains.SchemaAttribute
        SchemaObjectClass: TypeAlias = FlextLdifModelsDomains.SchemaObjectClass
        Syntax: TypeAlias = FlextLdifModelsDomains.Syntax
        Attributes: TypeAlias = FlextLdifModelsDomains.Attributes
        ProcessingResult: TypeAlias = ProcessingResult
        FormatDetails: TypeAlias = FlextLdifModelsDomains.FormatDetails
        SchemaFormatDetails: TypeAlias = FlextLdifModelsDomains.SchemaFormatDetails
        EntryStatistics: TypeAlias = FlextLdifModelsDomains.EntryStatistics
        DNStatistics: TypeAlias = FlextLdifModelsDomains.DNStatistics

        ServerType: TypeAlias = c.Ldif.ServerTypes
        SpaceHandlingOption: TypeAlias = c.Ldif.SpaceHandlingOption
        EscapeHandlingOption: TypeAlias = c.Ldif.EscapeHandlingOption
        SortOption: TypeAlias = c.Ldif.SortOption
        OutputFormat: TypeAlias = c.Ldif.Domain.OutputFormat

        DnNormalizationConfig: TypeAlias = DnNormalizationConfig
        AttrNormalizationConfig: TypeAlias = AttrNormalizationConfig
        AclConversionConfig: TypeAlias = AclConversionConfig
        ValidationConfig: TypeAlias = ValidationConfig
        MetadataConfig: TypeAlias = MetadataConfig
        ProcessConfig: TypeAlias = ProcessConfig
        TransformConfig: TypeAlias = TransformConfig
        FilterConfig: TypeAlias = FilterConfig
        ValidationBatchResult: TypeAlias = FlextLdifModelsResults.ValidationBatchResult
        EntryResult: TypeAlias = FlextLdifModelsResults.EntryResult
        ParseResponse: TypeAlias = FlextLdifModelsResults.ParseResponse
        WriteOptions: TypeAlias = FlextLdifModelsDomains.WriteOptions
        WriteOutputOptions: TypeAlias = FlextLdifModelsSettings.WriteOutputOptions
        WriteFormatOptions: TypeAlias = FlextLdifModelsSettings.WriteFormatOptions
        WriteConfig: TypeAlias = WriteConfig

        CategoryRules: TypeAlias = FlextLdifModelsSettings.CategoryRules
        WhitelistRules: TypeAlias = FlextLdifModelsSettings.WhitelistRules
        TransformationTrackingConfig: TypeAlias = (
            FlextLdifModelsSettings.TransformationTrackingConfig
        )
        SortConfig: TypeAlias = FlextLdifModelsSettings.SortConfig

        ParseFormatOptions: TypeAlias = FlextLdifModelsSettings.ParseFormatOptions
        MigrateOptions: TypeAlias = FlextLdifModelsSettings.MigrateOptions
        PermissionMappingConfig: TypeAlias = (
            FlextLdifModelsSettings.PermissionMappingConfig
        )

        MigrationPipelineResult: TypeAlias = (
            FlextLdifModelsResults.MigrationPipelineResult
        )
        FlexibleCategories: TypeAlias = _FlexibleCategories

        class Events:
            """Extended event models namespace."""

            DnEvent: TypeAlias = FlextLdifModelsEvents.DnEvent
            DnEventConfig: TypeAlias = FlextLdifModelsEvents.DnEventConfig
            MigrationEvent: TypeAlias = FlextLdifModelsEvents.MigrationEvent
            MigrationEventConfig: TypeAlias = FlextLdifModelsEvents.MigrationEventConfig
            ConversionEvent: TypeAlias = FlextLdifModelsEvents.ConversionEvent
            ConversionEventConfig: TypeAlias = (
                FlextLdifModelsEvents.ConversionEventConfig
            )
            SchemaEvent: TypeAlias = FlextLdifModelsEvents.SchemaEvent
            SchemaEventConfig: TypeAlias = FlextLdifModelsEvents.SchemaEventConfig
            ParseEvent: TypeAlias = FlextLdifModelsEvents.ParseEvent
            WriteEvent: TypeAlias = FlextLdifModelsEvents.WriteEvent
            AclEvent: TypeAlias = FlextLdifModelsEvents.AclEvent
            CategoryEvent: TypeAlias = FlextLdifModelsEvents.CategoryEvent
            FilterEvent: TypeAlias = FlextLdifModelsEvents.FilterEvent

        class Configuration:
            """Extended configuration models namespace."""

            EntryParseConfig: TypeAlias = FlextLdifModelsSettings.EntryParseConfig
            EntryParseMetadataConfig: TypeAlias = (
                FlextLdifModelsSettings.EntryParseMetadataConfig
            )
            EntryProcessingConfig: TypeAlias = (
                FlextLdifModelsSettings.EntryProcessingConfig
            )
            EntryTransformConfig: TypeAlias = (
                FlextLdifModelsSettings.EntryTransformConfig
            )
            EntryFilterConfig: TypeAlias = FlextLdifModelsSettings.EntryFilterConfig
            EntryWriteConfig: TypeAlias = FlextLdifModelsSettings.EntryWriteConfig
            ObjectClassParseConfig: TypeAlias = (
                FlextLdifModelsSettings.ObjectClassParseConfig
            )
            LdifContentParseConfig: TypeAlias = (
                FlextLdifModelsSettings.LdifContentParseConfig
            )
            ParserParams: TypeAlias = FlextLdifModelsSettings.ParserParams
            WriterParams: TypeAlias = FlextLdifModelsSettings.WriterParams
            ParseFormatOptions: TypeAlias = FlextLdifModelsSettings.ParseFormatOptions
            BatchWriteConfig: TypeAlias = FlextLdifModelsSettings.BatchWriteConfig
            AttributeNormalizeConfig: TypeAlias = (
                FlextLdifModelsSettings.AttributeNormalizeConfig
            )
            AttributeDenormalizeConfig: TypeAlias = (
                FlextLdifModelsSettings.AttributeDenormalizeConfig
            )
            RdnProcessingConfig: TypeAlias = FlextLdifModelsSettings.RdnProcessingConfig
            DnCaseRules: TypeAlias = FlextLdifModelsSettings.DnCaseRules
            EncodingRules: TypeAlias = FlextLdifModelsSettings.EncodingRules
            AclFormatRules: TypeAlias = FlextLdifModelsSettings.AclFormatRules
            MigrationPipelineParams: TypeAlias = (
                FlextLdifModelsSettings.MigrationPipelineParams
            )
            MigrationConfig: TypeAlias = FlextLdifModelsSettings.MigrationConfig
            ServerValidationRules: TypeAlias = (
                FlextLdifModelsSettings.ServerValidationRules
            )
            ServerPatternsConfig: TypeAlias = (
                FlextLdifModelsSettings.ServerPatternsConfig
            )
            AciLineFormatConfig: TypeAlias = FlextLdifModelsSettings.AciLineFormatConfig
            FilterCriteria: TypeAlias = FlextLdifModelsSettings.FilterCriteria
            MetadataTransformationConfig: TypeAlias = (
                FlextLdifModelsSettings.MetadataTransformationConfig
            )
            ConfigInfo: TypeAlias = FlextLdifModelsSettings.ConfigInfo
            PermissionMappingConfig: TypeAlias = (
                FlextLdifModelsSettings.PermissionMappingConfig
            )
            SchemaConversionPipelineConfig: TypeAlias = (
                FlextLdifModelsSettings.SchemaConversionPipelineConfig
            )
            MigrateOptions: TypeAlias = FlextLdifModelsSettings.MigrateOptions

        class Results:
            """Extended results models namespace."""

            Statistics: TypeAlias = FlextLdifModelsResults.Statistics
            StatisticsResult: TypeAlias = FlextLdifModelsResults.StatisticsResult
            StatisticsSummary: TypeAlias = FlextLdifModelsResults.StatisticsSummary
            EntriesStatistics: TypeAlias = FlextLdifModelsResults.EntriesStatistics
            MigrationSummary: TypeAlias = FlextLdifModelsResults.MigrationSummary
            CategorizedEntries: TypeAlias = FlextLdifModelsResults.CategorizedEntries

            AnalysisResult: TypeAlias = FlextLdifModelsResults.AnalysisResult
            EntryAnalysisResult: TypeAlias = FlextLdifModelsResults.EntryAnalysisResult
            ServerDetectionResult: TypeAlias = (
                FlextLdifModelsResults.ServerDetectionResult
            )

            ParseResponse: TypeAlias = FlextLdifModelsResults.ParseResponse
            WriteResponse: TypeAlias = FlextLdifModelsResults.WriteResponse

            SchemaDiscoveryResult: TypeAlias = (
                FlextLdifModelsResults.SchemaDiscoveryResult
            )
            SchemaBuilderResult: TypeAlias = FlextLdifModelsResults.SchemaBuilderResult
            SyntaxLookupResult: TypeAlias = FlextLdifModelsResults.SyntaxLookupResult

            AclResponse: TypeAlias = FlextLdifModelsResults.AclResponse
            AclEvaluationResult: TypeAlias = FlextLdifModelsResults.AclEvaluationResult

            MigrationEntriesResult: TypeAlias = (
                FlextLdifModelsResults.MigrationEntriesResult
            )
            MigrationPipelineResult: TypeAlias = (
                FlextLdifModelsResults.MigrationPipelineResult
            )

            ValidationResult: TypeAlias = FlextLdifModelsResults.ValidationResult
            ValidationBatchResult: TypeAlias = (
                FlextLdifModelsResults.ValidationBatchResult
            )
            LdifValidationResult: TypeAlias = (
                FlextLdifModelsResults.LdifValidationResult
            )

            DynamicCounts = FlextLdifModelsResults.DynamicCounts
            FlexibleCategories: TypeAlias = _FlexibleCategories

            ClientStatus = FlextLdifModelsResults.ClientStatus
            ServiceStatus = FlextLdifModelsResults.ServiceStatus

            DictAccessibleValue = FlextLdifModelsResults.DictAccessibleValue
            BooleanFlags = FlextLdifModelsResults.BooleanFlags
            ConfigSettings = FlextLdifModelsResults.ConfigSettings
            CategoryPaths = FlextLdifModelsResults.CategoryPaths
            EventType = FlextLdifModelsResults.EventType

        class LdifResults:
            """Backward-compatible namespace for result types."""

            AclResponse: TypeAlias = FlextLdifModelsResults.AclResponse
            AclEvaluationResult: TypeAlias = FlextLdifModelsResults.AclEvaluationResult
            AclPermissions: TypeAlias = FlextLdifModelsDomains.AclPermissions

            Statistics: TypeAlias = FlextLdifModelsResults.Statistics
            StatisticsResult: TypeAlias = FlextLdifModelsResults.StatisticsResult
            StatisticsSummary: TypeAlias = FlextLdifModelsResults.StatisticsSummary
            EntriesStatistics: TypeAlias = FlextLdifModelsResults.EntriesStatistics

            ClientStatus: TypeAlias = FlextLdifModelsResults.ClientStatus
            StatisticsServiceStatus: TypeAlias = (
                FlextLdifModelsResults.StatisticsServiceStatus
            )
            SchemaServiceStatus: TypeAlias = FlextLdifModelsResults.SchemaServiceStatus
            SyntaxServiceStatus: TypeAlias = FlextLdifModelsResults.SyntaxServiceStatus
            ValidationServiceStatus: TypeAlias = (
                FlextLdifModelsResults.ValidationServiceStatus
            )
            EntryAnalysisResult: TypeAlias = FlextLdifModelsResults.EntryAnalysisResult
            ServiceStatus: TypeAlias = FlextLdifModelsResults.ServiceStatus
            Syntax: TypeAlias = FlextLdifModelsDomains.Syntax

            ParseResponse: TypeAlias = FlextLdifModelsResults.ParseResponse
            WriteResponse: TypeAlias = FlextLdifModelsResults.WriteResponse
            WriteOptions: TypeAlias = FlextLdifModelsDomains.WriteOptions
            WriteFormatOptions: TypeAlias = FlextLdifModelsSettings.WriteFormatOptions

            SchemaDiscoveryResult: TypeAlias = (
                FlextLdifModelsResults.SchemaDiscoveryResult
            )
            SchemaBuilderResult: TypeAlias = FlextLdifModelsResults.SchemaBuilderResult
            SyntaxLookupResult: TypeAlias = FlextLdifModelsResults.SyntaxLookupResult

            MigrationEntriesResult: TypeAlias = (
                FlextLdifModelsResults.MigrationEntriesResult
            )
            MigrationPipelineResult: TypeAlias = (
                FlextLdifModelsResults.MigrationPipelineResult
            )

            ValidationResult: TypeAlias = FlextLdifModelsResults.ValidationResult
            ValidationBatchResult: TypeAlias = (
                FlextLdifModelsResults.ValidationBatchResult
            )
            LdifValidationResult: TypeAlias = (
                FlextLdifModelsResults.LdifValidationResult
            )

            ServerDetectionResult: TypeAlias = (
                FlextLdifModelsResults.ServerDetectionResult
            )
            AnalysisResult: TypeAlias = FlextLdifModelsResults.AnalysisResult
            EntryResult: TypeAlias = FlextLdifModelsResults.EntryResult

            FlexibleCategories: TypeAlias = _FlexibleCategories
            DynamicCounts = FlextLdifModelsResults.DynamicCounts

            DnEvent: TypeAlias = FlextLdifModelsEvents.DnEvent
            DnEventConfig: TypeAlias = FlextLdifModelsEvents.DnEventConfig

            CategoryRules: TypeAlias = FlextLdifModelsSettings.CategoryRules
            WhitelistRules: TypeAlias = FlextLdifModelsSettings.WhitelistRules
            SortConfig: TypeAlias = FlextLdifModelsSettings.SortConfig

            class Events:
                """Events namespace for conversion events."""

                ConversionEventConfig = FlextLdifModelsEvents.ConversionEventConfig

        class Types:
            """Type models namespace - moved from typings.py TypedDict to Pydantic models."""

            class SchemaDict(FlextModelsBase.ArbitraryTypesModel):
                """Schema extraction result dictionary model."""

                ATTRIBUTES: list[FlextLdifModelsDomains.SchemaAttribute] = Field(
                    default_factory=list,
                )
                OBJECTCLASS: list[FlextLdifModelsDomains.SchemaObjectClass] = Field(
                    default_factory=list,
                )

            class PermissionsDict(FlextModelsBase.ArbitraryTypesModel):
                """ACL permissions dictionary model."""

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
                """ACL evaluation context dictionary model."""

                subject_dn: str | None = Field(default=None)
                target_dn: str | None = Field(default=None)
                operation: str | None = Field(default=None)
                attributes: list[str] | None = Field(default=None)

            class TransformationInfo(FlextModelsBase.ArbitraryTypesModel):
                """Transformation step information model."""

                step: str | None = Field(default=None)
                server: str | None = Field(default=None)
                changes: list[str] | None = Field(default=None)

            class QuirksByServerDict(FlextModelsBase.ArbitraryTypesModel):
                """Quirks by server dictionary model."""

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
                """Registry statistics dictionary model."""

                total_servers: int = Field(default=0)
                quirks_by_server: dict[
                    str,
                    FlextLdifModels.Ldif.Types.QuirksByServerDict,
                ] = Field(default_factory=dict)
                server_priorities: dict[str, int] = Field(default_factory=dict)

            class EntryParsingContext(FlextModelsBase.ArbitraryTypesModel):
                """Entry parsing context model."""

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
                """Attribute write context model."""

                attr_name: str | None = Field(default=None)
                attr_values: FlextTypes.GeneralValueType | None = Field(default=None)
                minimal_differences_attrs: dict[
                    str,
                    FlextTypes.MetadataAttributeValue,
                ] = Field(default_factory=dict)
                hidden_attrs: set[str] = Field(default_factory=set)

            type BooleanFormat = Literal["TRUE/FALSE", "true/false", "1/0", "yes/no"]

            type AttributeMetadataMap = dict[str, dict[str, str | list[str]]]

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

        class Registry:
            """Registry-related type aliases using protocols."""

            type QuirksDict = dict[
                str,
                p.Ldif.SchemaQuirkProtocol
                | p.Ldif.AclQuirkProtocol
                | p.Ldif.EntryQuirkProtocol
                | None,
            ]

        class ProcessingConfig:
            """Processing configuration models namespace."""

            EntryTransformConfig = FlextLdifModelsSettings.EntryTransformConfig
            EntryFilterConfig = FlextLdifModelsSettings.EntryFilterConfig
            CaseFoldOption = c.Ldif.CaseFoldOption


m = FlextLdifModels

__all__ = ["FlextLdifModels", "m"]
