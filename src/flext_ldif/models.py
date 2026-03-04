"""LDIF Domain Models - Unified Model Aggregation Layer.

Facade that groups all LDIF model classes for the ``FlextLdifModels``
namespace.  Every nested class uses real MRO inheritance from its
internal ``_models`` definition — no ``TypeAlias`` for classes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, TypeAlias

from flext_core import FlextModels
from pydantic import Field

from flext_ldif import c, p, t
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.events import FlextLdifModelsEvents
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._models.processing import ProcessingResult
from flext_ldif._models.results import FlextLdifModelsResults
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


class FlextLdifModels(FlextModels):
    """LDIF domain models — flat façade with MRO class inheritance.

    Architecture: Domain layer helper
    All nested classes inherit via MRO from their ``_models`` implementations.
    Types live in ``typings.py``, constants in ``constants.py``.
    """

    class Ldif:
        """LDIF namespace for cross-project access."""

        # =================================================================
        # TYPE ALIASES — non-class types only (enums, unions, containers)
        # Class-level types moved to FlextLdifTypes.Ldif in typings.py
        # =================================================================

        EntryAttributesDict: TypeAlias = t.Ldif.EntryAttributesDict
        RawEntryDict: TypeAlias = t.Ldif.RawEntryDict

        ServerType: TypeAlias = c.Ldif.ServerTypes
        SpaceHandlingOption: TypeAlias = c.Ldif.SpaceHandlingOption
        EscapeHandlingOption: TypeAlias = c.Ldif.EscapeHandlingOption
        SortOption: TypeAlias = c.Ldif.SortOption
        OutputFormat: TypeAlias = c.Ldif.Domain.OutputFormat

        # =================================================================
        # DOMAIN MODELS — MRO class inheritance (FlextLdifModelsDomains)
        # =================================================================

        class AttributeTransformation(FlextLdifModelsDomains.AttributeTransformation):
            """Detailed tracking of attribute transformation operations."""

        class Entry(FlextLdifModelsDomains.Entry):
            """LDIF entry with DN and attributes."""

        class DN(FlextLdifModelsDomains.DN):
            """Distinguished Name model."""

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

        class SchemaAttribute(FlextLdifModelsDomains.SchemaAttribute):
            """LDAP schema attribute definition."""

        class SchemaObjectClass(FlextLdifModelsDomains.SchemaObjectClass):
            """LDAP schema object class definition."""

        class Syntax(FlextLdifModelsDomains.Syntax):
            """LDAP attribute syntax definition."""

        class Attributes(FlextLdifModelsDomains.Attributes):
            """Dictionary-like container for LDIF attributes."""

        class FormatDetails(FlextLdifModelsDomains.FormatDetails):
            """Format details for entry output."""

        class SchemaFormatDetails(FlextLdifModelsDomains.SchemaFormatDetails):
            """Schema format details."""

        class EntryStatistics(FlextLdifModelsDomains.EntryStatistics):
            """Statistics for an LDIF entry."""

        class DNStatistics(FlextLdifModelsDomains.DNStatistics):
            """Statistics for a DN."""

        class WriteOptions(FlextLdifModelsDomains.WriteOptions):
            """Write output options."""

        class ProcessingResult(ProcessingResult):
            """Processing result with DN and attributes."""

        # =================================================================
        # METADATA MODELS — MRO class inheritance
        # =================================================================

        class DynamicMetadata(FlextLdifModelsMetadata.DynamicMetadata):
            """Model with extra='allow' for dynamic field storage."""

        class EntryMetadata(FlextLdifModelsMetadata.EntryMetadata):
            """Model for entry processing metadata."""

        # =================================================================
        # SETTINGS/CONFIG MODELS — MRO class inheritance
        # =================================================================

        class LogContextExtras(FlextLdifModelsSettings.LogContextExtras):
            """Log context extras configuration."""

        class AclMetadataConfig(FlextLdifModelsSettings.AclMetadataConfig):
            """Configuration for ACL metadata extensions."""

        class AciParserConfig(FlextLdifModelsSettings.AciParserConfig):
            """ACI parser configuration."""

        class AciWriterConfig(FlextLdifModelsSettings.AciWriterConfig):
            """ACI writer configuration."""

        class AciLineFormatConfig(FlextLdifModelsSettings.AciLineFormatConfig):
            """ACI line format configuration."""

        class ServerPatternsConfig(FlextLdifModelsSettings.ServerPatternsConfig):
            """Server pattern matching configuration."""

        class AttributeDenormalizeConfig(
            FlextLdifModelsSettings.AttributeDenormalizeConfig,
        ):
            """Attribute denormalization configuration."""

        class AttributeNormalizeConfig(
            FlextLdifModelsSettings.AttributeNormalizeConfig,
        ):
            """Attribute normalization configuration."""

        class EntryCriteriaConfig(FlextLdifModelsSettings.EntryCriteriaConfig):
            """Entry criteria matching configuration."""

        class EntryTransformConfig(FlextLdifModelsSettings.EntryTransformConfig):
            """Entry transformation configuration."""

        class EntryFilterConfig(FlextLdifModelsSettings.EntryFilterConfig):
            """Entry filter configuration."""

        class EntryWriteConfig(FlextLdifModelsSettings.EntryWriteConfig):
            """Entry write configuration."""

        class EntryParseMetadataConfig(
            FlextLdifModelsSettings.EntryParseMetadataConfig,
        ):
            """Entry parse metadata configuration."""

        class BatchWriteConfig(FlextLdifModelsSettings.BatchWriteConfig):
            """Batch write configuration."""

        class RdnProcessingConfig(FlextLdifModelsSettings.RdnProcessingConfig):
            """RDN processing configuration."""

        class DnCaseRules(FlextLdifModelsSettings.DnCaseRules):
            """DN case rules configuration."""

        class EncodingRules(FlextLdifModelsSettings.EncodingRules):
            """Encoding rules configuration."""

        class AclFormatRules(FlextLdifModelsSettings.AclFormatRules):
            """ACL format rules configuration."""

        class ServerValidationRules(FlextLdifModelsSettings.ServerValidationRules):
            """Server validation rules configuration."""

        class FilterCriteria(FlextLdifModelsSettings.FilterCriteria):
            """Filter criteria configuration."""

        class MetadataTransformationConfig(
            FlextLdifModelsSettings.MetadataTransformationConfig,
        ):
            """Metadata transformation configuration."""

        class PermissionMappingConfig(
            FlextLdifModelsSettings.PermissionMappingConfig,
        ):
            """Permission mapping configuration."""

        class SchemaConversionPipelineConfig(
            FlextLdifModelsSettings.SchemaConversionPipelineConfig,
        ):
            """Schema conversion pipeline configuration."""

        class CategoryRules(FlextLdifModelsSettings.CategoryRules):
            """Category rules configuration."""

        class WhitelistRules(FlextLdifModelsSettings.WhitelistRules):
            """Whitelist rules configuration."""

        class SortConfig(FlextLdifModelsSettings.SortConfig):
            """Sort configuration."""

        class ParseFormatOptions(FlextLdifModelsSettings.ParseFormatOptions):
            """Parse format options."""

        class MigrateOptions(FlextLdifModelsSettings.MigrateOptions):
            """Migration options."""

        class WriteOutputOptions(FlextLdifModelsSettings.WriteOutputOptions):
            """Write output options."""

        class WriteFormatOptions(FlextLdifModelsSettings.WriteFormatOptions):
            """Write format options."""

        class DnNormalizationConfig(DnNormalizationConfig):
            """DN normalization configuration."""

        class AttrNormalizationConfig(AttrNormalizationConfig):
            """Attribute normalization configuration."""

        class AclConversionConfig(AclConversionConfig):
            """ACL conversion configuration."""

        class ValidationConfig(ValidationConfig):
            """Validation configuration."""

        class MetadataConfig(MetadataConfig):
            """Metadata configuration."""

        class ProcessConfig(ProcessConfig):
            """Process configuration."""

        class TransformConfig(TransformConfig):
            """Transform configuration."""

        class FilterConfig(FilterConfig):
            """Filter configuration."""

        class WriteConfig(WriteConfig):
            """Write configuration."""

        # =================================================================
        # EVENT MODELS — MRO class inheritance
        # =================================================================

        class DnEvent(FlextLdifModelsEvents.DnEvent):
            """DN event."""

        class DnEventConfig(FlextLdifModelsEvents.DnEventConfig):
            """DN event configuration."""

        class MigrationEvent(FlextLdifModelsEvents.MigrationEvent):
            """Migration event."""

        class MigrationEventConfig(FlextLdifModelsEvents.MigrationEventConfig):
            """Migration event configuration."""

        class ConversionEvent(FlextLdifModelsEvents.ConversionEvent):
            """Conversion event."""

        class ConversionEventConfig(FlextLdifModelsEvents.ConversionEventConfig):
            """Conversion event configuration."""

        class SchemaEvent(FlextLdifModelsEvents.SchemaEvent):
            """Schema event."""

        class SchemaEventConfig(FlextLdifModelsEvents.SchemaEventConfig):
            """Schema event configuration."""

        class ParseEvent(FlextLdifModelsEvents.ParseEvent):
            """Parse event."""

        class WriteEvent(FlextLdifModelsEvents.WriteEvent):
            """Write event."""

        class AclEvent(FlextLdifModelsEvents.AclEvent):
            """ACL event."""

        class CategoryEvent(FlextLdifModelsEvents.CategoryEvent):
            """Category event."""

        class FilterEvent(FlextLdifModelsEvents.FilterEvent):
            """Filter event."""

        # =================================================================
        # RESULT MODELS — MRO class inheritance
        # =================================================================

        class Statistics(FlextLdifModelsResults.Statistics):
            """Statistics result."""

        class StatisticsResult(FlextLdifModelsResults.StatisticsResult):
            """Statistics result container."""

        class StatisticsSummary(FlextLdifModelsResults.StatisticsSummary):
            """Statistics summary."""

        class EntriesStatistics(FlextLdifModelsResults.EntriesStatistics):
            """Entries statistics."""

        class MigrationSummary(FlextLdifModelsResults.MigrationSummary):
            """Migration summary."""

        class EntryAnalysisResult(FlextLdifModelsResults.EntryAnalysisResult):
            """Entry analysis result."""

        class ServerDetectionResult(FlextLdifModelsResults.ServerDetectionResult):
            """Server detection result."""

        class ParseResponse(FlextLdifModelsResults.ParseResponse):
            """Parse response."""

        class WriteResponse(FlextLdifModelsResults.WriteResponse):
            """Write response."""

        class AclResponse(FlextLdifModelsResults.AclResponse):
            """ACL response."""

        class AclEvaluationResult(FlextLdifModelsResults.AclEvaluationResult):
            """ACL evaluation result."""

        class MigrationPipelineResult(FlextLdifModelsResults.MigrationPipelineResult):
            """Migration pipeline result."""

        class ValidationServiceStatus(FlextLdifModelsResults.ValidationServiceStatus):
            """Validation service status."""

        class ValidationBatchResult(FlextLdifModelsResults.ValidationBatchResult):
            """Validation batch result."""

        class EntryResult(FlextLdifModelsResults.EntryResult):
            """Entry result."""

        class DynamicCounts(FlextLdifModelsResults.DynamicCounts):
            """Dynamic counts."""

        class FlexibleCategories(FlextLdifModelsResults.FlexibleCategories):
            """Flexible categories."""

        class ClientStatus(FlextLdifModelsResults.ClientStatus):
            """Client status."""

        class ServiceStatus(FlextLdifModelsResults.ServiceStatus):
            """Service status."""

        class SchemaServiceStatus(FlextLdifModelsResults.SchemaServiceStatus):
            """Schema service status."""

        class StatisticsServiceStatus(FlextLdifModelsResults.StatisticsServiceStatus):
            """Statistics service status."""

        class DictAccessibleValue(FlextLdifModelsResults.DictAccessibleValue):
            """Dict-accessible value."""

        class BooleanFlags(FlextLdifModelsResults.BooleanFlags):
            """Boolean flags."""

        class ConfigSettings(FlextLdifModelsResults.ConfigSettings):
            """Config settings."""

        class CategoryPaths(FlextLdifModelsResults.CategoryPaths):
            """Category paths."""

        class EventType(FlextLdifModelsResults.EventType):
            """Event type."""

        class SyntaxServiceStatus(FlextLdifModelsResults.SyntaxServiceStatus):
            """Syntax service status."""

        class ValidationResult(FlextLdifModelsResults.ValidationResult):
            """Validation result."""

        # =================================================================
        # COMPOSITE MODELS — defined here, not in _models
        # =================================================================

        class QuirksByServerDict(FlextModels.ArbitraryTypesModel):
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

        class RegistryStatsDict(FlextModels.ArbitraryTypesModel):
            """Registry statistics dictionary model."""

            total_servers: int = Field(default=0)
            quirks_by_server: dict[
                str,
                FlextLdifModels.Ldif.QuirksByServerDict,
            ] = Field(default_factory=dict)
            server_priorities: dict[str, int] = Field(default_factory=dict)

        # =================================================================
        # NON-CLASS TYPE ALIASES — type unions, protocol references
        # =================================================================

        class Schema:
            """Schema element type with protocol references."""

            type SchemaElement = (
                FlextLdifModels.Ldif.SchemaAttribute
                | FlextLdifModels.Ldif.SchemaObjectClass
                | str
                | int
                | float
                | bool
                | None
            )

        class Registry:
            """Registry-related type aliases using protocols."""

            type QuirksDict = Mapping[
                str,
                p.Ldif.SchemaQuirkProtocol
                | p.Ldif.AclQuirkProtocol
                | p.Ldif.EntryQuirkProtocol
                | None,
            ]

        class ProcessingConfig:
            """Processing configuration models namespace."""

            EntryTransformConfig: Final = FlextLdifModelsSettings.EntryTransformConfig
            EntryFilterConfig: Final = FlextLdifModelsSettings.EntryFilterConfig
            CaseFoldOption: Final = c.Ldif.CaseFoldOption


# =========================================================================
# MODULE ALIASES - Runtime access patterns
# =========================================================================

m = FlextLdifModels

__all__ = ["FlextLdifModels", "m"]
