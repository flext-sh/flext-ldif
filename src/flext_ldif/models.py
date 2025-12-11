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

import warnings
from collections.abc import Sequence
from enum import StrEnum
from typing import Literal

from flext_core import FlextModels, FlextTypes
from flext_core._models.base import FlextModelsBase
from flext_core._models.collections import FlextModelsCollections
from pydantic import BaseModel, Field

from flext_ldif._models.config import FlextLdifModelsSettings
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.events import FlextLdifModelsEvents
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._models.processing import ProcessingResult as ProcessingResultModel
from flext_ldif._models.results import FlextLdifModelsResults
from flext_ldif.constants import FlextLdifConstants as c
from flext_ldif.protocols import FlextLdifProtocols as p

# Type aliases for LDIF domain - exposed via m.Ldif namespace
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

        # Event models - real inheritance classes
        class DnEventConfig(FlextLdifModelsEvents.DnEventConfig):
            """DN event configuration."""

        class DnEvent(FlextLdifModelsEvents.DnEvent):
            """DN event model."""

        class MigrationEventConfig(FlextLdifModelsEvents.MigrationEventConfig):
            """Migration event configuration."""

        class MigrationEvent(FlextLdifModelsEvents.MigrationEvent):
            """Migration event model."""

        class CategoryEvent(FlextLdifModelsEvents.CategoryEvent):
            """Category event model."""

        class ConversionEventConfig(FlextLdifModelsEvents.ConversionEventConfig):
            """Conversion event configuration."""

        class ConversionEvent(FlextLdifModelsEvents.ConversionEvent):
            """Conversion event model."""

        class SchemaEventConfig(FlextLdifModelsEvents.SchemaEventConfig):
            """Configuration for schema event creation.

            Consolidates parameters for create_schema_event utility function.
            Reduces function signature from 7 parameters to 1 model.

            Example:
                config = FlextLdifModels.SchemaEventConfig(
                    schema_operation="parse_attribute",
                    items_processed=50,
                    items_succeeded=48,
                    items_failed=2,
                    operation_duration_ms=125.3,
                    server_type=c.Ldif.ServerType.OUD,
                )
                event = FlextLdifUtilitiesEvents.create_schema_event(config)

            """

        class SchemaEvent(FlextLdifModelsEvents.SchemaEvent):
            """Schema event model."""

        # Statistics and domain models - real inheritance classes
        class EntryStatistics(FlextLdifModelsDomains.EntryStatistics):
            """Entry statistics model."""

        class DNStatistics(FlextLdifModelsDomains.DNStatistics):
            """DN statistics model."""

        class TransformationFlags(FlextLdifModelsDomains.DNStatisticsFlags):
            """Type for DN transformation flags.

            Public type for tracking DN transformation state during cleaning operations.
            Used internally by FlextLdifUtilitiesDN for collecting transformation metadata.
            """

        class WriteOptions(FlextLdifModelsDomains.WriteOptions):
            """Write options model."""

        class Syntax(FlextLdifModelsDomains.Syntax):
            """Syntax model."""

        # Metadata models - real inheritance classes
        class QuirkMetadata(FlextLdifModelsDomains.QuirkMetadata):
            """Quirk metadata model for server-specific extensions."""

        # DN models - real inheritance classes
        class DN(FlextLdifModelsDomains.DN):
            """Distinguished Name model."""

        class ErrorDetail(FlextLdifModelsDomains.ErrorDetail):
            """Error detail information for failed operations."""

        # Processing result models - real inheritance classes
        class ProcessingResult(ProcessingResultModel):
            """Processing result model."""

        class ParseResponse(FlextLdifModelsResults.ParseResponse):
            """Parse response model."""

        class WriteResponse(FlextLdifModelsResults.WriteResponse):
            """Write response model."""

        # =========================================================================
        # DTO MODELS - Data transfer objects
        # =========================================================================

        # SearchConfig deleted (0 usages) - use proper typed models for LDAP search config
        # DiffItem and DiffResult deleted (0 usages) - use typed models for diff operations

        class FilterCriteria(FlextLdifModelsSettings.FilterCriteria):
            """Criteria for filtering LDIF entries.

            Supports multiple filter types:
            - dn_pattern: Wildcard DN pattern matching (e.g., "*,dc=example,dc=com")
            Uses c.Ldif.FilterType.DN_PATTERN for type safety
            - oid_pattern: OID pattern matching with wildcard support
            - objectclass: Filter by objectClass with optional attribute validation
            - attribute: Filter by attribute presence/absence

            Example:
                criteria = FilterCriteria(
                    filter_type=c.Ldif.FilterType.DN_PATTERN,
                    pattern="*,ou=users,dc=example,dc=com",
                    mode=c.FilterMode.INCLUDE
                )

            """

        class CategoryRules(FlextLdifModelsSettings.CategoryRules):
            """Rules for entry categorization.

            Contains DN patterns and objectClass lists for each category.
            Replaces dict[str, str | list[str] | None] with type-safe Pydantic model.
            """

        class WhitelistRules(FlextLdifModelsSettings.WhitelistRules):
            """Whitelist rules for entry validation.

            Defines blocked objectClasses and validation rules.
            Replaces dict[str, str | list[str] | bool | None] with type-safe Pydantic model.
            """

        class ExclusionInfo(FlextLdifModelsDomains.ExclusionInfo):
            """Metadata for excluded entries/schema items.

            Stored in QuirkMetadata.extensions['exclusion_info'] to track why
            an entry was excluded during filtering operations.

            Example:
                exclusion = ExclusionInfo(
                    excluded=True,
                    exclusion_reason="DN outside base context",
                    filter_criteria=FilterCriteria(
                        filter_type=c.Ldif.FilterType.DN_PATTERN,
                        pattern="*,dc=old,dc=com"
                    ),
                    timestamp="2025-10-09T12:34:56Z"
                )

            """

        class CategorizedEntries(FlextLdifModelsResults.CategorizedEntries):
            """Result of entry categorization by objectClass.

            Categorizes LDIF entries into users, groups, containers, and uncategorized
            based on configurable objectClass sets.

            Example:
                categorized = CategorizedEntries(
                    users=[user_entry1, user_entry2],
                    groups=[group_entry1],
                    containers=[ou_entry1, ou_entry2],
                    uncategorized=[],
                    summary={"users": 2, "groups": 1, "containers": 2, "uncategorized": 0}
                )

            """

        # Statistics type alias - extends FlextModels.Statistics with LDIF-specific fields
        # FlextLdifModelsResults.Statistics inherits from FlextModelsCollections.Statistics,
        # so it's compatible with FlextModels.Statistics while adding LDIF-specific metrics.
        # Business Rule: Statistics model is frozen (immutable) to ensure data integrity
        # during processing pipelines. All statistics operations return new instances
        # rather than modifying existing ones, following functional programming principles.
        # Both parent and child are frozen (FrozenValueModel), ensuring consistent mutability.
        # Note: We cannot override Statistics with a type alias because parent Statistics
        # is also a type alias to FlextModelsCollections.Statistics. Type aliases cannot
        # be overridden with incompatible types. Instead, LDIF-specific statistics are
        # available via FlextLdifModels.Results.Statistics which extends the base Statistics.
        # Users should use:
        # - FlextLdifModels.Statistics (from parent) for base statistics
        # - FlextLdifModels.Results.Statistics for LDIF-specific statistics with additional fields
        # This avoids type system conflicts while maintaining API clarity.
        # Statistics type alias removed - use Results.Statistics for LDIF-specific stats

        class StatisticsResult(FlextLdifModelsResults.StatisticsResult):
            """Result of statistics operations.

            Contains computed statistics with optional metadata and processing details.
            Provides structured access to statistical data with error handling.

            Example:
                result = StatisticsResult(
                    statistics=Statistics(...),
                    metadata={"processing_version": "1.0.0", "source": "client-a.ldif"},
                    errors=[]
                )

            """

        class EntriesStatistics(FlextLdifModelsResults.EntriesStatistics):
            """Statistics for LDIF entries.

            Detailed breakdown of entry processing metrics including counts, types,
            and processing status. Helps identify patterns and issues in LDIF data.

            Example:
                entries_stats = EntriesStatistics(
                    total_entries=1500,
                    processed_entries=1450,
                    failed_entries=50,
                    entries_by_objectclass={"person": 800, "group": 200, "ou": 450},
                    large_entries={"dn1": 50000, "dn2": 45000},
                    empty_entries=10
                )

            """

        class DictAccessibleValue(FlextLdifModelsResults.DictAccessibleValue):
            """Value accessible as dictionary.

            Provides dictionary-like access to values with additional type safety.
            Useful for accessing nested data structures in results.

            """

        class SchemaServiceStatus(FlextLdifModelsResults.SchemaServiceStatus):
            """Status information for schema service operations.

            Tracks schema processing state with detailed metadata about
            attributes, objectClasses, and syntax processing.

            Example:
                schema_status = SchemaServiceStatus(
                    status="completed",
                    attributes_processed=45,
                    objectclasses_processed=12,
                    syntaxes_processed=8,
                    errors=[],
                    processing_time_seconds=1.23
                )

            """

        class SyntaxServiceStatus(FlextLdifModelsResults.SyntaxServiceStatus):
            """Status information for syntax service operations.

            Tracks syntax validation and processing state with detailed
            information about syntax checks and conversions.

            Example:
                syntax_status = SyntaxServiceStatus(
                    status="completed",
                    total_attributes=1500,
                    syntax_validated=1480,
                    syntax_errors=20,
                    conversions_performed=15,
                    processing_time_seconds=0.89
                )

            """

        class StatisticsServiceStatus(FlextLdifModelsResults.StatisticsServiceStatus):
            """Status information for statistics service operations.

            Tracks statistics computation state with performance metrics
            and processing details.

            Example:
                stats_status = StatisticsServiceStatus(
                    status="completed",
                    entries_analyzed=1500,
                    statistics_computed=1450,
                    computation_time_seconds=2.34,
                    memory_used_mb=45.6,
                    errors=[]
                )

            """

        class ValidationServiceStatus(FlextLdifModelsResults.ValidationServiceStatus):
            """Status information for validation service operations.

            Tracks validation processing with detailed error reporting
            and performance metrics.

            Example:
                validation_status = ValidationServiceStatus(
                    status="completed_with_errors",
                    total_entries=1500,
                    valid_entries=1400,
                    invalid_entries=100,
                    errors=[ErrorDetail(...)],
                    processing_time_seconds=3.45
                )

            """

        class ValidationBatchResult(FlextLdifModelsResults.ValidationBatchResult):
            """Result of batch validation operations.

            Contains aggregated validation results for multiple entries
            with summary statistics and detailed error information.

            Example:
                batch_result = ValidationBatchResult(
                    batch_id="batch_001",
                    total_entries=100,
                    valid_entries=90,
                    invalid_entries=10,
                    errors=[ErrorDetail(...)],
                    summary={"validation_time": 1.23, "error_rate": 0.1}
                )

            """

        # Type alias for flexible categorization of LDIF entries (PEP 695)
        # Use FlextModelsCollections.Categories directly since FlextModels.Categories is a type alias
        type FlexibleCategories = FlextModelsCollections.Categories[
            FlextLdifModels.Ldif.Entry
        ]

        # Schema models - real inheritance classes
        class SchemaAttribute(FlextLdifModelsDomains.SchemaAttribute):
            """Schema attribute model."""

        class SchemaObjectClass(FlextLdifModelsDomains.SchemaObjectClass):
            """Schema objectClass model."""

        # ACL models - real inheritance classes
        class Acl(FlextLdifModelsDomains.Acl):
            """ACL (Access Control List) model."""

        class AclTarget(FlextLdifModelsDomains.AclTarget):
            """ACL target model."""

        class AclSubject(FlextLdifModelsDomains.AclSubject):
            """ACL subject model."""

        class AclPermissions(FlextLdifModelsDomains.AclPermissions):
            """ACL permissions model."""

        class DnRegistry(FlextLdifModelsDomains.DnRegistry):
            """DN registry model."""

        class Entry(FlextLdifModelsDomains.Entry):
            """LDIF entry with DN and attributes.

            Represents a complete LDAP directory entry with distinguished name
            and associated attributes. Provides type-safe access to entry data
            with validation and normalization capabilities.

            Example:
                entry = Entry(
                    dn="cn=john.doe,ou=users,dc=example,dc=com",
                    attributes={
                        "cn": ["john.doe"],
                        "sn": ["Doe"],
                        "givenName": ["John"],
                        "objectClass": ["person", "organizationalPerson", "user"],
                        "userPassword": ["{SSHA}hashedpassword"]
                    }
                )

            """

        class ValidationMetadata(FlextLdifModelsDomains.ValidationMetadata):
            """Metadata for validation operations.

            Contains information about validation processing including
            timestamps, processing details, and validation state.

            Example:
                metadata = ValidationMetadata(
                    validated_at="2025-10-09T12:34:56Z",
                    validation_version="1.0.0",
                    processing_details={"schema_check": True, "syntax_check": True},
                    validation_errors=[]
                )

            """

        # Server validation rule models - exposed for test access
        class ServerValidationRules(FlextLdifModelsSettings.ServerValidationRules):
            """Server-specific validation rules."""

        class EncodingRules(FlextLdifModelsSettings.EncodingRules):
            """Encoding rules for LDIF processing."""

        class DnCaseRules(FlextLdifModelsSettings.DnCaseRules):
            """DN case handling rules."""

        class AclFormatRules(FlextLdifModelsSettings.AclFormatRules):
            """ACL format rules."""

        class FormatDetails(FlextLdifModelsDomains.FormatDetails):
            r"""Original formatting details for round-trip preservation.

            Preserves original LDIF formatting information to maintain
            exact representation during parsing and rewriting operations.

            Example:
                details = FormatDetails(
                    line_width=78,
                    include_version_header=True,
                    include_timestamps=False,
                    encoding="utf-8",
                    line_ending="\n"
                )

            """

        class SchemaFormatDetails(FlextLdifModelsDomains.SchemaFormatDetails):
            """Original schema formatting details.

            Preserves schema-specific formatting for accurate round-trip
            processing of LDAP schema definitions.

            """

        class Attributes(FlextLdifModelsDomains.Attributes):
            """LDIF attribute collection.

            Manages collections of LDAP attributes with type safety and
            validation. Provides convenient access to attribute values
            with support for single and multi-valued attributes.

            Example:
                attributes = Attributes({
                    "cn": ["john.doe"],
                    "member": ["cn=user1,ou=users,dc=example,dc=com", "cn=user2,ou=users,dc=example,dc=com"],
                    "description": ["User account for John Doe"]
                })

            """

        class EntryAnalysisResult(FlextLdifModelsResults.EntryAnalysisResult):
            """Result of entry analysis operations.

            Contains detailed analysis of a single LDIF entry including
            validation results, statistics, and processing metadata.

            Example:
                analysis = EntryAnalysisResult(
                    entry=Entry(...),
                    validation_result=ValidationResult(...),
                    statistics={"attributes": 5, "values": 12},
                    processing_time_seconds=0.012,
                    errors=[]
                )

            """

        class WriteFormatOptions(FlextLdifModelsSettings.WriteFormatOptions):
            r"""Options for controlling LDIF write formatting.

            Configures how LDIF content is formatted during writing operations.
            Controls line width, encoding, headers, and other formatting aspects.

            Example:
                options = WriteFormatOptions(
                    line_width=78,
                    include_version_header=True,
                    include_timestamps=False,
                    encoding="utf-8",
                    line_ending="\n",
                    normalize_attribute_names=True,
                    base64_encode_binary=True,
                    respect_attribute_order=False
                )

            """

        class WriteOutputOptions(FlextLdifModelsSettings.WriteOutputOptions):
            """Options for controlling LDIF write output behavior.

            Configures output destinations and processing behavior for
            LDIF writing operations.

            Example:
                output_options = WriteOutputOptions(
                    output_target="file",
                    output_path=Path("/tmp/output.ldif"),
                    template_data={},
                    use_original_acl_format=False,
                    include_dn_comments=False
                )

            """

        class MigrationPipelineResult(FlextLdifModelsResults.MigrationPipelineResult):
            """Result of migration pipeline operations.

            Contains comprehensive results from migration processing including
            success/failure status, processed entries, and detailed statistics.

            Example:
                pipeline_result = MigrationPipelineResult(
                    success=True,
                    total_entries=1500,
                    processed_entries=1450,
                    failed_entries=50,
                    statistics=Statistics(...),
                    errors=[ErrorDetail(...)],
                    processing_time_seconds=45.6
                )

            """

        class ClientStatus(FlextLdifModelsResults.ClientStatus):
            """Status information for LDAP client connections.

            Tracks connection state and health for LDAP client operations.

            Example:
                status = ClientStatus(
                    connected=True,
                    server_type="openldap",
                    last_operation="search",
                    connection_time_seconds=10.5,
                    operations_count=42
                )

            """

        class ValidationResult(FlextLdifModelsResults.ValidationResult):
            """Result of validation operations.

            Contains validation outcome with detailed error information
            and processing metadata.

            Example:
                result = ValidationResult(
                    valid=True,
                    errors=[],
                    warnings=[],
                    processing_time_seconds=1.23,
                    validated_at="2025-10-09T12:34:56Z"
                )

            """

        class MigrationEntriesResult(FlextLdifModelsResults.MigrationEntriesResult):
            """Result of migration entry processing.

            Contains results from processing individual entries during
            migration operations.

            Example:
                entries_result = MigrationEntriesResult(
                    total_entries=100,
                    migrated_entries=95,
                    failed_entries=5,
                    entries=[Entry(...)],
                    errors=[ErrorDetail(...)]
                )

            """

        class EntryResult(FlextLdifModelsResults.EntryResult):
            """Result of LDIF processing containing categorized entries and statistics.

            This is the UNIFIED result model for all LDIF operations. Contains entries
            categorized by type and comprehensive processing statistics.

            Example:
                result = EntryResult(
                    entries=[Entry(...)],
                    users=[Entry(...)],
                    groups=[Entry(...)],
                    containers=[Entry(...)],
                    statistics=Statistics(...),
                    processing_time_seconds=2.34
                )

            """

        class ServerDetectionResult(FlextLdifModelsResults.ServerDetectionResult):
            """Result of LDAP server detection operations.

            Contains detected server type and confidence information
            from LDIF content analysis.

            Example:
                detection = ServerDetectionResult(
                    detected_server="openldap",
                    confidence=0.95,
                    detection_method="pattern_matching",
                    matched_patterns=["olcOverlay", "olcModuleLoad"],
                    processing_time_seconds=0.034
                )

            """

        class QuirkCollection(FlextLdifModelsDomains.QuirkCollection):
            """Collection of server-specific quirks.

            Contains all server-specific modifications and extensions
            for processing LDIF content from different LDAP servers.

            Example:
                quirks = QuirkCollection(
                    server_type="openldap",
                    dn_quirks=DnQuirks(...),
                    acl_quirks=AclQuirks(...),
                    entry_quirks=EntryQuirks(...),
                    schema_quirks=SchemaQuirks(...)
                )

            """

        class MigrateOptions(FlextLdifModelsSettings.MigrateOptions):
            """Options for FlextLdif.migrate() operation.

            Consolidates 12+ optional parameters into single typed Model.
            Reduces migrate() signature from 16 parameters to 5 parameters.
            """

        class SortConfig(FlextLdifModelsSettings.SortConfig):
            """Configuration for entry sorting operations."""

        class MigrationConfig(FlextLdifModelsSettings.MigrationConfig):
            """Configuration for migration operations.

            Defines parameters for migrating LDIF content between different
            LDAP server types.

            Example:
                config = MigrationConfig(
                    source_server="oid",
                    target_server="oud",
                    preserve_original_format=True,
                    validate_after_migration=True,
                    migration_options=MigrateOptions(...)
                )

            """

        class ParseFormatOptions(FlextLdifModelsSettings.ParseFormatOptions):
            """Options for controlling LDIF parsing behavior.

            Configures how LDIF content is parsed from different sources
            and server types.

            Example:
                options = ParseFormatOptions(
                    server_type="openldap",
                    strict_mode=False,
                    ignore_comments=True,
                    encoding="utf-8",
                    validate_syntax=True
                )

            """

        class MigrationPipelineParams(FlextLdifModelsSettings.MigrationPipelineParams):
            """Parameters for migration pipeline operations.

            Defines the complete set of parameters for running migration
            pipelines between LDAP servers.

            Example:
                params = MigrationPipelineParams(
                    input_files=[Path("source.ldif")],
                    output_dir=Path("/tmp/migrated"),
                    source_server="oid",
                    target_server="oud",
                    config=MigrationConfig(...),
                    options=MigrateOptions(...)
                )

            """

        class ParserParams(FlextLdifModelsSettings.ParserParams):
            """Parameters for LDIF parsing operations.

            Defines all parameters needed for parsing LDIF content.

            Example:
                params = ParserParams(
                    file_path=Path("input.ldif"),
                    server_type="openldap",
                    parse_options=ParseFormatOptions(...),
                    validation_options=ValidationOptions(...)
                )

            """

        class WriterParams(FlextLdifModelsSettings.WriterParams):
            """Parameters for LDIF writing operations.

            Defines all parameters needed for writing LDIF content.

            Example:
                params = WriterParams(
                    entries=[Entry(...)],
                    output_path=Path("output.ldif"),
                    server_type="openldap",
                    write_options=WriteFormatOptions(...),
                    output_options=WriteOutputOptions(...)
                )

            """

        class ConfigInfo(FlextLdifModelsSettings.ConfigInfo):
            """Information about configuration state.

            Contains current configuration details and metadata.

            Example:
                info = ConfigInfo(
                    ldif_max_line_length=199,
                    supported_servers=["oid", "oud", "openldap"],
                    default_encoding="utf-8",
                    config_source="environment"
                )

            """

        class SchemaDiscoveryResult(FlextLdifModelsResults.SchemaDiscoveryResult):
            """Result of schema discovery operations.

            Contains discovered schema attributes and objectClasses with
            comprehensive metadata about the schema processing.

            Example:
                result = SchemaDiscoveryResult(
                    objectclasses={"person": {"oid": "2.5.4.0", ...}},
                    attributes={"cn": {"oid": "2.5.4.3", ...}},
                    total_attributes=45,
                    total_objectclasses=12
                )

            """

        class AclWriteMetadata(FlextLdifModelsDomains.AclWriteMetadata):
            """Metadata for ACL write operations.

            Contains information about ACL subject types and other metadata
            used during ACL writing operations.
            """

        class SchemaConversionPipelineConfig(
            FlextLdifModelsSettings.SchemaConversionPipelineConfig
        ):
            """Configuration for schema conversion pipeline.

            Configures schema conversion operations between different
            LDAP server types.
            """

        class PermissionMappingConfig(FlextLdifModelsSettings.PermissionMappingConfig):
            """Configuration for permission mapping operations.

            Defines how permissions are mapped between source and target
            LDAP servers during migration.
            """

        # Note: AclResponse is NOT overridden here because FlextModels.AclResponse
        # (FlextModelsService.AclResponse) is a generic ACL response model with different
        # fields (resource, user, action) than FlextLdifModelsResults.AclResponse
        # (acls, statistics) which is LDIF-specific. Use FlextLdifModelsResults.AclResponse
        # directly for LDIF ACL extraction operations.

        # ═══════════════════════════════════════════════════════════════════════════
        # PROCESSING CONFIGURATION MODELS - Moved from _utilities/configs.py
        # ═══════════════════════════════════════════════════════════════════════════

        # Enums - moved from _utilities/configs.py
        class ServerType(StrEnum):
            """LDAP server type enumeration."""

            AUTO = "auto"
            OID = "oid"
            OUD = "oud"
            OPENLDAP = "openldap"
            OPENLDAP1 = "openldap1"
            AD = "ad"
            DS389 = "ds389"
            NOVELL = "novell"
            TIVOLI = "tivoli"
            RELAXED = "relaxed"
            RFC = "rfc"

        class OutputFormat(StrEnum):
            """Output format enumeration."""

            LDIF = "ldif"
            JSON = "json"
            CSV = "csv"
            YAML = "yaml"

        class SpaceHandlingOption(StrEnum):
            """Space handling options for DN normalization."""

            PRESERVE = "preserve"
            TRIM = "trim"
            NORMALIZE = "normalize"

        class EscapeHandlingOption(StrEnum):
            """Escape sequence handling options."""

            PRESERVE = "preserve"
            UNESCAPE = "unescape"
            NORMALIZE = "normalize"

        class SortOption(StrEnum):
            """Attribute sorting options."""

            NONE = "none"
            ALPHABETICAL = "alphabetical"
            HIERARCHICAL = "hierarchical"

        # Configuration models - inherit from FlextModels base classes
        class DnNormalizationConfig(FlextModels.Config):
            """DN (Distinguished Name) normalization configuration."""

            case_fold: Literal["none", "lower", "upper"] = Field(
                default="lower",
            )
            space_handling: Literal["preserve", "trim", "normalize"] = Field(
                default="trim",
            )
            escape_handling: Literal["preserve", "unescape", "normalize"] = Field(
                default="preserve",
            )
            validate_before: bool = Field(
                default=True,
                description="Validate DN before normalization",
            )

        class AttrNormalizationConfig(FlextModels.Config):
            """Attribute normalization configuration."""

            sort_attributes: Literal["none", "alphabetical", "hierarchical"] = Field(
                default="alphabetical",
            )
            sort_values: bool = Field(default=True)
            normalize_whitespace: bool = Field(default=True)
            case_fold_names: bool = Field(
                default=True,
                description="Lowercase attribute names",
            )
            trim_values: bool = Field(
                default=True,
                description="Trim whitespace from values",
            )
            remove_empty: bool = Field(
                default=False,
                description="Remove empty attribute values",
            )

        class AclConversionConfig(FlextModels.Config):
            """ACL (Access Control List) conversion configuration."""

            convert_aci: bool = Field(default=True)
            preserve_original_aci: bool = Field(default=False)
            map_server_specific: bool = Field(default=True)

        class MetadataConfig(FlextModels.Config):
            """Metadata preservation configuration."""

            preserve_original: bool = Field(default=True)
            preserve_tracking: bool = Field(default=True)
            preserve_validation: bool = Field(default=False)

        class ValidationConfig(FlextModels.Config):
            """Validation configuration."""

            strict_rfc: bool = Field(default=False)
            allow_server_quirks: bool = Field(default=True)
            validate_dn_format: bool = Field(default=True)

        class FilterConfig(FlextModels.Config):
            """Entry filtering configuration."""

            filter_expression: str | None = Field(default=None)
            exclude_filter: str | None = Field(default=None)
            include_operational: bool = Field(default=False)
            mode: Literal["all", "any"] = Field(
                default="all",
                description="Filter combination mode (all=AND, any=OR)",
            )
            case_sensitive: bool = Field(
                default=False,
                description="Case-sensitive matching",
            )
            include_metadata_matches: bool = Field(
                default=False,
                description="Match against metadata fields",
            )

        class ProcessConfig(BaseModel):
            """Main process configuration."""

            @staticmethod
            def _default_server_type() -> FlextLdifModels.Ldif.ServerType:
                """Default server type factory function."""
                # Use forward reference to avoid unbound name error
                return FlextLdifModels.Ldif.ServerType.RFC

            @staticmethod
            def _default_dn_config() -> FlextLdifModels.Ldif.DnNormalizationConfig:
                """Default DN config factory function."""
                # Use forward reference to avoid unbound name error
                return FlextLdifModels.Ldif.DnNormalizationConfig()

            @staticmethod
            def _default_attr_config() -> FlextLdifModels.Ldif.AttrNormalizationConfig:
                """Default attribute config factory function."""
                # Use forward reference to avoid unbound name error
                return FlextLdifModels.Ldif.AttrNormalizationConfig()

            @staticmethod
            def _default_acl_config() -> FlextLdifModels.Ldif.AclConversionConfig:
                """Default ACL config factory function."""
                # Use direct class reference - will be resolved at runtime
                return m.Ldif.AclConversionConfig()

            @staticmethod
            def _default_validation_config() -> FlextLdifModels.Ldif.ValidationConfig:
                """Default validation config factory function."""
                # Use direct class reference - will be resolved at runtime
                return m.Ldif.ValidationConfig()

            @staticmethod
            def _default_metadata_config() -> FlextLdifModels.Ldif.MetadataConfig:
                """Default metadata config factory function."""
                # Use direct class reference - will be resolved at runtime
                return m.Ldif.MetadataConfig()

            source_server: FlextLdifModels.Ldif.ServerType = Field(
                default_factory=_default_server_type,
            )
            target_server: FlextLdifModels.Ldif.ServerType = Field(
                default_factory=_default_server_type,
            )
            dn_config: FlextLdifModels.Ldif.DnNormalizationConfig = Field(
                default_factory=_default_dn_config,
            )
            attr_config: FlextLdifModels.Ldif.AttrNormalizationConfig = Field(
                default_factory=_default_attr_config,
            )
            acl_config: FlextLdifModels.Ldif.AclConversionConfig = Field(
                default_factory=_default_acl_config,
            )
            validation_config: FlextLdifModels.Ldif.ValidationConfig = Field(
                default_factory=_default_validation_config,
            )
            metadata_config: FlextLdifModels.Ldif.MetadataConfig = Field(
                default_factory=_default_metadata_config,
            )

        class TransformConfig(FlextModels.Config):
            """Transformation pipeline configuration."""

            @staticmethod
            def _default_process_config() -> FlextLdifModels.Ldif.ProcessConfig:
                """Default process config factory function."""
                return FlextLdifModels.Ldif.ProcessConfig()

            @staticmethod
            def _default_filter_config() -> FlextLdifModels.Ldif.FilterConfig:
                """Default filter config factory function."""
                return FlextLdifModels.Ldif.FilterConfig()

            process_config: FlextLdifModels.Ldif.ProcessConfig = Field(
                default_factory=_default_process_config,
            )
            filter_config: FlextLdifModels.Ldif.FilterConfig = Field(
                default_factory=_default_filter_config,
            )
            normalize_dns: bool = Field(default=True)
            normalize_attrs: bool = Field(default=True)
            convert_acls: bool = Field(default=True)
            fail_fast: bool = Field(default=True, description="Stop on first error")
            preserve_order: bool = Field(
                default=True,
                description="Preserve entry order",
            )
            track_changes: bool = Field(
                default=True,
                description="Track changes in metadata",
            )

        class WriteConfig(FlextModels.Config):
            """LDIF output/write configuration."""

            @staticmethod
            def _default_output_format() -> FlextLdifModels.Ldif.OutputFormat:
                """Default output format factory function."""
                return FlextLdifModels.Ldif.OutputFormat.LDIF

            @staticmethod
            def _default_sort_option() -> FlextLdifModels.Ldif.SortOption:
                """Default sort option factory function."""
                return FlextLdifModels.Ldif.SortOption.ALPHABETICAL

            output_format: FlextLdifModels.Ldif.OutputFormat = Field(
                default_factory=_default_output_format,
            )
            version: int = Field(default=1, ge=1)
            wrap_lines: bool = Field(default=True)
            line_length: int = Field(default=76, ge=10)
            format: FlextLdifModels.Ldif.OutputFormat = Field(
                default_factory=_default_output_format,
                description="Alias for output_format",
            )
            line_width: int = Field(
                default=76,
                ge=10,
                description="Alias for line_length",
            )
            fold_lines: bool = Field(
                default=True,
                description="Alias for wrap_lines",
            )
            base64_attrs: Sequence[str] | Literal["auto"] = Field(
                default="auto",
                description="Attributes to encode in base64",
            )
            sort_by: FlextLdifModels.Ldif.SortOption = Field(
                default_factory=_default_sort_option,
                description="Sort entries by field",
            )
            attr_order: Sequence[str] | None = Field(
                default=None,
                description="Preferred attribute order",
            )
            include_metadata: bool = Field(
                default=False,
                description="Include metadata in output",
            )
            server: FlextLdifModels.Ldif.ServerType | None = Field(
                default=None,
                description="Target server type for formatting",
            )

        class LoadConfig(FlextModels.Config):
            """LDIF file loading configuration."""

            file_path: str = Field(default="")
            encoding: str = Field(default="utf-8")
            ignore_errors: bool = Field(default=False)
            skip_comments: bool = Field(default=False)

        class SchemaParseConfig(FlextModels.Config):
            """Schema parsing configuration."""

            parse_attributes: bool = Field(default=True)
            parse_objectclasses: bool = Field(default=True)
            parse_matching_rules: bool = Field(default=False)
            parse_syntaxes: bool = Field(default=False)

        class ValidationRuleSet(FlextModels.Config):
            """Validation rule set configuration."""

            name: str = Field(default="default")
            strict_mode: bool = Field(default=False)
            allow_undefined_attrs: bool = Field(default=True)
            allow_undefined_ocs: bool = Field(default=True)

        # ═══════════════════════════════════════════════════════════════════════════
        # LDIF RESULTS AGGREGATE - Unified namespace for all result types
        # ═══════════════════════════════════════════════════════════════════════════

        class LdifResults:
            """Aggregates all LDIF-specific result types for convenient access."""

            # ACL-related results - real inheritance classes
            class AclResponse(FlextLdifModelsResults.AclResponse):
                """ACL response model."""

            class AclEvaluationResult(FlextLdifModelsResults.AclEvaluationResult):
                """ACL evaluation result model."""

            # Statistics results - real inheritance classes
            class Statistics(FlextLdifModelsResults.Statistics):
                """Statistics model."""

            class StatisticsResult(FlextLdifModelsResults.StatisticsResult):
                """Statistics result model."""

            class StatisticsSummary(FlextLdifModelsResults.StatisticsSummary):
                """Statistics summary model."""

            class EntriesStatistics(FlextLdifModelsResults.EntriesStatistics):
                """Entries statistics model."""

            class StatisticsServiceStatus(
                FlextLdifModelsResults.StatisticsServiceStatus,
            ):
                """Statistics service status model."""

            class SchemaServiceStatus(FlextLdifModelsResults.SchemaServiceStatus):
                """Schema service status model."""

            class SyntaxServiceStatus(FlextLdifModelsResults.SyntaxServiceStatus):
                """Syntax service status model."""

            class ValidationServiceStatus(
                FlextLdifModelsResults.ValidationServiceStatus,
            ):
                """Validation service status model."""

            # Parsing and writing results - real inheritance classes
            class ParseResponse(FlextLdifModelsResults.ParseResponse):
                """Parse response model."""

            class WriteResponse(FlextLdifModelsResults.WriteResponse):
                """Write response model."""

            # Schema discovery - real inheritance classes
            class SchemaDiscoveryResult(FlextLdifModelsResults.SchemaDiscoveryResult):
                """Schema discovery result model."""

            class SchemaBuilderResult(FlextLdifModelsResults.SchemaBuilderResult):
                """Schema builder result model."""

            class SyntaxLookupResult(FlextLdifModelsResults.SyntaxLookupResult):
                """Syntax lookup result model."""

            # Migration results - real inheritance classes
            class MigrationEntriesResult(FlextLdifModelsResults.MigrationEntriesResult):
                """Migration entries result model."""

            class MigrationPipelineResult(
                FlextLdifModelsResults.MigrationPipelineResult,
            ):
                """Migration pipeline result model."""

            # Validation results - real inheritance classes
            class ValidationResult(FlextLdifModelsResults.ValidationResult):
                """Validation result model."""

            class ValidationBatchResult(FlextLdifModelsResults.ValidationBatchResult):
                """Validation batch result model."""

            class LdifValidationResult(FlextLdifModelsResults.LdifValidationResult):
                """LDIF validation result model."""

            # Analysis and detection results - real inheritance classes
            class ServerDetectionResult(FlextLdifModelsResults.ServerDetectionResult):
                """Server detection result model."""

            class AnalysisResult(FlextLdifModelsResults.AnalysisResult):
                """Analysis result model."""

            class EntryAnalysisResult(FlextLdifModelsResults.EntryAnalysisResult):
                """Entry analysis result model."""

            class EntryResult(FlextLdifModelsResults.EntryResult):
                """Entry result model."""

            # Dynamic counts model - used by analysis and detection services
            class DynamicCounts(FlextModelsBase):
                """Dynamic counts model for object class distribution, rejection reasons, etc."""

            # Domain models exposed in results namespace for unified access
            # These are referenced by services and should be accessible via m.Ldif.LdifResults.*
            class Entry(FlextLdifModelsDomains.Entry):
                """Entry model - exposed in results namespace for unified service access."""

            class WriteOptions(FlextLdifModelsDomains.WriteOptions):
                """Write options model - exposed in results namespace for unified service access."""

            class WriteFormatOptions(FlextLdifModelsSettings.WriteFormatOptions):
                """Write format options model - exposed in results namespace for unified service access."""

            # Additional domain and config models exposed for service access
            class Syntax(FlextLdifModelsDomains.Syntax):
                """Syntax model - exposed in results namespace for unified service access."""

            class SortConfig(FlextLdifModelsSettings.SortConfig):
                """Sort configuration model - exposed in results namespace for unified service access."""

            class DnEvent(FlextLdifModelsEvents.DnEvent):
                """DN event model - exposed in results namespace for unified service access."""

            class DnEventConfig(FlextLdifModelsEvents.DnEventConfig):
                """DN event configuration model - exposed in results namespace for unified service access."""

            class CategoryRules(FlextLdifModelsSettings.CategoryRules):
                """Category rules model - exposed in results namespace for unified service access."""

            class WhitelistRules(FlextLdifModelsSettings.WhitelistRules):
                """Whitelist rules model - exposed in results namespace for unified service access."""

            class AclPermissions(FlextLdifModelsDomains.AclPermissions):
                """ACL permissions model - exposed in results namespace for unified service access."""

            class FlexibleCategories(
                FlextModelsCollections.Categories["FlextLdifModels.Ldif.Entry"]
            ):
                """Flexible categories model - exposed in results namespace for unified service access."""

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

                ATTRIBUTES: list[FlextLdifModels.Ldif.SchemaAttribute] = Field(
                    default_factory=list,
                )
                OBJECTCLASS: list[FlextLdifModels.Ldif.SchemaObjectClass] = Field(
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
            ServerType = c.Ldif.ServerTypes


# =========================================================================
# NAMESPACE HIERARCHY - PADRAO CORRETO PARA FLEXT-LDIF
# =========================================================================
# Use namespace hierarquico completo: m.Ldif.Entry, m.Ldif.Attribute, m.Ldif.DN
# SEM duplicacao de declaracoes - heranca real de FlextModels
# SEM quebra de codigo - mantem compatibilidade backward
# =========================================================================

m = FlextLdifModels

__all__ = ["FlextLdifModels", "m"]
