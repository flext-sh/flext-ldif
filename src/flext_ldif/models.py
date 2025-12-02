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
- Server-specific quirk data preserved in extensions (FlextTypes.MetadataAttributeValue)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextModels
from flext_core._models.collections import FlextModelsCollections

from flext_ldif._models.config import FlextLdifModelsConfig
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.events import FlextLdifModelsEvents
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._models.processing import ProcessingResult as ProcessingResultModel
from flext_ldif._models.results import FlextLdifModelsResults


class FlextLdifModels(FlextModels):
    """LDIF domain models extending flext-core FlextModels.

    Unified namespace class that aggregates all LDIF domain models.
    Provides a single access point for all LDIF models while maintaining
    modular organization.

    This class extends flext-core FlextModels and organizes LDIF-specific
    models into focused sub-modules for better maintainability.
    """

    # =========================================================================
    # BASE TYPE ALIASES - For type compatibility with internal domain models
    # =========================================================================

    # Base Entry type for type compatibility with internal domain models
    # Use this in type unions where internal ParseResponse.entries returns domain Entry
    BaseEntry = FlextLdifModelsDomains.Entry

    # =========================================================================
    # DOMAIN MODELS - Core business entities
    # =========================================================================

    # Nested classes inheriting from _models classes (following flext-core pattern)

    class AttributeTransformation(FlextLdifModelsDomains.AttributeTransformation):
        """Detailed tracking of attribute transformation operations.

        Records complete transformation history for LDIF attribute conversions.
        """

    # Public metadata types - direct access
    DynamicMetadata = FlextLdifModelsMetadata.DynamicMetadata
    EntryMetadata = FlextLdifModelsMetadata.EntryMetadata

    # AclMetadataConfig moved to _models/config.py

    # LogContextExtras moved to _models/config.py
    LogContextExtras = FlextLdifModelsConfig.LogContextExtras

    # DnEventConfig moved to _models/events.py
    DnEventConfig = FlextLdifModelsEvents.DnEventConfig
    DnEvent = FlextLdifModelsEvents.DnEvent

    # MigrationEventConfig moved to _models/events.py
    MigrationEventConfig = FlextLdifModelsEvents.MigrationEventConfig
    MigrationEvent = FlextLdifModelsEvents.MigrationEvent

    # ConversionEventConfig moved to _models/events.py
    ConversionEventConfig = FlextLdifModelsEvents.ConversionEventConfig
    ConversionEvent = FlextLdifModelsEvents.ConversionEvent

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
                server_type=FlextLdifConstants.ServerType.OUD,
            )
            event = FlextLdifUtilities.Events.create_schema_event(config)

        """

    SchemaEvent = FlextLdifModelsEvents.SchemaEvent

    # EntryStatistics from domain models
    EntryStatistics = FlextLdifModelsDomains.EntryStatistics

    # =========================================================================
    # DOMAIN EVENTS - Processing events
    # =========================================================================

    # =========================================================================
    # CONFIGURATION AND OPTIONS
    # =========================================================================

    # ACL configuration models
    AclMetadataConfig = FlextLdifModelsConfig.AclMetadataConfig
    AciParserConfig = FlextLdifModelsConfig.AciParserConfig
    AciWriterConfig = FlextLdifModelsConfig.AciWriterConfig

    # Metadata models
    QuirkMetadata = FlextLdifModelsDomains.QuirkMetadata

    # DN and statistics models
    DistinguishedName = FlextLdifModelsDomains.DistinguishedName
    DNStatistics = FlextLdifModelsDomains.DNStatistics

    # Transformation flags type alias
    TransformationFlags = FlextLdifModelsDomains.DNStatisticsFlags
    """Type alias for DN transformation flags.

    Public type for tracking DN transformation state during cleaning operations.
    Used internally by FlextLdifUtilitiesDN for collecting transformation metadata.
    """

    # Processing and writer models
    ProcessingResult = ProcessingResultModel
    ParseResponse = FlextLdifModelsResults.ParseResponse
    WriteResponse = FlextLdifModelsResults.WriteResponse
    WriteOptions = FlextLdifModelsDomains.WriteOptions
    Syntax = FlextLdifModelsDomains.Syntax

    # =========================================================================
    # DTO MODELS - Data transfer objects
    # =========================================================================
    # Note: CQRS classes (ParseLdifCommand, WriteLdifCommand, etc.) are
    # exported from flext_ldif.__init__.py to avoid circular imports.

    # SearchConfig deleted (0 usages) - use proper typed models for LDAP search config
    # DiffItem and DiffResult deleted (0 usages) - use typed models for diff operations

    class FilterCriteria(FlextLdifModelsConfig.FilterCriteria):
        """Criteria for filtering LDIF entries.

        Supports multiple filter types:
        - dn_pattern: Wildcard DN pattern matching (e.g., "*,dc=example,dc=com")
          Uses FlextLdifConstants.FilterType.DN_PATTERN for type safety
        - oid_pattern: OID pattern matching with wildcard support
        - objectclass: Filter by objectClass with optional attribute validation
        - attribute: Filter by attribute presence/absence

        Example:
            criteria = FilterCriteria(
                filter_type=FlextLdifConstants.FilterType.DN_PATTERN,
                pattern="*,ou=users,dc=ctbc,dc=com",
                mode=FlextLdifConstants.FilterMode.INCLUDE
            )

        """

    class CategoryRules(FlextLdifModelsConfig.CategoryRules):
        """Rules for entry categorization.

        Contains DN patterns and objectClass lists for each category.
        Replaces dict[str, str | list[str] | None] with type-safe Pydantic model.
        """

    class WhitelistRules(FlextLdifModelsConfig.WhitelistRules):
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
                    filter_type=FlextLdifConstants.FilterType.DN_PATTERN,
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

    class Statistics(FlextLdifModelsResults.Statistics):
        """Comprehensive LDIF processing statistics.

        Tracks detailed metrics for entries, attributes, DNs, and processing performance.
        Provides insights into LDIF content characteristics and processing efficiency.

        Example:
            stats = Statistics(
                total_entries=1500,
                entries_processed=1450,
                entries_excluded=50,
                total_attributes=4500,
                dn_statistics=DNStatistics(...),
                entry_statistics=EntryStatistics(...),
                processing_time_seconds=2.34,
                memory_peak_mb=45.6
            )

        """

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
    type FlexibleCategories = FlextModelsCollections.Categories[FlextLdifModels.Entry]

    # Schema models
    SchemaAttribute = FlextLdifModelsDomains.SchemaAttribute
    SchemaObjectClass = FlextLdifModelsDomains.SchemaObjectClass

    # ACL models
    Acl = FlextLdifModelsDomains.Acl
    AclTarget = FlextLdifModelsDomains.AclTarget
    AclSubject = FlextLdifModelsDomains.AclSubject
    AclPermissions = FlextLdifModelsDomains.AclPermissions
    DnRegistry = FlextLdifModelsDomains.DnRegistry

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

    class LdifAttributes(FlextLdifModelsDomains.LdifAttributes):
        """LDIF attribute collection.

        Manages collections of LDAP attributes with type safety and
        validation. Provides convenient access to attribute values
        with support for single and multi-valued attributes.

        Example:
            attributes = LdifAttributes({
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

    class WriteFormatOptions(FlextLdifModelsConfig.WriteFormatOptions):
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

    class WriteOutputOptions(FlextLdifModelsConfig.WriteOutputOptions):
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

    class MigrationConfig(FlextLdifModelsConfig.MigrationConfig):
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

    class ParseFormatOptions(FlextLdifModelsConfig.ParseFormatOptions):
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

    class MigrationPipelineParams(FlextLdifModelsConfig.MigrationPipelineParams):
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

    class ParserParams(FlextLdifModelsConfig.ParserParams):
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

    class WriterParams(FlextLdifModelsConfig.WriterParams):
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

    class ConfigInfo(FlextLdifModelsConfig.ConfigInfo):
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

    class AclResponse(FlextLdifModelsResults.AclResponse):
        """Composed response from ACL extraction.

        Combines extracted Acl models with extraction statistics.

        Example:
            response = AclResponse(
                acls=[Acl(...), Acl(...)],
                statistics=Statistics(
                    processed_entries=10,
                    acls_extracted=5
                )
            )

        """


__all__ = ["FlextLdifModels"]
