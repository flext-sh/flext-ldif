"""LDIF domain models and data structures.

This module defines Pydantic models for LDIF data structures including entries,
attributes, DNs, ACLs, and schema elements. Models provide validation and
type safety for LDIF operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Notes:
 - Uses object type in **extensions for server-specific quirk data
 - Models follow Pydantic v2 patterns with computed fields and validators
 - All models are immutable by default (frozen=True where applicable)

"""

from __future__ import annotations

from flext_core import FlextLogger, FlextModels, FlextResult
from pydantic import computed_field

from flext_ldif._models.config import FlextLdifModelsConfig
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.events import FlextLdifModelsEvents
from flext_ldif._models.results import FlextLdifModelsResults

logger = FlextLogger(__name__)


class FlextLdifModels(FlextModels):
    """LDIF domain models extending flext-core FlextModels.

    Unified namespace class that aggregates all LDIF domain models.
    Provides a single access point for all LDIF models while maintaining
    modular organization.

    This class extends flext-core FlextModels and organizes LDIF-specific
    models into focused sub-modules for better maintainability.
    """

    # =========================================================================
    # DOMAIN MODELS - Core business entities
    # =========================================================================

    # Nested classes inheriting from _models classes (following flext-core pattern)
    class DistinguishedName(FlextLdifModelsDomains.DistinguishedName):
        """Distinguished Name value object."""

    class AttributeTransformation(FlextLdifModelsDomains.AttributeTransformation):
        """Detailed tracking of attribute transformation operations.

        Records complete transformation history for LDIF attribute conversions.
        """

    class QuirkMetadata(FlextLdifModelsDomains.QuirkMetadata):
        """Universal metadata container for quirk-specific data preservation."""

    class DNStatistics(FlextLdifModelsDomains.DNStatistics):
        """Statistics tracking for DN transformations and validation."""

    class EntryStatistics(FlextLdifModelsDomains.EntryStatistics):
        """Statistics tracking for entry-level transformations and validation."""

    class ErrorDetail(FlextLdifModelsDomains.ErrorDetail):
        """Error detail information for failed operations."""

    class AclPermissions(FlextLdifModelsDomains.AclPermissions):
        """ACL permissions for LDAP operations."""

    class AclTarget(FlextLdifModelsDomains.AclTarget):
        """ACL target specification."""

    class AclSubject(FlextLdifModelsDomains.AclSubject):
        """ACL subject specification."""

    class DnRegistry(FlextLdifModelsDomains.DnRegistry):
        """Registry for DN normalization and canonical forms."""

    # AclMetadataConfig moved to _models/config.py

    class AclMetadataConfig(FlextLdifModelsConfig.AclMetadataConfig):
        """Configuration for ACL metadata extensions."""

    # LogContextExtras moved to _models/config.py

    class LogContextExtras(FlextLdifModelsConfig.LogContextExtras):
        """Additional context fields for logging events."""

    # DnEventConfig moved to _models/events.py

    class DnEventConfig(FlextLdifModelsEvents.DnEventConfig):
        """Configuration for DN event creation."""

    # MigrationEventConfig moved to _models/events.py

    class MigrationEventConfig(FlextLdifModelsEvents.MigrationEventConfig):
        """Configuration for migration event creation."""

    # ConversionEventConfig moved to _models/events.py

    class ConversionEventConfig(FlextLdifModelsEvents.ConversionEventConfig):
        """Configuration for conversion event creation."""

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
                server_type="oud",
            )
            event = FlextLdifUtilities.Events.create_schema_event(config)

        """

    # =========================================================================
    # DOMAIN EVENTS - Processing events
    # =========================================================================

    class FilterEvent(FlextLdifModelsEvents.FilterEvent):
        """Event emitted when LDIF entries are filtered."""

    class ParseEvent(FlextLdifModelsEvents.ParseEvent):
        """Event emitted when LDIF content is parsed."""

    class WriteEvent(FlextLdifModelsEvents.WriteEvent):
        """Event emitted when LDIF content is written."""

    class CategoryEvent(FlextLdifModelsEvents.CategoryEvent):
        """Event emitted when entries are categorized."""

    class AclEvent(FlextLdifModelsEvents.AclEvent):
        """Event emitted when ACLs are processed."""

    class DnEvent(FlextLdifModelsEvents.DnEvent):
        """Event emitted when DNs are processed."""

    class MigrationEvent(FlextLdifModelsEvents.MigrationEvent):
        """Event emitted during migration operations."""

    class ConversionEvent(FlextLdifModelsEvents.ConversionEvent):
        """Event emitted during conversion operations."""

    class SchemaEvent(FlextLdifModelsEvents.SchemaEvent):
        """Event emitted during schema processing."""

    # =========================================================================
    # CONFIGURATION AND OPTIONS
    # =========================================================================

    class MigrateOptions(FlextLdifModelsConfig.MigrateOptions):
        """Options for FlextLdif.migrate() operation."""

    class Acl(FlextLdifModelsDomains.Acl):
        """Universal ACL model for all LDAP server types."""

    # =========================================================================
    # DTO MODELS - Data transfer objects
    # =========================================================================
    # Note: CQRS classes (ParseLdifCommand, WriteLdifCommand, etc.) are
    # exported from flext_ldif.__init__.py to avoid circular imports.

    class LdifValidationResult(FlextLdifModelsResults.LdifValidationResult):
        """Result of LDIF validation operations."""

    class AnalysisResult(FlextLdifModelsResults.AnalysisResult):
        """Result of LDIF analytics operations."""

    # SearchConfig deleted (0 usages) - use dict[str, object] for LDAP search config
    # DiffItem and DiffResult deleted (0 usages) - use dict[str, list[dict]] for diff operations

    class FilterCriteria(FlextLdifModelsConfig.FilterCriteria):
        """Criteria for filtering LDIF entries.

        Supports multiple filter types:
        - dn_pattern: Wildcard DN pattern matching (e.g., "*,dc=example,dc=com")
        - oid_pattern: OID pattern matching with wildcard support
        - objectclass: Filter by objectClass with optional attribute validation
        - attribute: Filter by attribute presence/absence

        Example:
            criteria = FilterCriteria(
                filter_type="dn_pattern",
                pattern="*,ou=users,dc=ctbc,dc=com",
                mode="include"
            )

        """

    class CategoryRules(FlextLdifModelsConfig.CategoryRules):
        """Rules for entry categorization.

        Contains DN patterns and objectClass lists for each category.
        Replaces dict[str, Any] with type-safe Pydantic model.
        """

    class WhitelistRules(FlextLdifModelsConfig.WhitelistRules):
        """Whitelist rules for entry validation.

        Defines blocked objectClasses and validation rules.
        Replaces dict[str, Any] with type-safe Pydantic model.
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
                    filter_type="dn_pattern", pattern="*,dc=old,dc=com"
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

    class SchemaDiscoveryResult(FlextLdifModelsResults.SchemaDiscoveryResult):
        """Result of schema discovery operations."""

    class SchemaAttribute(FlextLdifModelsDomains.SchemaAttribute):
        """LDAP schema attribute definition model (RFC 4512 compliant).

        Represents an LDAP attribute type definition from schema with full RFC 4512 support.
        """

        @computed_field
        def syntax_definition(self) -> FlextLdifModels.Syntax | None:
            """Resolve syntax OID to complete public Syntax model.

            Override parent to return public FlextLdifModels.Syntax type instead of
            internal FlextLdifModelsDomains.Syntax type. This maintains proper type
            separation between domain layer and public API layer.

            Returns:
                Public Syntax model or None if syntax cannot be resolved.

            """
            # Get internal syntax from parent implementation
            internal_syntax = super().syntax_definition
            if internal_syntax is None:
                return None

            # Type guard: ensure internal_syntax is a Pydantic model with model_dump method
            if not hasattr(internal_syntax, "model_dump"):
                return None

            # Convert to public type using model_validate
            # Exclude computed fields since they will be recomputed automatically
            # Use mode='python' to get plain Python dict, and exclude computed fields
            dump_data = internal_syntax.model_dump(
                mode="python",
                exclude={"is_rfc4517_standard", "syntax_oid_suffix"},
                exclude_unset=False,
            )
            # Filter out any remaining computed fields that might have been included
            # Only include fields that exist in the Syntax model
            valid_fields = {
                "oid",
                "name",
                "desc",
                "type_category",
                "is_binary",
                "max_length",
                "case_insensitive",
                "allows_multivalued",
                "encoding",
                "validation_pattern",
                "metadata",
            }
            filtered_data = {k: v for k, v in dump_data.items() if k in valid_fields}
            return FlextLdifModels.Syntax.model_validate(filtered_data)

    class Syntax(FlextLdifModelsDomains.Syntax):
        """LDAP attribute syntax definition model (RFC 4517 compliant).

        Represents an LDAP attribute syntax OID and its validation rules per RFC 4517.
        """

    class SchemaObjectClass(FlextLdifModelsDomains.SchemaObjectClass):
        """LDAP schema object class definition model (RFC 4512 compliant).

        Represents an LDAP object class definition from schema with full RFC 4512 support.
        """

    class Entry(FlextLdifModelsDomains.Entry):
        """LDIF entry domain model - moved to _models/domain.py for organization."""

        @classmethod
        def _normalize_create_params(
            cls,
            dn: str
            | FlextLdifModels.DistinguishedName
            | FlextLdifModelsDomains.DistinguishedName,
            attributes: (
                dict[str, str | list[str]]
                | FlextLdifModels.LdifAttributes
                | FlextLdifModelsDomains.LdifAttributes
            ),
            metadata: FlextLdifModels.QuirkMetadata
            | FlextLdifModelsDomains.QuirkMetadata
            | None,
            acls: list[FlextLdifModels.Acl] | list[FlextLdifModelsDomains.Acl] | None,
            objectclasses: list[FlextLdifModels.SchemaObjectClass]
            | list[FlextLdifModelsDomains.SchemaObjectClass]
            | None,
            attributes_schema: list[FlextLdifModels.SchemaAttribute]
            | list[FlextLdifModelsDomains.SchemaAttribute]
            | None,
            statistics: FlextLdifModels.EntryStatistics
            | FlextLdifModelsDomains.EntryStatistics
            | None,
        ) -> tuple[
            str | FlextLdifModelsDomains.DistinguishedName,
            dict[str, str | list[str]] | FlextLdifModelsDomains.LdifAttributes,
            FlextLdifModelsDomains.QuirkMetadata | None,
            list[FlextLdifModelsDomains.Acl] | None,
            list[FlextLdifModelsDomains.SchemaObjectClass] | None,
            list[FlextLdifModelsDomains.SchemaAttribute] | None,
            FlextLdifModelsDomains.EntryStatistics | None,
        ]:
            """Normalize public types to domain types for parent method call."""
            # Normalize DN
            domain_dn: str | FlextLdifModelsDomains.DistinguishedName
            if isinstance(
                dn,
                (
                    FlextLdifModelsDomains.DistinguishedName,
                    FlextLdifModels.DistinguishedName,
                ),
            ):
                domain_dn = dn
            else:
                domain_dn = dn

            # Normalize attributes
            domain_attributes: (
                dict[str, str | list[str]] | FlextLdifModelsDomains.LdifAttributes
            )
            if isinstance(
                attributes,
                (FlextLdifModelsDomains.LdifAttributes, FlextLdifModels.LdifAttributes),
            ):
                domain_attributes = attributes
            else:
                domain_attributes = attributes

            # Normalize metadata
            domain_metadata: FlextLdifModelsDomains.QuirkMetadata | None = metadata

            # Normalize lists (lists are invariant, so we need to convert them)
            domain_acls: list[FlextLdifModelsDomains.Acl] | None = (
                list(acls) if acls is not None else None
            )
            domain_objectclasses: (
                list[FlextLdifModelsDomains.SchemaObjectClass] | None
            ) = list(objectclasses) if objectclasses is not None else None
            domain_attributes_schema: (
                list[FlextLdifModelsDomains.SchemaAttribute] | None
            ) = list(attributes_schema) if attributes_schema is not None else None
            domain_statistics: FlextLdifModelsDomains.EntryStatistics | None = (
                statistics
            )

            return (
                domain_dn,
                domain_attributes,
                domain_metadata,
                domain_acls,
                domain_objectclasses,
                domain_attributes_schema,
                domain_statistics,
            )

        @classmethod
        def create(
            cls,
            dn: str
            | FlextLdifModels.DistinguishedName
            | FlextLdifModelsDomains.DistinguishedName,
            attributes: (
                dict[str, str | list[str]]
                | FlextLdifModels.LdifAttributes
                | FlextLdifModelsDomains.LdifAttributes
            ),
            metadata: FlextLdifModels.QuirkMetadata
            | FlextLdifModelsDomains.QuirkMetadata
            | None = None,
            acls: list[FlextLdifModels.Acl]
            | list[FlextLdifModelsDomains.Acl]
            | None = None,
            objectclasses: list[FlextLdifModels.SchemaObjectClass]
            | list[FlextLdifModelsDomains.SchemaObjectClass]
            | None = None,
            attributes_schema: list[FlextLdifModels.SchemaAttribute]
            | list[FlextLdifModelsDomains.SchemaAttribute]
            | None = None,
            entry_metadata: dict[str, object] | None = None,
            validation_metadata: dict[str, object] | None = None,
            server_type: str | None = None,
            source_entry: str | None = None,
            unconverted_attributes: dict[str, object] | None = None,
            statistics: FlextLdifModels.EntryStatistics
            | FlextLdifModelsDomains.EntryStatistics
            | None = None,
        ) -> FlextResult[FlextLdifModelsDomains.Entry]:
            """Create a new Entry instance (public API wrapper).

            Wraps the domain Entry.create() method to return the public Entry type.
            Converts public types to domain types for the parent method call.
            """
            # Normalize parameters to domain types
            (
                domain_dn,
                domain_attributes,
                domain_metadata,
                domain_acls,
                domain_objectclasses,
                domain_attributes_schema,
                domain_statistics,
            ) = cls._normalize_create_params(
                dn,
                attributes,
                metadata,
                acls,
                objectclasses,
                attributes_schema,
                statistics,
            )

            # Call parent create method
            domain_result = super().create(
                dn=domain_dn,
                attributes=domain_attributes,
                metadata=domain_metadata,
                acls=domain_acls,
                objectclasses=domain_objectclasses,
                attributes_schema=domain_attributes_schema,
                entry_metadata=entry_metadata,
                validation_metadata=validation_metadata,
                server_type=server_type,
                source_entry=source_entry,
                unconverted_attributes=unconverted_attributes,
                statistics=domain_statistics,
            )
            if domain_result.is_failure:
                return FlextResult[FlextLdifModelsDomains.Entry].fail(
                    domain_result.error or "Entry creation failed",
                )

            domain_entry = domain_result.unwrap()
            # Convert domain Entry to public Entry type
            # Since FlextLdifModels.Entry extends FlextLdifModelsDomains.Entry,
            # we can safely cast it
            if not isinstance(
                domain_entry,
                (FlextLdifModels.Entry, FlextLdifModelsDomains.Entry),
            ):
                return FlextResult[FlextLdifModelsDomains.Entry].fail(
                    "Internal error: Entry.create() returned wrong type",
                )
            # Return as domain Entry (parent type) to satisfy type checker
            # The actual instance is still a FlextLdifModels.Entry at runtime
            return FlextResult[FlextLdifModelsDomains.Entry].ok(domain_entry)

    class LdifAttributes(FlextLdifModelsDomains.LdifAttributes):
        """LDIF attributes container - simplified dict-like interface."""

    class EntryResult(FlextLdifModelsResults.EntryResult):
        """Result of LDIF processing containing categorized entries and statistics.

        This is the UNIFIED result model for all LDIF operations. Contains entries
        organized by category, comprehensive statistics, and output file paths.

        Immutable value object following DDD patterns.

        Attributes:
            entries_by_category: Entries organized by their categorization
                                (schema, hierarchy, users, groups, acl, data, rejected)
            statistics: Comprehensive execution statistics (counts, durations, reasons)
            file_paths: Output file paths for each category

        """

        @classmethod
        def from_entries(
            cls,
            entries: list[FlextLdifModels.Entry] | list[FlextLdifModelsDomains.Entry],
            category: str = "all",
            statistics: FlextLdifModels.Statistics
            | FlextLdifModelsResults.Statistics
            | None = None,
        ) -> FlextLdifModels.EntryResult:
            """Create EntryResult from list of entries (public API wrapper).

            Wraps the domain EntryResult.from_entries() method to accept public Entry types.
            Converts public Entry list to domain Entry list for internal storage.

            Args:
                entries: List of Entry objects (public or domain Entry types)
                category: Category name for the entries (default: "all")
                statistics: Optional statistics object (creates default if None)

            Returns:
                New EntryResult instance (public type).

            """
            # Convert public Entry list to domain Entry list
            # Public Entry types inherit from domain Entry, so individual instances are compatible
            domain_entries: list[FlextLdifModelsDomains.Entry] = []
            for entry in entries:
                # Each entry is already a FlextLdifModelsDomains.Entry (via inheritance)
                if isinstance(entry, FlextLdifModelsDomains.Entry):
                    domain_entries.append(entry)
                else:
                    # Should not happen if types are correct, but handle gracefully
                    return cls(
                        entries_by_category={},
                        statistics=FlextLdifModelsResults.Statistics.for_pipeline(
                            total=0,
                        ),
                    )

            # Convert statistics to domain type if needed
            domain_statistics: FlextLdifModelsResults.Statistics | None = None
            if statistics is not None:
                if isinstance(statistics, FlextLdifModelsResults.Statistics):
                    domain_statistics = statistics
                else:
                    # Public statistics is already a domain statistics (inheritance)
                    domain_statistics = statistics

            # Call parent from_entries method with domain types
            domain_result = super().from_entries(
                entries=domain_entries,
                category=category,
                statistics=domain_statistics,
            )
            # The result is already a FlextLdifModels.EntryResult instance because cls is FlextLdifModels.EntryResult
            # Verify it's the correct type (should always be true due to inheritance)
            if not isinstance(domain_result, FlextLdifModels.EntryResult):
                # This should not happen, but create a new instance if needed
                return cls(
                    entries_by_category=domain_result.entries_by_category,
                    statistics=domain_result.statistics,
                    file_paths=domain_result.file_paths,
                )
            return domain_result

        @classmethod
        def empty(cls) -> FlextLdifModels.EntryResult:
            """Create empty EntryResult (public API wrapper).

            Returns:
                Empty EntryResult instance (public type).

            """
            domain_result = super().empty()
            # The result is already a FlextLdifModels.EntryResult instance because cls is FlextLdifModels.EntryResult
            if not isinstance(domain_result, FlextLdifModels.EntryResult):
                return cls(
                    entries_by_category={},
                    statistics=None,
                    file_paths={},
                )
            return domain_result

    class Statistics(FlextLdifModelsResults.Statistics):
        """Unified statistics model for all LDIF operations.

        Consolidates PipelineStatistics, ParseStatistics, WriteStatistics,
        and AclStatistics into a single model following the EntryResult pattern.

        Uses helper methods to create operation-specific statistics while
        maintaining a single source of truth for all statistical data.

        Attributes:
            Core counters (all operations):
                total_entries: Total entries encountered/processed
                processed_entries: Successfully processed entries
                failed_entries: Entries that failed processing

            Category counters (pipeline operations):
                schema_entries: Schema entries categorized
                data_entries: Data entries (non-schema)
                hierarchy_entries: Hierarchy/organizational entries
                user_entries: User entries
                group_entries: Group entries
                acl_entries: ACL entries

            Schema migration counters:
                schema_attributes: Schema attributes migrated
                schema_objectclasses: Schema object classes migrated

            ACL extraction counters:
                acls_extracted: Total ACL objects extracted
                acls_failed: ACL parsing failures
                acl_attribute_name: Primary ACL attribute name

            Parsing counters:
                parse_errors: Parse errors encountered
                detected_server_type: Auto-detected LDAP server type

            Writing counters:
                entries_written: Entries successfully written
                output_file: Output file path
                file_size_bytes: Written file size
                encoding: File encoding used

            Metadata:
                processing_duration: Processing time in seconds
                rejection_reasons: Map of rejection reason to count

        Example:
            >>> # Parsing statistics
            >>> stats = Statistics.for_parsing(total=100, schema=10, data=90, errors=2)
            >>>
            >>> # Pipeline statistics
            >>> stats = Statistics.for_pipeline(
            ...     total=100, processed=98, schema=10, users=50, groups=38
            ... )
            >>>
            >>> # Merge statistics
            >>> combined = stats1.merge(stats2)

        """

    class SchemaBuilderResult(FlextLdifModelsResults.SchemaBuilderResult):
        """Result of schema builder build() operation.

        Contains attributes, object classes, server type, and metadata about the schema.

        Note: Uses builder-friendly field names (description, required_attributes)
        rather than RFC 4512 names (desc, must, may) for better API usability.

        Attributes:
            attributes: Dict of attribute name to attribute definition
            object_classes: Dict of object class name to object class definition
            server_type: Target LDAP server type identifier
            entry_count: Number of entries in the schema

        """

    # =========================================================================
    # RESPONSE MODELS - Composed from domain models and statistics
    # =========================================================================

    class ParseResponse(FlextLdifModelsResults.ParseResponse):
        """Composed response from parsing operation.

        Combines Entry models with statistics from parse operation.
        Uses model composition instead of dict intermediaries.
        """

    class WriteResponse(FlextLdifModelsResults.WriteResponse):
        """Composed response from write operation.

        Contains written LDIF content and statistics using model composition.
        """

    class WriteFormatOptions(FlextLdifModelsConfig.WriteFormatOptions):
        """Formatting options for LDIF serialization.

        Provides detailed control over the output format, including line width
        for folding, and whether to respect attribute ordering from metadata.
        """

    class AclResponse(FlextLdifModelsResults.AclResponse):
        """Composed response from ACL extraction.

        Combines extracted Acl models with extraction statistics.
        """

    class MigrationPipelineResult(FlextLdifModelsResults.MigrationPipelineResult):
        """Result of migration pipeline execution.

        Contains migrated schema, entries, statistics, and output file paths
        from a complete LDIF migration operation. Immutable value object following
        DDD patterns.

        Attributes:
            migrated_schema: Migrated schema data (attributes and object classes)
            entries: List of migrated directory entries as dicts
            stats: Migration statistics with computed metrics (always present)
            output_files: List of generated output file paths

        """

    # =========================================================================
    # CLIENT AND SERVICE RESULT MODELS
    # =========================================================================

    class ClientStatus(FlextLdifModelsResults.ClientStatus):
        """Client status information."""

    class ValidationResult(FlextLdifModelsResults.ValidationResult):
        """Entry validation result."""

    class MigrationEntriesResult(FlextLdifModelsResults.MigrationEntriesResult):
        """Result from migrating entries between servers."""

    class EntryAnalysisResult(FlextLdifModelsResults.EntryAnalysisResult):
        """Result from entry analysis operations."""

    class ServerDetectionResult(FlextLdifModelsResults.ServerDetectionResult):
        """Result from LDAP server type detection."""

    class QuirkCollection(FlextLdifModelsDomains.QuirkCollection):
        """Collection of all quirks (Schema, ACL, Entry) for a single server type.

        Stores all three quirk types together for unified access and management.
        """

    class MigrationConfig(FlextLdifModelsConfig.MigrationConfig):
        """Configuration for migration pipeline from YAML or dict.

        Supports structured 6-file output (00-06) with flexible categorization,
        filtering, and removed attribute tracking.
        """

    class ParseFormatOptions(FlextLdifModelsConfig.ParseFormatOptions):
        """Formatting options for LDIF parsing."""

    # =========================================================================
    # SERVICE PARAMETER MODELS - Typed parameters for service factories
    # =========================================================================
    class MigrationPipelineParams(FlextLdifModelsConfig.MigrationPipelineParams):
        """Typed parameters for migration pipeline factory.

        Replaces dict-based parameter passing with type-safe Pydantic model.
        """

    class ParserParams(FlextLdifModelsConfig.ParserParams):
        """Typed parameters for parser service factory.

        Provides type-safe configuration for LDIF parsing operations.
        """

    class WriterParams(FlextLdifModelsConfig.WriterParams):
        """Typed parameters for writer service factory.

        Provides type-safe configuration for LDIF writing operations.
        """

    class ConfigInfo(FlextLdifModelsConfig.ConfigInfo):
        """Configuration information for logging and introspection.

        Structured representation of FlextLdifConfig for reporting and diagnostics.
        """

    # ═══════════════════════════════════════════════════════════════════════
    # STATISTICS MODELS
    # ═══════════════════════════════════════════════════════════════════════

    class StatisticsResult(FlextLdifModelsResults.StatisticsResult):
        """Statistics result from LDIF processing pipeline.

        Contains comprehensive statistics about categorized entries, rejections,
        and output files generated during migration.

        Attributes:
            total_entries: Total number of entries processed
            categorized: Count of entries per category
            rejection_rate: Percentage of entries rejected (0.0-1.0)
            rejection_count: Number of rejected entries
            rejection_reasons: List of unique rejection reasons
            written_counts: Count of entries written per category
            output_files: Mapping of categories to output file paths

        """

    class EntriesStatistics(FlextLdifModelsResults.EntriesStatistics):
        """Statistics calculated from a list of Entry models.

        Provides distribution analysis of objectClasses and server types
        across a collection of LDIF entries.

        Attributes:
            total_entries: Total number of entries analyzed
            object_class_distribution: Count of entries per objectClass
            server_type_distribution: Count of entries per server type

        """

    class DictAccessibleValue(FlextLdifModelsResults.DictAccessibleValue):
        """Base value model providing dict-style access (backwards compatibility)."""

    class ServiceStatus(FlextLdifModelsResults.ServiceStatus):
        """Generic service status model for execute() health checks.

        Base model for all service health check responses providing
        standard status information across all FLEXT LDIF services.

        Attributes:
            service: Service name identifier
            status: Operational status (e.g., "operational", "degraded")
            rfc_compliance: RFC standards implemented (e.g., "RFC 2849", "RFC 4512")

        """

    class SchemaServiceStatus(FlextLdifModelsResults.SchemaServiceStatus):
        """Schema service status with server-specific metadata.

        Extended status model for FlextLdifSchema service including
        server type configuration and available operations.

        Attributes:
            service: Service name identifier
            server_type: Server type configuration (e.g., "oud", "oid", "rfc")
            status: Operational status
            rfc_compliance: RFC 4512 compliance
            operations: List of available schema operations

        """

    class SyntaxServiceStatus(FlextLdifModelsResults.SyntaxServiceStatus):
        """Syntax service status with lookup table metadata.

        Extended status model for FlextLdifSyntax service including
        counts of registered syntax OIDs and common syntaxes.

        Attributes:
            service: Service name identifier
            status: Operational status
            rfc_compliance: RFC 4517 compliance
            total_syntaxes: Total number of registered syntax OIDs
            common_syntaxes: Number of commonly used syntax OIDs

        """

    class StatisticsServiceStatus(FlextLdifModelsResults.StatisticsServiceStatus):
        """Statistics service status with capability metadata.

        Extended status model for FlextLdifStatistics service including
        operational status and available capabilities.

        Attributes:
            service: Service name identifier
            status: Operational status (e.g., "operational", "degraded")
            capabilities: List of available statistical operations
            version: Service version

        """

    class SyntaxLookupResult(FlextLdifModelsResults.SyntaxLookupResult):
        """Result of syntax OID/name lookup operations.

        Contains results from bidirectional OID ↔ name lookups
        performed by FlextLdifSyntax builder pattern.

        Attributes:
            oid_lookup: Resolved name for OID lookup (None if not found or not requested)
            name_lookup: Resolved OID for name lookup (None if not found or not requested)

        """

    class ValidationServiceStatus(FlextLdifModelsResults.ValidationServiceStatus):
        """Validation service status with validation type metadata.

        Status model for FlextLdifValidation service including
        list of supported validation types.

        Attributes:
            service: Service name identifier
            status: Operational status
            rfc_compliance: RFC 2849/4512 compliance
            validation_types: List of supported validation types

        """

    type ParseResult = list[Entry] | tuple[list[Entry], int, list[str]]

    class ValidationBatchResult(FlextLdifModelsResults.ValidationBatchResult):
        """Result of batch validation operations.

        Contains validation results for multiple attribute names
        and objectClass names validated in a single operation.

        Attributes:
            results: Mapping of validated item names to validation status (True=valid, False=invalid)

        """


__all__ = ["FlextLdifModels"]
