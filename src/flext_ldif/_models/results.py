"""Result models for LDIF processing."""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import Annotated, Self

from pydantic import Field, computed_field

from flext_core import m
from flext_ldif import (
    FlextLdifModelsCollections,
    FlextLdifModelsDomainsEntries,
    FlextLdifModelsEvents,
    c,
    t,
)


class FlextLdifModelsResults:
    """Namespace for LDIF result models."""

    class StatisticsSummary(m.FrozenModel):
        total_entries: int = Field(
            default=0, description="Total number of entries processed"
        )
        processed_entries: int = Field(
            default=0, description="Entries successfully processed"
        )
        failed_entries: int = Field(
            default=0, description="Entries that failed processing"
        )
        rejected_entries: int = Field(
            default=0, description="Entries rejected by filter rules"
        )
        success_rate: float = Field(
            default=0.0, description="Percentage of entries successfully processed"
        )
        failure_rate: float = Field(
            default=0.0, description="Percentage of entries that failed"
        )
        rejection_rate: float = Field(
            default=0.0, description="Percentage of entries rejected"
        )
        schema_entries: int = Field(
            default=0, description="Count of schema definition entries"
        )
        data_entries: int = Field(default=0, description="Count of data entries")
        hierarchy_entries: int = Field(
            default=0, description="Count of organizational hierarchy entries"
        )
        user_entries: int = Field(default=0, description="Count of user entries")
        group_entries: int = Field(default=0, description="Count of group entries")
        acl_entries: int = Field(default=0, description="Count of ACL entries")
        acls_extracted: int = Field(
            default=0, description="ACLs successfully extracted"
        )
        acls_failed: int = Field(default=0, description="ACLs that failed extraction")
        parse_errors: int = Field(
            default=0, description="Count of parse errors encountered"
        )
        entries_written: int = Field(default=0, description="Entries written to output")

    class MigrationSummary(m.FrozenModel):
        statistics: FlextLdifModelsResults.StatisticsSummary | None = Field(
            default=None,
            description="Aggregated statistics summary for the migration",
        )
        entry_count: int = Field(
            default=0, description="Total entries in migration result"
        )
        output_files: int = Field(
            default=0, description="Number of output files generated"
        )
        is_empty: bool = Field(
            default=True, description="Whether the migration produced no output"
        )

    class Statistics(m.Statistics):
        total_entries: t.NonNegativeInt = Field(
            default=0, description="Total number of entries processed"
        )
        processed_entries: t.NonNegativeInt = Field(
            default=0, description="Entries successfully processed"
        )
        failed_entries: t.NonNegativeInt = Field(
            default=0, description="Entries that failed processing"
        )
        schema_entries: t.NonNegativeInt = Field(
            default=0, description="Count of schema definition entries"
        )
        data_entries: t.NonNegativeInt = Field(
            default=0, description="Count of data entries"
        )
        hierarchy_entries: t.NonNegativeInt = Field(
            default=0, description="Count of organizational hierarchy entries"
        )
        user_entries: t.NonNegativeInt = Field(
            default=0, description="Count of user entries"
        )
        group_entries: t.NonNegativeInt = Field(
            default=0, description="Count of group entries"
        )
        acl_entries: t.NonNegativeInt = Field(
            default=0, description="Count of ACL entries"
        )
        rejected_entries: t.NonNegativeInt = Field(
            default=0, description="Entries rejected by filter rules"
        )
        schema_attributes: t.NonNegativeInt = Field(
            default=0, description="Count of schema attributes parsed"
        )
        schema_objectclasses: t.NonNegativeInt = Field(
            default=0, description="Count of schema object classes parsed"
        )
        acls_extracted: t.NonNegativeInt = Field(
            default=0, description="ACLs successfully extracted"
        )
        acls_failed: t.NonNegativeInt = Field(
            default=0, description="ACLs that failed extraction"
        )
        acl_attribute_name: str | None = Field(
            default=None, description="Name of the ACL attribute used for extraction"
        )
        parse_errors: t.NonNegativeInt = Field(
            default=0, description="Count of parse errors encountered"
        )
        detected_server_type: c.Ldif.ServerTypeLiteral | None = Field(
            default=None, description="LDAP server type detected from LDIF content"
        )
        entries_written: t.NonNegativeInt = Field(
            default=0, description="Entries written to output"
        )
        output_file: str | None = Field(
            default=None, description="Path to the output file"
        )
        file_size_bytes: t.NonNegativeInt = Field(
            default=0, description="Output file size in bytes"
        )
        encoding: c.Ldif.EncodingLiteral = Field(
            default=c.Ldif.Encoding.UTF8,
            description="Character encoding used for output",
        )
        processing_duration: t.NonNegativeFloat = Field(
            default=0.0, description="Total processing duration in seconds"
        )
        rejection_reasons: FlextLdifModelsCollections.DynamicCounts = Field(
            default_factory=FlextLdifModelsCollections.DynamicCounts,
            description="Counts of entries rejected by reason category",
        )
        events: MutableSequence[
            FlextLdifModelsEvents.ConversionEvent | FlextLdifModelsEvents.DnEvent
        ] = Field(
            default_factory=lambda: list[
                FlextLdifModelsEvents.ConversionEvent | FlextLdifModelsEvents.DnEvent
            ](),
            description="Domain events emitted during processing",
        )

        @computed_field
        def failure_rate(self) -> float:
            return self._rate(self.failed_entries)

        @computed_field
        def rejection_rate(self) -> float:
            return self._rate(self.rejected_entries)

        @computed_field
        def success_rate(self) -> float:
            return self._rate(self.processed_entries)

        @computed_field
        def summary(self) -> FlextLdifModelsResults.StatisticsSummary:
            return self.to_summary()

        @classmethod
        def for_pipeline(
            cls,
            total: int = 0,
            processed: int = 0,
            failed: int = 0,
            rejected: int = 0,
            schema: int = 0,
            data: int = 0,
            hierarchy: int = 0,
            users: int = 0,
            groups: int = 0,
            acl: int = 0,
            acls_extracted: int = 0,
            acls_failed: int = 0,
            acl_attribute_name: str | None = None,
            schema_attributes: int = 0,
            schema_objectclasses: int = 0,
            processing_duration: float = 0.0,
            rejection_reasons: FlextLdifModelsCollections.DynamicCounts | None = None,
        ) -> Self:
            return cls(
                total_entries=total,
                processed_entries=processed,
                failed_entries=failed,
                rejected_entries=rejected,
                schema_entries=schema,
                data_entries=data,
                hierarchy_entries=hierarchy,
                user_entries=users,
                group_entries=groups,
                acl_entries=acl,
                acls_extracted=acls_extracted,
                acls_failed=acls_failed,
                acl_attribute_name=acl_attribute_name,
                schema_attributes=schema_attributes,
                schema_objectclasses=schema_objectclasses,
                processing_duration=processing_duration,
                rejection_reasons=rejection_reasons
                or FlextLdifModelsCollections.DynamicCounts(),
            )

        def merge(self, other: Self) -> Self:
            merged_reasons: t.MutableIntMapping = dict(self.rejection_reasons.items())
            for reason, count in other.rejection_reasons.items():
                merged_reasons[reason] = merged_reasons.get(reason, 0) + count
            sum_fields = {
                "total_entries",
                "processed_entries",
                "failed_entries",
                "rejected_entries",
                "schema_entries",
                "data_entries",
                "hierarchy_entries",
                "user_entries",
                "group_entries",
                "acl_entries",
                "schema_attributes",
                "schema_objectclasses",
                "acls_extracted",
                "acls_failed",
                "parse_errors",
                "entries_written",
                "file_size_bytes",
            }
            updates = {
                name: getattr(self, name) + getattr(other, name) for name in sum_fields
            }
            updates |= {
                "processing_duration": self.processing_duration
                + other.processing_duration,
                "acl_attribute_name": self.acl_attribute_name
                or other.acl_attribute_name,
                "detected_server_type": self.detected_server_type
                or other.detected_server_type,
                "output_file": self.output_file or other.output_file,
                "encoding": self.encoding,
                "rejection_reasons": FlextLdifModelsCollections.DynamicCounts(
                    **merged_reasons,
                ),
                "events": [*self.events, *other.events],
            }
            return self.model_copy(update=updates)

        def to_summary(self) -> FlextLdifModelsResults.StatisticsSummary:
            fields = {
                name: getattr(self, name)
                for name in FlextLdifModelsResults.StatisticsSummary.model_fields
            }
            return FlextLdifModelsResults.StatisticsSummary(**fields)

        def _rate(self, numerator: int) -> float:
            return (
                round(numerator / self.total_entries * 100, 2)
                if self.total_entries
                else 0.0
            )

    class MigrationPipelineResult(m.FrozenModel):
        migrated_schema: FlextLdifModelsCollections.SchemaContent = Field(
            ...,
            description="Schema content after migration transformation",
        )
        entries: MutableSequence[FlextLdifModelsDomainsEntries.Entry] = Field(
            ...,
            description="Migrated LDIF entries",
        )
        stats: FlextLdifModelsResults.Statistics = Field(
            ...,
            description="Migration processing statistics",
        )
        output_files: MutableSequence[str] = Field(
            ..., description="Paths to generated output files"
        )

        @computed_field
        def entry_count(self) -> int:
            return len(self.entries)

        @computed_field
        def is_empty(self) -> bool:
            has_schema = (
                self.stats.schema_attributes > 0 or self.stats.schema_objectclasses > 0
            )
            return not has_schema and self.stats.total_entries == 0

        @computed_field
        def migration_summary(self) -> FlextLdifModelsResults.MigrationSummary:
            return FlextLdifModelsResults.MigrationSummary(
                statistics=self.stats.to_summary(),
                entry_count=len(self.entries),
                output_files=len(self.output_files),
                is_empty=not (
                    self.stats.schema_attributes > 0
                    or self.stats.schema_objectclasses > 0
                )
                and self.stats.total_entries == 0,
            )

        @computed_field
        def output_file_count(self) -> int:
            return len(self.output_files)

    class ClientStatus(m.Value):
        status: Annotated[str, Field(description="Current client operational status")]
        services: Annotated[
            MutableSequence[str],
            Field(description="Available service names"),
        ]
        config: Annotated[
            FlextLdifModelsCollections.ConfigSettings,
            Field(description="Active client configuration settings"),
        ]

    class ValidationResult(m.FrozenModel):
        is_valid: Annotated[
            bool,
            Field(description="Whether all entries passed validation"),
        ]
        total_entries: t.NonNegativeInt = Field(description="Total entries validated")
        valid_entries: t.NonNegativeInt = Field(
            description="Entries that passed validation"
        )
        invalid_entries: t.NonNegativeInt = Field(
            description="Entries that failed validation"
        )
        errors: Annotated[
            MutableSequence[str],
            Field(description="Validation error messages"),
        ]

        @computed_field
        def success_rate(self) -> float:
            if self.total_entries == 0:
                return 100.0
            return self.valid_entries / self.total_entries * 100.0

    class EntryAnalysisResult(m.FrozenModel):
        total_entries: t.NonNegativeInt = Field(description="Total entries analyzed")
        objectclass_distribution: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            Field(description="Distribution of objectClass values across entries"),
        ]
        patterns_detected: Annotated[
            MutableSequence[str],
            Field(description="Entry patterns identified during analysis"),
        ]

        @computed_field
        def unique_objectclasses(self) -> int:
            return len(self.objectclass_distribution)

    class ServerDetectionResult(m.FrozenModel):
        detected_server_type: Annotated[
            c.Ldif.ServerTypeLiteral,
            Field(description="LDAP server type detected from LDIF content"),
        ]
        confidence: t.DecimalFraction = Field(
            description="Detection confidence score between 0 and 1"
        )
        scores: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            Field(description="Per-server-type detection scores"),
        ]
        patterns_found: Annotated[
            MutableSequence[str],
            Field(description="Server-identifying patterns found in LDIF"),
        ]
        is_confident: Annotated[
            bool,
            Field(
                description="Whether confidence exceeds threshold for reliable detection"
            ),
        ]
        detection_error: str | None = Field(
            default=None, description="Error message if detection failed"
        )
        fallback_reason: str | None = Field(
            default=None, description="Reason for using fallback server type"
        )

    class StatisticsResult(m.StrictModel):
        total_entries: Annotated[
            int,
            Field(description="Total entries in result set"),
        ]
        categorized: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            Field(description="Entry counts per category"),
        ]
        rejection_rate: Annotated[
            float,
            Field(description="Percentage of entries rejected"),
        ]
        rejection_count: Annotated[
            int,
            Field(description="Total entries rejected"),
        ]
        written_counts: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            Field(description="Entry counts written per category"),
        ]
        output_files: Annotated[
            FlextLdifModelsCollections.CategoryPaths,
            Field(description="Category to output file path mapping"),
        ]

    class EntriesStatistics(m.Value):
        total_entries: Annotated[
            int,
            Field(description="Total entries analyzed"),
        ]
        object_class_distribution: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            Field(description="Distribution of objectClass values across entries"),
        ]
        server_type_distribution: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            Field(description="Distribution of detected server types across entries"),
        ]

    class DictAccessibleValue(m.Value):
        """Temporary wrapper for values accessed like dicts."""

        def __getitem__(self, key: str) -> t.Scalar | None:
            value = self._resolve_key(key)
            return str(value) if value is not None else None

        def __contains__(self, key: str) -> bool:
            if key in type(self).model_fields:
                return True
            extra = self.__pydantic_extra__
            return extra is not None and key in extra

        def get(
            self,
            key: str,
            default: str | float | bool | None = None,
        ) -> t.Scalar | None:
            try:
                return self[key]
            except KeyError:
                return default

        def items(self) -> MutableSequence[tuple[str, t.Scalar]]:
            results: MutableSequence[tuple[str, t.Scalar]] = []
            for key in self.model_fields_set:
                val = getattr(self, key)
                if isinstance(val, t.PRIMITIVES_TYPES):
                    results.append((key, val))
                elif val is None:
                    continue
                else:
                    results.append((key, str(val)))
            return results

        def keys(self) -> MutableSequence[str]:
            return list(self.model_fields_set)

        def _resolve_key(self, key: str) -> t.NormalizedValue:
            if key in type(self).model_fields:
                return getattr(self, key)
            extra = self.__pydantic_extra__
            if extra is not None and key in extra:
                return extra[key]
            raise KeyError(key)

    class SchemaServiceStatus(DictAccessibleValue):
        service: Annotated[str, Field(description="Schema service name")]
        server_type: Annotated[
            c.Ldif.ServerTypeLiteral,
            Field(description="LDAP server type for schema operations"),
        ]
        status: Annotated[str, Field(description="Current service operational status")]
        rfc_compliance: Annotated[
            str,
            Field(description="RFC compliance level of the schema service"),
        ]
        operations: Annotated[
            MutableSequence[str],
            Field(description="Supported schema operations"),
        ]

    class SyntaxServiceStatus(DictAccessibleValue):
        service: Annotated[str, Field(description="Syntax service name")]
        status: Annotated[str, Field(description="Current service operational status")]
        rfc_compliance: Annotated[
            str,
            Field(description="RFC compliance level of the syntax service"),
        ]
        total_syntaxes: Annotated[
            int,
            Field(description="Total number of registered syntaxes"),
        ]
        common_syntaxes: Annotated[
            int,
            Field(description="Number of commonly used syntaxes"),
        ]

    class StatisticsServiceStatus(DictAccessibleValue):
        service: Annotated[str, Field(description="Statistics service name")]
        status: Annotated[str, Field(description="Current service operational status")]
        capabilities: Annotated[
            MutableSequence[str],
            Field(description="Supported statistics capabilities"),
        ]
        version: Annotated[str, Field(description="Service version identifier")]

    class ValidationServiceStatus(DictAccessibleValue):
        service: Annotated[str, Field(description="Validation service name")]
        status: Annotated[str, Field(description="Current service operational status")]
        rfc_compliance: Annotated[
            str,
            Field(description="RFC compliance level of the validation service"),
        ]
        validation_types: Annotated[
            MutableSequence[str],
            Field(description="Supported validation types"),
        ]

    class ValidationBatchResult(m.StrictModel):
        results: Annotated[
            FlextLdifModelsCollections.BooleanFlags,
            Field(description="Per-entry validation results as boolean flags"),
        ]

    class ParseResponse(m.Value):
        entries: MutableSequence[FlextLdifModelsDomainsEntries.Entry] = Field(
            ...,
            description="Parsed LDIF entries",
        )
        statistics: FlextLdifModelsResults.Statistics = Field(
            ...,
            description="Parsing statistics",
        )
        detected_server_type: c.Ldif.ServerTypeLiteral | None = Field(
            default=None, description="LDAP server type detected during parsing"
        )

    class AclResponse(m.Value):
        acls: MutableSequence[FlextLdifModelsDomainsEntries.Acl] = Field(
            ...,
            description="Extracted ACL models",
        )
        statistics: FlextLdifModelsResults.Statistics = Field(
            ...,
            description="ACL extraction statistics",
        )

    class AclEvaluationResult(m.Value):
        granted: bool = Field(
            default=False, description="Whether the ACL granted access"
        )
        matched_acl: FlextLdifModelsDomainsEntries.Acl | None = Field(
            default=None, description="ACL rule that matched the evaluation"
        )
        message: str = Field(
            default="",
            description="Human-readable evaluation result message",
        )

    class WriteResponse(m.Value):
        content: str | None = Field(
            default=None, description="Serialized LDIF content string"
        )
        statistics: FlextLdifModelsResults.Statistics = Field(
            ...,
            description="Write operation statistics",
        )


__all__ = ["FlextLdifModelsResults"]
