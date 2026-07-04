"""Result models for LDIF processing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Self

from flext_core import m
from flext_core.utilities import FlextUtilities as u
from flext_ldif import c, t
from flext_ldif._models.collections import FlextLdifModelsCollections as mc
from flext_ldif._models.events import FlextLdifModelsEvents as me

if TYPE_CHECKING:
    from flext_ldif._models.domain_entries import FlextLdifModelsDomainsEntries as mde


class FlextLdifModelsResults:
    """Namespace for LDIF result models."""

    class StatisticsSummary(m.FrozenModel):
        total_entries: Annotated[
            int,
            u.Field(description="Total number of entries processed"),
        ] = 0
        processed_entries: Annotated[
            int,
            u.Field(description="Entries successfully processed"),
        ] = 0
        failed_entries: Annotated[
            int,
            u.Field(description="Entries that failed processing"),
        ] = 0
        rejected_entries: Annotated[
            int,
            u.Field(description="Entries rejected by filter rules"),
        ] = 0
        success_rate: Annotated[
            float,
            u.Field(description="Percentage of entries successfully processed"),
        ] = 0.0
        failure_rate: Annotated[
            float,
            u.Field(description="Percentage of entries that failed"),
        ] = 0.0
        rejection_rate: Annotated[
            float,
            u.Field(description="Percentage of entries rejected"),
        ] = 0.0
        schema_entries: Annotated[
            int,
            u.Field(description="Count of schema definition entries"),
        ] = 0
        data_entries: Annotated[int, u.Field(description="Count of data entries")] = 0
        hierarchy_entries: Annotated[
            int,
            u.Field(description="Count of organizational hierarchy entries"),
        ] = 0
        user_entries: Annotated[int, u.Field(description="Count of user entries")] = 0
        group_entries: Annotated[int, u.Field(description="Count of group entries")] = 0
        acl_entries: Annotated[int, u.Field(description="Count of ACL entries")] = 0
        acls_extracted: Annotated[
            int,
            u.Field(description="ACLs successfully extracted"),
        ] = 0
        acls_failed: Annotated[
            int,
            u.Field(description="ACLs that failed extraction"),
        ] = 0
        parse_errors: Annotated[
            int,
            u.Field(description="Count of parse errors encountered"),
        ] = 0
        entries_written: Annotated[
            int,
            u.Field(description="Entries written to output"),
        ] = 0

    class MigrationSummary(m.FrozenModel):
        statistics: Annotated[
            FlextLdifModelsResults.StatisticsSummary | None,
            u.Field(
                description="Aggregated statistics summary for the migration",
            ),
        ] = None
        entry_count: Annotated[
            int,
            u.Field(description="Total entries in migration result"),
        ] = 0
        output_files: Annotated[
            int,
            u.Field(description="Number of output files generated"),
        ] = 0
        is_empty: Annotated[
            bool,
            u.Field(description="Whether the migration produced no output"),
        ] = True

    class Statistics(m.FrozenModel):
        total_entries: Annotated[
            t.NonNegativeInt,
            u.Field(description="Total number of entries processed"),
        ] = 0
        processed_entries: Annotated[
            t.NonNegativeInt,
            u.Field(description="Entries successfully processed"),
        ] = 0
        failed_entries: Annotated[
            t.NonNegativeInt,
            u.Field(description="Entries that failed processing"),
        ] = 0
        schema_entries: Annotated[
            t.NonNegativeInt,
            u.Field(description="Count of schema definition entries"),
        ] = 0
        data_entries: Annotated[
            t.NonNegativeInt,
            u.Field(description="Count of data entries"),
        ] = 0
        hierarchy_entries: Annotated[
            t.NonNegativeInt,
            u.Field(description="Count of organizational hierarchy entries"),
        ] = 0
        user_entries: Annotated[
            t.NonNegativeInt,
            u.Field(description="Count of user entries"),
        ] = 0
        group_entries: Annotated[
            t.NonNegativeInt,
            u.Field(description="Count of group entries"),
        ] = 0
        acl_entries: Annotated[
            t.NonNegativeInt,
            u.Field(description="Count of ACL entries"),
        ] = 0
        rejected_entries: Annotated[
            t.NonNegativeInt,
            u.Field(description="Entries rejected by filter rules"),
        ] = 0
        schema_attributes: Annotated[
            t.NonNegativeInt,
            u.Field(description="Count of schema attributes parsed"),
        ] = 0
        schema_objectclasses: Annotated[
            t.NonNegativeInt,
            u.Field(description="Count of schema object classes parsed"),
        ] = 0
        acls_extracted: Annotated[
            t.NonNegativeInt,
            u.Field(description="ACLs successfully extracted"),
        ] = 0
        acls_failed: Annotated[
            t.NonNegativeInt,
            u.Field(description="ACLs that failed extraction"),
        ] = 0
        acl_attribute_name: Annotated[
            str | None,
            u.Field(description="Name of the ACL attribute used for extraction"),
        ] = None
        parse_errors: Annotated[
            t.NonNegativeInt,
            u.Field(description="Count of parse errors encountered"),
        ] = 0
        detected_server_type: Annotated[
            c.Ldif.ServerTypes | None,
            u.Field(description="LDAP server type detected from LDIF content"),
        ] = None
        entries_written: Annotated[
            t.NonNegativeInt,
            u.Field(description="Entries written to output"),
        ] = 0
        output_file: Annotated[
            str | None,
            u.Field(description="Path to the output file"),
        ] = None
        file_size_bytes: Annotated[
            t.NonNegativeInt,
            u.Field(description="Output file size in bytes"),
        ] = 0
        encoding: Annotated[
            c.Ldif.Encoding,
            u.Field(
                description="Character encoding used for output",
            ),
        ] = c.Ldif.Encoding.UTF8
        processing_duration: Annotated[
            t.NonNegativeFloat,
            u.Field(description="Total processing duration in seconds"),
        ] = 0.0
        rejection_reasons: mc.DynamicCounts = u.Field(
            default_factory=mc.DynamicCounts,
            description="Counts of entries rejected by reason category",
        )
        events: t.MutableSequenceOf[me.ConversionEvent | me.DnEvent] = u.Field(
            default_factory=list[me.ConversionEvent | me.DnEvent],
            description="Domain events emitted during processing",
        )

        @u.computed_field()
        @property
        def failure_rate(self) -> float:
            return self._rate(self.failed_entries)

        @u.computed_field()
        @property
        def rejection_rate(self) -> float:
            return self._rate(self.rejected_entries)

        @u.computed_field()
        @property
        def success_rate(self) -> float:
            return self._rate(self.processed_entries)

        @u.computed_field()
        @property
        def summary(self) -> FlextLdifModelsResults.StatisticsSummary:
            return self.to_summary()

        @classmethod
        def for_pipeline(
            cls,
            *,
            total: int,
            processed: int,
            rejected: int,
            schema: int,
            hierarchy: int,
            users: int,
            groups: int,
            acl: int,
        ) -> Self:
            return cls(
                total_entries=total,
                processed_entries=processed,
                rejected_entries=rejected,
                schema_entries=schema,
                hierarchy_entries=hierarchy,
                user_entries=users,
                group_entries=groups,
                acl_entries=acl,
            )

        def merge(self, other: Self) -> Self:
            merged_reasons = t.int_dict_adapter().validate_python(
                self.rejection_reasons,
            )
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
                "rejection_reasons": mc.DynamicCounts(
                    **merged_reasons,
                ),
                "events": [*self.events, *other.events],
            }
            copied: Self = self.model_copy(update=updates)
            return copied

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
        migrated_schema: mc.SchemaContent = u.Field(
            default_factory=lambda: mc.SchemaContent.model_construct(
                attributes=[],
                object_classes=[],
            ),
            description="Schema content after migration transformation",
        )
        entries: t.MutableSequenceOf[mde.Entry] = u.Field(
            default_factory=list,
            description="Migrated LDIF entries",
        )
        stats: FlextLdifModelsResults.Statistics = u.Field(
            default_factory=FlextLdifModelsResults.Statistics,
            description="Migration processing statistics",
        )
        output_files: t.MutableSequenceOf[str] = u.Field(
            default_factory=list,
            description="Output file paths produced by the migration pipeline.",
        )

        @u.computed_field()
        @property
        def entry_count(self) -> int:
            return len(self.entries)

        @u.computed_field()
        @property
        def is_empty(self) -> bool:
            has_schema = (
                self.stats.schema_attributes > 0 or self.stats.schema_objectclasses > 0
            )
            return not has_schema and self.stats.total_entries == 0

        @u.computed_field()
        @property
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

        @u.computed_field()
        @property
        def output_file_count(self) -> int:
            return len(self.output_files)

    class ValidationResult(m.FrozenModel):
        valid: Annotated[
            bool,
            u.Field(description="Whether all entries passed validation"),
        ]
        total_entries: t.NonNegativeInt = u.Field(description="Total entries validated")
        valid_entries: t.NonNegativeInt = u.Field(
            description="Entries that passed validation",
        )
        invalid_entries: t.NonNegativeInt = u.Field(
            description="Entries that failed validation",
        )
        errors: Annotated[
            t.MutableSequenceOf[str],
            u.Field(description="Validation error messages"),
        ]

        @u.computed_field()
        @property
        def success_rate(self) -> float:
            if self.total_entries == 0:
                return 100.0
            success_rate: float = self.valid_entries / self.total_entries * 100.0
            return success_rate

    class ServerDetectionResult(m.FrozenModel):
        detected_server_type: Annotated[
            c.Ldif.ServerTypes,
            u.Field(description="LDAP server type detected from LDIF content"),
        ]
        confidence: t.DecimalFraction = u.Field(
            description="Detection confidence score between 0 and 1",
        )
        scores: Annotated[
            mc.DynamicCounts,
            u.Field(description="Per-server-type detection scores"),
        ]
        patterns_found: Annotated[
            t.MutableSequenceOf[str],
            u.Field(description="Server-identifying patterns found in LDIF"),
        ]
        detection_error: Annotated[
            str | None,
            u.Field(description="Error message if detection failed"),
        ] = None
        fallback_reason: Annotated[
            str | None,
            u.Field(description="Reason for using fallback server type"),
        ] = None

        @u.computed_field()
        @property
        def is_confident(self) -> bool:
            return self.confidence >= c.Ldif.CONFIDENCE_THRESHOLD

    class EntriesStatistics(m.Value):
        total_entries: Annotated[
            int,
            u.Field(description="Total entries analyzed"),
        ]
        object_class_distribution: Annotated[
            mc.DynamicCounts,
            u.Field(description="Distribution of objectClass values across entries"),
        ]
        server_type_distribution: Annotated[
            mc.DynamicCounts,
            u.Field(description="Distribution of detected server types across entries"),
        ]

    class Response(m.Value):
        statistics: Annotated[
            FlextLdifModelsResults.Statistics,
            u.Field(
                description="Canonical LDIF service statistics payload",
            ),
        ]

    class ParseResponse(Response):
        entries: Annotated[
            t.MutableSequenceOf[mde.Entry],
            u.Field(
                description="Parsed LDIF entries",
            ),
        ]
        detected_server_type: Annotated[
            c.Ldif.ServerTypes | None,
            u.Field(description="LDAP server type detected during parsing"),
        ] = None

    class AclResponse(Response):
        acls: Annotated[
            t.MutableSequenceOf[mde.Acl],
            u.Field(
                description="Extracted ACL models",
            ),
        ]

    class AclEvaluationResult(m.Value):
        granted: Annotated[
            bool,
            u.Field(description="Whether the ACL granted access"),
        ] = False
        matched_acl: Annotated[
            mde.Acl | None,
            u.Field(description="ACL rule that matched the evaluation"),
        ] = None
        message: Annotated[
            str,
            u.Field(
                description="Human-readable evaluation result message",
            ),
        ] = ""

    class WriteResponse(Response):
        content: Annotated[
            str | None,
            u.Field(description="Serialized LDIF content string"),
        ] = None
        output_path: Annotated[
            str | None,
            u.Field(
                description="Target file path when the write operation persisted content",
            ),
        ] = None


__all__: list[str] = ["FlextLdifModelsResults"]
