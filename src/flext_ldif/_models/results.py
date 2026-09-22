"""Result models for LDIF processing."""

from __future__ import annotations

from typing import Annotated

from flext_core import FlextUtilities as u, m
from flext_ldif import c, t

from .collections import FlextLdifModelsCollections as mc
from .domain_entries import FlextLdifModelsDomainsEntries as mde
from .results_statistics import FlextLdifModelsResultsStatistics


class FlextLdifModelsResults(FlextLdifModelsResultsStatistics):
    """Namespace for LDIF result models."""

    class MigrationSummary(m.FrozenModel):
        statistics: Annotated[
            FlextLdifModelsResults.StatisticsSummary | None,
            u.Field(description="Aggregated statistics summary for the migration"),
        ] = None
        entry_count: Annotated[
            int, u.Field(description="Total entries in migration result")
        ] = 0
        output_files: Annotated[
            int, u.Field(description="Number of output files generated")
        ] = 0
        is_empty: Annotated[
            bool, u.Field(description="Whether the migration produced no output")
        ] = True

    class MigrationPipelineResult(m.FrozenModel):
        migrated_schema: mc.SchemaContent = u.Field(
            default_factory=lambda: mc.SchemaContent(
                attributes=[], object_classes=[]
            ),
            description="Schema content after migration transformation",
        )
        entries: t.MutableSequenceOf[mde.Entry] = u.Field(
            default_factory=list, description="Migrated LDIF entries"
        )
        stats: FlextLdifModelsResults.Statistics = u.Field(
            default_factory=FlextLdifModelsResultsStatistics.Statistics,
            description="Migration processing statistics",
        )
        output_files: t.MutableSequenceOf[str] = u.Field(
            default_factory=list,
            description="Output file paths produced by the migration pipeline.",
        )

        @u.computed_field
        @property
        def entry_count(self) -> int:
            return len(self.entries)

        @u.computed_field
        @property
        def is_empty(self) -> bool:
            has_schema = (
                self.stats.schema_attributes > 0 or self.stats.schema_objectclasses > 0
            )
            return not has_schema and self.stats.total_entries == 0

        @u.computed_field
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

        @u.computed_field
        @property
        def output_file_count(self) -> int:
            return len(self.output_files)

    class ValidationResult(m.FrozenModel):
        valid: Annotated[
            bool, u.Field(description="Whether all entries passed validation")
        ]
        total_entries: t.NonNegativeInt = u.Field(description="Total entries validated")
        valid_entries: t.NonNegativeInt = u.Field(
            description="Entries that passed validation"
        )
        invalid_entries: t.NonNegativeInt = u.Field(
            description="Entries that failed validation"
        )
        errors: Annotated[
            t.MutableSequenceOf[str], u.Field(description="Validation error messages")
        ]

        @u.computed_field
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
            description="Detection confidence score between 0 and 1"
        )
        scores: Annotated[
            mc.DynamicCounts, u.Field(description="Per-server-type detection scores")
        ]
        patterns_found: Annotated[
            t.MutableSequenceOf[str],
            u.Field(description="Server-identifying patterns found in LDIF"),
        ]
        detection_error: Annotated[
            str | None, u.Field(description="Error message if detection failed")
        ] = None
        fallback_reason: Annotated[
            str | None, u.Field(description="Reason for using fallback server type")
        ] = None

        @u.computed_field
        @property
        def is_confident(self) -> bool:
            confidence: float = self.confidence
            threshold: float = c.Ldif.CONFIDENCE_THRESHOLD
            return confidence >= threshold

    class EntriesStatistics(m.Value):
        total_entries: Annotated[int, u.Field(description="Total entries analyzed")]
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
            u.Field(description="Canonical LDIF service statistics payload"),
        ]

    class ParseResponse(Response):
        entries: Annotated[
            t.MutableSequenceOf[mde.Entry], u.Field(description="Parsed LDIF entries")
        ]
        detected_server_type: Annotated[
            c.Ldif.ServerTypes | None,
            u.Field(description="LDAP server type detected during parsing"),
        ] = None

    class AclResponse(Response):
        acls: Annotated[
            t.MutableSequenceOf[mde.Acl], u.Field(description="Extracted ACL models")
        ]

    class AclEvaluationResult(m.Value):
        granted: Annotated[
            bool, u.Field(description="Whether the ACL granted access")
        ] = False
        matched_acl: Annotated[
            mde.Acl | None, u.Field(description="ACL rule that matched the evaluation")
        ] = None
        message: Annotated[
            str, u.Field(description="Human-readable evaluation result message")
        ] = ""

    class WriteResponse(Response):
        content: Annotated[
            str | None, u.Field(description="Serialized LDIF content string")
        ] = None
        output_path: Annotated[
            str | None,
            u.Field(
                description="Target file path when the write operation persisted content"
            ),
        ] = None


__all__: list[str] = ["FlextLdifModelsResults"]
