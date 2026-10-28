"""Result models for LDIF processing.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import MutableSequence
from pathlib import Path
from typing import Annotated, ClassVar

from flext_cli import m

from flext_ldif import c, p, t
from flext_ldif._models import (
    FlextLdifModelsCollections,
    FlextLdifModelsDomainsEntries,
    FlextLdifModelsResultsStatistics,
    FlextLdifModelsSettingsMigrate,
)


class FlextLdifModelsResults(FlextLdifModelsResultsStatistics):
    """Namespace for LDIF result models."""

    class WriteRequest(m.ArbitraryTypesModel):
        """One validated write boundary for structural entries and options."""

        entries: MutableSequence[FlextLdifModelsDomainsEntries.Entry] = m.Field(
            description="Owned LDIF entries supplied for serialization",
        )
        format_options: FlextLdifModelsSettingsMigrate.WriteFormatOptions | None = (
            m.Field(
                default=None,
                description="Optional explicit LDIF formatting options",
            )
        )

    class MigrationPipelineOptions(m.ArbitraryTypesModel):
        """Validated configuration consumed by the migration service."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(use_enum_values=False)

        input_dir: Path | None = m.Field(
            default=None,
            exclude=True,
            description="Input LDIF directory",
        )
        output_dir: Path | None = m.Field(
            default=None,
            exclude=True,
            description="Migrated LDIF directory",
        )
        output_filename: str | None = m.Field(
            default=None,
            exclude=True,
            description="Single-file output name override",
        )
        source_server_type: c.Ldif.ServerTypes = m.Field(
            default=c.Ldif.ServerTypes.RFC,
            exclude=True,
            description="Canonical source dialect",
        )
        target_server_type: c.Ldif.ServerTypes = m.Field(
            default=c.Ldif.ServerTypes.RFC,
            exclude=True,
            description="Canonical target dialect",
        )
        base_dn: str = m.Field(
            default="",
            exclude=True,
            description="DN scope for ACL migration",
        )
        sort_entries_hierarchically: bool = m.Field(
            default=False,
            exclude=True,
            description="Write entries by DN depth, then by reversed DN text",
        )
        format_options: FlextLdifModelsSettingsMigrate.WriteFormatOptions | None = (
            m.Field(
                default=None,
                exclude=True,
                description="LDIF formatting applied to the written output",
            )
        )

    class MigrationSummary(m.FrozenModel):
        statistics: Annotated[
            FlextLdifModelsResults.StatisticsSummary | None,
            m.Field(description="Aggregated statistics summary for the migration"),
        ] = None
        entry_count: Annotated[
            int,
            m.Field(description="Total entries in migration result"),
        ] = 0
        output_files: Annotated[
            int,
            m.Field(description="Number of output files generated"),
        ] = 0
        is_empty: Annotated[
            bool,
            m.Field(description="Whether the migration produced no output"),
        ] = True

    class MigrationPipelineResult(m.FrozenModel):
        migrated_schema: FlextLdifModelsCollections.SchemaContent = m.Field(
            default_factory=lambda: FlextLdifModelsCollections.SchemaContent(
                attributes=[], object_classes=[]
            ),
            description="Schema content after migration transformation",
        )
        entries: MutableSequence[FlextLdifModelsDomainsEntries.Entry] = m.Field(
            default_factory=list[FlextLdifModelsDomainsEntries.Entry],
            description="Migrated LDIF entries",
        )
        stats: FlextLdifModelsResults.Statistics = m.Field(
            default_factory=FlextLdifModelsResultsStatistics.Statistics,
            description="Migration processing statistics",
        )
        output_files: MutableSequence[str] = m.Field(
            default_factory=list[str],
            description="Output file paths produced by the migration pipeline.",
        )

        @m.computed_field
        @property
        def entry_count(self) -> int:
            return len(self.entries)

        @m.computed_field
        @property
        def is_empty(self) -> bool:
            has_schema = (
                self.stats.schema_attributes > 0 or self.stats.schema_objectclasses > 0
            )
            return not has_schema and self.stats.total_entries == 0

        @m.computed_field
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

        @m.computed_field
        @property
        def output_file_count(self) -> int:
            return len(self.output_files)

    class ValidationResult(m.FrozenModel):
        valid: Annotated[
            bool,
            m.Field(description="Whether all entries passed validation"),
        ]
        total_entries: t.NonNegativeInt = m.Field(description="Total entries validated")
        valid_entries: t.NonNegativeInt = m.Field(
            description="Entries that passed validation",
        )
        invalid_entries: t.NonNegativeInt = m.Field(
            description="Entries that failed validation",
        )
        errors: Annotated[
            MutableSequence[str],
            m.Field(description="Validation error messages"),
        ]

        @m.computed_field
        @property
        def success_rate(self) -> float:
            if self.total_entries == 0:
                return 100.0
            success_rate: float = self.valid_entries / self.total_entries * 100.0
            return success_rate

    class ServerDetectionResult(m.FrozenModel):
        detected_server_type: Annotated[
            c.Ldif.ServerTypes,
            m.Field(description="LDAP server type detected from LDIF content"),
        ]
        confidence: t.DecimalFraction = m.Field(
            description="Detection confidence score between 0 and 1",
        )
        scores: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            m.Field(description="Per-server-type detection scores"),
        ]
        patterns_found: Annotated[
            MutableSequence[str],
            m.Field(description="Server-identifying patterns found in LDIF"),
        ]
        detection_error: Annotated[
            str | None,
            m.Field(description="Error message if detection failed"),
        ] = None
        fallback_reason: Annotated[
            str | None,
            m.Field(description="Reason for using fallback server type"),
        ] = None

        @m.computed_field
        @property
        def is_confident(self) -> bool:
            confidence: float = self.confidence
            threshold: float = c.Ldif.CONFIDENCE_THRESHOLD
            return confidence >= threshold

    class EntriesStatistics(m.Value):
        total_entries: Annotated[int, m.Field(description="Total entries analyzed")]
        object_class_distribution: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            m.Field(description="Distribution of objectClass values across entries"),
        ]
        server_type_distribution: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            m.Field(description="Distribution of detected server types across entries"),
        ]

    class Response(m.Value):
        statistics: Annotated[
            FlextLdifModelsResults.Statistics,
            m.Field(description="Canonical LDIF service statistics payload"),
        ]

    class ParseResponse(Response):
        entries: Annotated[
            MutableSequence[FlextLdifModelsDomainsEntries.Entry],
            m.Field(description="Parsed LDIF entries"),
        ]
        detected_server_type: Annotated[
            c.Ldif.ServerTypes | None,
            m.Field(description="LDAP server type detected during parsing"),
        ] = None

    class AclResponse(Response):
        acls: Annotated[
            MutableSequence[t.Port[p.Ldif.Acl]],
            m.Field(description="Extracted ACL models"),
        ]

    class AclEvaluationResult(Response):
        granted: Annotated[
            bool,
            m.Field(description="Whether the ACL granted access"),
        ] = False
        matched_acl: Annotated[
            t.Port[p.Ldif.Acl] | None,
            m.Field(description="ACL rule that matched the evaluation"),
        ] = None
        message: Annotated[
            str,
            m.Field(description="Human-readable evaluation result message"),
        ] = ""

    class WriteResponse(Response):
        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(
            str_strip_whitespace=False,
        )

        content: Annotated[
            str | None,
            m.Field(description="Serialized LDIF content string"),
        ] = None
        output_path: Annotated[
            str | None,
            m.Field(
                description="Target file path when the write operation persisted "
                "content",
            ),
        ] = None


__all__: list[str] = ["FlextLdifModelsResults"]
