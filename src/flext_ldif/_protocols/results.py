# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/results
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif import c, t
    from flext_ldif._protocols import (
        FlextLdifProtocolsCollections,
        FlextLdifProtocolsDomainAcl,
        FlextLdifProtocolsDomainEntry,
        FlextLdifProtocolsResultsStatistics,
    )
    from flext_ldif._protocols._settings import FlextLdifProtocolsSettingsMigrate


class FlextLdifProtocolsResults:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class WriteRequest(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def entries(self) -> Sequence[FlextLdifProtocolsDomainEntry.Entry]:
            """Owned LDIF entries supplied for serialization."""
            ...

        @property
        def format_options(
            self,
        ) -> FlextLdifProtocolsSettingsMigrate.WriteFormatOptions | None:
            """Optional explicit LDIF formatting options."""
            ...

    @runtime_checkable
    class MigrationPipelineOptions(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        input_dir: Path | None
        output_dir: Path | None
        output_filename: str | None
        source_server_type: c.Ldif.ServerTypes
        target_server_type: c.Ldif.ServerTypes
        base_dn: str
        sort_entries_hierarchically: bool

        @property
        def format_options(
            self,
        ) -> FlextLdifProtocolsSettingsMigrate.WriteFormatOptions | None:
            """LDIF formatting applied to the written output."""
            ...

    @runtime_checkable
    class MigrationSummary(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def statistics(
            self,
        ) -> FlextLdifProtocolsResultsStatistics.StatisticsSummary | None:
            """Aggregated statistics summary for the migration."""
            ...

        @property
        def entry_count(self) -> int:
            """Total entries in migration result."""
            ...

        @property
        def output_files(self) -> int:
            """Number of output files generated."""
            ...

        @property
        def is_empty(self) -> bool:
            """Whether the migration produced no output."""
            ...

    @runtime_checkable
    class MigrationPipelineResult(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def migrated_schema(self) -> FlextLdifProtocolsCollections.SchemaContent:
            """Schema content after migration transformation."""
            ...

        @property
        def entries(self) -> Sequence[FlextLdifProtocolsDomainEntry.Entry]:
            """Migrated LDIF entries."""
            ...

        @property
        def stats(self) -> FlextLdifProtocolsResultsStatistics.Statistics:
            """Migration processing statistics."""
            ...

        @property
        def output_files(self) -> MutableSequence[str]:
            """Output file paths produced by the migration pipeline."""
            ...

        @property
        def entry_count(self) -> int:
            """Structural member projected from the owning model."""
            ...

        @property
        def is_empty(self) -> bool:
            """Structural member projected from the owning model."""
            ...

        @property
        def migration_summary(self) -> FlextLdifProtocolsResults.MigrationSummary:
            """Structural member projected from the owning model."""
            ...

        @property
        def output_file_count(self) -> int:
            """Structural member projected from the owning model."""
            ...

    @runtime_checkable
    class ValidationResult(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def valid(self) -> bool:
            """Whether all entries passed validation."""
            ...

        @property
        def total_entries(self) -> t.NonNegativeInt:
            """Total entries validated."""
            ...

        @property
        def valid_entries(self) -> t.NonNegativeInt:
            """Entries that passed validation."""
            ...

        @property
        def invalid_entries(self) -> t.NonNegativeInt:
            """Entries that failed validation."""
            ...

        @property
        def errors(self) -> MutableSequence[str]:
            """Validation error messages."""
            ...

        @property
        def success_rate(self) -> float:
            """Structural member projected from the owning model."""
            ...

    @runtime_checkable
    class ServerDetectionResult(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def detected_server_type(self) -> c.Ldif.ServerTypes:
            """LDAP server type detected from LDIF content."""
            ...

        @property
        def confidence(self) -> t.DecimalFraction:
            """Detection confidence score between 0 and 1."""
            ...

        @property
        def scores(self) -> FlextLdifProtocolsCollections.DynamicCounts:
            """Per-server-type detection scores."""
            ...

        @property
        def patterns_found(self) -> MutableSequence[str]:
            """Server-identifying patterns found in LDIF."""
            ...

        @property
        def detection_error(self) -> str | None:
            """Error message if detection failed."""
            ...

        @property
        def fallback_reason(self) -> str | None:
            """Reason for using fallback server type."""
            ...

        @property
        def is_confident(self) -> bool:
            """Structural member projected from the owning model."""
            ...

    @runtime_checkable
    class EntriesStatistics(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def total_entries(self) -> int:
            """Total entries analyzed."""
            ...

        @property
        def object_class_distribution(
            self,
        ) -> FlextLdifProtocolsCollections.DynamicCounts:
            """Distribution of objectClass values across entries."""
            ...

        @property
        def server_type_distribution(
            self,
        ) -> FlextLdifProtocolsCollections.DynamicCounts:
            """Distribution of detected server types across entries."""
            ...

    @runtime_checkable
    class Response(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def statistics(self) -> FlextLdifProtocolsResultsStatistics.Statistics:
            """Canonical LDIF service statistics payload."""
            ...

    @runtime_checkable
    class ParseResponse(Response, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def entries(self) -> Sequence[FlextLdifProtocolsDomainEntry.Entry]:
            """Parsed LDIF entries."""
            ...

        @property
        def detected_server_type(self) -> c.Ldif.ServerTypes | None:
            """LDAP server type detected during parsing."""
            ...

    @runtime_checkable
    class AclResponse(Response, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def acls(self) -> Sequence[FlextLdifProtocolsDomainAcl.Acl]:
            """Extracted ACL models."""
            ...

    @runtime_checkable
    class AclEvaluationResult(Response, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def granted(self) -> bool:
            """Whether the ACL granted access."""
            ...

        @property
        def matched_acl(self) -> FlextLdifProtocolsDomainAcl.Acl | None:
            """ACL rule that matched the evaluation."""
            ...

        @property
        def message(self) -> str:
            """Human-readable evaluation result message."""
            ...

    @runtime_checkable
    class WriteResponse(Response, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def content(self) -> str | None:
            """Serialized LDIF content string."""
            ...

        @property
        def output_path(self) -> str | None:
            """Target file path when the write operation persisted content."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsResults",
]
