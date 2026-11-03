# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/results_statistics
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol, Self, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif import t
    from flext_ldif._constants import FlextLdifConstantsBaseParts
    from flext_ldif._protocols import (
        FlextLdifProtocolsCollections,
        FlextLdifProtocolsEvents,
    )


class FlextLdifProtocolsResultsStatistics:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class StatisticsSummary(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def total_entries(self) -> int:
            """Total number of entries processed."""
            ...

        @property
        def processed_entries(self) -> int:
            """Entries successfully processed."""
            ...

        @property
        def failed_entries(self) -> int:
            """Entries that failed processing."""
            ...

        @property
        def rejected_entries(self) -> int:
            """Entries rejected by filter rules."""
            ...

        @property
        def success_rate(self) -> float:
            """Percentage of entries successfully processed."""
            ...

        @property
        def failure_rate(self) -> float:
            """Percentage of entries that failed."""
            ...

        @property
        def rejection_rate(self) -> float:
            """Percentage of entries rejected."""
            ...

        @property
        def schema_entries(self) -> int:
            """Count of schema definition entries."""
            ...

        @property
        def data_entries(self) -> int:
            """Count of data entries."""
            ...

        @property
        def hierarchy_entries(self) -> int:
            """Count of organizational hierarchy entries."""
            ...

        @property
        def user_entries(self) -> int:
            """Count of user entries."""
            ...

        @property
        def group_entries(self) -> int:
            """Count of group entries."""
            ...

        @property
        def acl_entries(self) -> int:
            """Count of ACL entries."""
            ...

        @property
        def acls_extracted(self) -> int:
            """ACLs successfully extracted."""
            ...

        @property
        def acls_failed(self) -> int:
            """ACLs that failed extraction."""
            ...

        @property
        def parse_errors(self) -> int:
            """Count of parse errors encountered."""
            ...

        @property
        def entries_written(self) -> int:
            """Entries written to output."""
            ...

    @runtime_checkable
    class StatisticsEntryCounts(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def total_entries(self) -> t.NonNegativeInt:
            """Total number of entries processed."""
            ...

        @property
        def processed_entries(self) -> t.NonNegativeInt:
            """Entries successfully processed."""
            ...

        @property
        def failed_entries(self) -> t.NonNegativeInt:
            """Entries that failed processing."""
            ...

        @property
        def schema_entries(self) -> t.NonNegativeInt:
            """Count of schema definition entries."""
            ...

        @property
        def data_entries(self) -> t.NonNegativeInt:
            """Count of data entries."""
            ...

        @property
        def hierarchy_entries(self) -> t.NonNegativeInt:
            """Count of organizational hierarchy entries."""
            ...

        @property
        def user_entries(self) -> t.NonNegativeInt:
            """Count of user entries."""
            ...

        @property
        def group_entries(self) -> t.NonNegativeInt:
            """Count of group entries."""
            ...

        @property
        def acl_entries(self) -> t.NonNegativeInt:
            """Count of ACL entries."""
            ...

        @property
        def rejected_entries(self) -> t.NonNegativeInt:
            """Entries rejected by filter rules."""
            ...

    @runtime_checkable
    class StatisticsSchemaAcl(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def schema_attributes(self) -> t.NonNegativeInt:
            """Count of schema attributes parsed."""
            ...

        @property
        def schema_objectclasses(self) -> t.NonNegativeInt:
            """Count of schema object classes parsed."""
            ...

        @property
        def acls_extracted(self) -> t.NonNegativeInt:
            """ACLs successfully extracted."""
            ...

        @property
        def acls_failed(self) -> t.NonNegativeInt:
            """ACLs that failed extraction."""
            ...

        @property
        def acl_attribute_name(self) -> str | None:
            """Name of the ACL attribute used for extraction."""
            ...

    @runtime_checkable
    class StatisticsRun(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def parse_errors(self) -> t.NonNegativeInt:
            """Count of parse errors encountered."""
            ...

        @property
        def detected_server_type(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.ServerTypes | None:
            """LDAP server type detected from LDIF content."""
            ...

        @property
        def entries_written(self) -> t.NonNegativeInt:
            """Entries written to output."""
            ...

        @property
        def output_file(self) -> str | None:
            """Path to the output file."""
            ...

        @property
        def file_size_bytes(self) -> t.NonNegativeInt:
            """Output file size in bytes."""
            ...

        @property
        def encoding(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.Encoding:
            """Character encoding used for output."""
            ...

        @property
        def processing_duration(self) -> t.NonNegativeFloat:
            """Total processing duration in seconds."""
            ...

        @property
        def rejection_reasons(self) -> FlextLdifProtocolsCollections.DynamicCounts:
            """Counts of entries rejected by reason category."""
            ...

        @property
        def events(
            self,
        ) -> Sequence[
            FlextLdifProtocolsEvents.ConversionEvent | FlextLdifProtocolsEvents.DnEvent
        ]:
            """Domain events emitted during processing."""
            ...

    @runtime_checkable
    class Statistics(
        StatisticsRun, StatisticsSchemaAcl, StatisticsEntryCounts, Protocol
    ):
        """Structural data contract projected from the owning model."""

        @property
        def failure_rate(self) -> float:
            """Structural member projected from the owning model."""
            ...

        @property
        def rejection_rate(self) -> float:
            """Structural member projected from the owning model."""
            ...

        @property
        def success_rate(self) -> float:
            """Structural member projected from the owning model."""
            ...

        @property
        def summary(self) -> FlextLdifProtocolsResultsStatistics.StatisticsSummary:
            """Structural member projected from the owning model."""
            ...

        def merge(self, other: Self) -> Self:
            """Structural member projected from the owning model."""
            ...

        def to_summary(self) -> FlextLdifProtocolsResultsStatistics.StatisticsSummary:
            """Structural member projected from the owning model."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsResultsStatistics",
]
