"""Migration statistics facet for LDIF result models."""

from __future__ import annotations

from typing import Annotated, Self

from flext_core import FlextUtilities as u, m
from flext_ldif import c, t

from .collections import FlextLdifModelsCollections as mc
from .events import FlextLdifModelsEvents as me


class FlextLdifModelsResultsStatistics:
    """Statistics facet for LDIF migration result models."""

    class StatisticsSummary(m.FrozenModel):
        total_entries: Annotated[
            int, u.Field(description="Total number of entries processed")
        ] = 0
        processed_entries: Annotated[
            int, u.Field(description="Entries successfully processed")
        ] = 0
        failed_entries: Annotated[
            int, u.Field(description="Entries that failed processing")
        ] = 0
        rejected_entries: Annotated[
            int, u.Field(description="Entries rejected by filter rules")
        ] = 0
        success_rate: Annotated[
            float, u.Field(description="Percentage of entries successfully processed")
        ] = 0.0
        failure_rate: Annotated[
            float, u.Field(description="Percentage of entries that failed")
        ] = 0.0
        rejection_rate: Annotated[
            float, u.Field(description="Percentage of entries rejected")
        ] = 0.0
        schema_entries: Annotated[
            int, u.Field(description="Count of schema definition entries")
        ] = 0
        data_entries: Annotated[int, u.Field(description="Count of data entries")] = 0
        hierarchy_entries: Annotated[
            int, u.Field(description="Count of organizational hierarchy entries")
        ] = 0
        user_entries: Annotated[int, u.Field(description="Count of user entries")] = 0
        group_entries: Annotated[int, u.Field(description="Count of group entries")] = 0
        acl_entries: Annotated[int, u.Field(description="Count of ACL entries")] = 0
        acls_extracted: Annotated[
            int, u.Field(description="ACLs successfully extracted")
        ] = 0
        acls_failed: Annotated[
            int, u.Field(description="ACLs that failed extraction")
        ] = 0
        parse_errors: Annotated[
            int, u.Field(description="Count of parse errors encountered")
        ] = 0
        entries_written: Annotated[
            int, u.Field(description="Entries written to output")
        ] = 0

    class Statistics(m.FrozenModel):
        total_entries: Annotated[
            t.NonNegativeInt, u.Field(description="Total number of entries processed")
        ] = 0
        processed_entries: Annotated[
            t.NonNegativeInt, u.Field(description="Entries successfully processed")
        ] = 0
        failed_entries: Annotated[
            t.NonNegativeInt, u.Field(description="Entries that failed processing")
        ] = 0
        schema_entries: Annotated[
            t.NonNegativeInt, u.Field(description="Count of schema definition entries")
        ] = 0
        data_entries: Annotated[
            t.NonNegativeInt, u.Field(description="Count of data entries")
        ] = 0
        hierarchy_entries: Annotated[
            t.NonNegativeInt,
            u.Field(description="Count of organizational hierarchy entries"),
        ] = 0
        user_entries: Annotated[
            t.NonNegativeInt, u.Field(description="Count of user entries")
        ] = 0
        group_entries: Annotated[
            t.NonNegativeInt, u.Field(description="Count of group entries")
        ] = 0
        acl_entries: Annotated[
            t.NonNegativeInt, u.Field(description="Count of ACL entries")
        ] = 0
        rejected_entries: Annotated[
            t.NonNegativeInt, u.Field(description="Entries rejected by filter rules")
        ] = 0
        schema_attributes: Annotated[
            t.NonNegativeInt, u.Field(description="Count of schema attributes parsed")
        ] = 0
        schema_objectclasses: Annotated[
            t.NonNegativeInt,
            u.Field(description="Count of schema object classes parsed"),
        ] = 0
        acls_extracted: Annotated[
            t.NonNegativeInt, u.Field(description="ACLs successfully extracted")
        ] = 0
        acls_failed: Annotated[
            t.NonNegativeInt, u.Field(description="ACLs that failed extraction")
        ] = 0
        acl_attribute_name: Annotated[
            str | None,
            u.Field(description="Name of the ACL attribute used for extraction"),
        ] = None
        parse_errors: Annotated[
            t.NonNegativeInt, u.Field(description="Count of parse errors encountered")
        ] = 0
        detected_server_type: Annotated[
            c.Ldif.ServerTypes | None,
            u.Field(description="LDAP server type detected from LDIF content"),
        ] = None
        entries_written: Annotated[
            t.NonNegativeInt, u.Field(description="Entries written to output")
        ] = 0
        output_file: Annotated[
            str | None, u.Field(description="Path to the output file")
        ] = None
        file_size_bytes: Annotated[
            t.NonNegativeInt, u.Field(description="Output file size in bytes")
        ] = 0
        encoding: Annotated[
            c.Ldif.Encoding, u.Field(description="Character encoding used for output")
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

        @u.computed_field
        @property
        def failure_rate(self) -> float:
            return self._rate(self.failed_entries)

        @u.computed_field
        @property
        def rejection_rate(self) -> float:
            return self._rate(self.rejected_entries)

        @u.computed_field
        @property
        def success_rate(self) -> float:
            return self._rate(self.processed_entries)

        @u.computed_field
        @property
        def summary(self) -> FlextLdifModelsResultsStatistics.StatisticsSummary:
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
                self.rejection_reasons
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
                "rejection_reasons": mc.DynamicCounts(**merged_reasons),
                "events": [*self.events, *other.events],
            }
            copied: Self = self.model_copy(update=updates)
            return copied

        def to_summary(self) -> FlextLdifModelsResultsStatistics.StatisticsSummary:
            fields = {
                name: getattr(self, name)
                for name in FlextLdifModelsResultsStatistics.StatisticsSummary.model_fields
            }
            return FlextLdifModelsResultsStatistics.StatisticsSummary(**fields)

        def _rate(self, numerator: int) -> float:
            return (
                round(numerator / self.total_entries * 100, 2)
                if self.total_entries
                else 0.0
            )


__all__: list[str] = ["FlextLdifModelsResultsStatistics"]
