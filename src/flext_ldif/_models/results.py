from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, ClassVar, Self, overload

from flext_core import m
from pydantic import ConfigDict, Field, computed_field, field_validator

from flext_ldif import (
    FlextLdifModelsBases,
    FlextLdifModelsCollections,
    FlextLdifModelsDomains,
    FlextLdifModelsEvents,
    c,
    t,
)


class FlextLdifModelsResults:
    @staticmethod
    def _events_factory() -> list[FlextLdifModelsResults.EventType]:
        return []

    @staticmethod
    def _statistics_factory() -> FlextLdifModelsResults.Statistics:
        return FlextLdifModelsResults.Statistics()

    type EventType = (
        FlextLdifModelsEvents.AclEvent
        | FlextLdifModelsEvents.CategoryEvent
        | FlextLdifModelsEvents.ConversionEvent
        | FlextLdifModelsEvents.DnEvent
        | FlextLdifModelsEvents.FilterEvent
        | FlextLdifModelsEvents.MigrationEvent
        | FlextLdifModelsEvents.ParseEvent
        | FlextLdifModelsEvents.SchemaEvent
        | FlextLdifModelsEvents.WriteEvent
    )

    class StatisticsSummary(FlextLdifModelsBases.Base):
        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
        total_entries: int = 0
        processed_entries: int = 0
        failed_entries: int = 0
        rejected_entries: int = 0
        success_rate: float = 0.0
        failure_rate: float = 0.0
        rejection_rate: float = 0.0
        schema_entries: int = 0
        data_entries: int = 0
        hierarchy_entries: int = 0
        user_entries: int = 0
        group_entries: int = 0
        acl_entries: int = 0
        acls_extracted: int = 0
        acls_failed: int = 0
        parse_errors: int = 0
        entries_written: int = 0

    class MigrationSummary(FlextLdifModelsBases.Base):
        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
        statistics: FlextLdifModelsResults.StatisticsSummary | None = None
        entry_count: int = 0
        output_files: int = 0
        is_empty: bool = True

    class EntryResult(FlextLdifModelsBases.Base):
        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True, validate_default=True
        )
        entries_by_category: Annotated[
            FlextLdifModelsCollections.FlexibleCategories,
            Field(),
        ] = Field(default_factory=FlextLdifModelsCollections.FlexibleCategories)
        statistics: Annotated[
            FlextLdifModelsResults.Statistics,
            Field(),
        ] = Field(default_factory=lambda: FlextLdifModelsResults._statistics_factory())
        file_paths: Annotated[
            FlextLdifModelsCollections.CategoryPaths,
            Field(),
        ] = Field(default_factory=FlextLdifModelsCollections.CategoryPaths)

        @overload
        def __getitem__(self, key: slice) -> list[FlextLdifModelsDomains.Entry]: ...

        @overload
        def __getitem__(self, key: int) -> FlextLdifModelsDomains.Entry: ...

        def __getitem__(
            self,
            key: int | slice,
        ) -> FlextLdifModelsDomains.Entry | list[FlextLdifModelsDomains.Entry]:
            return self.get_all_entries()[key]

        def __len__(self) -> int:
            return len(self.get_all_entries())

        @property
        def content(self) -> Sequence[FlextLdifModelsDomains.Entry]:
            return self.get_all_entries()

        @property
        def entries(self) -> Sequence[FlextLdifModelsDomains.Entry]:
            return self.get_all_entries()

        @field_validator("entries_by_category", mode="before")
        @classmethod
        def _convert_dict_to_categories(
            cls,
            value: FlextLdifModelsCollections.FlexibleCategories
            | dict[str, list[FlextLdifModelsDomains.Entry]],
        ) -> FlextLdifModelsCollections.FlexibleCategories:
            if isinstance(value, dict):
                result = FlextLdifModelsCollections.FlexibleCategories()
                for cat, entries in value.items():
                    result.add_entries(str(cat), list(entries))
                return result
            return value

        @classmethod
        def empty(cls) -> Self:
            return cls(
                entries_by_category=FlextLdifModelsCollections.FlexibleCategories(),
                statistics=FlextLdifModelsResults.Statistics.for_pipeline(),
            )

        @classmethod
        def from_entries(
            cls,
            entries: Sequence[FlextLdifModelsDomains.Entry],
            category: str = "all",
            statistics: FlextLdifModelsResults.Statistics | None = None,
        ) -> Self:
            entry_list = list(entries)
            stats = statistics or FlextLdifModelsResults.Statistics.for_pipeline(
                total=len(entry_list),
            )
            flex = FlextLdifModelsCollections.FlexibleCategories()
            flex[category] = entry_list
            return cls(entries_by_category=flex, statistics=stats)

        def get_all_entries(self) -> list[FlextLdifModelsDomains.Entry]:
            all_entries: list[FlextLdifModelsDomains.Entry] = []
            for entries in self.entries_by_category.values():
                all_entries.extend(entries)
            return all_entries

        def get_category(
            self,
            category: str,
            default: list[FlextLdifModelsDomains.Entry] | None = None,
        ) -> list[FlextLdifModelsDomains.Entry]:
            if category in self.entries_by_category:
                return self.entries_by_category[category]
            return default if default is not None else []

        def merge(self, other: FlextLdifModelsResults.EntryResult) -> Self:
            merged_categories = FlextLdifModelsCollections.FlexibleCategories()
            for cat, entries in self.entries_by_category.items():
                merged_categories.add_entries(cat, list(entries))
            for cat, entries in other.entries_by_category.items():
                merged_categories.add_entries(cat, list(entries))
            self_stats = (
                self.statistics or FlextLdifModelsResults.Statistics.for_pipeline()
            )
            other_stats = (
                other.statistics or FlextLdifModelsResults.Statistics.for_pipeline()
            )
            merged_stats = self_stats.model_copy(
                update={
                    "total_entries": self_stats.total_entries
                    + other_stats.total_entries,
                },
            )
            merged_paths = FlextLdifModelsCollections.CategoryPaths()
            merged_paths.update(self.file_paths.to_dict())
            merged_paths.update(other.file_paths.to_dict())
            return self.__class__(
                entries_by_category=merged_categories,
                statistics=merged_stats,
                file_paths=merged_paths,
            )

    class Statistics(m.Statistics):
        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True,
            extra="forbid",
            validate_default=True,
            str_strip_whitespace=True,
        )
        total_entries: t.NonNegativeInt = 0
        processed_entries: t.NonNegativeInt = 0
        failed_entries: t.NonNegativeInt = 0
        schema_entries: t.NonNegativeInt = 0
        data_entries: t.NonNegativeInt = 0
        hierarchy_entries: t.NonNegativeInt = 0
        user_entries: t.NonNegativeInt = 0
        group_entries: t.NonNegativeInt = 0
        acl_entries: t.NonNegativeInt = 0
        rejected_entries: t.NonNegativeInt = 0
        schema_attributes: t.NonNegativeInt = 0
        schema_objectclasses: t.NonNegativeInt = 0
        acls_extracted: t.NonNegativeInt = 0
        acls_failed: t.NonNegativeInt = 0
        acl_attribute_name: str | None = None
        parse_errors: t.NonNegativeInt = 0
        detected_server_type: c.Ldif.ServerTypeLiteral | None = None
        entries_written: t.NonNegativeInt = 0
        output_file: str | None = None
        file_size_bytes: t.NonNegativeInt = 0
        encoding: c.Ldif.EncodingLiteral = "utf-8"
        processing_duration: t.NonNegativeFloat = 0.0
        rejection_reasons: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            Field(),
        ] = Field(default_factory=FlextLdifModelsCollections.DynamicCounts)
        events: Annotated[
            list[FlextLdifModelsResults.EventType],
            Field(),
        ] = Field(default_factory=list)

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

        def merge(
            self,
            other: FlextLdifModelsResults.Statistics,
        ) -> FlextLdifModelsResults.Statistics:
            merged_reasons: dict[str, int] = dict(self.rejection_reasons.items())
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
            }
            events_merged: list[FlextLdifModelsResults.EventType] = [
                *self.events,
                *other.events,
            ]
            updates["events"] = events_merged
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

    class MigrationPipelineResult(FlextLdifModelsBases.Base):
        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True, validate_default=True
        )
        migrated_schema: Annotated[
            FlextLdifModelsCollections.SchemaContent,
            Field(),
        ] = Field(default_factory=FlextLdifModelsCollections.SchemaContent)
        entries: Annotated[
            Sequence[FlextLdifModelsDomains.Entry],
            Field(),
        ] = Field(default_factory=tuple)
        stats: Annotated[
            FlextLdifModelsResults.Statistics,
            Field(),
        ] = Field(default_factory=lambda: FlextLdifModelsResults._statistics_factory())
        output_files: Annotated[list[str], Field()] = Field(default_factory=list)

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

    class MigrationComparisonResult(FlextLdifModelsBases.Base):
        """Result of a migration comparison between source and target."""

        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True, validate_default=True
        )
        total_oid: t.NonNegativeInt
        total_target: t.NonNegativeInt
        status: Annotated[str, Field()]
        details: Annotated[str, Field()]
        id: Annotated[str, Field()]
        timestamp: Annotated[str, Field()]
        is_synchronized: Annotated[bool, Field()]

    class MigrationWorkflowResult(FlextLdifModelsBases.Base):
        """Result of a comprehensive migration workflow."""

        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True, validate_default=True
        )
        intermediate_migration: Annotated[str, Field()]
        final_migration: Annotated[str, Field()]
        final_entry_count: t.NonNegativeInt
        source_server_detected: Annotated[str, Field()]
        migration_pipeline: Annotated[str, Field()]
        parallel_processing: Annotated[bool, Field()]
        validation_performed: Annotated[bool, Field()]
        detection_confidence: t.DecimalFraction
        detected_server: Annotated[str, Field()]

    class AutoDetectionResult(FlextLdifModelsBases.Base):
        """Result of an auto-detection migration pipeline."""

        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True, validate_default=True
        )
        detected_server: Annotated[str, Field()]
        confidence: t.DecimalFraction
        patterns_found: Annotated[list[str], Field()] = Field(default_factory=list)
        total_entries: t.NonNegativeInt
        migration_success: Annotated[bool, Field()]

    class ServerComparisonSummary(FlextLdifModelsBases.Base):
        """Summary of batch server comparisons."""

        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True, validate_default=True
        )
        servers_tested: t.NonNegativeInt
        successful_parses: t.NonNegativeInt
        success_rate: t.NonNegativeFloat
        server_results: Annotated[
            dict[str, t.Ldif.MetadataValue],
            Field(),
        ] = Field(default_factory=dict)

    class ClientStatus(m.Value):
        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True, validate_default=True
        )
        status: Annotated[str, Field()]
        services: Annotated[list[str], Field()] = Field(default_factory=list)
        config: Annotated[
            FlextLdifModelsCollections.ConfigSettings,
            Field(),
        ] = Field(default_factory=FlextLdifModelsCollections.ConfigSettings)

    class ValidationResult(FlextLdifModelsBases.Base):
        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True, validate_default=True
        )
        is_valid: Annotated[bool, Field()]
        total_entries: t.NonNegativeInt
        valid_entries: t.NonNegativeInt
        invalid_entries: t.NonNegativeInt
        errors: Annotated[list[str], Field()] = Field(default_factory=list)

        @computed_field
        def success_rate(self) -> float:
            if self.total_entries == 0:
                return 100.0
            return self.valid_entries / self.total_entries * 100.0

    class EntryAnalysisResult(FlextLdifModelsBases.Base):
        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True, validate_default=True
        )
        total_entries: t.NonNegativeInt
        objectclass_distribution: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            Field(),
        ] = Field(default_factory=FlextLdifModelsCollections.DynamicCounts)
        patterns_detected: Annotated[list[str], Field()] = Field(default_factory=list)

        @computed_field
        def unique_objectclasses(self) -> int:
            return len(self.objectclass_distribution)

    class ServerDetectionResult(FlextLdifModelsBases.Base):
        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True, validate_default=True
        )
        detected_server_type: Annotated[c.Ldif.ServerTypeLiteral, Field()]
        confidence: t.DecimalFraction
        scores: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            Field(),
        ] = Field(default_factory=FlextLdifModelsCollections.DynamicCounts)
        patterns_found: Annotated[list[str], Field()] = Field(default_factory=list)
        is_confident: Annotated[bool, Field()]
        detection_error: str | None = None
        fallback_reason: str | None = None

    class StatisticsResult(FlextLdifModelsBases.Base):
        total_entries: Annotated[int, Field()]
        categorized: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            Field(),
        ] = Field(default_factory=FlextLdifModelsCollections.DynamicCounts)
        rejection_rate: Annotated[float, Field()]
        rejection_count: Annotated[int, Field()]
        written_counts: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            Field(),
        ] = Field(default_factory=FlextLdifModelsCollections.DynamicCounts)
        output_files: Annotated[
            FlextLdifModelsCollections.CategoryPaths,
            Field(),
        ] = Field(default_factory=FlextLdifModelsCollections.CategoryPaths)

    class EntriesStatistics(m.Value):
        total_entries: Annotated[int, Field()]
        object_class_distribution: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            Field(),
        ] = Field(default_factory=FlextLdifModelsCollections.DynamicCounts)
        server_type_distribution: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            Field(),
        ] = Field(default_factory=FlextLdifModelsCollections.DynamicCounts)

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

        def items(self) -> list[tuple[str, t.Scalar]]:
            results: list[tuple[str, t.Scalar]] = []
            for key in self.model_fields_set:
                val = getattr(self, key)
                if isinstance(val, t.PRIMITIVES_TYPES):
                    results.append((key, val))
                elif val is None:
                    continue
                else:
                    results.append((key, str(val)))
            return results

        def keys(self) -> list[str]:
            return list(self.model_fields_set)

        def _resolve_key(self, key: str) -> t.NormalizedValue:
            if key in type(self).model_fields:
                return getattr(self, key)
            extra = self.__pydantic_extra__
            if extra is not None and key in extra:
                return extra[key]
            raise KeyError(key)

    class ServiceStatus(DictAccessibleValue):
        service: Annotated[str, Field()]
        status: Annotated[str, Field()]
        rfc_compliance: Annotated[str, Field()]

    class SchemaServiceStatus(DictAccessibleValue):
        service: Annotated[str, Field()]
        server_type: Annotated[c.Ldif.ServerTypeLiteral, Field()]
        status: Annotated[str, Field()]
        rfc_compliance: Annotated[str, Field()]
        operations: Annotated[list[str], Field()]

    class SyntaxServiceStatus(DictAccessibleValue):
        service: Annotated[str, Field()]
        status: Annotated[str, Field()]
        rfc_compliance: Annotated[str, Field()]
        total_syntaxes: Annotated[int, Field()]
        common_syntaxes: Annotated[int, Field()]

    class StatisticsServiceStatus(DictAccessibleValue):
        service: Annotated[str, Field()]
        status: Annotated[str, Field()]
        capabilities: Annotated[list[str], Field()]
        version: Annotated[str, Field()]

    class ValidationServiceStatus(DictAccessibleValue):
        service: Annotated[str, Field()]
        status: Annotated[str, Field()]
        rfc_compliance: Annotated[str, Field()]
        validation_types: Annotated[list[str], Field()]

    class BatchValidationResult(FlextLdifModelsBases.Base):
        valid: Annotated[bool, Field()]
        errors: Annotated[list[str], Field()]
        failed_entries: Annotated[int, Field()]

    class ParsingSummary(FlextLdifModelsBases.Base):
        total_parsed: Annotated[int, Field()]
        total_failed: Annotated[int, Field()]
        error_distribution: Annotated[
            FlextLdifModelsCollections.DynamicCounts,
            Field(),
        ] = Field(default_factory=FlextLdifModelsCollections.DynamicCounts)

    class RdbmsTableSummary(FlextLdifModelsBases.Base):
        table_name: Annotated[str, Field()]
        row_count: Annotated[int, Field()]
        columns: Annotated[list[str], Field()]

    class LdapConversionResult(FlextLdifModelsBases.Base):
        success: Annotated[bool, Field()]
        errors: Annotated[list[str], Field()]
        converted_count: Annotated[int, Field()]

    class RfcValidationResult(FlextLdifModelsBases.Base):
        is_valid: Annotated[bool, Field()]
        violations: Annotated[list[str], Field()]
        validation_types: Annotated[list[str], Field()]

    class ValidationBatchResult(FlextLdifModelsBases.Base):
        results: Annotated[
            FlextLdifModelsCollections.BooleanFlags,
            Field(),
        ] = Field(default_factory=FlextLdifModelsCollections.BooleanFlags)

    class ParseResponse(m.Value):
        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True, validate_default=True
        )
        entries: Annotated[
            Sequence[FlextLdifModelsDomains.Entry],
            Field(),
        ] = Field(default_factory=tuple)
        statistics: Annotated[FlextLdifModelsResults.Statistics, Field()]
        detected_server_type: c.Ldif.ServerTypeLiteral | None = None

        def get_entries(self) -> Sequence[FlextLdifModelsDomains.Entry]:
            return [
                entry
                for entry in self.entries
                if entry.dn is not None and entry.attributes is not None
            ]

    class AclResponse(m.Value):
        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True, validate_default=True
        )
        acls: Annotated[
            Sequence[FlextLdifModelsDomains.Acl],
            Field(),
        ] = Field(default_factory=tuple)
        statistics: Annotated[FlextLdifModelsResults.Statistics, Field()]

    class AclEvaluationResult(m.Value):
        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True, validate_default=True
        )
        granted: bool = False
        matched_acl: FlextLdifModelsDomains.Acl | None = None
        message: str = ""

    class WriteResponse(m.Value):
        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=True, validate_default=True
        )
        content: str | None = None
        statistics: Annotated[FlextLdifModelsResults.Statistics, Field()]

        def get_content(self) -> str:
            return self.content or ""
