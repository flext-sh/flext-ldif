from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import overload, override

from flext_core import m
from pydantic import ConfigDict, Field, computed_field, field_validator

from flext_ldif import c, t
from flext_ldif._models.base import FlextLdifModelsBase
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.events import FlextLdifModelsEvents
from flext_ldif._models.metadata import FlextLdifModelsMetadata


class DynamicCounts(FlextLdifModelsBase):
    model_config = ConfigDict(
        frozen=False,
        extra="allow",
        use_enum_values=True,
        str_strip_whitespace=True,
    )

    def set_count(self, key: str, value: int) -> None:
        setattr(self, key, value)

    @staticmethod
    def _to_count(value: t.MetadataAttributeValue) -> int:
        if isinstance(value, int | float):
            return int(value)
        if isinstance(value, str):
            try:
                return int(float(value))
            except (ValueError, TypeError):
                return 0
        return 0

    def __getitem__(self, key: str) -> int:
        extra = self._extra()
        if key in extra:
            return self._to_count(extra[key])
        msg = f"Key {key!r} not found"
        raise KeyError(msg)

    def _extra(self) -> dict[str, t.MetadataAttributeValue]:
        return self.__pydantic_extra__ or {}

    def get(self, key: str, default: int | None = None) -> int | None:
        extra = self._extra()
        if key in extra:
            return self._to_count(extra[key])
        return default

    def __contains__(self, key: str) -> bool:
        return key in self._extra()

    def __len__(self) -> int:
        return len(self._extra())

    def items(self) -> list[tuple[str, int]]:
        extra = self._extra()
        return [(k, self._to_count(v)) for k, v in extra.items()]

    @override
    def __eq__(self, other: object) -> bool:
        if other.__class__ is dict:
            self_dict = {
                key: value
                for key, value in self.__dict__.items()
                if not key.startswith("_")
            }
            extra = self.__pydantic_extra__
            if extra is not None:
                self_dict.update(extra)
            return self_dict == other
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(id(self))

    def max_key(self) -> str | None:
        extra = self._extra()
        if not extra:
            return None
        return max(extra, key=lambda k: self._to_count(extra.get(k, 0)))


class _SchemaContent(FlextLdifModelsBase):
    model_config = ConfigDict(frozen=True)
    attributes: Sequence[FlextLdifModelsDomains.SchemaAttribute] = Field(
        default_factory=list,
    )
    object_classes: Sequence[FlextLdifModelsDomains.SchemaObjectClass] = Field(
        default_factory=list,
    )


class _CategoryPaths(FlextLdifModelsMetadata.DynamicMetadata):
    """Category to file path mapping model."""


class _ConfigSettings(FlextLdifModelsMetadata.DynamicMetadata):
    def set_setting(self, key: str, value: str | int | bool) -> None:
        self[key] = value


class _BooleanFlags(FlextLdifModelsBase):
    model_config = ConfigDict(
        frozen=True,
        extra="allow",
        use_enum_values=True,
        str_strip_whitespace=True,
    )

    def __getitem__(self, key: str) -> bool:
        extra = self.__pydantic_extra__
        if extra is None or key not in extra:
            msg = f"Key '{key}' not found in flags"
            raise KeyError(msg)
        return bool(extra[key])

    @override
    @override
    def __eq__(self, other: object) -> bool:
        if isinstance(other, dict):
            extra = self.model_extra
            return (extra or {}) == other
        if isinstance(other, self.__class__):
            return self.model_extra == other.model_extra
        return NotImplemented

    def __hash__(self) -> int:
        extra = self.__pydantic_extra__
        if extra is None:
            return hash(())
        return hash(tuple(sorted(extra.items())))


class _FlexibleCategories(m.Collections.Categories):
    model_config = ConfigDict(extra="allow", frozen=False)

    def __hash__(self) -> int:
        msg = f"{self.__class__.__name__} is unhashable"
        raise TypeError(msg)

    @override
    def __eq__(self, other: object) -> bool:
        if isinstance(other, self.__class__):
            return self.categories == other.categories
        if isinstance(other, dict):
            return self.categories == other
        return False

    def items(self) -> Iterator[tuple[str, list[FlextLdifModelsDomains.Entry]]]:
        for category, values in self.categories.items():
            yield (
                category,
                [FlextLdifModelsDomains.Entry.model_validate(v) for v in values],
            )

    def values(self) -> Iterator[list[FlextLdifModelsDomains.Entry]]:
        for values in self.categories.values():
            yield [FlextLdifModelsDomains.Entry.model_validate(v) for v in values]

    def keys(self) -> Iterator[str]:
        return iter(self.categories.keys())

    def __contains__(self, category: str) -> bool:
        return category in self.categories

    def __getitem__(self, category: str) -> list[FlextLdifModelsDomains.Entry]:
        return [
            FlextLdifModelsDomains.Entry.model_validate(v)
            for v in self.categories[category]
        ]

    def __setitem__(
        self,
        category: str,
        entries: Sequence[FlextLdifModelsDomains.Entry],
    ) -> None:
        self.categories[category] = list(entries)


type _DynCategoriesInput = dict[str, list[FlextLdifModelsDomains.Entry]]


class FlextLdifModelsResults:
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
    FlexibleCategories = _FlexibleCategories
    CategoryPaths = _CategoryPaths
    DynamicCounts = DynamicCounts
    SchemaContent = _SchemaContent
    ConfigSettings = _ConfigSettings
    BooleanFlags = _BooleanFlags

    class StatisticsSummary(FlextLdifModelsBase):
        model_config = ConfigDict(frozen=True)
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

    class MigrationSummary(FlextLdifModelsBase):
        model_config = ConfigDict(frozen=True)
        statistics: FlextLdifModelsResults.StatisticsSummary | None = None
        entry_count: int = 0
        output_files: int = 0
        is_empty: bool = True

    class EntryResult(FlextLdifModelsBase):
        model_config = ConfigDict(frozen=True, validate_default=True)
        entries_by_category: _FlexibleCategories = Field(
            default_factory=_FlexibleCategories,
        )
        statistics: FlextLdifModelsResults.Statistics = Field(
            default_factory=lambda: FlextLdifModelsResults._statistics_factory(),
        )
        file_paths: _CategoryPaths = Field(default_factory=_CategoryPaths)

        @field_validator("entries_by_category", mode="before")
        @classmethod
        def _convert_dict_to_categories(
            cls,
            value: _FlexibleCategories | _DynCategoriesInput,
        ) -> _FlexibleCategories:
            if isinstance(value, dict):
                result = _FlexibleCategories()
                for cat, entries in value.items():
                    result.add_entries(str(cat), list(entries))
                return result
            return value

        def get_all_entries(self) -> list[FlextLdifModelsDomains.Entry]:
            all_entries: list[FlextLdifModelsDomains.Entry] = []
            for entries in self.entries_by_category.values():
                all_entries.extend(entries)
            return all_entries

        @property
        def content(self) -> Sequence[FlextLdifModelsDomains.Entry]:
            return self.get_all_entries()

        @property
        def entries(self) -> Sequence[FlextLdifModelsDomains.Entry]:
            return self.get_all_entries()

        def __len__(self) -> int:
            return len(self.get_all_entries())

        @overload
        def __getitem__(self, key: slice) -> list[FlextLdifModelsDomains.Entry]: ...
        @overload
        def __getitem__(self, key: int) -> FlextLdifModelsDomains.Entry: ...
        def __getitem__(
            self,
            key: int | slice,
        ) -> FlextLdifModelsDomains.Entry | list[FlextLdifModelsDomains.Entry]:
            return self.get_all_entries()[key]

        def get_category(
            self,
            category: str,
            default: list[FlextLdifModelsDomains.Entry] | None = None,
        ) -> list[FlextLdifModelsDomains.Entry]:
            if category in self.entries_by_category:
                return self.entries_by_category[category]
            return default if default is not None else []

        @classmethod
        def from_entries(
            cls,
            entries: Sequence[FlextLdifModelsDomains.Entry],
            category: str = "all",
            statistics: FlextLdifModelsResults.Statistics | None = None,
        ) -> FlextLdifModelsResults.EntryResult:
            entry_list = list(entries)
            stats = statistics or FlextLdifModelsResults.Statistics.for_pipeline(
                total=len(entry_list),
            )
            flex = _FlexibleCategories()
            flex[category] = entry_list
            return cls(entries_by_category=flex, statistics=stats)

        @classmethod
        def empty(cls) -> FlextLdifModelsResults.EntryResult:
            return cls(
                entries_by_category=_FlexibleCategories(),
                statistics=FlextLdifModelsResults.Statistics.for_pipeline(),
            )

        def merge(
            self,
            other: FlextLdifModelsResults.EntryResult,
        ) -> FlextLdifModelsResults.EntryResult:
            merged_categories = _FlexibleCategories()
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
            merged_paths = _CategoryPaths()
            merged_paths.update(self.file_paths.to_dict())
            merged_paths.update(other.file_paths.to_dict())
            return self.__class__(
                entries_by_category=merged_categories,
                statistics=merged_stats,
                file_paths=merged_paths,
            )

    class Statistics(m.Collections.Statistics):
        model_config = ConfigDict(
            frozen=True,
            extra="forbid",
            validate_default=True,
            str_strip_whitespace=True,
        )
        total_entries: int = Field(default=0, ge=0)
        processed_entries: int = Field(default=0, ge=0)
        failed_entries: int = Field(default=0, ge=0)
        schema_entries: int = Field(default=0, ge=0)
        data_entries: int = Field(default=0, ge=0)
        hierarchy_entries: int = Field(default=0, ge=0)
        user_entries: int = Field(default=0, ge=0)
        group_entries: int = Field(default=0, ge=0)
        acl_entries: int = Field(default=0, ge=0)
        rejected_entries: int = Field(default=0, ge=0)
        schema_attributes: int = Field(default=0, ge=0)
        schema_objectclasses: int = Field(default=0, ge=0)
        acls_extracted: int = Field(default=0, ge=0)
        acls_failed: int = Field(default=0, ge=0)
        acl_attribute_name: str | None = None
        parse_errors: int = Field(default=0, ge=0)
        detected_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = None
        entries_written: int = Field(default=0, ge=0)
        output_file: str | None = None
        file_size_bytes: int = Field(default=0, ge=0)
        encoding: c.Ldif.LiteralTypes.EncodingLiteral = "utf-8"
        processing_duration: float = Field(default=0.0, ge=0.0)
        rejection_reasons: DynamicCounts = Field(default_factory=DynamicCounts)
        events: list[FlextLdifModelsResults.EventType] = Field(default_factory=list)

        def _rate(self, numerator: int) -> float:
            return (
                round((numerator / self.total_entries) * 100, 2)
                if self.total_entries
                else 0.0
            )

        @computed_field
        def success_rate(self) -> float:
            return self._rate(self.processed_entries)

        @computed_field
        def failure_rate(self) -> float:
            return self._rate(self.failed_entries)

        @computed_field
        def rejection_rate(self) -> float:
            return self._rate(self.rejected_entries)

        @computed_field
        def summary(self) -> FlextLdifModelsResults.StatisticsSummary:
            return self.to_summary()

        def to_summary(self) -> FlextLdifModelsResults.StatisticsSummary:
            fields = {
                name: getattr(self, name)
                for name in FlextLdifModelsResults.StatisticsSummary.model_fields
            }
            return FlextLdifModelsResults.StatisticsSummary(**fields)

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
            rejection_reasons: DynamicCounts | None = None,
        ) -> FlextLdifModelsResults.Statistics:
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
                rejection_reasons=rejection_reasons or DynamicCounts(),
            )

        def merge(
            self,
            other: FlextLdifModelsResults.Statistics,
        ) -> FlextLdifModelsResults.Statistics:
            merged_reasons = dict(self.rejection_reasons)
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
                "rejection_reasons": DynamicCounts(**merged_reasons),
                "events": [*self.events, *other.events],
            }
            return self.model_copy(update=updates)

    class MigrationPipelineResult(FlextLdifModelsBase):
        model_config = ConfigDict(frozen=True, validate_default=True)
        migrated_schema: _SchemaContent = Field(default_factory=_SchemaContent)
        entries: Sequence[FlextLdifModelsDomains.Entry] = Field(default_factory=list)
        stats: FlextLdifModelsResults.Statistics = Field(
            default_factory=lambda: FlextLdifModelsResults._statistics_factory(),
        )
        output_files: list[str] = Field(default_factory=list)

        @computed_field
        def is_empty(self) -> bool:
            has_schema = (
                self.stats.schema_attributes > 0 or self.stats.schema_objectclasses > 0
            )
            return not has_schema and self.stats.total_entries == 0

        @computed_field
        def entry_count(self) -> int:
            return len(self.entries)

        @computed_field
        def output_file_count(self) -> int:
            return len(self.output_files)

        @computed_field
        def migration_summary(self) -> FlextLdifModelsResults.MigrationSummary:
            return FlextLdifModelsResults.MigrationSummary(
                statistics=self.stats.to_summary(),
                entry_count=len(self.entries),
                output_files=len(self.output_files),
                is_empty=self.is_empty,  # computed_field, accessed as property
            )

    class ClientStatus(m.EntityModels.Value):
        model_config = ConfigDict(frozen=True, validate_default=True)
        status: str = Field()
        services: list[str] = Field(default_factory=list)
        config: _ConfigSettings = Field(default_factory=_ConfigSettings)

    class ValidationResult(FlextLdifModelsBase):
        model_config = ConfigDict(frozen=True, validate_default=True)
        is_valid: bool = Field()
        total_entries: int = Field(ge=0)
        valid_entries: int = Field(ge=0)
        invalid_entries: int = Field(ge=0)
        errors: list[str] = Field(default_factory=list)

        @computed_field
        def success_rate(self) -> float:
            if self.total_entries == 0:
                return 100.0
            return (self.valid_entries / self.total_entries) * 100.0

    class EntryAnalysisResult(FlextLdifModelsBase):
        model_config = ConfigDict(frozen=True, validate_default=True)
        total_entries: int = Field(ge=0)
        objectclass_distribution: DynamicCounts = Field(default_factory=DynamicCounts)
        patterns_detected: list[str] = Field(default_factory=list)

        @computed_field
        def unique_objectclasses(self) -> int:
            return len(self.objectclass_distribution)

    class ServerDetectionResult(FlextLdifModelsBase):
        model_config = ConfigDict(frozen=True, validate_default=True)
        detected_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field()
        confidence: float = Field(ge=0.0, le=1.0)
        scores: DynamicCounts = Field(default_factory=DynamicCounts)
        patterns_found: list[str] = Field(default_factory=list)
        is_confident: bool = Field()
        detection_error: str | None = None
        fallback_reason: str | None = None

    class StatisticsResult(FlextLdifModelsBase):
        total_entries: int = Field()
        categorized: DynamicCounts = Field(default_factory=DynamicCounts)
        rejection_rate: float = Field()
        rejection_count: int = Field()
        rejection_reasons: list[str] = Field()
        written_counts: DynamicCounts = Field(default_factory=DynamicCounts)
        output_files: _CategoryPaths = Field(default_factory=_CategoryPaths)

    class EntriesStatistics(m.EntityModels.Value):
        total_entries: int = Field()
        object_class_distribution: DynamicCounts = Field(default_factory=DynamicCounts)
        server_type_distribution: DynamicCounts = Field(default_factory=DynamicCounts)

    class DictAccessibleValue(m.EntityModels.Value):
        def _resolve_key(self, key: str) -> t.ConfigMapValue:
            if key in type(self).model_fields:
                return getattr(self, key)
            extra = self.__pydantic_extra__
            if extra is not None and key in extra:
                return extra[key]
            raise KeyError(key)

        def __getitem__(self, key: str) -> str | int | float | bool | None:
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
        ) -> str | int | float | bool | None:
            try:
                return self[key]
            except KeyError:
                return default

        def keys(self) -> list[str]:
            return list(self.model_fields_set)

        def items(self) -> list[tuple[str, t.ScalarValue]]:
            return [(key, getattr(self, key)) for key in self.model_fields_set]

    class ServiceStatus(DictAccessibleValue):
        service: str = Field()
        status: str = Field()
        rfc_compliance: str = Field()

    class SchemaServiceStatus(DictAccessibleValue):
        service: str = Field()
        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field()
        status: str = Field()
        rfc_compliance: str = Field()
        operations: list[str] = Field()

    class SyntaxServiceStatus(DictAccessibleValue):
        service: str = Field()
        status: str = Field()
        rfc_compliance: str = Field()
        total_syntaxes: int = Field()
        common_syntaxes: int = Field()

    class StatisticsServiceStatus(DictAccessibleValue):
        service: str = Field()
        status: str = Field()
        capabilities: list[str] = Field()
        version: str = Field()

    class ValidationServiceStatus(DictAccessibleValue):
        service: str = Field()
        status: str = Field()
        rfc_compliance: str = Field()
        validation_types: list[str] = Field()

    class ValidationBatchResult(FlextLdifModelsBase):
        results: _BooleanFlags = Field(default_factory=_BooleanFlags)

    class ParseResponse(m.EntityModels.Value):
        model_config = ConfigDict(frozen=True, validate_default=True)
        entries: Sequence[FlextLdifModelsDomains.Entry] = Field(default_factory=list)
        statistics: FlextLdifModelsResults.Statistics = Field()
        detected_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = None

        def get_entries(self) -> Sequence[FlextLdifModelsDomains.Entry]:
            return [
                entry
                for entry in self.entries
                if entry.dn is not None and entry.attributes is not None
            ]

    class AclResponse(m.EntityModels.Value):
        model_config = ConfigDict(frozen=True, validate_default=True)
        acls: list[FlextLdifModelsDomains.Acl] = Field(default_factory=list)
        statistics: FlextLdifModelsResults.Statistics = Field()

    class AclEvaluationResult(m.EntityModels.Value):
        model_config = ConfigDict(frozen=True, validate_default=True)
        granted: bool = False
        matched_acl: FlextLdifModelsDomains.Acl | None = None
        message: str = ""

    class WriteResponse(m.EntityModels.Value):
        model_config = ConfigDict(frozen=True, validate_default=True)
        content: str | None = None
        statistics: FlextLdifModelsResults.Statistics = Field()

        def get_content(self) -> str:
            return self.content or ""
