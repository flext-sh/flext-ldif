from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from typing import overload

from flext_core._models.collections import FlextModelsCollections
from flext_core._models.entity import FlextModelsEntity
from pydantic import ConfigDict, Field, computed_field, field_validator

from flext_ldif._models.base import FlextLdifModelsBase
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.events import FlextLdifModelsEvents
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif.constants import c
from flext_ldif.typings import t


class DynamicCounts(FlextLdifModelsBase):
    model_config = ConfigDict(
        frozen=False,
        extra="allow",
        use_enum_values=True,
        str_strip_whitespace=True,
    )

    def set_count(self, key: str, value: int) -> None:
        setattr(self, key, value)

    def __getitem__(self, key: str) -> int:
        extra = self.__pydantic_extra__
        if extra is not None and key in extra:
            v = extra[key]
            return int(v) if isinstance(v, (int, float)) else 0
        msg = f"Key {key!r} not found"
        raise KeyError(msg)

    def get(self, key: str, default: int | None = None) -> int | None:
        extra = self.__pydantic_extra__
        if extra is not None and key in extra:
            v = extra[key]
            return int(v) if isinstance(v, (int, float)) else 0
        return default

    def __contains__(self, key: object) -> bool:
        extra = self.__pydantic_extra__
        return extra is not None and key in extra

    def __len__(self) -> int:
        extra = self.__pydantic_extra__
        return len(extra) if extra is not None else 0

    def items(self) -> list[tuple[str, int]]:
        extra = self.__pydantic_extra__
        if extra is None:
            return []
        return [
            (k, int(v) if isinstance(v, (int, float)) else 0) for k, v in extra.items()
        ]

    def __eq__(self, other: object) -> bool:
        if isinstance(other, dict):
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
        extra = self.__pydantic_extra__
        if extra is None or len(extra) == 0:
            return None
        return max(
            extra,
            key=lambda k: (
                int(extra.get(k, 0)) if isinstance(extra.get(k, 0), (int, float)) else 0
            ),
        )


class _SchemaContent(FlextLdifModelsBase):
    model_config = ConfigDict(frozen=True)
    attributes: Sequence[FlextLdifModelsDomains.SchemaAttribute] = Field(
        default_factory=list
    )
    object_classes: Sequence[FlextLdifModelsDomains.SchemaObjectClass] = Field(
        default_factory=list
    )


class _CategoryPaths(FlextLdifModelsMetadata.DynamicMetadata):
    """Category to file path mapping model (replaces dict[str, str])."""


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

    def __eq__(self, other: object) -> bool:
        if isinstance(other, dict):
            extra = self.__pydantic_extra__
            if extra is None:
                return other == {}
            return dict(extra) == other
        if isinstance(other, _BooleanFlags):
            return self.__pydantic_extra__ == other.__pydantic_extra__
        return NotImplemented

    def __hash__(self) -> int:
        extra = self.__pydantic_extra__
        if extra is None:
            return hash(())
        return hash(tuple(sorted(extra.items())))


class _FlexibleCategories(
    FlextModelsCollections.Categories[FlextLdifModelsDomains.Entry],
):
    model_config = ConfigDict(extra="allow", frozen=False)

    def __hash__(self) -> int:
        class_name = self.__class__.__name__
        msg = f"{class_name} is unhashable"
        raise TypeError(msg)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _FlexibleCategories):
            return self.categories == other.categories
        if isinstance(other, FlextModelsCollections.Categories):
            return self.categories == other.categories
        if isinstance(other, dict):
            return self.categories == other
        return False

    def items(self) -> Iterator[tuple[str, list[FlextLdifModelsDomains.Entry]]]:
        return iter(self.categories.items())

    def values(self) -> Iterator[list[FlextLdifModelsDomains.Entry]]:
        return iter(self.categories.values())

    def keys(self) -> Iterator[str]:
        return iter(self.categories.keys())

    def __contains__(self, category: str) -> bool:
        return category in self.categories

    def __getitem__(self, category: str) -> list[FlextLdifModelsDomains.Entry]:
        return self.categories[category]

    def __setitem__(
        self,
        category: str,
        entries: list[FlextLdifModelsDomains.Entry],
    ) -> None:
        self.categories[category] = entries


type _DynCategoriesInput = dict[str, list[FlextLdifModelsDomains.Entry]]


def _statistics_factory() -> FlextLdifModelsResults.Statistics:
    return FlextLdifModelsResults.Statistics()


class FlextLdifModelsResults:
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
        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )
        entries_by_category: _FlexibleCategories = Field(
            default_factory=_FlexibleCategories
        )
        statistics: FlextLdifModelsResults.Statistics = Field(
            default_factory=_statistics_factory
        )
        file_paths: _CategoryPaths = Field(default_factory=_CategoryPaths)

        @field_validator("entries_by_category", mode="before")
        @classmethod
        def _convert_dict_to_categories(
            cls,
            value: _FlexibleCategories
            | FlextModelsCollections.Categories[FlextLdifModelsDomains.Entry]
            | _DynCategoriesInput,
        ) -> _FlexibleCategories:
            if isinstance(value, _FlexibleCategories):
                return value
            if isinstance(value, FlextModelsCollections.Categories):
                result = _FlexibleCategories()
                for cat, entries in value.categories.items():
                    result.add_entries(cat, list(entries))
                return result
            if isinstance(value, dict):
                result = _FlexibleCategories()
                for cat, entries in value.items():
                    result.add_entries(str(cat), list(entries))
                return result
            return _FlexibleCategories()

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
            entries = self.get_all_entries()
            if isinstance(key, int):
                return entries[key]
            return entries[key]

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
            return cls(
                entries_by_category=flex,
                statistics=stats,
            )

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

    class Statistics(FlextModelsCollections.Statistics):
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
                field_name: getattr(self, field_name)
                for field_name in FlextLdifModelsResults.StatisticsSummary.model_fields
                if hasattr(self, field_name)
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
            updates: dict[str, t.GeneralValueType] = {
                field_name: getattr(self, field_name) + getattr(other, field_name)
                for field_name in sum_fields
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
        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )
        migrated_schema: _SchemaContent = Field(default_factory=_SchemaContent)
        entries: Sequence[FlextLdifModelsDomains.Entry] = Field(default_factory=list)
        stats: FlextLdifModelsResults.Statistics = Field(
            default_factory=_statistics_factory
        )
        output_files: list[str] = Field(default_factory=list)

        @computed_field
        def is_empty(self) -> bool:
            has_schema = (
                self.stats.schema_attributes > 0 or self.stats.schema_objectclasses > 0
            )
            has_entries = self.stats.total_entries > 0
            return not has_schema and not has_entries

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
                is_empty=not (
                    self.stats.schema_attributes > 0
                    or self.stats.schema_objectclasses > 0
                    or self.stats.total_entries > 0
                ),
            )

    class ClientStatus(FlextModelsEntity.Value):
        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )
        status: str = Field()
        services: list[str] = Field(default_factory=list)
        config: _ConfigSettings = Field(default_factory=_ConfigSettings)

    class ValidationResult(FlextLdifModelsBase):
        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )
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
        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )
        total_entries: int = Field(ge=0)
        objectclass_distribution: DynamicCounts = Field(default_factory=DynamicCounts)
        patterns_detected: list[str] = Field(default_factory=list)

        @computed_field
        def unique_objectclasses(self) -> int:
            return len(self.objectclass_distribution)

    class ServerDetectionResult(FlextLdifModelsBase):
        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )
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

    class EntriesStatistics(FlextModelsEntity.Value):
        total_entries: int = Field()
        object_class_distribution: DynamicCounts = Field(default_factory=DynamicCounts)
        server_type_distribution: DynamicCounts = Field(default_factory=DynamicCounts)

    class DictAccessibleValue(FlextModelsEntity.Value):
        def __getitem__(self, key: str) -> str | int | float | bool | None:
            if hasattr(self, key):
                value = getattr(self, key)
                if isinstance(value, (str, int, float, bool, type(None))):
                    return value
                return str(value) if value is not None else None
            raise KeyError(key)

        def __contains__(self, key: str) -> bool:
            return hasattr(self, key)

        def get(
            self,
            key: str,
            default: str | float | bool | None = None,
        ) -> str | int | float | bool | None:
            return getattr(self, key, default)

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

    class ParseResponse(FlextModelsEntity.Value):
        model_config = ConfigDict(frozen=True, validate_default=True)
        entries: Sequence[FlextLdifModelsDomains.Entry] = Field(default_factory=list)
        statistics: FlextLdifModelsResults.Statistics = Field()
        detected_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = None

        def get_entries(self) -> Sequence[FlextLdifModelsDomains.Entry]:
            converted_entries: list[FlextLdifModelsDomains.Entry] = []
            for entry in self.entries:
                if entry.dn is None:
                    continue
                if entry.attributes is None:
                    continue
                dn_value = (
                    entry.dn.value if hasattr(entry.dn, "value") else str(entry.dn)
                )
                attrs_dict: dict[str, list[str]] = {}
                if hasattr(entry.attributes, "attributes"):
                    raw_attrs = entry.attributes.attributes
                    if isinstance(raw_attrs, dict):
                        for k, v in raw_attrs.items():
                            if isinstance(k, str) and isinstance(v, list):
                                attrs_dict[str(k)] = [
                                    str(x) for x in v if x is not None
                                ]
                elif isinstance(entry.attributes, Mapping):
                    for k, v in entry.attributes.items():
                        if isinstance(k, str) and isinstance(v, list):
                            attrs_dict[str(k)] = [str(x) for x in v if x is not None]
                converted_entries.append(
                    FlextLdifModelsDomains.Entry(
                        dn=FlextLdifModelsDomains.DN(value=dn_value),
                        attributes=FlextLdifModelsDomains.Attributes(
                            attributes=attrs_dict,
                        ),
                    ),
                )
            return converted_entries

    class AclResponse(FlextModelsEntity.Value):
        model_config = ConfigDict(frozen=True, validate_default=True)
        acls: list[FlextLdifModelsDomains.Acl] = Field(default_factory=list)
        statistics: FlextLdifModelsResults.Statistics = Field()

    class AclEvaluationResult(FlextModelsEntity.Value):
        model_config = ConfigDict(frozen=True, validate_default=True)
        granted: bool = False
        matched_acl: FlextLdifModelsDomains.Acl | None = None
        message: str = ""

    class WriteResponse(FlextModelsEntity.Value):
        model_config = ConfigDict(frozen=True, validate_default=True)
        content: str | None = None
        statistics: FlextLdifModelsResults.Statistics = Field()

        def get_content(self) -> str:
            return self.content or ""
