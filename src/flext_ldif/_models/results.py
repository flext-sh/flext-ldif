"""Result and response models for LDIF operations.

This module contains result and response models for LDIF processing operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import overload, override

from flext_core import FlextModels
from pydantic import ConfigDict, Field, computed_field

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.events import FlextLdifModelsEvents
from flext_ldif.constants import FlextLdifConstants


class FlextLdifModelsResults:
    """LDIF result and response models container class.

    This class acts as a namespace container for LDIF result and response models.
    All nested classes are accessed via FlextLdifModels.* in the main models.py.
    """

    # Result and response classes will be added here

    class LdifValidationResult(FlextModels.ArbitraryTypesModel):
        """Result of LDIF validation operations."""

        model_config = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
        )

        is_valid: bool = Field(default=False, description="Whether validation passed")
        errors: list[str] = Field(
            default_factory=list,
            description="List of validation errors",
        )
        warnings: list[str] = Field(
            default_factory=list,
            description="List of validation warnings",
        )

        @computed_field
        def error_count(self) -> int:
            """Count of validation errors."""
            return len(self.errors)

        @computed_field
        def warning_count(self) -> int:
            """Count of validation warnings."""
            return len(self.warnings)

        @computed_field
        def total_issues(self) -> int:
            """Total issues (errors + warnings)."""
            # Explicit int cast to help type checker
            errors: int = len(self.errors)
            warnings: int = len(self.warnings)
            return errors + warnings

        @computed_field
        def validation_summary(self) -> str:
            """Get human-readable validation summary."""
            if self.is_valid:
                return f"Valid ({self.warning_count} warnings)"
            return f"Invalid ({self.error_count} errors, {self.warning_count} warnings)"

    class AnalysisResult(FlextModels.ArbitraryTypesModel):
        """Result of LDIF analytics operations."""

        total_entries: int = Field(
            default=0,
            description="Total number of entries analyzed",
        )
        object_class_distribution: dict[str, int] = Field(
            default_factory=dict,
            description="Distribution of object classes",
        )
        patterns_detected: list[str] = Field(
            default_factory=list,
            description="Detected patterns in the data",
        )

        @computed_field
        def unique_object_class_count(self) -> int:
            """Count of unique object classes."""
            return len(self.object_class_distribution)

        @computed_field
        def pattern_count(self) -> int:
            """Count of detected patterns."""
            return len(self.patterns_detected)

        @computed_field
        def most_common_object_class(self) -> str | None:
            """Get the most common object class."""
            if not self.object_class_distribution:
                return None
            return max(
                self.object_class_distribution,
                key=lambda k: self.object_class_distribution.get(k, 0),
            )

        @computed_field
        def analytics_summary(self) -> str:
            """Get human-readable analytics summary."""
            return (
                f"{self.total_entries} entries analyzed, "
                f"{self.unique_object_class_count} unique object classes, "
                f"{self.pattern_count} patterns detected"
            )

    class EntryResult(FlextModels.Value):
        """Result of LDIF processing containing categorized entries and statistics.

        This is the UNIFIED result model for all LDIF operations. Contains entries
        organized by category, comprehensive statistics, and output file paths.

        Immutable value object following DDD patterns.

        Attributes:
            entries_by_category: Entries organized by their categorization
                                (schema, hierarchy, users, groups, acl, data, rejected)
            statistics: Comprehensive execution statistics (counts, durations, reasons)
            file_paths: Output file paths for each category

        """

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        entries_by_category: dict[str, list[FlextLdifModelsDomains.Entry]] = Field(
            default_factory=dict,
            description="Entries organized by category",
        )
        statistics: FlextLdifModelsResults.Statistics | None = Field(
            default=None,
            description="Pipeline execution statistics",
        )
        file_paths: dict[str, str] = Field(
            default_factory=dict,
            description="Output file paths for each category",
        )

        def get_all_entries(self) -> list[FlextLdifModelsDomains.Entry]:
            """Flatten all categories into single list.

            Returns:
                List of all entries from all categories combined.

            """
            all_entries: list[FlextLdifModelsDomains.Entry] = []
            for entries in self.entries_by_category.values():
                all_entries.extend(entries)
            return all_entries

        @property
        def content(self) -> list[FlextLdifModelsDomains.Entry]:
            """Alias for get_all_entries() for backward compatibility.

            Returns:
                List of all entries from all categories combined.

            """
            return self.get_all_entries()

        def __len__(self) -> int:
            """Return the number of entries (makes EntryResult behave like a list)."""
            return len(self.get_all_entries())

        @override
        def __iter__(self) -> Iterator[FlextLdifModelsDomains.Entry]:
            """Iterate over entries (makes EntryResult behave like a list)."""
            return iter(self.get_all_entries())

        @overload
        def __getitem__(self, key: int) -> FlextLdifModelsDomains.Entry: ...

        @overload
        def __getitem__(self, key: slice) -> list[FlextLdifModelsDomains.Entry]: ...

        def __getitem__(
            self,
            key: int | slice,
        ) -> FlextLdifModelsDomains.Entry | list[FlextLdifModelsDomains.Entry]:
            """Get entry by index or slice (makes EntryResult behave like a list)."""
            entries = self.get_all_entries()
            if isinstance(key, int):
                return entries[key]
            return entries[key]

        def get_category(
            self,
            category: str,
            default: list[FlextLdifModelsDomains.Entry] | None = None,
        ) -> list[FlextLdifModelsDomains.Entry]:
            """Get entries from specific category safely.

            Args:
                category: Category name to retrieve
                default: Default value if category not found (defaults to empty list)

            Returns:
                List of entries in the category, or default if not found.

            """
            # If category exists, return it
            if category in self.entries_by_category:
                return self.entries_by_category[category]
            # Otherwise return the default (None defaults to empty list)
            return default if default is not None else []

        @classmethod
        def from_entries(
            cls,
            entries: list[FlextLdifModelsDomains.Entry],
            category: str = "all",
            statistics: FlextLdifModelsResults.Statistics | None = None,
        ) -> FlextLdifModelsResults.EntryResult:
            """Create EntryResult from list of entries.

            Args:
                entries: List of Entry objects
                category: Category name for the entries (default: "all")
                statistics: Optional statistics object (creates default if None)

            Returns:
                New EntryResult instance.

            """
            # Use class reference to avoid type errors
            stats = statistics or FlextLdifModelsResults.Statistics.for_pipeline(
                total=len(entries),
            )
            return cls(
                entries_by_category={category: entries},
                statistics=stats,
            )

        @classmethod
        def empty(cls) -> FlextLdifModelsResults.EntryResult:
            """Create empty EntryResult.

            Returns:
                Empty EntryResult with no entries and default statistics.

            """
            # Use class reference to avoid type errors
            return cls(
                entries_by_category={},
                statistics=FlextLdifModelsResults.Statistics.for_pipeline(),
            )

        def merge(
            self,
            other: FlextLdifModelsResults.EntryResult,
        ) -> FlextLdifModelsResults.EntryResult:
            """Merge two EntryResults.

            Combines entries from both results, with categories merged.
            If same category exists in both, entries are concatenated.
            Statistics are summed for numeric fields.

            Args:
                other: Another EntryResult to merge with this one

            Returns:
                New EntryResult with merged data.

            """
            # Merge categories - concatenate entries for duplicate categories
            merged_categories: dict[str, list[FlextLdifModelsDomains.Entry]] = {
                **self.entries_by_category,
            }
            for cat, entries in other.entries_by_category.items():
                if cat in merged_categories:
                    merged_categories[cat] = list(merged_categories[cat]) + list(
                        entries,
                    )
                else:
                    merged_categories[cat] = list(entries)

            # Merge statistics (sum counters)
            # Handle None statistics by creating defaults
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

            # Merge file paths
            merged_paths = {**self.file_paths, **other.file_paths}

            return self.__class__(
                entries_by_category=merged_categories,
                statistics=merged_stats,
                file_paths=merged_paths,
            )

        # =====================================================================
        # DOMAIN EVENT ACCESS (v1.0.0+)
        # =====================================================================

        @property
        def events(
            self,
        ) -> list[
            FlextLdifModelsEvents.ParseEvent
            | FlextLdifModelsEvents.FilterEvent
            | FlextLdifModelsEvents.CategoryEvent
            | FlextLdifModelsEvents.WriteEvent
            | FlextLdifModelsEvents.AclEvent
            | FlextLdifModelsEvents.DnEvent
            | FlextLdifModelsEvents.MigrationEvent
            | FlextLdifModelsEvents.ConversionEvent
            | FlextLdifModelsEvents.SchemaEvent
        ]:
            """Access domain events from statistics.

            Returns empty list if statistics is None or has no events.
            Provides convenient access to audit trail.

            Returns:
                List of domain events from statistics.events

            Example:
                >>> result = parser.parse(content)
                >>> for event in result.events:
                ...     print(f"{event.timestamp}: {type(event).__name__}")

            """
            return self.statistics.events if self.statistics else []

        @property
        def has_events(self) -> bool:
            """Indicates whether domain events are tracked in this result.

            Returns:
                True if events list is not empty.

            """
            return bool(self.events)

        def add_event(
            self,
            event: (
                FlextLdifModelsEvents.ParseEvent
                | FlextLdifModelsEvents.FilterEvent
                | FlextLdifModelsEvents.CategoryEvent
                | FlextLdifModelsEvents.WriteEvent
                | FlextLdifModelsEvents.AclEvent
                | FlextLdifModelsEvents.DnEvent
                | FlextLdifModelsEvents.MigrationEvent
                | FlextLdifModelsEvents.ConversionEvent
                | FlextLdifModelsEvents.SchemaEvent
            ),
        ) -> FlextLdifModelsResults.EntryResult:
            """Add domain event to result statistics.

            Creates new EntryResult with event added to statistics.events.
            Preserves immutability by returning new instance.

            Args:
                event: Domain event to add to audit trail

            Returns:
                New EntryResult with event added to statistics

            """
            if not self.statistics:
                stats = FlextLdifModelsResults.Statistics.for_pipeline()
            else:
                stats = self.statistics

            updated_stats = stats.add_event(event)

            return self.model_copy(update={"statistics": updated_stats})

        def get_events_by_type(
            self,
            event_type: type,
        ) -> list[
            FlextLdifModelsEvents.ParseEvent
            | FlextLdifModelsEvents.FilterEvent
            | FlextLdifModelsEvents.CategoryEvent
            | FlextLdifModelsEvents.WriteEvent
            | FlextLdifModelsEvents.AclEvent
            | FlextLdifModelsEvents.DnEvent
            | FlextLdifModelsEvents.MigrationEvent
            | FlextLdifModelsEvents.ConversionEvent
            | FlextLdifModelsEvents.SchemaEvent
        ]:
            """Get events filtered by specific event type.

            Args:
                event_type: Event class to filter by (e.g., ParseEvent)

            Returns:
                List of events matching the specified type.

            """
            return [e for e in self.events if isinstance(e, event_type)]

        @property
        def event_count(self) -> int:
            """Get total number of domain events recorded.

            Returns:
                Number of events in the events list.

            """
            return len(self.events)

        @computed_field
        def event_types(self) -> list[str]:
            """Get list of unique event types in history.

            Returns:
                List of event class names (e.g., ["ParseEvent", "FilterEvent"]).

            """
            return list({type(e).__name__ for e in self.events})

    class Statistics(FlextModels.Value):
        """Unified statistics model for all LDIF operations."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        # CORE COUNTERS
        total_entries: int = Field(
            default=0,
            ge=0,
            description="Total entries encountered/processed",
        )
        processed_entries: int = Field(
            default=0,
            ge=0,
            description="Successfully processed entries",
        )
        failed_entries: int = Field(
            default=0,
            ge=0,
            description="Entries that failed processing",
        )

        # CATEGORY COUNTERS
        schema_entries: int = Field(
            default=0,
            ge=0,
            description="Schema entries categorized",
        )
        data_entries: int = Field(
            default=0,
            ge=0,
            description="Data entries (non-schema)",
        )
        hierarchy_entries: int = Field(
            default=0,
            ge=0,
            description="Hierarchy/organizational entries",
        )
        user_entries: int = Field(
            default=0,
            ge=0,
            description="User entries",
        )
        group_entries: int = Field(
            default=0,
            ge=0,
            description="Group entries",
        )
        acl_entries: int = Field(
            default=0,
            ge=0,
            description="ACL entries",
        )
        rejected_entries: int = Field(
            default=0,
            ge=0,
            description="Entries rejected during processing",
        )

        # SCHEMA MIGRATION COUNTERS
        schema_attributes: int = Field(
            default=0,
            ge=0,
            description="Schema attributes migrated",
        )
        schema_objectclasses: int = Field(
            default=0,
            ge=0,
            description="Schema object classes migrated",
        )

        # ACL EXTRACTION COUNTERS
        acls_extracted: int = Field(
            default=0,
            ge=0,
            description="Total ACL objects extracted",
        )
        acls_failed: int = Field(
            default=0,
            ge=0,
            description="ACL parsing failures",
        )
        acl_attribute_name: str | None = Field(
            default=None,
            description="Primary ACL attribute name",
        )

        # PARSING COUNTERS
        parse_errors: int = Field(
            default=0,
            ge=0,
            description="Parse errors encountered",
        )
        detected_server_type: str | None = Field(
            default=None,
            description="Auto-detected LDAP server type",
        )

        # WRITING COUNTERS
        entries_written: int = Field(
            default=0,
            ge=0,
            description="Entries successfully written",
        )
        output_file: str | None = Field(
            default=None,
            description="Output file path",
        )
        file_size_bytes: int = Field(
            default=0,
            ge=0,
            description="Written file size",
        )
        encoding: str = Field(
            default="utf-8",
            description="File encoding used",
        )

        # METADATA
        processing_duration: float = Field(
            default=0.0,
            ge=0.0,
            description="Processing time in seconds",
        )
        rejection_reasons: dict[str, int] = Field(
            default_factory=dict,
            description="Map of rejection reason to count",
        )

        # DOMAIN EVENTS
        events: list[
            FlextLdifModelsEvents.AclEvent
            | FlextLdifModelsEvents.CategoryEvent
            | FlextLdifModelsEvents.ConversionEvent
            | FlextLdifModelsEvents.DnEvent
            | FlextLdifModelsEvents.FilterEvent
            | FlextLdifModelsEvents.MigrationEvent
            | FlextLdifModelsEvents.ParseEvent
            | FlextLdifModelsEvents.SchemaEvent
            | FlextLdifModelsEvents.WriteEvent
        ] = Field(  # Can contain any domain event type
            default_factory=list,
            description="Domain events recorded during processing",
        )

        @computed_field
        def success_rate(self) -> float:
            """Calculate processing success rate as percentage."""
            if self.total_entries == 0:
                return 0.0
            return round((self.processed_entries / self.total_entries) * 100, 2)

        @computed_field
        def failure_rate(self) -> float:
            """Calculate processing failure rate as percentage."""
            if self.total_entries == 0:
                return 0.0
            return round((self.failed_entries / self.total_entries) * 100, 2)

        @computed_field
        def rejection_rate(self) -> float:
            """Calculate rejection rate as percentage."""
            if self.total_entries == 0:
                return 0.0
            return round((self.rejected_entries / self.total_entries) * 100, 2)

        @computed_field
        def summary(self) -> dict[str, object]:
            """Get comprehensive processing summary."""
            return {
                "total_entries": self.total_entries,
                "processed_entries": self.processed_entries,
                "failed_entries": self.failed_entries,
                "rejected_entries": self.rejected_entries,
                "success_rate": self.success_rate,
                "failure_rate": self.failure_rate,
                "rejection_rate": self.rejection_rate,
                "schema_entries": self.schema_entries,
                "data_entries": self.data_entries,
                "hierarchy_entries": self.hierarchy_entries,
                "user_entries": self.user_entries,
                "group_entries": self.group_entries,
                "acl_entries": self.acl_entries,
                "acls_extracted": self.acls_extracted,
                "acls_failed": self.acls_failed,
                "parse_errors": self.parse_errors,
                "entries_written": self.entries_written,
                "processing_duration": self.processing_duration,
                "event_count": len(self.events),
            }

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
            rejection_reasons: dict[str, int] | None = None,
        ) -> FlextLdifModelsResults.Statistics:
            """Create statistics for pipeline operations."""
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
                rejection_reasons=(
                    rejection_reasons if rejection_reasons is not None else {}
                ),
            )

        @classmethod
        def for_parsing(
            cls,
            total: int,
            schema: int = 0,
            data: int = 0,
            errors: int = 0,
            detected_type: str | None = None,
        ) -> FlextLdifModelsResults.Statistics:
            """Create statistics for parsing operations."""
            return cls(
                total_entries=total,
                processed_entries=total - errors,
                failed_entries=errors,
                schema_entries=schema,
                data_entries=data,
                parse_errors=errors,
                detected_server_type=detected_type,
            )

        @classmethod
        def for_writing(
            cls,
            entries_written: int,
            output_file: str | None = None,
            file_size_bytes: int = 0,
            encoding: str = "utf-8",
            processing_duration: float = 0.0,
        ) -> FlextLdifModelsResults.Statistics:
            """Create statistics for writing operations."""
            return cls(
                total_entries=entries_written,
                processed_entries=entries_written,
                entries_written=entries_written,
                output_file=output_file,
                file_size_bytes=file_size_bytes,
                encoding=encoding,
                processing_duration=processing_duration,
            )

        def merge(
            self,
            other: FlextLdifModelsResults.Statistics,
        ) -> FlextLdifModelsResults.Statistics:
            """Merge two Statistics instances."""
            # Merge rejection reasons
            merged_reasons = dict(self.rejection_reasons)
            for reason, count in other.rejection_reasons.items():
                merged_reasons[reason] = merged_reasons.get(reason, 0) + count

            # Merge events
            merged_events = list(self.events) + list(other.events)

            return self.__class__(
                # Core counters
                total_entries=self.total_entries + other.total_entries,
                processed_entries=self.processed_entries + other.processed_entries,
                failed_entries=self.failed_entries + other.failed_entries,
                rejected_entries=self.rejected_entries + other.rejected_entries,
                # Category counters
                schema_entries=self.schema_entries + other.schema_entries,
                data_entries=self.data_entries + other.data_entries,
                hierarchy_entries=self.hierarchy_entries + other.hierarchy_entries,
                user_entries=self.user_entries + other.user_entries,
                group_entries=self.group_entries + other.group_entries,
                acl_entries=self.acl_entries + other.acl_entries,
                # Schema counters
                schema_attributes=self.schema_attributes + other.schema_attributes,
                schema_objectclasses=self.schema_objectclasses
                + other.schema_objectclasses,
                # ACL counters
                acls_extracted=self.acls_extracted + other.acls_extracted,
                acls_failed=self.acls_failed + other.acls_failed,
                acl_attribute_name=self.acl_attribute_name or other.acl_attribute_name,
                # Parsing counters
                parse_errors=self.parse_errors + other.parse_errors,
                detected_server_type=self.detected_server_type
                or other.detected_server_type,
                # Writing counters
                entries_written=self.entries_written + other.entries_written,
                output_file=self.output_file or other.output_file,
                file_size_bytes=self.file_size_bytes + other.file_size_bytes,
                encoding=self.encoding,  # Keep first encoding
                # Metadata
                processing_duration=self.processing_duration
                + other.processing_duration,
                rejection_reasons=merged_reasons,
                events=merged_events,
            )

        def add_event(
            self,
            event: FlextLdifModelsEvents.AclEvent
            | FlextLdifModelsEvents.CategoryEvent
            | FlextLdifModelsEvents.ConversionEvent
            | FlextLdifModelsEvents.DnEvent
            | FlextLdifModelsEvents.FilterEvent
            | FlextLdifModelsEvents.MigrationEvent
            | FlextLdifModelsEvents.ParseEvent
            | FlextLdifModelsEvents.SchemaEvent
            | FlextLdifModelsEvents.WriteEvent,
        ) -> FlextLdifModelsResults.Statistics:
            """Add a domain event to statistics."""
            return self.__class__(
                # Copy all existing fields
                total_entries=self.total_entries,
                processed_entries=self.processed_entries,
                failed_entries=self.failed_entries,
                rejected_entries=self.rejected_entries,
                schema_entries=self.schema_entries,
                data_entries=self.data_entries,
                hierarchy_entries=self.hierarchy_entries,
                user_entries=self.user_entries,
                group_entries=self.group_entries,
                acl_entries=self.acl_entries,
                schema_attributes=self.schema_attributes,
                schema_objectclasses=self.schema_objectclasses,
                acls_extracted=self.acls_extracted,
                acls_failed=self.acls_failed,
                acl_attribute_name=self.acl_attribute_name,
                parse_errors=self.parse_errors,
                detected_server_type=self.detected_server_type,
                entries_written=self.entries_written,
                output_file=self.output_file,
                file_size_bytes=self.file_size_bytes,
                encoding=self.encoding,
                processing_duration=self.processing_duration,
                rejection_reasons=dict(self.rejection_reasons),
                # Add new event to events list
                events=list(self.events) + [event],
            )

    class SchemaBuilderResult(FlextModels.Value):
        """Result of schema builder build() operation.

        Contains attributes, object classes, server type, and metadata about the schema.

        Note: Uses builder-friendly field names (description, required_attributes)
        rather than RFC 4512 names (desc, must, may) for better API usability.

        Attributes:
            attributes: Dict of attribute name to attribute definition
            object_classes: Dict of object class name to object class definition
            server_type: Target LDAP server type identifier
            entry_count: Number of entries in the schema

        """

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
            str_strip_whitespace=True,
        )

        attributes: dict[str, dict[str, object]] = Field(
            default_factory=dict,
            description="Attribute definitions keyed by attribute name",
        )
        object_classes: dict[str, dict[str, object]] = Field(
            default_factory=dict,
            description="Object class definitions keyed by class name",
        )
        server_type: str = Field(
            default="generic",
            min_length=1,
            description="Target LDAP server type (generic, oid, oud, openldap, etc.)",
        )
        entry_count: int = Field(
            default=0,
            ge=0,
            description="Number of entries associated with this schema",
        )

        @computed_field
        def total_attributes(self) -> int:
            """Total number of attributes defined in schema.

            Returns:
                Count of attribute definitions

            """
            return len(self.attributes)

        @computed_field
        def total_object_classes(self) -> int:
            """Total number of object classes defined in schema.

            Returns:
                Count of object class definitions

            """
            return len(self.object_classes)

        @computed_field
        def is_empty(self) -> bool:
            """Check if schema has no attributes or object classes.

            Returns:
                True if schema is empty (no attributes and no object classes)

            """
            attrs_count: int = len(self.attributes)
            obj_classes_count: int = len(self.object_classes)
            return attrs_count == 0 and obj_classes_count == 0

        @computed_field
        def schema_dict(self) -> dict[str, object]:
            """Complete schema containing both attributes and object classes.

            Returns:
                Dict with 'attributes' and 'object_classes' keys

            """
            return {
                "attributes": self.attributes,
                "object_classes": self.object_classes,
            }

        @computed_field
        def schema_summary(self) -> dict[str, int | str]:
            """Summary of schema contents.

            Returns:
                Dict with counts of attributes, object classes, server type, and entries

            """
            return {
                "attributes": self.total_attributes(),
                "object_classes": self.total_object_classes(),
                "server_type": self.server_type,
                "entry_count": self.entry_count,
            }

    class MigrationPipelineResult(FlextModels.Value):
        """Result of migration pipeline execution.

        Contains migrated schema, entries, statistics, and output file paths
        from a complete LDIF migration operation. Immutable value object following
        DDD patterns.

        Attributes:
            migrated_schema: Migrated schema data (attributes and object classes)
            entries: List of migrated directory entries as dicts
            stats: Migration statistics with computed metrics (always present)
            output_files: List of generated output file paths

        """

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        migrated_schema: dict[str, object] = Field(
            default_factory=dict,
            description="Migrated schema data",
        )
        entries: list[object] = Field(
            default_factory=list,
            description="List of migrated directory entries (Entry objects or dicts)",
        )
        stats: dict[str, int] | FlextLdifModelsResults.Statistics = Field(
            default_factory=dict,
            description="Migration statistics and metrics (Statistics or dict)",
        )
        output_files: list[str] = Field(
            default_factory=list,
            description="Generated output file paths",
        )

        @computed_field
        def is_empty(self) -> bool:
            """Check if migration produced no results.

            Returns:
                True if no schema and no entries were migrated

            """
            # Compute directly instead of accessing computed field properties
            # stats can be dict or MigrationStatistics object
            if isinstance(self.stats, dict):
                has_schema = (
                    self.stats.get("total_schema_attributes", 0) > 0
                    or self.stats.get("total_schema_objectclasses", 0) > 0
                )
                has_entries = self.stats.get("total_entries", 0) > 0
            else:
                has_schema = (
                    self.stats.schema_attributes > 0
                    or self.stats.schema_objectclasses > 0
                )
                has_entries = self.stats.total_entries > 0
            return not has_schema and not has_entries

        @computed_field
        def entry_count(self) -> int:
            """Get count of migrated entries.

            Returns:
                Number of entries in entries list

            """
            return len(self.entries)

        @computed_field
        def output_file_count(self) -> int:
            """Get count of generated output files.

            Returns:
                Number of output files produced

            """
            return len(self.output_files)

        @computed_field
        def migration_summary(self) -> dict[str, object]:
            """Comprehensive migration result summary.

            Returns:
                Dict with statistics, entry count, and output file count

            """
            stats_summary = getattr(self.stats, "statistics_summary", self.stats)
            return {
                "statistics": stats_summary,
                "entry_count": self.entry_count,
                "output_files": self.output_file_count,
                "is_empty": self.is_empty,
            }

    class ClientStatus(FlextModels.Value):
        """Client status information."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        status: str = Field(description="Client initialization status")
        services: list[str] = Field(
            default_factory=list,
            description="List of registered service names",
        )
        config: dict[str, object] = Field(
            default_factory=dict,
            description="Active configuration settings",
        )

    class ValidationResult(FlextModels.Value):
        """Entry validation result."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        is_valid: bool = Field(description="Overall validation status")
        total_entries: int = Field(
            ge=0,
            description="Total number of entries validated",
        )
        valid_entries: int = Field(ge=0, description="Number of valid entries")
        invalid_entries: int = Field(ge=0, description="Number of invalid entries")
        errors: list[str] = Field(
            default_factory=list,
            description="List of validation error messages",
        )

        @computed_field
        def success_rate(self) -> float:
            """Calculate validation success rate as percentage."""
            if self.total_entries == 0:
                return 100.0
            return (self.valid_entries / self.total_entries) * 100.0

    class MigrationEntriesResult(FlextModels.Value):
        """Result from migrating entries between servers."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        total_entries: int = Field(ge=0, description="Total number of input entries")
        migrated_entries: int = Field(
            ge=0,
            description="Number of successfully migrated entries",
        )
        from_server: str = Field(description="Source server type")
        to_server: str = Field(description="Target server type")
        success: bool = Field(description="Migration completion status")

        @computed_field
        def migration_rate(self) -> float:
            """Calculate migration success rate as percentage."""
            if self.total_entries == 0:
                return 100.0
            return (self.migrated_entries / self.total_entries) * 100.0

    class EntryAnalysisResult(FlextModels.Value):
        """Result from entry analysis operations."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        total_entries: int = Field(ge=0, description="Total number of entries analyzed")
        objectclass_distribution: dict[str, int] = Field(
            default_factory=dict,
            description="Distribution of object classes",
        )
        patterns_detected: list[str] = Field(
            default_factory=list,
            description="Detected patterns in entries",
        )

        @computed_field
        def unique_objectclasses(self) -> int:
            """Count of unique object classes."""
            return len(self.objectclass_distribution)

    class ServerDetectionResult(FlextModels.Value):
        """Result from LDAP server type detection."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        detected_server_type: str = Field(description="Detected LDAP server type")
        confidence: float = Field(
            ge=0.0,
            le=1.0,
            description="Detection confidence score",
        )
        scores: dict[str, int] = Field(
            default_factory=dict,
            description="Score for each server type",
        )
        patterns_found: list[str] = Field(
            default_factory=list,
            description="List of detected server-specific patterns",
        )
        is_confident: bool = Field(description="Whether confidence meets threshold")
        detection_error: str | None = Field(
            default=None,
            description="Error message if detection failed",
        )
        fallback_reason: str | None = Field(
            default=None,
            description="Reason for fallback to RFC mode",
        )

    class StatisticsResult(FlextModels.Value):
        """Statistics result from LDIF processing pipeline.

        Contains comprehensive statistics about categorized entries, rejections,
        and output files generated during migration.

        Attributes:
            total_entries: Total number of entries processed
            categorized: Count of entries per category
            rejection_rate: Percentage of entries rejected (0.0-1.0)
            rejection_count: Number of rejected entries
            rejection_reasons: List of unique rejection reasons
            written_counts: Count of entries written per category
            output_files: Mapping of categories to output file paths

        """

        total_entries: int = Field(
            description="Total number of entries processed",
        )
        categorized: dict[str, int] = Field(
            description="Count of entries per category",
        )
        rejection_rate: float = Field(
            description="Percentage of entries rejected (0.0-1.0)",
        )
        rejection_count: int = Field(
            description="Number of rejected entries",
        )
        rejection_reasons: list[str] = Field(
            description="List of unique rejection reasons",
        )
        written_counts: dict[str, int] = Field(
            description="Count of entries written per category",
        )
        output_files: dict[str, str] = Field(
            description="Mapping of categories to output file paths",
        )

    class EntriesStatistics(FlextModels.Value):
        """Statistics calculated from a list of Entry models.

        Provides distribution analysis of objectClasses and server types
        across a collection of LDIF entries.

        Attributes:
            total_entries: Total number of entries analyzed
            object_class_distribution: Count of entries per objectClass
            server_type_distribution: Count of entries per server type

        """

        total_entries: int = Field(
            description="Total number of entries analyzed",
        )
        object_class_distribution: dict[str, int] = Field(
            description="Count of entries per objectClass",
        )
        server_type_distribution: dict[str, int] = Field(
            description="Count of entries per server type",
        )

    class DictAccessibleValue(FlextModels.Value):
        """Base value model providing dict-style access (backwards compatibility)."""

        def __getitem__(self, key: str) -> object:
            """Get attribute value by key (dict-style access)."""
            if hasattr(self, key):
                return getattr(self, key)
            raise KeyError(key)

        def __contains__(self, key: str) -> bool:
            """Check if attribute exists (dict-style membership test)."""
            return hasattr(self, key)

        def get(self, key: str, default: object | None = None) -> object | None:
            """Get attribute value with optional default (dict-style access)."""
            return getattr(self, key, default)

        def keys(self) -> list[str]:
            """Return list of attribute keys (dict-style access)."""
            # Use model_fields_set for Pydantic v2 compatibility
            return list(self.model_fields_set)

        def items(self) -> list[tuple[str, object]]:
            """Return list of (key, value) tuples (dict-style access)."""
            # Use model_fields_set for Pydantic v2 compatibility
            return [(key, getattr(self, key)) for key in self.model_fields_set]

    class ServiceStatus(DictAccessibleValue):
        """Generic service status model for execute() health checks.

        Base model for all service health check responses providing
        standard status information across all FLEXT LDIF services.

        Attributes:
            service: Service name identifier
            status: Operational status (e.g., "operational", "degraded")
            rfc_compliance: RFC standards implemented (e.g., "RFC 2849", "RFC 4512")

        """

        service: str = Field(
            description="Service name identifier",
        )
        status: str = Field(
            description="Operational status",
        )
        rfc_compliance: str = Field(
            description="RFC standards implemented by this service",
        )

    class SchemaServiceStatus(DictAccessibleValue):
        """Schema service status with server-specific metadata.

        Extended status model for FlextLdifSchema service including
        server type configuration and available operations.

        Attributes:
            service: Service name identifier
            server_type: Server type configuration (e.g., "oud", "oid", "rfc")
            status: Operational status
            rfc_compliance: RFC 4512 compliance
            operations: List of available schema operations

        """

        service: str = Field(
            description="Service name identifier",
        )
        server_type: str = Field(
            description="Server type configuration",
        )
        status: str = Field(
            description="Operational status",
        )
        rfc_compliance: str = Field(
            description="RFC 4512 compliance",
        )
        operations: list[str] = Field(
            description="List of available schema operations",
        )

    class SyntaxServiceStatus(DictAccessibleValue):
        """Syntax service status with lookup table metadata.

        Extended status model for FlextLdifSyntax service including
        counts of registered syntax OIDs and common syntaxes.

        Attributes:
            service: Service name identifier
            status: Operational status
            rfc_compliance: RFC 4517 compliance
            total_syntaxes: Total number of registered syntax OIDs
            common_syntaxes: Number of commonly used syntax OIDs

        """

        service: str = Field(
            description="Service name identifier",
        )
        status: str = Field(
            description="Operational status",
        )
        rfc_compliance: str = Field(
            description="RFC 4517 compliance",
        )
        total_syntaxes: int = Field(
            description="Total number of registered syntax OIDs",
        )
        common_syntaxes: int = Field(
            description="Number of commonly used syntax OIDs",
        )

    class StatisticsServiceStatus(DictAccessibleValue):
        """Statistics service status with capability metadata.

        Extended status model for FlextLdifStatistics service including
        operational status and available capabilities.

        Attributes:
            service: Service name identifier
            status: Operational status (e.g., "operational", "degraded")
            capabilities: List of available statistical operations
            version: Service version

        """

        service: str = Field(
            description="Service name identifier",
        )
        status: str = Field(
            description="Operational status",
        )
        capabilities: list[str] = Field(
            description="List of available statistical operations",
        )
        version: str = Field(
            description="Service version",
        )

    class SyntaxLookupResult(FlextModels.Value):
        """Result of syntax OID/name lookup operations.

        Contains results from bidirectional OID ↔ name lookups
        performed by FlextLdifSyntax builder pattern.

        Attributes:
            oid_lookup: Resolved name for OID lookup (None if not found or not requested)
            name_lookup: Resolved OID for name lookup (None if not found or not requested)

        """

        oid_lookup: str | None = Field(
            default=None,
            description="Resolved name for OID lookup",
        )
        name_lookup: str | None = Field(
            default=None,
            description="Resolved OID for name lookup",
        )

    class ValidationServiceStatus(DictAccessibleValue):
        """Validation service status with validation type metadata.

        Status model for FlextLdifValidation service including
        list of supported validation types.

        Attributes:
            service: Service name identifier
            status: Operational status
            rfc_compliance: RFC 2849/4512 compliance
            validation_types: List of supported validation types

        """

        service: str = Field(
            description="Service name identifier",
        )
        status: str = Field(
            description="Operational status",
        )
        rfc_compliance: str = Field(
            description="RFC 2849/4512 compliance",
        )
        validation_types: list[str] = Field(
            description="List of supported validation types",
        )

    class ValidationBatchResult(FlextModels.Value):
        """Result of batch validation operations.

        Contains validation results for multiple attribute names
        and objectClass names validated in a single operation.

        Attributes:
            results: Mapping of validated item names to validation status (True=valid, False=invalid)

        """

        results: dict[str, bool] = Field(
            description="Mapping of validated items to validation status",
        )

    class ParseResponse(FlextModels.Value):
        """Composed response from parsing operation.

        Combines Entry models with statistics from parse operation.
        Uses model composition instead of dict intermediaries.
        """

        model_config = ConfigDict(frozen=True, validate_default=True)

        entries: Sequence[FlextLdifModelsDomains.Entry] = Field(
            description="Parsed LDIF entries",
        )
        statistics: FlextLdifModelsResults.Statistics = Field(
            description="Parse operation statistics",
        )
        detected_server_type: str | None = Field(None)

    class AclResponse(FlextModels.Value):
        """Composed response from ACL extraction.

        Combines extracted Acl models with extraction statistics.
        """

        model_config = ConfigDict(frozen=True, validate_default=True)

        acls: Sequence[FlextLdifModelsDomains.Acl] = Field(
            description="Extracted ACL models",
        )
        statistics: FlextLdifModelsResults.Statistics = Field(
            description="ACL extraction statistics",
        )

    class WriteResponse(FlextModels.Value):
        """Composed response from write operation.

        Contains written LDIF content and statistics using model composition.
        """

        model_config = ConfigDict(frozen=True, validate_default=True)

        content: str | None = Field(None, description="Written LDIF content")
        statistics: FlextLdifModelsResults.Statistics = Field(
            description="Write operation statistics",
        )

    class CategorizedEntries(FlextModels.ArbitraryTypesModel):
        """Result of entry categorization by objectClass.

        Categorizes LDIF entries into users, groups, containers, and uncategorized
        based on configurable objectClass sets.

        Example:
            categorized = CategorizedEntries(
                users=[user_entry1, user_entry2],
                groups=[group_entry1],
                containers=[ou_entry1, ou_entry2],
                uncategorized=[],
                summary={"users": 2, "groups": 1, "containers": 2, "uncategorized": 0}
            )

        """

        users: list[FlextLdifModelsDomains.Entry] = Field(
            default_factory=list,
            description="Entries categorized as users (inetOrgPerson, person, etc.)",
        )
        groups: list[FlextLdifModelsDomains.Entry] = Field(
            default_factory=list,
            description=f"Entries categorized as groups ({FlextLdifConstants.ObjectClasses.GROUP_OF_NAMES}, etc.)",
        )
        containers: list[FlextLdifModelsDomains.Entry] = Field(
            default_factory=list,
            description="Entries categorized as containers (organizationalUnit, etc.)",
        )
        uncategorized: list[FlextLdifModelsDomains.Entry] = Field(
            default_factory=list,
            description="Entries that don't match any category",
        )

        @computed_field
        def summary(self) -> dict[str, int]:
            """Get summary of entry counts by category."""
            return {
                "users": len(self.users),
                "groups": len(self.groups),
                "containers": len(self.containers),
                "uncategorized": len(self.uncategorized),
            }

        @computed_field
        def total_entries(self) -> int:
            """Total number of categorized entries."""
            return (
                len(self.users)
                + len(self.groups)
                + len(self.containers)
                + len(self.uncategorized)
            )

        @classmethod
        def create_empty(cls) -> FlextLdifModelsResults.CategorizedEntries:
            """Create an empty CategorizedEntries instance."""
            return cls(
                users=[],
                groups=[],
                containers=[],
                uncategorized=[],
            )

    class SchemaDiscoveryResult(FlextModels.ArbitraryTypesModel):
        """Result of schema discovery operations."""

        attributes: dict[str, dict[str, object]] = Field(
            default_factory=dict,
            description="Discovered attributes with their metadata",
        )
        objectclasses: dict[str, dict[str, object]] = Field(
            default_factory=dict,
            description="Discovered object classes with their metadata",
        )
        total_attributes: int = Field(
            default=0,
            description="Total number of discovered attributes",
        )
        total_objectclasses: int = Field(
            default=0,
            description="Total number of discovered object classes",
        )
        server_type: str = Field(
            default="generic",
            description="Server type for which schema was discovered",
        )
        entry_count: int = Field(
            default=0,
            description="Number of entries used for schema discovery",
        )
        server_info: object = Field(  # Use object instead of Any
            default=None,
            description="LDAP server information from Root DSE",
        )
        servers: object = Field(  # Use object instead of Any
            default=None,
            description="Server-specific quirks and behaviors",
        )
        naming_contexts: list[str] = Field(
            default_factory=list,
            description="Naming contexts (suffixes) available on server",
        )
        supported_controls: list[str] = Field(
            default_factory=list,
            description="LDAP controls supported by server",
        )
        supported_extensions: list[str] = Field(
            default_factory=list,
            description="LDAP extensions supported by server",
        )

        @computed_field
        def discovery_ratio(self) -> float:
            """Calculate discovery ratio (attributes per entry)."""
            if self.entry_count == 0:
                return 0.0
            return self.total_attributes / self.entry_count

        @computed_field
        def schema_completeness(self) -> float:
            """Calculate schema completeness score (0-100).

            Based on:
            - Attribute discovery density
            - ObjectClass coverage
            - Entry sample size
            """
            if self.entry_count == 0:
                return 0.0

            # Normalize components
            attr_density = min(self.total_attributes / 50, 1.0)  # Cap at 50 attrs
            oc_coverage = min(self.total_objectclasses / 10, 1.0)  # Cap at 10 OCs
            sample_size = min(self.entry_count / 1000, 1.0)  # Cap at 1000 entries

            # Weighted average
            completeness = (
                attr_density * 0.5 + oc_coverage * 0.3 + sample_size * 0.2
            ) * 100
            return round(completeness, 2)

        @computed_field
        def discovery_summary(self) -> str:
            """Get human-readable discovery summary."""
            return (
                f"Discovered {self.total_attributes} attributes and "
                f"{self.total_objectclasses} object classes from "
                f"{self.entry_count} entries ({self.server_type})"
            )
