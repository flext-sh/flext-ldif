"""Result and response models for LDIF operations.

This module contains result and response models for LDIF processing operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from typing import overload

from flext_core._models.base import FlextModelsBase
from flext_core._models.collections import FlextModelsCollections
from flext_core._models.entity import FlextModelsEntity
from pydantic import ConfigDict, Field, computed_field, field_validator

from flext_ldif._models.base import FlextLdifModelsBase
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.events import FlextLdifModelsEvents
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif.constants import c
from flext_ldif.typings import t

# =============================================================================
# MODULE-LEVEL MODELS (defined before container for forward reference support)
# =============================================================================


class DynamicCounts(FlextLdifModelsBase):
    """Dynamic counts model (replaces dict[str, int]).

    Supports int counts for DistributionCounts, RejectionReasons, etc.
    Consolidated base model to reduce code duplication.
    Defined at module level to avoid forward reference issues in default_factory.

    Example:
        counts = DynamicCounts()
        counts.set_count("users", 10)
        counts.increment("users", 5)
        assert counts.get_count("users") == 15

    """

    model_config = ConfigDict(
        frozen=True,
        extra="allow",  # Allow dynamic fields for server type scores
        use_enum_values=True,
        str_strip_whitespace=True,
    )

    def __hash__(self) -> int:
        """Hash implementation for frozen model with __eq__."""
        # Pydantic frozen models should have hash, but ruff requires explicit
        # Since model is frozen, use id-based hash
        return hash(id(self))

    def get_count(self, key: str, default: int = 0) -> int:
        """Get count for a key."""
        value = getattr(self, key, default)
        return int(value) if isinstance(value, (int, float)) else default

    def set_count(self, key: str, value: int) -> None:
        """Set count for a key."""
        setattr(self, key, value)

    def increment(self, key: str, amount: int = 1) -> None:
        """Increment count for a key."""
        current = self.get_count(key)
        setattr(self, key, current + amount)

    def __len__(self) -> int:
        """Return number of entries."""
        extra = self.__pydantic_extra__
        return len(extra) if extra is not None else 0

    def keys(self) -> list[str]:
        """Return all keys."""
        extra = self.__pydantic_extra__
        return list(extra.keys()) if extra is not None else []

    def values(self) -> list[int]:
        """Return all values."""
        extra = self.__pydantic_extra__
        if extra is None:
            return []
        return [int(v) if isinstance(v, (int, float)) else 0 for v in extra.values()]

    def items(self) -> list[tuple[str, int]]:
        """Return all key-value pairs."""
        extra = self.__pydantic_extra__
        if extra is None:
            return []
        return [
            (k, int(v) if isinstance(v, (int, float)) else 0) for k, v in extra.items()
        ]

    def get(self, key: str, default: int = 0) -> int:
        """Get count for a key with default."""
        # Check __dict__ first (where set_count stores values)
        if key in self.__dict__:
            value = self.__dict__[key]
            return int(value) if isinstance(value, (int, float)) else default
        # Fallback to __pydantic_extra__
        extra = self.__pydantic_extra__
        if extra is not None and key in extra:
            value = extra[key]
            return int(value) if isinstance(value, (int, float)) else default
        return default

    def __getitem__(self, key: str) -> int:
        """Allow dict-style access: counts['key']."""
        return self.get(key, 0)

    def __eq__(self, other: object) -> bool:
        """Compare with dict or another DynamicCounts."""
        if isinstance(other, dict):
            # Convert self to dict for comparison
            # Check regular attributes (not starting with _) first
            self_dict = {
                key: value
                for key, value in self.__dict__.items()
                if not key.startswith("_")
            }
            # Also check __pydantic_extra__
            extra = self.__pydantic_extra__
            if extra is not None:
                self_dict.update(extra)
            return self_dict == other
        return super().__eq__(other)

    def max_key(self) -> str | None:
        """Get key with maximum value."""
        extra = self.__pydantic_extra__
        if extra is None or len(extra) == 0:
            return None
        return max(
            extra,
            key=lambda k: (
                int(extra.get(k, 0)) if isinstance(extra.get(k, 0), (int, float)) else 0
            ),
        )

    def to_items(self) -> list[tuple[str, int]]:
        """Get all key-value pairs (alias for items() for compatibility)."""
        return self.items()


class _SchemaElementMap(FlextLdifModelsMetadata.DynamicMetadata):
    """Base schema element mapping model (replaces dict[str, object]).

    Consolidated base model for schema element mappings.
    Uses DynamicMetadata to reduce code duplication.
    Defined at module level to avoid forward reference issues.
    """

    def get_element(
        self,
        name: str,
        element_type: type[t.MetadataAttributeValue],
    ) -> t.MetadataAttributeValue | None:
        """Get element by name with type check.

        Returns element if it matches the specified type, None otherwise.
        """
        # Check if key exists first to avoid KeyError
        if name not in self:
            return None
        # Use __getitem__ which returns MetadataValue (from DynamicMetadata)
        # Then check type and narrow explicitly
        value_raw = self[name]
        # Use isinstance check for type narrowing
        if isinstance(value_raw, element_type):
            # Type narrowing: value_raw is element_type after isinstance check
            # element_type is constrained to MetadataAttributeValue subtypes
            # After isinstance check, value_raw is narrowed to element_type
            # Since element_type is type[MetadataAttributeValue], instances are MetadataAttributeValue
            return value_raw
        return None

    def set_element(self, name: str, element: t.MetadataAttributeValue) -> None:
        """Set element by name.

        Accepts schema elements (SchemaAttribute, SchemaObjectClass) or
        primitive types (str, int, float, bool, None).
        Uses t.MetadataAttributeValue to avoid circular import with models.py.
        """
        setattr(self, name, element)


class _SchemaAttributeMap(_SchemaElementMap):
    """Schema attribute mapping model (replaces dict[str, object]).

    Defined at module level to avoid forward reference issues in default_factory.
    """

    def get_attribute(self, name: str) -> FlextLdifModelsDomains.SchemaAttribute | None:
        """Get attribute by name."""
        value = self.get(name)
        # Use u.when() DSL for conditional return
        return (
            value if isinstance(value, FlextLdifModelsDomains.SchemaAttribute) else None
        )

    def set_attribute(
        self,
        name: str,
        attr: FlextLdifModelsDomains.SchemaAttribute,
    ) -> None:
        """Set attribute by name."""
        setattr(self, name, attr)

    def get_all_attributes(self) -> list[FlextLdifModelsDomains.SchemaAttribute]:
        """Return all attributes as list."""
        attrs: list[FlextLdifModelsDomains.SchemaAttribute] = []
        for key in self.keys():
            attr = self.get_attribute(key)
            if attr is not None:
                # Type narrowing: attr is FlextLdifModelsDomains.SchemaAttribute
                # FlextLdifModelsDomains.SchemaAttribute is the same class (public facade)
                attrs.append(attr)
        return attrs


class _SchemaObjectClassMap(_SchemaElementMap):
    """Schema object class mapping model (replaces dict[str, object]).

    Defined at module level to avoid forward reference issues in default_factory.
    """

    def get_object_class(
        self,
        name: str,
    ) -> FlextLdifModelsDomains.SchemaObjectClass | None:
        """Get object class by name."""
        value = self.get(name)
        # Use conditional expression to avoid unreachable code warning
        return (
            value
            if isinstance(value, FlextLdifModelsDomains.SchemaObjectClass)
            else None
        )

    def set_object_class(
        self,
        name: str,
        obj_class: FlextLdifModelsDomains.SchemaObjectClass,
    ) -> None:
        """Set object class by name."""
        setattr(self, name, obj_class)

    def get_all_object_classes(self) -> list[FlextLdifModelsDomains.SchemaObjectClass]:
        """Return all object classes as list."""
        ocs: list[FlextLdifModelsDomains.SchemaObjectClass] = []
        for key in self.keys():
            oc = self.get_object_class(key)
            if oc is not None:
                # Type narrowing: oc is FlextLdifModelsDomains.SchemaObjectClass
                # Both FlextLdifModelsDomains.SchemaObjectClass and FlextLdifModelsDomains.SchemaObjectClass are the same class
                ocs.append(oc)
        return ocs


class _SchemaContent(FlextLdifModelsBase):
    """Schema content model (replaces dict returns).

    Defined at module level to avoid forward reference issues in default_factory.
    """

    model_config = ConfigDict(frozen=True)

    attributes: Sequence[FlextLdifModelsDomains.SchemaAttribute] = Field(
        default_factory=list,
    )
    object_classes: Sequence[FlextLdifModelsDomains.SchemaObjectClass] = Field(
        default_factory=list,
    )


class _CategoryPaths(FlextLdifModelsMetadata.DynamicMetadata):
    """Category to file path mapping model (replaces dict[str, str]).

    Defined at module level to avoid forward reference issues in default_factory.
    """

    def get_path(self, category: str) -> str | None:
        """Get path for a category."""
        value = self.get(category)
        return str(value) if value is not None else None

    def set_path(self, category: str, path: str) -> None:
        """Set path for a category."""
        self[category] = path

    def get_paths(self) -> list[str]:
        """Return all paths as list."""
        return [str(v) for v in self.values()]

    def get_path_items(self) -> list[tuple[str, str]]:
        """Return all category-path pairs as list."""
        return [(k, str(v)) for k, v in self.items()]


class _ConfigSettings(FlextLdifModelsMetadata.DynamicMetadata):
    """Configuration settings model (replaces dict[str, str | int | bool]).

    Defined at module level to avoid forward reference issues in default_factory.
    """

    def get_setting(self, key: str) -> str | int | bool | None:
        """Get a setting value."""
        value = self.get(key)
        if isinstance(value, (str, int, bool)):
            return value
        return None

    def set_setting(self, key: str, value: str | int | bool) -> None:
        """Set a setting value."""
        self[key] = value

    def get_setting_items(self) -> list[tuple[str, str | int | bool]]:
        """Return all setting pairs as list."""
        return [(k, v) for k, v in self.items() if isinstance(v, (str, int, bool))]


class _BooleanFlags(FlextLdifModelsBase):
    """Boolean flags model (replaces dict[str, bool]).

    Defined at module level to avoid forward reference issues in default_factory.
    Uses extra="allow" to support dynamic field names for validation results.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="allow",
        use_enum_values=True,
        str_strip_whitespace=True,
    )

    def get_flag(self, key: str, *, default: bool = False) -> bool:
        """Get flag value for a key."""
        value = getattr(self, key, default)
        return bool(value) if isinstance(value, (bool, int)) else default

    def set_flag(self, key: str, value: bool) -> None:
        """Set flag value for a key."""
        setattr(self, key, value)

    def __len__(self) -> int:
        """Return number of flags."""
        extra = self.__pydantic_extra__
        return len(extra) if extra is not None else 0

    def keys(self) -> list[str]:
        """Return all keys."""
        extra = self.__pydantic_extra__
        return list(extra.keys()) if extra is not None else []

    def items(self) -> list[tuple[str, bool]]:
        """Return all key-value pairs."""
        extra = self.__pydantic_extra__
        if extra is None:
            return []
        return [(k, bool(v)) for k, v in extra.items()]

    def __getitem__(self, key: str) -> bool:
        """Get flag value by subscript access (e.g., flags["cn"])."""
        extra = self.__pydantic_extra__
        if extra is None or key not in extra:
            msg = f"Key '{key}' not found in flags"
            raise KeyError(msg)
        return bool(extra[key])

    def __contains__(self, key: str) -> bool:
        """Check if flag exists."""
        extra = self.__pydantic_extra__
        return key in extra if extra is not None else False

    def __eq__(self, other: object) -> bool:
        """Compare with dict or another _BooleanFlags."""
        if isinstance(other, dict):
            extra = self.__pydantic_extra__
            if extra is None:
                return other == {}
            return dict(extra) == other
        if isinstance(other, _BooleanFlags):
            return self.__pydantic_extra__ == other.__pydantic_extra__
        return NotImplemented

    def __hash__(self) -> int:
        """Hash based on extra fields for dict compatibility."""
        extra = self.__pydantic_extra__
        if extra is None:
            return hash(())
        return hash(tuple(sorted(extra.items())))


# Use simple type hint to avoid circular dependency
class _FlexibleCategories(
    FlextModelsCollections.Categories[FlextLdifModelsDomains.Entry],
):
    """Flexible entry categorization with dynamic categories.

    Replaces dict[str, list[Entry]] pattern with type-safe model.
    Supports arbitrary category names (schema, hierarchy, users, groups, acl, rejected, etc.)

    Defined at module level to avoid forward reference issues in default_factory.

    Exposes dict-like interface for backward compatibility.
    """

    model_config = ConfigDict(extra="allow", frozen=False)

    def __hash__(self) -> int:
        """Make unhashable - mutable with frozen=False."""
        class_name = self.__class__.__name__
        msg = f"{class_name} is unhashable"
        raise TypeError(msg)

    def __eq__(self, other: object) -> bool:
        """Compare with dict or other Categories instance."""
        if isinstance(other, _FlexibleCategories):
            return self.categories == other.categories
        if isinstance(other, FlextModelsCollections.Categories):
            return self.categories == other.categories
        # Allow comparison with dict for backward compatibility
        if isinstance(other, dict):
            return self.categories == other
        return False

    def items(self) -> Iterator[tuple[str, list[FlextLdifModelsDomains.Entry]]]:
        """Return iterator over (category, entries) pairs (dict-like interface)."""
        return iter(self.categories.items())

    def values(self) -> Iterator[list[FlextLdifModelsDomains.Entry]]:
        """Return iterator over entries lists (dict-like interface)."""
        return iter(self.categories.values())

    def keys(self) -> Iterator[str]:
        """Return iterator over category names (dict-like interface)."""
        return iter(self.categories.keys())

    def __contains__(self, category: str) -> bool:
        """Check if category exists (dict-like interface: 'category' in obj)."""
        return category in self.categories

    def __getitem__(self, category: str) -> list[FlextLdifModelsDomains.Entry]:
        """Get entries for a category (dict-like interface: obj[category])."""
        return self.categories[category]

    def __setitem__(
        self,
        category: str,
        entries: list[FlextLdifModelsDomains.Entry],
    ) -> None:
        """Set entries for a category (dict-like interface: obj[category] = entries)."""
        self.categories[category] = entries


# Type alias for dict input to _FlexibleCategories validator
type _DynCategoriesInput = dict[str, list[FlextLdifModelsDomains.Entry]]


def _statistics_factory() -> FlextLdifModelsResults.Statistics:
    """Factory function for default Statistics (avoids PLW0108 lambda warning)."""
    # Use direct reference to avoid Any return type
    return FlextLdifModelsResults.Statistics()


# =============================================================================
# CONTAINER CLASS
# =============================================================================


class FlextLdifModelsResults:
    """LDIF result and response models container class.

    This class acts as a namespace container for LDIF result and response models.
    All nested classes are accessed via m.* in the main models.py.
    """

    # Type alias for domain events (used in Statistics.events)
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

    # Aliases for loose classes (exposing via facade)
    FlexibleCategories = _FlexibleCategories
    CategoryPaths = _CategoryPaths
    DynamicCounts = DynamicCounts
    SchemaElementMap = _SchemaElementMap
    SchemaAttributeMap = _SchemaAttributeMap
    SchemaObjectClassMap = _SchemaObjectClassMap
    SchemaContent = _SchemaContent
    ConfigSettings = _ConfigSettings
    BooleanFlags = _BooleanFlags

    class StatisticsSummary(FlextLdifModelsBase):
        """Statistics summary model (replaces dict returns)."""

        model_config = ConfigDict(frozen=True)

        total_entries: int = Field(default=0)
        processed_entries: int = Field(default=0)
        failed_entries: int = Field(default=0)
        rejected_entries: int = Field(default=0)
        success_rate: float = Field(default=0.0)
        failure_rate: float = Field(default=0.0)
        rejection_rate: float = Field(default=0.0)
        schema_entries: int = Field(default=0)
        data_entries: int = Field(default=0)
        hierarchy_entries: int = Field(default=0)
        user_entries: int = Field(default=0)
        group_entries: int = Field(default=0)
        acl_entries: int = Field(default=0)
        acls_extracted: int = Field(default=0)
        acls_failed: int = Field(default=0)
        parse_errors: int = Field(default=0)
        entries_written: int = Field(default=0)

    class MigrationSummary(FlextLdifModelsBase):
        """Migration summary model (replaces dict returns)."""

        model_config = ConfigDict(frozen=True)

        statistics: FlextLdifModelsResults.StatisticsSummary | None = Field(
            default=None,
        )
        entry_count: int = Field(default=0)
        output_files: int = Field(default=0)
        is_empty: bool = Field(default=True)

    class CategorizedEntries(FlextLdifModelsBase):
        """Categorized entries model (replaces dict[str, list[Entry]]).

        Categories: schema, hierarchy, users, groups, acl, data, rejected
        """

        model_config = ConfigDict(arbitrary_types_allowed=True)

        schema_entries: list[FlextLdifModelsDomains.Entry] = Field(default_factory=list)
        hierarchy_entries: list[FlextLdifModelsDomains.Entry] = Field(
            default_factory=list,
        )
        user_entries: list[FlextLdifModelsDomains.Entry] = Field(default_factory=list)
        group_entries: list[FlextLdifModelsDomains.Entry] = Field(default_factory=list)
        acl_entries: list[FlextLdifModelsDomains.Entry] = Field(default_factory=list)
        data_entries: list[FlextLdifModelsDomains.Entry] = Field(default_factory=list)
        rejected_entries: list[FlextLdifModelsDomains.Entry] = Field(
            default_factory=list,
        )

        def get_entries(self, category: str) -> list[FlextLdifModelsDomains.Entry]:
            """Get entries for a category."""
            category_map = {
                "schema": self.schema_entries,
                "hierarchy": self.hierarchy_entries,
                "users": self.user_entries,
                "groups": self.group_entries,
                "acl": self.acl_entries,
                "data": self.data_entries,
                "rejected": self.rejected_entries,
            }
            return category_map.get(category, [])

        def get_all_entries(self) -> list[FlextLdifModelsDomains.Entry]:
            """Get all entries from all categories."""
            all_entries: list[FlextLdifModelsDomains.Entry] = []
            all_entries.extend(self.schema_entries)
            all_entries.extend(self.hierarchy_entries)
            all_entries.extend(self.user_entries)
            all_entries.extend(self.group_entries)
            all_entries.extend(self.acl_entries)
            all_entries.extend(self.data_entries)
            all_entries.extend(self.rejected_entries)
            return all_entries

        def category_counts(self) -> DynamicCounts:
            """Get counts per category."""
            counts = DynamicCounts()
            counts.set_count("schema", len(self.schema_entries))
            counts.set_count("hierarchy", len(self.hierarchy_entries))
            counts.set_count("users", len(self.user_entries))
            counts.set_count("groups", len(self.group_entries))
            counts.set_count("acl", len(self.acl_entries))
            counts.set_count("data", len(self.data_entries))
            counts.set_count("rejected", len(self.rejected_entries))
            return counts

    class SchemaSummary(FlextLdifModelsBase):
        """Schema summary model (replaces dict returns in schema methods)."""

        model_config = ConfigDict(frozen=True)

        attributes_count: int = Field(default=0)
        object_classes_count: int = Field(default=0)
        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
            default="generic",
        )
        entry_count: int = Field(default=0)

    class LdifValidationResult(FlextModelsBase.ArbitraryTypesModel):
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

    class AnalysisResult(FlextModelsBase.ArbitraryTypesModel):
        """Result of LDIF analytics operations."""

        total_entries: int = Field(
            default=0,
            description="Total number of entries analyzed",
        )
        object_class_distribution: DynamicCounts = Field(
            default_factory=DynamicCounts,
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
            if len(self.object_class_distribution) == 0:
                return None
            return self.object_class_distribution.max_key()

        @computed_field
        def analytics_summary(self) -> str:
            """Get human-readable analytics summary."""
            return (
                f"{self.total_entries} entries analyzed, "
                f"{self.unique_object_class_count} unique object classes, "
                f"{self.pattern_count} patterns detected"
            )

    class EntryResult(FlextLdifModelsBase):
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

        entries_by_category: _FlexibleCategories = Field(
            default_factory=_FlexibleCategories,
            description="Entries organized by category",
        )
        statistics: FlextLdifModelsResults.Statistics = Field(
            default_factory=_statistics_factory,
            description="Pipeline execution statistics",
        )
        file_paths: _CategoryPaths = Field(
            default_factory=_CategoryPaths,
            description="Output file paths for each category",
        )

        @field_validator("entries_by_category", mode="before")
        @classmethod
        def _convert_dict_to_categories(
            cls,
            value: _FlexibleCategories
            | FlextModelsCollections.Categories[FlextLdifModelsDomains.Entry]
            | _DynCategoriesInput,
        ) -> _FlexibleCategories:
            """Convert dict to _FlexibleCategories for backward compatibility."""
            if isinstance(value, _FlexibleCategories):
                return value
            if isinstance(value, FlextModelsCollections.Categories):
                # Convert from base Categories to _FlexibleCategories
                # Categories class has categories attribute (dict), access it directly
                result = _FlexibleCategories()
                for cat, entries in value.categories.items():
                    result.add_entries(cat, list(entries))
                return result
            if isinstance(value, dict):
                # Convert dict to _FlexibleCategories
                result = _FlexibleCategories()
                for cat, entries in value.items():
                    result.add_entries(str(cat), list(entries))
                return result
            return value

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
        def content(self) -> Sequence[FlextLdifModelsDomains.Entry]:
            """Alias for get_all_entries() for backward compatibility.

            Business Rule: Returns Sequence instead of list to satisfy
            EntryResultProtocol and enable covariance. The underlying
            implementation returns list which satisfies Sequence[Entry].

            Returns:
                Sequence of all entries from all categories combined.

            """
            return self.get_all_entries()

        @property
        def entries(self) -> Sequence[FlextLdifModelsDomains.Entry]:
            """Property to satisfy EntryResultProtocol and HasEntriesProtocol.

            Business Rule: Returns Sequence instead of list to enable
            covariant return types. This allows list[Entry] to be assigned
            to Sequence[EntryProtocol] since Sequence is covariant.

            Returns:
                Sequence of all entries from all categories combined.

            """
            return self.get_all_entries()

        def __len__(self) -> int:
            """Return the number of entries (makes EntryResult behave like a list)."""
            return len(self.get_all_entries())

        def entries_iter(self) -> Iterator[FlextLdifModelsDomains.Entry]:
            """Iterate over entries (alternative to __iter__ to avoid BaseModel conflict).

            Returns:
                Iterator over all entries from all categories combined.

            """
            return iter(self.get_all_entries())

        @overload
        def __getitem__(self, key: slice) -> list[FlextLdifModelsDomains.Entry]: ...

        @overload
        def __getitem__(self, key: int) -> FlextLdifModelsDomains.Entry: ...

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
            entries: Sequence[FlextLdifModelsDomains.Entry],
            category: str = "all",
            statistics: FlextLdifModelsResults.Statistics
            | None = None,  # Optional override
        ) -> FlextLdifModelsResults.EntryResult:
            """Create EntryResult from list of entries.

            Args:
                entries: Sequence of Entry objects (domain Entry type or subtypes)
                        Uses Sequence for covariance, allowing FlextLdifModelsDomains.Entry
                        which inherits from domain Entry.
                category: Category name for the entries (default: "all")
                statistics: Optional statistics object (creates default if None)

            Returns:
                New EntryResult instance.

            """
            # Convert Sequence to list for storage
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
            """Create empty EntryResult.

            Returns:
                Empty EntryResult with no entries and default statistics.

            """
            # Use class reference to avoid type errors
            return cls(
                entries_by_category=_FlexibleCategories(),
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
            # Merge categories - use _FlexibleCategories
            merged_categories = _FlexibleCategories()
            # Add entries from self
            for cat, entries in self.entries_by_category.items():
                merged_categories.add_entries(cat, list(entries))
            # Add entries from other (appends to existing categories)
            for cat, entries in other.entries_by_category.items():
                merged_categories.add_entries(cat, list(entries))

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

            # Merge file paths - use _CategoryPaths
            merged_paths = _CategoryPaths()
            merged_paths.update(self.file_paths.to_dict())
            merged_paths.update(other.file_paths.to_dict())

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

    class Statistics(FlextModelsCollections.Statistics):
        """Unified statistics model for all LDIF operations.

        Business Rule: Statistics model is frozen (immutable) to ensure data integrity
        during processing pipelines. This follows the parent class pattern (FrozenValueModel)
        and ensures consistency across the inheritance hierarchy.
        """

        model_config = ConfigDict(
            frozen=True,  # Consistent with parent FrozenValueModel
            extra="forbid",
            validate_default=True,
            str_strip_whitespace=True,
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
        detected_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = Field(
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
        encoding: c.Ldif.LiteralTypes.EncodingLiteral = Field(
            default="utf-8",
            description="File encoding used",
        )

        # METADATA
        processing_duration: float = Field(
            default=0.0,
            ge=0.0,
            description="Processing time in seconds",
        )
        rejection_reasons: DynamicCounts = Field(
            default_factory=DynamicCounts,
            description="Map of rejection reason to count",
        )

        # DOMAIN EVENTS
        events: list[FlextLdifModelsResults.EventType] = Field(
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
        def summary(self) -> FlextLdifModelsResults.StatisticsSummary:
            """Get comprehensive processing summary."""
            # Calculate rates inline to avoid computed_field Callable typing issues
            success_rate_value = (
                round((self.processed_entries / self.total_entries) * 100, 2)
                if self.total_entries > 0
                else 0.0
            )
            failure_rate_value = (
                round((self.failed_entries / self.total_entries) * 100, 2)
                if self.total_entries > 0
                else 0.0
            )
            rejection_rate_value = (
                round((self.rejected_entries / self.total_entries) * 100, 2)
                if self.total_entries > 0
                else 0.0
            )
            return FlextLdifModelsResults.StatisticsSummary(
                total_entries=self.total_entries,
                processed_entries=self.processed_entries,
                failed_entries=self.failed_entries,
                rejected_entries=self.rejected_entries,
                success_rate=success_rate_value,
                failure_rate=failure_rate_value,
                rejection_rate=rejection_rate_value,
                schema_entries=self.schema_entries,
                data_entries=self.data_entries,
                hierarchy_entries=self.hierarchy_entries,
                user_entries=self.user_entries,
                group_entries=self.group_entries,
                acl_entries=self.acl_entries,
                acls_extracted=self.acls_extracted,
                acls_failed=self.acls_failed,
                parse_errors=self.parse_errors,
                entries_written=self.entries_written,
            )

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
                    rejection_reasons
                    if rejection_reasons is not None
                    else DynamicCounts()
                ),
            )

        @classmethod
        def for_parsing(
            cls,
            total: int,
            schema: int = 0,
            data: int = 0,
            errors: int = 0,
            detected_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = None,
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
            encoding: c.Ldif.LiteralTypes.EncodingLiteral = "utf-8",
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
                rejection_reasons=DynamicCounts(**merged_reasons),
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
                rejection_reasons=DynamicCounts(**dict(self.rejection_reasons)),
                # Add new event to events list
                events=list(self.events) + [event],
            )

    class SchemaBuilderResult(FlextLdifModelsBase):
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

        attributes: _SchemaAttributeMap = Field(
            default_factory=_SchemaAttributeMap,
            description="Attribute definitions keyed by attribute name",
        )
        object_classes: _SchemaObjectClassMap = Field(
            default_factory=_SchemaObjectClassMap,
            description="Object class definitions keyed by class name",
        )
        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
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
        def schema_content(self) -> _SchemaContent:
            """Complete schema containing both attributes and object classes.

            Returns:
                SchemaContent model with attributes and object_classes

            """
            # Type narrowing: use specific get methods for proper type narrowing
            # _SchemaAttributeMap.get_attribute() and _SchemaObjectClassMap.get_object_class()
            # already handle type narrowing correctly
            attrs: list[FlextLdifModelsDomains.SchemaAttribute] = []
            # Use keys() method for proper type narrowing - returns list[str]
            attribute_names: list[str] = list(self.attributes.keys())
            for name in attribute_names:
                # name is already str from keys() method
                attr = self.attributes.get_attribute(name)
                if attr is not None:
                    attrs.append(attr)
            ocs: list[FlextLdifModelsDomains.SchemaObjectClass] = []
            # Use keys() method for proper type narrowing - returns list[str]
            object_class_names: list[str] = list(self.object_classes.keys())
            for name in object_class_names:
                # name is already str from keys() method
                oc = self.object_classes.get_object_class(name)
                if oc is not None:
                    ocs.append(oc)

            return _SchemaContent(
                attributes=attrs,
                object_classes=ocs,
            )

        @computed_field
        def schema_summary(self) -> FlextLdifModelsResults.SchemaSummary:
            """Summary of schema contents.

            Returns:
                SchemaSummary model with counts and server type

            """
            return FlextLdifModelsResults.SchemaSummary(
                attributes_count=len(self.attributes),
                object_classes_count=len(self.object_classes),
                server_type=self.server_type,
                entry_count=self.entry_count,
            )

    class MigrationPipelineResult(FlextLdifModelsBase):
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

        migrated_schema: _SchemaContent = Field(
            default_factory=_SchemaContent,
            description="Migrated schema data",
        )
        entries: Sequence[FlextLdifModelsDomains.Entry] = Field(
            default_factory=list,
            description="List of migrated directory entries",
        )
        stats: FlextLdifModelsResults.Statistics = Field(
            default_factory=_statistics_factory,
            description="Migration statistics and metrics",
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
            has_schema = (
                self.stats.schema_attributes > 0 or self.stats.schema_objectclasses > 0
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
        def migration_summary(self) -> FlextLdifModelsResults.MigrationSummary:
            """Comprehensive migration result summary.

            Returns:
                MigrationSummary with statistics, entry count, and output file count

            """
            # Compute values directly to avoid computed_field Callable typing issues
            entry_count_value = len(self.entries)
            output_file_count_value = len(self.output_files)
            is_empty_value = not (
                self.stats.schema_attributes > 0
                or self.stats.schema_objectclasses > 0
                or self.stats.total_entries > 0
            )
            # Build StatisticsSummary directly instead of using computed property
            stats_summary = FlextLdifModelsResults.StatisticsSummary(
                total_entries=self.stats.total_entries,
                processed_entries=self.stats.processed_entries,
                failed_entries=self.stats.failed_entries,
                rejected_entries=self.stats.rejected_entries,
                success_rate=(
                    round(
                        (self.stats.processed_entries / self.stats.total_entries) * 100,
                        2,
                    )
                    if self.stats.total_entries > 0
                    else 0.0
                ),
                failure_rate=(
                    round(
                        (self.stats.failed_entries / self.stats.total_entries) * 100,
                        2,
                    )
                    if self.stats.total_entries > 0
                    else 0.0
                ),
                rejection_rate=(
                    round(
                        (self.stats.rejected_entries / self.stats.total_entries) * 100,
                        2,
                    )
                    if self.stats.total_entries > 0
                    else 0.0
                ),
                schema_entries=self.stats.schema_entries,
                data_entries=self.stats.data_entries,
                hierarchy_entries=self.stats.hierarchy_entries,
                user_entries=self.stats.user_entries,
                group_entries=self.stats.group_entries,
                acl_entries=self.stats.acl_entries,
                acls_extracted=self.stats.acls_extracted,
                acls_failed=self.stats.acls_failed,
                parse_errors=self.stats.parse_errors,
                entries_written=self.stats.entries_written,
            )
            return FlextLdifModelsResults.MigrationSummary(
                statistics=stats_summary,
                entry_count=entry_count_value,
                output_files=output_file_count_value,
                is_empty=is_empty_value,
            )

    class ClientStatus(FlextModelsEntity.Value):
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
        config: _ConfigSettings = Field(
            default_factory=_ConfigSettings,
            description="Active configuration settings",
        )

    class ValidationResult(FlextLdifModelsBase):
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

    class MigrationEntriesResult(FlextLdifModelsBase):
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
        from_server: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
            description="Source server type",
        )
        to_server: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
            description="Target server type",
        )
        success: bool = Field(description="Migration completion status")

        @computed_field
        def migration_rate(self) -> float:
            """Calculate migration success rate as percentage."""
            if self.total_entries == 0:
                return 100.0
            return (self.migrated_entries / self.total_entries) * 100.0

    class EntryAnalysisResult(FlextLdifModelsBase):
        """Result from entry analysis operations."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        total_entries: int = Field(ge=0, description="Total number of entries analyzed")
        objectclass_distribution: DynamicCounts = Field(
            default_factory=DynamicCounts,
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

    class ServerDetectionResult(FlextLdifModelsBase):
        """Result from LDAP server type detection."""

        model_config = ConfigDict(
            frozen=True,
            validate_default=True,
        )

        detected_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
            description="Detected LDAP server type",
        )
        confidence: float = Field(
            ge=0.0,
            le=1.0,
            description="Detection confidence score",
        )
        scores: DynamicCounts = Field(
            default_factory=DynamicCounts,
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

    class StatisticsResult(FlextLdifModelsBase):
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
        categorized: DynamicCounts = Field(
            default_factory=DynamicCounts,
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
        written_counts: DynamicCounts = Field(
            default_factory=DynamicCounts,
            description="Count of entries written per category",
        )
        output_files: _CategoryPaths = Field(
            default_factory=_CategoryPaths,
            description="Mapping of categories to output file paths",
        )

    class EntriesStatistics(FlextModelsEntity.Value):
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
        object_class_distribution: DynamicCounts = Field(
            default_factory=DynamicCounts,
            description="Count of entries per objectClass",
        )
        server_type_distribution: DynamicCounts = Field(
            default_factory=DynamicCounts,
            description="Count of entries per server type",
        )

    class DictAccessibleValue(FlextModelsEntity.Value):
        """Base value model providing dict-style access (backwards compatibility)."""

        def __getitem__(self, key: str) -> str | int | float | bool | None:
            """Get attribute value by key (dict-style access)."""
            if hasattr(self, key):
                value = getattr(self, key)
                # Type narrowing: ensure return type matches expected union
                if isinstance(value, (str, int, float, bool, type(None))):
                    return value
                # Fallback: convert to string if not in expected types
                return str(value) if value is not None else None
            raise KeyError(key)

        def __contains__(self, key: str) -> bool:
            """Check if attribute exists (dict-style membership test)."""
            return hasattr(self, key)

        def get(
            self,
            key: str,
            default: str | float | bool | None = None,
        ) -> str | int | float | bool | None:
            """Get attribute value with optional default (dict-style access)."""
            return getattr(self, key, default)

        def keys(self) -> list[str]:
            """Return list of attribute keys (dict-style access)."""
            # Use model_fields_set for Pydantic v2 compatibility
            return list(self.model_fields_set)

        def items(self) -> list[tuple[str, t.ScalarValue]]:
            """Return list of (key, value) tuples (dict-style access)."""
            # Use model_fields_set for Pydantic v2 compatibility
            # Values are ScalarValue (str | int | float | bool | None)
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
        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
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

    class SyntaxLookupResult(FlextLdifModelsBase):
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

    class ValidationBatchResult(FlextLdifModelsBase):
        """Result of batch validation operations.

        Contains validation results for multiple attribute names
        and objectClass names validated in a single operation.

        Attributes:
            results: Mapping of validated item names to validation status (True=valid, False=invalid)

        """

        results: _BooleanFlags = Field(
            default_factory=_BooleanFlags,
            description="Mapping of validated items to validation status",
        )

    class ParseResponse(FlextModelsEntity.Value):
        """Composed response from parsing operation.

        Combines Entry models with statistics from parse operation.
        Uses model composition instead of dict intermediaries.
        """

        model_config = ConfigDict(frozen=True, validate_default=True)

        entries: Sequence[FlextLdifModelsDomains.Entry] = Field(
            default_factory=list,
            description="Parsed LDIF entries",
        )
        statistics: FlextLdifModelsResults.Statistics = Field(
            description="Parse operation statistics",
        )
        detected_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = Field(None)

        def get_entries(self) -> Sequence[FlextLdifModelsDomains.Entry]:
            """Get parsed entries.

            Returns:
                Sequence of parsed entries

            """
            # Convert domain entries to public facade entries
            converted_entries: list[FlextLdifModelsDomains.Entry] = []
            for entry in self.entries:
                # Handle None dn and attributes
                if entry.dn is None:
                    continue  # Skip entries with None dn
                if entry.attributes is None:
                    continue  # Skip entries with None attributes

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
        """Composed response from ACL extraction.

        Combines extracted Acl models with extraction statistics.
        """

        model_config = ConfigDict(frozen=True, validate_default=True)

        acls: list[FlextLdifModelsDomains.Acl] = Field(
            default_factory=list,
            description="Extracted ACL models",
        )
        statistics: FlextLdifModelsResults.Statistics = Field(
            description="ACL extraction statistics",
        )

    class AclEvaluationResult(FlextModelsEntity.Value):
        """Result from ACL context evaluation.

        Contains evaluation outcome indicating if ACLs grant required permissions.
        """

        model_config = ConfigDict(frozen=True, validate_default=True)

        granted: bool = Field(
            default=False,
            description="Whether required permissions are granted",
        )
        matched_acl: FlextLdifModelsDomains.Acl | None = Field(
            default=None,
            description="ACL that matched (if granted)",
        )
        message: str = Field(
            default="",
            description="Evaluation details message",
        )

    class WriteResponse(FlextModelsEntity.Value):
        """Composed response from write operation.

        Contains written LDIF content and statistics using model composition.
        """

        model_config = ConfigDict(frozen=True, validate_default=True)

        content: str | None = Field(None, description="Written LDIF content")
        statistics: FlextLdifModelsResults.Statistics = Field(
            description="Write operation statistics",
        )

        def get_content(self) -> str:
            """Get written LDIF content.

            Returns:
                Written LDIF content as string

            """
            return self.content or ""

    class SchemaDiscoveryResult(FlextModelsBase.ArbitraryTypesModel):
        """Result of schema discovery operations."""

        attributes: _SchemaAttributeMap = Field(
            default_factory=_SchemaAttributeMap,
            description="Discovered attributes with their metadata",
        )
        objectclasses: _SchemaObjectClassMap = Field(
            default_factory=_SchemaObjectClassMap,
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
        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
            default="generic",
            description="Server type for which schema was discovered",
        )
        entry_count: int = Field(
            default=0,
            description="Number of entries used for schema discovery",
        )
        server_info: (
            dict[str, str | int | float | bool | None]
            | FlextLdifModelsMetadata.DynamicMetadata
            | None
        ) = Field(
            default=None,
            description="LDAP server information from Root DSE",
        )
        servers: (
            dict[str, str | int | float | bool | None]
            | FlextLdifModelsMetadata.DynamicMetadata
            | None
        ) = Field(
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

    # Alias to module-level _FlexibleCategories (for backward compatibility)
    """Flexible entry categorization with dynamic categories.

    Replaces dict[str, list[Entry]] pattern with type-safe model.
    Supports arbitrary category names (schema, hierarchy, users, groups, acl, rejected, etc.)
    """
