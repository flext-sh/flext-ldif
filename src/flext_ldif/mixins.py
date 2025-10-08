"""FLEXT LDIF Mixins - Advanced Mixin Classes with Monadic Composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from typing import TypeVar, cast, override

from flext_core import FlextMixins, FlextResult

from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes

T = TypeVar("T")

U = TypeVar("U")


class FlextLdifMixins(FlextMixins):
    """LDIF domain mixins extending flext-core FlextMixins.

    Provides reusable functionality through mixin composition.
    Uses advanced patterns with monadic composition support.
    """

    # =============================================================================
    # VALIDATION MIXINS - Reusable Validation Logic
    # =============================================================================

    class ValidationMixin:
        """Mixin providing validation utilities with monadic composition.

        All validation now delegates to centralized Models with Pydantic validators.
        Centralizes validation logic through Pydantic v2 patterns.
        """

        @staticmethod
        def validate_dn_format(dn_value: str) -> FlextResult[str]:
            """Validate DN format using DistinguishedName Model validation.

            Returns:
                FlextResult[str]: Success with normalized DN or failure with validation error

            """
            # Use Model validation - centralized in FlextLdifModels.DistinguishedName
            # Explicit FlextResult error handling - NO try/except
            dn_model_result = FlextLdifModels.DistinguishedName.create(value=dn_value)
            if dn_model_result.is_failure:
                return FlextResult[str].fail(
                    f"Invalid DN format: {dn_model_result.error}"
                )

            dn_model = cast(
                "FlextLdifModels.DistinguishedName", dn_model_result.unwrap()
            )
            return FlextResult[str].ok(dn_model.value)

        @staticmethod
        def validate_attribute_name(attr_name: str) -> FlextResult[str]:
            """Validate attribute name format using AttributeName Model.

            Returns:
                FlextResult[str]: Success with validated attribute name or failure with validation error

            """
            # Use Model validation - centralized in FlextLdifModels.AttributeName
            # Explicit FlextResult error handling - NO try/except
            attr_model_result = FlextLdifModels.AttributeName.create(name=attr_name)
            if attr_model_result.is_failure:
                return FlextResult[str].fail(
                    f"Invalid attribute name: {attr_model_result.error}"
                )

            attr_model = cast(
                "FlextLdifModels.AttributeName", attr_model_result.unwrap()
            )
            return FlextResult[str].ok(attr_model.name)

        @staticmethod
        def validate_attribute_values(
            values: Sequence[str],
        ) -> FlextResult[FlextLdifTypes.StringList]:
            """Validate attribute values using AttributeValues Model.

            Returns:
                FlextResult[StringList]: Success with validated values or failure with validation error

            """
            # Check if input is a string (which is iterable but not valid)
            if isinstance(values, str):
                return FlextResult[FlextLdifTypes.StringList].fail(
                    "Attribute values must be a sequence, not a string"
                )

            # Use Model validation - centralized in FlextLdifModels.AttributeValues
            # Explicit FlextResult error handling - NO try/except
            values_model_result = FlextLdifModels.AttributeValues.create(
                values=list(values)
            )
            if values_model_result.is_failure:
                return FlextResult[FlextLdifTypes.StringList].fail(
                    f"Invalid attribute values: {values_model_result.error}"
                )

            values_model = cast(
                "FlextLdifModels.AttributeValues", values_model_result.unwrap()
            )
            return FlextResult[FlextLdifTypes.StringList].ok(values_model.values)

        @staticmethod
        def validate_url_format(url: str) -> FlextResult[str]:
            """Validate URL format using LdifUrl Model.

            Returns:
                FlextResult[str]: Success with validated URL or failure with validation error

            """
            # Use Model validation - centralized in FlextLdifModels.LdifUrl
            # Explicit FlextResult error handling - NO try/except
            url_model_result = FlextLdifModels.LdifUrl.create(url=url)
            if url_model_result.is_failure:
                return FlextResult[str].fail(
                    url_model_result.error or "Invalid URL format"
                )

            url_model = cast("FlextLdifModels.LdifUrl", url_model_result.unwrap())
            return FlextResult[str].ok(url_model.url)

        @staticmethod
        def validate_encoding(encoding: str) -> FlextResult[str]:
            """Validate character encoding using Encoding Model.

            Returns:
                FlextResult[str]: Success with validated encoding or failure with validation error

            """
            # Use Model validation - centralized in FlextLdifModels.Encoding
            # Explicit FlextResult error handling - NO try/except
            encoding_model_result = FlextLdifModels.Encoding.create(encoding=encoding)
            if encoding_model_result.is_failure:
                return FlextResult[str].fail(
                    encoding_model_result.error or "Invalid encoding"
                )

            encoding_model = cast(
                "FlextLdifModels.Encoding", encoding_model_result.unwrap()
            )
            return FlextResult[str].ok(encoding_model.encoding)

        @classmethod
        def validate_with_result(
            cls, validator_func: Callable[[T], U], data: T
        ) -> FlextResult[U]:
            """Validate data using validator function with FlextResult."""
            try:
                result = validator_func(data)
                return FlextResult[U].ok(result)
            except Exception as e:
                return FlextResult[U].fail(str(e))

    # =============================================================================
    # PROCESSING MIXINS - Reusable Processing Logic
    # =============================================================================

    class ProcessingMixin:
        """Mixin providing processing utilities with monadic composition."""

        @staticmethod
        def normalize_dn_components(dn: str) -> FlextResult[str]:
            """Normalize DN components using DistinguishedName Model.

            Returns:
                FlextResult[str]: Success with normalized DN or failure with validation error

            """
            # Use Model normalization - centralized in FlextLdifModels.DistinguishedName
            # Explicit FlextResult error handling - NO try/except
            dn_model_result = FlextLdifModels.DistinguishedName.create(value=dn)
            if dn_model_result.is_failure:
                # Return original DN on validation failure (fallback behavior)
                return FlextResult[str].ok(dn)

            dn_model = cast(
                "FlextLdifModels.DistinguishedName", dn_model_result.unwrap()
            )
            # computed_field property access - pyrefly needs explicit str() cast
            return FlextResult[str].ok(str(dn_model.normalized_value))

        @staticmethod
        def extract_dn_components(dn: str) -> FlextResult[list[tuple[str, str]]]:
            """Extract DN components as (attribute, value) pairs using DistinguishedName Model.

            Returns:
                FlextResult[list[tuple[str, str]]]: Success with component pairs or empty list on failure

            """
            # Use Model parsing - centralized in FlextLdifModels.DistinguishedName
            # Explicit FlextResult error handling - NO try/except
            dn_model_result = FlextLdifModels.DistinguishedName.create(value=dn)
            if dn_model_result.is_failure:
                # Return empty list on validation failure (fallback behavior)
                return FlextResult[list[tuple[str, str]]].ok([])

            dn_model = cast(
                "FlextLdifModels.DistinguishedName", dn_model_result.unwrap()
            )
            pairs: list[tuple[str, str]] = []
            for comp in dn_model.components:
                if "=" in comp:
                    attr, value = comp.split("=", 1)
                    pairs.append((attr.strip(), value.strip()))
            return FlextResult[list[tuple[str, str]]].ok(pairs)

        @staticmethod
        def build_dn_from_components(components: Sequence[tuple[str, str]]) -> str:
            """Build DN from component pairs."""
            return ",".join(f"{attr}={value}" for attr, value in components)

        @classmethod
        def process_with_result(
            cls, processor_func: Callable[[T], U], data: T
        ) -> FlextResult[U]:
            """Process data using processor function with FlextResult."""
            try:
                result = processor_func(data)
                return FlextResult[U].ok(result)
            except Exception as e:
                return FlextResult[U].fail(str(e))

        @classmethod
        def process_batch_with_result(
            cls, processor_func: Callable[[T], U], data_batch: Sequence[T]
        ) -> FlextResult[Sequence[U]]:
            """Process batch of data with FlextResult."""
            try:
                processed_batch: list[U] = []
                for item in data_batch:
                    result = processor_func(item)
                    processed_batch.append(result)
                return FlextResult[Sequence[U]].ok(processed_batch)
            except Exception as e:
                return FlextResult[Sequence[U]].fail(str(e))

    # =============================================================================
    # TRANSFORMATION MIXINS - Data Transformation Utilities
    # =============================================================================

    class TransformationMixin:
        """Mixin providing transformation utilities with monadic composition."""

        @staticmethod
        def transform_attribute_values(
            values: Sequence[str], transformer: Callable[[str], str]
        ) -> FlextLdifTypes.StringList:
            """Transform attribute values using transformer function."""
            return [transformer(value) for value in values]

        @staticmethod
        def transform_dn_case(dn: str, case_func: Callable[[str], str]) -> str:
            """Transform DN case using case function."""
            components: FlextLdifTypes.StringList = []
            for comp in dn.split(","):
                stripped_comp = comp.strip()
                if "=" in stripped_comp:
                    attr, value = stripped_comp.split("=", 1)
                    transformed_attr = case_func(attr.strip())
                    component_str = f"{transformed_attr}={value.strip()}"
                    components.append(component_str)
                else:
                    components.append(stripped_comp)
            return ",".join(components)

        @staticmethod
        def map_attributes(
            attributes: dict[str, Sequence[str]],
            mapper: Callable[[str, Sequence[str]], tuple[str, Sequence[str]]],
        ) -> dict[str, Sequence[str]]:
            """Map attributes using mapper function."""
            mapped_attributes: dict[str, Sequence[str]] = {}
            for attr_name, attr_values in attributes.items():
                new_name, new_values = mapper(attr_name, attr_values)
                mapped_attributes[new_name] = new_values
            return mapped_attributes

        @classmethod
        def transform_with_result(
            cls, transformer_func: Callable[[T], U], data: T
        ) -> FlextResult[U]:
            """Transform data using transformer function with FlextResult."""
            try:
                result = transformer_func(data)
                return FlextResult[U].ok(result)
            except Exception as e:
                return FlextResult[U].fail(str(e))

    # =============================================================================
    # ANALYTICS MIXINS - Analytics and Statistics Utilities
    # =============================================================================

    class AnalyticsMixin:
        """Mixin providing analytics utilities with monadic composition."""

        @staticmethod
        def count_entries_by_type(entries: Sequence[object]) -> dict[str, int]:
            """Count entries by type."""
            type_counts: dict[str, int] = {}
            for entry in entries:
                entry_type = getattr(
                    entry, "type", getattr(entry, "entry_type", "unknown")
                )
                type_counts[entry_type] = type_counts.get(entry_type, 0) + 1
            return type_counts

        @staticmethod
        def calculate_attribute_frequency(entries: Sequence[object]) -> dict[str, int]:
            """Calculate attribute frequency across entries."""
            attribute_counts: dict[str, int] = {}
            for entry in entries:
                attributes = getattr(entry, "attributes", {})
                for attr_name in attributes:
                    attribute_counts[attr_name] = attribute_counts.get(attr_name, 0) + 1
            return attribute_counts

        @staticmethod
        def analyze_dn_patterns(entries: Sequence[object]) -> dict[str, int]:
            """Analyze DN patterns using DistinguishedName Model."""
            pattern_counts: dict[str, int] = {}
            for entry in entries:
                dn = getattr(entry, "dn", "")
                if isinstance(dn, str):
                    # Use Model parsing - centralized in FlextLdifModels.DistinguishedName
                    # Explicit FlextResult error handling - NO try/except
                    dn_model_result = cast(
                        "FlextResult[FlextLdifModels.DistinguishedName]",
                        FlextLdifModels.DistinguishedName.create(value=dn),
                    )
                    if dn_model_result.is_failure:
                        # Skip invalid DNs (fallback behavior)
                        continue

                    dn_model = dn_model_result.unwrap()
                    for comp in dn_model.components:
                        if "=" in comp:
                            attr_name = comp.split("=")[0].strip().lower()
                            pattern_counts[attr_name] = (
                                pattern_counts.get(attr_name, 0) + 1
                            )
            return pattern_counts

        @classmethod
        def analyze_with_result(
            cls,
            analyzer_func: Callable[[Sequence[T]], FlextLdifTypes.Dict],
            data: Sequence[T],
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Analyze data using analyzer function with FlextResult."""
            try:
                result = analyzer_func(data)
                return FlextResult[FlextLdifTypes.Dict].ok(result)
            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(str(e))

    # =============================================================================
    # CACHING MIXINS - Caching and Performance Utilities
    # =============================================================================

    class CachingMixin:
        """Mixin providing caching utilities with monadic composition."""

        @override
        def __init__(self) -> None:
            """Initialize caching mixin with empty cache and statistics."""
            self._cache: FlextLdifTypes.Dict = {}
            self._cache_stats: dict[str, int] = {"hits": 0, "misses": 0}

        def get_from_cache(self, key: str) -> FlextResult[object]:
            """Get value from cache with FlextResult.

            Returns:
                FlextResult[object]: Success with cached value or failure for cache miss

            """
            # Explicit FlextResult handling - NO try/except for simple dict operations
            if key in self._cache:
                self._cache_stats["hits"] += 1
                return FlextResult[object].ok(self._cache[key])
            self._cache_stats["misses"] += 1
            return FlextResult[object].fail("Cache miss")

        def set_in_cache(self, key: str, value: object) -> FlextResult[None]:
            """Set value in cache with FlextResult.

            Returns:
                FlextResult[None]: Success confirmation

            """
            # Explicit FlextResult handling - NO try/except for simple dict operations
            self._cache[key] = value
            return FlextResult[None].ok(None)

        def clear_cache(self) -> FlextResult[None]:
            """Clear cache with FlextResult.

            Returns:
                FlextResult[None]: Success confirmation

            """
            # Explicit FlextResult handling - NO try/except for simple dict operations
            self._cache.clear()
            self._cache_stats = {"hits": 0, "misses": 0}
            return FlextResult[None].ok(None)

        def get_cache_stats(self) -> dict[str, int]:
            """Get cache statistics."""
            stats = self._cache_stats.copy()
            stats["size"] = len(self._cache)
            return stats

    # =============================================================================
    # MONADIC COMPOSITION MIXINS - Advanced Functional Patterns
    # =============================================================================

    class MonadicMixin:
        """Mixin providing monadic composition utilities."""

        def map(self, func: Callable[[object], U]) -> FlextResult[U]:
            """Map operation for monadic composition."""
            try:
                result = func(self)
                return FlextResult[U].ok(result)
            except Exception as e:
                return FlextResult[U].fail(str(e))

        def flat_map(self, func: Callable[[object], FlextResult[U]]) -> FlextResult[U]:
            """Flat map operation for monadic composition."""
            try:
                return func(self)
            except Exception as e:
                return FlextResult[U].fail(str(e))

        def filter(self, predicate: Callable[[object], bool]) -> FlextResult[object]:
            """Filter operation for monadic composition."""
            try:
                if predicate(self):
                    return FlextResult[object].ok(self)
                return FlextResult[object].fail("Predicate failed")
            except Exception as e:
                return FlextResult[object].fail(str(e))

        def fold(self, initial: U, func: Callable[[U, object], U]) -> U:
            """Fold operation for monadic composition."""
            try:
                return func(initial, self)
            except Exception as e:
                msg = f"Fold operation failed: {e}"
                raise ValueError(msg) from e

    # =============================================================================
    # ITERATOR MIXINS - Advanced Iterator Patterns
    # =============================================================================

    class IteratorMixin:
        """Mixin providing iterator utilities with monadic composition."""

        @staticmethod
        def map_iterator(
            iterator: Iterator[object], func: Callable[..., object]
        ) -> Iterator[FlextResult[object]]:
            """Map iterator with FlextResult."""
            for item in iterator:
                try:
                    result = func(item)
                    yield FlextResult[object].ok(result)
                except Exception as e:
                    yield FlextResult[object].fail(str(e))

        @staticmethod
        def filter_iterator(
            iterator: Iterator[object], predicate: Callable[[object], bool]
        ) -> Iterator[object]:
            """Filter iterator."""
            for item in iterator:
                if predicate(item):
                    yield item

        @staticmethod
        def fold_iterator(
            iterator: Iterator[object],
            initial: object,
            func: Callable[[object, object], object],
        ) -> object:
            """Fold iterator."""
            accumulator = initial
            for item in iterator:
                accumulator = func(accumulator, item)
            return accumulator

        @classmethod
        def process_iterator_with_result(
            cls,
            iterator: Iterator[object],
            processor: Callable[[object], FlextResult[object]],
        ) -> Iterator[FlextResult[object]]:
            """Process iterator with FlextResult."""
            for item in iterator:
                yield processor(item)

    # =============================================================================
    # UNIFIED MIXIN COORDINATOR - Centralized Mixin Management
    # =============================================================================

    class MixinCoordinator:
        """Unified mixin coordinator managing all mixin functionality."""

        @override
        def __init__(self) -> None:
            """Initialize mixin coordinator with all available mixins."""
            self._validation_mixin = FlextLdifMixins.ValidationMixin()
            self._processing_mixin = FlextLdifMixins.ProcessingMixin()
            self._transformation_mixin = FlextLdifMixins.TransformationMixin()
            self._analytics_mixin = FlextLdifMixins.AnalyticsMixin()
            self._caching_mixin = FlextLdifMixins.CachingMixin()
            self._iterator_mixin = FlextLdifMixins.IteratorMixin()

        def get_validation_mixin(self) -> FlextLdifMixins.ValidationMixin:
            """Get validation mixin instance."""
            return self._validation_mixin

        def get_processing_mixin(self) -> FlextLdifMixins.ProcessingMixin:
            """Get processing mixin instance."""
            return self._processing_mixin

        def get_transformation_mixin(self) -> FlextLdifMixins.TransformationMixin:
            """Get transformation mixin instance."""
            return self._transformation_mixin

        def get_analytics_mixin(self) -> FlextLdifMixins.AnalyticsMixin:
            """Get analytics mixin instance."""
            return self._analytics_mixin

        def get_caching_mixin(self) -> FlextLdifMixins.CachingMixin:
            """Get caching mixin instance."""
            return self._caching_mixin

        def get_iterator_mixin(self) -> FlextLdifMixins.IteratorMixin:
            """Get iterator mixin instance."""
            return self._iterator_mixin

        def combine_mixins(self, *mixins: type) -> FlextResult[type]:
            """Combine multiple mixins into a single class.

            Returns:
                FlextResult[type]: Success with combined class or failure

            """
            # Explicit FlextResult handling - NO try/except for type() builtin
            # The type() builtin with valid arguments doesn't raise exceptions
            combined_class = type("CombinedMixin", tuple(mixins), {})
            return FlextResult[type].ok(combined_class)


__all__ = ["FlextLdifMixins"]
