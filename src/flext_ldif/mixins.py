"""FLEXT LDIF Mixins - Advanced Mixin Classes with Monadic Composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from typing import cast, override

from flext_core import FlextCore

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


class FlextLdifMixins(FlextCore.Mixins):
    """LDIF domain mixins extending flext-core FlextCore.Mixins.

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
        def validate_dn_format(dn_value: str) -> FlextCore.Result[str]:
            """Validate DN format using DistinguishedName Model validation.

            Returns:
                FlextCore.Result[str]: Success with normalized DN or failure with validation error

            """
            # Use Model validation - centralized in FlextLdifModels.DistinguishedName
            # Explicit FlextCore.Result error handling - NO try/except
            dn_model_result = FlextLdifModels.DistinguishedName.create(value=dn_value)
            if dn_model_result.is_failure:
                return FlextCore.Result[str].fail(
                    f"Invalid DN format: {dn_model_result.error}"
                )

            dn_model = cast(
                "FlextLdifModels.DistinguishedName", dn_model_result.unwrap()
            )
            return FlextCore.Result[str].ok(dn_model.value)

        @staticmethod
        def validate_attribute_name(attr_name: str) -> FlextCore.Result[str]:
            """Validate attribute name format using AttributeName Model.

            Returns:
                FlextCore.Result[str]: Success with validated attribute name or failure with validation error

            """
            # Use Model validation - centralized in FlextLdifModels.AttributeName
            # Explicit FlextCore.Result error handling - NO try/except
            attr_model_result = FlextLdifModels.AttributeName.create(name=attr_name)
            if attr_model_result.is_failure:
                return FlextCore.Result[str].fail(
                    f"Invalid attribute name: {attr_model_result.error}"
                )

            attr_model = cast(
                "FlextLdifModels.AttributeName", attr_model_result.unwrap()
            )
            return FlextCore.Result[str].ok(attr_model.name)

        @staticmethod
        def validate_attribute_values(
            values: Sequence[str],
        ) -> FlextCore.Result[FlextLdifTypes.StringList]:
            """Validate attribute values using AttributeValues Model.

            Returns:
                FlextCore.Result[StringList]: Success with validated values or failure with validation error

            """
            # Check if input is a string (which is iterable but not valid)
            if isinstance(values, str):
                return FlextCore.Result[FlextLdifTypes.StringList].fail(
                    "Attribute values must be a sequence, not a string"
                )

            # Use Model validation - centralized in FlextLdifModels.AttributeValues
            # Explicit FlextCore.Result error handling - NO try/except
            values_model_result = FlextLdifModels.AttributeValues.create(
                values=list(values)
            )
            if values_model_result.is_failure:
                return FlextCore.Result[FlextLdifTypes.StringList].fail(
                    f"Invalid attribute values: {values_model_result.error}"
                )

            values_model = cast(
                "FlextLdifModels.AttributeValues", values_model_result.unwrap()
            )
            return FlextCore.Result[FlextLdifTypes.StringList].ok(values_model.values)

        @staticmethod
        def validate_url_format(url: str) -> FlextCore.Result[str]:
            """Validate URL format using LdifUrl Model.

            Returns:
                FlextCore.Result[str]: Success with validated URL or failure with validation error

            """
            # Use Model validation - centralized in FlextLdifModels.LdifUrl
            # Explicit FlextCore.Result error handling - NO try/except
            url_model_result = FlextLdifModels.LdifUrl.create(url=url)
            if url_model_result.is_failure:
                return FlextCore.Result[str].fail(
                    url_model_result.error or "Invalid URL format"
                )

            url_model = cast("FlextLdifModels.LdifUrl", url_model_result.unwrap())
            return FlextCore.Result[str].ok(url_model.url)

        @staticmethod
        def validate_encoding(encoding: str) -> FlextCore.Result[str]:
            """Validate character encoding using Encoding Model.

            Returns:
                FlextCore.Result[str]: Success with validated encoding or failure with validation error

            """
            # Use Model validation - centralized in FlextLdifModels.Encoding
            # Explicit FlextCore.Result error handling - NO try/except
            encoding_model_result = FlextLdifModels.Encoding.create(encoding=encoding)
            if encoding_model_result.is_failure:
                return FlextCore.Result[str].fail(
                    encoding_model_result.error or "Invalid encoding"
                )

            encoding_model = cast(
                "FlextLdifModels.Encoding", encoding_model_result.unwrap()
            )
            return FlextCore.Result[str].ok(encoding_model.encoding)

        @classmethod
        def validate_with_result(
            cls,
            validator_func: Callable[[FlextCore.Types.T], FlextCore.Types.U],
            data: FlextCore.Types.T,
        ) -> FlextCore.Result[FlextCore.Types.U]:
            """Validate data using validator function with FlextCore.Result."""
            try:
                result = validator_func(data)
                return FlextCore.Result[FlextCore.Types.U].ok(result)
            except Exception as e:
                return FlextCore.Result[FlextCore.Types.U].fail(str(e))

    # =============================================================================
    # PROCESSING MIXINS - Reusable Processing Logic
    # =============================================================================

    class ProcessingMixin:
        """Mixin providing processing utilities with monadic composition."""

        @staticmethod
        def normalize_dn_components(dn: str) -> FlextCore.Result[str]:
            """Normalize DN components using DistinguishedName Model.

            Returns:
                FlextCore.Result[str]: Success with normalized DN or failure with validation error

            """
            # Use Model normalization - centralized in FlextLdifModels.DistinguishedName
            # Explicit FlextCore.Result error handling - NO try/except, NO fallback
            dn_model_result = FlextLdifModels.DistinguishedName.create(value=dn)
            if dn_model_result.is_failure:
                # Strict RFC compliance - return error, not original DN
                return FlextCore.Result[str].fail(
                    f"DN normalization failed: {dn_model_result.error}"
                )

            dn_model = cast(
                "FlextLdifModels.DistinguishedName", dn_model_result.unwrap()
            )
            # computed_field property access - pyrefly needs explicit str() cast
            return FlextCore.Result[str].ok(str(dn_model.value))

        @staticmethod
        def extract_dn_components(dn: str) -> FlextCore.Result[list[tuple[str, str]]]:
            """Extract DN components as (attribute, value) pairs using DistinguishedName Model.

            Returns:
                FlextCore.Result[list[tuple[str, str]]]: Success with component pairs or empty list on failure

            """
            # Use Model parsing - centralized in FlextLdifModels.DistinguishedName
            # Explicit FlextCore.Result error handling - NO try/except, NO fallback
            dn_model_result = FlextLdifModels.DistinguishedName.create(value=dn)
            if dn_model_result.is_failure:
                # Strict RFC compliance - return error, not empty list
                return FlextCore.Result[list[tuple[str, str]]].fail(
                    f"Failed to extract DN components: {dn_model_result.error}"
                )

            dn_model = cast(
                "FlextLdifModels.DistinguishedName", dn_model_result.unwrap()
            )
            pairs: list[tuple[str, str]] = []
            for comp in dn_model.components:
                if "=" in comp:
                    attr, value = comp.split("=", 1)
                    pairs.append((attr.strip(), value.strip()))
            return FlextCore.Result[list[tuple[str, str]]].ok(pairs)

        @staticmethod
        def build_dn_from_components(components: Sequence[tuple[str, str]]) -> str:
            """Build DN from component pairs."""
            return ",".join(f"{attr}={value}" for attr, value in components)

        @classmethod
        def process_with_result(
            cls,
            processor_func: Callable[[FlextCore.Types.T], FlextCore.Types.U],
            data: FlextCore.Types.T,
        ) -> FlextCore.Result[FlextCore.Types.U]:
            """Process data using processor function with FlextCore.Result."""
            try:
                result = processor_func(data)
                return FlextCore.Result[FlextCore.Types.U].ok(result)
            except Exception as e:
                return FlextCore.Result[FlextCore.Types.U].fail(str(e))

        @classmethod
        def process_batch_with_result(
            cls,
            processor_func: Callable[[FlextCore.Types.T], FlextCore.Types.U],
            data_batch: Sequence[FlextCore.Types.T],
        ) -> FlextCore.Result[Sequence[FlextCore.Types.U]]:
            """Process batch of data with FlextCore.Result."""
            try:
                processed_batch: list[FlextCore.Types.U] = []
                for item in data_batch:
                    result = processor_func(item)
                    processed_batch.append(result)
                return FlextCore.Result[Sequence[FlextCore.Types.U]].ok(processed_batch)
            except Exception as e:
                return FlextCore.Result[Sequence[FlextCore.Types.U]].fail(str(e))

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
            cls,
            transformer_func: Callable[[FlextCore.Types.T], FlextCore.Types.U],
            data: FlextCore.Types.T,
        ) -> FlextCore.Result[FlextCore.Types.U]:
            """Transform data using transformer function with FlextCore.Result."""
            try:
                result = transformer_func(data)
                return FlextCore.Result[FlextCore.Types.U].ok(result)
            except Exception as e:
                return FlextCore.Result[FlextCore.Types.U].fail(str(e))

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
                attributes = getattr(entry, FlextLdifConstants.DictKeys.ATTRIBUTES, {})
                for attr_name in attributes:
                    attribute_counts[attr_name] = attribute_counts.get(attr_name, 0) + 1
            return attribute_counts

        @staticmethod
        def analyze_dn_patterns(entries: Sequence[object]) -> dict[str, int]:
            """Analyze DN patterns using DistinguishedName Model."""
            pattern_counts: dict[str, int] = {}
            for entry in entries:
                dn = getattr(entry, FlextLdifConstants.DictKeys.DN, "")
                if isinstance(dn, str):
                    # Use Model parsing - centralized in FlextLdifModels.DistinguishedName
                    # Explicit FlextCore.Result error handling - NO try/except, NO fallback
                    dn_model_result = cast(
                        "FlextCore.Result[FlextLdifModels.DistinguishedName]",
                        FlextLdifModels.DistinguishedName.create(value=dn),
                    )
                    if dn_model_result.is_failure:
                        # Strict RFC compliance - invalid DN fails the entire analysis
                        error_msg = f"Invalid DN in entry during pattern analysis: {dn_model_result.error}"
                        raise FlextCore.Exceptions.ValidationError(error_msg)

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
            analyzer_func: Callable[[Sequence[FlextCore.Types.T]], FlextLdifTypes.Dict],
            data: Sequence[FlextCore.Types.T],
        ) -> FlextCore.Result[FlextLdifTypes.Dict]:
            """Analyze data using analyzer function with FlextCore.Result."""
            try:
                result = analyzer_func(data)
                return FlextCore.Result[FlextLdifTypes.Dict].ok(result)
            except Exception as e:
                return FlextCore.Result[FlextLdifTypes.Dict].fail(str(e))

    # =============================================================================
    # CACHING MIXINS - Caching and Performance Utilities
    # =============================================================================

    class CachingMixin(FlextCore.Mixins):
        """Mixin providing caching utilities with monadic composition."""

        @override
        def __init__(self) -> None:
            """Initialize caching mixin with empty cache and statistics."""
            super().__init__()
            self._init_service("flext_ldif_caching")

            # Enrich context with caching metadata
            self._enrich_context(
                mixin_type="caching",
                cache_enabled=True,
                statistics_tracking=True,
            )

            self._cache: FlextLdifTypes.Dict = {}
            self._cache_stats: dict[str, int] = {"hits": 0, "misses": 0}

        def get_from_cache(self, key: str) -> FlextCore.Result[object]:
            """Get value from cache with FlextCore.Result.

            Returns:
                FlextCore.Result[object]: Success with cached value or failure for cache miss

            """
            # Explicit FlextCore.Result handling - NO try/except for simple dict operations
            if key in self._cache:
                self._cache_stats["hits"] += 1
                return FlextCore.Result[object].ok(self._cache[key])
            self._cache_stats["misses"] += 1
            return FlextCore.Result[object].fail("Cache miss")

        def set_in_cache(self, key: str, value: object) -> FlextCore.Result[None]:
            """Set value in cache with FlextCore.Result.

            Returns:
                FlextCore.Result[None]: Success confirmation

            """
            # Explicit FlextCore.Result handling - NO try/except for simple dict operations
            self._cache[key] = value
            return FlextCore.Result[None].ok(None)

        def clear_cache(self) -> FlextCore.Result[None]:
            """Clear cache with FlextCore.Result.

            Returns:
                FlextCore.Result[None]: Success confirmation

            """
            # Explicit FlextCore.Result handling - NO try/except for simple dict operations
            self._cache.clear()
            self._cache_stats = {"hits": 0, "misses": 0}
            return FlextCore.Result[None].ok(None)

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

        def map(
            self, func: Callable[[object], FlextCore.Types.U]
        ) -> FlextCore.Result[FlextCore.Types.U]:
            """Map operation for monadic composition."""
            try:
                result = func(self)
                return FlextCore.Result[FlextCore.Types.U].ok(result)
            except Exception as e:
                return FlextCore.Result[FlextCore.Types.U].fail(str(e))

        def flat_map(
            self, func: Callable[[object], FlextCore.Result[FlextCore.Types.U]]
        ) -> FlextCore.Result[FlextCore.Types.U]:
            """Flat map operation for monadic composition."""
            try:
                return func(self)
            except Exception as e:
                return FlextCore.Result[FlextCore.Types.U].fail(str(e))

        def filter(
            self, predicate: Callable[[object], bool]
        ) -> FlextCore.Result[object]:
            """Filter operation for monadic composition."""
            try:
                if predicate(self):
                    return FlextCore.Result[object].ok(self)
                return FlextCore.Result[object].fail("Predicate failed")
            except Exception as e:
                return FlextCore.Result[object].fail(str(e))

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
        ) -> Iterator[FlextCore.Result[object]]:
            """Map iterator with FlextCore.Result."""
            for item in iterator:
                try:
                    result = func(item)
                    yield FlextCore.Result[object].ok(result)
                except Exception as e:
                    yield FlextCore.Result[object].fail(str(e))

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
            processor: Callable[[object], FlextCore.Result[object]],
        ) -> Iterator[FlextCore.Result[object]]:
            """Process iterator with FlextCore.Result."""
            for item in iterator:
                yield processor(item)

    # =============================================================================
    # UNIFIED MIXIN COORDINATOR - Centralized Mixin Management
    # =============================================================================

    class MixinCoordinator(FlextCore.Mixins):
        """Unified mixin coordinator managing all mixin functionality."""

        @override
        def __init__(self) -> None:
            """Initialize mixin coordinator with all available mixins."""
            super().__init__()
            self._init_service("flext_ldif_coordinator")

            # Enrich context with coordinator metadata
            self._enrich_context(
                coordinator_type="ldif_mixins",
                manages_mixins=True,
                mixin_count=6,  # validation, processing, transformation, analytics, caching, iterator
            )

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

        def combine_mixins(self, *mixins: type) -> FlextCore.Result[type]:
            """Combine multiple mixins into a single class.

            Returns:
                FlextCore.Result[type]: Success with combined class or failure

            """
            # Explicit FlextCore.Result handling - NO try/except for type() builtin
            # The type() builtin with valid arguments doesn't raise exceptions
            combined_class = type("CombinedMixin", tuple(mixins), {})
            return FlextCore.Result[type].ok(combined_class)


__all__ = ["FlextLdifMixins"]
