"""FLEXT LDIF Mixins - Advanced Mixin Classes with Monadic Composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Sequence

# Import centralized TypeVars from flext-core (FLEXT STANDARD)
from flext_core.typings import T, U

from flext_core import FlextMixins, FlextResult
from flext_ldif.constants import FlextLdifConstants


class FlextLdifMixins(FlextMixins):
    """LDIF domain mixins extending flext-core FlextMixins.

    Provides reusable functionality through mixin composition.
    Uses advanced patterns with monadic composition support.
    """

    # =============================================================================
    # VALIDATION MIXINS - Reusable Validation Logic
    # =============================================================================

    class ValidationMixin:
        """Mixin providing validation utilities with monadic composition."""

        @staticmethod
        def validate_dn_format(dn_value: str) -> str:
            """Validate DN format and return normalized value."""
            if not dn_value or not dn_value.strip():
                raise ValueError(FlextLdifConstants.ErrorMessages.DN_EMPTY_ERROR)

            # Basic DN format validation
            if not re.match(
                r"^[a-zA-Z][a-zA-Z0-9-]*=", dn_value.split(",", maxsplit=1)[0]
            ):
                raise ValueError(
                    FlextLdifConstants.ErrorMessages.DN_INVALID_FORMAT_ERROR
                )

            # Check for invalid characters
            invalid_chars = {"\n", "\r", "\0"}
            if any(char in dn_value for char in invalid_chars):
                raise ValueError(
                    FlextLdifConstants.ErrorMessages.DN_INVALID_CHARS_ERROR
                )

            return dn_value.strip()

        @staticmethod
        def validate_attribute_name(attr_name: str) -> str:
            """Validate attribute name format."""
            if not isinstance(attr_name, str):
                raise TypeError(FlextLdifConstants.ErrorMessages.ATTRIBUTE_NAME_ERROR)

            if not attr_name.strip():
                msg = "Attribute name cannot be empty"
                raise ValueError(msg)

            # RFC 4512 attribute name validation
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9-]*$", attr_name):
                msg = f"Invalid attribute name format: {attr_name}"
                raise ValueError(msg)

            return attr_name.strip()

        @staticmethod
        def validate_attribute_values(values: Sequence[str]) -> list[str]:
            """Validate attribute values."""
            if not isinstance(values, (list, tuple)):
                raise TypeError(FlextLdifConstants.ErrorMessages.ATTRIBUTE_VALUES_ERROR)

            validated_values: list[str] = []
            for value in values:
                if not isinstance(value, str):
                    raise TypeError(
                        FlextLdifConstants.ErrorMessages.ATTRIBUTE_VALUE_TYPE_ERROR
                    )
                validated_values.append(value.strip())

            return validated_values

        @staticmethod
        def validate_url_format(url: str) -> str:
            """Validate URL format for LDIF URL references."""
            if not url or not url.strip():
                msg = "URL cannot be empty"
                raise ValueError(msg)

            # Basic URL validation
            url_pattern = r"^https?://[^\s/$.?#].[^\s]*$"
            if not re.match(url_pattern, url):
                msg = f"Invalid URL format: {url}"
                raise ValueError(msg)

            return url.strip()

        @staticmethod
        def validate_encoding(encoding: str) -> str:
            """Validate character encoding."""
            if encoding not in FlextLdifConstants.Encoding.SUPPORTED_ENCODINGS:
                msg = f"Unsupported encoding: {encoding}"
                raise ValueError(msg)
            return encoding

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
        def normalize_dn_components(dn: str) -> str:
            """Normalize DN components."""
            components = [comp.strip() for comp in dn.split(",") if comp.strip()]
            normalized_components: list[str] = []

            for comp in components:
                if "=" in comp:
                    attr, value = comp.split("=", 1)
                    normalized_attr = attr.strip().lower()
                    normalized_value = value.strip()
                    component_str = f"{normalized_attr}={normalized_value}"
                    normalized_components.append(component_str)
                else:
                    normalized_components.append(comp)

            return ",".join(normalized_components)

        @staticmethod
        def extract_dn_components(dn: str) -> list[tuple[str, str]]:
            """Extract DN components as (attribute, value) pairs."""
            components = []
            for comp in dn.split(","):
                stripped_comp = comp.strip()
                if "=" in stripped_comp:
                    attr, value = stripped_comp.split("=", 1)
                    components.append((attr.strip(), value.strip()))
            return components

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
        ) -> list[str]:
            """Transform attribute values using transformer function."""
            return [transformer(value) for value in values]

        @staticmethod
        def transform_dn_case(dn: str, case_func: Callable[[str], str]) -> str:
            """Transform DN case using case function."""
            components: list[str] = []
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
                entry_type = getattr(entry, "entry_type", "unknown")
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
            """Analyze DN patterns."""
            pattern_counts: dict[str, int] = {}
            for entry in entries:
                dn = getattr(entry, "dn", "")
                if isinstance(dn, str):
                    for comp in dn.split(","):
                        stripped_comp = comp.strip()
                        if "=" in stripped_comp:
                            attr_name = stripped_comp.split("=")[0].lower()
                            pattern_counts[attr_name] = (
                                pattern_counts.get(attr_name, 0) + 1
                            )
            return pattern_counts

        @classmethod
        def analyze_with_result(
            cls,
            analyzer_func: Callable[[Sequence[T]], dict[str, object]],
            data: Sequence[T],
        ) -> FlextResult[dict[str, object]]:
            """Analyze data using analyzer function with FlextResult."""
            try:
                result = analyzer_func(data)
                return FlextResult[dict[str, object]].ok(result)
            except Exception as e:
                return FlextResult[dict[str, object]].fail(str(e))

    # =============================================================================
    # CACHING MIXINS - Caching and Performance Utilities
    # =============================================================================

    class CachingMixin:
        """Mixin providing caching utilities with monadic composition."""

        def __init__(self) -> None:
            """Initialize caching mixin with empty cache and statistics."""
            self._cache: dict[str, object] = {}
            self._cache_stats: dict[str, int] = {"hits": 0, "misses": 0}

        def get_from_cache(self, key: str) -> FlextResult[object]:
            """Get value from cache with FlextResult."""
            try:
                if key in self._cache:
                    self._cache_stats["hits"] += 1
                    return FlextResult[object].ok(self._cache[key])
                self._cache_stats["misses"] += 1
                return FlextResult[object].fail("Cache miss")
            except Exception as e:
                return FlextResult[object].fail(f"Cache error: {e}")

        def set_in_cache(self, key: str, value: object) -> FlextResult[None]:
            """Set value in cache with FlextResult."""
            try:
                self._cache[key] = value
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Cache error: {e}")

        def clear_cache(self) -> FlextResult[None]:
            """Clear cache with FlextResult."""
            try:
                self._cache.clear()
                self._cache_stats = {"hits": 0, "misses": 0}
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Cache error: {e}")

        def get_cache_stats(self) -> dict[str, int]:
            """Get cache statistics."""
            return self._cache_stats.copy()

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
            iterator: Iterator[object], func: Callable[[object], object]
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
            """Combine multiple mixins into a single class."""
            try:
                # Create a new class that inherits from all mixins
                combined_class = type("CombinedMixin", tuple(mixins), {})
                return FlextResult[type].ok(combined_class)
            except Exception as e:
                return FlextResult[type].fail(f"Mixin combination error: {e}")


__all__ = ["FlextLdifMixins"]
