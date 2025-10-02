"""Test suite for FlextLdifMixins."""

from collections.abc import Sequence
from typing import cast

import pytest
from flext_core import FlextResult

from flext_ldif.mixins import FlextLdifMixins
from tests.test_support.ldif_data import \
    LdifTestData  # type: ignore[import-not-found]


class TestFlextLdifAnalyticsMixin:
    """Test suite for FlextLdifMixins.AnalyticsMixin."""

    def test_count_entries_by_type(self) -> None:
        """Test counting entries by type."""
        # Create mock entries with different types
        entries = [
            type("Entry", (), {"type": "person"})(),
            type("Entry", (), {"type": "person"})(),
            type("Entry", (), {"type": "group"})(),
            type("Entry", (), {"entry_type": "organization"})(),
        ]

        result = FlextLdifMixins.AnalyticsMixin.count_entries_by_type(entries)

        assert isinstance(result, dict)
        assert result["person"] == 2
        assert result["group"] == 1
        assert result["organization"] == 1

    def test_calculate_attribute_frequency(self) -> None:
        """Test calculating attribute frequency."""
        # Create mock entries with attributes
        entries = [
            type("Entry", (), {"attributes": {"cn": ["test1"], "sn": ["test1"]}})(),
            type(
                "Entry",
                (),
                {"attributes": {"cn": ["test2"], "mail": ["test2@example.com"]}},
            )(),
            type("Entry", (), {"attributes": {"cn": ["test3"]}})(),
        ]

        result = FlextLdifMixins.AnalyticsMixin.calculate_attribute_frequency(entries)

        assert isinstance(result, dict)
        assert result["cn"] == 3
        assert result["sn"] == 1
        assert result["mail"] == 1

    def test_generate_analytics_report(self) -> None:
        """Test generating analytics report."""
        entries = [
            type("Entry", (), {"type": "person", "attributes": {"cn": ["test1"]}})(),
            type("Entry", (), {"type": "group", "attributes": {"cn": ["group1"]}})(),
        ]

        # Use the actual methods available
        type_counts = FlextLdifMixins.AnalyticsMixin.count_entries_by_type(entries)
        attr_freq = FlextLdifMixins.AnalyticsMixin.calculate_attribute_frequency(
            entries
        )

        assert isinstance(type_counts, dict)
        assert isinstance(attr_freq, dict)
        assert type_counts["person"] == 1
        assert type_counts["group"] == 1
        assert attr_freq["cn"] == 2

    def test_analyze_dn_patterns(self) -> None:
        """Test analyze_dn_patterns method (lines 248-263)."""
        # Create entries with various DNs to cover all branches
        entries = [
            type("Entry", (), {"dn": "cn=test1,ou=users,dc=example,dc=com"})(),
            type("Entry", (), {"dn": "cn=test2,ou=users,dc=example,dc=com"})(),
            type("Entry", (), {"dn": "invalid<>DN"})(),  # Invalid DN - line 261-263
            type("Entry", (), {"dn": ""})(),  # Empty DN
        ]

        result = FlextLdifMixins.AnalyticsMixin.analyze_dn_patterns(entries)

        assert isinstance(result, dict)
        # Valid DNs should contribute to pattern counts
        assert "cn" in result
        assert "ou" in result
        assert "dc" in result

    def test_analyze_with_result_success(self) -> None:
        """Test analyze_with_result with successful analysis (lines 272-274)."""

        def analyzer(data: Sequence[int]) -> dict[str, object]:
            return {"sum": sum(data), "count": len(data)}

        result = FlextLdifMixins.AnalyticsMixin.analyze_with_result(
            analyzer, [1, 2, 3, 4, 5]
        )

        assert result.is_success
        unwrapped = result.unwrap()
        assert unwrapped["sum"] == 15
        assert unwrapped["count"] == 5

    def test_analyze_with_result_error(self) -> None:
        """Test analyze_with_result with error (lines 272, 275-276)."""

        def error_analyzer(data: Sequence[int]) -> dict[str, object]:
            error_msg = "Analysis error"
            raise ValueError(error_msg)

        result = FlextLdifMixins.AnalyticsMixin.analyze_with_result(
            error_analyzer, [1, 2, 3]
        )

        assert result.is_failure
        assert result.error is not None
        assert "Analysis error" in result.error


class TestFlextLdifValidationMixin:
    """Test suite for FlextLdifMixins.ValidationMixin."""

    def test_validate_dn_format(self) -> None:
        """Test validating DN format."""
        # Valid DN
        result = FlextLdifMixins.ValidationMixin.validate_dn_format(
            "cn=test,dc=example,dc=com"
        )
        assert result == "cn=test,dc=example,dc=com"

        # Invalid DN - empty
        with pytest.raises(ValueError):
            FlextLdifMixins.ValidationMixin.validate_dn_format("")

        # Invalid DN - bad format
        with pytest.raises(ValueError):
            FlextLdifMixins.ValidationMixin.validate_dn_format("invalid-dn")

    def test_validate_attribute_name(self) -> None:
        """Test validating attribute name."""
        # Valid attribute name
        result = FlextLdifMixins.ValidationMixin.validate_attribute_name("cn")
        assert result == "cn"

        # Invalid attribute name - empty
        with pytest.raises(ValueError):
            FlextLdifMixins.ValidationMixin.validate_attribute_name("")

        # Invalid attribute name - bad format
        with pytest.raises(ValueError):
            FlextLdifMixins.ValidationMixin.validate_attribute_name("1cn")

    def test_validate_attribute_values(self) -> None:
        """Test validating attribute values."""
        # Valid values
        result = FlextLdifMixins.ValidationMixin.validate_attribute_values(
            [
                "value1",
                "value2",
            ]
        )
        assert result == ["value1", "value2"]

        # Invalid values - not a sequence
        with pytest.raises(TypeError):
            FlextLdifMixins.ValidationMixin.validate_attribute_values("not a list")

        # Invalid values - non-string value
        with pytest.raises(ValueError):
            FlextLdifMixins.ValidationMixin.validate_attribute_values(
                cast("Sequence[str]", [123])
            )

    def test_validate_url_format(self) -> None:
        """Test validating URL format."""
        # Valid URLs
        valid_urls = [
            "http://example.com",
            "https://example.com",
            "ldap://ldap.example.com",
        ]

        for url in valid_urls:
            result = FlextLdifMixins.ValidationMixin.validate_url_format(url)
            assert result == url

        # Invalid URL - empty
        with pytest.raises(ValueError):
            FlextLdifMixins.ValidationMixin.validate_url_format("")

        # Invalid URL - bad format
        with pytest.raises(ValueError):
            FlextLdifMixins.ValidationMixin.validate_url_format("not-a-url")


class TestFlextLdifProcessingMixin:
    """Test suite for FlextLdifMixins.ProcessingMixin."""

    def test_normalize_dn_components(self) -> None:
        """Test normalizing DN components."""
        # Test various DN scenarios
        test_cases = [
            ("CN=Test,DC=Example,DC=Com", "cn=Test,dc=Example,dc=Com"),
            ("cn=test, dc=example, dc=com", "cn=test,dc=example,dc=com"),
            ("  cn=test  ,  dc=example  ", "cn=test,dc=example"),
        ]

        for input_dn, expected in test_cases:
            result = FlextLdifMixins.ProcessingMixin.normalize_dn_components(input_dn)
            assert result == expected

    def test_extract_dn_components(self) -> None:
        """Test extracting DN components."""
        dn = "cn=test,dc=example,dc=com"
        result = FlextLdifMixins.ProcessingMixin.extract_dn_components(dn)

        assert len(result) == 3
        assert result[0] == ("cn", "test")
        assert result[1] == ("dc", "example")
        assert result[2] == ("dc", "com")

    def test_build_dn_from_components(self) -> None:
        """Test building DN from components."""
        components = [("cn", "test"), ("dc", "example"), ("dc", "com")]
        result = FlextLdifMixins.ProcessingMixin.build_dn_from_components(components)

        assert result == "cn=test,dc=example,dc=com"

    def test_process_with_result(self) -> None:
        """Test processing with result."""

        def test_processor(data: str) -> str:
            return data.upper()

        result = FlextLdifMixins.ProcessingMixin.process_with_result(
            test_processor, "test"
        )

        assert result.is_success
        assert result.value == "TEST"

    def test_process_with_result_error(self) -> None:
        """Test processing with result error handling."""

        def error_processor(_data: str) -> str:
            msg = "Test error"
            raise ValueError(msg)

        result = FlextLdifMixins.ProcessingMixin.process_with_result(
            error_processor, "test"
        )

        assert result.is_failure
        assert result.error is not None
        assert "Test error" in result.error

    def test_normalize_dn_components_invalid_dn(self) -> None:
        """Test normalize_dn_components with invalid DN (error path lines 117-118)."""
        # Invalid DN that will trigger ValueError and return original
        invalid_dn = "invalid<>DN"
        result = FlextLdifMixins.ProcessingMixin.normalize_dn_components(invalid_dn)
        assert result == invalid_dn  # Should return original on error

    def test_extract_dn_components_invalid_dn(self) -> None:
        """Test extract_dn_components with invalid DN (error path lines 132-133)."""
        # Invalid DN that will trigger ValueError and return empty list
        invalid_dn = "invalid<>DN"
        result = FlextLdifMixins.ProcessingMixin.extract_dn_components(invalid_dn)
        assert result == []  # Should return empty list on error

    def test_process_batch_with_result_error(self) -> None:
        """Test process_batch_with_result with error (lines 156-163)."""

        def error_processor(x: str) -> str:
            error_msg = "Batch processing error"
            raise ValueError(error_msg)

        data_batch = ["item1", "item2", "item3"]
        result = FlextLdifMixins.ProcessingMixin.process_batch_with_result(
            error_processor, data_batch
        )

        assert result.is_failure
        assert result.error is not None
        assert "Batch processing error" in result.error


class TestFlextLdifTransformationMixin:
    """Test suite for FlextLdifMixins.TransformationMixin."""

    def test_transform_attribute_values(self) -> None:
        """Test transforming attribute values."""
        values = ["test1", "test2", "test3"]

        result = FlextLdifMixins.TransformationMixin.transform_attribute_values(
            values, lambda x: x.upper()
        )

        assert result == ["TEST1", "TEST2", "TEST3"]

    def test_transform_dn_case(self) -> None:
        """Test transforming DN case."""
        dn = "CN=Test,DC=Example,DC=Com"

        result = FlextLdifMixins.TransformationMixin.transform_dn_case(dn, str.lower)

        assert result == "cn=Test,dc=Example,dc=Com"

    def test_map_attributes(self) -> None:
        """Test mapping attributes."""
        attributes: dict[str, Sequence[str]] = {
            "CN": ["Test User"],
            "sn": ["User"],
            "mail": ["test@example.com"],
        }

        def mapper(attr_name: str, values: Sequence[str]) -> tuple[str, Sequence[str]]:
            return attr_name.lower(), values

        result = FlextLdifMixins.TransformationMixin.map_attributes(attributes, mapper)

        assert isinstance(result, dict)
        assert "cn" in result
        assert "sn" in result
        assert "mail" in result

    def test_transform_dn_case_with_invalid_component(self) -> None:
        """Test transform_dn_case with component without '=' (line 191)."""
        # DN component without '=' should be preserved as-is
        dn = "CN=Test,invalidcomponent,DC=Com"
        result = FlextLdifMixins.TransformationMixin.transform_dn_case(dn, str.lower)
        # Invalid component should be preserved
        assert "invalidcomponent" in result

    def test_transform_with_result_error(self) -> None:
        """Test transform_with_result with error (lines 211-215)."""

        def error_transformer(x: str) -> str:
            error_msg = "Transform error"
            raise ValueError(error_msg)

        result = FlextLdifMixins.TransformationMixin.transform_with_result(
            error_transformer, "test"
        )

        assert result.is_failure
        assert result.error is not None
        assert "Transform error" in result.error


class TestFlextLdifCachingMixin:
    """Test suite for FlextLdifMixins.CachingMixin."""

    def test_initialization(self) -> None:
        """Test mixin initialization."""
        mixin = FlextLdifMixins.CachingMixin()
        assert mixin is not None
        assert hasattr(mixin, "_cache")

    def test_get_from_cache(self) -> None:
        """Test getting from cache."""
        mixin = FlextLdifMixins.CachingMixin()

        # Cache should be empty initially
        result = mixin.get_from_cache("nonexistent")
        assert result.is_failure

    def test_set_in_cache(self) -> None:
        """Test setting in cache."""
        mixin = FlextLdifMixins.CachingMixin()

        result = mixin.set_in_cache("test_key", "test_value")
        assert result.is_success

    def test_clear_cache(self) -> None:
        """Test clearing cache."""
        mixin = FlextLdifMixins.CachingMixin()

        # Set something in cache
        mixin.set_in_cache("test_key", "test_value")

        # Clear cache
        result = mixin.clear_cache()
        assert result.is_success

    def test_get_cache_stats(self) -> None:
        """Test getting cache statistics."""
        mixin = FlextLdifMixins.CachingMixin()

        stats = mixin.get_cache_stats()
        assert isinstance(stats, dict)
        assert "size" in stats
        assert "hits" in stats
        assert "misses" in stats

    def test_get_from_cache_hit(self) -> None:
        """Test cache hit path (lines 295-296)."""
        mixin = FlextLdifMixins.CachingMixin()

        # Set a value first
        mixin.set_in_cache("key1", "value1")

        # Get it back - should hit cache (lines 295-296)
        result = mixin.get_from_cache("key1")
        assert result.is_success
        assert result.unwrap() == "value1"

        # Check stats show a hit
        stats = mixin.get_cache_stats()
        assert stats["hits"] >= 1


class TestFlextLdifIteratorMixin:
    """Test suite for FlextLdifMixins.IteratorMixin."""

    def test_map_iterator(self) -> None:
        """Test map_iterator operation."""
        # Test with a simple iterator
        test_data = ["test1", "test2", "test3"]
        iterator = iter(test_data)

        # Test mapping
        results = list(
            FlextLdifMixins.IteratorMixin.map_iterator(
                iterator, lambda x: str(x).upper()
            )
        )

        assert len(results) == 3
        assert all(result.is_success for result in results)
        assert results[0].value == "TEST1"

    def test_filter_iterator(self) -> None:
        """Test filter_iterator operation."""
        # Test with a simple iterator
        test_data = ["", "test1", "", "test2"]
        iterator = iter(test_data)

        # Test filtering
        results = list(
            FlextLdifMixins.IteratorMixin.filter_iterator(
                iterator, lambda x: len(str(x)) > 0
            )
        )

        assert len(results) == 2
        assert results[0] == "test1"
        assert results[1] == "test2"

    def test_fold_iterator(self) -> None:
        """Test fold_iterator operation."""
        # Test with a simple iterator
        test_data = ["a", "b", "c"]
        iterator = iter(test_data)

        # Test folding
        def fold_func(acc: object, x: object) -> object:
            return str(acc) + str(x)

        result = FlextLdifMixins.IteratorMixin.fold_iterator(iterator, "", fold_func)

        assert result == "abc"

    def test_iterator_with_error_handling(self) -> None:
        """Test iterator with error handling."""
        # Test with an iterator that causes actual errors
        test_data = ["test1", "test2", "test3"]
        iterator = iter(test_data)

        # Test mapping with a function that raises an exception
        def error_function(x: str) -> str:
            if x == "test2":
                msg = "Test error"
                raise ValueError(msg)
            return x.upper()

        results = list(
            FlextLdifMixins.IteratorMixin.map_iterator(iterator, error_function)
        )

        assert len(results) == 3
        assert results[0].is_success
        assert results[0].value == "TEST1"
        assert results[1].is_failure  # Should fail for test2
        assert results[1].error is not None
        assert "Test error" in results[1].error
        assert results[2].is_success
        assert results[2].value == "TEST3"


class TestFlextLdifMixinsIntegration:
    """Integration tests for all mixins working together."""

    def test_static_mixins_working_together(self) -> None:
        """Test static mixins working together."""
        # Test analytics with validation
        entries = [
            type("Entry", (), {"type": "person", "attributes": {"cn": ["test1"]}})(),
            type("Entry", (), {"type": "group", "attributes": {"cn": ["group1"]}})(),
        ]

        # Use analytics mixin
        analytics_result = FlextLdifMixins.AnalyticsMixin.count_entries_by_type(entries)
        assert analytics_result["person"] == 1
        assert analytics_result["group"] == 1

        # Use validation mixin
        valid_dn = FlextLdifMixins.ValidationMixin.validate_dn_format(
            "cn=test,dc=example,dc=com"
        )
        assert valid_dn == "cn=test,dc=example,dc=com"

        # Use processing mixin
        normalized = FlextLdifMixins.ProcessingMixin.normalize_dn_components(
            "CN=Test,DC=Example,DC=Com"
        )
        assert normalized == "cn=Test,dc=Example,dc=Com"

    def test_instance_mixins_working_together(self) -> None:
        """Test instance mixins working together."""

        # Create a class that uses instance mixins
        class TestService(
            FlextLdifMixins.CachingMixin,
        ):
            def __init__(self) -> None:
                super().__init__()

        service = TestService()

        # Test caching
        result = service.set_in_cache("test_key", "test_value")
        assert result.is_success

        # Test cache stats
        stats = service.get_cache_stats()
        assert isinstance(stats, dict)

    def test_mixins_with_real_data(self) -> None:
        """Test mixins with real LDIF data."""
        sample = LdifTestData.basic_entries()

        # Use processing mixin to normalize DN components
        # Extract DN from content
        lines = sample.content.split("\n")
        dn_line = next((line for line in lines if line.startswith("dn:")), None)
        if dn_line:
            dn_value = dn_line[3:].strip()  # Remove 'dn:' prefix
            normalized_dn = FlextLdifMixins.ProcessingMixin.normalize_dn_components(
                dn_value
            )
            assert isinstance(normalized_dn, str)

        # Use validation mixin to validate DN format
        # Extract DN from content
        lines = sample.content.split("\n")
        dn_line = next((line for line in lines if line.startswith("dn:")), None)
        if dn_line:
            dn_value = dn_line[3:].strip()  # Remove 'dn:' prefix
            valid_dn = FlextLdifMixins.ValidationMixin.validate_dn_format(dn_value)
            assert valid_dn == dn_value

        # Use analytics mixin to analyze content
        # Create mock entries from the content
        mock_entries = [
            type("Entry", (), {"type": "person", "attributes": {"cn": ["test"]}})()
        ]
        analytics_result = FlextLdifMixins.AnalyticsMixin.count_entries_by_type(
            mock_entries
        )
        assert analytics_result["person"] >= 1

    # =========================================================================
    # COVERAGE IMPROVEMENT TESTS - Missing Lines (93 lines)
    # =========================================================================

    def test_validate_encoding_with_model(self) -> None:
        """Test validate_encoding using Model validation (lines 86-90)."""
        # Valid encoding
        result = FlextLdifMixins.ValidationMixin.validate_encoding("utf-8")
        assert result == "utf-8"

        # Invalid encoding should raise ValueError
        with pytest.raises(ValueError):
            FlextLdifMixins.ValidationMixin.validate_encoding("invalid-encoding")

    def test_validate_with_result_success(self) -> None:
        """Test validate_with_result with successful validation (lines 97-99)."""

        def validate_positive(x: int) -> int:
            if x > 0:
                return x
            error_msg = "Must be positive"
            raise ValueError(error_msg)

        result = FlextLdifMixins.ValidationMixin.validate_with_result(
            validate_positive, 5
        )
        assert result.is_success
        assert result.unwrap() == 5

    def test_validate_with_result_error(self) -> None:
        """Test validate_with_result with validation error (lines 100-101)."""

        def validate_positive(x: int) -> int:
            if x > 0:
                return x
            error_msg = "Must be positive"
            raise ValueError(error_msg)

        result = FlextLdifMixins.ValidationMixin.validate_with_result(
            validate_positive, -5
        )
        assert result.is_failure
        assert "positive" in str(result.error).lower()

    def test_caching_mixin_clear_cache_error_handling(self) -> None:
        """Test clear_cache success path and error handling."""
        cache = FlextLdifMixins.CachingMixin()

        # Add data to cache
        cache.set_in_cache("key1", "value1")
        cache.set_in_cache("key2", "value2")

        # Verify cache has data
        stats = cache.get_cache_stats()
        assert stats["size"] == 2

        # Clear cache successfully
        result = cache.clear_cache()
        assert result.is_success

        # Verify cache is empty after clear
        stats = cache.get_cache_stats()
        assert stats["size"] == 0
        assert stats["hits"] == 0
        assert stats["misses"] == 0

    def test_iterator_mixin_process_iterator_with_result(self) -> None:
        """Test process_iterator_with_result method."""
        data = [1, 2, 3, 4, 5]
        data_iter = iter(data)

        def processor(x: object) -> FlextResult[object]:
            if isinstance(x, int) and x > 0:
                return FlextResult[object].ok(x * 2)
            return FlextResult[object].fail("Invalid value")

        results = list(
            FlextLdifMixins.IteratorMixin.process_iterator_with_result(
                data_iter, processor
            )
        )
        assert len(results) == 5
        assert all(r.is_success for r in results)
        assert results[0].unwrap() == 2
        assert results[4].unwrap() == 10

    def test_mixin_coordinator_combine_mixins(self) -> None:
        """Test combine_mixins method."""
        coordinator = FlextLdifMixins.MixinCoordinator()

        # Test combining mixins
        result = coordinator.combine_mixins(
            FlextLdifMixins.ValidationMixin, FlextLdifMixins.ProcessingMixin
        )
        assert result.is_success
        combined_class = result.unwrap()
        assert combined_class is not None

    def test_mixin_coordinator_get_mixins(self) -> None:
        """Test all get_*_mixin methods."""
        coordinator = FlextLdifMixins.MixinCoordinator()

        # Test all getter methods
        assert coordinator.get_validation_mixin() is not None
        assert coordinator.get_processing_mixin() is not None
        assert coordinator.get_transformation_mixin() is not None
        assert coordinator.get_analytics_mixin() is not None
        assert coordinator.get_caching_mixin() is not None
        assert coordinator.get_iterator_mixin() is not None
