"""Test suite for FlextLdifMixins."""

from collections.abc import Sequence
from typing import cast

import pytest
from tests.support import (
    LdifTestData,
)

from flext_ldif.mixins import FlextLdifMixins


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
        result = FlextLdifMixins.ValidationMixin.validate_attribute_values([
            "value1",
            "value2",
        ])
        assert result == ["value1", "value2"]

        # Invalid values - not a sequence
        with pytest.raises(TypeError):
            FlextLdifMixins.ValidationMixin.validate_attribute_values("not a list")

        # Invalid values - non-string value
        with pytest.raises(TypeError):
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
