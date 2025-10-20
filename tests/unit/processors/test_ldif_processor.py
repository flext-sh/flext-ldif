# pyright: reportArgumentType=false, reportOperatorIssue=false, reportOptionalMemberAccess=false
"""Comprehensive tests for LDIF batch and parallel processors.

This module provides complete test coverage for LDIF processors,
including:
- Batch processing with configurable batch sizes
- Parallel processing with configurable workers
- Error handling and edge cases
- Generic type support for return values
"""

from __future__ import annotations

from flext_ldif.models import FlextLdifModels
from flext_ldif.processors.ldif_processor import (
    LdifBatchProcessor,
    LdifParallelProcessor,
)


class TestLdifBatchProcessor:
    """Tests for LDIF batch processor."""

    def test_initialization_default(self) -> None:
        """Test batch processor initialization with defaults."""
        processor = LdifBatchProcessor()
        assert processor is not None
        assert isinstance(processor, LdifBatchProcessor)
        assert processor._batch_size == 100  # Default batch size

    def test_initialization_custom_batch_size(self) -> None:
        """Test batch processor with custom batch size."""
        processor = LdifBatchProcessor(batch_size=50)
        assert processor._batch_size == 50

    def test_process_batch_empty_entries(self) -> None:
        """Test batch processing with empty entries list."""
        processor = LdifBatchProcessor(batch_size=10)

        def extract_dn(entry: FlextLdifModels.Entry) -> str:
            return entry.dn.value

        result = processor.process_batch([], extract_dn)
        assert result.is_success
        results = result.unwrap()
        assert results == []

    def test_process_batch_single_entry(self) -> None:
        """Test batch processing with single entry."""
        processor = LdifBatchProcessor(batch_size=10)

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                    "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
                }
            ),
        )

        def extract_dn(entry: FlextLdifModels.Entry) -> str:
            return entry.dn.value

        result = processor.process_batch([entry], extract_dn)
        assert result.is_success
        results = result.unwrap()
        assert len(results) == 1
        assert results[0] == "cn=test,dc=example,dc=com"

    def test_process_batch_multiple_entries_single_batch(self) -> None:
        """Test batch processing with multiple entries in single batch."""
        processor = LdifBatchProcessor(batch_size=10)

        # Create 5 entries (less than batch size)
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value=f"cn=user{i},dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": FlextLdifModels.AttributeValues(values=[f"user{i}"]),
                        "objectClass": FlextLdifModels.AttributeValues(
                            values=["person"]
                        ),
                    }
                ),
            )
            for i in range(5)
        ]

        def extract_cn(entry: FlextLdifModels.Entry) -> str:
            cn_values = entry.attributes.attributes["cn"]
            return cn_values.values[0]

        result = processor.process_batch(entries, extract_cn)
        assert result.is_success
        results = result.unwrap()
        assert len(results) == 5
        assert results == ["user0", "user1", "user2", "user3", "user4"]

    def test_process_batch_multiple_batches(self) -> None:
        """Test batch processing with multiple batches."""
        processor = LdifBatchProcessor(batch_size=3)

        # Create 10 entries (will require 4 batches: 3, 3, 3, 1)
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value=f"cn=user{i},dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": FlextLdifModels.AttributeValues(values=[f"user{i}"]),
                        "objectClass": FlextLdifModels.AttributeValues(
                            values=["person"]
                        ),
                    }
                ),
            )
            for i in range(10)
        ]

        def count_attributes(entry: FlextLdifModels.Entry) -> int:
            return len(entry.attributes.attributes)

        result = processor.process_batch(entries, count_attributes)
        assert result.is_success
        results = result.unwrap()
        assert len(results) == 10
        assert all(
            count == 2 for count in results
        )  # Each entry has 2 attributes (cn, objectClass)

    def test_process_batch_exact_batch_boundary(self) -> None:
        """Test batch processing with exact batch size boundary."""
        processor = LdifBatchProcessor(batch_size=5)

        # Create exactly 10 entries (2 full batches)
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value=f"cn=user{i},dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": FlextLdifModels.AttributeValues(values=[f"user{i}"]),
                        "objectClass": FlextLdifModels.AttributeValues(
                            values=["person"]
                        ),
                    }
                ),
            )
            for i in range(10)
        ]

        def get_index(entry: FlextLdifModels.Entry) -> str:
            cn_values = entry.attributes.attributes["cn"]
            return cn_values.values[0]

        result = processor.process_batch(entries, get_index)
        assert result.is_success
        results = result.unwrap()
        assert len(results) == 10

    def test_process_batch_with_complex_return_type(self) -> None:
        """Test batch processing with complex return type (dict)."""
        processor = LdifBatchProcessor(batch_size=5)

        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value=f"cn=user{i},dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": FlextLdifModels.AttributeValues(values=[f"user{i}"]),
                        "mail": FlextLdifModels.AttributeValues(
                            values=[f"user{i}@example.com"]
                        ),
                        "objectClass": FlextLdifModels.AttributeValues(
                            values=["person"]
                        ),
                    }
                ),
            )
            for i in range(3)
        ]

        def extract_user_data(entry: FlextLdifModels.Entry) -> dict[str, str]:
            cn_values = entry.attributes.attributes["cn"]
            mail_values = entry.attributes.attributes["mail"]
            return {
                "cn": cn_values.values[0],
                "mail": mail_values.values[0],
            }

        result = processor.process_batch(entries, extract_user_data)
        assert result.is_success
        results = result.unwrap()
        assert len(results) == 3
        assert results[0]["cn"] == "user0"
        assert results[0]["mail"] == "user0@example.com"

    def test_process_batch_with_exception(self) -> None:
        """Test batch processing error handling."""
        processor = LdifBatchProcessor(batch_size=10)

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                    "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
                }
            ),
        )

        def failing_func(entry: FlextLdifModels.Entry) -> str:
            error_msg = "Test error"
            raise ValueError(error_msg)

        result = processor.process_batch([entry], failing_func)
        assert not result.is_success
        assert result.error is not None
        assert result.error is not None
        assert "Batch processing failed" in result.error
        assert result.error is not None
        assert "Test error" in result.error


class TestLdifParallelProcessor:
    """Tests for LDIF parallel processor."""

    def test_initialization_default(self) -> None:
        """Test parallel processor initialization with defaults."""
        processor = LdifParallelProcessor()
        assert processor is not None
        assert isinstance(processor, LdifParallelProcessor)
        assert processor._max_workers == 4  # Default workers

    def test_initialization_custom_workers(self) -> None:
        """Test parallel processor with custom worker count."""
        processor = LdifParallelProcessor(max_workers=8)
        assert processor._max_workers == 8

    def test_process_parallel_empty_entries(self) -> None:
        """Test parallel processing with empty entries list."""
        processor = LdifParallelProcessor(max_workers=2)

        def extract_dn(entry: FlextLdifModels.Entry) -> str:
            return entry.dn.value

        result = processor.process_parallel([], extract_dn)
        assert result.is_success
        results = result.unwrap()
        assert results == []

    def test_process_parallel_single_entry(self) -> None:
        """Test parallel processing with single entry."""
        processor = LdifParallelProcessor(max_workers=2)

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                    "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
                }
            ),
        )

        def extract_dn(entry: FlextLdifModels.Entry) -> str:
            return entry.dn.value

        result = processor.process_parallel([entry], extract_dn)
        assert result.is_success
        results = result.unwrap()
        assert len(results) == 1
        assert results[0] == "cn=test,dc=example,dc=com"

    def test_process_parallel_multiple_entries(self) -> None:
        """Test parallel processing with multiple entries."""
        processor = LdifParallelProcessor(max_workers=2)

        # Create 10 entries
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value=f"cn=user{i},dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": FlextLdifModels.AttributeValues(values=[f"user{i}"]),
                        "objectClass": FlextLdifModels.AttributeValues(
                            values=["person"]
                        ),
                    }
                ),
            )
            for i in range(10)
        ]

        def extract_cn(entry: FlextLdifModels.Entry) -> str:
            cn_values = entry.attributes.attributes["cn"]
            return cn_values.values[0]

        result = processor.process_parallel(entries, extract_cn)
        assert result.is_success
        results = result.unwrap()
        assert len(results) == 10
        # Results may be in different order due to parallel execution
        # Verify all expected values are present
        assert set(results) == {f"user{i}" for i in range(10)}

    def test_process_parallel_with_complex_return_type(self) -> None:
        """Test parallel processing with complex return type (dict)."""
        processor = LdifParallelProcessor(max_workers=4)

        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value=f"cn=user{i},dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": FlextLdifModels.AttributeValues(values=[f"user{i}"]),
                        "uid": FlextLdifModels.AttributeValues(values=[str(1000 + i)]),
                        "objectClass": FlextLdifModels.AttributeValues(
                            values=["person"]
                        ),
                    }
                ),
            )
            for i in range(5)
        ]

        def extract_user_info(entry: FlextLdifModels.Entry) -> dict[str, object]:
            cn_values = entry.attributes.attributes["cn"]
            uid_values = entry.attributes.attributes["uid"]
            return {
                "dn": entry.dn.value,
                "cn": cn_values.values[0],
                "uid": uid_values.values[0],
            }

        result = processor.process_parallel(entries, extract_user_info)
        assert result.is_success
        results = result.unwrap()
        assert len(results) == 5
        # Verify all expected values are present (order may vary due to parallel execution)
        cns = {r["cn"] for r in results}
        uids = {r["uid"] for r in results}
        assert cns == {f"user{i}" for i in range(5)}
        assert uids == {str(1000 + i) for i in range(5)}

    def test_process_parallel_model_dump(self) -> None:
        """Test parallel processing with model_dump (common use case)."""
        processor = LdifParallelProcessor(max_workers=2)

        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value=f"cn=user{i},dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": FlextLdifModels.AttributeValues(values=[f"user{i}"]),
                        "objectClass": FlextLdifModels.AttributeValues(
                            values=["person"]
                        ),
                    }
                ),
            )
            for i in range(3)
        ]

        def serialize_entry(entry: FlextLdifModels.Entry) -> dict[str, object]:
            return entry.model_dump()

        result = processor.process_parallel(entries, serialize_entry)
        assert result.is_success
        results = result.unwrap()
        assert len(results) == 3
        assert isinstance(results[0], dict)
        assert "dn" in results[0]
        assert "attributes" in results[0]

    def test_process_parallel_with_exception(self) -> None:
        """Test parallel processing error handling."""
        processor = LdifParallelProcessor(max_workers=2)

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                    "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
                }
            ),
        )

        def failing_func(entry: FlextLdifModels.Entry) -> str:
            error_msg = "Parallel processing error"
            raise RuntimeError(error_msg)

        result = processor.process_parallel([entry], failing_func)
        assert not result.is_success
        assert result.error is not None
        assert result.error is not None
        assert "Parallel processing failed" in result.error
        assert result.error is not None
        assert "Parallel processing error" in result.error

    def test_process_parallel_attribute_counting(self) -> None:
        """Test parallel processing with attribute counting."""
        processor = LdifParallelProcessor(max_workers=4)

        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value=f"cn=user{i},dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": FlextLdifModels.AttributeValues(values=[f"user{i}"]),
                        "objectClass": FlextLdifModels.AttributeValues(
                            values=["person"]
                        ),
                        "sn": FlextLdifModels.AttributeValues(values=[f"surname{i}"]),
                        "mail": FlextLdifModels.AttributeValues(
                            values=[f"user{i}@example.com"]
                        ),
                    }
                ),
            )
            for i in range(5)
        ]

        def count_attrs(entry: FlextLdifModels.Entry) -> int:
            return len(entry.attributes.attributes)

        result = processor.process_parallel(entries, count_attrs)
        assert result.is_success
        results = result.unwrap()
        assert len(results) == 5
        assert all(count == 4 for count in results)  # Each entry has 4 attributes


class TestProcessorComparison:
    """Tests comparing batch and parallel processors."""

    def test_batch_and_parallel_same_results(self) -> None:
        """Test that batch and parallel processors produce same results."""
        batch_processor = LdifBatchProcessor(batch_size=3)
        parallel_processor = LdifParallelProcessor(max_workers=2)

        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(
                    value=f"cn=user{i},dc=example,dc=com"
                ),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": FlextLdifModels.AttributeValues(values=[f"user{i}"]),
                        "objectClass": FlextLdifModels.AttributeValues(
                            values=["person"]
                        ),
                    }
                ),
            )
            for i in range(10)
        ]

        def extract_dn(entry: FlextLdifModels.Entry) -> str:
            return entry.dn.value

        batch_result = batch_processor.process_batch(entries, extract_dn)
        parallel_result = parallel_processor.process_parallel(entries, extract_dn)

        assert batch_result.is_success
        assert parallel_result.is_success

        batch_results = batch_result.unwrap()
        parallel_results = parallel_result.unwrap()

        # Both should produce same results, but parallel may be in different order
        assert set(batch_results) == set(parallel_results)
        assert len(batch_results) == len(parallel_results)
