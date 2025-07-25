"""Tests for FlextLdif domain events."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from flext_ldif import (
    FlextLdifDocumentParsed,
    FlextLdifEntryValidated,
    FlextLdifFilterApplied,
    FlextLdifProcessingCompleted,
    FlextLdifTransformationApplied,
    FlextLdifValidationFailed,
    FlextLdifWriteCompleted,
)


class TestFlextLdifDocumentParsed:
    """Test FlextLdifDocumentParsed domain event."""

    def test_valid_event_creation(self) -> None:
        """Test creating a valid document parsed event."""
        event = FlextLdifDocumentParsed.model_validate(
            {
                "aggregate_id": "doc-123",
                "entry_count": 50,
                "content_length": 1024,
                "parsing_time_ms": 150.5,
            },
        )
        assert event.aggregate_id == "doc-123"
        assert event.entry_count == 50
        assert event.content_length == 1024
        assert event.parsing_time_ms == 150.5

    def test_valid_event_without_parsing_time(self) -> None:
        """Test creating event without parsing time."""
        event = FlextLdifDocumentParsed.model_validate(
            {"aggregate_id": "doc-456", "entry_count": 25, "content_length": 512},
        )
        assert event.aggregate_id == "doc-456"
        assert event.entry_count == 25
        assert event.content_length == 512
        assert event.parsing_time_ms is None

    def test_validate_domain_rules_valid(self) -> None:
        """Test domain rules validation with valid data."""
        event = FlextLdifDocumentParsed.model_validate(
            {"aggregate_id": "doc-123", "entry_count": 50, "content_length": 1024},
        )
        # Should not raise
        event.validate_domain_rules()

    def test_validate_domain_rules_empty_aggregate_id(self) -> None:
        """Test domain rules validation with empty aggregate_id."""
        event = FlextLdifDocumentParsed.model_validate(
            {"aggregate_id": "", "entry_count": 50, "content_length": 1024},
        )
        with pytest.raises(ValueError, match="aggregate_id must be a non-empty string"):
            event.validate_domain_rules()

    def test_validate_domain_rules_negative_entry_count(self) -> None:
        """Test domain rules validation with negative entry count."""
        event = FlextLdifDocumentParsed.model_validate(
            {"aggregate_id": "doc-123", "entry_count": -1, "content_length": 1024},
        )
        with pytest.raises(ValueError, match="entry_count must be non-negative"):
            event.validate_domain_rules()

    def test_validate_domain_rules_negative_content_length(self) -> None:
        """Test domain rules validation with negative content length."""
        event = FlextLdifDocumentParsed.model_validate(
            {"aggregate_id": "doc-123", "entry_count": 50, "content_length": -1},
        )
        with pytest.raises(ValueError, match="content_length must be non-negative"):
            event.validate_domain_rules()

    def test_zero_values_allowed(self) -> None:
        """Test that zero values are allowed."""
        event = FlextLdifDocumentParsed.model_validate(
            {
                "aggregate_id": "doc-empty",
                "entry_count": 0,
                "content_length": 0,
            },
        )
        # Should not raise
        event.validate_domain_rules()


class TestFlextLdifEntryValidated:
    """Test FlextLdifEntryValidated domain event."""

    def test_valid_event_creation(self) -> None:
        """Test creating a valid entry validated event."""
        event = FlextLdifEntryValidated.model_validate(
            {
                "aggregate_id": "entry-123",
                "entry_dn": "cn=test,dc=example,dc=com",
                "is_valid": True,
                "validation_errors": ["Error 1", "Error 2"],
            },
        )
        assert event.aggregate_id == "entry-123"
        assert event.entry_dn == "cn=test,dc=example,dc=com"
        assert event.is_valid is True
        assert event.validation_errors == ["Error 1", "Error 2"]

    def test_valid_event_without_errors(self) -> None:
        """Test creating event without validation errors."""
        event = FlextLdifEntryValidated.model_validate(
            {
                "aggregate_id": "entry-456",
                "entry_dn": "cn=user,dc=test,dc=com",
                "is_valid": True,
            },
        )
        assert event.aggregate_id == "entry-456"
        assert event.entry_dn == "cn=user,dc=test,dc=com"
        assert event.is_valid is True
        assert event.validation_errors == []

    def test_validate_domain_rules_valid(self) -> None:
        """Test domain rules validation with valid data."""
        event = FlextLdifEntryValidated.model_validate(
            {
                "aggregate_id": "entry-123",
                "entry_dn": "cn=test,dc=example,dc=com",
                "is_valid": True,
            },
        )
        # Should not raise
        event.validate_domain_rules()

    def test_validate_domain_rules_empty_aggregate_id(self) -> None:
        """Test domain rules validation with empty aggregate_id."""
        event = FlextLdifEntryValidated.model_validate(
            {
                "aggregate_id": "",
                "entry_dn": "cn=test,dc=example,dc=com",
                "is_valid": True,
            },
        )
        with pytest.raises(ValueError, match="aggregate_id must be a non-empty string"):
            event.validate_domain_rules()

    def test_validate_domain_rules_empty_entry_dn(self) -> None:
        """Test domain rules validation with empty entry_dn."""
        event = FlextLdifEntryValidated.model_validate(
            {"aggregate_id": "entry-123", "entry_dn": "", "is_valid": True},
        )
        with pytest.raises(ValueError, match="entry_dn must be a non-empty string"):
            event.validate_domain_rules()

    def test_invalid_event_creation(self) -> None:
        """Test creating an invalid entry event."""
        event = FlextLdifEntryValidated.model_validate(
            {
                "aggregate_id": "entry-invalid",
                "entry_dn": "cn=invalid,dc=test,dc=com",
                "is_valid": False,
                "validation_errors": ["Missing objectClass", "Invalid DN format"],
            },
        )
        assert event.is_valid is False
        assert len(event.validation_errors) == 2


class TestFlextLdifProcessingCompleted:
    """Test FlextLdifProcessingCompleted domain event."""

    def test_valid_event_creation(self) -> None:
        """Test creating a valid processing completed event."""
        event = FlextLdifProcessingCompleted.model_validate(
            {
                "aggregate_id": "proc-123",
                "entry_count": 100,
                "success": True,
                "processing_time_ms": 250.0,
                "errors": [],
            },
        )
        assert event.aggregate_id == "proc-123"
        assert event.entry_count == 100
        assert event.success is True
        assert event.processing_time_ms == 250.0
        assert event.errors == []

    def test_failed_processing_event(self) -> None:
        """Test creating a failed processing event."""
        event = FlextLdifProcessingCompleted.model_validate(
            {
                "aggregate_id": "proc-failed",
                "entry_count": 25,
                "success": False,
                "errors": ["Parse error", "Validation failed"],
            },
        )
        assert event.success is False
        assert len(event.errors) == 2

    def test_validate_domain_rules_valid(self) -> None:
        """Test domain rules validation with valid data."""
        event = FlextLdifProcessingCompleted.model_validate(
            {"aggregate_id": "proc-123", "entry_count": 100, "success": True},
        )
        # Should not raise
        event.validate_domain_rules()

    def test_validate_domain_rules_empty_aggregate_id(self) -> None:
        """Test domain rules validation with empty aggregate_id."""
        event = FlextLdifProcessingCompleted.model_validate(
            {"aggregate_id": "", "entry_count": 100, "success": True},
        )
        with pytest.raises(ValueError, match="aggregate_id must be a non-empty string"):
            event.validate_domain_rules()

    def test_validate_domain_rules_negative_entry_count(self) -> None:
        """Test domain rules validation with negative entry count."""
        event = FlextLdifProcessingCompleted.model_validate(
            {"aggregate_id": "proc-123", "entry_count": -5, "success": True},
        )
        with pytest.raises(ValueError, match="entry_count must be non-negative"):
            event.validate_domain_rules()


class TestFlextLdifWriteCompleted:
    """Test FlextLdifWriteCompleted domain event."""

    def test_valid_event_creation(self) -> None:
        """Test creating a valid write completed event."""
        event = FlextLdifWriteCompleted.model_validate(
            {
                "aggregate_id": "write-123",
                "output_path": str(Path(tempfile.gettempdir()) / "output.ldif"),
                "entry_count": 75,
                "bytes_written": 2048,
            },
        )
        assert event.aggregate_id == "write-123"
        assert event.output_path == str(Path(tempfile.gettempdir()) / "output.ldif")
        assert event.entry_count == 75
        assert event.bytes_written == 2048

    def test_validate_domain_rules_valid(self) -> None:
        """Test domain rules validation with valid data."""
        event = FlextLdifWriteCompleted.model_validate(
            {
                "aggregate_id": "write-123",
                "output_path": str(Path(tempfile.gettempdir()) / "output.ldif"),
                "entry_count": 75,
                "bytes_written": 2048,
            },
        )
        # Should not raise
        event.validate_domain_rules()

    def test_validate_domain_rules_empty_aggregate_id(self) -> None:
        """Test domain rules validation with empty aggregate_id."""
        event = FlextLdifWriteCompleted.model_validate(
            {
                "aggregate_id": "",
                "output_path": str(Path(tempfile.gettempdir()) / "output.ldif"),
                "entry_count": 75,
                "bytes_written": 2048,
            },
        )
        with pytest.raises(ValueError, match="aggregate_id must be a non-empty string"):
            event.validate_domain_rules()

    def test_validate_domain_rules_empty_output_path(self) -> None:
        """Test domain rules validation with empty output path."""
        event = FlextLdifWriteCompleted.model_validate(
            {
                "aggregate_id": "write-123",
                "output_path": "",
                "entry_count": 75,
                "bytes_written": 2048,
            },
        )
        with pytest.raises(ValueError, match="output_path must be a non-empty string"):
            event.validate_domain_rules()

    def test_validate_domain_rules_negative_entry_count(self) -> None:
        """Test domain rules validation with negative entry count."""
        event = FlextLdifWriteCompleted.model_validate(
            {
                "aggregate_id": "write-123",
                "output_path": str(Path(tempfile.gettempdir()) / "output.ldif"),
                "entry_count": -1,
                "bytes_written": 2048,
            },
        )
        with pytest.raises(ValueError, match="entry_count must be non-negative"):
            event.validate_domain_rules()

    def test_validate_domain_rules_negative_bytes_written(self) -> None:
        """Test domain rules validation with negative bytes written."""
        event = FlextLdifWriteCompleted.model_validate(
            {
                "aggregate_id": "write-123",
                "output_path": str(Path(tempfile.gettempdir()) / "output.ldif"),
                "entry_count": 75,
                "bytes_written": -1,
            },
        )
        with pytest.raises(ValueError, match="bytes_written must be non-negative"):
            event.validate_domain_rules()

    def test_zero_values_allowed(self) -> None:
        """Test that zero values are allowed."""
        event = FlextLdifWriteCompleted.model_validate(
            {
                "aggregate_id": "write-empty",
                "output_path": str(Path(tempfile.gettempdir()) / "empty.ldif"),
                "entry_count": 0,
                "bytes_written": 0,
            },
        )
        # Should not raise
        event.validate_domain_rules()


class TestFlextLdifTransformationApplied:
    """Test FlextLdifTransformationApplied domain event."""

    def test_valid_event_creation(self) -> None:
        """Test creating a valid transformation applied event."""
        event = FlextLdifTransformationApplied.model_validate(
            {
                "aggregate_id": "transform-123",
                "transformation_type": "normalize_attributes",
                "entries_affected": 30,
                "transformation_rules": {"rule1": "value1", "rule2": "value2"},
            },
        )
        assert event.aggregate_id == "transform-123"
        assert event.transformation_type == "normalize_attributes"
        assert event.entries_affected == 30
        assert event.transformation_rules == {"rule1": "value1", "rule2": "value2"}

    def test_valid_event_without_rules(self) -> None:
        """Test creating event without transformation rules."""
        event = FlextLdifTransformationApplied.model_validate(
            {
                "aggregate_id": "transform-456",
                "transformation_type": "filter_entries",
                "entries_affected": 15,
            },
        )
        assert event.aggregate_id == "transform-456"
        assert event.transformation_type == "filter_entries"
        assert event.entries_affected == 15
        assert event.transformation_rules == {}

    def test_validate_domain_rules_valid(self) -> None:
        """Test domain rules validation with valid data."""
        event = FlextLdifTransformationApplied.model_validate(
            {
                "aggregate_id": "transform-123",
                "transformation_type": "normalize_attributes",
                "entries_affected": 30,
            },
        )
        # Should not raise
        event.validate_domain_rules()

    def test_validate_domain_rules_empty_aggregate_id(self) -> None:
        """Test domain rules validation with empty aggregate_id."""
        event = FlextLdifTransformationApplied.model_validate(
            {
                "aggregate_id": "",
                "transformation_type": "normalize_attributes",
                "entries_affected": 30,
            },
        )
        with pytest.raises(ValueError, match="aggregate_id must be a non-empty string"):
            event.validate_domain_rules()

    def test_validate_domain_rules_empty_transformation_type(self) -> None:
        """Test domain rules validation with empty transformation type."""
        event = FlextLdifTransformationApplied.model_validate(
            {
                "aggregate_id": "transform-123",
                "transformation_type": "",
                "entries_affected": 30,
            },
        )
        with pytest.raises(
            ValueError,
            match="transformation_type must be a non-empty string",
        ):
            event.validate_domain_rules()

    def test_validate_domain_rules_negative_entries_affected(self) -> None:
        """Test domain rules validation with negative entries affected."""
        event = FlextLdifTransformationApplied.model_validate(
            {
                "aggregate_id": "transform-123",
                "transformation_type": "normalize_attributes",
                "entries_affected": -5,
            },
        )
        with pytest.raises(ValueError, match="entries_affected must be non-negative"):
            event.validate_domain_rules()

    def test_zero_entries_affected_allowed(self) -> None:
        """Test that zero entries affected is allowed."""
        event = FlextLdifTransformationApplied.model_validate(
            {
                "aggregate_id": "transform-none",
                "transformation_type": "no_op",
                "entries_affected": 0,
            },
        )
        # Should not raise
        event.validate_domain_rules()


class TestFlextLdifValidationFailed:
    """Test FlextLdifValidationFailed domain event."""

    def test_valid_event_creation(self) -> None:
        """Test creating a valid validation failed event."""
        event = FlextLdifValidationFailed.model_validate(
            {
                "aggregate_id": "validation-123",
                "entry_dn": "cn=invalid,dc=test,dc=com",
                "error_message": "Missing required objectClass attribute",
                "error_code": "MISSING_OBJECTCLASS",
            },
        )
        assert event.aggregate_id == "validation-123"
        assert event.entry_dn == "cn=invalid,dc=test,dc=com"
        assert event.error_message == "Missing required objectClass attribute"
        assert event.error_code == "MISSING_OBJECTCLASS"

    def test_valid_event_without_entry_dn_and_error_code(self) -> None:
        """Test creating event without entry DN and error code."""
        event = FlextLdifValidationFailed.model_validate(
            {
                "aggregate_id": "validation-456",
                "error_message": "General validation error",
            },
        )
        assert event.aggregate_id == "validation-456"
        assert event.entry_dn is None
        assert event.error_message == "General validation error"
        assert event.error_code is None

    def test_validate_domain_rules_valid(self) -> None:
        """Test domain rules validation with valid data."""
        event = FlextLdifValidationFailed.model_validate(
            {
                "aggregate_id": "validation-123",
                "error_message": "Validation error occurred",
            },
        )
        # Should not raise
        event.validate_domain_rules()

    def test_validate_domain_rules_empty_aggregate_id(self) -> None:
        """Test domain rules validation with empty aggregate_id."""
        event = FlextLdifValidationFailed.model_validate(
            {"aggregate_id": "", "error_message": "Validation error occurred"},
        )
        with pytest.raises(ValueError, match="aggregate_id must be a non-empty string"):
            event.validate_domain_rules()

    def test_validate_domain_rules_empty_error_message(self) -> None:
        """Test domain rules validation with empty error message."""
        event = FlextLdifValidationFailed.model_validate(
            {"aggregate_id": "validation-123", "error_message": ""},
        )
        with pytest.raises(
            ValueError,
            match="error_message must be a non-empty string",
        ):
            event.validate_domain_rules()


class TestFlextLdifFilterApplied:
    """Test FlextLdifFilterApplied domain event."""

    def test_valid_event_creation(self) -> None:
        """Test creating a valid filter applied event."""
        event = FlextLdifFilterApplied.model_validate(
            {
                "aggregate_id": "filter-123",
                "filter_criteria": "objectClass=person",
                "entries_matched": 45,
                "total_entries": 100,
            },
        )
        assert event.aggregate_id == "filter-123"
        assert event.filter_criteria == "objectClass=person"
        assert event.entries_matched == 45
        assert event.total_entries == 100

    def test_validate_domain_rules_valid(self) -> None:
        """Test domain rules validation with valid data."""
        event = FlextLdifFilterApplied.model_validate(
            {
                "aggregate_id": "filter-123",
                "filter_criteria": "objectClass=person",
                "entries_matched": 45,
                "total_entries": 100,
            },
        )
        # Should not raise
        event.validate_domain_rules()

    def test_validate_domain_rules_empty_aggregate_id(self) -> None:
        """Test domain rules validation with empty aggregate_id."""
        event = FlextLdifFilterApplied.model_validate(
            {
                "aggregate_id": "",
                "filter_criteria": "objectClass=person",
                "entries_matched": 45,
                "total_entries": 100,
            },
        )
        with pytest.raises(ValueError, match="aggregate_id must be a non-empty string"):
            event.validate_domain_rules()

    def test_validate_domain_rules_empty_filter_criteria(self) -> None:
        """Test domain rules validation with empty filter criteria."""
        event = FlextLdifFilterApplied.model_validate(
            {
                "aggregate_id": "filter-123",
                "filter_criteria": "",
                "entries_matched": 45,
                "total_entries": 100,
            },
        )
        with pytest.raises(
            ValueError,
            match="filter_criteria must be a non-empty string",
        ):
            event.validate_domain_rules()

    def test_validate_domain_rules_negative_entries_matched(self) -> None:
        """Test domain rules validation with negative entries matched."""
        event = FlextLdifFilterApplied.model_validate(
            {
                "aggregate_id": "filter-123",
                "filter_criteria": "objectClass=person",
                "entries_matched": -1,
                "total_entries": 100,
            },
        )
        with pytest.raises(ValueError, match="entries_matched must be non-negative"):
            event.validate_domain_rules()

    def test_validate_domain_rules_negative_total_entries(self) -> None:
        """Test domain rules validation with negative total entries."""
        event = FlextLdifFilterApplied.model_validate(
            {
                "aggregate_id": "filter-123",
                "filter_criteria": "objectClass=person",
                "entries_matched": 45,
                "total_entries": -1,
            },
        )
        with pytest.raises(ValueError, match="total_entries must be non-negative"):
            event.validate_domain_rules()

    def test_validate_domain_rules_entries_matched_exceeds_total(self) -> None:
        """Test domain rules validation when matched entries exceed total."""
        event = FlextLdifFilterApplied.model_validate(
            {
                "aggregate_id": "filter-123",
                "filter_criteria": "objectClass=person",
                "entries_matched": 150,
                "total_entries": 100,
            },
        )
        with pytest.raises(
            ValueError,
            match="entries_matched cannot exceed total_entries",
        ):
            event.validate_domain_rules()

    def test_zero_values_allowed(self) -> None:
        """Test that zero values are allowed."""
        event = FlextLdifFilterApplied.model_validate(
            {
                "aggregate_id": "filter-empty",
                "filter_criteria": "objectClass=nonExistent",
                "entries_matched": 0,
                "total_entries": 0,
            },
        )
        # Should not raise
        event.validate_domain_rules()

    def test_all_entries_matched(self) -> None:
        """Test when all entries match the filter."""
        event = FlextLdifFilterApplied.model_validate(
            {
                "aggregate_id": "filter-all",
                "filter_criteria": "objectClass=*",
                "entries_matched": 100,
                "total_entries": 100,
            },
        )
        # Should not raise
        event.validate_domain_rules()


class TestDomainEventEquality:
    """Test domain event equality and hashing."""

    def test_same_events_are_equal(self) -> None:
        """Test that identical events are equal."""
        event1 = FlextLdifDocumentParsed.model_validate(
            {"aggregate_id": "doc-123", "entry_count": 50, "content_length": 1024},
        )
        event2 = FlextLdifDocumentParsed.model_validate(
            {"aggregate_id": "doc-123", "entry_count": 50, "content_length": 1024},
        )
        assert event1 == event2

    def test_different_events_are_not_equal(self) -> None:
        """Test that different events are not equal."""
        event1 = FlextLdifDocumentParsed.model_validate(
            {"aggregate_id": "doc-123", "entry_count": 50, "content_length": 1024},
        )
        event2 = FlextLdifDocumentParsed.model_validate(
            {"aggregate_id": "doc-456", "entry_count": 50, "content_length": 1024},
        )
        assert event1 != event2

    def test_event_hashing(self) -> None:
        """Test that identical events have same hash."""
        event1 = FlextLdifEntryValidated.model_validate(
            {
                "aggregate_id": "entry-123",
                "entry_dn": "cn=test,dc=example,dc=com",
                "is_valid": True,
            },
        )
        event2 = FlextLdifEntryValidated.model_validate(
            {
                "aggregate_id": "entry-123",
                "entry_dn": "cn=test,dc=example,dc=com",
                "is_valid": True,
            },
        )
        assert hash(event1) == hash(event2)
