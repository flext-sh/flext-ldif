"""Unit tests for FLEXT-LDIF services."""

from __future__ import annotations

import pytest

from flext_ldif import (
    FlextLDIFEntry,
    FlextLDIFParserService,
    FlextLDIFValidatorService,
    FlextLDIFWriterService,
)


class TestServices:
    """Test service classes are properly defined and functional."""

    def test_parser_service_initialization(self) -> None:
        """Test parser service can be initialized."""
        service = FlextLDIFParserService()
        assert service is not None

    def test_writer_service_initialization(self) -> None:
        """Test writer service can be initialized."""
        service = FlextLDIFWriterService()
        assert service is not None

    def test_validator_service_initialization(self) -> None:
        """Test validator service can be initialized."""
        service = FlextLDIFValidatorService()
        assert service is not None


@pytest.fixture
def sample_entry() -> FlextLDIFEntry:
    """Create a sample LDIF entry for testing."""
    return FlextLDIFEntry.model_validate(
        {
            "id": "test-entry-123",
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        }
    )


class TestServiceFunctionality:
    """Test service functionality with sample data."""

    def test_parser_service_with_valid_ldif(self) -> None:
        """Test parser service with valid LDIF content."""
        service = FlextLDIFParserService()
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""
        # Use unwrap_or() pattern for cleaner testing
        entries = service.parse(ldif_content).unwrap_or([])
        assert len(entries) == 1

    def test_validator_service_with_valid_entry(
        self,
        sample_entry: FlextLDIFEntry,
    ) -> None:
        """Test validator service with valid entry."""
        service = FlextLDIFValidatorService()
        # Use unwrap_or() for cleaner validation testing
        is_valid = service.validate_data([sample_entry]).unwrap_or(False)
        assert is_valid

    def test_writer_service_with_valid_entries(
        self,
        sample_entry: FlextLDIFEntry,
    ) -> None:
        """Test writer service with valid entries."""
        service = FlextLDIFWriterService()
        # Use unwrap_or() for cleaner writer testing
        output = service.write([sample_entry]).unwrap_or("")
        assert "dn: cn=test,dc=example,dc=com" in output
