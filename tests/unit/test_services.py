"""Unit tests for FLEXT-LDIF services."""

from __future__ import annotations

import pytest

from flext_ldif import (
    FlextLdifAnalyticsService,
    FlextLdifAttributes,
    FlextLdifDistinguishedName,
    FlextLdifEntry,
    FlextLdifParserService,
    FlextLdifRepositoryService,
    FlextLdifTransformerService,
    FlextLdifValidatorService,
    FlextLdifWriterService,
)


class TestServices:
    """Test service classes are properly defined and functional."""

    def test_parser_service_initialization(self) -> None:
        """Test parser service can be initialized."""
        service = FlextLdifParserService()
        assert service is not None

    def test_writer_service_initialization(self) -> None:
        """Test writer service can be initialized."""
        service = FlextLdifWriterService()
        assert service is not None

    def test_validator_service_initialization(self) -> None:
        """Test validator service can be initialized."""
        service = FlextLdifValidatorService()
        assert service is not None

    def test_repository_service_initialization(self) -> None:
        """Test repository service can be initialized."""
        service = FlextLdifRepositoryService()
        assert service is not None

    def test_transformer_service_initialization(self) -> None:
        """Test transformer service can be initialized."""
        service = FlextLdifTransformerService()
        assert service is not None

    def test_analytics_service_initialization(self) -> None:
        """Test analytics service can be initialized."""
        service = FlextLdifAnalyticsService()
        assert service is not None


@pytest.fixture
def sample_entry() -> FlextLdifEntry:
    """Create a sample LDIF entry for testing."""
    return FlextLdifEntry(
        id="test-entry-123",
        dn=FlextLdifDistinguishedName(value="cn=test,dc=example,dc=com"),
        attributes=FlextLdifAttributes(
            attributes={"cn": ["test"], "objectClass": ["person"]},
        ),
    )


class TestServiceFunctionality:
    """Test service functionality with sample data."""

    def test_parser_service_with_valid_ldif(self) -> None:
        """Test parser service with valid LDIF content."""
        service = FlextLdifParserService()
        ldif_content = """dn: cn=test,dc=example,dc=com
cn: test
objectClass: person
"""
        result = service.parse(ldif_content)
        assert result.success
        assert result.data is not None
        assert len(result.data) == 1

    def test_validator_service_with_valid_entry(
        self,
        sample_entry: FlextLdifEntry,
    ) -> None:
        """Test validator service with valid entry."""
        service = FlextLdifValidatorService()
        result = service.validate_data([sample_entry])
        assert result.success

    def test_writer_service_with_valid_entries(
        self,
        sample_entry: FlextLdifEntry,
    ) -> None:
        """Test writer service with valid entries."""
        service = FlextLdifWriterService()
        result = service.write([sample_entry])
        assert result.success
        assert result.data is not None
        assert "dn: cn=test,dc=example,dc=com" in result.data
