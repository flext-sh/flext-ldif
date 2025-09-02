"""Unit tests for FLEXT-LDIF protocols and interfaces."""

from __future__ import annotations

from flext_ldif import (
    FlextLDIFAnalyticsProtocol,
    FlextLDIFParserProtocol,
    FlextLDIFRepositoryProtocol,
    FlextLDIFTransformerProtocol,
    FlextLDIFValidatorProtocol,
    FlextLDIFWriterProtocol,
)


class TestProtocolDefinitions:
    """Test protocol definitions are properly defined."""

    def test_parser_protocol_exists(self) -> None:
        """Test FlextLDIFParserProtocol is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFParserProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFParserProtocol, "parse")
        assert hasattr(FlextLDIFParserProtocol, "parse_file")

    def test_validator_protocol_exists(self) -> None:
        """Test FlextLDIFValidatorProtocol is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFValidatorProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFValidatorProtocol, "validate_entry")
        assert hasattr(FlextLDIFValidatorProtocol, "validate_entries")

    def test_writer_protocol_exists(self) -> None:
        """Test FlextLDIFWriterProtocol is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFWriterProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFWriterProtocol, "write")
        assert hasattr(FlextLDIFWriterProtocol, "write_file")

    def test_repository_protocol_exists(self) -> None:
        """Test FlextLDIFRepositoryProtocol is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFRepositoryProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFRepositoryProtocol, "find_by_dn")
        assert hasattr(FlextLDIFRepositoryProtocol, "filter_by_objectclass")

    def test_transformer_protocol_exists(self) -> None:
        """Test FlextLDIFTransformerProtocol is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFTransformerProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFTransformerProtocol, "transform_entry")
        assert hasattr(FlextLDIFTransformerProtocol, "transform_entries")

    def test_analytics_protocol_exists(self) -> None:
        """Test FlextLDIFAnalyticsProtocol is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFAnalyticsProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFAnalyticsProtocol, "analyze_entry_patterns")
        assert hasattr(FlextLDIFAnalyticsProtocol, "get_objectclass_distribution")
