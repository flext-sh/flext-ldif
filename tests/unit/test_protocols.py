"""Unit tests for FLEXT-LDIF protocols and interfaces."""

from __future__ import annotations

from flext_ldif.protocols import (
    FlextLdifAnalyticsProtocol,
    FlextLdifParserProtocol,
    FlextLdifRepositoryProtocol,
    FlextLdifTransformerProtocol,
    FlextLdifValidatorProtocol,
    FlextLdifWriterProtocol,
)


class TestProtocolDefinitions:
    """Test protocol definitions are properly defined."""

    def test_parser_protocol_exists(self) -> None:
        """Test FlextLdifParserProtocol is properly defined."""        # Check if it's a Protocol class
        assert hasattr(FlextLdifParserProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLdifParserProtocol, "parse")
        assert hasattr(FlextLdifParserProtocol, "parse_file")

    def test_validator_protocol_exists(self) -> None:
        """Test FlextLdifValidatorProtocol is properly defined."""        # Check if it's a Protocol class
        assert hasattr(FlextLdifValidatorProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLdifValidatorProtocol, "validate_entry")
        assert hasattr(FlextLdifValidatorProtocol, "validate_entries")

    def test_writer_protocol_exists(self) -> None:
        """Test FlextLdifWriterProtocol is properly defined."""        # Check if it's a Protocol class
        assert hasattr(FlextLdifWriterProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLdifWriterProtocol, "write")
        assert hasattr(FlextLdifWriterProtocol, "write_file")

    def test_repository_protocol_exists(self) -> None:
        """Test FlextLdifRepositoryProtocol is properly defined."""        # Check if it's a Protocol class
        assert hasattr(FlextLdifRepositoryProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLdifRepositoryProtocol, "find_by_dn")
        assert hasattr(FlextLdifRepositoryProtocol, "filter_by_objectclass")

    def test_transformer_protocol_exists(self) -> None:
        """Test FlextLdifTransformerProtocol is properly defined."""        # Check if it's a Protocol class
        assert hasattr(FlextLdifTransformerProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLdifTransformerProtocol, "transform_entry")
        assert hasattr(FlextLdifTransformerProtocol, "transform_entries")

    def test_analytics_protocol_exists(self) -> None:
        """Test FlextLdifAnalyticsProtocol is properly defined."""        # Check if it's a Protocol class
        assert hasattr(FlextLdifAnalyticsProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLdifAnalyticsProtocol, "analyze_entry_patterns")
        assert hasattr(FlextLdifAnalyticsProtocol, "get_objectclass_distribution")
