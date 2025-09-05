"""Unit tests for FLEXT-LDIF protocols and interfaces."""

from __future__ import annotations

from flext_ldif.protocols import FlextLDIFProtocols


class TestProtocolDefinitions:
    """Test protocol definitions are properly defined."""

    def test_parser_protocol_exists(self) -> None:
        """Test FlextLDIFProtocols.ParserProtocol is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFProtocols.ParserProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFProtocols.ParserProtocol, "parse")
        assert hasattr(FlextLDIFProtocols.ParserProtocol, "parse_file")

    def test_validator_protocol_exists(self) -> None:
        """Test FlextLDIFProtocols.ValidatorProtocol is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFProtocols.ValidatorProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFProtocols.ValidatorProtocol, "validate_entry")
        assert hasattr(FlextLDIFProtocols.ValidatorProtocol, "validate_entries")

    def test_writer_protocol_exists(self) -> None:
        """Test FlextLDIFProtocols.WriterProtocol is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFProtocols.WriterProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFProtocols.WriterProtocol, "write")
        assert hasattr(FlextLDIFProtocols.WriterProtocol, "write_file")

    def test_repository_protocol_exists(self) -> None:
        """Test FlextLDIFProtocols.RepositoryProtocol is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFProtocols.RepositoryProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFProtocols.RepositoryProtocol, "find_by_dn")
        assert hasattr(FlextLDIFProtocols.RepositoryProtocol, "filter_by_objectclass")

    def test_transformer_protocol_exists(self) -> None:
        """Test FlextLDIFProtocols.TransformerProtocol is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFProtocols.TransformerProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFProtocols.TransformerProtocol, "transform_entry")
        assert hasattr(FlextLDIFProtocols.TransformerProtocol, "transform_entries")

    def test_analytics_protocol_exists(self) -> None:
        """Test FlextLDIFProtocols.AnalyticsProtocol is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFProtocols.AnalyticsProtocol, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFProtocols.AnalyticsProtocol, "analyze_patterns")
        assert hasattr(
            FlextLDIFProtocols.AnalyticsProtocol, "get_objectclass_distribution"
        )
