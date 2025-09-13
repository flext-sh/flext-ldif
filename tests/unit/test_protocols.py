"""Unit tests for FLEXT-LDIF protocols and interfaces.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.protocols import FlextLDIFProtocols


class TestProtocolDefinitions:
    """Test protocol definitions are properly defined."""

    def test_parser_protocol_exists(self) -> None:
        """Test FlextLDIFProtocols.LdifParser is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFProtocols.LdifParser, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFProtocols.LdifParser, "parse")
        assert hasattr(FlextLDIFProtocols.LdifParser, "parse_file")

    def test_validator_protocol_exists(self) -> None:
        """Test FlextLDIFProtocols.ValidatorProtocol is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFProtocols.LdifValidator, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFProtocols.LdifValidator, "validate_entry")
        assert hasattr(FlextLDIFProtocols.LdifValidator, "validate_entries")

    def test_writer_protocol_exists(self) -> None:
        """Test FlextLDIFProtocols.LdifWriter is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFProtocols.LdifWriter, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFProtocols.LdifWriter, "write")
        assert hasattr(FlextLDIFProtocols.LdifWriter, "write_file")

    def test_repository_protocol_exists(self) -> None:
        """Test FlextLDIFProtocols.LdifRepository is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFProtocols.LdifRepository, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFProtocols.LdifRepository, "find_by_dn")
        assert hasattr(FlextLDIFProtocols.LdifRepository, "filter_by_objectclass")

    def test_transformer_protocol_exists(self) -> None:
        """Test FlextLDIFProtocols.LdifTransformer is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFProtocols.LdifTransformer, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFProtocols.LdifTransformer, "transform_entry")
        assert hasattr(FlextLDIFProtocols.LdifTransformer, "transform_entries")

    def test_analytics_protocol_exists(self) -> None:
        """Test FlextLDIFProtocols.LdifAnalyzer is properly defined."""  # Check if it's a Protocol class
        assert hasattr(FlextLDIFProtocols.LdifAnalyzer, "__annotations__")
        # Check if it has the expected methods
        assert hasattr(FlextLDIFProtocols.LdifAnalyzer, "analyze_patterns")
        assert hasattr(FlextLDIFProtocols.LdifAnalyzer, "get_objectclass_distribution")
