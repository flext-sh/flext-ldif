"""Test suite for LDIF typings module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.typings import FlextLdifTypes


class TestFlextLdifTypes:
    """Test suite for FlextLdifTypes namespace class."""

    def test_types_namespace_exists(self) -> None:
        """Test FlextLdifTypes namespace class is accessible."""
        assert FlextLdifTypes is not None
        assert hasattr(FlextLdifTypes, "__name__")

    def test_entry_nested_class_exists(self) -> None:
        """Test Entry nested class exists in FlextLdifTypes."""
        assert hasattr(FlextLdifTypes, "Entry")
        entry_class = FlextLdifTypes.Entry
        assert entry_class is not None

    def test_parser_nested_class_exists(self) -> None:
        """Test Parser nested class exists in FlextLdifTypes."""
        assert hasattr(FlextLdifTypes, "Parser")
        parser_class = FlextLdifTypes.Parser
        assert parser_class is not None

    def test_ldif_validation_nested_class_exists(self) -> None:
        """Test LdifValidation nested class exists in FlextLdifTypes."""
        assert hasattr(FlextLdifTypes, "LdifValidation")
        validation_class = FlextLdifTypes.LdifValidation
        assert validation_class is not None

    def test_ldif_processing_nested_class_exists(self) -> None:
        """Test LdifProcessing nested class exists in FlextLdifTypes."""
        assert hasattr(FlextLdifTypes, "LdifProcessing")
        processing_class = FlextLdifTypes.LdifProcessing
        assert processing_class is not None

    def test_analytics_nested_class_exists(self) -> None:
        """Test Analytics nested class exists in FlextLdifTypes."""
        assert hasattr(FlextLdifTypes, "Analytics")
        analytics_class = FlextLdifTypes.Analytics
        assert analytics_class is not None

    def test_writer_nested_class_exists(self) -> None:
        """Test Writer nested class exists in FlextLdifTypes."""
        assert hasattr(FlextLdifTypes, "Writer")
        writer_class = FlextLdifTypes.Writer
        assert writer_class is not None

    def test_server_types_nested_class_exists(self) -> None:
        """Test ServerTypes nested class exists in FlextLdifTypes."""
        assert hasattr(FlextLdifTypes, "ServerTypes")
        server_types_class = FlextLdifTypes.ServerTypes
        assert server_types_class is not None

    def test_functional_nested_class_exists(self) -> None:
        """Test Functional nested class exists in FlextLdifTypes."""
        assert hasattr(FlextLdifTypes, "Functional")
        functional_class = FlextLdifTypes.Functional
        assert functional_class is not None

    def test_streaming_nested_class_exists(self) -> None:
        """Test Streaming nested class exists in FlextLdifTypes."""
        assert hasattr(FlextLdifTypes, "Streaming")
        streaming_class = FlextLdifTypes.Streaming
        assert streaming_class is not None

    def test_project_nested_class_exists(self) -> None:
        """Test Project nested class exists in FlextLdifTypes."""
        assert hasattr(FlextLdifTypes, "Project")
        project_class = FlextLdifTypes.Project
        assert project_class is not None
