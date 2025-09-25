"""Unified tests for flext_ldif.utilities module.

This module consolidates all tests for the utilities module, ensuring
comprehensive coverage of utility functions and classes.
"""

from pathlib import Path

from flext_ldif import FlextLdifUtilities


class TestFlextLdifUtilities:
    """Test suite for FlextLdifUtilities class."""

    def test_utilities_class_exists(self) -> None:
        """Test that FlextLdifUtilities class exists."""
        assert FlextLdifUtilities is not None

    def test_utilities_methods_available(self) -> None:
        """Test that utility methods are available."""
        # Test that utility methods exist
        assert hasattr(FlextLdifUtilities, "get_timestamp")
        assert hasattr(FlextLdifUtilities, "get_formatted_timestamp")
        assert hasattr(FlextLdifUtilities, "validate_file_path")
        assert hasattr(FlextLdifUtilities, "ensure_file_extension")

    def test_get_timestamp_functionality(self) -> None:
        """Test timestamp generation functionality."""
        # Test timestamp generation
        timestamp = FlextLdifUtilities.get_timestamp()
        assert isinstance(timestamp, str)
        assert len(timestamp) > 0

    def test_get_formatted_timestamp_functionality(self) -> None:
        """Test formatted timestamp generation functionality."""
        # Test formatted timestamp generation
        timestamp = FlextLdifUtilities.get_formatted_timestamp()
        assert isinstance(timestamp, str)
        assert len(timestamp) > 0

    def test_validate_file_path_functionality(self) -> None:
        """Test file path validation functionality."""
        # Test file path validation
        result = FlextLdifUtilities.validate_file_path(Path("/tmp/test.ldif"))  # noqa: S108
        assert result.is_success

    def test_ensure_file_extension_functionality(self) -> None:
        """Test file extension ensuring functionality."""
        # Test file extension ensuring
        result = FlextLdifUtilities.ensure_file_extension(Path("test"), ".ldif")
        assert result.suffix == ".ldif"
