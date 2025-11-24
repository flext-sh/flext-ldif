"""Test FlextLdifUtilities.Constants module."""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdifUtilities


class TestFlextLdifUtilitiesConstants:
    """Test constants utilities."""

    def test_get_valid_values_server_type(self) -> None:
        """Test get_valid_values for server_type category."""
        values = FlextLdifUtilities.Constants.get_valid_values("server_type")
        assert isinstance(values, set)
        assert "rfc" in values
        assert "oid" in values
        assert "oud" in values

    def test_get_valid_values_encoding(self) -> None:
        """Test get_valid_values for encoding category."""
        values = FlextLdifUtilities.Constants.get_valid_values("encoding")
        assert isinstance(values, set)
        assert "utf-8" in values

    def test_get_valid_values_unknown_category(self) -> None:
        """Test get_valid_values with unknown category raises KeyError."""
        with pytest.raises(KeyError, match="Unknown category"):
            FlextLdifUtilities.Constants.get_valid_values("unknown")

    def test_is_valid_known_value(self) -> None:
        """Test is_valid with known valid value."""
        assert FlextLdifUtilities.Constants.is_valid("rfc", "server_type")
        assert FlextLdifUtilities.Constants.is_valid(
            "UTF-8", "encoding"
        )  # Case insensitive

    def test_is_valid_unknown_value(self) -> None:
        """Test is_valid with unknown value."""
        assert not FlextLdifUtilities.Constants.is_valid("unknown", "server_type")

    def test_is_valid_unknown_category(self) -> None:
        """Test is_valid with unknown category."""
        assert not FlextLdifUtilities.Constants.is_valid("any", "unknown")

    def test_validate_many_all_valid(self) -> None:
        """Test validate_many with all valid values."""
        values = {"rfc", "oid", "oud"}
        is_valid, invalid = FlextLdifUtilities.Constants.validate_many(
            values, "server_type"
        )
        assert is_valid
        assert invalid == []

    def test_validate_many_some_invalid(self) -> None:
        """Test validate_many with some invalid values."""
        values = {"rfc", "invalid", "oud", "also_invalid"}
        is_valid, invalid = FlextLdifUtilities.Constants.validate_many(
            values, "server_type"
        )
        assert not is_valid
        assert set(invalid) == {"invalid", "also_invalid"}

    def test_validate_many_unknown_category(self) -> None:
        """Test validate_many with unknown category raises KeyError."""
        values = {"any"}
        with pytest.raises(KeyError):
            FlextLdifUtilities.Constants.validate_many(values, "unknown")

    def test_constants_are_accessible(self) -> None:
        """Test that constants are properly defined and accessible."""
        # Test that we can access the constants
        assert hasattr(FlextLdifUtilities.Constants, "_VALID_VALUES")

        # Test that the constants contain expected categories
        valid_values = FlextLdifUtilities.Constants._VALID_VALUES
        assert "server_type" in valid_values
        assert "encoding" in valid_values
