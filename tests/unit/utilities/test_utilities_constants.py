"""Tests for LDIF constants utilities and valid value retrieval.

This module tests constants utility functions for retrieving valid values for different
categories (server_type, encoding), validation of known values, and bulk validation of
multiple constant values using parametrized test scenarios.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest
from tests import s

from flext_ldif import FlextLdifUtilities

# =============================================================================
# TEST SCENARIO ENUMS
# =============================================================================


class GetValidValuesType(StrEnum):
    """Get valid values test scenarios."""

    SERVER_TYPE = "server_type"
    ENCODING = "encoding"
    UNKNOWN_CATEGORY = "unknown_category"


class IsValidTestType(StrEnum):
    """Is valid test scenarios."""

    KNOWN_VALUE = "known_value"
    UNKNOWN_VALUE = "unknown_value"
    UNKNOWN_CATEGORY = "unknown_category"


class ValidateManyType(StrEnum):
    """Validate many test scenarios."""

    ALL_VALID = "all_valid"
    SOME_INVALID = "some_invalid"
    UNKNOWN_CATEGORY = "unknown_category"


# =============================================================================
# PARAMETRIZED TEST DATA
# =============================================================================


@pytest.mark.unit
class TestsTestFlextLdifConstants(s):
    """Test constants utilities."""

    # Get valid values test data
    GET_VALID_VALUES_DATA: ClassVar[
        dict[str, tuple[GetValidValuesType, str, set[str], bool]]
    ] = {
        "get_valid_values_server_type": (
            GetValidValuesType.SERVER_TYPE,
            "server_type",
            {
                "rfc",
                "oid",
                "oud",
                "openldap",
                "openldap1",
                "openldap2",
                "ad",
                "apache",
                "ds389",
                "novell",
                "ibm_tivoli",
                "relaxed",
                "generic",
            },
            False,
        ),
        "get_valid_values_encoding": (
            GetValidValuesType.ENCODING,
            "encoding",
            {
                "utf-8",
                "utf-16",
                "utf-16-le",
                "utf-32",
                "ascii",
                "latin-1",
                "cp1252",
                "iso-8859-1",
            },
            False,
        ),
        "get_valid_values_unknown_category": (
            GetValidValuesType.UNKNOWN_CATEGORY,
            "unknown",
            set(),
            True,
        ),
    }

    # Is valid test data
    IS_VALID_DATA: ClassVar[dict[str, tuple[IsValidTestType, str, str, bool, bool]]] = {
        "is_valid_known_value": (
            IsValidTestType.KNOWN_VALUE,
            "rfc",
            "server_type",
            True,
            False,
        ),
        "is_valid_known_value_case_insensitive": (
            IsValidTestType.KNOWN_VALUE,
            "UTF-8",
            "encoding",
            True,
            False,
        ),
        "is_valid_unknown_value": (
            IsValidTestType.UNKNOWN_VALUE,
            "unknown",
            "server_type",
            False,
            False,
        ),
        "is_valid_unknown_category": (
            IsValidTestType.UNKNOWN_CATEGORY,
            "any",
            "unknown",
            False,
            False,
        ),
    }

    # Validate many test data
    VALIDATE_MANY_DATA: ClassVar[
        dict[str, tuple[ValidateManyType, set[str], str, bool, bool]]
    ] = {
        "validate_many_all_valid": (
            ValidateManyType.ALL_VALID,
            {"rfc", "oid", "oud"},
            "server_type",
            True,
            False,
        ),
        "validate_many_some_invalid": (
            ValidateManyType.SOME_INVALID,
            {"rfc", "invalid", "oud", "also_invalid"},
            "server_type",
            False,
            False,
        ),
        "validate_many_unknown_category": (
            ValidateManyType.UNKNOWN_CATEGORY,
            {"any"},
            "unknown",
            False,
            True,
        ),
    }

    # =======================================================================
    # Get Valid Values Tests
    # =======================================================================

    @pytest.mark.parametrize(
        ("scenario", "test_type", "category", "expected_values", "should_raise"),
        [
            (name, data[0], data[1], data[2], data[3])
            for name, data in GET_VALID_VALUES_DATA.items()
        ],
    )
    def test_get_valid_values(
        self,
        scenario: str,
        test_type: GetValidValuesType,
        category: str,
        expected_values: set[str],
        should_raise: bool,
    ) -> None:
        """Parametrized test for get_valid_values."""
        if should_raise:
            with pytest.raises(KeyError):
                FlextLdifUtilities.Ldif.Constants.get_valid_values(category)
        else:
            values = FlextLdifUtilities.Ldif.Constants.get_valid_values(category)
            assert isinstance(values, set)
            assert values == expected_values, (
                f"Expected {expected_values}, got {values}"
            )

    # =======================================================================
    # Is Valid Tests
    # =======================================================================

    @pytest.mark.parametrize(
        (
            "scenario",
            "test_type",
            "value",
            "category",
            "expected_result",
            "should_raise",
        ),
        [
            (name, data[0], data[1], data[2], data[3], data[4])
            for name, data in IS_VALID_DATA.items()
        ],
    )
    def test_is_valid(
        self,
        scenario: str,
        test_type: IsValidTestType,
        value: str,
        category: str,
        expected_result: bool,
        should_raise: bool,
    ) -> None:
        """Parametrized test for is_valid."""
        if should_raise:
            pytest.skip("is_valid does not raise for unknown category")
        else:
            result = FlextLdifUtilities.Ldif.Constants.is_valid(value, category)
            assert result == expected_result

    # =======================================================================
    # Validate Many Tests
    # =======================================================================

    @pytest.mark.parametrize(
        (
            "scenario",
            "test_type",
            "values",
            "category",
            "expected_valid",
            "should_raise",
        ),
        [
            (name, data[0], data[1], data[2], data[3], data[4])
            for name, data in VALIDATE_MANY_DATA.items()
        ],
    )
    def test_validate_many(
        self,
        scenario: str,
        test_type: ValidateManyType,
        values: set[str],
        category: str,
        expected_valid: bool,
        should_raise: bool,
    ) -> None:
        """Parametrized test for validate_many."""
        if should_raise:
            with pytest.raises(KeyError):
                FlextLdifUtilities.Ldif.Constants.validate_many(values, category)
        else:
            is_valid, invalid = FlextLdifUtilities.Ldif.Constants.validate_many(
                values,
                category,
            )
            assert is_valid == expected_valid
            if not expected_valid:
                assert len(invalid) > 0

    # =======================================================================
    # Constants Accessibility Tests
    # =======================================================================

    def test_constants_are_accessible(self) -> None:
        """Test that constants are properly defined and accessible."""
        # Check that category map exists and has expected keys
        assert hasattr(FlextLdifUtilities.Ldif.Constants, "_CATEGORY_MAP")
        category_map = FlextLdifUtilities.Ldif.Constants._CATEGORY_MAP
        assert "server_type" in category_map
        assert "encoding" in category_map
        # Verify the methods are accessible
        assert hasattr(FlextLdifUtilities.Ldif.Constants, "get_valid_values")
        assert hasattr(FlextLdifUtilities.Ldif.Constants, "is_valid")
        assert hasattr(FlextLdifUtilities.Ldif.Constants, "validate_many")
