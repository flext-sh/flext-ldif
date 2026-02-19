"""Tests for LDIF attribute utilities.

This module tests attribute utility functions including attribute description parsing,
option extraction, validation of attribute names and options, and handling of RFC 4512
compliant attribute descriptions with language tags and binary options.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest
from flext_ldif._utilities.attribute import FlextLdifUtilitiesAttribute
from tests import s


class AttributeTestCase(StrEnum):
    """Test cases for attribute validation."""

    SIMPLE = "simple"
    WITH_OPTION = "with_option"
    MULTIPLE_OPTIONS = "multiple_options"
    LANGUAGE_TAG = "language_tag"
    BINARY_OPTION = "binary_option"
    CUSTOM_OPTION = "custom_option"
    EMPTY = "empty"
    INVALID_START = "invalid_start"
    TOO_LONG = "too_long"
    INVALID_CHARS = "invalid_chars"
    OPTION_WITH_VALUE = "option_with_value"
    OPTION_INVALID = "option_invalid"
    OPTION_UNDERSCORE = "option_underscore"


class TestsTestFlextLdifUtilitiesAttribute(s):
    """Comprehensive tests for attribute utilities."""

    # Test data for split_attribute_description
    SPLIT_TEST_CASES: ClassVar[dict[str, tuple[str, tuple[str, list[str]]]]] = {
        AttributeTestCase.SIMPLE: (
            "displayname",
            ("displayname", []),
        ),
        AttributeTestCase.WITH_OPTION: (
            "displayname;lang-ar",
            ("displayname", ["lang-ar"]),
        ),
        AttributeTestCase.MULTIPLE_OPTIONS: (
            "cn;lang-ja;x-custom",
            ("cn", ["lang-ja", "x-custom"]),
        ),
        AttributeTestCase.BINARY_OPTION: (
            "userCertificate;binary",
            ("userCertificate", ["binary"]),
        ),
        AttributeTestCase.OPTION_WITH_VALUE: (
            "cn;lang=en",
            ("cn", ["lang=en"]),
        ),
    }

    # Test data for validate_attribute_name
    VALID_NAMES: ClassVar[list[str]] = [
        "displayname",
        "cn",
        "sn",
        "givenName",
        "userCertificate",
        "objectClass",
        "a",
        "a1",
        "a-1",
        "a1-b2",
        "veryLongAttributeNameThatIsStillValid",
    ]

    INVALID_NAMES: ClassVar[list[str]] = [
        "123invalid",  # Starts with digit
        "",  # Empty
        "displayname;lang-ar",  # Has option
        "cn;binary",  # Has option
        "a" * 128,  # Too long (>127 chars)
    ]

    # Test data for validate_attribute_option
    VALID_OPTIONS: ClassVar[list[str]] = [
        "lang-ar",
        "lang-es_es",  # RFC 3066 with underscore
        "lang-pt_BR",
        "binary",
        "x-custom",
        "x-my-custom-option",
        "lang=en",
        "lang=fr_CA",
        "x-my-option=value",
    ]

    INVALID_OPTIONS: ClassVar[list[str]] = [
        "123",
        "123bad",
        "-invalid",  # Starts with hyphen
        "",
    ]

    # Test data for validate_attribute_description
    VALID_DESCRIPTIONS: ClassVar[list[str]] = [
        "displayname",
        "displayname;lang-ar",
        "cn;lang-ja;x-custom",
        "userCertificate;binary",
        "cn;lang=en",
        "sn;lang-es_es",
    ]

    INVALID_DESCRIPTIONS: ClassVar[list[str]] = [
        "123invalid",
        "cn;123bad",
        "",
        "a" * 128,  # Too long
    ]

    @pytest.mark.parametrize(
        "test_case",
        [
            AttributeTestCase.SIMPLE,
            AttributeTestCase.WITH_OPTION,
            AttributeTestCase.MULTIPLE_OPTIONS,
            AttributeTestCase.BINARY_OPTION,
            AttributeTestCase.OPTION_WITH_VALUE,
        ],
    )
    def test_split_attribute_description(
        self,
        test_case: AttributeTestCase,
    ) -> None:
        """Test split_attribute_description with various inputs."""
        if test_case not in self.SPLIT_TEST_CASES:
            pytest.skip(f"No test data for {test_case}")

        input_desc, expected = self.SPLIT_TEST_CASES[test_case]
        result = FlextLdifUtilitiesAttribute.split_attribute_description(input_desc)

        assert result == expected
        assert isinstance(result[0], str)
        assert isinstance(result[1], list)

    def test_split_attribute_description_empty(self) -> None:
        """Test split_attribute_description raises ValueError for empty input."""
        with pytest.raises(ValueError, match="cannot be empty"):
            FlextLdifUtilitiesAttribute.split_attribute_description("")

        # Test None - intentionally testing incorrect type
        with pytest.raises((ValueError, AttributeError)):
            FlextLdifUtilitiesAttribute.split_attribute_description(None)  # type: ignore[arg-type]

    def test_split_attribute_description_none(self) -> None:
        """Test split_attribute_description raises ValueError for None."""
        # Method raises ValueError per implementation (line 69-71)
        # Intentionally testing incorrect type
        with pytest.raises(
            (ValueError, AttributeError), match="cannot be empty or None"
        ):
            FlextLdifUtilitiesAttribute.split_attribute_description(None)  # type: ignore[arg-type]

    @pytest.mark.parametrize("attribute_name", VALID_NAMES)
    def test_validate_attribute_name_valid(
        self,
        attribute_name: str,
    ) -> None:
        """Test validate_attribute_name with valid names."""
        result = FlextLdifUtilitiesAttribute.validate_attribute_name(attribute_name)
        assert result is True

    @pytest.mark.parametrize("attribute_name", INVALID_NAMES)
    def test_validate_attribute_name_invalid(
        self,
        attribute_name: str,
    ) -> None:
        """Test validate_attribute_name with invalid names."""
        result = FlextLdifUtilitiesAttribute.validate_attribute_name(attribute_name)
        assert result is False

    def test_validate_attribute_name_empty(self) -> None:
        """Test validate_attribute_name with empty string."""
        result = FlextLdifUtilitiesAttribute.validate_attribute_name("")
        assert result is False

    def test_validate_attribute_name_none(self) -> None:
        """Test validate_attribute_name with None."""
        # Intentionally testing incorrect type to validate error handling
        result = FlextLdifUtilitiesAttribute.validate_attribute_name(None)  # type: ignore[arg-type]
        assert result is False

    def test_validate_attribute_name_too_long(self) -> None:
        """Test validate_attribute_name with name exceeding max length."""
        long_name = "a" * 128  # Exceeds 127 char limit
        result = FlextLdifUtilitiesAttribute.validate_attribute_name(long_name)
        assert result is False

    @pytest.mark.parametrize("option", VALID_OPTIONS)
    def test_validate_attribute_option_valid(
        self,
        option: str,
    ) -> None:
        """Test validate_attribute_option with valid options."""
        result = FlextLdifUtilitiesAttribute.validate_attribute_option(option)
        assert result is True

    @pytest.mark.parametrize("option", INVALID_OPTIONS)
    def test_validate_attribute_option_invalid(
        self,
        option: str,
    ) -> None:
        """Test validate_attribute_option with invalid options."""
        result = FlextLdifUtilitiesAttribute.validate_attribute_option(option)
        assert result is False

    def test_validate_attribute_option_empty(self) -> None:
        """Test validate_attribute_option with empty string."""
        result = FlextLdifUtilitiesAttribute.validate_attribute_option("")
        assert result is False

    def test_validate_attribute_option_none(self) -> None:
        """Test validate_attribute_option with None."""
        # Intentionally testing incorrect type to validate error handling
        result = FlextLdifUtilitiesAttribute.validate_attribute_option(
            None,  # type: ignore[arg-type]
        )
        assert result is False

    def test_validate_attribute_option_with_value(self) -> None:
        """Test validate_attribute_option handles options with values."""
        result = FlextLdifUtilitiesAttribute.validate_attribute_option("lang=en")
        assert result is True

        result = FlextLdifUtilitiesAttribute.validate_attribute_option("x-custom=value")
        assert result is True

    def test_validate_attribute_option_underscore(self) -> None:
        """Test validate_attribute_option allows underscores (RFC 3066)."""
        result = FlextLdifUtilitiesAttribute.validate_attribute_option("lang-es_es")
        assert result is True

        result = FlextLdifUtilitiesAttribute.validate_attribute_option("lang-pt_BR")
        assert result is True

    @pytest.mark.parametrize("description", VALID_DESCRIPTIONS)
    def test_validate_attribute_description_valid(
        self,
        description: str,
    ) -> None:
        """Test validate_attribute_description with valid descriptions."""
        is_valid, violations = (
            FlextLdifUtilitiesAttribute.validate_attribute_description(
                description,
            )
        )

        assert is_valid is True
        assert violations == []

    @pytest.mark.parametrize(
        "description",
        [
            "123invalid",
            "cn;123bad",
            "a" * 128,  # Too long
        ],
    )
    def test_validate_attribute_description_invalid(
        self,
        description: str,
    ) -> None:
        """Test validate_attribute_description with invalid descriptions."""
        is_valid, violations = (
            FlextLdifUtilitiesAttribute.validate_attribute_description(
                description,
            )
        )

        assert is_valid is False
        assert len(violations) > 0
        assert all(isinstance(v, str) for v in violations)

    def test_validate_attribute_description_empty(self) -> None:
        """Test validate_attribute_description with empty string raises ValueError."""
        # Empty string raises ValueError from split_attribute_description
        with pytest.raises(ValueError, match="cannot be empty"):
            FlextLdifUtilitiesAttribute.validate_attribute_description("")

    def test_validate_attribute_description_invalid_base(self) -> None:
        """Test validate_attribute_description detects invalid base attribute."""
        is_valid, violations = (
            FlextLdifUtilitiesAttribute.validate_attribute_description(
                "123invalid",
            )
        )

        assert is_valid is False
        assert any("base attribute" in v.lower() for v in violations)

    def test_validate_attribute_description_invalid_option(self) -> None:
        """Test validate_attribute_description detects invalid options."""
        is_valid, violations = (
            FlextLdifUtilitiesAttribute.validate_attribute_description(
                "cn;123bad",
            )
        )

        assert is_valid is False
        assert any("option" in v.lower() for v in violations)

    def test_validate_attribute_description_multiple_violations(self) -> None:
        """Test validate_attribute_description reports multiple violations."""
        is_valid, violations = (
            FlextLdifUtilitiesAttribute.validate_attribute_description(
                "123invalid;123bad;456bad",
            )
        )

        assert is_valid is False
        assert len(violations) >= 2  # Base + multiple options

    # Edge cases
    def test_split_with_multiple_semicolons(self) -> None:
        """Test split handles multiple semicolons correctly."""
        result = FlextLdifUtilitiesAttribute.split_attribute_description(
            "cn;opt1;opt2;opt3",
        )
        assert result == ("cn", ["opt1", "opt2", "opt3"])

    def test_split_with_trailing_semicolon(self) -> None:
        """Test split handles trailing semicolon."""
        result = FlextLdifUtilitiesAttribute.split_attribute_description("cn;")
        assert result == ("cn", [""])

    def test_validate_name_max_length_boundary(self) -> None:
        """Test validate_name at max length boundary (127 chars)."""
        max_length_name = "a" * 127
        result = FlextLdifUtilitiesAttribute.validate_attribute_name(max_length_name)
        assert result is True

        over_length_name = "a" * 128
        result = FlextLdifUtilitiesAttribute.validate_attribute_name(over_length_name)
        assert result is False

    def test_validate_option_starts_with_letter(self) -> None:
        """Test validate_option requires starting with letter."""
        assert FlextLdifUtilitiesAttribute.validate_attribute_option("a") is True
        assert FlextLdifUtilitiesAttribute.validate_attribute_option("A") is True
        assert FlextLdifUtilitiesAttribute.validate_attribute_option("1a") is False
        assert FlextLdifUtilitiesAttribute.validate_attribute_option("-a") is False
