"""Comprehensive validation service tests for flext-ldif.

Tests RFC 2849/4512 compliant entry validation including attribute names,
object classes, values, DN components, and error handling. Uses advanced
Python 3.13 features, factories, and helpers for minimal code with maximum coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum

import pytest
from flext_tests import FlextTestsMatchers

from flext_ldif import FlextLdifModels
from flext_ldif.services.validation import FlextLdifValidation
from tests.fixtures.constants import Names


class ValidationTestCases(StrEnum):
    """Test case categories for validation."""

    VALID_NAMES = "valid_names"
    INVALID_NAMES = "invalid_names"
    VALID_VALUES = "valid_values"
    INVALID_VALUES = "invalid_values"
    DN_COMPONENTS = "dn_components"


class ValidationTestFactory:
    """Factory for creating validation service test instances."""

    @staticmethod
    def create_service() -> FlextLdifValidation:
        """Create validation service instance."""
        return FlextLdifValidation()

    @classmethod
    def parametrize_valid_names(cls) -> list[tuple[str, bool]]:
        """Parametrize valid attribute/object class names."""
        return [
            (Names.CN, True),
            ("cn2", True),
            ("user-name", True),
            ("CN", True),
            ("inetOrgPerson", True),
        ]

    @classmethod
    def parametrize_invalid_names(cls) -> list[tuple[str, bool]]:
        """Parametrize invalid attribute/object class names."""
        return [
            ("2invalid", False),
            ("invalid name", False),
            ("cn@user", False),
            ("", False),
            ("a" * 128, False),
        ]

    @classmethod
    def parametrize_valid_values(cls) -> list[tuple[str, bool]]:
        """Parametrize valid attribute values."""
        return [
            ("John Smith", True),
            ("", True),  # Empty valid in LDAP
            ("test@example.com", True),
            ("José García", True),
            ("123", True),  # Numeric strings valid
        ]

    @classmethod
    def parametrize_invalid_values(cls) -> list[tuple[str, bool]]:
        """Parametrize invalid attribute values."""
        large_value = "a" * (1048576 + 1)
        return [
            (large_value, False),  # Exceeds max length
        ]

    @classmethod
    def parametrize_dn_components(cls) -> list[tuple[str, str, bool]]:
        """Parametrize DN component validations."""
        return [
            (Names.CN, "John Smith", True),
            ("CN", "test", True),
            (Names.CN, "", True),  # Empty values allowed
            ("2invalid", "test", False),  # Invalid attribute
            (Names.CN, "Smith, John", True),  # Special chars allowed
        ]


class TestValidationService:
    """Comprehensive validation service tests.

    Tests all validation paths using factories, parametrization, and helpers
    for minimal code with complete coverage.
    """

    class TestAttributeName:
        """Test attribute name validation against RFC 4512 rules."""

        @pytest.mark.parametrize(
            ("name", "expected"),
            tuple(ValidationTestFactory.parametrize_valid_names())
            + tuple(ValidationTestFactory.parametrize_invalid_names()),
        )
        def test_validate_attribute_name(
            self,
            name: str,
            expected: bool,
        ) -> None:
            """Test attribute name validation with comprehensive cases."""
            service = ValidationTestFactory.create_service()
            result = service.validate_attribute_name(name)
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert unwrapped is expected

    class TestObjectClassName:
        """Test object class name validation."""

        @pytest.mark.parametrize(
            ("name", "expected"),
            tuple(ValidationTestFactory.parametrize_valid_names())
            + tuple(ValidationTestFactory.parametrize_invalid_names()),
        )
        def test_validate_objectclass_name(
            self,
            name: str,
            expected: bool,
        ) -> None:
            """Test object class name validation with comprehensive cases."""
            service = ValidationTestFactory.create_service()
            result = service.validate_objectclass_name(name)
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert unwrapped is expected

        def test_validate_objectclass_delegates_to_attribute(self) -> None:
            """Test object class validation uses same rules as attribute names."""
            service = ValidationTestFactory.create_service()
            test_name = "testName"
            attr_result = service.validate_attribute_name(test_name)
            class_result = service.validate_objectclass_name(test_name)
            assert attr_result.unwrap() == class_result.unwrap()

    class TestAttributeValue:
        """Test attribute value validation."""

        @pytest.mark.parametrize(
            ("value", "expected"),
            tuple(ValidationTestFactory.parametrize_valid_values())
            + tuple(ValidationTestFactory.parametrize_invalid_values()),
        )
        def test_validate_attribute_value(
            self,
            value: str,
            expected: bool,
        ) -> None:
            """Test attribute value validation with comprehensive cases."""
            service = ValidationTestFactory.create_service()
            result = service.validate_attribute_value(value)
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert unwrapped is expected

        @pytest.mark.parametrize(
            ("value", "max_length", "expected"),
            [
                ("test", 2, False),
                ("test", 10, True),
                ("a" * 1048576, None, True),  # Within default max
            ],
        )
        def test_validate_attribute_value_with_length(
            self,
            value: str,
            max_length: int | None,
            expected: bool,
        ) -> None:
            """Test attribute value validation with custom max length."""
            service = ValidationTestFactory.create_service()
            result = service.validate_attribute_value(value, max_length=max_length)
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert unwrapped is expected

    class TestDnComponent:
        """Test DN component (attribute=value pair) validation."""

        @pytest.mark.parametrize(
            ("attr", "value", "expected"),
            tuple(ValidationTestFactory.parametrize_dn_components()),
        )
        def test_validate_dn_component(
            self,
            attr: str,
            value: str,
            expected: bool,
        ) -> None:
            """Test DN component validation with comprehensive cases."""
            service = ValidationTestFactory.create_service()
            result = service.validate_dn_component(attr, value)
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert unwrapped is expected

        def test_validate_dn_component_invalid_attribute(self) -> None:
            """Test DN component validation with invalid attribute fails."""
            service = ValidationTestFactory.create_service()
            result = service.validate_dn_component("", "test")
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert unwrapped is False

    class TestExecute:
        """Test validation service self-check."""

        def test_execute_returns_success(self) -> None:
            """Test execute returns successful status."""
            service = ValidationTestFactory.create_service()
            result = service.execute()
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert isinstance(unwrapped, FlextLdifModels.ValidationServiceStatus)
            assert unwrapped.service == "ValidationService"
            assert unwrapped.status == "operational"
            assert "RFC 2849" in unwrapped.rfc_compliance


__all__ = [
    "TestValidationService",
    "ValidationTestCases",
    "ValidationTestFactory",
]
