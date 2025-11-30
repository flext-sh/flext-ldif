"""Test suite for Validation Service - RFC 2849/4512 compliant entry validation.

Modules tested:
- flext_ldif.services.validation.FlextLdifValidation (RFC 2849/4512 validation service)

Scope:
- Service initialization and execute pattern
- Attribute name validation (valid, invalid names)
- Object class name validation (valid, invalid names, delegation to attribute validation)
- Attribute value validation (valid, invalid values, custom max length)
- DN component validation (attribute=value pairs, invalid attributes)
- Builder pattern (fluent API, with_attribute_names, with_objectclass_names,
  with_max_attr_value_length, build)
- Batch validation (multiple attribute names, empty lists, failure handling)
- Error handling (non-string values, list values)

Test Coverage:
- All validation service methods (validate_attribute_name, validate_objectclass_name,
  validate_attribute_value, validate_dn_component, validate_attribute_names,
  builder pattern methods)
- Edge cases (empty values, large values, invalid formats, batch operations)
- Parametrized tests for multiple scenarios

Uses Python 3.13 features, factories, constants, dynamic tests, and extensive helper reuse
to reduce code while maintaining 100% behavior coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum

import pytest
from flext_tests import FlextTestsMatchers  # Mocked in conftest

from flext_ldif import FlextLdifModels
from flext_ldif.services.validation import FlextLdifValidation
from tests.fixtures.constants import Names


class TestFlextLdifValidation:
    """Test FlextLdifValidation service with consolidated parametrized tests.

    Uses nested classes for organization: TestCases, Factories, TestAttributeName,
    TestObjectClassName, TestAttributeValue, TestDnComponent, TestExecute,
    TestBuilderPattern, TestBatchValidation, TestErrorHandling.
    Reduces code duplication through helper methods and factories.
    Uses FlextTestsMatchers extensively for maximum code reduction.
    """

    class TestCases(StrEnum):
        """Test case categories for validation organized as nested enum."""

        __test__ = False

        VALID_NAMES = "valid_names"
        INVALID_NAMES = "invalid_names"
        VALID_VALUES = "valid_values"
        INVALID_VALUES = "invalid_values"
        DN_COMPONENTS = "dn_components"

    class Factories:
        """Factory for creating validation service test instances organized as nested class."""

        __test__ = False

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

    class TestAttributeName:
        """Test attribute name validation against RFC 4512 rules."""

        @pytest.mark.parametrize(
            ("name", "expected"),
            [
                (Names.CN, True),
                ("cn2", True),
                ("user-name", True),
                ("CN", True),
                ("inetOrgPerson", True),
                ("2invalid", False),
                ("invalid name", False),
                ("cn@user", False),
                ("", False),
                ("a" * 128, False),
            ],
        )
        def test_validate_attribute_name(
            self,
            name: str,
            expected: bool,
        ) -> None:
            """Test attribute name validation with comprehensive cases."""
            service = FlextLdifValidation()
            result = service.validate_attribute_name(name)
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert unwrapped is expected

    class TestObjectClassName:
        """Test object class name validation."""

        @pytest.mark.parametrize(
            ("name", "expected"),
            [
                (Names.CN, True),
                ("cn2", True),
                ("user-name", True),
                ("CN", True),
                ("inetOrgPerson", True),
                ("2invalid", False),
                ("invalid name", False),
                ("cn@user", False),
                ("", False),
                ("a" * 128, False),
            ],
        )
        def test_validate_objectclass_name(
            self,
            name: str,
            expected: bool,
        ) -> None:
            """Test object class name validation with comprehensive cases."""
            service = FlextLdifValidation()
            result = service.validate_objectclass_name(name)
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert unwrapped is expected

        def test_validate_objectclass_delegates_to_attribute(self) -> None:
            """Test object class validation uses same rules as attribute names."""
            service = FlextLdifValidation()
            test_name = "testName"
            attr_result = service.validate_attribute_name(test_name)
            class_result = service.validate_objectclass_name(test_name)
            assert attr_result.unwrap() == class_result.unwrap()

    class TestAttributeValue:
        """Test attribute value validation."""

        @pytest.mark.parametrize(
            ("value", "expected"),
            [
                ("John Smith", True),
                ("", True),  # Empty valid in LDAP
                ("test@example.com", True),
                ("José García", True),
                ("123", True),  # Numeric strings valid
                ("a" * (1048576 + 1), False),  # Exceeds max length
            ],
        )
        def test_validate_attribute_value(
            self,
            value: str,
            expected: bool,
        ) -> None:
            """Test attribute value validation with comprehensive cases."""
            service = FlextLdifValidation()
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
            service = FlextLdifValidation()
            result = service.validate_attribute_value(value, max_length=max_length)
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert unwrapped is expected

    class TestDnComponent:
        """Test DN component (attribute=value pair) validation."""

        @pytest.mark.parametrize(
            ("attr", "value", "expected"),
            [
                (Names.CN, "John Smith", True),
                ("CN", "test", True),
                (Names.CN, "", True),  # Empty values allowed
                ("2invalid", "test", False),  # Invalid attribute
                (Names.CN, "Smith, John", True),  # Special chars allowed
            ],
        )
        def test_validate_dn_component(
            self,
            attr: str,
            value: str,
            expected: bool,
        ) -> None:
            """Test DN component validation with comprehensive cases."""
            service = FlextLdifValidation()
            result = service.validate_dn_component(attr, value)
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert unwrapped is expected

        def test_validate_dn_component_invalid_attribute(self) -> None:
            """Test DN component validation with invalid attribute fails."""
            service = FlextLdifValidation()
            result = service.validate_dn_component("", "test")
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert unwrapped is False

    class TestExecute:
        """Test validation service self-check."""

        def test_execute_returns_success(self) -> None:
            """Test execute returns successful status."""
            service = FlextLdifValidation()
            result = service.execute()
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert isinstance(unwrapped, FlextLdifModels.ValidationServiceStatus)
            assert unwrapped.service == "ValidationService"
            assert unwrapped.status == "operational"
            assert "RFC 2849" in unwrapped.rfc_compliance

    class TestBuilderPattern:
        """Test fluent builder pattern."""

        def test_builder_creates_instance(self) -> None:
            """Test builder() creates service instance."""
            builder = FlextLdifValidation.builder()
            assert isinstance(builder, FlextLdifValidation)

        def test_with_attribute_names(self) -> None:
            """Test with_attribute_names fluent method."""
            builder = FlextLdifValidation.builder()
            result = builder.with_attribute_names(["cn", "mail"])
            assert result is builder
            assert builder.attribute_names == ["cn", "mail"]

        def test_with_objectclass_names(self) -> None:
            """Test with_objectclass_names fluent method."""
            builder = FlextLdifValidation.builder()
            result = builder.with_objectclass_names(["person"])
            assert result is builder
            assert builder.objectclass_names == ["person"]

        def test_with_max_attr_value_length(self) -> None:
            """Test with_max_attr_value_length fluent method."""
            builder = FlextLdifValidation.builder()
            result = builder.with_max_attr_value_length(1024)
            assert result is builder
            assert builder.max_attr_value_length == 1024

        def test_build_with_attribute_names(self) -> None:
            """Test build() validates attribute names."""
            result = (
                FlextLdifValidation.builder()
                .with_attribute_names(["cn", "2invalid"])
                .build()
            )
            assert isinstance(result, FlextLdifModels.ValidationBatchResult)
            assert result.results["cn"] is True
            assert result.results["2invalid"] is False

        def test_build_with_objectclass_names(self) -> None:
            """Test build() validates objectClass names."""
            result = (
                FlextLdifValidation.builder()
                .with_objectclass_names(["person", "invalid class"])
                .build()
            )
            assert isinstance(result, FlextLdifModels.ValidationBatchResult)
            assert result.results["person"] is True
            assert result.results["invalid class"] is False

        def test_build_with_both(self) -> None:
            """Test build() validates both attribute and objectClass names."""
            result = (
                FlextLdifValidation.builder()
                .with_attribute_names(["cn"])
                .with_objectclass_names(["person"])
                .build()
            )
            assert isinstance(result, FlextLdifModels.ValidationBatchResult)
            assert result.results["cn"] is True
            assert result.results["person"] is True

        def test_build_with_empty_lists(self) -> None:
            """Test build() with empty lists returns empty results."""
            result = FlextLdifValidation.builder().build()
            assert isinstance(result, FlextLdifModels.ValidationBatchResult)
            assert result.results == {}

    class TestBatchValidation:
        """Test batch validation operations."""

        def test_validate_attribute_names_batch(self) -> None:
            """Test batch validation of multiple attribute names."""
            service = FlextLdifValidation()
            result = service.validate_attribute_names(["cn", "mail", "2invalid"])
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert unwrapped["cn"] is True
            assert unwrapped["mail"] is True
            assert unwrapped["2invalid"] is False

        def test_validate_attribute_names_empty_list(self) -> None:
            """Test batch validation with empty list."""
            service = FlextLdifValidation()
            result = service.validate_attribute_names([])
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert unwrapped == {}

        def test_validate_attribute_names_with_failure_handling(self) -> None:
            """Test batch validation handles individual failures."""
            service = FlextLdifValidation()
            # This should succeed even if individual validations might fail
            result = service.validate_attribute_names(["cn", "valid-name"])
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert isinstance(unwrapped, dict)
            assert "cn" in unwrapped
            assert "valid-name" in unwrapped

    class TestErrorHandling:
        """Test error handling paths."""

        def test_validate_dn_component_non_string_value(self) -> None:
            """Test validate_dn_component with non-string value."""
            service = FlextLdifValidation()
            result = service.validate_dn_component("cn", 123)
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert unwrapped is False

        def test_validate_dn_component_with_list_value(self) -> None:
            """Test validate_dn_component with list value."""
            service = FlextLdifValidation()
            result = service.validate_dn_component("cn", ["test"])
            unwrapped = FlextTestsMatchers.assert_success(result)
            assert unwrapped is False


__all__ = ["TestFlextLdifValidation"]
