from __future__ import annotations

from typing import cast

import pytest
from flext_tests.matchers import FlextTestsMatchers
from flext_tests.utilities import FlextTestsUtilities

from flext_ldif import FlextLdifEntries
from flext_ldif.models import m
from tests import c, m, s

# FlextLdifFixtures and TypedDicts are available from conftest.py (pytest auto-imports)


class TestsTestFlextLdifEntries(s):
    """Test FlextLdifEntries with consolidated parametrized tests.

    Uses nested classes for organization: Factories, TestAttributeExtraction.
    Reduces code duplication through helper methods and factories.
    Uses TestAssertions extensively for maximum code reduction.
    """

    class Factories:
        """Factory methods for creating test data organized as nested class."""

        __test__ = False

        @staticmethod
        def create_entry(
            dn_str: str,
            attributes: dict[str, list[str]] | dict[str, str | list[str]],
        ) -> m.Entry:
            """Create test entry with DN and attributes."""
            # Convert dict[str, list[str]] to dict[str, str | list[str]] for factory
            attrs: dict[str, str | list[str]] = dict(attributes)
            return self.create_entry(dn=dn_str, attributes=attrs)

        @staticmethod
        def create_simple_user_entry() -> m.Entry:
            """Create a simple user entry."""
            return self.create_entry(
                dn=f"cn={c.Values.USER},ou=users,{c.DNs.EXAMPLE}",
                attributes={
                    c.Names.CN: [c.Values.USER],
                    c.Names.SN: [c.Values.USER],
                    c.Names.GIVEN_NAME: [c.Values.USER],
                    c.Names.MAIL: [c.Values.TEST_EMAIL],
                    c.Names.UID: [c.Values.TEST],
                    c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.INET_ORG_PERSON],
                },
            )

        @staticmethod
        def create_service() -> FlextLdifEntries:
            """Create FlextLdifEntries instance."""
            return FlextLdifEntries()

    class TestAttributeExtraction:
        """Test attribute extraction methods - consolidated with parametrization."""

        class TestCases:
            """Factory for test cases - reduces 50+ lines."""

            __test__ = False

            @staticmethod
            def get_get_entry_attribute_cases() -> list[
                tuple[str, str, bool, list[str] | None, str | None]
            ]:
                """Get parametrized test cases for get_entry_attribute."""
                return [
                    ("success", c.Names.CN, True, [c.Values.USER], None),
                    ("not_found", "nonexistent", False, None, "not found"),
                    ("no_attributes", c.Names.CN, False, None, None),
                ]

            @staticmethod
            def get_normalize_attribute_value_cases() -> list[
                tuple[str, object, bool, str | None, str | None]
            ]:
                """Get parametrized test cases for normalize_attribute_value."""
                return [
                    ("list", ["value1"], True, "value1", None),
                    ("string", "  test  ", True, "test", None),
                    ("none", None, False, None, "None"),
                    ("empty_string", "   ", False, None, "empty"),
                ]

            @staticmethod
            def get_get_normalized_attribute_cases() -> list[
                tuple[str, str, bool, str | None]
            ]:
                """Get parametrized test cases for get_normalized_attribute."""
                return [
                    ("success", c.Names.CN, True, c.Values.USER),
                    ("not_found", "nonexistent", False, None),
                ]

        @pytest.mark.parametrize(
            (
                "test_name",
                "attr_name",
                "should_succeed",
                "expected_value",
                "expected_error",
            ),
            TestCases.get_get_entry_attribute_cases(),
        )
        def test_get_entry_attribute(
            self,
            test_name: str,
            attr_name: str,
            should_succeed: bool,
            expected_value: list[str] | None,
            expected_error: str | None,
        ) -> None:
            """Test get_entry_attribute using advanced parametrization - reduces 30+ lines."""
            service = TestFlextLdifEntries.Factories.create_service()

            if test_name == "no_attributes":
                # Create entry with empty attributes explicitly
                dn = m.DistinguishedName(value=c.DNs.TEST_USER)
                attrs = m.LdifAttributes.create({}).unwrap()
                entry = m.Entry(dn=dn, attributes=attrs)
            else:
                entry = TestFlextLdifEntries.Factories.create_simple_user_entry()

            result = service.get_entry_attribute(entry, attr_name)

            if should_succeed:
                FlextTestsMatchers.assert_result_success(result)
                if expected_value is not None:
                    value = FlextTestsUtilities.ResultHelpers.assert_result_success_and_unwrap(
                        result,
                    )
                    FlextTestsMatchers.assert_list_equals(value, expected_value)
            elif expected_error:
                FlextTestsMatchers.assert_result_failure(
                    result,
                    expected_error=expected_error,
                )
            else:
                FlextTestsMatchers.assert_result_failure(result)

        @pytest.mark.parametrize(
            (
                "test_name",
                "input_value",
                "should_succeed",
                "expected_normalized",
                "expected_error",
            ),
            TestCases.get_normalize_attribute_value_cases(),
        )
        def test_normalize_attribute_value(
            self,
            test_name: str,
            input_value: object,
            should_succeed: bool,
            expected_normalized: str | None,
            expected_error: str | None,
        ) -> None:
            """Test normalize_attribute_value using advanced parametrization - reduces 40+ lines."""
            service = TestFlextLdifEntries.Factories.create_service()
            # Cast to proper type for service method
            typed_input: str | list[str] | None = cast(
                "str | list[str] | None",
                input_value,
            )
            result = service.normalize_attribute_value(typed_input)

            if should_succeed:
                FlextTestsMatchers.assert_result_success(result)
                if expected_normalized is not None:
                    normalized = FlextTestsUtilities.ResultHelpers.assert_result_success_and_unwrap(
                        result,
                    )
                    FlextTestsMatchers.assert_strings_equal_case_insensitive(
                        normalized,
                        expected_normalized,
                    )
            elif expected_error:
                FlextTestsMatchers.assert_result_failure(
                    result,
                    expected_error=expected_error,
                )
            else:
                FlextTestsMatchers.assert_result_failure(result)

        @pytest.mark.parametrize(
            ("test_name", "attr_name", "should_succeed", "expected_value"),
            TestCases.get_get_normalized_attribute_cases(),
        )
        def test_get_normalized_attribute(
            self,
            test_name: str,
            attr_name: str,
            should_succeed: bool,
            expected_value: str | None,
        ) -> None:
            """Test get_normalized_attribute using advanced parametrization - reduces 20+ lines."""
            service = TestFlextLdifEntries.Factories.create_service()
            entry = TestFlextLdifEntries.Factories.create_simple_user_entry()
            result = service.get_normalized_attribute(entry, attr_name)

            if should_succeed:
                FlextTestsMatchers.assert_result_success(result)
                if expected_value is not None:
                    value = FlextTestsUtilities.ResultHelpers.assert_result_success_and_unwrap(
                        result,
                    )
                    FlextTestsMatchers.assert_strings_equal_case_insensitive(
                        value,
                        expected_value,
                    )
            else:
                FlextTestsMatchers.assert_result_failure(result)


__all__ = ["TestFlextLdifEntries"]
