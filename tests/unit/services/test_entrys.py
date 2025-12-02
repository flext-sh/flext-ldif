"""Entry Service Tests - Comprehensive test coverage for FlextLdifEntries with real implementations.

Modules Tested:
- flext_ldif.services.entries: Entry CRUD, transformation, manipulation
- flext_ldif.services.validation: RFC 4512/4514 LDAP validation
- flext_ldif.services.syntax: RFC 4517 LDAP attribute syntax
- flext_ldif.utilities: DN cleaning, entry operations

Scope:
- DN cleaning with various formats (spaces, escaped chars, already clean)
- Attribute removal (single, multiple, nonexistent, case-insensitive)
- Operational attribute removal (single, batch, case-insensitive)
- Execute pattern, builder pattern, integration pipelines
- Edge cases (no attributes, only operational, unicode, long values, many attributes)
- RFC 4512/4514 validation (attribute names, objectClass, values, DN components)
- RFC 4517 syntax validation (OID format, lookup, resolve, validate value)

Uses Python 3.13 features, factories, parametrization, and helpers for minimal code
with maximum coverage. All tests use real implementations, no mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

import pytest

# from flext_tests import FlextTestsMatchers  # Mocked in conftest
from flext_ldif import FlextLdifModels, FlextLdifUtilities
from flext_ldif.services.entries import FlextLdifEntries
from flext_ldif.services.syntax import FlextLdifSyntax
from flext_ldif.services.validation import FlextLdifValidation
from tests.fixtures.constants import EntryTestConstants, Names, Values
from tests.helpers.test_entry_helpers import EntryTestHelpers
from tests.helpers.test_factories import FlextLdifTestFactories


class TestFlextLdifEntrys:
    """Comprehensive tests for FlextLdifEntries service with real implementations.

    Single class with nested test groups following project patterns.
    Uses factories, parametrization, and helpers for DRY code.
    """

    class TestTypes:
        """Test scenario types organized in nested class."""

        class DnCleaning(StrEnum):
            """DN cleaning test scenarios."""

            WITH_SPACES = "with_spaces"
            ALREADY_CLEAN = "already_clean"
            WITH_ESCAPED_CHARS = "with_escaped_chars"

        class AttributeRemoval(StrEnum):
            """Attribute removal test scenarios."""

            REMOVE_SINGLE = "remove_single"
            REMOVE_MULTIPLE = "remove_multiple"
            REMOVE_NONEXISTENT = "remove_nonexistent"
            CASE_INSENSITIVE = "case_insensitive"
            OPERATIONAL_SINGLE = "operational_single"
            OPERATIONAL_BATCH = "operational_batch"
            CASE_INSENSITIVE_OPERATIONAL = "case_insensitive_operational"

        class Validation(StrEnum):
            """Validation test scenarios."""

            VALIDATE_ATTR_NAME_VALID = "validate_attr_name_valid"
            VALIDATE_ATTR_NAME_INVALID = "validate_attr_name_invalid"
            VALIDATE_OBJECTCLASS = "validate_objectclass"
            VALIDATE_ATTR_VALUE = "validate_attr_value"
            VALIDATE_DN_COMPONENT = "validate_dn_component"
            VALIDATE_ATTR_NAMES_BATCH = "validate_attr_names_batch"

        class Syntax(StrEnum):
            """Syntax validation test scenarios."""

            VALIDATE_OID = "validate_oid"
            IS_RFC4517_STANDARD = "is_rfc4517_standard"
            LOOKUP_NAME = "lookup_name"
            LOOKUP_OID = "lookup_oid"
            RESOLVE_SYNTAX = "resolve_syntax"
            VALIDATE_VALUE = "validate_value"
            GET_CATEGORY = "get_category"
            LIST_ALL = "list_all"

        class EdgeCase(StrEnum):
            """Edge case test scenarios."""

            NO_ATTRIBUTES = "no_attributes"
            ONLY_OPERATIONAL = "only_operational"
            UNICODE_DN = "unicode_dn"
            LONG_VALUES = "long_values"
            MANY_ATTRIBUTES = "many_attributes"

    class Constants:
        """Test constants organized in nested class."""

        # Operational attributes
        OPERATIONAL_ATTRS: Final[list[str]] = EntryTestConstants.OPERATIONAL_ATTRS

        # Edge case values
        LONG_VALUE_LENGTH: Final[int] = EntryTestConstants.LONG_VALUE_LENGTH
        MANY_ATTRS_COUNT: Final[int] = EntryTestConstants.MANY_ATTRS_COUNT
        MANY_ATTRS_REMOVE_COUNT: Final[int] = EntryTestConstants.MANY_ATTRS_REMOVE_COUNT

        # Unicode test values
        UNICODE_DN: Final[str] = EntryTestConstants.UNICODE_DN
        UNICODE_VALUE: Final[str] = EntryTestConstants.UNICODE_VALUE

        # Validation test values
        VALID_ATTR_NAMES: Final[list[str]] = EntryTestConstants.VALID_ATTR_NAMES
        INVALID_ATTR_NAMES: Final[list[str]] = EntryTestConstants.INVALID_ATTR_NAMES

        # Syntax test values
        BOOLEAN_OID: Final[str] = EntryTestConstants.BOOLEAN_OID
        BOOLEAN_NAME: Final[str] = EntryTestConstants.BOOLEAN_NAME

        # DN cleaning test cases
        DN_CLEANING_CASES: Final[dict[str, tuple[str, str | None, str | None]]] = (
            EntryTestConstants.DN_CLEANING_CASES
        )

    class Factories:
        """Entry factories for testing."""

        @staticmethod
        def create_simple_entry() -> FlextLdifModels.Entry:
            """Create a simple test entry using factory."""
            return FlextLdifTestFactories.create_user_entry(
                username="john",
                template=FlextLdifTestFactories.USER_TEMPLATE,
                sn=["Doe"],
                mail=["john@example.com"],
            )

        @staticmethod
        def create_entry_with_operational_attrs() -> FlextLdifModels.Entry:
            """Create entry with operational attributes."""
            return FlextLdifTestFactories.create_entry(
                dn="cn=jane,ou=users,dc=example,dc=com",
                attributes={
                    Names.CN: ["jane"],
                    Names.SN: ["Smith"],
                    Names.MAIL: ["jane@example.com"],
                    **{
                        attr: ["20250104120000Z"]
                        for attr in EntryTestConstants.OPERATIONAL_ATTRS[:4]
                    },
                    "entryCSN": ["20250105120000.123456Z#000000#000#000000"],
                    "entryUUID": ["12345678-1234-5678-1234-567812345678"],
                },
            )

        @staticmethod
        def create_entries_batch() -> list[FlextLdifModels.Entry]:
            """Create batch of entries for testing."""
            return [
                FlextLdifTestFactories.create_entry(
                    f"cn=user{i},ou=users,dc=example,dc=com",
                    {
                        Names.CN: [f"user{i}"],
                        **(
                            {
                                EntryTestConstants.OPERATIONAL_ATTRS[i % 3]: [
                                    "20250104120000Z",
                                ],
                            }
                            if i < 3
                            else {}
                        ),
                    },
                )
                for i in range(1, 4)
            ]

    class TestDnCleaning:
        """Test DN cleaning public API."""

        @pytest.mark.parametrize(
            ("scenario", "input_dn", "expected_present", "expected_absent"),
            [
                (name, *data)
                for name, data in EntryTestConstants.DN_CLEANING_CASES.items()
            ],
        )
        def test_clean_dn(
            self,
            scenario: str,
            input_dn: str,
            expected_present: str | None,
            expected_absent: str | None,
        ) -> None:
            """Parametrized test for DN cleaning."""
            cleaned = FlextLdifUtilities.DN.clean_dn(input_dn)
            assert isinstance(cleaned, str) and len(cleaned) > 0
            if expected_present:
                assert expected_present in cleaned
            if expected_absent:
                assert expected_absent not in cleaned

    class TestAttributeRemoval:
        """Test attribute removal public API."""

        REMOVAL_DATA: Final[
            dict[
                str,
                tuple[
                    str,
                    str,
                    list[str] | None,
                    list[str] | None,
                    bool,
                ],
            ]
        ] = {
            "test_remove_single_attribute": (
                "remove_single",
                "simple_entry",
                [Names.MAIL],
                [Names.MAIL],
                True,
            ),
            "test_remove_multiple_attributes": (
                "remove_multiple",
                "simple_entry",
                [Names.MAIL, Names.SN, Names.OBJECTCLASS],
                [Names.MAIL, Names.SN, Names.OBJECTCLASS],
                True,
            ),
            "test_remove_nonexistent_attribute": (
                "remove_nonexistent",
                "simple_entry",
                ["nonexistent"],
                None,
                False,
            ),
            "test_case_insensitive_attribute_removal": (
                "case_insensitive",
                "simple_entry",
                ["MAIL", "SN"],
                [Names.MAIL, Names.SN],
                True,
            ),
            "test_remove_operational_attributes_single": (
                "operational_single",
                "entry_with_operational_attrs",
                None,
                EntryTestConstants.OPERATIONAL_ATTRS[:4],
                False,
            ),
            "test_remove_operational_attributes_batch": (
                "operational_batch",
                "entries_batch",
                None,
                EntryTestConstants.OPERATIONAL_ATTRS[:3],
                False,
            ),
            "test_case_insensitive_operational_attr_matching": (
                "case_insensitive_operational",
                "entry_with_operational_attrs",
                None,
                ["CREATETIMESTAMP", "modifyTimestamp"],
                False,
            ),
        }

        @pytest.mark.parametrize(
            (
                "scenario",
                "test_type",
                "fixture_name",
                "attrs_to_remove",
                "attrs_to_check",
                "is_selective",
            ),
            [
                (name, data[0], data[1], data[2], data[3], data[4])
                for name, data in REMOVAL_DATA.items()
            ],
        )
        def test_attribute_removal(
            self,
            scenario: str,
            test_type: str,
            fixture_name: str,
            attrs_to_remove: list[str] | None,
            attrs_to_check: list[str] | None,
            is_selective: bool,
        ) -> None:
            """Parametrized test for attribute removal scenarios."""
            simple_entry = TestFlextLdifEntrys.Factories.create_simple_entry()
            entry_with_operational_attrs = (
                TestFlextLdifEntrys.Factories.create_entry_with_operational_attrs()
            )
            entries_batch = TestFlextLdifEntrys.Factories.create_entries_batch()

            fixtures: dict[str, FlextLdifModels.Entry | list[FlextLdifModels.Entry]] = {
                "simple_entry": simple_entry,
                "entry_with_operational_attrs": entry_with_operational_attrs,
                "entries_batch": entries_batch,
            }
            fixture_data = fixtures[fixture_name]

            if is_selective and fixture_name == "simple_entry":
                assert isinstance(fixture_data, FlextLdifModels.Entry)
                EntryTestHelpers.test_remove_attributes_complete(
                    fixture_data,
                    attrs_to_remove or [],
                    expected_removed=attrs_to_check,
                )
            elif is_selective and fixture_name == "entries_batch":
                assert isinstance(fixture_data, list)
                EntryTestHelpers.test_batch_remove_attributes_complete(
                    fixture_data,
                    attrs_to_remove or [],
                    expected_removed=attrs_to_check,
                )
            elif fixture_name == "entries_batch":
                assert isinstance(fixture_data, list)
                EntryTestHelpers.test_batch_remove_operational_attributes_complete(
                    fixture_data,
                    expected_removed=attrs_to_check,
                )
            else:
                assert isinstance(fixture_data, FlextLdifModels.Entry)
                EntryTestHelpers.test_remove_operational_attributes_complete(
                    fixture_data,
                    expected_removed=attrs_to_check,
                )

    class TestPatterns:
        """Test execute pattern, builder pattern, and integration scenarios."""

        def test_execute_pattern_operations(self) -> None:
            """Test execute() method with various operations."""
            entries_batch = TestFlextLdifEntrys.Factories.create_entries_batch()
            simple_entry = TestFlextLdifEntrys.Factories.create_simple_entry()

            # Test 1: Batch operational attribute removal
            service1 = FlextLdifEntries(
                entries=entries_batch,
                operation="remove_operational_attributes",
            )
            result1 = FlextTestsMatchers.assert_success(service1.execute())
            assert isinstance(result1, list) and len(result1) == 3

            # Test 2: Selective attribute removal
            service2 = FlextLdifEntries(
                entries=[simple_entry],
                operation="remove_attributes",
                attributes_to_remove=[Names.MAIL],
            )
            result2 = FlextTestsMatchers.assert_success(service2.execute())
            assert isinstance(result2, list) and len(result2) == 1
            assert Names.MAIL not in result2[0].attributes.attributes

            # Test 3: Empty batch
            service4 = FlextLdifEntries(
                entries=[],
                operation="remove_operational_attributes",
            )
            result4 = FlextTestsMatchers.assert_success(service4.execute())
            assert isinstance(result4, list) and result4 == []

        def test_builder_pattern(self) -> None:
            """Test fluent builder pattern."""
            simple_entry = TestFlextLdifEntrys.Factories.create_simple_entry()

            # Test 1: Basic builder
            result1 = (
                FlextLdifEntries.builder()
                .with_entries([simple_entry])
                .with_operation("remove_operational_attributes")
                .build()
            )
            assert isinstance(result1, list) and len(result1) == 1
            assert Names.CN in result1[0].attributes.attributes

            # Test 2: Builder with attributes_to_remove
            result2 = (
                FlextLdifEntries.builder()
                .with_entries([simple_entry])
                .with_operation("remove_attributes")
                .with_attributes_to_remove([Names.MAIL, Names.SN])
                .build()
            )
            attrs = result2[0].attributes.attributes
            assert Names.MAIL not in attrs and Names.SN not in attrs

            # Test 3: Builder chaining returns same instance
            builder = FlextLdifEntries.builder()
            assert builder.with_entries([simple_entry]) is builder

        def test_integration_pipeline(self) -> None:
            """Test realistic processing pipelines."""
            entry_with_operational_attrs = (
                TestFlextLdifEntrys.Factories.create_entry_with_operational_attrs()
            )
            entries_batch = TestFlextLdifEntrys.Factories.create_entries_batch()

            # Single entry pipeline
            intermediate = EntryTestHelpers.test_remove_operational_attributes_complete(
                entry_with_operational_attrs,
                expected_removed=EntryTestConstants.OPERATIONAL_ATTRS[:4],
            )
            assert intermediate is not None
            final = EntryTestHelpers.test_remove_attributes_complete(
                intermediate,
                [Names.MAIL],
                expected_removed=[Names.MAIL],
                expected_present=[Names.CN],
            )
            assert final is not None
            assert Names.MAIL not in final.attributes.attributes
            assert "createTimestamp" not in final.attributes.attributes

            # Batch pipeline
            batch_result = FlextTestsMatchers.assert_success(
                FlextLdifEntries.remove_operational_attributes_batch(entries_batch),
            )
            final_batch = FlextTestsMatchers.assert_success(
                FlextLdifEntries.remove_attributes_batch(
                    batch_result,
                    attributes=[Names.CN],
                ),
            )
            assert len(final_batch) == len(entries_batch)
            for entry in final_batch:
                assert Names.CN not in entry.attributes.attributes

    class TestEdgeCases:
        """Test edge cases and special situations."""

        EDGE_CASE_DATA: Final[dict[str, tuple[str]]] = {
            "test_entry_with_no_attributes": ("no_attributes",),
            "test_entry_with_only_operational_attributes": ("only_operational",),
            "test_unicode_in_dn": ("unicode_dn",),
            "test_very_long_attribute_values": ("long_values",),
            "test_entry_with_many_attributes": ("many_attributes",),
        }

        @pytest.mark.parametrize(
            ("scenario", "test_type"),
            [(name, data[0]) for name, data in EDGE_CASE_DATA.items()],
        )
        def test_edge_case(
            self,
            scenario: str,
            test_type: str,
        ) -> None:
            """Parametrized test for edge cases."""
            if test_type == "no_attributes":
                entry = FlextLdifTestFactories.create_entry(
                    "cn=empty,dc=example,dc=com",
                    {Names.CN: ["empty"]},
                )
                EntryTestHelpers.test_remove_operational_attributes_complete(
                    entry,
                    expected_present=[Names.CN],
                )

            elif test_type == "only_operational":
                entry = FlextLdifTestFactories.create_entry(
                    "cn=test,dc=example,dc=com",
                    {
                        attr: ["20250104120000Z"]
                        for attr in EntryTestConstants.OPERATIONAL_ATTRS[:2]
                    },
                )
                operational_set = {"dn", *EntryTestConstants.OPERATIONAL_ATTRS[:2]}
                non_operational = [
                    attr
                    for attr in entry.attributes.attributes
                    if attr not in operational_set
                ]
                if non_operational:
                    entries_service = FlextLdifEntries()
                    entry_result = entries_service.remove_attributes(
                        entry=entry,
                        attributes_to_remove=non_operational,
                    )
                    entry = FlextTestsMatchers.assert_success(entry_result)
                cleaned = EntryTestHelpers.test_remove_operational_attributes_complete(
                    entry,
                )
                assert cleaned is not None
                assert (
                    len(cleaned.attributes.attributes) <= 1
                    or "dn" in cleaned.attributes.attributes
                )

            elif test_type == "unicode_dn":
                entry = FlextLdifTestFactories.create_entry(
                    EntryTestConstants.UNICODE_DN,
                    {Names.CN: [EntryTestConstants.UNICODE_VALUE]},
                )
                EntryTestHelpers.test_remove_operational_attributes_complete(
                    entry,
                    expected_present=[Names.CN],
                )

            elif test_type == "long_values":
                long_value = "x" * EntryTestConstants.LONG_VALUE_LENGTH
                entry = FlextLdifTestFactories.create_entry(
                    "cn=test,dc=example,dc=com",
                    {Names.CN: [Values.TEST], "description": [long_value]},
                )
                EntryTestHelpers.test_remove_attributes_complete(
                    entry,
                    ["description"],
                    expected_removed=["description"],
                    expected_present=[Names.CN],
                )

            elif test_type == "many_attributes":
                attrs: dict[str, str | list[str]] = {
                    f"attr{i}": [f"value{i}"]
                    for i in range(EntryTestConstants.MANY_ATTRS_COUNT)
                }
                attrs[Names.CN] = [Values.TEST]
                entry = FlextLdifTestFactories.create_entry(
                    "cn=test,dc=example,dc=com",
                    attrs,
                )
                cleaned = EntryTestHelpers.test_remove_attributes_complete(
                    entry,
                    [
                        f"attr{i}"
                        for i in range(EntryTestConstants.MANY_ATTRS_REMOVE_COUNT)
                    ],
                )
                assert cleaned is not None
                assert all(
                    f"attr{i}" not in cleaned.attributes.attributes
                    for i in range(EntryTestConstants.MANY_ATTRS_REMOVE_COUNT)
                )
                assert all(
                    f"attr{i}" in cleaned.attributes.attributes
                    for i in range(
                        EntryTestConstants.MANY_ATTRS_REMOVE_COUNT,
                        EntryTestConstants.MANY_ATTRS_COUNT,
                    )
                )

    class TestValidation:
        """RFC 4512/4514 LDAP validation tests."""

        VALIDATION_DATA: Final[dict[str, tuple[str]]] = {
            "test_validate_attribute_name_valid": ("validate_attr_name_valid",),
            "test_validate_attribute_name_invalid": ("validate_attr_name_invalid",),
            "test_validate_objectclass_name": ("validate_objectclass",),
            "test_validate_attribute_value": ("validate_attr_value",),
            "test_validate_dn_component": ("validate_dn_component",),
            "test_validate_attribute_names_batch": ("validate_attr_names_batch",),
        }

        @pytest.mark.parametrize(
            ("scenario", "test_type"),
            [(name, data[0]) for name, data in VALIDATION_DATA.items()],
        )
        def test_validation_scenarios(
            self,
            scenario: str,
            test_type: str,
        ) -> None:
            """Parametrized test for validation scenarios."""
            service = FlextLdifValidation()

            if test_type == "validate_attr_name_valid":
                for name in EntryTestConstants.VALID_ATTR_NAMES:
                    assert service.validate_attribute_name(name).unwrap() is True

            elif test_type == "validate_attr_name_invalid":
                for name in EntryTestConstants.INVALID_ATTR_NAMES:
                    assert service.validate_attribute_name(name).unwrap() is False

            elif test_type == "validate_objectclass":
                assert service.validate_objectclass_name(Names.PERSON).unwrap() is True
                assert (
                    service.validate_objectclass_name("invalid class").unwrap() is False
                )

            elif test_type == "validate_attr_value":
                assert service.validate_attribute_value("John Smith").unwrap() is True
                assert (
                    service.validate_attribute_value("test", max_length=2).unwrap()
                    is False
                )

            elif test_type == "validate_dn_component":
                assert (
                    service.validate_dn_component(Names.CN, "John Smith").unwrap()
                    is True
                )
                assert (
                    service.validate_dn_component("2invalid", "value").unwrap() is False
                )

            elif test_type == "validate_attr_names_batch":
                validated = service.validate_attribute_names([
                    Names.CN,
                    Names.MAIL,
                    "2invalid",
                    Names.OBJECTCLASS,
                ]).unwrap()
                assert validated[Names.CN] is True
                assert validated["2invalid"] is False

    class TestSyntax:
        """RFC 4517 LDAP attribute syntax tests."""

        SYNTAX_DATA: Final[dict[str, tuple[str]]] = {
            "test_validate_oid_format": ("validate_oid",),
            "test_is_rfc4517_standard": ("is_rfc4517_standard",),
            "test_lookup_syntax_name": ("lookup_name",),
            "test_lookup_syntax_oid": ("lookup_oid",),
            "test_resolve_syntax_oid": ("resolve_syntax",),
            "test_validate_syntax_value": ("validate_value",),
            "test_get_syntax_type": ("get_category",),
            "test_list_all_syntaxes": ("list_all",),
        }

        @pytest.mark.parametrize(
            ("scenario", "test_type"),
            [(name, data[0]) for name, data in SYNTAX_DATA.items()],
        )
        def test_syntax_scenarios(
            self,
            scenario: str,
            test_type: str,
        ) -> None:
            """Parametrized test for syntax scenarios."""
            syntax = FlextLdifSyntax()

            if test_type == "validate_oid":
                assert (
                    syntax.validate_oid(EntryTestConstants.BOOLEAN_OID).unwrap() is True
                )
                assert syntax.validate_oid("invalid-oid").unwrap() is False

            elif test_type == "is_rfc4517_standard":
                assert syntax.is_rfc4517_standard(
                    EntryTestConstants.BOOLEAN_OID,
                ).is_success

            elif test_type == "lookup_name":
                result = syntax.lookup_name(EntryTestConstants.BOOLEAN_NAME)
                if not result.is_success:
                    result = syntax.lookup_name(
                        EntryTestConstants.BOOLEAN_NAME.capitalize(),
                    )
                assert result.unwrap() == EntryTestConstants.BOOLEAN_OID

            elif test_type == "lookup_oid":
                assert (
                    syntax.lookup_oid(EntryTestConstants.BOOLEAN_OID).unwrap().lower()
                    == EntryTestConstants.BOOLEAN_NAME
                )

            elif test_type == "resolve_syntax":
                assert (
                    syntax.resolve_syntax(EntryTestConstants.BOOLEAN_OID).unwrap().oid
                    == EntryTestConstants.BOOLEAN_OID
                )

            elif test_type == "validate_value":
                assert syntax.validate_value(
                    "TRUE",
                    EntryTestConstants.BOOLEAN_OID,
                ).is_success

            elif test_type == "get_category":
                result = syntax.get_syntax_category(EntryTestConstants.BOOLEAN_OID)
                assert result.is_success and isinstance(result.unwrap(), str)

            elif test_type == "list_all":
                oids = syntax.list_common_syntaxes().unwrap()
                assert isinstance(oids, list) and len(oids) > 0


__all__ = ["TestFlextLdifEntrys"]
