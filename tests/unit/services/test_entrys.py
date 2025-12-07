"""Comprehensive tests for FlextLdifEntries service.

Tests entry manipulation, validation, syntax checking, and edge cases
using real implementations and flext_tests matchers for concise assertions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

import pytest

from flext_ldif import FlextLdifUtilities
from flext_ldif.services.entries import FlextLdifEntries
from flext_ldif.services.syntax import FlextLdifSyntax
from flext_ldif.services.validation import FlextLdifValidation
from tests import c, m, s, tf, tm

# FlextLdifFixtures and TypedDicts are available from conftest.py (pytest auto-imports)

# Module-level constants to avoid NameError during class definition
_OPERATIONAL_ATTRS = [
    "createTimestamp",
    "modifyTimestamp",
    "creatorsName",
    "modifiersName",
    "entryCSN",
    "entryUUID",
]
_LONG_VALUE_LENGTH = 10000
_MANY_ATTRS_COUNT = 100
_MANY_ATTRS_REMOVE_COUNT = 50
_UNICODE_DN = "cn=测试,dc=example,dc=com"
_UNICODE_VALUE = "测试值"
_VALID_ATTR_NAMES = ["cn", "sn", "mail", "objectClass", "uid"]
_INVALID_ATTR_NAMES = ["2invalid", "invalid-name", "invalid name"]
_BOOLEAN_OID = "1.3.6.1.4.1.1466.115.121.1.7"
_BOOLEAN_NAME = "Boolean"


class TestFlextLdifEntrys(s):
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

        # Operational attributes - use module-level constants
        OPERATIONAL_ATTRS: Final[list[str]] = _OPERATIONAL_ATTRS

        # Edge case values - use module-level constants
        LONG_VALUE_LENGTH: Final[int] = _LONG_VALUE_LENGTH
        MANY_ATTRS_COUNT: Final[int] = _MANY_ATTRS_COUNT
        MANY_ATTRS_REMOVE_COUNT: Final[int] = _MANY_ATTRS_REMOVE_COUNT

        # Unicode test values - use module-level constants
        UNICODE_DN: Final[str] = _UNICODE_DN
        UNICODE_VALUE: Final[str] = _UNICODE_VALUE

        # Validation test values - use module-level constants
        VALID_ATTR_NAMES: Final[list[str]] = _VALID_ATTR_NAMES
        INVALID_ATTR_NAMES: Final[list[str]] = _INVALID_ATTR_NAMES

        # Syntax test values - use module-level constants
        BOOLEAN_OID: Final[str] = _BOOLEAN_OID
        BOOLEAN_NAME: Final[str] = _BOOLEAN_NAME

        # DN cleaning test cases
        DN_CLEANING_CASES: Final[dict[str, tuple[str, str | None, str | None]]] = {
            "with_spaces": ("cn=test ,dc=example,dc=com", "cn=test", " "),
            "already_clean": (
                "cn=test,dc=example,dc=com",
                "cn=test,dc=example,dc=com",
                None,
            ),
            "with_escaped_chars": ("cn=test\\,user,dc=example", "cn=test\\,user", None),
        }

    class Factories:
        """Entry factories for testing."""

        @staticmethod
        def create_simple_entry() -> m.Entry:
            """Create a simple test entry using factory."""
            return tf.create_entry(
                f"cn=john,ou=users,{c.DNs.EXAMPLE}",
                cn=["john"],
                sn=["Doe"],
                mail=["john@example.com"],
                objectClass=["person", "inetOrgPerson"],
            )

        @staticmethod
        def create_entry_with_operational_attrs() -> m.Entry:
            """Create entry with operational attributes."""
            return tf.create_entry(
                f"cn=jane,ou=users,{c.DNs.EXAMPLE}",
                cn=["jane"],
                sn=["Smith"],
                mail=["jane@example.com"],
                objectClass=["person", "inetOrgPerson"],
                createTimestamp=["20250104120000Z"],
                modifyTimestamp=["20250104120000Z"],
                creatorsName=["cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"],
                modifiersName=["cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"],
                entryCSN=["20250105120000.123456Z#000000#000#000000"],
                entryUUID=["12345678-1234-5678-1234-567812345678"],
            )

        @staticmethod
        def create_entries_batch() -> list[m.Entry]:
            """Create batch of entries for testing."""
            # Access Constants via class attribute after class is fully defined
            operational_attrs = [
                "createTimestamp",
                "modifyTimestamp",
                "creatorsName",
                "modifiersName",
                "entryCSN",
                "entryUUID",
            ]
            return [
                tf.create_entry(
                    f"cn={c.Values.USER}{i},ou=users,{c.DNs.EXAMPLE}",
                    cn=[f"user{i}"],
                    objectClass=["person", "inetOrgPerson"],
                    **(
                        {
                            operational_attrs[i % 3]: ["20250104120000Z"],
                        }
                        if i < 3
                        else {}
                    ),
                )
                for i in range(1, 4)
            ]

    class TestDnCleaning:
        """Test DN cleaning public API."""

        @pytest.mark.parametrize(
            ("scenario", "input_dn", "expected_present", "expected_absent"),
            [
                ("with_spaces", "cn=test ,dc=example,dc=com", "cn=test", " "),
                (
                    "already_clean",
                    "cn=test,dc=example,dc=com",
                    "cn=test,dc=example,dc=com",
                    None,
                ),
                (
                    "with_escaped_chars",
                    "cn=test\\,user,dc=example",
                    "cn=test\\,user",
                    None,
                ),
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
            tm.that(cleaned, is_=str, empty=False)
            if expected_present:
                tm.that(cleaned, contains=expected_present)
            if expected_absent:
                assert expected_absent not in cleaned, (
                    f"DN should not contain '{expected_absent}': {cleaned}"
                )

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
                [c.Names.MAIL],
                [c.Names.MAIL],
                True,
            ),
            "test_remove_multiple_attributes": (
                "remove_multiple",
                "simple_entry",
                [c.Names.MAIL, c.Names.SN, c.Names.OBJECTCLASS],
                [c.Names.MAIL, c.Names.SN, c.Names.OBJECTCLASS],
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
                [c.Names.MAIL, c.Names.SN],
                True,
            ),
            "test_remove_operational_attributes_single": (
                "operational_single",
                "entry_with_operational_attrs",
                None,
                ["createTimestamp", "modifyTimestamp", "creatorsName", "modifiersName"],
                False,
            ),
            "test_remove_operational_attributes_batch": (
                "operational_batch",
                "entries_batch",
                None,
                ["createTimestamp", "modifyTimestamp", "creatorsName"],
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

            fixtures: dict[str, m.Entry | list[m.Entry]] = {
                "simple_entry": simple_entry,
                "entry_with_operational_attrs": entry_with_operational_attrs,
                "entries_batch": entries_batch,
            }
            fixture_data = fixtures[fixture_name]

            if is_selective and fixture_name == "simple_entry":
                assert isinstance(fixture_data, m.Entry)
                result_list = tm.ok(
                    FlextLdifEntries()
                    .with_entries([fixture_data])
                    .with_operation("remove_attributes")
                    .with_attributes_to_remove(attrs_to_remove or [])
                    .execute(),
                    is_=list,
                )
                assert len(result_list) > 0
                result = result_list[0]
                tm.entry(result, not_has_attr=attrs_to_check)
            elif is_selective and fixture_name == "entries_batch":
                assert isinstance(fixture_data, list)
                result_list = tm.ok(
                    FlextLdifEntries()
                    .with_entries(fixture_data)
                    .with_operation("remove_attributes")
                    .with_attributes_to_remove(attrs_to_remove or [])
                    .execute(),
                    is_=list,
                )
                tm.entries(result_list, all_have_attr=attrs_to_check)
                for entry in result_list:
                    if attrs_to_check:
                        tm.entry(entry, not_has_attr=attrs_to_check)
            elif fixture_name == "entries_batch":
                assert isinstance(fixture_data, list)
                result_list = tm.ok(
                    FlextLdifEntries()
                    .with_entries(fixture_data)
                    .with_operation("remove_operational_attributes")
                    .execute(),
                    is_=list,
                )
                tm.entries(result_list, all_have_attr=attrs_to_check)
                for entry in result_list:
                    if attrs_to_check:
                        tm.entry(entry, not_has_attr=attrs_to_check)
            else:
                assert isinstance(fixture_data, m.Entry)
                result_list = tm.ok(
                    FlextLdifEntries()
                    .with_entries([fixture_data])
                    .with_operation("remove_operational_attributes")
                    .execute(),
                    is_=list,
                )
                assert len(result_list) > 0
                result = result_list[0]
                tm.entry(result, not_has_attr=attrs_to_check)

    class TestPatterns:
        """Test execute pattern, builder pattern, and integration scenarios."""

        def test_execute_pattern_operations(self) -> None:
            """Test execute() method with various operations."""
            entries_batch = TestFlextLdifEntrys.Factories.create_entries_batch()
            simple_entry = TestFlextLdifEntrys.Factories.create_simple_entry()

            # Test 1: Batch operational attribute removal - using unified method
            service1 = FlextLdifEntries(
                entries=entries_batch,
                operation="remove_operational_attributes",
            )
            tm.ok_entries(service1.execute(), count=3)

            # Test 2: Selective attribute removal - using unified method
            service2 = FlextLdifEntries(
                entries=[simple_entry],
                operation="remove_attributes",
                attributes_to_remove=[c.Names.MAIL],
            )
            result2 = tm.ok_entries(service2.execute(), count=1)
            tm.entry(result2[0], not_has_attr=c.Names.MAIL)

            # Test 3: Empty batch - using unified method
            service4 = FlextLdifEntries(
                entries=[],
                operation="remove_operational_attributes",
            )
            tm.ok_entries(service4.execute(), empty=True)

        def test_builder_pattern(self) -> None:
            """Test fluent builder pattern."""
            simple_entry = TestFlextLdifEntrys.Factories.create_simple_entry()

            # Test 1: Basic builder
            result1_list = (
                FlextLdifEntries.builder()
                .with_entries([simple_entry])
                .with_operation("remove_operational_attributes")
                .build()
            )
            result1 = tm.entries(result1_list, count=1)
            tm.entry(result1[0], has_attr=c.Names.CN)

            # Test 2: Builder with attributes_to_remove
            result2 = (
                FlextLdifEntries.builder()
                .with_entries([simple_entry])
                .with_operation("remove_attributes")
                .with_attributes_to_remove([c.Names.MAIL, c.Names.SN])
                .build()
            )
            assert len(result2) == 1
            if result2[0].attributes and result2[0].attributes.attributes:
                attrs = result2[0].attributes.attributes
                assert c.Names.MAIL not in attrs
                assert c.Names.SN not in attrs

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
            intermediate_list = tm.ok(
                FlextLdifEntries()
                .with_entries([entry_with_operational_attrs])
                .with_operation("remove_operational_attributes")
                .execute(),
                is_=list,
            )
            intermediate = intermediate_list[0]
            operational_attrs = [
                "createTimestamp",
                "modifyTimestamp",
                "creatorsName",
                "modifiersName",
            ]
            tm.entry(intermediate, not_has_attr=operational_attrs)
            final_list = tm.ok_entries(
                FlextLdifEntries()
                .with_entries([intermediate])
                .with_operation("remove_attributes")
                .with_attributes_to_remove([c.Names.MAIL])
                .execute(),
                count=1,
            )
            final = final_list[0]
            tm.entry(final, not_has_attr=c.Names.MAIL, has_attr=[c.Names.CN])

            # Batch pipeline - using unified methods
            entries_service = FlextLdifEntries()
            batch_result = tm.ok_entries(
                entries_service.remove_operational_attributes_batch(entries_batch),
            )
            # Get all attribute names except CN to remove them (keep CN)
            all_attrs_except_cn: list[str] = []
            if (
                batch_result
                and batch_result[0].attributes
                and batch_result[0].attributes.attributes
            ):
                all_attrs_except_cn = [
                    attr
                    for attr in batch_result[0].attributes.attributes
                    if attr.lower() != c.Names.CN.lower()
                ]
            final_batch = tm.ok_entries(
                entries_service.remove_attributes_batch(
                    batch_result,
                    attributes=all_attrs_except_cn,
                ),
                count=len(entries_batch),
            )
            tm.entries(final_batch, all_have_attr=c.Names.CN, count=len(entries_batch))

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
                entry = tf.create_entry(
                    f"cn={c.Values.TEST},{c.DNs.EXAMPLE}",
                    cn=["empty"],
                )
                result_list = tm.ok(
                    FlextLdifEntries()
                    .with_entries([entry])
                    .with_operation("remove_operational_attributes")
                    .execute(),
                    is_=list,
                )
                result = result_list[0]
                tm.entry(result, has_attr=c.Names.CN)

            elif test_type == "only_operational":
                entry = tf.create_entry(
                    c.DNs.TEST_USER,
                    createTimestamp=["20250104120000Z"],
                    modifyTimestamp=["20250104120000Z"],
                )
                operational_set = {
                    "dn",
                    *["createTimestamp", "modifyTimestamp"],
                }
                attrs_dict = entry.attributes.attributes if entry.attributes else {}
                non_operational = [
                    attr for attr in attrs_dict if attr not in operational_set
                ]
                if non_operational:
                    entry_result = FlextLdifEntries.remove_attributes(
                        entry,
                        non_operational,
                    )
                    entry = tm.ok(entry_result)
                cleaned_list = tm.ok(
                    FlextLdifEntries()
                    .with_entries([entry])
                    .with_operation("remove_operational_attributes")
                    .execute(),
                    is_=list,
                )
                cleaned = cleaned_list[0]
                if cleaned.attributes and cleaned.attributes.attributes:
                    tm.that(
                        len(cleaned.attributes.attributes),
                        lte=1,
                        msg="Should have at most 1 attribute (dn)",
                    )
                else:
                    tm.that(0, lte=1, msg="Should have at most 1 attribute (dn)")

            elif test_type == "unicode_dn":
                entry = tf.create_entry(
                    "cn=测试,dc=example,dc=com",
                    cn=["测试值"],
                )
                result_list = tm.ok(
                    FlextLdifEntries()
                    .with_entries([entry])
                    .with_operation("remove_operational_attributes")
                    .execute(),
                    is_=list,
                )
                result = result_list[0]
                tm.entry(result, has_attr=c.Names.CN)

            elif test_type == "long_values":
                long_value = "x" * 10000
                entry = tf.create_entry(
                    c.DNs.TEST_USER,
                    cn=[c.Values.TEST],
                    description=[long_value],
                )
                result_list = tm.ok(
                    FlextLdifEntries()
                    .with_entries([entry])
                    .with_operation("remove_attributes")
                    .with_attributes_to_remove(["description"])
                    .execute(),
                    is_=list,
                )
                result = result_list[0]
                tm.entry(result, not_has_attr="description")
                tm.entry(result, has_attr=c.Names.CN)

            elif test_type == "many_attributes":
                attrs: dict[str, list[str]] = {
                    f"attr{i}": [f"value{i}"] for i in range(100)
                }
                attrs[c.Names.CN] = [c.Values.TEST]
                entry = tf.create_entry(c.DNs.TEST_USER, **attrs)
                attrs_to_remove = [f"attr{i}" for i in range(50)]
                cleaned_list = tm.ok(
                    FlextLdifEntries()
                    .with_entries([entry])
                    .with_operation("remove_attributes")
                    .with_attributes_to_remove(attrs_to_remove)
                    .execute(),
                    is_=list,
                )
                cleaned = cleaned_list[0]
                for i in range(_MANY_ATTRS_REMOVE_COUNT):
                    tm.entry(cleaned, not_has_attr=f"attr{i}")
                if cleaned.attributes and cleaned.attributes.attributes:
                    assert all(
                        f"attr{i}" in cleaned.attributes.attributes
                        for i in range(
                            50,
                            100,
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
                valid_attr_names = ["cn", "sn", "mail", "objectClass", "uid"]
                for name in valid_attr_names:
                    tm.ok(service.validate_attribute_name(name), eq=True)

            elif test_type == "validate_attr_name_invalid":
                invalid_attr_names = ["2invalid", "invalid-name", "invalid name"]
                for name in invalid_attr_names:
                    tm.ok(service.validate_attribute_name(name), eq=False)

            elif test_type == "validate_objectclass":
                tm.ok(service.validate_objectclass_name(c.Names.PERSON), eq=True)
                tm.ok(service.validate_objectclass_name("invalid class"), eq=False)

            elif test_type == "validate_attr_value":
                tm.ok(service.validate_attribute_value("John Smith"), eq=True)
                tm.ok(service.validate_attribute_value("test", max_length=2), eq=False)

            elif test_type == "validate_dn_component":
                tm.ok(service.validate_dn_component(c.Names.CN, "John Smith"), eq=True)
                tm.ok(service.validate_dn_component("2invalid", "value"), eq=False)

            elif test_type == "validate_attr_names_batch":
                validated = service.validate_attribute_names([
                    c.Names.CN,
                    c.Names.MAIL,
                    "2invalid",
                    c.Names.OBJECTCLASS,
                ]).unwrap()
                assert validated[c.Names.CN] is True
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
                tm.ok(
                    syntax.validate_oid("1.3.6.1.4.1.1466.115.121.1.7"),
                    eq=True,
                )
                tm.ok(syntax.validate_oid("invalid-oid"), eq=False)

            elif test_type == "is_rfc4517_standard":
                tm.ok(syntax.is_rfc4517_standard("1.3.6.1.4.1.1466.115.121.1.7"))

            elif test_type == "lookup_name":
                result = syntax.lookup_name("Boolean")
                if not result.is_success:
                    result = syntax.lookup_name("Boolean".capitalize())
                tm.ok(
                    result,
                    eq=TestFlextLdifEntrys.Constants.BOOLEAN_OID,
                )

            elif test_type == "lookup_oid":
                result_obj = syntax.lookup_oid(
                    TestFlextLdifEntrys.Constants.BOOLEAN_OID
                )
                result = tm.ok(result_obj, is_=str)
                tm.that(
                    result.lower(),
                    eq=TestFlextLdifEntrys.Constants.BOOLEAN_NAME.lower(),
                )

            elif test_type == "resolve_syntax":
                result_obj = syntax.resolve_syntax("1.3.6.1.4.1.1466.115.121.1.7")
                syntax_obj = tm.ok(result_obj)
                tm.that(
                    syntax_obj.oid,
                    eq=TestFlextLdifEntrys.Constants.BOOLEAN_OID,
                )

            elif test_type == "validate_value":
                tm.ok(
                    syntax.validate_value(
                        "TRUE",
                        TestFlextLdifEntrys.Constants.BOOLEAN_OID,
                    ),
                )

            elif test_type == "get_category":
                tm.ok(
                    syntax.get_syntax_category("1.3.6.1.4.1.1466.115.121.1.7"),
                    is_=str,
                )

            elif test_type == "list_all":
                oids = tm.ok(syntax.list_common_syntaxes(), is_=list)
                tm.that(oids, length_gt=0)


__all__ = ["TestFlextLdifEntrys"]
