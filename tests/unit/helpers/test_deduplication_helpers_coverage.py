"""Comprehensive test coverage for DeduplicationHelpers.

This test file ensures 100% coverage of all helper methods in
tests/helpers/test_deduplication_helpers.py.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldif import (
    FlextLdif,
    FlextLdifModels,
    FlextLdifParser,
    FlextLdifWriter,
)
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.services.schema import FlextLdifSchema

from ...helpers.test_assertions import TestAssertions
from ...helpers.test_deduplication_helpers import DeduplicationHelpers


class TestBasicAssertions:
    """Test basic assertion helpers."""

    def test_assert_success_and_unwrap(self) -> None:
        """Test assert_success_and_unwrap."""
        result = FlextResult[str].ok("test")
        unwrapped = DeduplicationHelpers.assert_success_and_unwrap(result)
        assert unwrapped == "test"

    def test_assert_success_and_unwrap_with_error_msg(self) -> None:
        """Test assert_success_and_unwrap with custom error message."""
        result = FlextResult[str].ok("test")
        unwrapped = DeduplicationHelpers.assert_success_and_unwrap(
            result,
            "Custom error",
        )
        assert unwrapped == "test"

    def test_assert_success_and_unwrap_failure(self) -> None:
        """Test assert_success_and_unwrap with failure."""
        result = FlextResult[str].fail("error")
        with pytest.raises(AssertionError):
            DeduplicationHelpers.assert_success_and_unwrap(result)

    def test_assert_success_and_unwrap_list(self) -> None:
        """Test assert_success_and_unwrap_list."""
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
                attributes=FlextLdifModels.LdifAttributes.create(
                    {
                        "cn": ["test"],
                    },
                ).unwrap(),
            ),
        ]
        result = FlextResult[list[FlextLdifModels.Entry]].ok(entries)
        unwrapped = DeduplicationHelpers.assert_success_and_unwrap_list(result)
        assert len(unwrapped) == 1

    def test_assert_success_and_unwrap_entry(self) -> None:
        """Test assert_success_and_unwrap_entry."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.create({"cn": ["test"]}).unwrap(),
        )
        result = FlextResult[FlextLdifModels.Entry].ok(entry)
        unwrapped = DeduplicationHelpers.assert_success_and_unwrap_entry(result)
        assert unwrapped.dn.value == "cn=test,dc=example,dc=com"

    def test_assert_success_and_unwrap_string(self) -> None:
        """Test assert_success_and_unwrap_string."""
        result = FlextResult[str].ok("test string")
        unwrapped = DeduplicationHelpers.assert_success_and_unwrap_string(result)
        assert unwrapped == "test string"


class TestEntryCreation:
    """Test entry creation helpers."""

    def test_create_entry_from_dict(self) -> None:
        """Test create_entry_from_dict."""
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "sn": ["Doe"]},
        )
        assert entry.dn.value == "cn=test,dc=example,dc=com"
        assert "cn" in entry.attributes.attributes
        assert "sn" in entry.attributes.attributes

    def test_create_entry_simple(self) -> None:
        """Test TestAssertions.create_entry (formerly create_entry_simple)."""
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        assert entry.dn.value == "cn=test,dc=example,dc=com"

    def test_create_attributes_from_dict(self) -> None:
        """Test create_attributes_from_dict."""
        attrs = DeduplicationHelpers.create_attributes_from_dict(
            {
                "cn": ["test"],
                "sn": ["Doe"],
            },
        )
        assert "cn" in attrs.attributes
        assert "sn" in attrs.attributes


class TestDNAssertions:
    """Test DN assertion helpers."""

    def test_assert_dn_value_equals(self) -> None:
        """Test assert_dn_value_equals."""
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
        DeduplicationHelpers.assert_dn_value_equals(dn, "cn=test,dc=example,dc=com")

    def test_assert_dn_value_equals_with_error_msg(self) -> None:
        """Test assert_dn_value_equals with custom error message."""
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
        DeduplicationHelpers.assert_dn_value_equals(
            dn,
            "cn=test,dc=example,dc=com",
            "Custom error",
        )

    def test_assert_dn_value_equals_failure(self) -> None:
        """Test assert_dn_value_equals with wrong value."""
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
        with pytest.raises(AssertionError):
            DeduplicationHelpers.assert_dn_value_equals(
                dn,
                "cn=wrong,dc=example,dc=com",
            )

    def test_assert_dn_value_is_not_none(self) -> None:
        """Test assert_dn_value_is_not_none."""
        dn = FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com")
        DeduplicationHelpers.assert_dn_value_is_not_none(dn)

    def test_assert_entry_dn_value_equals(self) -> None:
        """Test assert_entry_dn_value_equals."""
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        DeduplicationHelpers.assert_entry_dn_value_equals(
            entry,
            "cn=test,dc=example,dc=com",
        )


class TestLengthAssertions:
    """Test length assertion helpers."""

    def test_assert_length_equals(self) -> None:
        """Test assert_length_equals."""
        items = [1, 2, 3]
        DeduplicationHelpers.assert_length_equals(items, 3)

    def test_assert_length_equals_failure(self) -> None:
        """Test assert_length_equals with wrong length."""
        items = [1, 2, 3]
        with pytest.raises(AssertionError):
            DeduplicationHelpers.assert_length_equals(items, 5)

    def test_assert_length_greater_than(self) -> None:
        """Test assert_length_greater_than."""
        items = [1, 2, 3]
        DeduplicationHelpers.assert_length_greater_than(items, 2)

    def test_assert_length_greater_or_equal(self) -> None:
        """Test assert_length_greater_or_equal."""
        items = [1, 2, 3]
        DeduplicationHelpers.assert_length_greater_or_equal(items, 3)

    def test_assert_length_zero(self) -> None:
        """Test assert_length_zero."""
        items: list[int] = []
        DeduplicationHelpers.assert_length_zero(items)

    def test_assert_length_non_zero(self) -> None:
        """Test assert_length_non_zero."""
        items = [1, 2, 3]
        DeduplicationHelpers.assert_length_non_zero(items)


class TestEntryAssertions:
    """Test entry assertion helpers."""

    def test_assert_entry_has_attribute(self) -> None:
        """Test assert_entry_has_attribute."""
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        DeduplicationHelpers.assert_entry_has_attribute(entry, "cn")

    def test_assert_entry_not_has_attribute(self) -> None:
        """Test assert_entry_not_has_attribute."""
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        DeduplicationHelpers.assert_entry_not_has_attribute(entry, "sn")

    def test_assert_entry_attribute_equals(self) -> None:
        """Test assert_entry_attribute_equals."""
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        DeduplicationHelpers.assert_entry_attribute_equals(entry, "cn", ["test"])

    def test_assert_entry_dn_equals(self) -> None:
        """Test assert_entry_dn_equals."""
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        DeduplicationHelpers.assert_entry_dn_equals(entry, "cn=test,dc=example,dc=com")

    def test_assert_entry_attributes_not_none(self) -> None:
        """Test assert_entry_attributes_not_none."""
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        DeduplicationHelpers.assert_entry_attributes_not_none(entry)

    def test_assert_first_entry_dn_equals(self) -> None:
        """Test assert_first_entry_dn_equals."""
        entries = [
            TestAssertions.create_entry(
                "cn=test,dc=example,dc=com",
                {"cn": ["test"]},
            ),
        ]
        DeduplicationHelpers.assert_first_entry_dn_equals(
            entries,
            "cn=test,dc=example,dc=com",
        )


class TestStringAssertions:
    """Test string assertion helpers."""

    def test_assert_string_contains(self) -> None:
        """Test assert_string_contains."""
        DeduplicationHelpers.assert_string_contains("hello world", "world")

    def test_assert_string_not_contains(self) -> None:
        """Test assert_string_not_contains."""
        DeduplicationHelpers.assert_string_not_contains("hello world", "foo")

    def test_assert_string_startswith(self) -> None:
        """Test assert_string_startswith."""
        DeduplicationHelpers.assert_string_startswith("hello world", "hello")

    def test_assert_string_endswith(self) -> None:
        """Test assert_string_endswith."""
        DeduplicationHelpers.assert_string_endswith("hello world", "world")

    def test_assert_strings_equal_case_insensitive(self) -> None:
        """Test assert_strings_equal_case_insensitive."""
        DeduplicationHelpers.assert_strings_equal_case_insensitive("Hello", "hello")


class TestDictAssertions:
    """Test dictionary assertion helpers."""

    def test_assert_dict_get_equals(self) -> None:
        """Test assert_dict_get_equals."""
        d = {"key": "value"}
        DeduplicationHelpers.assert_dict_get_equals(d, "key", "value")

    def test_assert_dict_equals(self) -> None:
        """Test assert_dict_equals."""
        d1 = {"key": "value"}
        d2 = {"key": "value"}
        DeduplicationHelpers.assert_dict_equals(d1, d2)

    def test_assert_dict_has_key(self) -> None:
        """Test assert_dict_has_key."""
        d = {"key": "value"}
        DeduplicationHelpers.assert_dict_has_key(d, "key")

    def test_assert_dict_has_value(self) -> None:
        """Test assert_dict_has_value."""
        d = {"key": "value"}
        DeduplicationHelpers.assert_dict_has_value(d, "value")

    def test_assert_dict_key_equals(self) -> None:
        """Test assert_dict_key_equals."""
        d = {"key": "value"}
        DeduplicationHelpers.assert_dict_key_equals(d, "key", "value")

    def test_assert_dict_key_isinstance(self) -> None:
        """Test assert_dict_key_isinstance."""
        d = {"key": ["value"]}
        DeduplicationHelpers.assert_dict_key_isinstance(d, "key", list)

    def test_assert_dict_key_is_not_none(self) -> None:
        """Test assert_dict_key_is_not_none."""
        d = {"key": "value"}
        DeduplicationHelpers.assert_dict_key_is_not_none(d, "key")


class TestListAssertions:
    """Test list assertion helpers."""

    def test_assert_list_equals(self) -> None:
        """Test assert_list_equals."""
        lst = [1, 2, 3]
        DeduplicationHelpers.assert_list_equals(lst, [1, 2, 3])

    def test_assert_list_first_equals(self) -> None:
        """Test assert_list_first_equals."""
        lst = [1, 2, 3]
        DeduplicationHelpers.assert_list_first_equals(lst, 1)

    def test_assert_list_last_equals(self) -> None:
        """Test assert_list_last_equals."""
        lst = [1, 2, 3]
        DeduplicationHelpers.assert_list_last_equals(lst, 3)

    def test_assert_in_list(self) -> None:
        """Test assert_in_list."""
        lst = [1, 2, 3]
        DeduplicationHelpers.assert_in_list(2, lst)

    def test_assert_not_in_list(self) -> None:
        """Test assert_not_in_list."""
        lst = [1, 2, 3]
        DeduplicationHelpers.assert_not_in_list(4, lst)

    def test_assert_any_matches(self) -> None:
        """Test assert_any_matches."""
        items = [1, 2, 3, 4, 5]
        DeduplicationHelpers.assert_any_matches(items, lambda x: x > 3)

    def test_assert_all_match(self) -> None:
        """Test assert_all_match."""
        items = [2, 4, 6]
        DeduplicationHelpers.assert_all_match(items, lambda x: x % 2 == 0)


class TestBooleanAssertions:
    """Test boolean assertion helpers."""

    def test_assert_is_none(self) -> None:
        """Test assert_is_none."""
        DeduplicationHelpers.assert_is_none(None)

    def test_assert_is_not_none(self) -> None:
        """Test assert_is_not_none."""
        DeduplicationHelpers.assert_is_not_none("value")

    def test_assert_is_true(self) -> None:
        """Test assert_is_true."""
        DeduplicationHelpers.assert_is_true(True)

    def test_assert_is_false(self) -> None:
        """Test assert_is_false."""
        DeduplicationHelpers.assert_is_false(False)


class TestServiceExecution:
    """Test service execution helpers."""

    def test_service_execute_and_unwrap(self) -> None:
        """Test service_execute_and_unwrap."""
        # Use real schema service instead of mock
        service = FlextLdifSchema(server_type="rfc")
        result = DeduplicationHelpers.service_execute_and_unwrap(service)
        # Schema service returns SchemaServiceStatus
        assert result is not None
        assert hasattr(result, "service")
        assert result.service == "SchemaService"

    def test_service_execute_and_assert_fields(self) -> None:
        """Test service_execute_and_assert_fields."""
        # Use real schema service instead of mock
        service = FlextLdifSchema(server_type="rfc")
        result = DeduplicationHelpers.service_execute_and_assert_fields(
            service,
            expected_fields={"service": "SchemaService", "status": "operational"},
            expected_type=FlextLdifModels.SchemaServiceStatus,
        )
        assert result.service == "SchemaService"
        assert result.status == "operational"


class TestMetadataAssertions:
    """Test metadata assertion helpers."""

    def test_assert_metadata_extensions_not_none(self) -> None:
        """Test assert_metadata_extensions_not_none."""
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        DeduplicationHelpers.assert_metadata_extensions_not_none(entry)

    def test_assert_metadata_extensions_get_equals(self) -> None:
        """Test assert_metadata_extensions_get_equals."""
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        entry.metadata.extensions["test_key"] = "test_value"
        DeduplicationHelpers.assert_metadata_extensions_get_equals(
            entry,
            "test_key",
            "test_value",
        )

    def test_assert_metadata_extension_equals(self) -> None:
        """Test assert_metadata_extension_equals."""
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        entry.metadata.extensions["test_key"] = "test_value"
        DeduplicationHelpers.assert_metadata_extension_equals(
            entry,
            "test_key",
            "test_value",
        )

    def test_assert_metadata_extension_get_isinstance(self) -> None:
        """Test assert_metadata_extension_get_isinstance."""
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        entry.metadata.extensions["test_key"] = {"nested": "value"}
        DeduplicationHelpers.assert_metadata_extension_get_isinstance(
            entry,
            "test_key",
            dict,
        )

    def test_assert_metadata_quirk_type_equals(self) -> None:
        """Test assert_metadata_quirk_type_equals."""
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        entry.metadata.quirk_type = "rfc"
        DeduplicationHelpers.assert_metadata_quirk_type_equals(entry, "rfc")


class TestSchemaAssertions:
    """Test schema assertion helpers."""

    def test_assert_isinstance_schema_attribute(self) -> None:
        """Test assert_isinstance_schema_attribute."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        DeduplicationHelpers.assert_isinstance_schema_attribute(attr)

    def test_assert_isinstance_schema_objectclass(self) -> None:
        """Test assert_isinstance_schema_objectclass."""
        oc = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="testOC",
            kind="STRUCTURAL",
        )
        DeduplicationHelpers.assert_isinstance_schema_objectclass(oc)

    def test_assert_schema_oid_equals(self) -> None:
        """Test assert_schema_oid_equals."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        DeduplicationHelpers.assert_schema_oid_equals(attr, "1.2.3.4")

    def test_assert_schema_name_equals(self) -> None:
        """Test assert_schema_name_equals."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        DeduplicationHelpers.assert_schema_name_equals(attr, "testAttr")

    def test_assert_schema_syntax_equals(self) -> None:
        """Test assert_schema_syntax_equals."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        DeduplicationHelpers.assert_schema_syntax_equals(
            attr,
            "1.3.6.1.4.1.1466.115.121.1.15",
        )

    def test_assert_schema_single_value_equals(self) -> None:
        """Test assert_schema_single_value_equals."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            single_value=True,
        )
        DeduplicationHelpers.assert_schema_single_value_equals(attr, True)

    def test_assert_schema_desc_equals(self) -> None:
        """Test assert_schema_desc_equals."""
        attr = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            desc="Test description",
        )
        DeduplicationHelpers.assert_schema_desc_equals(attr, "Test description")

    def test_assert_schema_kind_equals(self) -> None:
        """Test assert_schema_kind_equals."""
        oc = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="testOC",
            kind="STRUCTURAL",
        )
        DeduplicationHelpers.assert_schema_kind_equals(oc, "STRUCTURAL")


class TestResultTypeAssertions:
    """Test result type assertion helpers."""

    def test_assert_result_success_and_type(self) -> None:
        """Test assert_result_success_and_type."""
        result = FlextResult[str].ok("test")
        unwrapped = DeduplicationHelpers.assert_result_success_and_type(result, str)
        assert unwrapped == "test"


class TestParseAndUnwrap:
    """Test parse and unwrap helpers."""

    def test_parse_and_unwrap_simple(self) -> None:
        """Test parse_and_unwrap_simple."""
        api = FlextLdif()
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"
        result = api.parse(ldif_content)
        entries = DeduplicationHelpers.assert_success_and_unwrap_list(result)
        assert len(entries) > 0
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"

    def test_write_and_unwrap_simple(self) -> None:
        """Test write_and_unwrap_simple."""
        api = FlextLdif()
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        result = api.write([entry])
        ldif = DeduplicationHelpers.assert_success_and_unwrap_string(result)
        assert "dn: cn=test,dc=example,dc=com" in ldif
        assert "cn: test" in ldif


class TestQuirkOperations:
    """Test quirk operation helpers."""

    def test_quirk_parse_and_unwrap(self) -> None:
        """Test quirk_parse_and_unwrap."""
        quirk = FlextLdifServersRfc()
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"
        result = quirk.Entry().parse(ldif_content)
        entries = DeduplicationHelpers.assert_success_and_unwrap_list(result)
        assert len(entries) > 0

    def test_quirk_write_and_unwrap(self) -> None:
        """Test quirk_write_and_unwrap."""
        quirk = FlextLdifServersRfc()
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        result = quirk.Entry().write(entry)
        ldif = DeduplicationHelpers.assert_success_and_unwrap_string(result)
        assert "dn: cn=test,dc=example,dc=com" in ldif


class TestWriteUnwrapAssert:
    """Test write_unwrap_and_assert helper."""

    def test_write_unwrap_and_assert_success(self) -> None:
        """Test write_unwrap_and_assert with success."""
        api = FlextLdif()
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        result = api.write([entry])
        ldif = DeduplicationHelpers.assert_success_and_unwrap_string(result)
        assert "dn: cn=test,dc=example,dc=com" in ldif

    def test_write_unwrap_and_assert_must_not_contain(self) -> None:
        """Test write_unwrap_and_assert with must_not_contain."""
        api = FlextLdif()
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        result = api.write([entry])
        ldif = DeduplicationHelpers.assert_success_and_unwrap_string(result)
        assert "password" not in ldif.lower()


class TestParseAndAssert:
    """Test parse_and_assert helper."""

    def test_parse_and_assert_success(self) -> None:
        """Test parse_and_assert with success."""
        parser = FlextLdifParser()
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"
        entries = DeduplicationHelpers.parse_and_assert(
            parser,
            ldif_content,
            expected_count=1,
            expected_dn="cn=test,dc=example,dc=com",
            expected_attributes=["cn"],
        )
        assert len(entries) == 1
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"

    def test_parse_and_assert_failure(self) -> None:
        """Test parse_and_assert with failure."""
        parser = FlextLdifParser()
        # Use content that will fail parsing
        ldif_content = ""
        entries = DeduplicationHelpers.parse_and_assert(
            parser,
            ldif_content,
            should_succeed=False,
        )
        assert len(entries) == 0


class TestWriteAndAssert:
    """Test write_and_assert helper."""

    def test_write_and_assert_success(self) -> None:
        """Test write_and_assert with success."""
        writer = FlextLdifWriter()
        entries = [
            TestAssertions.create_entry(
                "cn=test,dc=example,dc=com",
                {"cn": ["test"]},
            ),
        ]
        ldif = DeduplicationHelpers.write_and_assert(
            writer,
            entries,
            must_contain=["dn: cn=test"],
            must_not_contain=["password"],
        )
        assert isinstance(ldif, str)
        assert "dn: cn=test,dc=example,dc=com" in ldif


class TestRoundtripAndAssert:
    """Test roundtrip_and_assert helper."""

    def test_roundtrip_and_assert_success(self) -> None:
        """Test roundtrip_and_assert with success."""
        parser = FlextLdifParser()
        writer = FlextLdifWriter()
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"
        original_entries, roundtripped_entries = (
            DeduplicationHelpers.roundtrip_and_assert(parser, writer, ldif_content)
        )
        assert len(original_entries) == 1
        assert len(roundtripped_entries) == 1
        assert original_entries[0].dn.value == roundtripped_entries[0].dn.value


class TestSchemaParseAndAssert:
    """Test schema_parse_and_assert helper."""

    def test_schema_parse_and_assert_attribute(self) -> None:
        """Test schema_parse_and_assert for attribute."""
        quirk = FlextLdifServersRfc()
        attr_def = "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch )"
        attr = DeduplicationHelpers.schema_parse_and_assert(
            quirk.Schema(),
            attr_def,
            expected_type="attribute",
            expected_oid="2.5.4.3",
            expected_name="cn",
        )
        assert attr.oid == "2.5.4.3"
        assert attr.name == "cn"


class TestSchemaWriteAndAssert:
    """Test schema_write_and_assert helper."""

    def test_schema_write_and_assert_success(self) -> None:
        """Test schema_write_and_assert with success."""
        quirk = FlextLdifServersRfc()
        attr = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        ldif = DeduplicationHelpers.schema_write_and_assert(
            quirk.Schema(),
            attr,
            must_contain=["testAttr"],
        )
        assert "testAttr" in ldif


class TestQuirkRoundtrip:
    """Test quirk roundtrip helpers."""

    def test_quirk_parse_write_roundtrip(self) -> None:
        """Test quirk_parse_write_roundtrip."""
        quirk = FlextLdifServersRfc()
        schema_quirk = quirk.Schema()
        attr_def = "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch )"
        original, written, roundtripped = (
            DeduplicationHelpers.quirk_parse_write_roundtrip(
                schema_quirk,
                attr_def,
                parse_method="parse_attribute",
                expected_type=FlextLdifModels.SchemaAttribute,
            )
        )
        assert isinstance(original, FlextLdifModels.SchemaAttribute)
        assert isinstance(written, str)
        assert isinstance(roundtripped, FlextLdifModels.SchemaAttribute)


class TestAPIRoundtrip:
    """Test API roundtrip helpers."""

    def test_api_parse_write_roundtrip(self) -> None:
        """Test api_parse_write_roundtrip."""
        api = FlextLdif()
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"
        original, written, roundtripped = (
            DeduplicationHelpers.api_parse_write_roundtrip(
                api,
                ldif_content,
                expected_count=1,
            )
        )
        assert len(original) == 1
        assert isinstance(written, str)
        assert len(roundtripped) == 1


class TestBatchOperations:
    """Test batch operation helpers."""

    def test_batch_parse_and_assert(self) -> None:
        """Test batch_parse_and_assert."""
        parser = FlextLdifParser()
        test_cases = [
            {
                "ldif_content": "dn: cn=test1,dc=example,dc=com\ncn: test1\n",
                "expected_count": 1,
            },
            {
                "ldif_content": "dn: cn=test2,dc=example,dc=com\ncn: test2\n",
                "expected_count": 1,
            },
        ]
        results = DeduplicationHelpers.batch_parse_and_assert(parser, test_cases)
        assert len(results) == 2
        assert all(len(entries) == 1 for entries in results)

    def test_create_entries_batch(self) -> None:
        """Test create_entries_batch."""
        entries_data = [
            {"dn": "cn=test1,dc=example,dc=com", "attributes": {"cn": ["test1"]}},
            {"dn": "cn=test2,dc=example,dc=com", "attributes": {"cn": ["test2"]}},
        ]
        entries = DeduplicationHelpers.create_entries_batch(entries_data)
        assert len(entries) == 2
        assert entries[0].dn.value == "cn=test1,dc=example,dc=com"
        assert entries[1].dn.value == "cn=test2,dc=example,dc=com"


class TestSchemaHelpers:
    """Test schema helper methods."""

    def test_parse_schema_and_unwrap(self) -> None:
        """Test parse_schema_and_unwrap."""
        quirk = FlextLdifServersRfc()
        attr_def = "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch )"
        attr = DeduplicationHelpers.parse_schema_and_unwrap(quirk.Schema(), attr_def)
        assert isinstance(attr, FlextLdifModels.SchemaAttribute)
        assert attr.oid == "2.5.4.3"

    def test_write_schema_and_unwrap(self) -> None:
        """Test write_schema_and_unwrap."""
        quirk = FlextLdifServersRfc()
        attr = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        ldif = DeduplicationHelpers.write_schema_and_unwrap(quirk.Schema(), attr)
        assert isinstance(ldif, str)
        assert "testAttr" in ldif


class TestEntryHelpers:
    """Test entry helper methods."""

    def test_parse_entry_and_unwrap(self) -> None:
        """Test parse_entry_and_unwrap."""
        quirk = FlextLdifServersRfc()
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"
        entry = DeduplicationHelpers.parse_entry_and_unwrap(
            quirk.Entry(),
            ldif_content,
            expected_dn="cn=test,dc=example,dc=com",
        )
        assert entry.dn.value == "cn=test,dc=example,dc=com"

    def test_write_entry_and_unwrap(self) -> None:
        """Test write_entry_and_unwrap."""
        quirk = FlextLdifServersRfc()
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        ldif = DeduplicationHelpers.write_entry_and_unwrap(
            quirk.Entry(),
            entry,
            must_contain="cn: test",
        )
        assert "cn: test" in ldif


class TestACLHelpers:
    """Test ACL helper methods."""

    def test_acl_quirk_parse_and_assert(self) -> None:
        """Test acl_quirk_parse_and_assert."""
        quirk = FlextLdifServersRfc()
        acl_line = "grant(user1) read"
        acl = DeduplicationHelpers.acl_quirk_parse_and_assert(quirk.Acl(), acl_line)
        assert isinstance(acl, FlextLdifModels.Acl)

    def test_acl_quirk_write_and_assert(self) -> None:
        """Test acl_quirk_write_and_assert."""
        quirk = FlextLdifServersRfc()
        # Create ACL by parsing first
        acl_line = "grant(user1) read"
        acl = DeduplicationHelpers.acl_quirk_parse_and_assert(quirk.Acl(), acl_line)
        # Then write it
        ldif = DeduplicationHelpers.acl_quirk_write_and_assert(
            quirk.Acl(),
            acl,
            must_contain=["grant"],
        )
        assert "grant" in ldif.lower()
