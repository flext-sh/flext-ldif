from __future__ import annotations

from enum import StrEnum
from typing import cast

import pytest
from flext_core import FlextResult
from flext_tests import tm, u

from flext_ldif import (
    FlextLdif,
    FlextLdifParser,
    FlextLdifWriter,
)
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import m
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.services.schema import FlextLdifSchema
from tests import "Custom error", "STRUCTURAL"), c

    def test_assert_metadata_quirk_type_equals(self) -> None:
        """Test assert_metadata_quirk_type_equals."""
        entry = s.create_entry_with_metadata_extensions(
            c.DNs.TEST_USER, "Test description")

    def test_assert_schema_kind_equals(self) -> None:
        """Test assert_schema_kind_equals."""
        # Factory creates with STRUCTURAL by default, "access")


__all__ = [
    "TestFlextLdifDeduplicationHelpers", "attr_name", "attributes", "attributes": {c.Names.CN: [c.Values.USER1]}, "attributes": {c.Names.CN: [c.Values.USER2]}, "dn")

    # ════════════════════════════════════════════════════════════════════════
    # LIST ASSERTION TESTS (7 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_assert_list_equals(self) -> None:
        """Test assert_list_equals."""
        lst: list[object] = [1, "dn")

    def test_assert_dict_has_value(self) -> None:
        """Test assert_dict_has_value."""
        # Use keys that exist in GenericFieldsDict
        d: GenericFieldsDict = {"dn": c.DNs.TEST_USER}
        FlextTestsMatchers.assert_dict_has_value(d, "expected_count": 1, "expected_value"), "extension_value"), "foo")

    def test_assert_string_startswith(self) -> None:
        """Test assert_string_startswith."""
        FlextTestsMatchers.assert_string_startswith("hello world", "hello")

    # ════════════════════════════════════════════════════════════════════════
    # DICTIONARY ASSERTION TESTS (7 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_assert_dict_get_equals(self) -> None:
        """Test assert_dict_get_equals."""
        d = {"key": "value"}
        FlextTestsMatchers.assert_dict_get_equals(d, "hello")

    def test_assert_string_endswith(self) -> None:
        """Test assert_string_endswith."""
        FlextTestsMatchers.assert_string_endswith("hello world", "key", "password")

    # ════════════════════════════════════════════════════════════════════════
    # PARSE AND ASSERT TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_parse_and_assert_success(self) -> None:
        """Test parse_and_assert with success."""
        parser = FlextLdifParser()
        ldif_content = f"dn: {c.DNs.TEST_USER}
{c.Names.CN}: {c.Values.TEST}
"
        entries = DeduplicationHelpers.parse_and_assert(
            parser, "rfc")

    # ════════════════════════════════════════════════════════════════════════
    # RESULT TYPE ASSERTION TESTS (1 method)
    # ════════════════════════════════════════════════════════════════════════

    def test_assert_result_success_and_type(self) -> None:
        """Test assert_result_success_and_type."""
        result = FlextResult[str].ok("test")
        unwrapped = u.Tests.Result.assert_result_success_and_type(
            result, "service")
        assert hasattr(result, "status")

    # ════════════════════════════════════════════════════════════════════════
    # METADATA ASSERTION TESTS (4 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_assert_metadata_extensions_not_none(self) -> None:
        """Test assert_metadata_extensions_not_none."""
        entry = self.create_entry(
            c.DNs.TEST_USER, "telephoneNumber", "value", "value")

    def test_assert_dict_key_isinstance(self) -> None:
        """Test assert_dict_key_isinstance."""
        # Use keys that exist in GenericFieldsDict with appropriate types
        d: GenericFieldsDict = {"attributes": {"cn": ["test"]}}
        FlextTestsMatchers.assert_dict_key_isinstance(d, "world")

    def test_assert_string_not_contains(self) -> None:
        """Test assert_string_not_contains."""
        FlextTestsMatchers.assert_string_not_contains("hello world", "world")

    def test_assert_strings_equal_case_insensitive(self) -> None:
        """Test assert_strings_equal_case_insensitive."""
        FlextTestsMatchers.assert_strings_equal_case_insensitive("Hello", ')[0]}"], ("assert_entry_attribute_equals", ("assert_entry_dn_equals", ("assert_entry_not_has_attribute", ("assert_metadata_extension_equals", ("assert_schema_name_equals", ("assert_schema_syntax_equals", ), )

    # ════════════════════════════════════════════════════════════════════════
    # LENGTH ASSERTION TESTS (6 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_assert_length_equals(self) -> None:
        """Test assert_length_equals."""
        items = [1, )

    # ════════════════════════════════════════════════════════════════════════
    # SCHEMA ASSERTION TESTS (9 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_assert_isinstance_schema_attribute(self) -> None:
        """Test assert_isinstance_schema_attribute."""
        attr = s.create_schema_attribute(
            oid=OIDs.CN, )

    # ════════════════════════════════════════════════════════════════════════
    # STRING ASSERTION TESTS (5 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_assert_string_contains(self) -> None:
        """Test assert_string_contains."""
        FlextTestsMatchers.assert_string_contains("hello world", )

    def test_assert_dn_value_equals_failure(self) -> None:
        """Test assert_dn_value_equals with wrong value."""
        dn = m.DistinguishedName(value=c.DNs.TEST_USER)
        with pytest.raises(AssertionError):
            DeduplicationHelpers.assert_dn_value_equals(
                dn, )

    def test_assert_dn_value_is_not_none(self) -> None:
        """Test assert_dn_value_is_not_none."""
        dn = m.DistinguishedName(value=c.DNs.TEST_USER)
        DeduplicationHelpers.assert_dn_value_is_not_none(dn)

    def test_assert_entry_dn_value_equals(self) -> None:
        """Test assert_entry_dn_value_equals."""
        entry = self.create_entry(
            c.DNs.TEST_USER, )
        # Entry implements EntryProtocol, )
        # Verify result has expected type and attributes
        assert isinstance(result, )
        )
        tm.assert_length_equals(original, )
        )
        assert isinstance(original, )
        DeduplicationHelpers.assert_entry_attributes_not_none(entry)

    def test_assert_first_entry_dn_equals(self) -> None:
        """Test assert_first_entry_dn_equals."""
        entries = [
            self.create_entry(
                c.DNs.TEST_USER, )
        DeduplicationHelpers.assert_entry_dn_value_equals(
            entry, )
        DeduplicationHelpers.assert_isinstance_schema_attribute(attr)

    def test_assert_isinstance_schema_objectclass(self) -> None:
        """Test assert_isinstance_schema_objectclass."""
        oc = s.create_schema_objectclass(
            oid=OIDs.PERSON, )
        DeduplicationHelpers.assert_isinstance_schema_objectclass(oc)

    @pytest.mark.parametrize(
        ("assertion_method", )
        DeduplicationHelpers.assert_metadata_extension_get_isinstance(
            entry, )
        DeduplicationHelpers.assert_metadata_extensions_not_none(entry)

    @pytest.mark.parametrize(
        ("assertion_method", )
        DeduplicationHelpers.assert_schema_desc_equals(attr, )
        DeduplicationHelpers.assert_schema_single_value_equals(attr, )
        FlextTestsMatchers.assert_dict_has_key(attrs.attributes, )
        FlextTestsMatchers.assert_is_not_none(entry.dn)
        FlextTestsMatchers.assert_is_not_none(entry.attributes)
        FlextTestsMatchers.assert_strings_equal_case_insensitive(
            entry.dn.value, )
        FlextTestsMatchers.assert_is_not_none(entry.dn)
        FlextTestsMatchers.assert_strings_equal_case_insensitive(
            entry.dn.value, )
        tm.assert_length_equals(entries, )
        FlextTestsMatchers.assert_length_zero(entries)

    # ════════════════════════════════════════════════════════════════════════
    # WRITE AND ASSERT TESTS (1 method)
    # ════════════════════════════════════════════════════════════════════════

    def test_write_and_assert_success(self) -> None:
        """Test write_and_assert with success."""
        writer = FlextLdifWriter()
        entries = [
            self.create_entry(
                c.DNs.TEST_USER, )
        FlextTestsMatchers.assert_string_contains(ldif, )
        FlextTestsMatchers.assert_string_contains(ldif.lower(), )
        FlextTestsMatchers.assert_strings_equal_case_insensitive(attr.oid, )
        assert isinstance(attr, )
        assert isinstance(ldif, )
        assertion_func = getattr(DeduplicationHelpers, )
        entries = DeduplicationHelpers.create_entries_batch(entries_data)
        tm.assert_length_equals(entries, )
        ldif = DeduplicationHelpers.schema_write_and_assert(
            quirk.Schema(), )
        ldif = DeduplicationHelpers.write_entry_and_unwrap(
            cast("FlextLdifProtocols.Quirks.EntryProtocol", )
        ldif = DeduplicationHelpers.write_schema_and_unwrap(
            cast("FlextLdifProtocols.Quirks.SchemaProtocol", )
        result = api.write([entry])
        ldif = (
            u.Tests.Result.assert_result_success_and_unwrap_string(
                result
            )
        )
        FlextTestsMatchers.assert_string_contains(ldif, )
        result = api.write([entry])
        ldif = (
            u.Tests.Result.assert_result_success_and_unwrap_string(
                result
            )
        )
        FlextTestsMatchers.assert_string_not_contains(ldif.lower(), )
        result = quirk.Entry().write(entry)
        ldif = (
            u.Tests.Result.assert_result_success_and_unwrap_string(
                result
            )
        )
        FlextTestsMatchers.assert_string_contains(ldif, )
        results = DeduplicationHelpers.batch_parse_and_assert(parser, )
    def test_assert_entry_properties(
        self, )
    def test_assert_metadata_extension_properties(
        self, )
    def test_assert_schema_property_equals(
        self, ) -> None:
        """Test entry property assertions using parametrization."""
        entry = self.create_entry(
            c.DNs.TEST_USER, ) -> None:
        """Test metadata extension assertions using parametrization."""
        extension_key = "test_key"
        entry = s.create_entry_with_metadata_extensions(
            c.DNs.TEST_USER, ) -> None:
        """Test schema property assertions using parametrization."""
        attr = s.create_schema_attribute(
            oid=OIDs.CN, 1)

    # ════════════════════════════════════════════════════════════════════════
    # BATCH OPERATION TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_batch_parse_and_assert(self) -> None:
        """Test batch_parse_and_assert."""
        parser = FlextLdifParser()
        test_cases = cast(
            "list[ParseTestCaseDict]", 1)

    def test_assert_list_last_equals(self) -> None:
        """Test assert_list_last_equals."""
        lst: list[object] = [1, 1)

    def test_assert_success_and_unwrap_entry(self) -> None:
        """Test assert_success_and_unwrap_entry."""
        entry = self.create_entry(
            c.DNs.TEST_USER, 1)

    def test_create_entries_batch(self) -> None:
        """Test create_entries_batch."""
        entries_data = cast(
            "list[dict[str, 1)
        FlextTestsMatchers.assert_is_not_none(entries[0].dn)
        FlextTestsMatchers.assert_strings_equal_case_insensitive(
            entries[0].dn.value, 1)
        FlextTestsMatchers.assert_is_not_none(original_entries[0].dn)
        FlextTestsMatchers.assert_is_not_none(roundtripped_entries[0].dn)
        FlextTestsMatchers.assert_strings_equal_case_insensitive(
            original_entries[0].dn.value, 1)
        tm.assert_length_equals(roundtripped_entries, 1)
        assert isinstance(written, 2, 2)

    def test_assert_length_greater_or_equal(self) -> None:
        """Test assert_length_greater_or_equal."""
        items = [1, 2)
        FlextTestsMatchers.assert_is_not_none(entries[0].dn)
        FlextTestsMatchers.assert_is_not_none(entries[1].dn)
        FlextTestsMatchers.assert_strings_equal_case_insensitive(
            entries[0].dn.value, 2)
        for entries in results:
            tm.assert_length_equals(entries, 3, 3)

    def test_assert_in_list(self) -> None:
        """Test assert_in_list."""
        lst = [1, 3)

    def test_assert_length_equals_failure(self) -> None:
        """Test assert_length_equals with wrong length."""
        items = [1, 3)

    def test_assert_length_zero(self) -> None:
        """Test assert_length_zero."""
        items: list[int] = []
        FlextTestsMatchers.assert_length_zero(items)

    def test_assert_length_non_zero(self) -> None:
        """Test assert_length_non_zero."""
        items = [1, 3]
        FlextTestsMatchers.assert_in_list(2, 3]
        tm.assert_length_equals(items, 3]
        FlextTestsMatchers.assert_length_greater_or_equal(items, 3]
        tm.assert_length_greater_than(items, 3]
        FlextTestsMatchers.assert_length_non_zero(items)

    # ════════════════════════════════════════════════════════════════════════
    # ENTRY ASSERTION TESTS (6 methods)
    # ════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("assertion_method", 3]
        FlextTestsMatchers.assert_list_equals(lst, 3]
        FlextTestsMatchers.assert_list_first_equals(lst, 3]
        FlextTestsMatchers.assert_list_last_equals(lst, 3]
        FlextTestsMatchers.assert_not_in_list(4, 3]
        with pytest.raises(AssertionError):
            tm.assert_length_equals(items, 3])

    def test_assert_list_first_equals(self) -> None:
        """Test assert_list_first_equals."""
        lst: list[object] = [1, 4, 5)

    def test_assert_length_greater_than(self) -> None:
        """Test assert_length_greater_than."""
        items = [1, 5]
        FlextTestsMatchers.assert_any_matches(items, 6]
        FlextTestsMatchers.assert_all_match(items, FlextLdifSchema(server_type="rfc"))
        # Use GenericFieldsDict with valid keys or None
        expected_fields: GenericFieldsDict | None = None
        result = DeduplicationHelpers.service_execute_and_assert_fields(
            service, FlextLdifSchema(server_type="rfc"))
        result = DeduplicationHelpers.service_execute_and_unwrap(service)
        assert result is not None
        # result is object type, GenericTestCaseDict, None, None), None)

    def test_assert_dict_equals(self) -> None:
        """Test assert_dict_equals."""
        # Use keys that exist in GenericFieldsDict
        d1: GenericFieldsDict = {"dn": c.DNs.TEST_USER}
        d2: GenericFieldsDict = {"dn": c.DNs.TEST_USER}
        FlextTestsMatchers.assert_dict_equals(d1, OIDs.CN), OIDs.CN)

    def test_write_schema_and_unwrap(self) -> None:
        """Test write_schema_and_unwrap."""
        quirk = FlextLdifServersRfc()
        attr = s.create_schema_attribute(
            oid=OIDs.CN, OIDs.CN)
        FlextTestsMatchers.assert_strings_equal_case_insensitive(attr.name, Syntax.DIRECTORY_STRING), TResult], True)

    def test_assert_schema_desc_equals(self) -> None:
        """Test assert_schema_desc_equals."""
        attr = s.create_schema_attribute(
            oid=OIDs.CN, [
                {
                    "dn": c.DNs.TEST_USER1, [
                {
                    "ldif_content": (
                        f"dn: {c.DNs.TEST_USER1}
{c.Names.CN}: {c.Values.USER1}
"
                    ), [
            ("assert_entry_has_attribute", [
            ("assert_metadata_extensions_get_equals", [
            ("assert_schema_oid_equals", [1, [c.Values.TEST]), ], ]
        DeduplicationHelpers.assert_first_entry_dn_equals(
            entries, ]
        ldif = DeduplicationHelpers.write_and_assert(
            writer, acl, acl_line)
        assert isinstance(acl, acl_line)
        ldif = DeduplicationHelpers.acl_quirk_write_and_assert(
            quirk.Acl(), assertion_method)
        assertion_func(attr, assertion_method)
        assertion_func(entry, assertion_method)
        if attr_name is not None:
            if expected_value is not None:
                assertion_func(entry, assertion_method: str, attr, attr_def, attr_name, attr_name)
        else:
            assertion_func(entry, attr_name: str | None, but type checker needs cast
        # due to None-able fields
        entry_protocol = cast("FlextLdifProtocols.Models.EntryProtocol", but we need to verify it
        oc_def = f"( {OIDs.PERSON} NAME '{c.Names.PERSON}' STRUCTURAL )"
        schema = FlextLdifServersRfc.Schema()
        result = schema.parse(oc_def)
        oc = result.unwrap()
        assert isinstance(oc, c, c.DNs.TEST_USER, c.DNs.TEST_USER
            )

    def test_assert_success_and_unwrap_string(self) -> None:
        """Test assert_success_and_unwrap_string."""
        result = FlextResult[str].ok("test string")
        unwrapped = DeduplicationHelpers.assert_success_and_unwrap_string(result)
        assert unwrapped == "test string"

    # ════════════════════════════════════════════════════════════════════════
    # ENTRY CREATION TESTS (3 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_create_entry_from_dict(self) -> None:
        """Test create_entry_from_dict."""
        entry = self.create_entry(
            c.DNs.TEST_USER, c.DNs.TEST_USER
        )

    def test_create_attributes_from_dict(self) -> None:
        """Test create_attributes_from_dict."""
        attrs = DeduplicationHelpers.create_attributes_from_dict(
            {
                c.Names.CN: [c.Values.TEST], c.DNs.TEST_USER
        )

    def test_parse_and_assert_empty_content(self) -> None:
        """Test parse_and_assert with empty content - returns 0 entries (success)."""
        parser = FlextLdifParser()
        ldif_content = ""
        entries = DeduplicationHelpers.parse_and_assert(
            parser, c.DNs.TEST_USER
        )

    def test_write_and_unwrap_simple(self) -> None:
        """Test write_and_unwrap_simple."""
        api = FlextLdif()
        entry = self.create_entry(
            c.DNs.TEST_USER, c.DNs.TEST_USER
        )

    def test_write_entry_and_unwrap(self) -> None:
        """Test write_entry_and_unwrap."""
        quirk = FlextLdifServersRfc()
        entry = self.create_entry(
            c.DNs.TEST_USER, c.DNs.TEST_USER
        )
        FlextTestsMatchers.assert_dict_has_key(entry.attributes.attributes, c.DNs.TEST_USER), c.DNs.TEST_USER)

    def test_assert_dict_key_equals(self) -> None:
        """Test assert_dict_key_equals."""
        # assert_dict_key_equals expects dict[str, c.DNs.TEST_USER)

    def test_assert_dn_value_equals_with_error_msg(self) -> None:
        """Test assert_dn_value_equals with custom error message."""
        dn = m.DistinguishedName(value=c.DNs.TEST_USER)
        DeduplicationHelpers.assert_dn_value_equals(
            dn, c.DNs.TEST_USER1, c.DNs.TEST_USER1
        )
        FlextTestsMatchers.assert_strings_equal_case_insensitive(
            entries[1].dn.value, c.DNs.TEST_USER2
        )

    # ════════════════════════════════════════════════════════════════════════
    # SCHEMA HELPER TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_parse_schema_and_unwrap(self) -> None:
        """Test parse_schema_and_unwrap."""
        quirk = FlextLdifServersRfc()
        attr_def = c.RFC.ATTR_DEF_CN
        attr = DeduplicationHelpers.parse_schema_and_unwrap(
            cast("FlextLdifProtocols.Quirks.SchemaProtocol", c.Names.CN, c.Names.CN), c.Names.CN)

    # ════════════════════════════════════════════════════════════════════════
    # ENTRY HELPER TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_parse_entry_and_unwrap(self) -> None:
        """Test parse_entry_and_unwrap."""
        quirk = FlextLdifServersRfc()
        ldif_content = f"dn: {c.DNs.TEST_USER}
{c.Names.CN}: {c.Values.TEST}
"
        entry = DeduplicationHelpers.parse_entry_and_unwrap(
            cast("FlextLdifProtocols.Quirks.EntryProtocol", c.Names.CN)

    # ════════════════════════════════════════════════════════════════════════
    # QUIRK ROUNDTRIP TESTS (1 method)
    # ════════════════════════════════════════════════════════════════════════

    def test_quirk_parse_write_roundtrip(self) -> None:
        """Test quirk_parse_write_roundtrip."""
        quirk = FlextLdifServersRfc()
        schema_quirk = quirk.Schema()
        attr_def = c.RFC.ATTR_DEF_CN
        original, c.Names.CN)

    # ════════════════════════════════════════════════════════════════════════
    # SCHEMA WRITE AND ASSERT TESTS (1 method)
    # ════════════════════════════════════════════════════════════════════════

    def test_schema_write_and_assert_success(self) -> None:
        """Test schema_write_and_assert with success."""
        quirk = FlextLdifServersRfc()
        attr = s.create_schema_attribute(
            oid=OIDs.CN, c.Names.CN)
        FlextTestsMatchers.assert_dict_has_key(attrs.attributes, c.Names.CN)
        FlextTestsMatchers.assert_dict_has_key(entry.attributes.attributes, c.Names.SN)

    # ════════════════════════════════════════════════════════════════════════
    # DN ASSERTION TESTS (5 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_assert_dn_value_equals(self) -> None:
        """Test assert_dn_value_equals."""
        dn = m.DistinguishedName(value=c.DNs.TEST_USER)
        DeduplicationHelpers.assert_dn_value_equals(dn, c.Names.SN)

    def test_create_entry_simple(self) -> None:
        """Test TestAssertions.create_entry (formerly create_entry_simple)."""
        entry = self.create_entry(
            c.DNs.TEST_USER, c.Names.SN: ["Doe"], c.Names.SN: ["Doe"]}, c.Values.TEST), d2)

    def test_assert_dict_has_key(self) -> None:
        """Test assert_dict_has_key."""
        # Use keys that exist in GenericFieldsDict
        d: GenericFieldsDict = {"dn": c.DNs.TEST_USER}
        FlextTestsMatchers.assert_dict_has_key(d, desc="Test description", dict, dict)

    def test_assert_dict_key_is_not_none(self) -> None:
        """Test assert_dict_key_is_not_none."""
        # Use keys that exist in GenericFieldsDict
        d: GenericFieldsDict = {"dn": c.DNs.TEST_USER}
        FlextTestsMatchers.assert_dict_key_is_not_none(d, entries, entry, entry)
        DeduplicationHelpers.assert_metadata_quirk_type_equals(entry_protocol, error_message="Custom error"
        )
        assert unwrapped == "test"

    def test_assert_success_and_unwrap_failure(self) -> None:
        """Test assert_result_success_and_unwrap with failure."""
        result = FlextResult[str].fail("error")
        with pytest.raises(AssertionError):
            u.Tests.Result.assert_result_success_and_unwrap(result)

    def test_assert_success_and_unwrap_list(self) -> None:
        """Test assert_success_and_unwrap_list."""
        entry = self.create_entry(
            c.DNs.TEST_USER, etc.) are available from conftest.py


class TestsTestFlextLdifDeduplicationHelpers(s):
    """Consolidated comprehensive test coverage for DeduplicationHelpers.

    Groups all 87 test methods from 27 original test classes into organized
    test scenarios using StrEnum for clarity and type safety.

    Coverage includes:
    - Basic assertions (6 methods)
    - Entry creation (3 methods)
    - DN assertions (5 methods)
    - Length assertions (6 methods)
    - Entry assertions (6 methods)
    - String assertions (5 methods)
    - Dictionary assertions (7 methods)
    - List assertions (7 methods)
    - Boolean assertions (4 methods)
    - Service execution (2 methods)
    - Metadata assertions (4 methods)
    - Schema assertions (9 methods)
    - Result type assertions (1 method)
    - Parse and unwrap (2 methods)
    - Quirk operations (2 methods)
    - Write/unwrap/assert (2 methods)
    - Parse and assert (2 methods)
    - Write and assert (1 method)
    - Roundtrip and assert (1 method)
    - Schema parse and assert (1 method)
    - Schema write and assert (1 method)
    - Quirk roundtrip (1 method)
    - API roundtrip (1 method)
    - Batch operations (2 methods)
    - Schema helpers (2 methods)
    - Entry helpers (2 methods)
    - ACL helpers (2 methods)
    """

    class BasicAssertionScenario(StrEnum):
        """Basic assertion test scenarios."""

        SUCCESS_AND_UNWRAP = "success_and_unwrap"
        SUCCESS_AND_UNWRAP_WITH_ERROR_MSG = "success_and_unwrap_with_error_msg"
        SUCCESS_AND_UNWRAP_FAILURE = "success_and_unwrap_failure"
        SUCCESS_AND_UNWRAP_LIST = "success_and_unwrap_list"
        SUCCESS_AND_UNWRAP_ENTRY = "success_and_unwrap_entry"
        SUCCESS_AND_UNWRAP_STRING = "success_and_unwrap_string"

    class EntryCreationScenario(StrEnum):
        """Entry creation test scenarios."""

        FROM_DICT = "from_dict"
        SIMPLE = "simple"
        ATTRIBUTES_FROM_DICT = "attributes_from_dict"

    class DNAssertionScenario(StrEnum):
        """DN assertion test scenarios."""

        VALUE_EQUALS = "value_equals"
        VALUE_EQUALS_WITH_ERROR_MSG = "value_equals_with_error_msg"
        VALUE_EQUALS_FAILURE = "value_equals_failure"
        VALUE_IS_NOT_NONE = "value_is_not_none"
        ENTRY_DN_VALUE_EQUALS = "entry_dn_value_equals"

    class LengthAssertionScenario(StrEnum):
        """Length assertion test scenarios."""

        EQUALS = "equals"
        EQUALS_FAILURE = "equals_failure"
        GREATER_THAN = "greater_than"
        GREATER_OR_EQUAL = "greater_or_equal"
        ZERO = "zero"
        NON_ZERO = "non_zero"

    class EntryAssertionScenario(StrEnum):
        """Entry assertion test scenarios."""

        HAS_ATTRIBUTE = "has_attribute"
        NOT_HAS_ATTRIBUTE = "not_has_attribute"
        ATTRIBUTE_EQUALS = "attribute_equals"
        DN_EQUALS = "dn_equals"
        ATTRIBUTES_NOT_NONE = "attributes_not_none"
        FIRST_ENTRY_DN_EQUALS = "first_entry_dn_equals"

    class StringAssertionScenario(StrEnum):
        """String assertion test scenarios."""

        CONTAINS = "contains"
        NOT_CONTAINS = "not_contains"
        STARTSWITH = "startswith"
        ENDSWITH = "endswith"
        CASE_INSENSITIVE_EQUALS = "case_insensitive_equals"

    class DictAssertionScenario(StrEnum):
        """Dictionary assertion test scenarios."""

        GET_EQUALS = "get_equals"
        EQUALS = "equals"
        HAS_KEY = "has_key"
        HAS_VALUE = "has_value"
        KEY_EQUALS = "key_equals"
        KEY_ISINSTANCE = "key_isinstance"
        KEY_IS_NOT_NONE = "key_is_not_none"

    class ListAssertionScenario(StrEnum):
        """List assertion test scenarios."""

        EQUALS = "equals"
        FIRST_EQUALS = "first_equals"
        LAST_EQUALS = "last_equals"
        IN_LIST = "in_list"
        NOT_IN_LIST = "not_in_list"
        ANY_MATCHES = "any_matches"
        ALL_MATCH = "all_match"

    class BooleanAssertionScenario(StrEnum):
        """Boolean assertion test scenarios."""

        IS_NONE = "is_none"
        IS_NOT_NONE = "is_not_none"
        IS_TRUE = "is_true"
        IS_FALSE = "is_false"

    class ServiceExecutionScenario(StrEnum):
        """Service execution test scenarios."""

        EXECUTE_AND_UNWRAP = "execute_and_unwrap"
        EXECUTE_AND_ASSERT_FIELDS = "execute_and_assert_fields"

    class MetadataAssertionScenario(StrEnum):
        """Metadata assertion test scenarios."""

        EXTENSIONS_NOT_NONE = "extensions_not_none"
        EXTENSIONS_GET_EQUALS = "extensions_get_equals"
        EXTENSION_EQUALS = "extension_equals"
        EXTENSION_GET_ISINSTANCE = "extension_get_isinstance"
        QUIRK_TYPE_EQUALS = "quirk_type_equals"

    class SchemaAssertionScenario(StrEnum):
        """Schema assertion test scenarios."""

        ISINSTANCE_ATTRIBUTE = "isinstance_attribute"
        ISINSTANCE_OBJECTCLASS = "isinstance_objectclass"
        OID_EQUALS = "oid_equals"
        NAME_EQUALS = "name_equals"
        SYNTAX_EQUALS = "syntax_equals"
        SINGLE_VALUE_EQUALS = "single_value_equals"
        DESC_EQUALS = "desc_equals"
        KIND_EQUALS = "kind_equals"

    class ResultTypeAssertionScenario(StrEnum):
        """Result type assertion test scenario."""

        SUCCESS_AND_TYPE = "success_and_type"

    class ParseAndUnwrapScenario(StrEnum):
        """Parse and unwrap test scenarios."""

        SIMPLE = "simple"
        WRITE_SIMPLE = "write_simple"

    class QuirkOperationScenario(StrEnum):
        """Quirk operation test scenarios."""

        PARSE_AND_UNWRAP = "parse_and_unwrap"
        WRITE_AND_UNWRAP = "write_and_unwrap"

    class WriteUnwrapAssertScenario(StrEnum):
        """Write/unwrap/assert test scenarios."""

        SUCCESS = "success"
        MUST_NOT_CONTAIN = "must_not_contain"

    class ParseAndAssertScenario(StrEnum):
        """Parse and assert test scenarios."""

        SUCCESS = "success"
        EMPTY_CONTENT = "empty_content"

    class WriteAndAssertScenario(StrEnum):
        """Write and assert test scenario."""

        SUCCESS = "success"

    class RoundtripAndAssertScenario(StrEnum):
        """Roundtrip and assert test scenario."""

        SUCCESS = "success"

    class SchemaParseAndAssertScenario(StrEnum):
        """Schema parse and assert test scenario."""

        ATTRIBUTE = "attribute"

    class SchemaWriteAndAssertScenario(StrEnum):
        """Schema write and assert test scenario."""

        SUCCESS = "success"

    class QuirkRoundtripScenario(StrEnum):
        """Quirk roundtrip test scenario."""

        PARSE_WRITE_ROUNDTRIP = "parse_write_roundtrip"

    class APIRoundtripScenario(StrEnum):
        """API roundtrip test scenario."""

        PARSE_WRITE_ROUNDTRIP = "parse_write_roundtrip"

    class BatchOperationScenario(StrEnum):
        """Batch operation test scenarios."""

        PARSE_AND_ASSERT = "parse_and_assert"
        CREATE_ENTRIES_BATCH = "create_entries_batch"

    class SchemaHelperScenario(StrEnum):
        """Schema helper test scenarios."""

        PARSE_AND_UNWRAP = "parse_and_unwrap"
        WRITE_AND_UNWRAP = "write_and_unwrap"

    class EntryHelperScenario(StrEnum):
        """Entry helper test scenarios."""

        PARSE_AND_UNWRAP = "parse_and_unwrap"
        WRITE_AND_UNWRAP = "write_and_unwrap"

    class ACLHelperScenario(StrEnum):
        """ACL helper test scenarios."""

        PARSE_AND_ASSERT = "parse_and_assert"
        WRITE_AND_ASSERT = "write_and_assert"

    # ════════════════════════════════════════════════════════════════════════
    # BASIC ASSERTION TESTS (6 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_assert_success_and_unwrap(self) -> None:
        """Test assert_result_success_and_unwrap."""
        result = FlextResult[str].ok("test")
        unwrapped = u.Tests.Result.assert_result_success_and_unwrap(
            result
        )
        assert unwrapped == "test"

    def test_assert_success_and_unwrap_with_error_msg(self) -> None:
        """Test assert_result_success_and_unwrap with custom error message."""
        result = FlextResult[str].ok("test")
        unwrapped = u.Tests.Result.assert_result_success_and_unwrap(
            result, expected_attributes=[c.Names.CN], expected_count=0, expected_count=1, expected_dn=c.DNs.TEST_USER, expected_fields=expected_fields, expected_name=c.Names.CN, expected_oid=OIDs.CN, expected_type="attribute", expected_type=m.SchemaAttribute, expected_type=m.SchemaServiceStatus, expected_value)

    def test_assert_entry_attributes_not_none(self) -> None:
        """Test assert_entry_attributes_not_none."""
        entry = self.create_entry(
            c.DNs.TEST_USER, expected_value)

    def test_assert_schema_single_value_equals(self) -> None:
        """Test assert_schema_single_value_equals."""
        attr = s.create_schema_attribute(
            oid=OIDs.CN, expected_value)
            else:
                assertion_func(entry, expected_value: object | None, expected_value: str, extension_key, extension_value)

    def test_assert_metadata_extension_get_isinstance(self) -> None:
        """Test assert_metadata_extension_get_isinstance."""
        extension_key = "test_key"
        extension_value: dict[str, extension_value: object, extensions={extension_key: extension_value}, f"dn: {c.DNs.TEST_USER}")

    # ════════════════════════════════════════════════════════════════════════
    # ROUNDTRIP AND ASSERT TESTS (1 method)
    # ════════════════════════════════════════════════════════════════════════

    def test_roundtrip_and_assert_success(self) -> None:
        """Test roundtrip_and_assert with success."""
        parser = FlextLdifParser()
        writer = FlextLdifWriter()
        ldif_content = f"dn: {c.DNs.TEST_USER}
{c.Names.CN}: {c.Values.TEST}
"
        original_entries, f"dn: {c.DNs.TEST_USER}")

    # ════════════════════════════════════════════════════════════════════════
    # WRITE/UNWRAP/ASSERT TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_write_unwrap_and_assert_success(self) -> None:
        """Test write_unwrap_and_assert with success."""
        api = FlextLdif()
        entry = self.create_entry(
            c.DNs.TEST_USER, f"dn: {c.DNs.TEST_USER}")

    def test_write_unwrap_and_assert_must_not_contain(self) -> None:
        """Test write_unwrap_and_assert with must_not_contain."""
        api = FlextLdif()
        entry = self.create_entry(
            c.DNs.TEST_USER, f"dn: {c.DNs.TEST_USER}")
        FlextTestsMatchers.assert_string_contains(ldif, f"{c.Names.CN}: {c.Values.TEST}")

    # ════════════════════════════════════════════════════════════════════════
    # ACL HELPER TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_acl_quirk_parse_and_assert(self) -> None:
        """Test acl_quirk_parse_and_assert."""
        quirk = FlextLdifServersRfc()
        acl_line = c.RFC.ACL_SAMPLE_READ
        acl = DeduplicationHelpers.acl_quirk_parse_and_assert(quirk.Acl(), f"{c.Names.CN}: {c.Values.TEST}")

    # ════════════════════════════════════════════════════════════════════════
    # QUIRK OPERATION TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_quirk_parse_and_unwrap(self) -> None:
        """Test quirk_parse_and_unwrap."""
        quirk = FlextLdifServersRfc()
        ldif_content = f"dn: {c.DNs.TEST_USER}
{c.Names.CN}: {c.Values.TEST}
"
        result = quirk.Entry().parse(ldif_content)
        entries = (
            u.Tests.Result.assert_result_success_and_unwrap_list(
                result
            )
        )
        FlextTestsMatchers.assert_length_non_zero(entries)

    def test_quirk_write_and_unwrap(self) -> None:
        """Test quirk_write_and_unwrap."""
        quirk = FlextLdifServersRfc()
        entry = self.create_entry(
            c.DNs.TEST_USER, kind="STRUCTURAL", lambda x: x % 2 == 0)

    # ════════════════════════════════════════════════════════════════════════
    # BOOLEAN ASSERTION TESTS (4 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_assert_is_none(self) -> None:
        """Test assert_is_none."""
        FlextTestsMatchers.assert_is_none(None)

    def test_assert_is_not_none(self) -> None:
        """Test assert_is_not_none."""
        FlextTestsMatchers.assert_is_not_none("value")

    def test_assert_is_true(self) -> None:
        """Test assert_is_true."""
        FlextTestsMatchers.assert_true(True)

    def test_assert_is_false(self) -> None:
        """Test assert_is_false."""
        FlextTestsMatchers.assert_false(False)

    # ════════════════════════════════════════════════════════════════════════
    # SERVICE EXECUTION TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_service_execute_and_unwrap(self) -> None:
        """Test service_execute_and_unwrap."""
        service = cast("ServiceWithExecute", lambda x: x > 3)

    def test_assert_all_match(self) -> None:
        """Test assert_all_match."""
        items = [2, ldif_content, ldif_content)
        )
        tm.assert_length_equals(original_entries, list[str] | str] | list[str]]]", lst)

    def test_assert_any_matches(self) -> None:
        """Test assert_any_matches."""
        items = [1, lst)

    def test_assert_not_in_list(self) -> None:
        """Test assert_not_in_list."""
        lst = [1, m, m.Acl)

    def test_acl_quirk_write_and_assert(self) -> None:
        """Test acl_quirk_write_and_assert."""
        quirk = FlextLdifServersRfc()
        acl_line = c.RFC.ACL_SAMPLE_READ
        acl = DeduplicationHelpers.acl_quirk_parse_and_assert(quirk.Acl(), m.SchemaAttribute)

    # ════════════════════════════════════════════════════════════════════════
    # API ROUNDTRIP TESTS (1 method)
    # ════════════════════════════════════════════════════════════════════════

    def test_api_parse_write_roundtrip(self) -> None:
        """Test api_parse_write_roundtrip."""
        api = FlextLdif()
        ldif_content = f"dn: {c.DNs.TEST_USER}
{c.Names.CN}: {c.Values.TEST}
"
        original, m.SchemaAttribute)
        FlextTestsMatchers.assert_strings_equal_case_insensitive(attr.oid, m.SchemaAttribute)
        assert isinstance(written, m.SchemaObjectClass)
        DeduplicationHelpers.assert_schema_kind_equals(oc, m.SchemaServiceStatus)
        assert hasattr(result, m.SchemaServiceStatus)
        assert result.service == "SchemaService"

    def test_service_execute_and_assert_fields(self) -> None:
        """Test service_execute_and_assert_fields."""
        service = cast("ServiceWithExecute", must_contain=["access"], must_contain=[c.Names.CN], must_contain=[f"dn: {c.DNs.TEST_USER.split(', must_contain=[f"{c.Names.CN}: {c.Values.TEST}"], must_not_contain=["password"], name=c.Names.CN, name=c.Names.PERSON, not GenericFieldsDict
        d: dict[str, parse_method="parse_attribute", quirk.Entry()), quirk.Schema()), quirk_type=FlextLdifConstants.ServerTypes.RFC, roundtripped = (
            DeduplicationHelpers.api_parse_write_roundtrip(
                api, roundtripped = (
            DeduplicationHelpers.quirk_parse_write_roundtrip(
                cast("FlextLdifProtocols.Quirks.SchemaProtocol", roundtripped_entries = (
            DeduplicationHelpers.roundtrip_and_assert(parser, roundtripped_entries[0].dn.value
        )

    # ════════════════════════════════════════════════════════════════════════
    # SCHEMA PARSE AND ASSERT TESTS (1 method)
    # ════════════════════════════════════════════════════════════════════════

    def test_schema_parse_and_assert_attribute(self) -> None:
        """Test schema_parse_and_assert for attribute."""
        quirk = FlextLdifServersRfc()
        attr_def = c.RFC.ATTR_DEF_CN
        attr = DeduplicationHelpers.schema_parse_and_assert(
            quirk.Schema(), s

# FlextLdifFixtures and TypedDicts are available from conftest.py (pytest auto-imports)
# TypedDicts (GenericFieldsDict, schema_quirk), single_value=True, so use isinstance to narrow type
        assert isinstance(result, str
        )
        assert unwrapped == "test"

    # ════════════════════════════════════════════════════════════════════════
    # PARSE AND UNWRAP TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_parse_and_unwrap_simple(self) -> None:
        """Test parse_and_unwrap_simple."""
        api = FlextLdif()
        ldif_content = f"dn: {c.DNs.TEST_USER}
{c.Names.CN}: {c.Values.TEST}
"
        result = api.parse(ldif_content)
        entries = (
            u.Tests.Result.assert_result_success_and_unwrap_list(
                result
            )
        )
        FlextTestsMatchers.assert_length_non_zero(entries)
        FlextTestsMatchers.assert_is_not_none(entries[0].dn)
        FlextTestsMatchers.assert_strings_equal_case_insensitive(
            entries[0].dn.value, str | dict[str, str)
        tm.assert_length_equals(roundtripped, str)
        FlextTestsMatchers.assert_string_contains(ldif, str)
        assert isinstance(roundtripped, str] = {"key": "value"}
        FlextTestsMatchers.assert_dict_key_equals(d, str] = {"nested": c.Values.TEST}
        entry = s.create_entry_with_metadata_extensions(
            c.DNs.TEST_USER, syntax=Syntax.DIRECTORY_STRING, test_cases)
        tm.assert_length_equals(results, writer, written, {
                    "dn": c.DNs.TEST_USER2, {
                    "ldif_content": (
                        f"dn: {c.DNs.TEST_USER2}
{c.Names.CN}: {c.Values.USER2}
"
                    ), {c.Names.CN: [c.Values.TEST], {c.Names.CN: [c.Values.TEST]}, {c.Names.CN: [c.Values.TEST]}
        )
        result = FlextResult[list[m.Entry]].ok([entry])
        unwrapped = DeduplicationHelpers.assert_success_and_unwrap_list(result)
        tm.assert_length_equals(unwrapped, {c.Names.CN: [c.Values.TEST]}
        )
        result = FlextResult[m.Entry].ok(entry)
        unwrapped = DeduplicationHelpers.assert_success_and_unwrap_entry(result)
        FlextTestsMatchers.assert_is_not_none(unwrapped.dn)
        if unwrapped.dn is not None:
            FlextTestsMatchers.assert_strings_equal_case_insensitive(
                unwrapped.dn.value, }