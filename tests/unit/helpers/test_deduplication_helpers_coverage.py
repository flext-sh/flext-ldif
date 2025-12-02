"""Comprehensive test coverage for DeduplicationHelpers - CONSOLIDATED.

This test file ensures 100% coverage of all helper methods in
tests/helpers/test_deduplication_helpers.py.

Consolidated from 27 test classes into single TestFlextLdifDeduplicationHelpers
class with 11 StrEnum scenario groups covering all 87 test methods.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from enum import StrEnum
from typing import cast

import pytest
from flext_core import FlextResult

from flext_ldif import (
    FlextLdif,
    FlextLdifModels,
    FlextLdifParser,
    FlextLdifWriter,
)
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.services.schema import FlextLdifSchema
from tests.fixtures.typing import GenericFieldsDict
from tests.helpers.test_assertions import TestAssertions
from tests.helpers.test_deduplication_helpers import (
    DeduplicationHelpers,
    ParseTestCaseDict,
    ServiceWithExecute,
)


class TestFlextLdifDeduplicationHelpers:
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
                dn=FlextLdifModels.DistinguishedName(
                    value="cn=test,dc=example,dc=com",
                ),
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
            dn=FlextLdifModels.DistinguishedName(
                value="cn=test,dc=example,dc=com",
            ),
            attributes=FlextLdifModels.LdifAttributes.create(
                {"cn": ["test"]},
            ).unwrap(),
        )
        result = FlextResult[FlextLdifModels.Entry].ok(entry)
        unwrapped = DeduplicationHelpers.assert_success_and_unwrap_entry(result)
        assert unwrapped.dn is not None, "Entry must have DN"
        assert unwrapped.dn.value == "cn=test,dc=example,dc=com"

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
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "sn": ["Doe"]},
        )
        assert entry.dn is not None, "Entry must have DN"
        assert entry.attributes is not None, "Entry must have attributes"
        assert entry.dn.value == "cn=test,dc=example,dc=com"
        assert "cn" in entry.attributes.attributes
        assert "sn" in entry.attributes.attributes

    def test_create_entry_simple(self) -> None:
        """Test TestAssertions.create_entry (formerly create_entry_simple)."""
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        assert entry.dn is not None, "Entry must have DN"
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

    # ════════════════════════════════════════════════════════════════════════
    # DN ASSERTION TESTS (5 methods)
    # ════════════════════════════════════════════════════════════════════════

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

    # ════════════════════════════════════════════════════════════════════════
    # LENGTH ASSERTION TESTS (6 methods)
    # ════════════════════════════════════════════════════════════════════════

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

    # ════════════════════════════════════════════════════════════════════════
    # ENTRY ASSERTION TESTS (6 methods)
    # ════════════════════════════════════════════════════════════════════════

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
        DeduplicationHelpers.assert_entry_not_has_attribute(entry, "telephoneNumber")

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

    # ════════════════════════════════════════════════════════════════════════
    # STRING ASSERTION TESTS (5 methods)
    # ════════════════════════════════════════════════════════════════════════

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

    # ════════════════════════════════════════════════════════════════════════
    # DICTIONARY ASSERTION TESTS (7 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_assert_dict_get_equals(self) -> None:
        """Test assert_dict_get_equals."""
        d = {"key": "value"}
        DeduplicationHelpers.assert_dict_get_equals(d, "key", "value")

    def test_assert_dict_equals(self) -> None:
        """Test assert_dict_equals."""
        # Use keys that exist in GenericFieldsDict
        d1: GenericFieldsDict = {"dn": "cn=test,dc=example,dc=com"}
        d2: GenericFieldsDict = {"dn": "cn=test,dc=example,dc=com"}
        DeduplicationHelpers.assert_dict_equals(d1, d2)

    def test_assert_dict_has_key(self) -> None:
        """Test assert_dict_has_key."""
        # Use keys that exist in GenericFieldsDict
        d: GenericFieldsDict = {"dn": "cn=test,dc=example,dc=com"}
        DeduplicationHelpers.assert_dict_has_key(d, "dn")

    def test_assert_dict_has_value(self) -> None:
        """Test assert_dict_has_value."""
        # Use keys that exist in GenericFieldsDict
        d: GenericFieldsDict = {"dn": "cn=test,dc=example,dc=com"}
        DeduplicationHelpers.assert_dict_has_value(d, "cn=test,dc=example,dc=com")

    def test_assert_dict_key_equals(self) -> None:
        """Test assert_dict_key_equals."""
        # assert_dict_key_equals expects dict[str, TResult], not GenericFieldsDict
        d: dict[str, str] = {"key": "value"}
        DeduplicationHelpers.assert_dict_key_equals(d, "key", "value")

    def test_assert_dict_key_isinstance(self) -> None:
        """Test assert_dict_key_isinstance."""
        # Use keys that exist in GenericFieldsDict with appropriate types
        d: GenericFieldsDict = {"attributes": {"cn": ["test"]}}
        DeduplicationHelpers.assert_dict_key_isinstance(d, "attributes", dict)

    def test_assert_dict_key_is_not_none(self) -> None:
        """Test assert_dict_key_is_not_none."""
        # Use keys that exist in GenericFieldsDict
        d: GenericFieldsDict = {"dn": "cn=test,dc=example,dc=com"}
        DeduplicationHelpers.assert_dict_key_is_not_none(d, "dn")

    # ════════════════════════════════════════════════════════════════════════
    # LIST ASSERTION TESTS (7 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_assert_list_equals(self) -> None:
        """Test assert_list_equals."""
        lst: list[object] = [1, 2, 3]
        DeduplicationHelpers.assert_list_equals(lst, [1, 2, 3])

    def test_assert_list_first_equals(self) -> None:
        """Test assert_list_first_equals."""
        lst: list[object] = [1, 2, 3]
        DeduplicationHelpers.assert_list_first_equals(lst, 1)

    def test_assert_list_last_equals(self) -> None:
        """Test assert_list_last_equals."""
        lst: list[object] = [1, 2, 3]
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

    # ════════════════════════════════════════════════════════════════════════
    # BOOLEAN ASSERTION TESTS (4 methods)
    # ════════════════════════════════════════════════════════════════════════

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

    # ════════════════════════════════════════════════════════════════════════
    # SERVICE EXECUTION TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_service_execute_and_unwrap(self) -> None:
        """Test service_execute_and_unwrap."""
        service = cast("ServiceWithExecute", FlextLdifSchema(server_type="rfc"))
        result = DeduplicationHelpers.service_execute_and_unwrap(service)
        assert result is not None
        # result is object type, so use isinstance to narrow type
        assert isinstance(result, FlextLdifModels.SchemaServiceStatus)
        assert result.service == "SchemaService"

    def test_service_execute_and_assert_fields(self) -> None:
        """Test service_execute_and_assert_fields."""
        service = cast("ServiceWithExecute", FlextLdifSchema(server_type="rfc"))
        # Use GenericFieldsDict with valid keys or None
        expected_fields: GenericFieldsDict | None = None
        result = DeduplicationHelpers.service_execute_and_assert_fields(
            service,
            expected_fields=expected_fields,
            expected_type=FlextLdifModels.SchemaServiceStatus,
        )
        # Verify result has expected type and attributes
        assert isinstance(result, FlextLdifModels.SchemaServiceStatus)
        assert hasattr(result, "service")
        assert hasattr(result, "status")

    # ════════════════════════════════════════════════════════════════════════
    # METADATA ASSERTION TESTS (4 methods)
    # ════════════════════════════════════════════════════════════════════════

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
        # Ensure metadata and extensions exist - use model_copy to update extensions
        if entry.metadata is None:
            entry = entry.model_copy(
                update={
                    "metadata": FlextLdifModelsDomains.QuirkMetadata(
                        quirk_type="rfc",
                        extensions=FlextLdifModelsMetadata.DynamicMetadata(
                            test_key="test_value"
                        ),
                    )
                }
            )
        else:
            # Update extensions via model_copy
            current_extensions = (
                entry.metadata.extensions or FlextLdifModelsMetadata.DynamicMetadata()
            )
            # Get existing extensions as dict
            existing_dict = (
                current_extensions.model_dump()
                if hasattr(current_extensions, "model_dump")
                else {}
            )
            # Create new extensions with test_key
            updated_extensions = FlextLdifModelsMetadata.DynamicMetadata(
                **existing_dict,
                test_key="test_value",
            )
            entry = entry.model_copy(
                update={
                    "metadata": entry.metadata.model_copy(
                        update={"extensions": updated_extensions}
                    )
                }
            )
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
        # Ensure metadata and extensions exist
        if entry.metadata is None:
            entry = entry.model_copy(
                update={
                    "metadata": FlextLdifModelsDomains.QuirkMetadata(
                        quirk_type="rfc",
                        extensions=FlextLdifModelsMetadata.DynamicMetadata(
                            test_key="test_value"
                        ),
                    )
                }
            )
        else:
            # Update extensions via model_copy to ensure type safety
            current_extensions = (
                entry.metadata.extensions or FlextLdifModelsMetadata.DynamicMetadata()
            )
            updated_extensions = FlextLdifModelsMetadata.DynamicMetadata(
                **current_extensions.model_dump()
                if hasattr(current_extensions, "model_dump")
                else {},
                test_key="test_value",
            )
            entry = entry.model_copy(
                update={
                    "metadata": entry.metadata.model_copy(
                        update={"extensions": updated_extensions}
                    )
                }
            )
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
        # Ensure metadata and extensions exist
        if entry.metadata is None:
            entry = entry.model_copy(
                update={
                    "metadata": FlextLdifModelsDomains.QuirkMetadata(
                        quirk_type="rfc",
                        extensions=FlextLdifModelsMetadata.DynamicMetadata(
                            test_key={"nested": "value"}
                        ),
                    )
                }
            )
        else:
            # Update extensions via model_copy to ensure type safety
            current_extensions = (
                entry.metadata.extensions or FlextLdifModelsMetadata.DynamicMetadata()
            )
            updated_extensions = FlextLdifModelsMetadata.DynamicMetadata(
                **current_extensions.model_dump()
                if hasattr(current_extensions, "model_dump")
                else {},
                test_key={"nested": "value"},
            )
            entry = entry.model_copy(
                update={
                    "metadata": entry.metadata.model_copy(
                        update={"extensions": updated_extensions}
                    )
                }
            )
        DeduplicationHelpers.assert_metadata_extension_get_isinstance(
            entry,
            "test_key",
            dict,
        )

    # ════════════════════════════════════════════════════════════════════════
    # SCHEMA ASSERTION TESTS (9 methods)
    # ════════════════════════════════════════════════════════════════════════

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

    def test_assert_metadata_quirk_type_equals(self) -> None:
        """Test assert_metadata_quirk_type_equals."""
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        # Ensure metadata exists with quirk_type
        if entry.metadata is None:
            entry = entry.model_copy(
                update={
                    "metadata": FlextLdifModelsDomains.QuirkMetadata(
                        quirk_type="rfc",
                        extensions=FlextLdifModelsMetadata.DynamicMetadata(),
                    )
                }
            )
        else:
            # Update quirk_type via model_copy
            entry = entry.model_copy(
                update={
                    "metadata": entry.metadata.model_copy(update={"quirk_type": "rfc"})
                }
            )
        # Entry implements EntryProtocol, but type checker needs cast due to None-able fields
        entry_protocol = cast("FlextLdifProtocols.Models.EntryProtocol", entry)
        DeduplicationHelpers.assert_metadata_quirk_type_equals(entry_protocol, "rfc")

    # ════════════════════════════════════════════════════════════════════════
    # RESULT TYPE ASSERTION TESTS (1 method)
    # ════════════════════════════════════════════════════════════════════════

    def test_assert_result_success_and_type(self) -> None:
        """Test assert_result_success_and_type."""
        result = FlextResult[str].ok("test")
        unwrapped = DeduplicationHelpers.assert_result_success_and_type(result, str)
        assert unwrapped == "test"

    # ════════════════════════════════════════════════════════════════════════
    # PARSE AND UNWRAP TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_parse_and_unwrap_simple(self) -> None:
        """Test parse_and_unwrap_simple."""
        api = FlextLdif()
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"
        result = api.parse(ldif_content)
        entries = DeduplicationHelpers.assert_success_and_unwrap_list(result)
        assert len(entries) > 0
        assert entries[0].dn is not None, "Entry must have DN"
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

    # ════════════════════════════════════════════════════════════════════════
    # QUIRK OPERATION TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

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

    # ════════════════════════════════════════════════════════════════════════
    # WRITE/UNWRAP/ASSERT TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

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

    # ════════════════════════════════════════════════════════════════════════
    # PARSE AND ASSERT TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

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
        assert entries[0].dn is not None, "Entry must have DN"
        assert entries[0].dn.value == "cn=test,dc=example,dc=com"

    def test_parse_and_assert_empty_content(self) -> None:
        """Test parse_and_assert with empty content - returns 0 entries (success)."""
        parser = FlextLdifParser()
        ldif_content = ""
        entries = DeduplicationHelpers.parse_and_assert(
            parser,
            ldif_content,
            expected_count=0,
        )
        assert len(entries) == 0

    # ════════════════════════════════════════════════════════════════════════
    # WRITE AND ASSERT TESTS (1 method)
    # ════════════════════════════════════════════════════════════════════════

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

    # ════════════════════════════════════════════════════════════════════════
    # ROUNDTRIP AND ASSERT TESTS (1 method)
    # ════════════════════════════════════════════════════════════════════════

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
        assert original_entries[0].dn is not None, "Original entry must have DN"
        assert roundtripped_entries[0].dn is not None, "Roundtripped entry must have DN"
        assert original_entries[0].dn.value == roundtripped_entries[0].dn.value

    # ════════════════════════════════════════════════════════════════════════
    # SCHEMA PARSE AND ASSERT TESTS (1 method)
    # ════════════════════════════════════════════════════════════════════════

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

    # ════════════════════════════════════════════════════════════════════════
    # SCHEMA WRITE AND ASSERT TESTS (1 method)
    # ════════════════════════════════════════════════════════════════════════

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

    # ════════════════════════════════════════════════════════════════════════
    # QUIRK ROUNDTRIP TESTS (1 method)
    # ════════════════════════════════════════════════════════════════════════

    def test_quirk_parse_write_roundtrip(self) -> None:
        """Test quirk_parse_write_roundtrip."""
        quirk = FlextLdifServersRfc()
        schema_quirk = quirk.Schema()
        attr_def = "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch )"
        original, written, roundtripped = (
            DeduplicationHelpers.quirk_parse_write_roundtrip(
                cast("FlextLdifProtocols.Quirks.SchemaProtocol", schema_quirk),
                attr_def,
                parse_method="parse_attribute",
                expected_type=FlextLdifModels.SchemaAttribute,
            )
        )
        assert isinstance(original, FlextLdifModels.SchemaAttribute)
        assert isinstance(written, str)
        assert isinstance(roundtripped, FlextLdifModels.SchemaAttribute)

    # ════════════════════════════════════════════════════════════════════════
    # API ROUNDTRIP TESTS (1 method)
    # ════════════════════════════════════════════════════════════════════════

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

    # ════════════════════════════════════════════════════════════════════════
    # BATCH OPERATION TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_batch_parse_and_assert(self) -> None:
        """Test batch_parse_and_assert."""
        parser = FlextLdifParser()
        test_cases = cast(
            "list[ParseTestCaseDict]",
            [
                {
                    "ldif_content": "dn: cn=test1,dc=example,dc=com\ncn: test1\n",
                    "expected_count": 1,
                },
                {
                    "ldif_content": "dn: cn=test2,dc=example,dc=com\ncn: test2\n",
                    "expected_count": 1,
                },
            ],
        )
        results = DeduplicationHelpers.batch_parse_and_assert(parser, test_cases)
        assert len(results) == 2
        assert all(len(entries) == 1 for entries in results)

    def test_create_entries_batch(self) -> None:
        """Test create_entries_batch."""
        entries_data = cast(
            "list[dict[str, str | dict[str, list[str] | str] | list[str]]]",
            [
                {"dn": "cn=test1,dc=example,dc=com", "attributes": {"cn": ["test1"]}},
                {"dn": "cn=test2,dc=example,dc=com", "attributes": {"cn": ["test2"]}},
            ],
        )
        entries = DeduplicationHelpers.create_entries_batch(entries_data)
        assert len(entries) == 2
        assert entries[0].dn is not None, "Entry 0 must have DN"
        assert entries[1].dn is not None, "Entry 1 must have DN"
        assert entries[0].dn.value == "cn=test1,dc=example,dc=com"
        assert entries[1].dn.value == "cn=test2,dc=example,dc=com"

    # ════════════════════════════════════════════════════════════════════════
    # SCHEMA HELPER TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_parse_schema_and_unwrap(self) -> None:
        """Test parse_schema_and_unwrap."""
        quirk = FlextLdifServersRfc()
        attr_def = "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch )"
        attr = DeduplicationHelpers.parse_schema_and_unwrap(
            cast("FlextLdifProtocols.Quirks.SchemaProtocol", quirk.Schema()),
            attr_def,
        )
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
        ldif = DeduplicationHelpers.write_schema_and_unwrap(
            cast("FlextLdifProtocols.Quirks.SchemaProtocol", quirk.Schema()),
            attr,
        )
        assert isinstance(ldif, str)
        assert "testAttr" in ldif

    # ════════════════════════════════════════════════════════════════════════
    # ENTRY HELPER TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_parse_entry_and_unwrap(self) -> None:
        """Test parse_entry_and_unwrap."""
        quirk = FlextLdifServersRfc()
        ldif_content = "dn: cn=test,dc=example,dc=com\ncn: test\n"
        entry = DeduplicationHelpers.parse_entry_and_unwrap(
            cast("FlextLdifProtocols.Quirks.EntryProtocol", quirk.Entry()),
            ldif_content,
            expected_dn="cn=test,dc=example,dc=com",
        )
        assert entry.dn is not None, "Entry must have DN"
        assert entry.dn.value == "cn=test,dc=example,dc=com"

    def test_write_entry_and_unwrap(self) -> None:
        """Test write_entry_and_unwrap."""
        quirk = FlextLdifServersRfc()
        entry = TestAssertions.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )
        ldif = DeduplicationHelpers.write_entry_and_unwrap(
            cast("FlextLdifProtocols.Quirks.EntryProtocol", quirk.Entry()),
            entry,
            must_contain=["cn: test"],
        )
        assert "cn: test" in ldif

    # ════════════════════════════════════════════════════════════════════════
    # ACL HELPER TESTS (2 methods)
    # ════════════════════════════════════════════════════════════════════════

    def test_acl_quirk_parse_and_assert(self) -> None:
        """Test acl_quirk_parse_and_assert."""
        quirk = FlextLdifServersRfc()
        acl_line = "grant(user1) read"
        acl = DeduplicationHelpers.acl_quirk_parse_and_assert(quirk.Acl(), acl_line)
        assert isinstance(acl, FlextLdifModels.Acl)

    def test_acl_quirk_write_and_assert(self) -> None:
        """Test acl_quirk_write_and_assert."""
        quirk = FlextLdifServersRfc()
        acl_line = "grant(user1) read"
        acl = DeduplicationHelpers.acl_quirk_parse_and_assert(quirk.Acl(), acl_line)
        ldif = DeduplicationHelpers.acl_quirk_write_and_assert(
            quirk.Acl(),
            acl,
            must_contain=["grant"],
        )
        assert "grant" in ldif.lower()


__all__ = [
    "TestFlextLdifDeduplicationHelpers",
]
