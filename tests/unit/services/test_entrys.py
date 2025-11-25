"""Test FlextLdifEntry service with real implementations.

Tests FlextLdifEntry service operations using actual implementations.
Validates DN cleaning, operational attribute removal, attribute stripping,
and entry transformations with real data and edge cases.

Scope: Entry service functionality with comprehensive validation.
Modules tested: flext_ldif.services.entry, flext_ldif.models, flext_ldif.utilities

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

import pytest

from flext_ldif import FlextLdifModels, FlextLdifUtilities
from flext_ldif.services.entry import FlextLdifEntry
from flext_ldif.services.syntax import FlextLdifSyntax
from flext_ldif.services.validation import FlextLdifValidation
from tests.helpers.test_deduplication_helpers import TestDeduplicationHelpers
from tests.helpers.test_rfc_helpers import RfcTestHelpers

# =============================================================================
# TEST SCENARIO ENUMS & DATA CLASSES
# =============================================================================


class DnCleaningTestType(StrEnum):
    """DN cleaning test scenarios."""

    WITH_SPACES = "with_spaces"
    ALREADY_CLEAN = "already_clean"
    WITH_ESCAPED_CHARS = "with_escaped_chars"
    MULTIPLE_SPACES = "multiple_spaces"
    PRESERVES_VALUE_SPACES = "preserves_value_spaces"
    WITH_SPECIAL_CHARS = "with_special_chars"
    EMPTY_STRING = "empty_string"


class AttributeRemovalTestType(StrEnum):
    """Attribute removal test scenarios."""

    REMOVE_SINGLE = "remove_single"
    REMOVE_MULTIPLE = "remove_multiple"
    REMOVE_NONEXISTENT = "remove_nonexistent"
    CASE_INSENSITIVE = "case_insensitive"
    OPERATIONAL_SINGLE = "operational_single"
    OPERATIONAL_BATCH = "operational_batch"
    CASE_INSENSITIVE_OPERATIONAL = "case_insensitive_operational"


class ValidationTestType(StrEnum):
    """Validation test scenarios."""

    VALIDATE_ATTR_NAME_VALID = "validate_attr_name_valid"
    VALIDATE_ATTR_NAME_INVALID = "validate_attr_name_invalid"
    VALIDATE_OBJECTCLASS = "validate_objectclass"
    VALIDATE_ATTR_VALUE = "validate_attr_value"
    VALIDATE_DN_COMPONENT = "validate_dn_component"
    VALIDATE_ATTR_NAMES_BATCH = "validate_attr_names_batch"


class SyntaxTestType(StrEnum):
    """Syntax validation test scenarios."""

    VALIDATE_OID = "validate_oid"
    IS_RFC4517_STANDARD = "is_rfc4517_standard"
    LOOKUP_NAME = "lookup_name"
    LOOKUP_OID = "lookup_oid"
    RESOLVE_SYNTAX = "resolve_syntax"
    VALIDATE_VALUE = "validate_value"
    GET_CATEGORY = "get_category"
    LIST_ALL = "list_all"


class EdgeCaseTestType(StrEnum):
    """Edge case test scenarios."""

    NO_ATTRIBUTES = "no_attributes"
    ONLY_OPERATIONAL = "only_operational"
    UNICODE_DN = "unicode_dn"
    LONG_VALUES = "long_values"
    MANY_ATTRIBUTES = "many_attributes"


@dataclass(frozen=True)
class DnCleaningCase:
    """DN cleaning test case."""

    test_type: DnCleaningTestType
    input_dn: str
    expected_present: str | None = None
    expected_absent: str | None = None


@dataclass(frozen=True)
class ValidationCase:
    """Validation test case."""

    test_type: ValidationTestType
    input_value: str | list[str] | dict[str, str] | None = None
    expected_result: bool | dict[str, bool] | None = None
    description: str = ""


class TestCategory(StrEnum):
    """Test categories for entry service testing."""

    DN_CLEANING = "dn_cleaning"
    OPERATIONAL_ATTRS = "operational_attrs"
    ATTRIBUTE_STRIPPING = "attribute_stripping"
    BATCH_TRANSFORMATIONS = "batch_transformations"
    ERROR_HANDLING = "error_handling"
    EDGE_CASES = "edge_cases"


# ════════════════════════════════════════════════════════════════════════════
# TEST FIXTURES
# ════════════════════════════════════════════════════════════════════════════


def create_entry(
    dn_str: str,
    attributes: Mapping[str, str | list[str]],
) -> FlextLdifModels.Entry:
    """Create test entry with DN and attributes."""
    dn = FlextLdifModels.DistinguishedName(value=dn_str)
    attrs = TestDeduplicationHelpers.create_attributes_from_dict(attributes)  # type: ignore[arg-type]
    return FlextLdifModels.Entry(dn=dn, attributes=attrs)


@pytest.fixture
def simple_entry() -> FlextLdifModels.Entry:
    """Create a simple test entry."""
    return create_entry(
        "cn=john,ou=users,dc=example,dc=com",
        {
            "cn": ["john"],
            "sn": ["Doe"],
            "mail": ["john@example.com"],
            "objectClass": ["person", "inetOrgPerson"],
        },
    )


@pytest.fixture
def entry_with_operational_attrs() -> FlextLdifModels.Entry:
    """Create entry with operational attributes."""
    return create_entry(
        "cn=jane,ou=users,dc=example,dc=com",
        {
            "cn": ["jane"],
            "sn": ["Smith"],
            "mail": ["jane@example.com"],
            "createTimestamp": ["20250104120000Z"],
            "modifyTimestamp": ["20250105120000Z"],
            "creatorsName": ["cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"],
            "modifiersName": ["cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"],
            "entryCSN": ["20250105120000.123456Z#000000#000#000000"],
            "entryUUID": ["12345678-1234-5678-1234-567812345678"],
        },
    )


@pytest.fixture
def entries_batch() -> list[FlextLdifModels.Entry]:
    """Create batch of entries for testing."""
    return [
        create_entry(
            "cn=user1,ou=users,dc=example,dc=com",
            {"cn": ["user1"], "createTimestamp": ["20250104120000Z"]},
        ),
        create_entry(
            "cn=user2,ou=users,dc=example,dc=com",
            {"cn": ["user2"], "modifyTimestamp": ["20250105120000Z"]},
        ),
        create_entry(
            "cn=user3,ou=users,dc=example,dc=com",
            {"cn": ["user3"], "entryCSN": ["20250105120000.123456Z"]},
        ),
    ]


# ════════════════════════════════════════════════════════════════════════════
# TEST DN CLEANING (Public API)
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestDnCleaningPublicApi:
    """Test DN cleaning public API."""

    DN_CLEANING_DATA: ClassVar[dict[str, tuple[DnCleaningTestType, str, str | None, str | None]]] = {
        "test_clean_dn_with_spaces": (
            DnCleaningTestType.WITH_SPACES,
            "cn = John Doe , ou = users , dc = example , dc = com",
            "cn=",
            " = ",
        ),
        "test_clean_dn_already_clean": (
            DnCleaningTestType.ALREADY_CLEAN,
            "cn=john,ou=users,dc=example,dc=com",
            "cn=john",
            None,
        ),
        "test_clean_dn_with_escaped_chars": (
            DnCleaningTestType.WITH_ESCAPED_CHARS,
            r"cn=John\, Doe,ou=users,dc=example,dc=com",
            None,
            None,
        ),
    }

    @pytest.mark.parametrize(
        ("scenario", "test_type", "input_dn", "expected_present", "expected_absent"),
        [
            (name, data[0], data[1], data[2], data[3])
            for name, data in DN_CLEANING_DATA.items()
        ],
    )
    def test_clean_dn(
        self,
        scenario: str,
        test_type: DnCleaningTestType,
        input_dn: str,
        expected_present: str | None,
        expected_absent: str | None,
    ) -> None:
        """Parametrized test for DN cleaning."""
        cleaned = FlextLdifUtilities.DN.clean_dn(input_dn)

        assert isinstance(cleaned, str)
        assert len(cleaned) > 0
        if expected_present:
            assert expected_present in cleaned
        if expected_absent:
            assert expected_absent not in cleaned


# ════════════════════════════════════════════════════════════════════════════
# TEST ATTRIBUTE REMOVAL (Public API)
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestAttributeRemovalPublicApi:
    """Test attribute removal public API."""

    REMOVAL_DATA: ClassVar[
        dict[
            str,
            tuple[
                AttributeRemovalTestType,
                str,
                list[str] | None,
                list[str] | None,
                bool,
            ],
        ]
    ] = {
        "test_remove_single_attribute": (
            AttributeRemovalTestType.REMOVE_SINGLE,
            "simple_entry",
            ["mail"],
            ["mail"],
            True,
        ),
        "test_remove_multiple_attributes": (
            AttributeRemovalTestType.REMOVE_MULTIPLE,
            "simple_entry",
            ["mail", "sn", "objectClass"],
            ["mail", "sn", "objectClass"],
            True,
        ),
        "test_remove_nonexistent_attribute": (
            AttributeRemovalTestType.REMOVE_NONEXISTENT,
            "simple_entry",
            ["nonexistent"],
            None,
            None,
        ),
        "test_case_insensitive_attribute_removal": (
            AttributeRemovalTestType.CASE_INSENSITIVE,
            "simple_entry",
            ["MAIL", "SN"],
            ["mail", "sn"],
            True,
        ),
        "test_remove_operational_attributes_single": (
            AttributeRemovalTestType.OPERATIONAL_SINGLE,
            "entry_with_operational_attrs",
            None,
            ["createTimestamp", "modifyTimestamp", "creatorsName", "entryCSN"],
            False,
        ),
        "test_remove_operational_attributes_batch": (
            AttributeRemovalTestType.OPERATIONAL_BATCH,
            "entries_batch",
            None,
            ["createTimestamp", "modifyTimestamp", "entryCSN"],
            False,
        ),
        "test_case_insensitive_operational_attr_matching": (
            AttributeRemovalTestType.CASE_INSENSITIVE_OPERATIONAL,
            "entry_with_operational_attrs",
            None,
            ["CREATETIMESTAMP", "modifyTimestamp"],
            False,
        ),
    }

    @pytest.mark.parametrize(
        ("scenario", "test_type", "fixture_name", "attrs_to_remove", "attrs_to_check", "is_selective"),
        [
            (name, data[0], data[1], data[2], data[3], data[4])
            for name, data in REMOVAL_DATA.items()
        ],
    )
    def test_attribute_removal(
        self,
        scenario: str,
        test_type: AttributeRemovalTestType,
        fixture_name: str,
        attrs_to_remove: list[str] | None,
        attrs_to_check: list[str] | None,
        is_selective: bool,
        simple_entry: FlextLdifModels.Entry,
        entry_with_operational_attrs: FlextLdifModels.Entry,
        entries_batch: list[FlextLdifModels.Entry],
    ) -> None:
        """Parametrized test for attribute removal scenarios."""
        fixtures = {
            "simple_entry": simple_entry,
            "entry_with_operational_attrs": entry_with_operational_attrs,
            "entries_batch": entries_batch,
        }
        fixture_data = fixtures[fixture_name]

        if is_selective and fixture_name == "simple_entry":
            result = FlextLdifEntry.remove_attributes(fixture_data, attributes=attrs_to_remove or [])
        elif is_selective and fixture_name == "entries_batch":
            result = FlextLdifEntry.remove_attributes_batch(fixture_data, attributes=attrs_to_remove or [])
        else:
            result = FlextLdifEntry.remove_operational_attributes(fixture_data if fixture_name != "entries_batch" else fixture_data[0])

        if isinstance(fixture_data, list):
            result = FlextLdifEntry.remove_operational_attributes_batch(fixture_data)

        assert result.is_success
        cleaned = result.unwrap()

        if attrs_to_check:
            if isinstance(cleaned, list):
                for entry in cleaned:
                    attrs = entry.attributes.attributes
                    for attr in attrs_to_check:
                        assert attr not in attrs
            else:
                attrs = cleaned.attributes.attributes
                for attr in attrs_to_check:
                    assert attr not in attrs


# ════════════════════════════════════════════════════════════════════════════
# TEST PATTERNS (Execute, Builder, Integrations)
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestPatterns:
    """Test execute pattern, builder pattern, and integration scenarios."""

    def test_execute_pattern_operations(
        self,
        entries_batch: list[FlextLdifModels.Entry],
        simple_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test execute() method with various operations."""
        # Test 1: Batch operational attribute removal
        service1 = FlextLdifEntry(
            entries=entries_batch,
            operation="remove_operational_attributes",
        )
        result1 = RfcTestHelpers.test_service_execute_and_assert(
            service1,  # type: ignore[arg-type]
            expected_type=list,
            expected_count=3,
        )
        assert len(result1) == 3

        # Test 2: Selective attribute removal
        service2 = FlextLdifEntry(
            entries=[simple_entry],
            operation="remove_attributes",
            attributes_to_remove=["mail"],
        )
        result2 = RfcTestHelpers.test_service_execute_and_assert(
            service2,  # type: ignore[arg-type]
            expected_type=list,
        )
        assert "mail" not in result2[0].attributes.attributes  # type: ignore[index,attr-defined]

        # Test 3: Empty batch
        service4 = FlextLdifEntry(
            entries=[],
            operation="remove_operational_attributes",
        )
        result4 = RfcTestHelpers.test_service_execute_and_assert(
            service4,  # type: ignore[arg-type]
            expected_type=list,
            expected_count=0,
        )
        assert result4 == []

    def test_builder_pattern(self, simple_entry: FlextLdifModels.Entry) -> None:
        """Test fluent builder pattern."""
        # Test 1: Basic builder
        result1 = (
            FlextLdifEntry.builder()
            .with_entries([simple_entry])
            .with_operation("remove_operational_attributes")
            .build()
        )
        assert isinstance(result1, list)
        assert len(result1) == 1
        assert "cn" in result1[0].attributes.attributes

        # Test 2: Builder with attributes_to_remove
        result2 = (
            FlextLdifEntry.builder()
            .with_entries([simple_entry])
            .with_operation("remove_attributes")
            .with_attributes_to_remove(["mail", "sn"])
            .build()
        )
        attrs = result2[0].attributes.attributes
        assert "mail" not in attrs
        assert "sn" not in attrs

        # Test 3: Builder chaining returns same instance
        builder = FlextLdifEntry.builder()
        builder2 = builder.with_entries([simple_entry])
        assert builder2 is builder

    def test_integration_pipeline(
        self,
        entry_with_operational_attrs: FlextLdifModels.Entry,
        entries_batch: list[FlextLdifModels.Entry],
    ) -> None:
        """Test realistic processing pipelines."""
        # Single entry pipeline
        result1 = FlextLdifEntry.remove_operational_attributes(entry_with_operational_attrs)
        assert result1.is_success
        intermediate = result1.unwrap()
        result2 = FlextLdifEntry.remove_attributes(intermediate, attributes=["mail"])
        assert result2.is_success
        final = result2.unwrap()
        attrs = final.attributes.attributes
        assert "mail" not in attrs
        assert "createTimestamp" not in attrs
        assert "cn" in attrs

        # Batch pipeline
        result3 = FlextLdifEntry.remove_operational_attributes_batch(entries_batch)
        assert result3.is_success
        cleaned_batch = result3.unwrap()
        result4 = FlextLdifEntry.remove_attributes_batch(cleaned_batch, attributes=["cn"])
        assert result4.is_success
        final_batch = result4.unwrap()
        assert len(final_batch) == len(entries_batch)
        for entry in final_batch:
            assert "cn" not in entry.attributes.attributes


# ════════════════════════════════════════════════════════════════════════════
# TEST EDGE CASES
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestEdgeCases:
    """Test edge cases and special situations."""

    EDGE_CASE_DATA: ClassVar[dict[str, tuple[EdgeCaseTestType]]] = {
        "test_entry_with_no_attributes": (EdgeCaseTestType.NO_ATTRIBUTES,),
        "test_entry_with_only_operational_attributes": (EdgeCaseTestType.ONLY_OPERATIONAL,),
        "test_unicode_in_dn": (EdgeCaseTestType.UNICODE_DN,),
        "test_very_long_attribute_values": (EdgeCaseTestType.LONG_VALUES,),
        "test_entry_with_many_attributes": (EdgeCaseTestType.MANY_ATTRIBUTES,),
    }

    @pytest.mark.parametrize(
        ("scenario", "test_type"),
        [(name, data[0]) for name, data in EDGE_CASE_DATA.items()],
    )
    def test_edge_case(
        self,
        scenario: str,
        test_type: EdgeCaseTestType,
    ) -> None:
        """Parametrized test for edge cases."""
        if test_type == EdgeCaseTestType.NO_ATTRIBUTES:
            entry = create_entry("cn=empty,dc=example,dc=com", {"cn": ["empty"]})
            result = FlextLdifEntry.remove_operational_attributes(entry)
            assert result.is_success
            assert "cn" in result.unwrap().attributes.attributes

        elif test_type == EdgeCaseTestType.ONLY_OPERATIONAL:
            entry = create_entry(
                "cn=test,dc=example,dc=com",
                {
                    "createTimestamp": ["20250104120000Z"],
                    "modifyTimestamp": ["20250105120000Z"],
                },
            )
            result = FlextLdifEntry.remove_operational_attributes(entry)
            assert result.is_success
            assert len(result.unwrap().attributes.attributes) == 0

        elif test_type == EdgeCaseTestType.UNICODE_DN:
            entry = create_entry("cn=日本語,dc=example,dc=com", {"cn": ["日本語"]})
            result = FlextLdifEntry.remove_operational_attributes(entry)
            assert result.is_success
            assert "cn" in result.unwrap().attributes.attributes

        elif test_type == EdgeCaseTestType.LONG_VALUES:
            long_value = "x" * 10000
            entry = create_entry(
                "cn=test,dc=example,dc=com",
                {"cn": ["test"], "description": [long_value]},
            )
            result = FlextLdifEntry.remove_attributes(entry, attributes=["description"])
            assert result.is_success
            cleaned = result.unwrap()
            assert "description" not in cleaned.attributes.attributes
            assert "cn" in cleaned.attributes.attributes

        elif test_type == EdgeCaseTestType.MANY_ATTRIBUTES:
            attrs = {f"attr{i}": [f"value{i}"] for i in range(100)}
            attrs["cn"] = ["test"]
            entry = create_entry("cn=test,dc=example,dc=com", attrs)
            result = FlextLdifEntry.remove_attributes(
                entry,
                attributes=[f"attr{i}" for i in range(50)],
            )
            assert result.is_success
            cleaned = result.unwrap()
            assert all(f"attr{i}" not in cleaned.attributes.attributes for i in range(50))
            assert all(f"attr{i}" in cleaned.attributes.attributes for i in range(50, 100))


# ════════════════════════════════════════════════════════════════════════════
# TEST VALIDATION (RFC 4512/4514)
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestValidation:
    """RFC 4512/4514 LDAP validation tests."""

    VALIDATION_DATA: ClassVar[dict[str, tuple[ValidationTestType]]] = {
        "test_validate_attribute_name_valid": (ValidationTestType.VALIDATE_ATTR_NAME_VALID,),
        "test_validate_attribute_name_invalid": (ValidationTestType.VALIDATE_ATTR_NAME_INVALID,),
        "test_validate_objectclass_name": (ValidationTestType.VALIDATE_OBJECTCLASS,),
        "test_validate_attribute_value": (ValidationTestType.VALIDATE_ATTR_VALUE,),
        "test_validate_dn_component": (ValidationTestType.VALIDATE_DN_COMPONENT,),
        "test_validate_attribute_names_batch": (ValidationTestType.VALIDATE_ATTR_NAMES_BATCH,),
    }

    @pytest.mark.parametrize(
        ("scenario", "test_type"),
        [(name, data[0]) for name, data in VALIDATION_DATA.items()],
    )
    def test_validation_scenarios(
        self,
        scenario: str,
        test_type: ValidationTestType,
    ) -> None:
        """Parametrized test for validation scenarios."""
        service = FlextLdifValidation()

        if test_type == ValidationTestType.VALIDATE_ATTR_NAME_VALID:
            for name in ["cn", "mail", "objectClass", "user-account", "extensionAttribute123"]:
                assert service.validate_attribute_name(name).unwrap() is True

        elif test_type == ValidationTestType.VALIDATE_ATTR_NAME_INVALID:
            for name in ["2invalid", "user name", "", "user@name"]:
                assert service.validate_attribute_name(name).unwrap() is False

        elif test_type == ValidationTestType.VALIDATE_OBJECTCLASS:
            assert service.validate_objectclass_name("person").unwrap() is True
            assert service.validate_objectclass_name("invalid class").unwrap() is False

        elif test_type == ValidationTestType.VALIDATE_ATTR_VALUE:
            assert service.validate_attribute_value("John Smith").unwrap() is True
            assert service.validate_attribute_value("test", max_length=2).unwrap() is False

        elif test_type == ValidationTestType.VALIDATE_DN_COMPONENT:
            assert service.validate_dn_component("cn", "John Smith").unwrap() is True
            assert service.validate_dn_component("2invalid", "value").unwrap() is False

        elif test_type == ValidationTestType.VALIDATE_ATTR_NAMES_BATCH:
            validated = service.validate_attribute_names(["cn", "mail", "2invalid", "objectClass"]).unwrap()
            assert validated["cn"] is True
            assert validated["2invalid"] is False


# ════════════════════════════════════════════════════════════════════════════
# TEST SYNTAX (RFC 4517)
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.unit
class TestSyntax:
    """RFC 4517 LDAP attribute syntax tests."""

    SYNTAX_DATA: ClassVar[dict[str, tuple[SyntaxTestType]]] = {
        "test_validate_oid_format": (SyntaxTestType.VALIDATE_OID,),
        "test_is_rfc4517_standard": (SyntaxTestType.IS_RFC4517_STANDARD,),
        "test_lookup_syntax_name": (SyntaxTestType.LOOKUP_NAME,),
        "test_lookup_syntax_oid": (SyntaxTestType.LOOKUP_OID,),
        "test_resolve_syntax_oid": (SyntaxTestType.RESOLVE_SYNTAX,),
        "test_validate_syntax_value": (SyntaxTestType.VALIDATE_VALUE,),
        "test_get_syntax_type": (SyntaxTestType.GET_CATEGORY,),
        "test_list_all_syntaxes": (SyntaxTestType.LIST_ALL,),
    }

    @pytest.mark.parametrize(
        ("scenario", "test_type"),
        [(name, data[0]) for name, data in SYNTAX_DATA.items()],
    )
    def test_syntax_scenarios(
        self,
        scenario: str,
        test_type: SyntaxTestType,
    ) -> None:
        """Parametrized test for syntax scenarios."""
        syntax = FlextLdifSyntax()
        boolean_oid = "1.3.6.1.4.1.1466.115.121.1.7"

        if test_type == SyntaxTestType.VALIDATE_OID:
            assert syntax.validate_oid(boolean_oid).unwrap() is True
            assert syntax.validate_oid("invalid-oid").unwrap() is False

        elif test_type == SyntaxTestType.IS_RFC4517_STANDARD:
            assert syntax.is_rfc4517_standard(boolean_oid).is_success

        elif test_type == SyntaxTestType.LOOKUP_NAME:
            result = syntax.lookup_name("boolean")
            if not result.is_success:
                result = syntax.lookup_name("Boolean")
            assert result.unwrap() == boolean_oid

        elif test_type == SyntaxTestType.LOOKUP_OID:
            assert syntax.lookup_oid(boolean_oid).unwrap().lower() == "boolean"

        elif test_type == SyntaxTestType.RESOLVE_SYNTAX:
            assert syntax.resolve_syntax(boolean_oid).unwrap().oid == boolean_oid

        elif test_type == SyntaxTestType.VALIDATE_VALUE:
            assert syntax.validate_value("TRUE", boolean_oid).is_success

        elif test_type == SyntaxTestType.GET_CATEGORY:
            result = syntax.get_syntax_category(boolean_oid)
            assert result.is_success
            assert isinstance(result.unwrap(), str)

        elif test_type == SyntaxTestType.LIST_ALL:
            oids = syntax.list_common_syntaxes().unwrap()
            assert isinstance(oids, list)
            assert len(oids) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
