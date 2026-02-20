"""Consolidated tests for FlextLdif Entries service.

This module consolidates all entries service tests from multiple test files into
a single optimized test suite. Tests entry operations including creation,
manipulation, validation, transformation, and real-world scenarios using
real implementations and flext_tests utilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Final, cast

import pytest
from flext_ldif import FlextLdif, FlextLdifProtocols, FlextLdifUtilities
from flext_ldif.services.entries import FlextLdifEntries
from flext_ldif.services.syntax import FlextLdifSyntax
from flext_ldif.services.validation import FlextLdifValidation

from tests import c, m, p, s, tf, tm

# Module-level constants
_OPERATIONAL_ATTRS: Final[list[str]] = [
    "createTimestamp",
    "modifyTimestamp",
    "creatorsName",
    "modifiersName",
    "entryCSN",
    "entryUUID",
]
_LONG_VALUE_LENGTH: Final[int] = 10000
_MANY_ATTRS_COUNT: Final[int] = 100
_MANY_ATTRS_REMOVE_COUNT: Final[int] = 50
_UNICODE_DN: Final[str] = "cn=测试,dc=example,dc=com"
_UNICODE_VALUE: Final[str] = "测试值"
_VALID_ATTR_NAMES: Final[list[str]] = ["cn", "sn", "mail", "objectClass", "uid"]
# RFC 4512 allows hyphens in attribute names, so "invalid-name" is actually valid!
# Invalid names: starts with digit, contains @, contains space
_INVALID_ATTR_NAMES: Final[list[str]] = ["2invalid", "invalid@name", "invalid name"]
_BOOLEAN_OID: Final[str] = "1.3.6.1.4.1.1466.115.121.1.7"
# NAME_TO_OID uses lowercase snake_case from OID_TO_NAME mapping
_BOOLEAN_NAME: Final[str] = "boolean"

# Fixtures path - tests/unit/services/ -> tests/fixtures/
FIXTURES_ROOT = Path(__file__).parent.parent.parent / "fixtures"


# ════════════════════════════════════════════════════════════════════════════
# REAL LDIF FIXTURE LOADERS
# ════════════════════════════════════════════════════════════════════════════


class RealLdifLoader:
    """Load REAL LDIF fixture data from test fixtures directory."""

    @staticmethod
    def load_oid_entries() -> list[p.Entry]:
        """Load real OID LDIF entries from fixtures."""
        fixture_path = FIXTURES_ROOT / "oid" / "oid_entries_fixtures.ldif"
        ldif = FlextLdif()
        result = ldif.parse(fixture_path)
        if result.is_success:
            return result.value
        msg = f"Failed to parse OID fixtures: {result.error}"
        raise ValueError(msg)

    @staticmethod
    def load_oud_entries() -> list[p.Entry]:
        """Load real OUD LDIF entries from fixtures."""
        fixture_path = FIXTURES_ROOT / "oud" / "oud_entries_fixtures.ldif"
        ldif = FlextLdif()
        result = ldif.parse(fixture_path)
        if result.is_success:
            return result.value
        msg = f"Failed to parse OUD fixtures: {result.error}"
        raise ValueError(msg)

    @staticmethod
    def load_openldap2_entries() -> list[p.Entry]:
        """Load real OpenLDAP2 LDIF entries from fixtures."""
        fixture_path = FIXTURES_ROOT / "openldap2" / "openldap2_entries_fixtures.ldif"
        ldif = FlextLdif()
        result = ldif.parse(fixture_path)
        if result.is_success:
            return result.value
        msg = f"Failed to parse OpenLDAP2 fixtures: {result.error}"
        raise ValueError(msg)

    @staticmethod
    def load_rfc_entries() -> list[p.Entry]:
        """Load real RFC LDIF entries from fixtures."""
        fixture_path = FIXTURES_ROOT / "rfc" / "rfc_entries_fixtures.ldif"
        ldif = FlextLdif()
        result = ldif.parse(fixture_path)
        if result.is_success:
            return result.value
        msg = f"Failed to parse RFC fixtures: {result.error}"
        raise ValueError(msg)


# ════════════════════════════════════════════════════════════════════════════
# PYTEST FIXTURES
# ════════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="module")
def oid_entries() -> list[p.Entry]:
    """Load real OID LDIF entries (module-scoped to avoid repeated parsing)."""
    return RealLdifLoader.load_oid_entries()


@pytest.fixture(scope="module")
def oud_entries() -> list[p.Entry]:
    """Load real OUD LDIF entries (module-scoped to avoid repeated parsing)."""
    return RealLdifLoader.load_oud_entries()


@pytest.fixture(scope="module")
def openldap2_entries() -> list[p.Entry]:
    """Load real OpenLDAP2 LDIF entries (module-scoped to avoid repeated parsing)."""
    return RealLdifLoader.load_openldap2_entries()


@pytest.fixture(scope="module")
def rfc_entries() -> list[p.Entry]:
    """Load real RFC LDIF entries (module-scoped to avoid repeated parsing)."""
    return RealLdifLoader.load_rfc_entries()


# ════════════════════════════════════════════════════════════════════════════
# MAIN TEST CLASS
# ════════════════════════════════════════════════════════════════════════════


class TestsFlextLdifEntries(s):
    """Consolidated test suite for FlextLdifEntries service.

    Merges all test classes from:
    - test_entries.py (TestFlextLdifEntries)
    - test_entrys.py (TestFlextLdifEntrys)
    - test_entry_manipulation.py (TestsTestFlextLdifEntries)
    - test_entrys_with_real_ldif.py (various real data test classes)

    Uses nested classes for organization and flext_tests utilities for assertions.
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

        OPERATIONAL_ATTRS: Final[list[str]] = _OPERATIONAL_ATTRS
        LONG_VALUE_LENGTH: Final[int] = _LONG_VALUE_LENGTH
        MANY_ATTRS_COUNT: Final[int] = _MANY_ATTRS_COUNT
        MANY_ATTRS_REMOVE_COUNT: Final[int] = _MANY_ATTRS_REMOVE_COUNT
        UNICODE_DN: Final[str] = _UNICODE_DN
        UNICODE_VALUE: Final[str] = _UNICODE_VALUE
        VALID_ATTR_NAMES: Final[list[str]] = _VALID_ATTR_NAMES
        INVALID_ATTR_NAMES: Final[list[str]] = _INVALID_ATTR_NAMES
        BOOLEAN_OID: Final[str] = _BOOLEAN_OID
        BOOLEAN_NAME: Final[str] = _BOOLEAN_NAME
        DN_TEST_USER: Final[str] = c.DNs.TEST_USER

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
        """Factory methods for creating test entries."""

        @staticmethod
        def create_test_entry(dn: str | None = None, **overrides: object) -> p.Entry:
            """Create test entry using factory."""
            if dn is None:
                dn = c.DNs.TEST_USER
            attrs: dict[str, str | list[str]] = {
                c.Names.OBJECTCLASS: [c.Names.PERSON],
                c.Names.CN: [c.Values.TEST],
            }
            compatible_overrides: dict[str, str | list[str]] = {
                k: v for k, v in overrides.items() if isinstance(v, (str, list))
            }
            attrs.update(compatible_overrides)
            service = FlextLdifEntries()
            result = service.create_entry(dn, attrs)
            if result.is_success:
                return result.value
            return p.Entry.model_construct(
                dn=m.Ldif.DN(value=dn),
                attributes=m.Ldif.Attributes(attributes=attrs),
            )

        @staticmethod
        def create_simple_entry() -> p.Entry:
            """Create a simple test entry using factory."""
            return tf.create_entry(
                f"cn=john,ou=users,{c.DNs.EXAMPLE}",
                cn=["john"],
                sn=["Doe"],
                mail=["john@example.com"],
                objectClass=["person", "inetOrgPerson"],
            )

        @staticmethod
        def create_entry_with_operational_attrs() -> p.Entry:
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
        def create_entries_batch() -> list[p.Entry]:
            """Create batch of entries for testing."""
            operational_attrs = _OPERATIONAL_ATTRS
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

        @staticmethod
        def create_simple_user_entry() -> p.Entry:
            """Create a simple user entry."""
            service = FlextLdifEntries()
            result = service.create_entry(
                dn=f"cn={c.Values.USER},ou=users,{c.DNs.EXAMPLE}",
                attributes={
                    c.Names.CN: [c.Values.USER],
                    c.Names.SN: [c.Values.USER],
                    c.Names.MAIL: ["test@example.com"],
                    c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.INETORGPERSON],
                },
            )
            if result.is_success:
                return result.value
            raise ValueError(f"Failed to create entry: {result.error}")

        @staticmethod
        def create_service() -> FlextLdifEntries:
            """Create FlextLdifEntries instance."""
            return FlextLdifEntries()

        @staticmethod
        def create_mock_entry_with_dn(
            dn_value: str,
            attributes: object = None,
        ) -> FlextLdifProtocols.Models.EntryWithDnProtocol:
            """Create mock entry implementing EntryWithDnProtocol."""

            class MockEntry:
                def __init__(self, dn_val: str, attrs: object) -> None:
                    self.dn: object = dn_val
                    self.attributes: object = attrs or {}

            return MockEntry(dn_value, attributes)

        @staticmethod
        def create_mock_entry_with_dn_value(
            dn_value: str,
            attributes: object = None,
        ) -> FlextLdifProtocols.Models.EntryWithDnProtocol:
            """Create mock entry with DN that has .value attribute."""

            class DnWithValue:
                def __init__(self, value: str) -> None:
                    self.value = value

                def __str__(self) -> str:
                    return self.value

            class MockEntry:
                def __init__(self, dn_val: str, attrs: object) -> None:
                    self.dn: object = DnWithValue(dn_val)
                    self.attributes: object = attrs or {}

            return MockEntry(dn_value, attributes)

        @staticmethod
        def create_mock_attribute_value(
            values: list[str] | str,
        ) -> FlextLdifProtocols.Models.AttributeValueProtocol:
            """Create mock attribute value implementing AttributeValueProtocol."""

            class MockAttributeValue(FlextLdifProtocols.Models.AttributeValueProtocol):
                def __init__(self, vals: list[str] | str) -> None:
                    self.values = vals

            return MockAttributeValue(values)

    # ════════════════════════════════════════════════════════════════════════
    # SERVICE INITIALIZATION TESTS
    # ════════════════════════════════════════════════════════════════════════

    def test_init_creates_service(self) -> None:
        """Test entries service can be instantiated."""
        service = FlextLdifEntries()
        assert service is not None

    def test_execute_returns_unknown_operation_error(self) -> None:
        """Test execute returns error for unknown operations."""
        service = FlextLdifEntries(entries=[], operation="invalid_operation")
        result = service.execute()
        assert result.is_failure
        assert result.error is not None
        assert "Unknown operation: invalid_operation" in result.error

    # ════════════════════════════════════════════════════════════════════════
    # DN EXTRACTION TESTS
    # ════════════════════════════════════════════════════════════════════════

    def test_get_entry_dn_from_entry_model(self) -> None:
        """Test get_entry_dn with Entry model using factory."""
        entry = self.Factories.create_test_entry()
        service = FlextLdifEntries()
        result = service.get_entry_dn(entry)
        tm.ok(result)
        assert result.value == c.DNs.TEST_USER

    @pytest.mark.parametrize(
        ("entry_input", "expected_dn", "should_succeed"),
        [
            (
                {"dn": c.DNs.TEST_USER, c.Names.CN: [c.Values.TEST]},
                c.DNs.TEST_USER,
                True,
            ),
            ({"cn": ["test"]}, None, False),
            ({}, None, False),
        ],
    )
    def test_get_entry_dn_from_dict(
        self,
        entry_input: dict[str, str | list[str]],
        expected_dn: str | None,
        should_succeed: bool,
    ) -> None:
        """Test get_entry_dn with dict entry using parametrization."""
        service = FlextLdifEntries()
        result = service.get_entry_dn(entry_input)
        if should_succeed:
            assert expected_dn is not None
            tm.ok(result)
            assert result.value == expected_dn
        else:
            assert result.is_failure
            assert result.error is not None

    def test_get_entry_dn_from_entry_missing_dn(self) -> None:
        """Test get_entry_dn with Entry model missing DN."""
        entry = m.Ldif.Entry.model_construct(
            dn=None,
            attributes=m.Ldif.Attributes.model_construct(attributes={}),
        )
        service = FlextLdifEntries()
        result = service.get_entry_dn(entry)
        assert result.is_failure
        assert result.error is not None
        assert "missing DN" in result.error

    @pytest.mark.parametrize(
        ("has_value_attr", "dn_value"),
        [
            (True, c.DNs.TEST_USER),
            (False, c.DNs.TEST_USER),
        ],
    )
    def test_get_entry_dn_from_protocol(
        self,
        has_value_attr: bool,
        dn_value: str,
    ) -> None:
        """Test get_entry_dn with EntryWithDnProtocol with/without .value attribute."""
        if has_value_attr:
            entry = self.Factories.create_mock_entry_with_dn_value(dn_value)
        else:
            entry = self.Factories.create_mock_entry_with_dn(dn_value)
        service = FlextLdifEntries()
        result = service.get_entry_dn(entry)
        tm.ok(result)
        assert result.value == dn_value

    # ════════════════════════════════════════════════════════════════════════
    # ENTRY CREATION TESTS
    # ════════════════════════════════════════════════════════════════════════

    def test_create_entry_basic(self) -> None:
        """Test create_entry with basic attributes using constants."""
        service = FlextLdifEntries()
        result = service.create_entry(
            dn=c.DNs.TEST_USER,
            attributes={
                c.Names.CN: c.Values.TEST,
                c.Names.SN: c.Values.TEST,
            },
        )
        tm.ok(result)
        entry = result.value
        assert entry.dn is not None
        assert entry.attributes is not None
        assert entry.dn.value == c.DNs.TEST_USER
        assert c.Names.CN in entry.attributes.attributes
        assert c.Names.SN in entry.attributes.attributes

    def test_create_entry_with_objectclasses(self) -> None:
        """Test create_entry with objectclasses parameter using constants."""
        service = FlextLdifEntries()
        result = service.create_entry(
            dn=c.DNs.TEST_USER,
            attributes={
                c.Names.CN: [c.Values.TEST],
            },
            objectclasses=[c.Names.PERSON, c.Names.TOP],
        )
        tm.ok(result)
        entry = result.value
        assert entry.attributes is not None
        assert c.Names.OBJECTCLASS in entry.attributes.attributes
        objectclasses = entry.attributes.attributes[c.Names.OBJECTCLASS]
        assert isinstance(objectclasses, list)
        assert c.Names.PERSON in objectclasses
        assert c.Names.TOP in objectclasses

    # ════════════════════════════════════════════════════════════════════════
    # ATTRIBUTE EXTRACTION TESTS
    # ════════════════════════════════════════════════════════════════════════

    def test_get_entry_attributes_from_entry_model(self) -> None:
        """Test get_entry_attributes with Entry model using factory."""
        service = FlextLdifEntries()
        entry = self.Factories.create_test_entry(
            dn=None,
            **{
                c.Names.OBJECTCLASS: [c.Names.PERSON],
                c.Names.CN: c.Values.TEST,
                c.Names.SN: c.Values.TEST,
            },
        )
        result = service.get_entry_attributes(entry)
        tm.ok(result)
        attrs = result.value
        assert c.Names.CN in attrs
        assert c.Names.SN in attrs
        assert c.Names.OBJECTCLASS in attrs

    def test_get_entry_objectclasses_from_entry_model(self) -> None:
        """Test get_entry_objectclasses with Entry model using factory."""
        service = FlextLdifEntries()
        entry = self.Factories.create_test_entry(
            dn=None,
            **{
                c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.TOP],
                c.Names.CN: c.Values.TEST,
            },
        )
        result = service.get_entry_objectclasses(entry)
        tm.ok(result)
        objectclasses = result.value
        assert c.Names.PERSON in objectclasses
        assert c.Names.TOP in objectclasses

    @pytest.mark.parametrize(
        ("attr_input", "expected_values"),
        [
            (c.Values.TEST, [c.Values.TEST]),
            (
                [c.Values.USER1, c.Values.USER2],
                [c.Values.USER1, c.Values.USER2],
            ),
        ],
    )
    def test_get_attribute_values_from_string_and_list(
        self,
        attr_input: str | list[str],
        expected_values: list[str],
    ) -> None:
        """Test get_attribute_values with string and list using parametrization."""
        service = FlextLdifEntries()
        result = service.get_attribute_values(attr_input)
        tm.ok(result)
        assert result.value == expected_values

    # ════════════════════════════════════════════════════════════════════════
    # DN CLEANING TESTS
    # ════════════════════════════════════════════════════════════════════════

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
        cleaned = FlextLdifUtilities.Ldif.DN.clean_dn(input_dn)
        tm.that(cleaned, is_=str, empty=False)
        if expected_present:
            tm.that(cleaned, contains=expected_present)
        if expected_absent:
            assert expected_absent not in cleaned, (
                f"DN should not contain '{expected_absent}': {cleaned}"
            )

    # ════════════════════════════════════════════════════════════════════════
    # ATTRIBUTE REMOVAL TESTS
    # ════════════════════════════════════════════════════════════════════════

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
        simple_entry = self.Factories.create_simple_entry()
        entry_with_operational_attrs = (
            self.Factories.create_entry_with_operational_attrs()
        )
        entries_batch = self.Factories.create_entries_batch()

        fixtures: dict[str, p.Entry | list[p.Entry]] = {
            "simple_entry": simple_entry,
            "entry_with_operational_attrs": entry_with_operational_attrs,
            "entries_batch": entries_batch,
        }
        fixture_data = fixtures[fixture_name]

        if is_selective and fixture_name == "simple_entry":
            assert isinstance(fixture_data, m.Ldif.Entry)
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
            # After removing operational attributes, entries should NOT have them
            for entry in result_list:
                if attrs_to_check:
                    tm.entry(entry, not_has_attr=attrs_to_check)
        else:
            assert isinstance(fixture_data, m.Ldif.Entry)
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

    # ════════════════════════════════════════════════════════════════════════
    # EXECUTE PATTERN AND BUILDER TESTS
    # ════════════════════════════════════════════════════════════════════════

    def test_execute_pattern_operations(self) -> None:
        """Test execute() method with various operations."""
        entries_batch = self.Factories.create_entries_batch()
        simple_entry = self.Factories.create_simple_entry()

        service1 = FlextLdifEntries(
            entries=entries_batch,
            operation="remove_operational_attributes",
        )
        tm.ok_entries(service1.execute(), count=3)

        service2 = FlextLdifEntries(
            entries=[simple_entry],
            operation="remove_attributes",
            attributes_to_remove=[c.Names.MAIL],
        )
        result2 = tm.ok_entries(service2.execute(), count=1)
        tm.entry(result2[0], not_has_attr=c.Names.MAIL)

        service4 = FlextLdifEntries(
            entries=[],
            operation="remove_operational_attributes",
        )
        tm.ok_entries(service4.execute(), empty=True)

    def test_builder_pattern(self) -> None:
        """Test fluent builder pattern."""
        simple_entry = self.Factories.create_simple_entry()

        result1_list = (
            FlextLdifEntries
            .builder()
            .with_entries([simple_entry])
            .with_operation("remove_operational_attributes")
            .build()
        )
        result1 = tm.entries(result1_list, count=1)
        tm.entry(result1[0], has_attr=c.Names.CN)

        result2 = (
            FlextLdifEntries
            .builder()
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

    # ════════════════════════════════════════════════════════════════════════
    # EDGE CASE TESTS
    # ════════════════════════════════════════════════════════════════════════

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
                    f"attr{i}" in cleaned.attributes.attributes for i in range(50, 100)
                )

    # ════════════════════════════════════════════════════════════════════════
    # VALIDATION TESTS
    # ════════════════════════════════════════════════════════════════════════

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
            # RFC 4512 allows hyphens, so use @ and space which are truly invalid
            invalid_attr_names = ["2invalid", "invalid@name", "invalid name"]
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
            ]).value
            assert validated[c.Names.CN] is True
            assert validated["2invalid"] is False

    # ════════════════════════════════════════════════════════════════════════
    # SYNTAX TESTS
    # ════════════════════════════════════════════════════════════════════════

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
            # NAME_TO_OID uses lowercase snake_case from OID_TO_NAME mapping
            result = syntax.lookup_name(self.Constants.BOOLEAN_NAME)
            tm.ok(
                result,
                eq=self.Constants.BOOLEAN_OID,
            )

        elif test_type == "lookup_oid":
            result_obj = syntax.lookup_oid(self.Constants.BOOLEAN_OID)
            result = tm.ok(result_obj, is_=str)
            tm.that(
                result.lower(),
                eq=self.Constants.BOOLEAN_NAME.lower(),
            )

        elif test_type == "resolve_syntax":
            result_obj = syntax.resolve_syntax("1.3.6.1.4.1.1466.115.121.1.7")
            syntax_obj = tm.ok(result_obj)
            tm.that(
                syntax_obj.oid,
                eq=self.Constants.BOOLEAN_OID,
            )

        elif test_type == "validate_value":
            tm.ok(
                syntax.validate_value(
                    "TRUE",
                    self.Constants.BOOLEAN_OID,
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

    # ════════════════════════════════════════════════════════════════════════
    # REAL LDIF DATA TESTS
    # ════════════════════════════════════════════════════════════════════════

    def test_clean_dn_with_real_oid_entries(
        self,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test DN cleaning with real OID LDIF entries."""
        assert len(oid_entries) > 0, "OID fixture should have entries"

        first_entry = oid_entries[0]
        assert first_entry.dn is not None
        cleaned_dn = FlextLdifUtilities.Ldif.DN.clean_dn(first_entry.dn.value)

        assert " = " not in cleaned_dn
        assert "=" in cleaned_dn

    def test_remove_operational_attributes_from_real_oid_entry(
        self,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test removing operational attributes from real OID LDIF entry."""
        assert len(oid_entries) > 0

        entry = oid_entries[0]
        entries_service = FlextLdifEntries()
        result = entries_service.remove_operational_attributes(entry)

        assert result.is_success
        cleaned_entry = result.value

        assert cleaned_entry.attributes is not None
        assert len(cleaned_entry.attributes.attributes) > 0
        assert cleaned_entry.dn is not None
        assert entry.dn is not None
        assert cleaned_entry.dn.value == entry.dn.value

    def test_remove_operational_attributes_batch_real_oid(
        self,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test batch operational attribute removal with real OID LDIF entries."""
        assert len(oid_entries) > 0

        entries_service = FlextLdifEntries()
        result = entries_service.remove_operational_attributes_batch(oid_entries)

        assert result.is_success
        cleaned_entries = result.value

        assert len(cleaned_entries) == len(oid_entries)

        for entry in cleaned_entries:
            assert entry.dn is not None
            assert len(entry.dn.value) > 0
            assert entry.attributes is not None
            assert len(entry.attributes.attributes) > 0

    def test_execute_remove_operational_attributes_with_real_data(
        self,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test execute() pattern for operational attribute removal with real data."""
        assert len(oid_entries) > 0

        result = FlextLdifEntries(
            entries=oid_entries,
            operation="remove_operational_attributes",
        ).execute()

        assert result.is_success
        cleaned_entries = result.value
        assert len(cleaned_entries) == len(oid_entries)

    def test_builder_with_oid_entries(
        self,
        oid_entries: list[p.Entry],
    ) -> None:
        """Test fluent builder with real OID LDIF entries."""
        assert len(oid_entries) > 0

        result = (
            FlextLdifEntries
            .builder()
            .with_entries(oid_entries)
            .with_operation("remove_operational_attributes")
            .build()
        )

        assert len(result) == len(oid_entries)

    def test_unified_cleaning_all_servers(
        self,
        oid_entries: list[p.Entry],
        oud_entries: list[p.Entry],
        openldap2_entries: list[p.Entry],
    ) -> None:
        """Test that cleaning works uniformly across all server types."""
        servers_data = [
            ("OID", oid_entries),
            ("OUD", oud_entries),
            ("OpenLDAP2", openldap2_entries),
        ]

        for server_name, entries in servers_data:
            assert len(entries) > 0, f"{server_name} fixtures should have entries"

            entries_service = FlextLdifEntries()
            result = entries_service.remove_operational_attributes_batch(entries)

            assert result.is_success, f"Cleaning {server_name} entries should succeed"
            cleaned = result.value
            assert len(cleaned) == len(entries), (
                f"{server_name} entry count should match"
            )

    # ════════════════════════════════════════════════════════════════════════
    # ATTRIBUTE EXTRACTION TESTS (from test_entry_manipulation.py)
    # ════════════════════════════════════════════════════════════════════════

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
            """Test get_entry_attribute using advanced parametrization."""
            service = TestsFlextLdifEntries.Factories.create_service()

            if test_name == "no_attributes":
                dn = m.Ldif.DN(value=c.DNs.TEST_USER)
                attrs = m.Ldif.Attributes.create({}).value
                entry = m.Ldif.Entry(dn=dn, attributes=attrs)
            else:
                entry = TestsFlextLdifEntries.Factories.create_simple_user_entry()

            result = service.get_entry_attribute(entry, attr_name)

            if should_succeed:
                tm.ok(result)
                if expected_value is not None:
                    value = tm.ok(result)
                    tm.that(value, eq=expected_value)
            elif expected_error:
                tm.fail(result, has=expected_error)
            else:
                tm.fail(result)

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
            """Test normalize_attribute_value using advanced parametrization."""
            service = TestsFlextLdifEntries.Factories.create_service()
            typed_input: str | list[str] | None = cast(
                "str | list[str] | None",
                input_value,
            )
            result = service.normalize_attribute_value(typed_input)

            if should_succeed:
                tm.ok(result)
                if expected_normalized is not None:
                    normalized = tm.ok(result)
                    tm.that(
                        normalized.lower()
                        if isinstance(normalized, str)
                        else normalized,
                        eq=expected_normalized.lower()
                        if isinstance(expected_normalized, str)
                        else expected_normalized,
                    )
            elif expected_error:
                tm.fail(result, has=expected_error)
            else:
                tm.fail(result)

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
            """Test get_normalized_attribute using advanced parametrization."""
            service = TestsFlextLdifEntries.Factories.create_service()
            entry = TestsFlextLdifEntries.Factories.create_simple_user_entry()
            result = service.get_normalized_attribute(entry, attr_name)

            if should_succeed:
                tm.ok(result)
                if expected_value is not None:
                    value = tm.ok(result)
                    tm.that(
                        value.lower() if isinstance(value, str) else value,
                        eq=expected_value.lower()
                        if isinstance(expected_value, str)
                        else expected_value,
                    )
            else:
                tm.fail(result)


__all__ = ["RealLdifLoader", "TestsFlextLdifEntries"]
