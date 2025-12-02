"""Entries Service Tests - Comprehensive test coverage for FlextLdifEntries.

Modules Tested:
- flext_ldif.services.entries: Entry CRUD operations, DN extraction, attribute extraction,
  objectClass management, attribute value extraction from various protocols

Scope:
- Entry creation with validation
- DN extraction from multiple formats (Entry model, dict, EntryWithDnProtocol)
- Attribute extraction and normalization
- ObjectClass management
- Attribute value extraction from various protocols (string, list, AttributeValueProtocol)
- Error handling and edge cases
- Protocol compliance testing

Uses Python 3.13 features, factories, parametrization, and helpers for minimal code
with maximum coverage. All tests use real implementations, no mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

import pytest

# from flext_tests import FlextTestsMatchers  # Mocked in conftest
from flext_ldif import FlextLdifModels, FlextLdifProtocols
from flext_ldif.services.entries import FlextLdifEntries
from tests.fixtures.constants import DNs, Names, Values
from tests.fixtures.typing import GenericFieldsDict
from tests.helpers.test_factories import FlextLdifTestFactories


class TestFlextLdifEntries:
    """Comprehensive tests for FlextLdifEntries service.

    Single class with nested test groups following project patterns.
    Uses factories, parametrization, and helpers for DRY code.
    """

    class Constants:
        """Test constants organized in nested class."""

        # Test DNs
        DN_TEST_USER: Final[str] = DNs.TEST_USER
        DN_TEST_GROUP: Final[str] = DNs.TEST_GROUP

        # Attribute names
        ATTR_CN: Final[str] = Names.CN
        ATTR_SN: Final[str] = Names.SN
        ATTR_OBJECTCLASS: Final[str] = Names.OBJECTCLASS
        ATTR_MAIL: Final[str] = Names.MAIL

        # ObjectClass names
        OC_PERSON: Final[str] = Names.PERSON
        OC_TOP: Final[str] = Names.TOP
        OC_INET_ORG_PERSON: Final[str] = Names.INET_ORG_PERSON

        # Test values
        VALUE_TEST: Final[str] = Values.TEST
        VALUE_USER1: Final[str] = Values.USER1
        VALUE_USER2: Final[str] = Values.USER2

        # Error messages
        ERROR_MISSING_DN: Final[str] = "missing DN"
        ERROR_MISSING_ATTRIBUTES: Final[str] = "missing attributes"
        ERROR_MISSING_OBJECTCLASS: Final[str] = "missing objectClass"
        ERROR_UNSUPPORTED_TYPE: Final[str] = "Unsupported attribute type"
        ERROR_DOES_NOT_IMPLEMENT: Final[str] = "does not implement EntryWithDnProtocol"

    class Factories:
        """Entry factories for testing."""

        @staticmethod
        def create_test_entry(
            dn: str | None = None,
            **overrides: str | list[str] | object,
        ) -> FlextLdifModels.Entry:
            """Create test entry using factory."""
            if dn is None:
                dn = DNs.TEST_USER
            attrs: dict[str, str | list[str]] = {
                Names.OBJECTCLASS: [Names.PERSON],
                Names.CN: [Values.TEST],
            }
            # Filter overrides to only include compatible types
            compatible_overrides: dict[str, str | list[str]] = {
                k: v for k, v in overrides.items() if isinstance(v, (str, list))
            }
            attrs.update(compatible_overrides)
            return FlextLdifTestFactories.create_entry(dn, attrs)

        @staticmethod
        def create_mock_entry_with_dn(
            dn_value: str,
            attributes: object = None,
        ) -> FlextLdifProtocols.Models.EntryWithDnProtocol:
            """Create mock entry implementing EntryWithDnProtocol."""

            class MockEntry(FlextLdifProtocols.Models.EntryWithDnProtocol):
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

            class MockEntry(FlextLdifProtocols.Models.EntryWithDnProtocol):
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

    class TestServiceInitialization:
        """Test service initialization and basic functionality."""

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

    class TestGetEntryDn:
        """Test get_entry_dn method for DN extraction from various entry types."""

        def test_get_entry_dn_from_entry_model(self) -> None:
            """Test get_entry_dn with Entry model using factory."""
            entry = TestFlextLdifEntries.Factories.create_test_entry()
            service = FlextLdifEntries()
            result = service.get_entry_dn(entry)
            FlextTestsMatchers.assert_success(result)
            assert result.unwrap() == DNs.TEST_USER

        @pytest.mark.parametrize(
            ("entry_input", "expected_dn", "should_succeed"),
            [
                (
                    {"dn": "cn=test,dc=example,dc=com", "cn": ["test"]},
                    "cn=test,dc=example,dc=com",
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
                FlextTestsMatchers.assert_success(result)
                assert result.unwrap() == expected_dn
            else:
                assert result.is_failure
                assert result.error is not None

        def test_get_entry_dn_from_entry_missing_dn(self) -> None:
            """Test get_entry_dn with Entry model missing DN."""
            entry = FlextLdifModels.Entry.model_construct(
                dn=None,
                attributes=FlextLdifModels.LdifAttributes.model_construct(
                    attributes={},
                ),
            )
            service = FlextLdifEntries()
            result = service.get_entry_dn(entry)
            assert result.is_failure
            assert result.error is not None
            assert "missing DN" in result.error

        def test_get_entry_dn_from_non_protocol_type(self) -> None:
            """Test get_entry_dn with type that is not Entry or EntryWithDnProtocol."""

            class InvalidEntryType:
                pass

            invalid_entry_obj = InvalidEntryType()
            service = FlextLdifEntries()
            # Pass as object to test error handling without cast
            result = service.get_entry_dn(invalid_entry_obj)
            assert result.is_failure
            assert result.error is not None
            assert "does not implement EntryWithDnProtocol" in result.error

        def test_get_entry_dn_exception_handling(self) -> None:
            """Test get_entry_dn exception handling."""
            exception_msg = "Test exception"

            class ExceptionDn:
                def __str__(self) -> str:
                    raise ValueError(exception_msg)

            class MockEntry(FlextLdifProtocols.Models.EntryWithDnProtocol):
                def __init__(self) -> None:
                    self.dn: object = ExceptionDn()
                    self.attributes: object = {}

            service = FlextLdifEntries()
            result = service.get_entry_dn(MockEntry())
            assert result.is_failure
            assert result.error is not None
            assert "Failed to extract DN" in result.error

        @pytest.mark.parametrize(
            ("has_value_attr", "dn_value"),
            [
                (True, DNs.TEST_USER),
                (False, DNs.TEST_USER),
            ],
        )
        def test_get_entry_dn_from_protocol(
            self,
            has_value_attr: bool,
            dn_value: str,
        ) -> None:
            """Test get_entry_dn with EntryWithDnProtocol with/without .value attribute."""
            if has_value_attr:
                entry = TestFlextLdifEntries.Factories.create_mock_entry_with_dn_value(
                    dn_value,
                )
            else:
                entry = TestFlextLdifEntries.Factories.create_mock_entry_with_dn(
                    dn_value,
                )
            service = FlextLdifEntries()
            result = service.get_entry_dn(entry)
            FlextTestsMatchers.assert_success(result)
            assert result.unwrap() == dn_value

    class TestCreateEntry:
        """Test create_entry method for entry creation with validation."""

        def test_create_entry_basic(self) -> None:
            """Test create_entry with basic attributes using constants."""
            service = FlextLdifEntries()
            result = service.create_entry(
                dn=DNs.TEST_USER,
                attributes={
                    Names.CN: Values.TEST,
                    Names.SN: Values.TEST,
                },
            )
            FlextTestsMatchers.assert_success(result)
            entry = result.unwrap()
            assert entry.dn.value == DNs.TEST_USER
            assert Names.CN in entry.attributes.attributes
            assert Names.SN in entry.attributes.attributes

        def test_create_entry_with_objectclasses(self) -> None:
            """Test create_entry with objectclasses parameter using constants."""
            service = FlextLdifEntries()
            result = service.create_entry(
                dn=DNs.TEST_USER,
                attributes={
                    Names.CN: Values.TEST,
                },
                objectclasses=[Names.PERSON, Names.TOP],
            )
            FlextTestsMatchers.assert_success(result)
            entry = result.unwrap()
            assert Names.OBJECTCLASS in entry.attributes.attributes
            objectclasses = entry.attributes.attributes[Names.OBJECTCLASS]
            assert isinstance(objectclasses, list)
            assert Names.PERSON in objectclasses
            assert Names.TOP in objectclasses

        @pytest.mark.parametrize(
            ("attributes", "expected_cn_count", "expected_cn_first"),
            [
                (
                    {
                        Names.CN: [Values.USER1, Values.USER2],
                        Names.SN: Values.TEST,
                    },
                    2,
                    None,
                ),
                (
                    {
                        Names.CN: Values.TEST,
                        Names.SN: Values.TEST,
                    },
                    1,
                    Values.TEST,
                ),
            ],
        )
        def test_create_entry_with_list_and_string_values(
            self,
            attributes: dict[str, str | list[str]],
            expected_cn_count: int,
            expected_cn_first: str | None,
        ) -> None:
            """Test create_entry with list and string attribute values."""
            service = FlextLdifEntries()
            result = service.create_entry(
                dn=DNs.TEST_USER,
                attributes=attributes,
            )
            FlextTestsMatchers.assert_success(result)
            entry = result.unwrap()
            cn_values = entry.attributes.attributes[Names.CN]
            assert isinstance(cn_values, list)
            assert len(cn_values) == expected_cn_count
            if expected_cn_first:
                assert cn_values[0] == expected_cn_first

        @pytest.mark.parametrize(
            ("dn", "should_succeed"),
            [
                ("", False),
                (DNs.TEST_USER, True),
            ],
        )
        def test_create_entry_validation(
            self,
            dn: str,
            should_succeed: bool,
        ) -> None:
            """Test create_entry validation with parametrization."""
            service = FlextLdifEntries()
            result = service.create_entry(
                dn=dn,
                attributes={
                    Names.CN: Values.TEST,
                },
            )
            if should_succeed:
                FlextTestsMatchers.assert_success(result)
            else:
                assert result.is_failure
                if result.error:
                    assert (
                        "Failed to create entry" in result.error
                        or "Invalid DN" in result.error
                    )

    class TestGetEntryAttributes:
        """Test get_entry_attributes method for attribute extraction."""

        def test_get_entry_attributes_from_entry_model(self) -> None:
            """Test get_entry_attributes with Entry model using factory."""
            service = FlextLdifEntries()
            entry = TestFlextLdifEntries.Factories.create_test_entry(
                dn=None,
                **{
                    Names.OBJECTCLASS: [Names.PERSON],
                    Names.CN: Values.TEST,
                    Names.SN: Values.TEST,
                },
            )
            result = service.get_entry_attributes(entry)
            FlextTestsMatchers.assert_success(result)
            attrs = result.unwrap()
            assert Names.CN in attrs
            assert Names.SN in attrs
            assert Names.OBJECTCLASS in attrs

        def test_get_entry_attributes_missing_attributes(self) -> None:
            """Test get_entry_attributes with entry missing attributes."""

            class EntryWithoutAttributesAttr:
                """Mock entry without attributes for testing error handling."""

                def __init__(self) -> None:
                    self.dn: object = DNs.TEST_USER
                    # Don't set attributes to test missing attributes case

            service = FlextLdifEntries()
            entry = EntryWithoutAttributesAttr()
            # Entry doesn't have attributes attribute, so hasattr will return False
            result = service.get_entry_attributes(entry)
            assert result.is_failure
            assert result.error is not None
            assert (
                "missing attributes" in result.error
                or "Entry missing attributes" in result.error
            )

        def test_get_entry_attributes_with_none_entry(self) -> None:
            """Test get_entry_attributes with entry that has None attributes."""

            class EntryWithNoneAttributes(FlextLdifProtocols.Models.EntryWithDnProtocol):
                def __init__(self) -> None:
                    self.dn: object = TestFlextLdifEntries.Constants.DN_TEST_USER
                    self.attributes: object = None

            service = FlextLdifEntries()
            entry = EntryWithNoneAttributes()
            result = service.get_entry_attributes(entry)
            assert result.is_failure
            assert result.error is not None

        @pytest.mark.parametrize(
            ("attributes", "expected_attrs"),
            [
                (
                    {
                        Names.CN: [Values.TEST],
                        Names.SN: Values.TEST,
                    },
                    [Names.CN, Names.SN],
                ),
                (
                    {
                        Names.CN: [123, 456],
                        Names.SN: 789,
                    },
                    [Names.CN, Names.SN],
                ),
            ],
        )
        def test_get_entry_attributes_from_dict_like(
            self,
            attributes: GenericFieldsDict,
            expected_attrs: list[str],
        ) -> None:
            """Test get_entry_attributes with dict-like attributes."""

            class EntryWithDictAttributes(FlextLdifProtocols.Models.EntryWithDnProtocol):
                def __init__(self, attrs: GenericFieldsDict) -> None:
                    self.dn: object = DNs.TEST_USER
                    self.attributes: object = attrs

            service = FlextLdifEntries()
            entry = EntryWithDictAttributes(attributes)
            result = service.get_entry_attributes(entry)
            FlextTestsMatchers.assert_success(result)
            attrs = result.unwrap()
            for attr in expected_attrs:
                assert attr in attrs

        def test_get_entry_attributes_from_unknown_container_type(
            self,
        ) -> None:
            """Test get_entry_attributes with unknown attributes container type."""

            class EntryWithUnknownAttributes(
                FlextLdifProtocols.Models.EntryWithDnProtocol,
            ):
                def __init__(self) -> None:
                    self.dn = "cn=test,dc=example,dc=com"
                    self.attributes = 123

            service = FlextLdifEntries()
            entry = EntryWithUnknownAttributes()
            result = service.get_entry_attributes(entry)
            assert result.is_failure
            assert result.error is not None
            assert "Unknown attributes container type" in result.error

        def test_get_entry_attributes_exception_handling(self) -> None:
            """Test get_entry_attributes exception handling."""
            exception_msg = "Test exception"

            class ExceptionAttribute:
                def __init__(self, msg: str) -> None:
                    self.msg = msg

                def __getattribute__(self, name: str) -> object:
                    if name == "msg":
                        return super().__getattribute__(name)
                    raise ValueError(self.msg)

            class EntryThatRaises(FlextLdifProtocols.Models.EntryWithDnProtocol):
                def __init__(self) -> None:
                    self.dn: object = "cn=test,dc=example,dc=com"
                    self.attributes: object = ExceptionAttribute(exception_msg)

            service = FlextLdifEntries()
            entry = EntryThatRaises()
            result = service.get_entry_attributes(entry)
            assert result.is_failure
            assert result.error is not None
            assert "Failed to extract attributes" in result.error

    class TestGetEntryObjectclasses:
        """Test get_entry_objectclasses method for objectClass extraction."""

        def test_get_entry_objectclasses_from_entry_model(self) -> None:
            """Test get_entry_objectclasses with Entry model using factory."""
            service = FlextLdifEntries()
            entry = TestFlextLdifEntries.Factories.create_test_entry(
                dn=None,
                **{
                    Names.OBJECTCLASS: [Names.PERSON, Names.TOP],
                    Names.CN: Values.TEST,
                },
            )
            result = service.get_entry_objectclasses(entry)
            FlextTestsMatchers.assert_success(result)
            objectclasses = result.unwrap()
            assert Names.PERSON in objectclasses
            assert Names.TOP in objectclasses

        def test_get_entry_objectclasses_missing_objectclass(self) -> None:
            """Test get_entry_objectclasses with entry missing objectClass."""
            service = FlextLdifEntries()
            entry = FlextLdifModels.Entry.model_construct(
                dn=FlextLdifModels.DistinguishedName(value=DNs.TEST_USER),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        Names.CN: [Values.TEST],
                    },
                ),
            )
            result = service.get_entry_objectclasses(entry)
            assert result.is_failure
            assert result.error is not None
            assert "missing objectClass" in result.error

        def test_get_entry_objectclasses_with_lowercase_key(self) -> None:
            """Test get_entry_objectclasses with lowercase objectclass key."""

            class EntryWithLowercaseObjectclass(
                FlextLdifProtocols.Models.EntryWithDnProtocol,
            ):
                def __init__(self) -> None:
                    self.dn = "cn=test,dc=example,dc=com"
                    self.attributes = {"objectclass": ["person", "top"]}

            service = FlextLdifEntries()
            entry = EntryWithLowercaseObjectclass()
            result = service.get_entry_objectclasses(entry)
            FlextTestsMatchers.assert_success(result)
            objectclasses = result.unwrap()
            assert "person" in objectclasses
            assert "top" in objectclasses

        def test_get_entry_objectclasses_with_string_value(self) -> None:
            """Test get_entry_objectclasses with string objectClass value."""
            service = FlextLdifEntries()
            entry = TestFlextLdifEntries.Factories.create_test_entry(
                **{
                    Names.OBJECTCLASS: Names.PERSON,
                    Names.CN: Values.TEST,
                },
            )
            result = service.get_entry_objectclasses(entry)
            FlextTestsMatchers.assert_success(result)
            objectclasses = result.unwrap()
            assert Names.PERSON in objectclasses

        def test_get_entry_objectclasses_when_get_entry_attributes_fails(
            self,
        ) -> None:
            """Test get_entry_objectclasses when get_entry_attributes fails."""

            class EntryWithoutAttributesAttr(
                FlextLdifProtocols.Models.EntryWithDnProtocol,
            ):
                def __init__(self) -> None:
                    self.dn: object = TestFlextLdifEntries.Constants.DN_TEST_USER
                    self.attributes: object = None

            service = FlextLdifEntries()
            entry = EntryWithoutAttributesAttr()
            result = service.get_entry_objectclasses(entry)
            assert result.is_failure
            assert result.error is not None
            assert "Failed to get entry attributes" in result.error

        def test_get_entry_objectclasses_exception_handling(self) -> None:
            """Test get_entry_objectclasses exception handling."""
            exception_msg = "Test exception"

            class ExceptionAttribute:
                def __init__(self, msg: str) -> None:
                    self.msg = msg

                def __getattribute__(self, name: str) -> object:
                    if name == "msg":
                        return super().__getattribute__(name)
                    raise ValueError(self.msg)

            class EntryThatRaises(FlextLdifProtocols.Models.EntryWithDnProtocol):
                def __init__(self) -> None:
                    self.dn: object = "cn=test,dc=example,dc=com"
                    self.attributes: object = ExceptionAttribute(exception_msg)

            service = FlextLdifEntries()
            entry = EntryThatRaises()
            result = service.get_entry_objectclasses(entry)
            assert result.is_failure
            assert result.error is not None
            assert (
                "Failed to get entry attributes" in result.error
                or "Failed to extract objectClasses" in result.error
            )

    class TestGetAttributeValues:
        """Test get_attribute_values method for attribute value extraction."""

        @pytest.mark.parametrize(
            ("attr_input", "expected_values"),
            [
                (Values.TEST, [Values.TEST]),
                (
                    [Values.USER1, Values.USER2],
                    [Values.USER1, Values.USER2],
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
            FlextTestsMatchers.assert_success(result)
            assert result.unwrap() == expected_values

        @pytest.mark.parametrize(
            ("values", "expected_values"),
            [
                ([Values.USER1, Values.USER2], [Values.USER1, Values.USER2]),
                (Values.TEST, [Values.TEST]),
            ],
        )
        def test_get_attribute_values_from_protocol(
            self,
            values: list[str] | str,
            expected_values: list[str],
        ) -> None:
            """Test get_attribute_values with AttributeValueProtocol."""
            service = FlextLdifEntries()
            attr_value = TestFlextLdifEntries.Factories.create_mock_attribute_value(
                values,
            )
            result = service.get_attribute_values(attr_value)
            FlextTestsMatchers.assert_success(result)
            assert result.unwrap() == expected_values

        def test_get_attribute_values_from_invalid_type(self) -> None:
            """Test get_attribute_values with invalid type."""

            class InvalidAttribute:
                def __init__(self) -> None:
                    pass

            service = FlextLdifEntries()
            invalid_attr_obj = InvalidAttribute()
            # Pass as object to test error handling without cast
            result = service.get_attribute_values(invalid_attr_obj)
            assert result.is_failure
            assert result.error is not None
            assert "Unsupported attribute type" in result.error


__all__ = ["TestFlextLdifEntries"]
