from __future__ import annotations
from tests import c, m, s, t

from typing import Final

import pytest
from flext_tests import tm

from flext_ldif import FlextLdifProtocols
from flext_ldif.models import m
from flext_ldif.services.entries import FlextLdifEntries
# FlextLdifFixtures and TypedDicts are available from conftest.py (pytest auto-imports)
# TypedDicts (GenericFieldsDict, GenericTestCaseDict, etc.) are available from conftest.py
        ) -> m.Entry:
            """Create test entry using factory."""
            if dn is None:
                dn = c.DNs.TEST_USER
            attrs: dict[str, str | list[str]] = {
                c.Names.OBJECTCLASS: [c.Names.PERSON],
                c.Names.CN: [c.Values.TEST],
            }
            # Filter overrides to only include compatible types
            compatible_overrides: dict[str, str | list[str]] = {
                k: v for k, v in overrides.items() if isinstance(v, (str, list))
            }
            attrs.update(compatible_overrides)
            return self.create_entry(dn, attrs)

        @staticmethod
        def create_mock_entry_with_dn(
            dn_value: str,
            attributes: object = None,
        ) -> FlextLdifProtocols.Models.EntryWithDnProtocol:
            """Create mock entry implementing EntryWithDnProtocol.

            Note: We don't inherit from the protocol because it defines dn as @property.
            Protocols use structural subtyping (duck typing), so inheritance is not needed.
            """

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
            """Create mock entry with DN that has .value attribute.

            Note: We don't inherit from the protocol because it defines dn as @property.
            Protocols use structural subtyping (duck typing), so inheritance is not needed.
            """

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

    class TestsFlextLdifServiceInitialization(s):
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
            tm.ok(result)
            assert result.unwrap() == c.DNs.TEST_USER

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
                assert result.unwrap() == expected_dn
            else:
                assert result.is_failure
                assert result.error is not None

        def test_get_entry_dn_from_entry_missing_dn(self) -> None:
            """Test get_entry_dn with Entry model missing DN."""
            entry = m.Entry.model_construct(
                dn=None,
                attributes=m.LdifAttributes.model_construct(
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

            # Don't inherit from protocol - it defines dn as @property
            class MockEntry:
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
                entry = TestFlextLdifEntries.Factories.create_mock_entry_with_dn_value(
                    dn_value,
                )
            else:
                entry = TestFlextLdifEntries.Factories.create_mock_entry_with_dn(
                    dn_value,
                )
            service = FlextLdifEntries()
            result = service.get_entry_dn(entry)
            tm.ok(result)
            assert result.unwrap() == dn_value

    class TestCreateEntry:
        """Test create_entry method for entry creation with validation."""

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
            entry = result.unwrap()
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
                    c.Names.CN: c.Values.TEST,
                },
                objectclasses=[c.Names.PERSON, c.Names.TOP],
            )
            tm.ok(result)
            entry = result.unwrap()
            assert entry.attributes is not None
            assert c.Names.OBJECTCLASS in entry.attributes.attributes
            objectclasses = entry.attributes.attributes[c.Names.OBJECTCLASS]
            assert isinstance(objectclasses, list)
            assert c.Names.PERSON in objectclasses
            assert c.Names.TOP in objectclasses

        @pytest.mark.parametrize(
            ("attributes", "expected_cn_count", "expected_cn_first"),
            [
                (
                    {
                        c.Names.CN: [c.Values.USER1, c.Values.USER2],
                        c.Names.SN: c.Values.TEST,
                    },
                    2,
                    None,
                ),
                (
                    {
                        c.Names.CN: c.Values.TEST,
                        c.Names.SN: c.Values.TEST,
                    },
                    1,
                    c.Values.TEST,
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
                dn=c.DNs.TEST_USER,
                attributes=attributes,
            )
            tm.ok(result)
            entry = result.unwrap()
            assert entry.attributes is not None
            cn_values = entry.attributes.attributes[c.Names.CN]
            assert isinstance(cn_values, list)
            tm.assert_length_equals(cn_values, expected_cn_count)
            if expected_cn_first:
                assert cn_values[0] == expected_cn_first

        @pytest.mark.parametrize(
            ("dn", "should_succeed"),
            [
                ("", False),
                (c.DNs.TEST_USER, True),
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
                    c.Names.CN: c.Values.TEST,
                },
            )
            if should_succeed:
                tm.ok(result)
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
                    c.Names.OBJECTCLASS: [c.Names.PERSON],
                    c.Names.CN: c.Values.TEST,
                    c.Names.SN: c.Values.TEST,
                },
            )
            result = service.get_entry_attributes(entry)
            tm.ok(result)
            attrs = result.unwrap()
            assert c.Names.CN in attrs
            assert c.Names.SN in attrs
            assert c.Names.OBJECTCLASS in attrs

        def test_get_entry_attributes_missing_attributes(self) -> None:
            """Test get_entry_attributes with entry missing attributes."""

            class EntryWithoutAttributesAttr:
                """Mock entry without attributes for testing error handling."""

                def __init__(self) -> None:
                    self.dn: object = c.DNs.TEST_USER
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

            # Don't inherit from protocol - it defines dn as @property
            class EntryWithNoneAttributes:
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
                        c.Names.CN: [c.Values.TEST],
                        c.Names.SN: c.Values.TEST,
                    },
                    [c.Names.CN, c.Names.SN],
                ),
                (
                    {
                        c.Names.CN: [123, 456],
                        c.Names.SN: 789,
                    },
                    [c.Names.CN, c.Names.SN],
                ),
            ],
        )
        def test_get_entry_attributes_from_dict_like(
            self,
            attributes: GenericFieldsDict,
            expected_attrs: list[str],
        ) -> None:
            """Test get_entry_attributes with dict-like attributes."""

            # Don't inherit from protocol - it defines dn as @property
            class EntryWithDictAttributes:
                def __init__(self, attrs: GenericFieldsDict) -> None:
                    self.dn: object = c.DNs.TEST_USER
                    self.attributes: object = attrs

            service = FlextLdifEntries()
            entry = EntryWithDictAttributes(attributes)
            result = service.get_entry_attributes(entry)
            tm.ok(result)
            attrs = result.unwrap()
            for attr in expected_attrs:
                assert attr in attrs

        def test_get_entry_attributes_from_unknown_container_type(
            self,
        ) -> None:
            """Test get_entry_attributes with unknown attributes container type."""

            # Don't inherit from protocol - it defines dn as @property
            class EntryWithUnknownAttributes:
                def __init__(self) -> None:
                    self.dn = c.DNs.TEST_USER
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

            # Don't inherit from protocol - it defines dn as @property
            class EntryThatRaises:
                def __init__(self) -> None:
                    self.dn: object = c.DNs.TEST_USER
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
                    c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.TOP],
                    c.Names.CN: c.Values.TEST,
                },
            )
            result = service.get_entry_objectclasses(entry)
            tm.ok(result)
            objectclasses = result.unwrap()
            assert c.Names.PERSON in objectclasses
            assert c.Names.TOP in objectclasses

        def test_get_entry_objectclasses_missing_objectclass(self) -> None:
            """Test get_entry_objectclasses with entry missing objectClass."""
            service = FlextLdifEntries()
            entry = m.Entry.model_construct(
                dn=m.DistinguishedName(value=c.DNs.TEST_USER),
                attributes=m.LdifAttributes(
                    attributes={
                        c.Names.CN: [c.Values.TEST],
                    },
                ),
            )
            result = service.get_entry_objectclasses(entry)
            assert result.is_failure
            assert result.error is not None
            assert "missing objectClass" in result.error

        def test_get_entry_objectclasses_with_lowercase_key(self) -> None:
            """Test get_entry_objectclasses with lowercase objectclass key."""

            # Don't inherit from protocol - it defines dn as @property
            class EntryWithLowercaseObjectclass:
                def __init__(self) -> None:
                    self.dn = c.DNs.TEST_USER
                    self.attributes = {"objectclass": ["person", "top"]}

            service = FlextLdifEntries()
            entry = EntryWithLowercaseObjectclass()
            result = service.get_entry_objectclasses(entry)
            tm.ok(result)
            objectclasses = result.unwrap()
            assert "person" in objectclasses
            assert "top" in objectclasses

        def test_get_entry_objectclasses_with_string_value(self) -> None:
            """Test get_entry_objectclasses with string objectClass value."""
            service = FlextLdifEntries()
            entry = TestFlextLdifEntries.Factories.create_test_entry(
                **{
                    c.Names.OBJECTCLASS: c.Names.PERSON,
                    c.Names.CN: c.Values.TEST,
                },
            )
            result = service.get_entry_objectclasses(entry)
            tm.ok(result)
            objectclasses = result.unwrap()
            assert c.Names.PERSON in objectclasses

        def test_get_entry_objectclasses_when_get_entry_attributes_fails(
            self,
        ) -> None:
            """Test get_entry_objectclasses when get_entry_attributes fails."""

            # Don't inherit from protocol - it defines dn as @property
            class EntryWithoutAttributesAttr:
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

            # Don't inherit from protocol - it defines dn as @property
            class EntryThatRaises:
                def __init__(self) -> None:
                    self.dn: object = c.DNs.TEST_USER
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
            assert result.unwrap() == expected_values

        @pytest.mark.parametrize(
            ("values", "expected_values"),
            [
                ([c.Values.USER1, c.Values.USER2], [c.Values.USER1, c.Values.USER2]),
                (c.Values.TEST, [c.Values.TEST]),
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
            tm.ok(result)
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
