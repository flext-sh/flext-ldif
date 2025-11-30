"""Test suite for Entry Manipulation Services - Entry attribute manipulation.

Modules tested:
- flext_ldif.services.entry_manipulation.EntryManipulationServices (entry manipulation service)

Scope:
- Attribute extraction (get_entry_attribute, normalize_attribute_value,
  get_normalized_attribute)

Test Coverage:
- All entry manipulation service methods
- Edge cases (empty attributes, missing attributes, invalid values, conflicts)
- Real implementations (no mocks)

Uses Python 3.13 features, factories, constants, dynamic tests, and extensive helper reuse
to reduce code while maintaining 100% behavior coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifModels
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services.entry_manipulation import EntryManipulationServices


class TestEntryManipulationServices:
    """Test EntryManipulationServices with consolidated parametrized tests.

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
            attributes: dict[str, list[str]],
        ) -> FlextLdifModels.Entry:
            """Create test entry with DN and attributes."""
            dn = FlextLdifModels.DistinguishedName(value=dn_str)
            attrs = FlextLdifModels.LdifAttributes.create(attributes).unwrap()
            return FlextLdifModels.Entry(dn=dn, attributes=attrs)

        @staticmethod
        def create_simple_user_entry() -> FlextLdifModels.Entry:
            """Create a simple user entry."""
            return TestEntryManipulationServices.Factories.create_entry(
                "cn=john,ou=users,dc=example,dc=com",
                {
                    "cn": ["john"],
                    "sn": ["Doe"],
                    "givenName": ["John"],
                    "mail": ["john@example.com"],
                    "uid": ["jdoe"],
                    FlextLdifConstants.DictKeys.OBJECTCLASS: [
                        "person",
                        "inetOrgPerson",
                    ],
                },
            )

        @staticmethod
        def create_service() -> EntryManipulationServices:
            """Create EntryManipulationServices instance."""
            return EntryManipulationServices()

    class TestAttributeExtraction:
        """Test attribute extraction methods."""

        def test_get_entry_attribute_success(self) -> None:
            """Test getting existing attribute."""
            service = TestEntryManipulationServices.Factories.create_service()
            entry = TestEntryManipulationServices.Factories.create_simple_user_entry()
            result = service.get_entry_attribute(entry, "cn")
            assert result.is_success
            value = result.unwrap()
            assert value == ["john"]

        def test_get_entry_attribute_not_found(self) -> None:
            """Test getting non-existent attribute."""
            service = TestEntryManipulationServices.Factories.create_service()
            entry = TestEntryManipulationServices.Factories.create_simple_user_entry()
            result = service.get_entry_attribute(entry, "nonexistent")
            assert result.is_failure
            error_msg = result.error or ""
            assert "not found" in error_msg.lower()

        def test_get_entry_attribute_no_attributes(self) -> None:
            """Test getting attribute from entry with no attributes."""
            service = TestEntryManipulationServices.Factories.create_service()
            entry = TestEntryManipulationServices.Factories.create_entry(
                "cn=test,dc=example,dc=com",
                {},
            )
            result = service.get_entry_attribute(entry, "cn")
            assert result.is_failure

        def test_normalize_attribute_value_list(self) -> None:
            """Test normalizing list attribute value."""
            service = TestEntryManipulationServices.Factories.create_service()
            result = service.normalize_attribute_value(["value1"])
            assert result.is_success
            assert result.unwrap() == "value1"

        def test_normalize_attribute_value_string(self) -> None:
            """Test normalizing string attribute value."""
            service = TestEntryManipulationServices.Factories.create_service()
            result = service.normalize_attribute_value("  test  ")
            assert result.is_success
            assert result.unwrap() == "test"

        def test_normalize_attribute_value_none(self) -> None:
            """Test normalizing None value."""
            service = TestEntryManipulationServices.Factories.create_service()
            result = service.normalize_attribute_value(None)
            assert result.is_failure
            error_msg = result.error
            assert error_msg is not None
            assert "None" in error_msg

        def test_normalize_attribute_value_empty_string(self) -> None:
            """Test normalizing empty string."""
            service = TestEntryManipulationServices.Factories.create_service()
            result = service.normalize_attribute_value("   ")
            assert result.is_failure
            error_msg = result.error or ""
            assert "empty" in error_msg.lower()

        def test_get_normalized_attribute_success(self) -> None:
            """Test getting and normalizing attribute."""
            service = TestEntryManipulationServices.Factories.create_service()
            entry = TestEntryManipulationServices.Factories.create_simple_user_entry()
            result = service.get_normalized_attribute(entry, "cn")
            assert result.is_success
            assert result.unwrap() == "john"

        def test_get_normalized_attribute_not_found(self) -> None:
            """Test getting non-existent normalized attribute."""
            service = TestEntryManipulationServices.Factories.create_service()
            entry = TestEntryManipulationServices.Factories.create_simple_user_entry()
            result = service.get_normalized_attribute(entry, "nonexistent")
            assert result.is_failure


__all__ = ["TestEntryManipulationServices"]
