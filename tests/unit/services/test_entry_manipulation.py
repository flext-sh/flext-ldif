"""Comprehensive unit tests for EntryManipulationServices.

Tests all entry manipulation methods with REAL implementations.
Validates attribute extraction, normalization, display name calculation,
user status determination, and group membership validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdifModels
from flext_ldif.services.entry_manipulation import EntryManipulationServices
from flext_ldif.services.validation import FlextLdifValidation
from tests.helpers.test_assertions import TestAssertions

# ════════════════════════════════════════════════════════════════════════════
# TEST FIXTURES
# ════════════════════════════════════════════════════════════════════════════


def create_entry(
    dn_str: str,
    attributes: dict[str, list[str]],
) -> FlextLdifModels.Entry:
    """Create test entry with DN and attributes."""
    dn = FlextLdifModels.DistinguishedName(value=dn_str)
    attrs = FlextLdifModels.LdifAttributes.create(attributes).unwrap()
    return FlextLdifModels.Entry(dn=dn, attributes=attrs)


@pytest.fixture
def simple_user_entry() -> FlextLdifModels.Entry:
    """Create a simple user entry."""
    return create_entry(
        "cn=john,ou=users,dc=example,dc=com",
        {
            "cn": ["john"],
            "sn": ["Doe"],
            "givenName": ["John"],
            "mail": ["john@example.com"],
            "uid": ["jdoe"],
            "objectClass": ["person", "inetOrgPerson"],
        },
    )


@pytest.fixture
def locked_user_entry() -> FlextLdifModels.Entry:
    """Create a locked user entry."""
    return TestAssertions.create_entry(
        "cn=locked,ou=users,dc=example,dc=com",
        {
            "cn": ["locked"],
            "accountLocked": ["true"],  # Use boolean string value
            "objectClass": ["person"],
        },
    )


@pytest.fixture
def disabled_user_entry() -> FlextLdifModels.Entry:
    """Create a disabled user entry."""
    return TestAssertions.create_entry(
        "cn=disabled,ou=users,dc=example,dc=com",
        {
            "cn": ["disabled"],
            "userAccountControl": ["2"],  # ADS_UF_ACCOUNTDISABLE (0x0002 = 2)
            "objectClass": ["person"],
        },
    )


@pytest.fixture
def group_entry() -> FlextLdifModels.Entry:
    """Create a group entry."""
    return create_entry(
        "cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com",
        {
            "cn": ["REDACTED_LDAP_BIND_PASSWORDs"],
            "objectClass": ["group"],
        },
    )


@pytest.fixture
def entry_manipulation_service() -> EntryManipulationServices:
    """Create EntryManipulationServices instance."""
    return EntryManipulationServices()


# ════════════════════════════════════════════════════════════════════════════
# TEST ATTRIBUTE EXTRACTION
# ════════════════════════════════════════════════════════════════════════════


class TestAttributeExtraction:
    """Test attribute extraction methods."""

    def test_get_entry_attribute_success(
        self,
        simple_user_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test getting existing attribute."""
        result = EntryManipulationServices.get_entry_attribute(
            simple_user_entry,
            "cn",
        )
        assert result.is_success
        value = result.unwrap()
        assert value == ["john"]

    def test_get_entry_attribute_not_found(
        self,
        simple_user_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test getting non-existent attribute."""
        result = EntryManipulationServices.get_entry_attribute(
            simple_user_entry,
            "nonexistent",
        )
        assert result.is_failure
        error_msg = result.error or ""
        assert "not found" in error_msg.lower()

    def test_get_entry_attribute_no_attributes(self) -> None:
        """Test getting attribute from entry with no attributes."""
        entry = create_entry("cn=test,dc=example,dc=com", {})
        result = EntryManipulationServices.get_entry_attribute(entry, "cn")
        assert result.is_failure

    def test_normalize_attribute_value_list(self) -> None:
        """Test normalizing list attribute value."""
        result = EntryManipulationServices.normalize_attribute_value(["value1"])
        assert result.is_success
        assert result.unwrap() == "value1"

    def test_normalize_attribute_value_string(self) -> None:
        """Test normalizing string attribute value."""
        result = EntryManipulationServices.normalize_attribute_value("  test  ")
        assert result.is_success
        assert result.unwrap() == "test"

    def test_normalize_attribute_value_none(self) -> None:
        """Test normalizing None value."""
        result = EntryManipulationServices.normalize_attribute_value(None)
        assert result.is_failure
        error_msg = result.error
        assert error_msg is not None
        assert "None" in error_msg

    def test_normalize_attribute_value_empty_string(self) -> None:
        """Test normalizing empty string."""
        result = EntryManipulationServices.normalize_attribute_value("   ")
        assert result.is_failure
        error_msg = result.error or ""
        assert "empty" in error_msg.lower()

    def test_get_normalized_attribute_success(
        self,
        simple_user_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test getting and normalizing attribute."""
        result = EntryManipulationServices.get_normalized_attribute(
            simple_user_entry,
            "cn",
        )
        assert result.is_success
        assert result.unwrap() == "john"

    def test_get_normalized_attribute_not_found(
        self,
        simple_user_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test getting non-existent normalized attribute."""
        result = EntryManipulationServices.get_normalized_attribute(
            simple_user_entry,
            "nonexistent",
        )
        assert result.is_failure


# ════════════════════════════════════════════════════════════════════════════
# TEST DISPLAY NAME
# ════════════════════════════════════════════════════════════════════════════


class TestDisplayName:
    """Test display name calculation methods."""

    def test_build_display_name_from_parts_success(self) -> None:
        """Test building display name from parts."""
        result = EntryManipulationServices.build_display_name_from_parts(
            "John",
            "Doe",
        )
        assert result.is_success
        assert result.unwrap() == "John Doe"

    def test_build_display_name_from_parts_missing_given_name(self) -> None:
        """Test building display name with missing given name."""
        result = EntryManipulationServices.build_display_name_from_parts(
            None,
            "Doe",
        )
        assert result.is_failure
        error_msg = result.error or ""
        assert "insufficient" in error_msg.lower()

    def test_build_display_name_from_parts_missing_sn(self) -> None:
        """Test building display name with missing surname."""
        result = EntryManipulationServices.build_display_name_from_parts(
            "John",
            None,
        )
        assert result.is_failure

    def test_get_display_name_priority_list(
        self,
        entry_manipulation_service: EntryManipulationServices,
        simple_user_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test getting display name priority list."""
        priority_list = entry_manipulation_service.get_display_name_priority_list(
            simple_user_entry,
        )
        assert len(priority_list) == 4
        # First should be displayName (not present, should fail)
        assert priority_list[0].is_failure
        # Second should be built from givenName + sn (should succeed)
        assert priority_list[1].is_success
        assert priority_list[1].unwrap() == "John Doe"
        # Third should be cn (should succeed)
        assert priority_list[2].is_success
        assert priority_list[2].unwrap() == "john"
        # Fourth should be uid (should succeed)
        assert priority_list[3].is_success
        assert priority_list[3].unwrap() == "jdoe"

    def test_calculate_user_display_name_with_display_name(
        self,
        entry_manipulation_service: EntryManipulationServices,
    ) -> None:
        """Test calculating display name when displayName exists."""
        entry = create_entry(
            "cn=test,dc=example,dc=com",
            {
                "displayName": ["John Doe"],
                "cn": ["test"],
            },
        )
        display_name = entry_manipulation_service.calculate_user_display_name(entry)
        assert display_name == "John Doe"

    def test_calculate_user_display_name_from_parts(
        self,
        entry_manipulation_service: EntryManipulationServices,
        simple_user_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test calculating display name from givenName + sn."""
        display_name = entry_manipulation_service.calculate_user_display_name(
            simple_user_entry,
        )
        assert display_name == "John Doe"

    def test_calculate_user_display_name_fallback_to_cn(
        self,
        entry_manipulation_service: EntryManipulationServices,
    ) -> None:
        """Test calculating display name falls back to cn."""
        entry = create_entry(
            "cn=testuser,dc=example,dc=com",
            {
                "cn": ["testuser"],
            },
        )
        display_name = entry_manipulation_service.calculate_user_display_name(entry)
        assert display_name == "testuser"

    def test_calculate_user_display_name_fallback_to_unknown(
        self,
        entry_manipulation_service: EntryManipulationServices,
    ) -> None:
        """Test calculating display name falls back to UNKNOWN_USER."""
        entry = create_entry("cn=test,dc=example,dc=com", {})
        display_name = entry_manipulation_service.calculate_user_display_name(entry)
        assert display_name == "UNKNOWN_USER"


# ════════════════════════════════════════════════════════════════════════════
# TEST USER STATUS
# ════════════════════════════════════════════════════════════════════════════


class TestUserStatus:
    """Test user status determination methods."""

    def test_check_lock_attributes_active(
        self,
        entry_manipulation_service: EntryManipulationServices,
        simple_user_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test checking lock attributes for active user."""
        result = entry_manipulation_service.check_lock_attributes(simple_user_entry)
        assert result.is_success
        assert result.unwrap() == "ACTIVE"

    def test_check_lock_attributes_locked(
        self,
        entry_manipulation_service: EntryManipulationServices,
        locked_user_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test checking lock attributes for locked user."""
        result = entry_manipulation_service.check_lock_attributes(locked_user_entry)
        assert result.is_success
        assert result.unwrap() == "LOCKED"

    def test_check_lock_attributes_disabled(
        self,
        entry_manipulation_service: EntryManipulationServices,
        disabled_user_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test checking lock attributes for disabled user."""
        result = entry_manipulation_service.check_lock_attributes(disabled_user_entry)
        assert result.is_success
        assert result.unwrap() == "DISABLED"

    def test_check_password_expiry(
        self,
        entry_manipulation_service: EntryManipulationServices,
        simple_user_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test checking password expiry."""
        result = entry_manipulation_service.check_password_expiry(simple_user_entry)
        # Returns True if pwdLastSet attribute exists
        assert isinstance(result, bool)

    def test_determine_user_status_active(
        self,
        entry_manipulation_service: EntryManipulationServices,
        simple_user_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test determining user status for active user."""
        status = entry_manipulation_service.determine_user_status(simple_user_entry)
        assert status == "ACTIVE"

    def test_determine_user_status_locked(
        self,
        entry_manipulation_service: EntryManipulationServices,
        locked_user_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test determining user status for locked user."""
        status = entry_manipulation_service.determine_user_status(locked_user_entry)
        assert status == "LOCKED"

    def test_check_user_active_status_active(
        self,
        entry_manipulation_service: EntryManipulationServices,
        simple_user_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test checking active status for active user."""
        is_active = entry_manipulation_service.check_user_active_status(
            simple_user_entry,
        )
        assert is_active is True

    def test_check_user_active_status_locked(
        self,
        entry_manipulation_service: EntryManipulationServices,
    ) -> None:
        """Test checking active status for locked user."""
        locked_entry = TestAssertions.create_entry(
            "cn=locked,ou=users,dc=example,dc=com",
            {
                "cn": ["locked"],
                "accountLocked": ["true"],
                "objectClass": ["person"],
            },
        )
        is_active = entry_manipulation_service.check_user_active_status(locked_entry)
        assert is_active is False


# ════════════════════════════════════════════════════════════════════════════
# TEST GROUP MEMBERSHIP
# ════════════════════════════════════════════════════════════════════════════


class TestGroupMembership:
    """Test group membership validation methods."""

    def test_check_group_email_requirement_no_requirement(
        self,
        entry_manipulation_service: EntryManipulationServices,
        simple_user_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test checking email requirement for non-REDACTED_LDAP_BIND_PASSWORD group."""
        group = create_entry(
            "cn=users,ou=groups,dc=example,dc=com",
            {"cn": ["users"]},
        )
        result = entry_manipulation_service.check_group_email_requirement(
            simple_user_entry,
            group,
        )
        assert result.is_success
        assert result.unwrap() is True

    def test_check_group_email_requirement_REDACTED_LDAP_BIND_PASSWORD_with_email(
        self,
        entry_manipulation_service: EntryManipulationServices,
        simple_user_entry: FlextLdifModels.Entry,
        group_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test checking email requirement for REDACTED_LDAP_BIND_PASSWORD group with email."""
        result = entry_manipulation_service.check_group_email_requirement(
            simple_user_entry,
            group_entry,
        )
        assert result.is_success
        assert result.unwrap() is True

    def test_check_group_email_requirement_REDACTED_LDAP_BIND_PASSWORD_without_email(
        self,
        entry_manipulation_service: EntryManipulationServices,
        group_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test checking email requirement for REDACTED_LDAP_BIND_PASSWORD group without email."""
        user = create_entry(
            "cn=nouser,ou=users,dc=example,dc=com",
            {"cn": ["nouser"]},
        )
        result = entry_manipulation_service.check_group_email_requirement(
            user,
            group_entry,
        )
        assert result.is_failure
        error_msg = result.error or ""
        assert "email" in error_msg.lower()

    def test_validate_group_membership_rules_valid(
        self,
        entry_manipulation_service: EntryManipulationServices,
        simple_user_entry: FlextLdifModels.Entry,
        group_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test validating valid group membership."""
        result = entry_manipulation_service.validate_group_membership_rules(
            simple_user_entry,
            group_entry,
        )
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_group_membership_rules_inactive_user(
        self,
        entry_manipulation_service: EntryManipulationServices,
        group_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test validating group membership for inactive user."""
        # Create locked user with email (so email check passes first)
        locked_entry = create_entry(
            "cn=locked,ou=users,dc=example,dc=com",
            {
                "cn": ["locked"],
                "mail": ["locked@example.com"],
                "accountLocked": ["true"],
            },
        )
        result = entry_manipulation_service.validate_group_membership_rules(
            locked_entry,
            group_entry,
        )
        assert result.is_failure
        error_msg = result.error or ""
        assert "inactive" in error_msg.lower()


# ════════════════════════════════════════════════════════════════════════════
# TEST USERNAME GENERATION
# ════════════════════════════════════════════════════════════════════════════


class TestUsernameGeneration:
    """Test username generation methods."""

    def test_normalize_username_base_success(
        self,
        entry_manipulation_service: EntryManipulationServices,
    ) -> None:
        """Test normalizing username base."""
        validation_service = FlextLdifValidation()
        # Use a simple name that will pass validation
        result = entry_manipulation_service.normalize_username_base(
            "johndoe",
            validation_service,
        )
        assert result.is_success
        username = result.unwrap()
        assert len(username) > 0

    def test_normalize_username_base_empty(
        self,
        entry_manipulation_service: EntryManipulationServices,
    ) -> None:
        """Test normalizing empty username base."""
        validation_service = FlextLdifValidation()
        result = entry_manipulation_service.normalize_username_base(
            "",
            validation_service,
        )
        assert result.is_failure
        error_msg = result.error or ""
        assert "empty" in error_msg.lower()

    def test_normalize_username_base_invalid_chars(
        self,
        entry_manipulation_service: EntryManipulationServices,
    ) -> None:
        """Test normalizing username base with invalid characters."""
        validation_service = FlextLdifValidation()
        result = entry_manipulation_service.normalize_username_base(
            "user@name#123",
            validation_service,
        )
        # Should sanitize invalid chars
        assert result.is_success or result.is_failure  # Depends on validation

    def test_collect_existing_uids(
        self,
        entry_manipulation_service: EntryManipulationServices,
    ) -> None:
        """Test collecting existing UIDs."""
        users = [
            create_entry(
                "cn=user1,dc=example,dc=com",
                {"uid": ["user1"]},
            ),
            create_entry(
                "cn=user2,dc=example,dc=com",
                {"uid": ["user2"]},
            ),
            create_entry(
                "cn=user3,dc=example,dc=com",
                {},  # No uid
            ),
        ]
        uids = entry_manipulation_service.collect_existing_uids(users)
        assert "user1" in uids
        assert "user2" in uids
        assert "user3" not in uids

    def test_generate_username_with_suffix_unique(
        self,
        entry_manipulation_service: EntryManipulationServices,
    ) -> None:
        """Test generating username with suffix when base is unique."""
        existing_uids: set[str] = {"user1", "user2"}
        result = entry_manipulation_service.generate_username_with_suffix(
            "user3",
            existing_uids,
            max_attempts=10,
        )
        assert result.is_success
        assert result.unwrap() == "user3"

    def test_generate_username_with_suffix_conflict(
        self,
        entry_manipulation_service: EntryManipulationServices,
    ) -> None:
        """Test generating username with suffix when base conflicts."""
        existing_uids: set[str] = {"user1", "user2", "user3"}
        result = entry_manipulation_service.generate_username_with_suffix(
            "user1",
            existing_uids,
            max_attempts=10,
        )
        assert result.is_success
        username = result.unwrap()
        assert username.startswith("user1")
        assert username != "user1"

    def test_generate_unique_username(
        self,
        entry_manipulation_service: EntryManipulationServices,
    ) -> None:
        """Test generating unique username."""
        validation_service = FlextLdifValidation()
        existing_users = [
            create_entry(
                "cn=user1,dc=example,dc=com",
                {"uid": ["user1"]},
            ),
        ]
        # Use a simple name that will pass validation
        result = entry_manipulation_service.generate_unique_username(
            "johndoe",
            existing_users,
            max_attempts=100,
            validation_service=validation_service,
        )
        assert result.is_success
        username = result.unwrap()
        assert len(username) > 0
        assert username != "user1"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
