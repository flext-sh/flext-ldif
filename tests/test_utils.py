"""Tests for LDIF utilities."""

from __future__ import annotations

# Use simplified imports from root level
from flext_ldif import LDIFEntry, LDIFUtils


class TestLDIFUtils:
    """Test LDIF utility functions."""

    def test_entries_to_ldif_single_entry(self) -> None:
        """Test converting single entry to LDIF."""
        entry = LDIFEntry.model_validate(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {
                    "cn": ["test"],
                    "objectClass": ["person"],
                    "mail": ["test@example.com"],
                },
            }
        )

        result = LDIFUtils.entries_to_ldif([entry])

        assert isinstance(result, str)  # LDIFContent is a NewType of str
        ldif_str = result
        assert "dn: cn=test,dc=example,dc=com" in ldif_str
        assert "cn: test" in ldif_str
        assert "objectClass: person" in ldif_str
        assert "mail: test@example.com" in ldif_str

    def test_entries_to_ldif_multiple_entries(self) -> None:
        """Test converting multiple entries to LDIF."""
        entries = [
            LDIFEntry.model_validate(
                {
                    "dn": "cn=user1,dc=example,dc=com",
                    "attributes": {
                        "cn": ["user1"],
                        "objectClass": ["person"],
                    },
                }
            ),
            LDIFEntry.model_validate(
                {
                    "dn": "cn=user2,dc=example,dc=com",
                    "attributes": {
                        "cn": ["user2"],
                        "objectClass": ["inetOrgPerson"],
                        "mail": ["user2@example.com"],
                    },
                }
            ),
        ]

        result = LDIFUtils.entries_to_ldif(entries)

        assert isinstance(result, str)  # LDIFContent is a NewType of str
        ldif_str = result

        # Check first entry
        assert "dn: cn=user1,dc=example,dc=com" in ldif_str
        assert "cn: user1" in ldif_str
        assert "objectClass: person" in ldif_str

        # Check second entry
        assert "dn: cn=user2,dc=example,dc=com" in ldif_str
        assert "cn: user2" in ldif_str
        assert "objectClass: inetOrgPerson" in ldif_str
        assert "mail: user2@example.com" in ldif_str

    def test_entries_to_ldif_empty_list(self) -> None:
        """Test converting empty entry list to LDIF."""
        result = LDIFUtils.entries_to_ldif([])

        assert isinstance(result, str)  # LDIFContent is a NewType of str
        assert result == ""

    def test_entries_to_ldif_entry_with_no_attributes(self) -> None:
        """Test converting entry with no attributes to LDIF."""
        entry = LDIFEntry.model_validate(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {},
            }
        )

        result = LDIFUtils.entries_to_ldif([entry])

        assert isinstance(result, str)  # LDIFContent is a NewType of str
        ldif_str = result
        assert "dn: cn=test,dc=example,dc=com" in ldif_str
        # Should still have the empty line at the end
        assert ldif_str.endswith("\n")

    def test_filter_entries_by_objectclass_found(self) -> None:
        """Test filtering entries by objectClass when matches exist."""
        entries = [
            LDIFEntry.model_validate(
                {
                    "dn": "cn=person1,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"]},
                }
            ),
            LDIFEntry.model_validate(
                {
                    "dn": "cn=group1,dc=example,dc=com",
                    "attributes": {"objectClass": ["groupOfNames"]},
                }
            ),
            LDIFEntry.model_validate(
                {
                    "dn": "cn=person2,dc=example,dc=com",
                    "attributes": {"objectClass": ["person", "inetOrgPerson"]},
                }
            ),
        ]

        filtered = LDIFUtils.filter_entries_by_objectclass(entries, "person")

        assert len(filtered) == 2
        assert str(filtered[0].dn) == "cn=person1,dc=example,dc=com"
        assert str(filtered[1].dn) == "cn=person2,dc=example,dc=com"

    def test_filter_entries_by_objectclass_not_found(self) -> None:
        """Test filtering entries by objectClass when no matches exist."""
        entries = [
            LDIFEntry.model_validate(
                {
                    "dn": "cn=person1,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"]},
                }
            ),
            LDIFEntry.model_validate(
                {
                    "dn": "cn=group1,dc=example,dc=com",
                    "attributes": {"objectClass": ["groupOfNames"]},
                }
            ),
        ]

        filtered = LDIFUtils.filter_entries_by_objectclass(entries, "inetOrgPerson")

        assert len(filtered) == 0

    def test_filter_entries_by_objectclass_empty_list(self) -> None:
        """Test filtering empty entry list by objectClass."""
        filtered = LDIFUtils.filter_entries_by_objectclass([], "person")

        assert len(filtered) == 0

    def test_filter_entries_by_objectclass_no_objectclass_attribute(self) -> None:
        """Test filtering entries without objectClass attribute."""
        entries = [
            LDIFEntry.model_validate(
                {
                    "dn": "cn=test1,dc=example,dc=com",
                    "attributes": {"cn": ["test1"]},  # No objectClass
                }
            ),
            LDIFEntry.model_validate(
                {
                    "dn": "cn=test2,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"]},
                }
            ),
        ]

        filtered = LDIFUtils.filter_entries_by_objectclass(entries, "person")

        assert len(filtered) == 1
        assert str(filtered[0].dn) == "cn=test2,dc=example,dc=com"

    def test_filter_entries_by_objectclass_empty_objectclass(self) -> None:
        """Test filtering entries with empty objectClass attribute."""
        entries = [
            LDIFEntry.model_validate(
                {
                    "dn": "cn=test1,dc=example,dc=com",
                    "attributes": {"objectClass": []},  # Empty objectClass
                }
            ),
            LDIFEntry.model_validate(
                {
                    "dn": "cn=test2,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"]},
                }
            ),
        ]

        filtered = LDIFUtils.filter_entries_by_objectclass(entries, "person")

        assert len(filtered) == 1
        assert str(filtered[0].dn) == "cn=test2,dc=example,dc=com"

    def test_get_entry_by_dn_found(self) -> None:
        """Test getting entry by DN when it exists."""
        entries = [
            LDIFEntry.model_validate(
                {"dn": "cn=user1,dc=example,dc=com", "attributes": {"cn": ["user1"]}}
            ),
            LDIFEntry.model_validate(
                {"dn": "cn=user2,dc=example,dc=com", "attributes": {"cn": ["user2"]}}
            ),
        ]

        entry = LDIFUtils.get_entry_by_dn(entries, "cn=user2,dc=example,dc=com")

        assert entry is not None
        assert str(entry.dn) == "cn=user2,dc=example,dc=com"
        assert entry.get_attribute("cn") == ["user2"]

    def test_get_entry_by_dn_not_found(self) -> None:
        """Test getting entry by DN when it doesn't exist."""
        entries = [
            LDIFEntry.model_validate(
                {"dn": "cn=user1,dc=example,dc=com", "attributes": {"cn": ["user1"]}}
            ),
        ]

        entry = LDIFUtils.get_entry_by_dn(entries, "cn=nonexistent,dc=example,dc=com")

        assert entry is None

    def test_get_entry_by_dn_empty_list(self) -> None:
        """Test getting entry by DN from empty list."""
        entry = LDIFUtils.get_entry_by_dn([], "cn=test,dc=example,dc=com")

        assert entry is None

    def test_get_entry_by_dn_case_sensitive(self) -> None:
        """Test getting entry by DN is case sensitive."""
        entries = [
            LDIFEntry.model_validate(
                {"dn": "cn=User1,dc=example,dc=com", "attributes": {"cn": ["User1"]}}
            ),
        ]

        # Exact case match should work
        entry = LDIFUtils.get_entry_by_dn(entries, "cn=User1,dc=example,dc=com")
        assert entry is not None

        # Different case should not match
        entry = LDIFUtils.get_entry_by_dn(entries, "cn=user1,dc=example,dc=com")
        assert entry is None

    def test_get_entry_by_dn_exact_match(self) -> None:
        """Test getting entry by DN requires exact match."""
        entries = [
            LDIFEntry.model_validate(
                {
                    "dn": "cn=user1,ou=people,dc=example,dc=com",
                    "attributes": {"cn": ["user1"]},
                }
            ),
        ]

        # Exact match should work
        entry = LDIFUtils.get_entry_by_dn(
            entries,
            "cn=user1,ou=people,dc=example,dc=com",
        )
        assert entry is not None

        # Partial match should not work
        entry = LDIFUtils.get_entry_by_dn(entries, "cn=user1")
        assert entry is None
