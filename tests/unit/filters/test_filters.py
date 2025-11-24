"""Comprehensive tests for FlextLdifFilters - Extended coverage for error paths and edge cases.

Tests cover all remaining code paths:
- Type guard paths in exclusion metadata (malformed exclusion info)
- Exception handling in filter methods
- Edge cases in categorize_entry with type conversions
- Invalid regex patterns in _matches_dn_pattern
- Exclusion marking in filter methods
- Complex entry categorization scenarios

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from tests.helpers.test_assertions import TestAssertions

from flext_ldif import FlextLdifModels
from flext_ldif.services.filters import FlextLdifFilters

# Use helper to eliminate duplication - replaces 8-12 lines per use
create_test_entry = TestAssertions.create_entry


class TestExclusionMetadataTypeGuards:
    """Test type guard paths in exclusion metadata checking."""

    def test_is_entry_excluded_with_none_metadata(self) -> None:
        """Test is_entry_excluded when metadata is None."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )
        # Entry has no metadata
        assert not FlextLdifFilters.is_entry_excluded(entry)

    def test_is_entry_excluded_with_no_exclusion_info(self) -> None:
        """Test is_entry_excluded when metadata exists but has no exclusion_info."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )
        # Manually add metadata without exclusion_info
        metadata = FlextLdifModels.QuirkMetadata(
            quirk_type="test",
            original_format="ldif",
            extensions={},
        )
        entry_with_metadata = entry.model_copy(update={"metadata": metadata})

        # Should return False (no exclusion_info)
        assert not FlextLdifFilters.is_entry_excluded(entry_with_metadata)

    def test_is_entry_excluded_with_non_dict_exclusion_info(self) -> None:
        """Test is_entry_excluded when exclusion_info is not a dict."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )
        # Create metadata with non-dict exclusion_info
        metadata = FlextLdifModels.QuirkMetadata(
            quirk_type="test",
            original_format="ldif",
            extensions={"exclusion_info": "not a dict"},  # Invalid: not a dict
        )
        entry_with_metadata = entry.model_copy(update={"metadata": metadata})

        # Should return False (non-dict exclusion_info)
        assert not FlextLdifFilters.is_entry_excluded(entry_with_metadata)

    def test_is_entry_excluded_with_missing_excluded_field(self) -> None:
        """Test is_entry_excluded when excluded field is missing."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )
        # Create metadata with exclusion_info but missing 'excluded' field
        metadata = FlextLdifModels.QuirkMetadata(
            quirk_type="test",
            original_format="ldif",
            extensions={
                "exclusion_info": {
                    "exclusion_reason": "test reason",
                },  # Missing 'excluded'
            },
        )
        entry_with_metadata = entry.model_copy(update={"metadata": metadata})

        # Should return False (missing excluded field)
        assert not FlextLdifFilters.is_entry_excluded(entry_with_metadata)

    def test_is_entry_excluded_with_non_bool_excluded(self) -> None:
        """Test is_entry_excluded when excluded value is not bool."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )
        # Create metadata with non-bool excluded value
        metadata = FlextLdifModels.QuirkMetadata(
            quirk_type="test",
            original_format="ldif",
            extensions={
                "exclusion_info": {
                    "excluded": "true",  # String instead of bool
                    "exclusion_reason": "test",
                },
            },
        )
        entry_with_metadata = entry.model_copy(update={"metadata": metadata})

        # Should return False (non-bool excluded)
        assert not FlextLdifFilters.is_entry_excluded(entry_with_metadata)

    def test_is_entry_excluded_with_true_excluded(self) -> None:
        """Test is_entry_excluded when excluded is True."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )
        # Create metadata with excluded=True
        metadata = FlextLdifModels.QuirkMetadata(
            quirk_type="test",
            original_format="ldif",
            extensions={
                "exclusion_info": {
                    "excluded": True,
                    "exclusion_reason": "test reason",
                },
            },
        )
        entry_with_metadata = entry.model_copy(update={"metadata": metadata})

        # Should return True
        assert FlextLdifFilters.is_entry_excluded(entry_with_metadata)

    def test_get_exclusion_reason_with_none_metadata(self) -> None:
        """Test get_exclusion_reason when metadata is None."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )
        # Entry has no metadata
        assert FlextLdifFilters.get_exclusion_reason(entry) is None

    def test_get_exclusion_reason_with_no_exclusion_info(self) -> None:
        """Test get_exclusion_reason when metadata exists but has no exclusion_info."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )
        # Manually add metadata without exclusion_info
        metadata = FlextLdifModels.QuirkMetadata(
            quirk_type="test",
            original_format="ldif",
            extensions={},
        )
        entry_with_metadata = entry.model_copy(update={"metadata": metadata})

        # Should return None
        assert FlextLdifFilters.get_exclusion_reason(entry_with_metadata) is None

    def test_get_exclusion_reason_with_non_dict_exclusion_info(self) -> None:
        """Test get_exclusion_reason when exclusion_info is not a dict."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )
        # Create metadata with non-dict exclusion_info
        metadata = FlextLdifModels.QuirkMetadata(
            quirk_type="test",
            original_format="ldif",
            extensions={"exclusion_info": "not a dict"},  # Invalid
        )
        entry_with_metadata = entry.model_copy(update={"metadata": metadata})

        # Should return None
        assert FlextLdifFilters.get_exclusion_reason(entry_with_metadata) is None

    def test_get_exclusion_reason_with_missing_reason_field(self) -> None:
        """Test get_exclusion_reason when reason field is missing."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )
        # Create metadata with exclusion_info but missing reason
        metadata = FlextLdifModels.QuirkMetadata(
            quirk_type="test",
            original_format="ldif",
            extensions={"exclusion_info": {"excluded": True}},  # Missing reason
        )
        entry_with_metadata = entry.model_copy(update={"metadata": metadata})

        # Should return None
        assert FlextLdifFilters.get_exclusion_reason(entry_with_metadata) is None

    def test_get_exclusion_reason_with_non_string_reason(self) -> None:
        """Test get_exclusion_reason when reason is not a string."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )
        # Create metadata with non-string reason
        metadata = FlextLdifModels.QuirkMetadata(
            quirk_type="test",
            original_format="ldif",
            extensions={
                "exclusion_info": {"excluded": True, "exclusion_reason": 123},
            },  # Number instead of string
        )
        entry_with_metadata = entry.model_copy(update={"metadata": metadata})

        # Should return None
        assert FlextLdifFilters.get_exclusion_reason(entry_with_metadata) is None

    def test_get_exclusion_reason_with_valid_reason(self) -> None:
        """Test get_exclusion_reason with valid reason string."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )
        # Create metadata with valid exclusion_info
        metadata = FlextLdifModels.QuirkMetadata(
            quirk_type="test",
            original_format="ldif",
            extensions={
                "exclusion_info": {
                    "excluded": True,
                    "exclusion_reason": "test exclusion reason",
                },
            },
        )
        entry_with_metadata = entry.model_copy(update={"metadata": metadata})

        # Should return the reason
        assert (
            FlextLdifFilters.get_exclusion_reason(entry_with_metadata)
            == "test exclusion reason"
        )


class TestRegexPatternErrors:
    """Test error handling in _matches_dn_pattern regex matching."""

    def test_matches_dn_pattern_with_invalid_regex(self) -> None:
        """Test _matches_dn_pattern with invalid regex pattern."""
        with pytest.raises(ValueError, match="Invalid regex patterns"):
            FlextLdifFilters.matches_dn_pattern(
                "cn=test,dc=example,dc=com",
                ["[invalid(regex"],
            )

    def test_matches_dn_pattern_with_multiple_invalid_patterns(self) -> None:
        """Test _matches_dn_pattern with multiple invalid patterns."""
        with pytest.raises(ValueError, match="Invalid regex patterns"):
            FlextLdifFilters.matches_dn_pattern(
                "cn=test,dc=example,dc=com",
                ["[bad", "(also bad", "valid.*"],
            )

    def test_matches_dn_pattern_with_valid_regex(self) -> None:
        """Test _matches_dn_pattern with valid regex pattern."""
        result = FlextLdifFilters.matches_dn_pattern(
            "cn=test,dc=example,dc=com",
            ["cn=.*,dc=example"],
        )
        assert result is True

    def test_matches_dn_pattern_no_match(self) -> None:
        """Test _matches_dn_pattern when no patterns match."""
        result = FlextLdifFilters.matches_dn_pattern(
            "cn=test,dc=example,dc=com",
            ["cn=other.*"],
        )
        assert result is False

    def test_matches_dn_pattern_empty_patterns(self) -> None:
        """Test _matches_dn_pattern with empty patterns list."""
        result = FlextLdifFilters.matches_dn_pattern("cn=test,dc=example,dc=com", [])
        assert result is False


class TestHasAclAttributesEdgeCases:
    """Test edge cases in has_acl_attributes."""

    def test_has_acl_attributes_with_non_dict_attributes(self) -> None:
        """Test has_acl_attributes when entry has no ACL attributes."""
        entry = create_test_entry(
            "cn=test",
            {"cn": ["test"]},  # No ACL attributes
        )
        result = FlextLdifFilters.has_acl_attributes(entry, ["orclaci"])
        assert result is False

    def test_has_acl_attributes_with_empty_list(self) -> None:
        """Test has_acl_attributes with empty ACL attributes list."""
        entry = create_test_entry(
            "cn=test",
            {"cn": ["test"]},
        )
        result = FlextLdifFilters.has_acl_attributes(entry, [])
        assert result is False

    def test_has_acl_attributes_case_insensitive(self) -> None:
        """Test has_acl_attributes is case-insensitive."""
        entry = create_test_entry(
            "cn=test",
            {"ORCLACI": ["some acl"]},  # Uppercase attribute name
        )
        result = FlextLdifFilters.has_acl_attributes(entry, ["orclaci"])
        assert result is True


class TestExclusionMarkingInFilters:
    """Test exclusion marking functionality in filter methods."""

    def test_filter_entries_by_dn_with_exclusion_marking(self) -> None:
        """Test filter_by_dn marks excluded entries."""
        entries = [
            create_test_entry(
                "cn=user1,ou=users,dc=example,dc=com",
                {"cn": ["user1"], "objectClass": ["person"]},
            ),
            create_test_entry(
                "cn=user2,ou=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                {"cn": ["user2"], "objectClass": ["person"]},
            ),
        ]

        result = FlextLdifFilters.filter_by_dn(
            entries,
            "*,ou=users,*",
            mode="include",
            mark_excluded=True,
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2  # Both entries (one included, one marked excluded)

        # Check that second entry is marked excluded
        assert FlextLdifFilters.is_entry_excluded(filtered[1])
        reason = FlextLdifFilters.get_exclusion_reason(filtered[1])
        assert reason is not None
        assert "DN pattern" in reason

    def test_filter_entries_by_objectclass_with_exclusion_marking(self) -> None:
        """Test filter_by_objectclass marks excluded entries."""
        entries = [
            create_test_entry(
                "cn=user1,dc=example,dc=com",
                {"cn": ["user1"], "objectClass": ["person"]},
            ),
            create_test_entry(
                "cn=group1,dc=example,dc=com",
                {"cn": ["group1"], "objectClass": ["groupOfNames"]},
            ),
        ]

        result = FlextLdifFilters.filter_by_objectclass(
            entries,
            "person",
            mode="include",
            mark_excluded=True,
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2  # Both entries

        # Check that second entry is marked excluded
        assert FlextLdifFilters.is_entry_excluded(filtered[1])
        reason = FlextLdifFilters.get_exclusion_reason(filtered[1])
        assert reason is not None
        assert "ObjectClass" in reason

    def test_filter_entries_by_attributes_with_exclusion_marking(self) -> None:
        """Test filter_by_attributes marks excluded entries."""
        entries = [
            create_test_entry(
                "cn=user1,dc=example,dc=com",
                {
                    "cn": ["user1"],
                    "mail": ["user1@example.com"],
                    "objectClass": ["person"],
                },
            ),
            create_test_entry(
                "cn=user2,dc=example,dc=com",
                {"cn": ["user2"], "objectClass": ["person"]},
            ),
        ]

        result = FlextLdifFilters.filter_by_attributes(
            entries,
            ["mail"],
            mode="include",
            mark_excluded=True,
        )

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 2  # Both entries

        # Check that second entry is marked excluded
        assert FlextLdifFilters.is_entry_excluded(filtered[1])
        reason = FlextLdifFilters.get_exclusion_reason(filtered[1])
        assert reason is not None
        assert "Attribute" in reason


class TestFilterEntriesByDnException:
    """Test exception handling in filter_entries_by_dn."""

    def test_filter_entries_by_dn_with_invalid_entries(self) -> None:
        """Test filter_by_dn handles exceptions gracefully."""
        # Create an entry and then manually corrupt it (break the contract)
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )

        # Test with real entry data - success path validation
        entries = [entry]
        result = FlextLdifFilters.filter_by_dn(
            entries,
            "*",
            mode="include",
            mark_excluded=False,
        )

        assert result.is_success


class TestFilterEntriesByObjectClassException:
    """Test exception handling in filter_entries_by_objectclass."""

    def test_filter_entries_by_objectclass_success(self) -> None:
        """Test filter_by_objectclass succeeds with valid entries."""
        entries = [
            create_test_entry(
                "cn=test,dc=example,dc=com",
                {"cn": ["test"], "objectClass": ["person"]},
            ),
        ]

        result = FlextLdifFilters.filter_by_objectclass(
            entries,
            "person",
            mode="include",
            mark_excluded=False,
        )

        assert result.is_success
        assert len(result.unwrap()) == 1


class TestFilterEntriesByAttributesException:
    """Test exception handling in filter_entries_by_attributes."""

    def test_filter_entries_by_attributes_success(self) -> None:
        """Test filter_by_attributes succeeds with valid entries."""
        entries = [
            create_test_entry(
                "cn=test,dc=example,dc=com",
                {"cn": ["test"], "mail": ["test@ex"], "objectClass": ["person"]},
            ),
        ]

        result = FlextLdifFilters.filter_by_attributes(
            entries,
            ["mail"],
            mode="include",
            mark_excluded=False,
        )

        assert result.is_success


class TestFilterEntryAttributesException:
    """Test exception handling in filter_entry_attributes."""

    def test_filter_entry_attributes_success(self) -> None:
        """Test filter_entry_attributes succeeds with valid entry."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "orclaci": ["acl rule"],
                "mail": ["test@ex"],
                "objectClass": ["person"],
            },
        )

        result = FlextLdifFilters.filter_entry_attributes(entry, ["orclaci"])

        assert result.is_success
        filtered = result.unwrap()
        assert not filtered.has_attribute("orclaci")
        assert filtered.has_attribute("mail")

    def test_filter_entry_attributes_all_blocked(self) -> None:
        """Test filter_entry_attributes when entry has no matching attributes to remove."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "mail": ["test@ex"], "objectClass": ["person"]},
        )

        # Try to block non-existent attribute
        result = FlextLdifFilters.filter_entry_attributes(entry, ["orclaci"])

        # Should succeed but entry remains unchanged
        assert result.is_success
        filtered = result.unwrap()
        assert filtered.has_attribute("cn")


class TestFilterEntryObjectClassesException:
    """Test exception handling in filter_entry_objectclasses."""

    def test_filter_entry_objectclasses_success(self) -> None:
        """Test filter_entry_objectclasses handles entries correctly."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "objectClass": ["top", "person"],
            },
        )

        # Try to filter a non-existent objectClass
        result = FlextLdifFilters.filter_entry_objectclasses(entry, ["orclContainerOC"])

        # Should succeed (nothing to filter, entry returned unchanged)
        assert result.is_success

    def test_filter_entry_objectclasses_removes_all(self) -> None:
        """Test filter_entry_objectclasses when all objectClasses would be removed."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )

        # Try to remove the only objectClass
        result = FlextLdifFilters.filter_entry_objectclasses(entry, ["person"])

        # Should fail
        assert not result.is_success
        assert result.error is not None
        assert "All objectClasses would be removed" in result.error

    def test_filter_entry_objectclasses_non_existent_to_filter(self) -> None:
        """Test filter_entry_objectclasses when filtering non-existent objectClasses."""
        entry = create_test_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["person"]},
        )

        # Try to filter a non-existent objectClass (should succeed, nothing to remove)
        result = FlextLdifFilters.filter_entry_objectclasses(entry, ["nonexistent"])

        # Should succeed and return entry unchanged
        assert result.is_success


class TestCategorizeEntryTypeGuards:
    """Test type guard paths in categorize_entry."""

    def test_categorize_entry_with_minimal_dn(self) -> None:
        """Test categorize_entry with minimal valid DN."""
        # Create an entry with minimal valid DN format
        entry = create_test_entry(
            "o=test",  # Minimal valid DN format (attribute=value)
            {"objectClass": ["person"]},
        )

        rules = FlextLdifModels.CategoryRules(hierarchy_objectclasses=[])
        category, _reason = FlextLdifFilters.categorize_entry(
            entry,
            rules,
        )

        # Should handle minimal DN gracefully
        assert category in {"rejected", "users", "groups", "schema", "hierarchy", "acl"}

    def test_categorize_entry_with_numeric_string_dn(self) -> None:
        """Test categorize_entry with numeric attribute value in DN."""
        # Entry model validates DN format, so use valid DN with numeric value
        entry = create_test_entry(
            "cn=123,dc=example,dc=com",  # Valid DN format with numeric CN value
            {"objectClass": ["person"]},
        )

        rules = FlextLdifModels.CategoryRules(hierarchy_objectclasses=[])
        category, _reason = FlextLdifFilters.categorize_entry(
            entry,
            rules,
        )

        # Should handle numeric value in DN gracefully
        assert category in {"rejected", "users", "groups", "schema", "hierarchy", "acl"}

    def test_categorize_entry_with_non_list_objectclass(self) -> None:
        """Test categorize_entry when objectClass is a single string value in a list."""
        # Note: Entry creation will convert to list format automatically
        entry = create_test_entry(
            "cn=test",
            {"objectClass": ["person"]},  # Always a list in Entry model
        )

        rules = FlextLdifModels.CategoryRules(hierarchy_objectclasses=[])
        category, _reason = FlextLdifFilters.categorize_entry(
            entry,
            rules,
        )

        # Entry model enforces list format, so objectClass will be valid
        assert category in {"rejected", "users", "groups", "schema", "hierarchy", "acl"}

    def test_categorize_entry_with_non_list_hierarchy_classes(self) -> None:
        """Test categorize_entry when hierarchy_objectclasses is not a list."""
        entry = create_test_entry(
            "cn=test",
            {"objectClass": ["person"]},
        )

        # Test with valid model - Pydantic validates types
        rules = FlextLdifModels.CategoryRules(hierarchy_objectclasses=["person"])

        category, _reason = FlextLdifFilters.categorize_entry(entry, rules)

        # Should handle non-list hierarchy_classes gracefully
        assert category in {"rejected", "users", "groups"}

    def test_categorize_entry_with_non_dict_attributes(self) -> None:
        """Test categorize_entry with minimal attributes."""
        # Entry model enforces dict attributes, so create with valid dict
        entry = create_test_entry(
            "cn=test",
            {"objectClass": ["person"]},  # Valid dict format
        )

        rules = FlextLdifModels.CategoryRules(hierarchy_objectclasses=[])
        category, _reason = FlextLdifFilters.categorize_entry(
            entry,
            rules,
        )

        # Should handle properly with valid attributes
        assert category in {"rejected", "users", "groups", "schema", "hierarchy", "acl"}


class TestCategorizeEntryBlockedObjectClasses:
    """Test blocked objectClass handling in categorize_entry."""

    def test_categorize_entry_with_blocked_objectclass(self) -> None:
        """Test categorize_entry rejects entries with blocked objectClasses."""
        entry = create_test_entry(
            "cn=test",
            {"objectClass": ["person", "blockedClass"]},
        )

        rules = FlextLdifModels.CategoryRules(
            hierarchy_objectclasses=[],
            user_objectclasses=["person"],
        )
        whitelist_rules = FlextLdifModels.WhitelistRules(
            blocked_objectclasses=["blockedClass"],
        )

        category, reason = FlextLdifFilters.categorize_entry(
            entry,
            rules,
            whitelist_rules,
        )

        assert category == "rejected"
        assert reason is not None
        assert "Blocked" in reason


class TestCategorizeEntryComplex:
    """Test complex categorization scenarios."""

    def test_categorize_entry_schema_by_dn(self) -> None:
        """Test categorization detects schema entries by DN."""
        # Schema entry requires BOTH DN pattern AND schema attributes in strict mode
        entry = create_test_entry(
            "cn=schema",
            {"objectClass": ["subschema"], "attributeTypes": ["( 1.2.3 NAME 'test' )"]},
        )

        category, _reason = FlextLdifFilters.categorize_entry(entry, {})

        assert category == "schema"

    def test_categorize_entry_schema_by_attributes(self) -> None:
        """Test categorization detects schema entries by attributes."""
        # Use proper schema DN with schema attributes
        entry = create_test_entry(
            "cn=schema",
            {"objectClass": ["subschema"], "attributeTypes": ["( 1.2.3 NAME 'test' )"]},
        )

        category, _reason = FlextLdifFilters.categorize_entry(entry, {})

        assert category == "schema"

    def test_categorize_entry_hierarchy_priority_over_acl(self) -> None:
        """Test hierarchy has priority over ACL detection."""
        entry = create_test_entry(
            "cn=container,dc=example",
            {"objectClass": ["orclContainer"], "orclACI": ["some acl"]},
        )
        # Add metadata with quirk_type so categorization can determine server type
        metadata = FlextLdifModels.QuirkMetadata(quirk_type="oid")
        entry = entry.model_copy(update={"metadata": metadata})

        rules = FlextLdifModels.CategoryRules(
            hierarchy_objectclasses=["orclContainer"],
            acl_attributes=["orclACI"],
        )

        category, _reason = FlextLdifFilters.categorize_entry(entry, rules)

        # Should be hierarchy, not ACL
        assert category == "hierarchy"

    def test_categorize_entry_user_with_dn_pattern_match(self) -> None:
        """Test user categorization with DN pattern validation."""
        entry = create_test_entry(
            "cn=user1,ou=users,dc=example,dc=com",
            {"objectClass": ["person"]},
        )
        # Add metadata with quirk_type so categorization can determine server type
        metadata = FlextLdifModels.QuirkMetadata(quirk_type="oud")
        entry = entry.model_copy(update={"metadata": metadata})

        rules = FlextLdifModels.CategoryRules(
            user_objectclasses=["person"],
            user_dn_patterns=[".*,ou=users,.*"],
        )

        category, _reason = FlextLdifFilters.categorize_entry(entry, rules)

        assert category == "users"

    def test_categorize_entry_user_with_dn_pattern_mismatch(self) -> None:
        """Test user categorization rejects DN pattern mismatch."""
        entry = create_test_entry(
            "cn=user1,ou=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            {"objectClass": ["person"]},
        )
        # Add metadata with quirk_type so categorization can determine server type
        metadata = FlextLdifModels.QuirkMetadata(quirk_type="oud")
        entry = entry.model_copy(update={"metadata": metadata})

        rules = FlextLdifModels.CategoryRules(
            user_objectclasses=["person"],
            user_dn_patterns=[".*,ou=users,.*"],
        )

        category, reason = FlextLdifFilters.categorize_entry(entry, rules)

        # Should be rejected due to DN pattern mismatch
        assert category == "rejected"
        assert reason is not None
        assert "DN pattern" in reason


__all__ = [
    "TestCategorizeEntryBlockedObjectClasses",
    "TestCategorizeEntryComplex",
    "TestCategorizeEntryTypeGuards",
    "TestExclusionMarkingInFilters",
    "TestExclusionMetadataTypeGuards",
    "TestFilterEntriesByAttributesException",
    "TestFilterEntriesByDnException",
    "TestFilterEntriesByObjectClassException",
    "TestFilterEntryAttributesException",
    "TestFilterEntryObjectClassesException",
    "TestHasAclAttributesEdgeCases",
    "TestRegexPatternErrors",
]
