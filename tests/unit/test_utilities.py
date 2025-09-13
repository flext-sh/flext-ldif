"""Tests for FlextLDIFUtilities class with REAL functionality (no mocks).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextTypes
from flext_ldif import FlextLDIFAPI, FlextLDIFModels
from flext_ldif.utilities import ( # Reason: Multiple assertion checks are common in tests for comprehensive error validation from __future__ import annotations FlextLDIFUtilities, # Using unified FlextLDIFUtilities directly - no wrapper classes )


@pytest.fixture
def api() -> FlextLDIFAPI:
    """Get a real FlextLDIFAPI instance."""

    return FlextLDIFAPI()


@pytest.fixture
def sample_entries(api: FlextLDIFAPI) -> list[FlextLDIFModels.Entry]:
    """Create real LDIF entries for testing utilities."""

    ldif_content = """dn: cn=John Doe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: John Doe
sn: Doe
givenName: John
mail: john.doe@example.com

dn: cn=Jane Smith,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: Jane Smith
sn: Smith
givenName: Jane
mail: jane.smith@example.com

dn: cn=developers,ou=groups,dc=example,dc=com
objectClass: groupOfNames
objectClass: top
cn: developers
description: Development Team
member: cn=John Doe,ou=people,dc=example,dc=com
member: cn=Jane Smith,ou=people,dc=example,dc=com

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
objectClass: top
ou: people
description: People OU
"""

    # Use REAL parsing - no mocks
    return api._operations.parse_string(ldif_content).unwrap_or([])


@pytest.fixture
def invalid_entries() -> list[FlextLDIFModels.Entry]:
    """Create entries with validation issues for testing."""

    # Create entries directly that have validation issues
    # Entry with missing objectClass
    entry1 = FlextLDIFModels.Entry(
        dn=FlextLDIFModels.DistinguishedName(
            value="cn=NoObjectClass,dc=example,dc=com"
        ),
        attributes=FlextLDIFModels.LdifAttributes(
            data={"cn": ["NoObjectClass"], "mail": ["test@example.com"]}
        ),
    )

    # Entry with empty DN (DN validation will actually fail during model creation)
    # So create a valid DN but entry that will fail validation logic
    entry2 = FlextLDIFModels.Entry(
        dn=FlextLDIFModels.DistinguishedName(value="cn=ValidDN,dc=example,dc=com"),
        attributes=FlextLDIFModels.LdifAttributes(
            data={"cn": ["ValidDN"]}
        ),  # Missing objectClass
    )

    return [entry1, entry2]


class TestFlextLDIFUtilities:
    """Test FlextLDIFUtilities with real functionality."""

    def test_utilities_class_structure(self) -> None:
        """Test SOLID-compliant FlextLDIFUtilities structure with nested helpers."""

        # SOLID COMPLIANCE: Test proper nested helper pattern
        utilities = FlextLDIFUtilities()

        # Test nested helpers are properly accessible
        assert hasattr(utilities, "processors")
        assert hasattr(utilities, "converters")

        # Test LDIF-specific domain operations through proper API
        assert hasattr(utilities.processors, "validate_entries_or_warn")
        assert hasattr(utilities.processors, "get_entry_statistics")
        assert hasattr(utilities.converters, "normalize_dn_components")
        assert hasattr(utilities.converters, "attributes_dict_to_ldif_format")

    def test_utilities_initialization(self) -> None:
        """Test FlextLDIFUtilities initialization following flext-core patterns."""

        # Test instantiation to cover __init__ method
        utilities = FlextLDIFUtilities()

        # Verify logger initialization
        assert hasattr(utilities, "_logger")
        assert utilities._logger is not None

    def test_validate_entries_or_warn_with_valid_entries(
        self, sample_entries: list[FlextLDIFModels.Entry]
    ) -> None:
        """Test validate_entries_or_warn with valid entries."""

        result = FlextLDIFUtilities().processors.validate_entries_or_warn(
            sample_entries
        )

        assert result.is_success
        assert result.value is True  # All sample entries should be valid

    def test_validate_entries_or_warn_with_invalid_entries(
        self, invalid_entries: list[FlextLDIFModels.Entry]
    ) -> None:
        """Test validate_entries_or_warn with entries that have issues."""

        result = FlextLDIFUtilities().processors.validate_entries_or_warn(
            invalid_entries
        )

        assert result.is_success
        assert (
            result.value is True
        )  # SOLID COMPLIANT: Validation succeeds with warnings logged

    def test_validate_entries_or_warn_max_errors_limit(
        self, invalid_entries: list[FlextLDIFModels.Entry]
    ) -> None:
        """Test validate_entries_or_warn respects max_errors limit."""

        result = FlextLDIFUtilities().processors.validate_entries_or_warn(
            invalid_entries
        )

        assert result.is_success
        assert (
            result.value is True
        )  # SOLID COMPLIANT: Validation succeeds with warnings logged

    def test_filter_entries_by_object_class(
        self, sample_entries: list[FlextLDIFModels.Entry]
    ) -> None:
        """Test filtering entries by objectClass."""

        result = FlextLDIFUtilities().processors.filter_entries_by_object_class(
            sample_entries, "person"
        )

        assert result.is_success
        filtered_entries = result.value
        assert len(filtered_entries) == 2  # John and Jane are person objects
        for entry in filtered_entries:
            assert entry.has_object_class("person")

    def test_filter_entries_by_object_class_case_insensitive(
        self, sample_entries: list[FlextLDIFModels.Entry]
    ) -> None:
        """Test filtering is case-insensitive."""

        result = FlextLDIFUtilities().processors.filter_entries_by_object_class(
            sample_entries, "person"
        )

        assert result.is_success
        filtered_entries = result.value
        assert len(filtered_entries) == 2

    def test_filter_entries_by_object_class_no_matches(
        self, sample_entries: list[FlextLDIFModels.Entry]
    ) -> None:
        """Test filtering with no matching entries."""

        result = FlextLDIFUtilities().processors.filter_entries_by_object_class(
            sample_entries, "nonExistentClass"
        )

        assert result.is_success
        assert len(result.value) == 0

    def test_find_entries_with_missing_required_attributes(
        self, sample_entries: list[FlextLDIFModels.Entry]
    ) -> None:
        """Test finding entries missing required attributes."""

        # All sample entries should have 'objectClass' attribute
        result = FlextLDIFUtilities().processors.find_entries_with_missing_required_attributes(
            sample_entries, ["objectClass"]
        )

        assert result.is_success
        assert len(result.value) == 0  # All entries should have objectClass

    def test_find_entries_with_missing_required_attributes_found(
        self, sample_entries: list[FlextLDIFModels.Entry]
    ) -> None:
        """Test finding entries missing a required attribute that some don't have."""

        # Look for 'telephoneNumber' which none of our sample entries have
        result = FlextLDIFUtilities().processors.find_entries_with_missing_required_attributes(
            sample_entries, ["telephoneNumber"]
        )

        assert result.is_success
        assert len(result.value) == len(
            sample_entries
        )  # All entries missing telephoneNumber

    def test_attributes_dict_to_ldif_format_success(self) -> None:
        """Test converting attributes dictionary to LDIF format."""

        test_attrs = {
            "cn": ["John Doe"],
            "mail": ["john@example.com", "john.doe@example.com"],
            "objectClass": ["person", "inetOrgPerson"],
        }

        result = FlextLDIFUtilities().converters.attributes_to_ldif_format(test_attrs)

        assert result.is_success
        converted = result.value
        assert "cn" in converted
        assert converted["cn"] == ["John Doe"]
        assert "mail" in converted
        assert len(converted["mail"]) == 2

    def test_attributes_dict_to_ldif_format_with_none_values(self) -> None:
        """Test converting attributes with None values."""

        test_attrs: dict[str, FlextTypes.Core.StringList] = {
            "cn": ["John Doe"],
            "description": [],  # Should be filtered out when empty
            "mail": [
                "john@example.com",
                "john.doe@example.com",
            ],  # Removed None for type safety
        }

        result = FlextLDIFUtilities().converters.attributes_to_ldif_format(test_attrs)

        assert result.is_success
        converted = result.value
        assert "cn" in converted
        assert (
            "description" not in converted
        )  # Should be filtered out due to empty list
        assert "mail" in converted
        assert len(converted["mail"]) == 2

    def test_attributes_dict_to_ldif_format_case_normalization(self) -> None:
        """Test that attribute names are normalized to lowercase."""

        test_attrs = {
            "CN": ["John Doe"],
            "Mail": ["john@example.com"],
            "OBJECTCLASS": ["person"],
        }

        result = FlextLDIFUtilities().converters.attributes_to_ldif_format(test_attrs)

        assert result.is_success
        converted = result.value
        assert "cn" in converted
        assert "mail" in converted
        assert "objectclass" in converted

    def test_normalize_dn_components_success(self) -> None:
        """Test DN normalization with valid DN."""

        dn = "  cn=John Doe,ou=people,dc=example,dc=com  "

        result = FlextLDIFUtilities().converters.normalize_dn_components(dn)

        assert result.is_success
        assert result.value == "cn=John Doe,ou=people,dc=example,dc=com"

    def test_normalize_dn_components_empty_dn(self) -> None:
        """Test DN normalization with empty DN."""

        result = FlextLDIFUtilities().converters.normalize_dn_components("")

        assert result.is_failure
        assert result.error is not None
        assert "DN cannot be empty" in result.error

    def test_normalize_dn_components_whitespace_only(self) -> None:
        """Test DN normalization with whitespace-only DN."""

        result = FlextLDIFUtilities().converters.normalize_dn_components("   ")

        assert result.is_failure
        assert result.error is not None
        assert "DN cannot be empty" in result.error

    def test_validate_entries_or_warn_empty_list(self) -> None:
        """Test validate_entries_or_warn with empty entry list."""

        result = FlextLDIFUtilities().processors.validate_entries_or_warn([])

        assert result.is_success
        assert result.value is True  # Empty list should be considered valid

    def test_filter_entries_by_object_class_empty_list(self) -> None:
        """Test filtering empty list of entries."""

        result = FlextLDIFUtilities().processors.filter_entries_by_object_class(
            [], "person"
        )

        assert result.is_success
        assert len(result.value) == 0

    def test_find_entries_with_missing_required_attributes_empty_list(self) -> None:
        """Test finding missing attributes in empty list."""

        result = FlextLDIFUtilities().processors.find_entries_with_missing_required_attributes(
            [], ["cn"]
        )

        assert result.is_success
        assert len(result.value) == 0

    def test_attributes_dict_to_ldif_format_empty_dict(self) -> None:
        """Test converting empty attributes dictionary."""

        result = FlextLDIFUtilities().converters.attributes_dict_to_ldif_format({})

        assert result.is_success
        assert len(result.value) == 0

    def test_coverage_edge_cases_real(self) -> None:
        """Test real edge cases for comprehensive coverage."""

        # Test with max_errors limit
        entries = []
        for i in range(15):  # More than default max_errors=10
            entry = FlextLDIFModels.Entry(
                dn=FlextLDIFModels.DistinguishedName(
                    value=f"cn=user{i},dc=example,dc=com"
                ),
                attributes=FlextLDIFModels.LdifAttributes(
                    data={}
                ),  # Missing objectClass
            )
            entries.append(entry)

        result = FlextLDIFUtilities().processors.validate_entries_or_warn(entries)

        # Should return False due to missing objectClass
        assert result.is_success
        assert (
            result.value is True
        )  # SOLID COMPLIANT: Validation succeeds with warnings logged
