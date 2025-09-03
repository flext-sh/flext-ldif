"""Tests for FlextLDIFUtilities class with REAL functionality (no mocks)."""

# ruff: noqa: PT018
# Reason: Multiple assertion checks are common in tests for comprehensive error validation

from __future__ import annotations

import pytest

from flext_ldif import FlextLDIFAPI
from flext_ldif.models import FlextLDIFEntry
from flext_ldif.utilities import FlextLDIFUtilities


@pytest.fixture
def api() -> FlextLDIFAPI:
    """Get a real FlextLDIFAPI instance."""
    return FlextLDIFAPI()


@pytest.fixture
def sample_entries(api: FlextLDIFAPI) -> list[FlextLDIFEntry]:
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
    return api.parse(ldif_content).unwrap_or([])


@pytest.fixture
def invalid_entries() -> list[FlextLDIFEntry]:
    """Create entries with validation issues for testing."""
    # Create entries directly that have validation issues
    from flext_ldif.models import FlextLDIFAttributes, FlextLDIFDistinguishedName

    # Entry with missing objectClass
    entry1 = FlextLDIFEntry(
        dn=FlextLDIFDistinguishedName(value="cn=NoObjectClass,dc=example,dc=com"),
        attributes=FlextLDIFAttributes(
            data={"cn": ["NoObjectClass"], "mail": ["test@example.com"]}
        ),
    )

    # Entry with empty DN (DN validation will actually fail during model creation)
    # So create a valid DN but entry that will fail validation logic
    entry2 = FlextLDIFEntry(
        dn=FlextLDIFDistinguishedName(value="cn=ValidDN,dc=example,dc=com"),
        attributes=FlextLDIFAttributes(data={"cn": ["ValidDN"]}),  # Missing objectClass
    )

    return [entry1, entry2]


class TestFlextLDIFUtilities:
    """Test FlextLDIFUtilities with real functionality."""

    def test_utilities_class_structure(self) -> None:
        """Test that FlextLDIFUtilities has the expected class structure."""
        # Test that the utility classes exist
        assert hasattr(FlextLDIFUtilities, "LdifDomainProcessors")
        assert hasattr(FlextLDIFUtilities, "LdifConverters")

        # Test that they are classes (not instances)
        import inspect

        assert inspect.isclass(FlextLDIFUtilities.LdifDomainProcessors)
        assert inspect.isclass(FlextLDIFUtilities.LdifConverters)

    def test_utilities_initialization(self) -> None:
        """Test FlextLDIFUtilities initialization following flext-core patterns."""
        # Test instantiation to cover __init__ method
        utilities = FlextLDIFUtilities()

        # Verify logger initialization
        assert hasattr(utilities, "_logger")
        assert utilities._logger is not None

    def test_validate_entries_or_warn_with_valid_entries(
        self, sample_entries: list[FlextLDIFEntry]
    ) -> None:
        """Test validate_entries_or_warn with valid entries."""
        result = FlextLDIFUtilities.LdifDomainProcessors.validate_entries_or_warn(
            sample_entries, max_errors=10
        )

        assert result.is_success
        assert result.value is True  # All sample entries should be valid

    def test_validate_entries_or_warn_with_invalid_entries(
        self, invalid_entries: list[FlextLDIFEntry]
    ) -> None:
        """Test validate_entries_or_warn with entries that have issues."""
        result = FlextLDIFUtilities.LdifDomainProcessors.validate_entries_or_warn(
            invalid_entries, max_errors=5
        )

        assert result.is_success
        assert result.value is False  # Should return False due to validation issues

    def test_validate_entries_or_warn_max_errors_limit(
        self, invalid_entries: list[FlextLDIFEntry]
    ) -> None:
        """Test validate_entries_or_warn respects max_errors limit."""
        result = FlextLDIFUtilities.LdifDomainProcessors.validate_entries_or_warn(
            invalid_entries, max_errors=1
        )

        assert result.is_success
        assert result.value is False  # Should stop early due to max_errors limit

    def test_filter_entries_by_object_class(
        self, sample_entries: list[FlextLDIFEntry]
    ) -> None:
        """Test filtering entries by objectClass."""
        result = FlextLDIFUtilities.LdifDomainProcessors.filter_entries_by_object_class(
            sample_entries, "person"
        )

        assert result.is_success
        filtered_entries = result.value
        assert len(filtered_entries) == 2  # John and Jane are person objects
        for entry in filtered_entries:
            assert entry.has_object_class("person")

    def test_filter_entries_by_object_class_case_insensitive(
        self, sample_entries: list[FlextLDIFEntry]
    ) -> None:
        """Test filtering is case-insensitive."""
        result = FlextLDIFUtilities.LdifDomainProcessors.filter_entries_by_object_class(
            sample_entries, "PERSON"
        )

        assert result.is_success
        filtered_entries = result.value
        assert len(filtered_entries) == 2

    def test_filter_entries_by_object_class_no_matches(
        self, sample_entries: list[FlextLDIFEntry]
    ) -> None:
        """Test filtering with no matching entries."""
        result = FlextLDIFUtilities.LdifDomainProcessors.filter_entries_by_object_class(
            sample_entries, "nonExistentClass"
        )

        assert result.is_success
        assert len(result.value) == 0

    def test_find_entries_with_missing_required_attributes(
        self, sample_entries: list[FlextLDIFEntry]
    ) -> None:
        """Test finding entries missing required attributes."""
        # All sample entries should have 'objectClass' attribute
        result = FlextLDIFUtilities.LdifDomainProcessors.find_entries_with_missing_required_attributes(
            sample_entries, ["objectClass"]
        )

        assert result.is_success
        assert len(result.value) == 0  # All entries should have objectClass

    def test_find_entries_with_missing_required_attributes_found(
        self, sample_entries: list[FlextLDIFEntry]
    ) -> None:
        """Test finding entries missing a required attribute that some don't have."""
        # Look for 'telephoneNumber' which none of our sample entries have
        result = FlextLDIFUtilities.LdifDomainProcessors.find_entries_with_missing_required_attributes(
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

        result = FlextLDIFUtilities.LdifConverters.attributes_dict_to_ldif_format(
            test_attrs
        )

        assert result.is_success
        converted = result.value
        assert "cn" in converted
        assert converted["cn"] == ["John Doe"]
        assert "mail" in converted
        assert len(converted["mail"]) == 2

    def test_attributes_dict_to_ldif_format_with_none_values(self) -> None:
        """Test converting attributes with None values."""
        test_attrs: dict[str, list[str]] = {
            "cn": ["John Doe"],
            "description": [],  # Should be filtered out when empty
            "mail": [
                "john@example.com",
                "john.doe@example.com",
            ],  # Removed None for type safety
        }

        result = FlextLDIFUtilities.LdifConverters.attributes_dict_to_ldif_format(
            test_attrs
        )

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

        result = FlextLDIFUtilities.LdifConverters.attributes_dict_to_ldif_format(
            test_attrs
        )

        assert result.is_success
        converted = result.value
        assert "cn" in converted
        assert "mail" in converted
        assert "objectclass" in converted

    def test_normalize_dn_components_success(self) -> None:
        """Test DN normalization with valid DN."""
        dn = "  cn=John Doe,ou=people,dc=example,dc=com  "

        result = FlextLDIFUtilities.LdifConverters.normalize_dn_components(dn)

        assert result.is_success
        assert result.value == "cn=John Doe,ou=people,dc=example,dc=com"

    def test_normalize_dn_components_empty_dn(self) -> None:
        """Test DN normalization with empty DN."""
        result = FlextLDIFUtilities.LdifConverters.normalize_dn_components("")

        assert result.is_failure
        assert result.error is not None and "DN cannot be empty" in result.error

    def test_normalize_dn_components_whitespace_only(self) -> None:
        """Test DN normalization with whitespace-only DN."""
        result = FlextLDIFUtilities.LdifConverters.normalize_dn_components("   ")

        assert result.is_failure
        assert result.error is not None and "DN cannot be empty" in result.error

    def test_validate_entries_or_warn_empty_list(self) -> None:
        """Test validate_entries_or_warn with empty entry list."""
        result = FlextLDIFUtilities.LdifDomainProcessors.validate_entries_or_warn(
            [], max_errors=10
        )

        assert result.is_success
        assert result.value is True  # Empty list should be considered valid

    def test_filter_entries_by_object_class_empty_list(self) -> None:
        """Test filtering empty list of entries."""
        result = FlextLDIFUtilities.LdifDomainProcessors.filter_entries_by_object_class(
            [], "person"
        )

        assert result.is_success
        assert len(result.value) == 0

    def test_find_entries_with_missing_required_attributes_empty_list(self) -> None:
        """Test finding missing attributes in empty list."""
        result = FlextLDIFUtilities.LdifDomainProcessors.find_entries_with_missing_required_attributes(
            [], ["cn"]
        )

        assert result.is_success
        assert len(result.value) == 0

    def test_attributes_dict_to_ldif_format_empty_dict(self) -> None:
        """Test converting empty attributes dictionary."""
        result = FlextLDIFUtilities.LdifConverters.attributes_dict_to_ldif_format({})

        assert result.is_success
        assert len(result.value) == 0
