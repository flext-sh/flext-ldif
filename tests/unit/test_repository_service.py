"""Tests for FlextLDIFRepositoryService - comprehensive coverage."""

# ruff: noqa: PT018
# Reason: Multiple assertion checks are common in tests for comprehensive error validation

from flext_ldif.constants import FlextLDIFValidationMessages
from flext_ldif.models import FlextLDIFConfig, FlextLDIFEntry
from flext_ldif.services import FlextLDIFRepositoryService


class TestFlextLDIFRepositoryService:
    """Test repository service functionality."""

    def test_service_initialization(self) -> None:
        """Test service can be initialized."""
        service = FlextLDIFRepositoryService()
        assert service.config is None

    def test_service_initialization_with_config(self) -> None:
        """Test service can be initialized with custom config."""
        config = FlextLDIFConfig(strict_validation=True)
        service = FlextLDIFRepositoryService(config=config)
        assert service.config is not None
        assert service.config.strict_validation is True

    def test_execute_default(self) -> None:
        """Test default execute method returns empty dict."""
        service = FlextLDIFRepositoryService()
        result = service.execute()

        assert result.is_success
        assert result.value is not None
        assert result.value == {}

    def test_find_by_dn_empty_dn(self) -> None:
        """Test find_by_dn with empty DN."""
        service = FlextLDIFRepositoryService()
        entries = []

        result = service.find_by_dn(entries, "")

        assert result.is_failure
        assert (
            result.error is not None
            and FlextLDIFValidationMessages.DN_EMPTY_ERROR in result.error
        )

    def test_find_by_dn_whitespace_only_dn(self) -> None:
        """Test find_by_dn with whitespace-only DN."""
        service = FlextLDIFRepositoryService()
        entries = []

        result = service.find_by_dn(entries, "   ")

        assert result.is_failure
        assert (
            result.error is not None
            and FlextLDIFValidationMessages.DN_EMPTY_ERROR in result.error
        )

    def test_find_by_dn_not_found(self) -> None:
        """Test find_by_dn when entry not found."""
        service = FlextLDIFRepositoryService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=John,dc=example,dc=com",
                    "attributes": {"cn": ["John"], "objectClass": ["person"]},
                }
            )
        ]

        result = service.find_by_dn(entries, "cn=Jane,dc=example,dc=com")

        assert result.is_success
        assert result.value is None

    def test_find_by_dn_found_exact_match(self) -> None:
        """Test find_by_dn when entry is found with exact match."""
        service = FlextLDIFRepositoryService()
        entry = FlextLDIFEntry.model_validate(
            {
                "dn": "cn=John Doe,ou=people,dc=example,dc=com",
                "attributes": {"cn": ["John Doe"], "objectClass": ["person"]},
            }
        )
        entries = [entry]

        result = service.find_by_dn(entries, "cn=John Doe,ou=people,dc=example,dc=com")

        assert result.is_success
        assert result.value == entry

    def test_find_by_dn_case_insensitive(self) -> None:
        """Test find_by_dn is case insensitive."""
        service = FlextLDIFRepositoryService()
        entry = FlextLDIFEntry.model_validate(
            {
                "dn": "CN=John Doe,OU=People,DC=Example,DC=Com",
                "attributes": {"cn": ["John Doe"], "objectClass": ["person"]},
            }
        )
        entries = [entry]

        result = service.find_by_dn(entries, "cn=john doe,ou=people,dc=example,dc=com")

        assert result.is_success
        assert result.value == entry

    def test_find_by_dn_multiple_entries(self) -> None:
        """Test find_by_dn with multiple entries."""
        service = FlextLDIFRepositoryService()
        entry1 = FlextLDIFEntry.model_validate(
            {
                "dn": "cn=John,dc=example,dc=com",
                "attributes": {"cn": ["John"], "objectClass": ["person"]},
            }
        )
        entry2 = FlextLDIFEntry.model_validate(
            {
                "dn": "cn=Jane,dc=example,dc=com",
                "attributes": {"cn": ["Jane"], "objectClass": ["person"]},
            }
        )
        entries = [entry1, entry2]

        result = service.find_by_dn(entries, "cn=Jane,dc=example,dc=com")

        assert result.is_success
        assert result.value == entry2

    def test_filter_by_objectclass_empty_objectclass(self) -> None:
        """Test filter_by_objectclass with empty objectclass."""
        service = FlextLDIFRepositoryService()
        entries = []

        result = service.filter_by_objectclass(entries, "")

        assert result.is_failure
        assert result.error is not None and (
            "Object class cannot be empty" in result.error
            or FlextLDIFCoreMessages.MISSING_OBJECTCLASS in result.error
        )

    def test_filter_by_objectclass_whitespace_only(self) -> None:
        """Test filter_by_objectclass with whitespace-only objectclass."""
        service = FlextLDIFRepositoryService()
        entries = []

        result = service.filter_by_objectclass(entries, "   ")

        assert result.is_failure
        assert result.error is not None and (
            "Object class cannot be empty" in result.error
            or FlextLDIFCoreMessages.MISSING_OBJECTCLASS in result.error
        )

    def test_filter_by_objectclass_no_matches(self) -> None:
        """Test filter_by_objectclass with no matches."""
        service = FlextLDIFRepositoryService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=John,dc=example,dc=com",
                    "attributes": {"cn": ["John"], "objectClass": ["person"]},
                }
            )
        ]

        result = service.filter_by_objectclass(entries, "organizationalUnit")

        assert result.is_success
        assert result.value == []

    def test_filter_by_objectclass_with_matches(self) -> None:
        """Test filter_by_objectclass with matches."""
        service = FlextLDIFRepositoryService()
        person_entry = FlextLDIFEntry.model_validate(
            {
                "dn": "cn=John,dc=example,dc=com",
                "attributes": {
                    "cn": ["John"],
                    "objectClass": ["person", "inetOrgPerson"],
                },
            }
        )
        org_entry = FlextLDIFEntry.model_validate(
            {
                "dn": "ou=people,dc=example,dc=com",
                "attributes": {"ou": ["people"], "objectClass": ["organizationalUnit"]},
            }
        )
        entries = [person_entry, org_entry]

        result = service.filter_by_objectclass(entries, "person")

        assert result.is_success
        assert len(result.value) == 1
        assert result.value[0] == person_entry

    def test_filter_by_objectclass_multiple_matches(self) -> None:
        """Test filter_by_objectclass with multiple matches."""
        service = FlextLDIFRepositoryService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=John,dc=example,dc=com",
                    "attributes": {"cn": ["John"], "objectClass": ["person"]},
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=Jane,dc=example,dc=com",
                    "attributes": {
                        "cn": ["Jane"],
                        "objectClass": ["person", "inetOrgPerson"],
                    },
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "ou=people,dc=example,dc=com",
                    "attributes": {
                        "ou": ["people"],
                        "objectClass": ["organizationalUnit"],
                    },
                }
            ),
        ]

        result = service.filter_by_objectclass(entries, "person")

        assert result.is_success
        assert len(result.value) == 2

    def test_filter_by_attribute_empty_attribute(self) -> None:
        """Test filter_by_attribute with empty attribute name."""
        service = FlextLDIFRepositoryService()
        entries = []

        result = service.filter_by_attribute(entries, "", "value")

        assert result.is_failure
        assert result.error is not None and "attribute" in result.error

    def test_filter_by_attribute_whitespace_attribute(self) -> None:
        """Test filter_by_attribute with whitespace-only attribute name."""
        service = FlextLDIFRepositoryService()
        entries = []

        result = service.filter_by_attribute(entries, "   ", "value")

        assert result.is_failure
        assert result.error is not None and "attribute" in result.error

    def test_filter_by_attribute_no_matches(self) -> None:
        """Test filter_by_attribute with no matches."""
        service = FlextLDIFRepositoryService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=John,dc=example,dc=com",
                    "attributes": {
                        "cn": ["John"],
                        "sn": ["Doe"],
                        "objectClass": ["person"],
                    },
                }
            )
        ]

        result = service.filter_by_attribute(entries, "cn", "Jane")

        assert result.is_success
        assert result.value == []

    def test_filter_by_attribute_with_matches(self) -> None:
        """Test filter_by_attribute with matches."""
        service = FlextLDIFRepositoryService()
        john_entry = FlextLDIFEntry.model_validate(
            {
                "dn": "cn=John Doe,dc=example,dc=com",
                "attributes": {
                    "cn": ["John Doe"],
                    "givenName": ["John"],
                    "objectClass": ["person"],
                },
            }
        )
        jane_entry = FlextLDIFEntry.model_validate(
            {
                "dn": "cn=Jane Smith,dc=example,dc=com",
                "attributes": {
                    "cn": ["Jane Smith"],
                    "givenName": ["Jane"],
                    "objectClass": ["person"],
                },
            }
        )
        entries = [john_entry, jane_entry]

        result = service.filter_by_attribute(entries, "givenName", "John")

        assert result.is_success
        assert len(result.value) == 1
        assert result.value[0] == john_entry

    def test_filter_by_attribute_no_attribute_values(self) -> None:
        """Test filter_by_attribute when entry has no values for attribute."""
        service = FlextLDIFRepositoryService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=John,dc=example,dc=com",
                    "attributes": {"cn": ["John"], "objectClass": ["person"]},
                }
            )
        ]

        result = service.filter_by_attribute(entries, "mail", "john@example.com")

        assert result.is_success
        assert result.value == []

    def test_get_statistics_empty_list(self) -> None:
        """Test get_statistics with empty list."""
        service = FlextLDIFRepositoryService()

        result = service.get_statistics([])

        assert result.is_success
        assert result.value == {
            "total_entries": 0,
            "person_entries": 0,
            "group_entries": 0,
            "other_entries": 0,
        }

    def test_get_statistics_with_person_entries(self) -> None:
        """Test get_statistics with person entries."""
        service = FlextLDIFRepositoryService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=John,dc=example,dc=com",
                    "attributes": {"cn": ["John"], "objectClass": ["person"]},
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=Jane,dc=example,dc=com",
                    "attributes": {"cn": ["Jane"], "objectClass": ["inetOrgPerson"]},
                }
            ),
        ]

        result = service.get_statistics(entries)

        assert result.is_success
        assert result.value["total_entries"] == 2
        assert result.value["person_entries"] == 2
        assert result.value["group_entries"] == 0
        assert result.value["other_entries"] == 0

    def test_get_statistics_with_group_entries(self) -> None:
        """Test get_statistics with group entries."""
        service = FlextLDIFRepositoryService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=admins,ou=groups,dc=example,dc=com",
                    "attributes": {"cn": ["admins"], "objectClass": ["groupOfNames"]},
                }
            )
        ]

        result = service.get_statistics(entries)

        assert result.is_success
        assert result.value["total_entries"] == 1
        assert result.value["person_entries"] == 0
        assert result.value["group_entries"] == 1
        assert result.value["other_entries"] == 0

    def test_get_statistics_with_other_entries(self) -> None:
        """Test get_statistics with other entry types."""
        service = FlextLDIFRepositoryService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "ou=people,dc=example,dc=com",
                    "attributes": {
                        "ou": ["people"],
                        "objectClass": ["organizationalUnit"],
                    },
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "dc=example,dc=com",
                    "attributes": {"dc": ["example"], "objectClass": ["dcObject"]},
                }
            ),
        ]

        result = service.get_statistics(entries)

        assert result.is_success
        assert result.value["total_entries"] == 2
        assert result.value["person_entries"] == 0
        assert result.value["group_entries"] == 0
        assert result.value["other_entries"] == 2

    def test_get_statistics_mixed_entries(self) -> None:
        """Test get_statistics with mixed entry types."""
        service = FlextLDIFRepositoryService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=John,dc=example,dc=com",
                    "attributes": {"cn": ["John"], "objectClass": ["person"]},
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=admins,ou=groups,dc=example,dc=com",
                    "attributes": {"cn": ["admins"], "objectClass": ["groupOfNames"]},
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "ou=people,dc=example,dc=com",
                    "attributes": {
                        "ou": ["people"],
                        "objectClass": ["organizationalUnit"],
                    },
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=Jane,dc=example,dc=com",
                    "attributes": {"cn": ["Jane"], "objectClass": ["inetOrgPerson"]},
                }
            ),
        ]

        result = service.get_statistics(entries)

        assert result.is_success
        assert result.value["total_entries"] == 4
        assert result.value["person_entries"] == 2
        assert result.value["group_entries"] == 1
        assert result.value["other_entries"] == 1
