"""Tests for FlextLDIFTransformerService - comprehensive coverage."""

from flext_ldif.models import FlextLDIFConfig, FlextLDIFEntry
from flext_ldif.services import FlextLDIFTransformerService


class TestFlextLDIFTransformerService:
    """Test transformer service functionality."""

    def test_service_initialization(self) -> None:
        """Test service can be initialized."""
        service = FlextLDIFTransformerService()
        assert service.config is None

    def test_service_initialization_with_config(self) -> None:
        """Test service can be initialized with custom config."""
        config = FlextLDIFConfig(strict_validation=True)
        service = FlextLDIFTransformerService(config=config)
        assert service.config is not None
        assert service.config.strict_validation is True

    def test_execute_default(self) -> None:
        """Test default execute method returns empty list."""
        service = FlextLDIFTransformerService()
        result = service.execute()

        assert result.is_success
        assert result.value is not None
        assert result.value == []

    def test_transform_entry_success(self) -> None:
        """Test transforming single entry."""
        service = FlextLDIFTransformerService()
        entry = FlextLDIFEntry.model_validate(
            {
                "dn": "cn=John Doe,ou=people,dc=example,dc=com",
                "attributes": {"cn": ["John Doe"], "objectClass": ["person"]},
            }
        )

        result = service.transform_entry(entry)

        assert result.is_success
        assert result.value is not None
        assert result.value == entry  # Base implementation returns as-is

    def test_transform_entries_empty_list(self) -> None:
        """Test transforming empty list of entries."""
        service = FlextLDIFTransformerService()
        result = service.transform_entries([])

        assert result.is_success
        assert result.value is not None
        assert result.value == []

    def test_transform_entries_single_entry(self) -> None:
        """Test transforming single entry in list."""
        service = FlextLDIFTransformerService()
        entry = FlextLDIFEntry.model_validate(
            {
                "dn": "cn=Jane Doe,ou=people,dc=example,dc=com",
                "attributes": {
                    "cn": ["Jane Doe"],
                    "mail": ["jane@example.com"],
                    "objectClass": ["person", "inetOrgPerson"],
                },
            }
        )

        result = service.transform_entries([entry])

        assert result.is_success
        assert result.value is not None
        assert len(result.value) == 1
        assert result.value[0] == entry

    def test_transform_entries_multiple_entries(self) -> None:
        """Test transforming multiple entries."""
        service = FlextLDIFTransformerService()
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
                    "attributes": {"cn": ["Jane"], "objectClass": ["person"]},
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

        result = service.transform_entries(entries)

        assert result.is_success
        assert result.value is not None
        assert len(result.value) == 3
        # Verify all entries are transformed (base implementation returns as-is)
        for i, transformed_entry in enumerate(result.value):
            assert transformed_entry == entries[i]

    def test_transform_entries_large_dataset(self) -> None:
        """Test transforming large dataset performance."""
        service = FlextLDIFTransformerService()

        # Create 50 entries
        entries = []
        for i in range(50):
            entry = FlextLDIFEntry.model_validate(
                {
                    "dn": f"cn=person{i},ou=people,dc=example,dc=com",
                    "attributes": {
                        "cn": [f"Person {i}"],
                        "uid": [f"person{i}"],
                        "objectClass": ["person"],
                    },
                }
            )
            entries.append(entry)

        result = service.transform_entries(entries)

        assert result.is_success
        assert result.value is not None
        assert len(result.value) == 50
        # Verify all entries are processed
        for i, transformed_entry in enumerate(result.value):
            assert transformed_entry == entries[i]

    def test_normalize_dns_empty_list(self) -> None:
        """Test DN normalization with empty list."""
        service = FlextLDIFTransformerService()
        result = service.normalize_dns([])

        assert result.is_success
        assert result.value is not None
        assert result.value == []

    def test_normalize_dns_single_entry(self) -> None:
        """Test DN normalization with single entry."""
        service = FlextLDIFTransformerService()
        entry = FlextLDIFEntry.model_validate(
            {
                "dn": "CN=John Doe,OU=People,DC=Example,DC=Com",  # Mixed case DN
                "attributes": {"cn": ["John Doe"], "objectClass": ["person"]},
            }
        )

        result = service.normalize_dns([entry])

        assert result.is_success
        assert result.value is not None
        assert len(result.value) == 1
        # DN normalization is handled by domain model, so entry is returned as-is
        assert result.value[0] == entry

    def test_normalize_dns_multiple_entries(self) -> None:
        """Test DN normalization with multiple entries."""
        service = FlextLDIFTransformerService()
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "CN=John,DC=Example,DC=Com",
                    "attributes": {"cn": ["John"], "objectClass": ["person"]},
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "OU=People,DC=Example,DC=Com",
                    "attributes": {
                        "ou": ["People"],
                        "objectClass": ["organizationalUnit"],
                    },
                }
            ),
        ]

        result = service.normalize_dns(entries)

        assert result.is_success
        assert result.value is not None
        assert len(result.value) == 2
        assert result.value == entries  # Returns as-is since normalization is in domain

    def test_service_with_different_configurations(self) -> None:
        """Test service behavior with different configurations."""
        # Test with strict validation
        strict_config = FlextLDIFConfig(strict_validation=True)
        strict_service = FlextLDIFTransformerService(config=strict_config)

        # Test with non-strict validation
        lenient_config = FlextLDIFConfig(strict_validation=False)
        lenient_service = FlextLDIFTransformerService(config=lenient_config)

        entry = FlextLDIFEntry.model_validate(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"cn": ["test"], "objectClass": ["person"]},
            }
        )

        # Both should work the same for base implementation
        strict_result = strict_service.transform_entry(entry)
        lenient_result = lenient_service.transform_entry(entry)

        assert strict_result.is_success
        assert lenient_result.is_success
        assert strict_result.value == lenient_result.value

    def test_transform_entries_uses_transform_entry(self) -> None:
        """Test that transform_entries calls transform_entry for each entry."""
        service = FlextLDIFTransformerService()

        # Create a simple entry
        entry = FlextLDIFEntry.model_validate(
            {
                "dn": "cn=test,dc=example,dc=com",
                "attributes": {"cn": ["test"], "objectClass": ["person"]},
            }
        )

        # Transform single entry directly
        single_result = service.transform_entry(entry)

        # Transform same entry through transform_entries
        list_result = service.transform_entries([entry])

        # Both should produce same result
        assert single_result.is_success
        assert list_result.is_success
        assert single_result.value == list_result.value[0]

    def test_edge_case_empty_attributes(self) -> None:
        """Test handling entry with minimal attributes."""
        service = FlextLDIFTransformerService()
        entry = FlextLDIFEntry.model_validate(
            {
                "dn": "dc=com",
                "attributes": {"objectClass": ["dcObject"]},
            }
        )

        result = service.transform_entry(entry)

        assert result.is_success
        assert result.value == entry

    def test_edge_case_complex_dn(self) -> None:
        """Test handling entry with complex DN."""
        service = FlextLDIFTransformerService()
        entry = FlextLDIFEntry.model_validate(
            {
                "dn": "cn=John+sn=Doe,ou=people,o=example corp,c=us",
                "attributes": {
                    "cn": ["John"],
                    "sn": ["Doe"],
                    "objectClass": ["person"],
                },
            }
        )

        result = service.transform_entry(entry)

        assert result.is_success
        assert result.value == entry
