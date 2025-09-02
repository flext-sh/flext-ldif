"""Tests for FlextLDIFAnalyticsService - comprehensive coverage."""

import pytest

from flext_ldif.constants import FlextLDIFAnalyticsConstants
from flext_ldif.models import FlextLDIFConfig, FlextLDIFEntry
from flext_ldif.services import FlextLDIFAnalyticsService


class TestFlextLDIFAnalyticsService:
    """Test analytics service functionality."""

    def test_service_initialization(self) -> None:
        """Test service can be initialized."""
        service = FlextLDIFAnalyticsService()
        assert service.config is not None
        assert isinstance(service.config, FlextLDIFConfig)

    def test_service_initialization_with_config(self) -> None:
        """Test service can be initialized with custom config."""
        config = FlextLDIFConfig(strict_validation=True)
        service = FlextLDIFAnalyticsService(config=config)
        assert service.config.strict_validation is True

    def test_execute_default(self) -> None:
        """Test default execute method."""
        service = FlextLDIFAnalyticsService()
        result = service.execute()

        assert result.is_success
        assert result.value is not None
        assert FlextLDIFAnalyticsConstants.TOTAL_ENTRIES_KEY in result.value
        assert result.value[FlextLDIFAnalyticsConstants.TOTAL_ENTRIES_KEY] == 0

    def test_analyze_entry_patterns_empty_list(self) -> None:
        """Test analyzing empty entry list."""
        service = FlextLDIFAnalyticsService()
        result = service.analyze_entry_patterns([])

        assert result.is_success
        assert result.value is not None
        assert result.value[FlextLDIFAnalyticsConstants.TOTAL_ENTRIES_KEY] == 0
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_CN_KEY] == 0
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_MAIL_KEY] == 0
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_TELEPHONE_KEY] == 0

    def test_analyze_entry_patterns_with_cn(
        self, sample_entry_with_cn: FlextLDIFEntry
    ) -> None:
        """Test analyzing entries with CN attribute."""
        service = FlextLDIFAnalyticsService()
        result = service.analyze_entry_patterns([sample_entry_with_cn])

        assert result.is_success
        assert result.value is not None
        assert result.value[FlextLDIFAnalyticsConstants.TOTAL_ENTRIES_KEY] == 1
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_CN_KEY] == 1
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_MAIL_KEY] == 0
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_TELEPHONE_KEY] == 0

    def test_analyze_entry_patterns_with_mail(
        self, sample_entry_with_mail: FlextLDIFEntry
    ) -> None:
        """Test analyzing entries with mail attribute."""
        service = FlextLDIFAnalyticsService()
        result = service.analyze_entry_patterns([sample_entry_with_mail])

        assert result.is_success
        assert result.value is not None
        assert result.value[FlextLDIFAnalyticsConstants.TOTAL_ENTRIES_KEY] == 1
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_CN_KEY] == 0
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_MAIL_KEY] == 1
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_TELEPHONE_KEY] == 0

    def test_analyze_entry_patterns_with_telephone(
        self, sample_entry_with_telephone: FlextLDIFEntry
    ) -> None:
        """Test analyzing entries with telephoneNumber attribute."""
        service = FlextLDIFAnalyticsService()
        result = service.analyze_entry_patterns([sample_entry_with_telephone])

        assert result.is_success
        assert result.value is not None
        assert result.value[FlextLDIFAnalyticsConstants.TOTAL_ENTRIES_KEY] == 1
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_CN_KEY] == 0
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_MAIL_KEY] == 0
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_TELEPHONE_KEY] == 1

    def test_analyze_entry_patterns_multiple_attributes(self) -> None:
        """Test analyzing entry with multiple tracked attributes."""
        entry = FlextLDIFEntry.model_validate(
            {
                "dn": "cn=John Doe,ou=people,dc=example,dc=com",
                "attributes": {
                    "cn": ["John Doe"],
                    "mail": ["john@example.com"],
                    "telephoneNumber": ["+1234567890"],
                    "objectClass": ["person", "inetOrgPerson"],
                },
            }
        )

        service = FlextLDIFAnalyticsService()
        result = service.analyze_entry_patterns([entry])

        assert result.is_success
        assert result.value is not None
        assert result.value[FlextLDIFAnalyticsConstants.TOTAL_ENTRIES_KEY] == 1
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_CN_KEY] == 1
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_MAIL_KEY] == 1
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_TELEPHONE_KEY] == 1

    def test_analyze_entry_patterns_multiple_entries(
        self,
        sample_entry_with_cn: FlextLDIFEntry,
        sample_entry_with_mail: FlextLDIFEntry,
    ) -> None:
        """Test analyzing multiple entries."""
        service = FlextLDIFAnalyticsService()
        result = service.analyze_entry_patterns(
            [
                sample_entry_with_cn,
                sample_entry_with_mail,
            ]
        )

        assert result.is_success
        assert result.value is not None
        assert result.value[FlextLDIFAnalyticsConstants.TOTAL_ENTRIES_KEY] == 2
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_CN_KEY] == 1
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_MAIL_KEY] == 1
        assert result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_TELEPHONE_KEY] == 0

    def test_analyze_entry_patterns_large_dataset(self) -> None:
        """Test analyzing large dataset performance."""
        # Create 100 entries with varying attributes
        entries = []
        for i in range(100):
            attrs = {"objectClass": ["person"]}
            if i % 3 == 0:
                attrs["cn"] = [f"Person {i}"]
            if i % 4 == 0:
                attrs["mail"] = [f"person{i}@example.com"]
            if i % 5 == 0:
                attrs["telephoneNumber"] = [f"+123456{i:04d}"]

            entry = FlextLDIFEntry.model_validate(
                {
                    "dn": f"cn=person{i},ou=people,dc=example,dc=com",
                    "attributes": attrs,
                }
            )
            entries.append(entry)

        service = FlextLDIFAnalyticsService()
        result = service.analyze_entry_patterns(entries)

        assert result.is_success
        assert result.value is not None
        assert result.value[FlextLDIFAnalyticsConstants.TOTAL_ENTRIES_KEY] == 100
        # Verify counts match expected patterns
        assert (
            result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_CN_KEY] == 34
        )  # 0, 3, 6, 9, ... up to 99
        assert (
            result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_MAIL_KEY] == 25
        )  # 0, 4, 8, 12, ... up to 96
        assert (
            result.value[FlextLDIFAnalyticsConstants.ENTRIES_WITH_TELEPHONE_KEY] == 20
        )  # 0, 5, 10, 15, ... up to 95

    def test_get_objectclass_distribution_empty_list(self) -> None:
        """Test objectClass distribution with empty list."""
        service = FlextLDIFAnalyticsService()
        result = service.get_objectclass_distribution([])

        assert result.is_success
        assert result.value is not None
        assert result.value == {}

    def test_get_objectclass_distribution_single_entry(self) -> None:
        """Test objectClass distribution with single entry."""
        entry = FlextLDIFEntry.model_validate(
            {
                "dn": "cn=John Doe,ou=people,dc=example,dc=com",
                "attributes": {
                    "cn": ["John Doe"],
                    "objectClass": ["person", "inetOrgPerson"],
                },
            }
        )

        service = FlextLDIFAnalyticsService()
        result = service.get_objectclass_distribution([entry])

        assert result.is_success
        assert result.value is not None
        assert result.value["person"] == 1
        assert result.value["inetOrgPerson"] == 1

    def test_get_objectclass_distribution_multiple_entries(self) -> None:
        """Test objectClass distribution with multiple entries."""
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=John,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"]},
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["organizationalUnit"]},
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=Jane,dc=example,dc=com",
                    "attributes": {"objectClass": ["person", "inetOrgPerson"]},
                }
            ),
        ]

        service = FlextLDIFAnalyticsService()
        result = service.get_objectclass_distribution(entries)

        assert result.is_success
        assert result.value is not None
        assert result.value["person"] == 2
        assert result.value["organizationalUnit"] == 1
        assert result.value["inetOrgPerson"] == 1

    def test_get_dn_depth_analysis_empty_list(self) -> None:
        """Test DN depth analysis with empty list."""
        service = FlextLDIFAnalyticsService()
        result = service.get_dn_depth_analysis([])

        assert result.is_success
        assert result.value is not None
        assert result.value == {}

    def test_get_dn_depth_analysis_various_depths(self) -> None:
        """Test DN depth analysis with entries of various depths."""
        entries = [
            FlextLDIFEntry.model_validate(
                {
                    "dn": "dc=com",  # depth 1
                    "attributes": {"objectClass": ["dcObject"]},
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "dc=example,dc=com",  # depth 2
                    "attributes": {"objectClass": ["dcObject"]},
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "ou=people,dc=example,dc=com",  # depth 3
                    "attributes": {"objectClass": ["organizationalUnit"]},
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=John,ou=people,dc=example,dc=com",  # depth 4
                    "attributes": {"objectClass": ["person"]},
                }
            ),
            FlextLDIFEntry.model_validate(
                {
                    "dn": "cn=Jane,ou=people,dc=example,dc=com",  # depth 4
                    "attributes": {"objectClass": ["person"]},
                }
            ),
        ]

        service = FlextLDIFAnalyticsService()
        result = service.get_dn_depth_analysis(entries)

        assert result.is_success
        assert result.value is not None

        # Check depth distribution using the constant format
        depth_1_key = FlextLDIFAnalyticsConstants.DEPTH_KEY_FORMAT.format(depth=1)
        depth_2_key = FlextLDIFAnalyticsConstants.DEPTH_KEY_FORMAT.format(depth=2)
        depth_3_key = FlextLDIFAnalyticsConstants.DEPTH_KEY_FORMAT.format(depth=3)
        depth_4_key = FlextLDIFAnalyticsConstants.DEPTH_KEY_FORMAT.format(depth=4)

        assert result.value[depth_1_key] == 1
        assert result.value[depth_2_key] == 1
        assert result.value[depth_3_key] == 1
        assert result.value[depth_4_key] == 2


@pytest.fixture
def sample_entry_with_cn() -> FlextLDIFEntry:
    """Create sample entry with CN attribute."""
    return FlextLDIFEntry.model_validate(
        {
            "dn": "cn=John Doe,ou=people,dc=example,dc=com",
            "attributes": {"cn": ["John Doe"], "objectClass": ["person"]},
        }
    )


@pytest.fixture
def sample_entry_with_mail() -> FlextLDIFEntry:
    """Create sample entry with mail attribute."""
    return FlextLDIFEntry.model_validate(
        {
            "dn": "uid=jane,ou=people,dc=example,dc=com",
            "attributes": {
                "mail": ["jane@example.com"],
                "objectClass": ["inetOrgPerson"],
            },
        }
    )


@pytest.fixture
def sample_entry_with_telephone() -> FlextLDIFEntry:
    """Create sample entry with telephoneNumber attribute."""
    return FlextLDIFEntry.model_validate(
        {
            "dn": "uid=bob,ou=people,dc=example,dc=com",
            "attributes": {
                "telephoneNumber": ["+1234567890"],
                "objectClass": ["person"],
            },
        }
    )
