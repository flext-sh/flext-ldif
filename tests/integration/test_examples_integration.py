"""Integration tests for examples workflows.

Tests the examples as complete workflows using the actual API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

from flext_ldif import FlextLdifAPI, FlextLdifConfig, FlextLdifModels


class TestBasicParsingWorkflow:
    """Test the basic parsing workflow from examples."""

    @staticmethod
    def test_basic_parsing_workflow(test_ldif_dir: Path) -> None:
        """Test basic LDIF parsing workflow."""
        # Create sample LDIF file
        sample_ldif = """dn: cn=John Doe,ou=people,dc=example,dc=com
cn: John Doe
sn: Doe
mail: john@example.com
objectClass: person
objectClass: inetOrgPerson

dn: cn=Jane Smith,ou=people,dc=example,dc=com
cn: Jane Smith
sn: Smith
mail: jane@example.com
objectClass: person
objectClass: inetOrgPerson

dn: ou=people,dc=example,dc=com
ou: people
objectClass: organizationalUnit
"""
        sample_file = test_ldif_dir / "sample_basic.ldif"
        sample_file.write_text(sample_ldif, encoding="utf-8")

        # Replicate basic parsing workflow
        config = FlextLdifConfig(
            ldif_strict_validation=True,
            ldif_max_entries=100,
            ldif_chunk_size=50,
        )
        api = FlextLdifAPI(config)

        # Parse LDIF file
        result = api.parse_ldif_file(sample_file)
        assert result.is_success
        entries = result.value
        assert len(entries) == 3

        # Get statistics
        stats_result = api.entry_statistics(entries)
        assert stats_result.is_success
        stats = stats_result.value
        assert stats["total_entries"] == 3

        # Validate first entry
        first_entry = entries[0]
        validation_result = first_entry.validate_business_rules()
        assert validation_result.is_success

        # Filter persons
        person_result = api.filter_persons(entries)
        assert person_result.is_success
        person_entries = person_result.value
        assert len(person_entries) == 2

        # Write filtered entries
        output_file = test_ldif_dir / "output_basic.ldif"
        write_result = api.write_file(person_entries, str(output_file))
        assert write_result.is_success
        assert output_file.exists()


class TestTransformationWorkflow:
    """Test transformation workflows."""

    @staticmethod
    def test_transformation_workflow() -> None:
        """Test entry transformation workflow."""
        # Create sample entries
        entry1_result = FlextLdifModels.Entry.create({
            "dn": "cn=test1,dc=example,dc=com",
            "attributes": {"cn": ["test1"], "objectClass": ["person"]},
        })
        entry2_result = FlextLdifModels.Entry.create({
            "dn": "cn=test2,dc=example,dc=com",
            "attributes": {"cn": ["test2"], "objectClass": ["person"]},
        })
        assert entry1_result.is_success
        assert entry2_result.is_success

        entries = [entry1_result.value, entry2_result.value]

        # Define transformer
        def uppercase_cn(entry: FlextLdifModels.Entry) -> FlextLdifModels.Entry:
            # Get current cn values
            cn_values = entry.get_attribute("cn") or []
            # Create new uppercased values
            new_cn_values = [cn.upper() for cn in cn_values]
            # Create new attributes dict with uppercased cn
            new_attrs_data = {**entry.attributes.data, "cn": new_cn_values}
            # Create new entry with transformed attributes
            new_entry_result = FlextLdifModels.Entry.create({
                "dn": entry.dn.value,
                "attributes": new_attrs_data,
            })
            return new_entry_result.value

        # Transform entries
        api = FlextLdifAPI()
        transform_result = api.transform(entries, uppercase_cn)
        assert transform_result.is_success
        transformed = transform_result.value
        assert len(transformed) == 2

        # Verify transformation
        cn_values = transformed[0].get_attribute("cn")
        assert cn_values is not None
        assert "TEST1" in cn_values


class TestAnalyticsWorkflow:
    """Test analytics workflows."""

    @staticmethod
    def test_analytics_workflow() -> None:
        """Test entry analytics workflow."""
        # Create diverse entries
        entries: list[FlextLdifModels.Entry] = []
        for i in range(5):
            entry_result = FlextLdifModels.Entry.create({
                "dn": f"cn=user{i},ou=people,dc=example,dc=com",
                "attributes": {
                    "cn": [f"user{i}"],
                    "objectClass": ["person", "inetOrgPerson"],
                    "mail": [f"user{i}@example.com"],
                },
            })
            if entry_result.is_success:
                entries.append(entry_result.value)

        # Analyze entries
        api = FlextLdifAPI()
        analyze_result = api.analyze(entries)
        assert analyze_result.is_success

        # Verify analytics
        stats_result = api.entry_statistics(entries)
        assert stats_result.is_success
        stats = stats_result.value
        assert stats["total_entries"] == 5

        object_class_counts = stats["object_class_counts"]
        assert isinstance(object_class_counts, dict)
        assert "person" in object_class_counts

        attribute_counts = stats["attribute_counts"]
        assert isinstance(attribute_counts, dict)
        assert "mail" in attribute_counts


class TestValidationWorkflow:
    """Test validation workflows."""

    @staticmethod
    def test_validation_workflow() -> None:
        """Test entry validation workflow."""
        # Create valid entry with required attributes for person
        valid_entry_result = FlextLdifModels.Entry.create(
            dn="cn=valid,dc=example,dc=com",
            attributes={
                "cn": ["valid"],
                "sn": ["Valid"],
                "objectClass": ["person"],
            },
        )
        assert valid_entry_result.is_success

        # Validate entry
        api = FlextLdifAPI()
        validation_result = api.validate_entries([valid_entry_result.value])
        assert validation_result.is_success

        # Test business rules
        entry = valid_entry_result.value
        business_result = entry.validate_business_rules()
        assert business_result.is_success


class TestFilteringWorkflow:
    """Test filtering workflows."""

    @staticmethod
    def test_object_class_filtering() -> None:
        """Test filtering by object class."""
        # Create mixed entries
        person_result = FlextLdifModels.Entry.create({
            "dn": "cn=person1,dc=example,dc=com",
            "attributes": {"cn": ["person1"], "objectClass": ["person"]},
        })
        ou_result = FlextLdifModels.Entry.create({
            "dn": "ou=group,dc=example,dc=com",
            "attributes": {"ou": ["group"], "objectClass": ["organizationalUnit"]},
        })
        assert person_result.is_success
        assert ou_result.is_success

        entries = [person_result.value, ou_result.value]

        # Filter by object class
        api = FlextLdifAPI()
        filter_result = api.filter_by_objectclass(entries, "person")
        assert filter_result.is_success
        filtered = filter_result.value
        assert len(filtered) == 1
        assert filtered[0].has_object_class("person")

    @staticmethod
    def test_custom_filtering() -> None:
        """Test custom filtering with predicate."""
        # Create entries with different depths
        shallow_result = FlextLdifModels.Entry.create({
            "dn": "dc=com",
            "attributes": {"dc": ["com"], "objectClass": ["dcObject"]},
        })
        deep_result = FlextLdifModels.Entry.create({
            "dn": "cn=test,ou=users,dc=example,dc=com",
            "attributes": {"cn": ["test"], "objectClass": ["person"]},
        })
        assert shallow_result.is_success
        assert deep_result.is_success

        entries = [shallow_result.value, deep_result.value]

        # Filter by DN depth
        def is_deep_dn(entry: FlextLdifModels.Entry) -> bool:
            return entry.dn.depth > 2

        filter_result = FlextLdifAPI.filter_entries(entries, is_deep_dn)
        assert filter_result.is_success
        filtered = filter_result.value
        assert len(filtered) == 1
        assert filtered[0].dn.depth > 2


class TestHealthCheckWorkflow:
    """Test health check workflows."""

    @staticmethod
    def test_health_check() -> None:
        """Test API health check."""
        api = FlextLdifAPI()
        health_result = api.health_check()
        assert health_result.is_success
        health_data = health_result.value
        assert health_data["status"] == "healthy"
        assert "timestamp" in health_data
        assert "config" in health_data

    @staticmethod
    def test_service_info() -> None:
        """Test service information."""
        api = FlextLdifAPI()
        service_info = api.get_service_info()
        assert service_info["api"] == "FlextLdifAPI"
        assert "capabilities" in service_info

        capabilities = service_info["capabilities"]
        assert isinstance(capabilities, list)
        assert "parse" in capabilities
        assert service_info["pattern"] == "railway_oriented_programming"
