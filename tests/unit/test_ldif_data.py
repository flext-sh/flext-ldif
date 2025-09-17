"""Tests for LDIF data module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.test_data import FlextLdifTestData
from flext_ldif.test_samples import FlextLdifTestSamples


class TestFlextLdifTestSamples:
    """Test LDIF sample data functionality."""

    def test_basic_ldif_content(self) -> None:
        """Test basic LDIF content."""
        assert "cn=test,dc=example,dc=com" in FlextLdifTestSamples.BASIC_LDIF
        assert "cn: test" in FlextLdifTestSamples.BASIC_LDIF
        assert "objectClass: person" in FlextLdifTestSamples.BASIC_LDIF
        assert "sn: TestUser" in FlextLdifTestSamples.BASIC_LDIF

    def test_complex_ldif_content(self) -> None:
        """Test complex LDIF content."""
        assert "cn=complex,dc=example,dc=com" in FlextLdifTestSamples.COMPLEX_LDIF
        assert "mail: complex@example.com" in FlextLdifTestSamples.COMPLEX_LDIF
        assert "telephoneNumber: +1-555-123-4567" in FlextLdifTestSamples.COMPLEX_LDIF
        assert "objectClass: groupOfNames" in FlextLdifTestSamples.COMPLEX_LDIF

    def test_invalid_ldif_content(self) -> None:
        """Test invalid LDIF content."""
        assert "cn: test" in FlextLdifTestSamples.INVALID_LDIF
        assert "objectClass: person" in FlextLdifTestSamples.INVALID_LDIF
        assert "sn: TestUser" in FlextLdifTestSamples.INVALID_LDIF
        # Should not have dn: line
        assert "dn:" not in FlextLdifTestSamples.INVALID_LDIF

    def test_sample_instance_properties(self) -> None:
        """Test sample instance properties."""
        sample = FlextLdifTestSamples()

        assert sample.description == "Basic LDIF sample"
        assert sample.content == FlextLdifTestSamples.BASIC_LDIF
        assert isinstance(sample.description, str)
        assert isinstance(sample.content, str)


class TestFlextLdifTestData:
    """Test LDIF test data utilities."""

    def test_get_sample_entries(self) -> None:
        """Test getting sample entries."""
        entries = FlextLdifTestData.get_sample_entries()

        assert isinstance(entries, list)
        assert len(entries) == 2

        # Check first entry
        first_entry = entries[0]
        assert first_entry["dn"] == ["cn=test,dc=example,dc=com"]
        assert first_entry["cn"] == ["test"]
        assert first_entry["objectClass"] == ["person"]
        assert first_entry["sn"] == ["TestUser"]

        # Check second entry
        second_entry = entries[1]
        assert second_entry["dn"] == ["cn=admin,dc=example,dc=com"]
        assert second_entry["cn"] == ["admin"]
        assert second_entry["objectClass"] == ["person"]
        assert second_entry["sn"] == ["AdminUser"]

    def test_get_complex_entries(self) -> None:
        """Test getting complex entries."""
        entries = FlextLdifTestData.get_complex_entries()

        assert isinstance(entries, list)
        assert len(entries) == 2

        # Check first entry (person)
        first_entry = entries[0]
        assert first_entry["dn"] == ["cn=complex,dc=example,dc=com"]
        assert first_entry["cn"] == ["complex"]
        assert first_entry["objectClass"] == ["person"]
        assert first_entry["sn"] == ["ComplexUser"]
        assert first_entry["mail"] == ["complex@example.com"]
        assert first_entry["telephoneNumber"] == ["+1-555-123-4567"]

        # Check second entry (group)
        second_entry = entries[1]
        assert second_entry["dn"] == ["cn=group,dc=example,dc=com"]
        assert second_entry["cn"] == ["group"]
        assert second_entry["objectClass"] == ["groupOfNames"]
        assert second_entry["member"] == ["cn=complex,dc=example,dc=com"]

    def test_all_samples(self) -> None:
        """Test getting all samples."""
        samples = FlextLdifTestData.all_samples()

        assert isinstance(samples, dict)
        assert "basic" in samples
        assert "complex" in samples
        assert "invalid" in samples

        # All should be FlextLdifTestSamples instances
        for sample in samples.values():
            assert isinstance(sample, FlextLdifTestSamples)

    def test_large_dataset_generation(self) -> None:
        """Test large dataset generation."""
        # Test with small number
        dataset = FlextLdifTestData.large_dataset(3)

        assert isinstance(dataset, str)
        assert "cn=user0,dc=example,dc=com" in dataset
        assert "cn=user1,dc=example,dc=com" in dataset
        assert "cn=user2,dc=example,dc=com" in dataset

        # Test with larger number
        large_dataset = FlextLdifTestData.large_dataset(10)
        assert isinstance(large_dataset, str)
        assert "cn=user9,dc=example,dc=com" in large_dataset

        # Count entries (should be 10)
        entry_count = large_dataset.count("dn:")
        assert entry_count == 10

    def test_large_dataset_zero_entries(self) -> None:
        """Test large dataset with zero entries."""
        dataset = FlextLdifTestData.large_dataset(0)

        assert isinstance(dataset, str)
        assert dataset == ""

    def test_invalid_data(self) -> None:
        """Test getting invalid data."""
        invalid_data = FlextLdifTestData.invalid_data()

        assert isinstance(invalid_data, str)
        assert invalid_data == FlextLdifTestSamples.INVALID_LDIF
        assert "cn: test" in invalid_data
        assert "dn:" not in invalid_data

    def test_entry_structure_consistency(self) -> None:
        """Test that all entries have consistent structure."""
        sample_entries = FlextLdifTestData.get_sample_entries()
        complex_entries = FlextLdifTestData.get_complex_entries()

        # All entries should have dn field
        for entry in sample_entries + complex_entries:
            assert "dn" in entry
            assert isinstance(entry["dn"], list)
            assert len(entry["dn"]) == 1
            assert isinstance(entry["dn"][0], str)

            # All entries should have cn field
            assert "cn" in entry
            assert isinstance(entry["cn"], list)
            assert len(entry["cn"]) == 1
            assert isinstance(entry["cn"][0], str)

            # All entries should have objectClass field
            assert "objectClass" in entry
            assert isinstance(entry["objectClass"], list)
            assert len(entry["objectClass"]) == 1
            assert isinstance(entry["objectClass"][0], str)
