"""Tests for FlextLdif Entries service with real LDIF fixtures.

This module tests the Entries service using actual LDIF files from fixtures,
validating real-world LDAP entry processing scenarios.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif import FlextLdif, FlextLdifUtilities
from flext_ldif.services.entries import FlextLdifEntries
from tests import m, s

# Add fixtures path
FIXTURES_ROOT = Path(__file__).parent.parent.parent / "fixtures"

# ════════════════════════════════════════════════════════════════════════════
# REAL LDIF FIXTURE LOADERS
# ════════════════════════════════════════════════════════════════════════════


class RealLdifLoader:
    """Load REAL LDIF fixture data from test fixtures directory."""

    @staticmethod
    def load_oid_entries() -> list[m.Entry]:
        """Load real OID LDIF entries from fixtures."""
        fixture_path = FIXTURES_ROOT / "oid" / "oid_entries_fixtures.ldif"
        ldif = FlextLdif()
        # Pass Path directly to avoid string path detection issues
        result = ldif.parse(fixture_path)
        if result.is_success:
            return result.unwrap()
        msg = f"Failed to parse OID fixtures: {result.error}"
        raise ValueError(msg)

    @staticmethod
    def load_oud_entries() -> list[m.Entry]:
        """Load real OUD LDIF entries from fixtures."""
        fixture_path = FIXTURES_ROOT / "oud" / "oud_entries_fixtures.ldif"
        ldif = FlextLdif()
        # Pass Path directly to avoid string path detection issues
        result = ldif.parse(fixture_path)
        if result.is_success:
            return result.unwrap()
        msg = f"Failed to parse OUD fixtures: {result.error}"
        raise ValueError(msg)

    @staticmethod
    def load_openldap2_entries() -> list[m.Entry]:
        """Load real OpenLDAP2 LDIF entries from fixtures."""
        fixture_path = FIXTURES_ROOT / "openldap2" / "openldap2_entries_fixtures.ldif"
        ldif = FlextLdif()
        # Pass Path directly to avoid string path detection issues
        result = ldif.parse(fixture_path)
        if result.is_success:
            return result.unwrap()
        msg = f"Failed to parse OpenLDAP2 fixtures: {result.error}"
        raise ValueError(msg)

    @staticmethod
    def load_rfc_entries() -> list[m.Entry]:
        """Load real RFC LDIF entries from fixtures."""
        fixture_path = FIXTURES_ROOT / "rfc" / "rfc_entries_fixtures.ldif"
        ldif = FlextLdif()
        # Pass Path directly to avoid string path detection issues
        result = ldif.parse(fixture_path)
        if result.is_success:
            return result.unwrap()
        msg = f"Failed to parse RFC fixtures: {result.error}"
        raise ValueError(msg)


# ════════════════════════════════════════════════════════════════════════════
# PYTEST FIXTURES
# ════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def oid_entries() -> list[m.Entry]:
    """Load real OID LDIF entries."""
    return RealLdifLoader.load_oid_entries()


@pytest.fixture
def oud_entries() -> list[m.Entry]:
    """Load real OUD LDIF entries."""
    return RealLdifLoader.load_oud_entries()


@pytest.fixture
def openldap2_entries() -> list[m.Entry]:
    """Load real OpenLDAP2 LDIF entries."""
    return RealLdifLoader.load_openldap2_entries()


@pytest.fixture
def rfc_entries() -> list[m.Entry]:
    """Load real RFC LDIF entries."""
    return RealLdifLoader.load_rfc_entries()


# ════════════════════════════════════════════════════════════════════════════
# TEST PUBLIC CLASSMETHODS WITH REAL DATA
# ════════════════════════════════════════════════════════════════════════════


class TestsFlextLdifPublicClassmethodsWithRealLdif(s):
    """Test public classmethods with REAL LDIF fixture data."""

    def test_clean_dn_with_real_oid_entries(
        self,
        oid_entries: list[m.Entry],
    ) -> None:
        """Test DN cleaning with real OID LDIF entries."""
        assert len(oid_entries) > 0, "OID fixture should have entries"

        # Clean DN from first OID entry
        first_entry = oid_entries[0]
        assert first_entry.dn is not None
        cleaned_dn = FlextLdifUtilities.DN.clean_dn(first_entry.dn.value)

        # Verify DN is RFC 4514 compliant (no spaces around =)
        assert " = " not in cleaned_dn
        assert "=" in cleaned_dn  # Should have attribute=value pairs

    def test_remove_operational_attributes_from_real_oid_entry(
        self,
        oid_entries: list[m.Entry],
    ) -> None:
        """Test removing operational attributes from real OID LDIF entry."""
        assert len(oid_entries) > 0

        entry = oid_entries[0]
        entries_service = FlextLdifEntries()
        result = entries_service.remove_operational_attributes(entry)

        assert result.is_success
        cleaned_entry = result.unwrap()

        # Verify entry still has basic attributes
        assert cleaned_entry.attributes is not None
        assert len(cleaned_entry.attributes.attributes) > 0
        # Verify DN is unchanged
        assert cleaned_entry.dn is not None
        assert entry.dn is not None
        assert cleaned_entry.dn.value == entry.dn.value

    def test_remove_operational_attributes_batch_real_oid(
        self,
        oid_entries: list[m.Entry],
    ) -> None:
        """Test batch operational attribute removal with real OID LDIF entries."""
        assert len(oid_entries) > 0

        entries_service = FlextLdifEntries()
        result = entries_service.remove_operational_attributes_batch(oid_entries)

        assert result.is_success
        cleaned_entries = result.unwrap()

        # Same number of entries
        assert len(cleaned_entries) == len(oid_entries)

        # All entries are still valid
        for entry in cleaned_entries:
            assert entry.dn is not None
            assert len(entry.dn.value) > 0
            assert entry.attributes is not None
            assert len(entry.attributes.attributes) > 0

    def test_remove_specific_attributes_from_real_entry(
        self,
        oid_entries: list[m.Entry],
    ) -> None:
        """Test removing specific attributes from real LDIF entry."""
        assert len(oid_entries) > 0

        entry = oid_entries[0]
        assert entry.attributes is not None
        original_attr_count = len(entry.attributes.attributes)

        # Remove common unnecessary attributes
        entries_service = FlextLdifEntries()
        result = entries_service.remove_attributes(
            entry,
            attributes_to_remove=["description", "employeeNumber", "telephoneNumber"],
        )

        assert result.is_success
        cleaned_entry = result.unwrap()

        # Should have fewer attributes than original
        assert cleaned_entry.attributes is not None
        assert len(cleaned_entry.attributes.attributes) <= original_attr_count

    def test_remove_attributes_batch_real_oud(
        self,
        oud_entries: list[m.Entry],
    ) -> None:
        """Test batch attribute removal with real OUD LDIF entries."""
        assert len(oud_entries) > 0

        entries_service = FlextLdifEntries()
        result = entries_service.remove_attributes_batch(
            entries=oud_entries,
            attributes=["description"],
        )

        assert result.is_success
        cleaned_entries = result.unwrap()

        # Same count of entries
        assert len(cleaned_entries) == len(oud_entries)


# ════════════════════════════════════════════════════════════════════════════
# TEST EXECUTE PATTERN WITH REAL DATA
# ════════════════════════════════════════════════════════════════════════════


class TestExecutePatternWithRealLdif:
    """Test V1 FlextService execute pattern with REAL LDIF data."""

    def test_execute_remove_operational_attributes_with_real_data(
        self,
        oid_entries: list[m.Entry],
    ) -> None:
        """Test execute() pattern for operational attribute removal with real data."""
        assert len(oid_entries) > 0

        result = FlextLdifEntries(
            entries=oid_entries,
            operation="remove_operational_attributes",
        ).execute()

        assert result.is_success
        cleaned_entries = result.unwrap()
        assert len(cleaned_entries) == len(oid_entries)

    def test_execute_remove_attributes_with_real_openldap2(
        self,
        openldap2_entries: list[m.Entry],
    ) -> None:
        """Test execute() pattern for attribute removal with real OpenLDAP2 data."""
        assert len(openldap2_entries) > 0

        result = FlextLdifEntries(
            entries=openldap2_entries,
            operation="remove_attributes",
            attributes_to_remove=["description", "mail"],
        ).execute()

        assert result.is_success
        cleaned_entries = result.unwrap()
        assert len(cleaned_entries) == len(openldap2_entries)


# ════════════════════════════════════════════════════════════════════════════
# TEST FLUENT BUILDER WITH REAL DATA
# ════════════════════════════════════════════════════════════════════════════


class TestFluentBuilderWithRealLdif:
    """Test fluent builder pattern with REAL LDIF fixture data."""

    def test_builder_with_oid_entries(
        self,
        oid_entries: list[m.Entry],
    ) -> None:
        """Test fluent builder with real OID LDIF entries."""
        assert len(oid_entries) > 0

        result = (
            FlextLdifEntries.builder()
            .with_entries(oid_entries)
            .with_operation("remove_operational_attributes")
            .build()
        )

        assert len(result) == len(oid_entries)

    def test_builder_with_attribute_removal_oud(
        self,
        oud_entries: list[m.Entry],
    ) -> None:
        """Test builder with attribute removal on real OUD data."""
        assert len(oud_entries) > 0

        result = (
            FlextLdifEntries.builder()
            .with_entries(oud_entries)
            .with_operation("remove_attributes")
            .with_attributes_to_remove(["description", "telephoneNumber"])
            .build()
        )

        assert len(result) == len(oud_entries)


# ════════════════════════════════════════════════════════════════════════════
# TEST REAL-WORLD SCENARIOS
# ════════════════════════════════════════════════════════════════════════════


class TestRealWorldScenarios:
    """Test real-world scenarios with REAL LDIF data from multiple servers."""

    def test_ouid_migration_scenario_cleaning(
        self,
        oid_entries: list[m.Entry],
        oud_entries: list[m.Entry],
    ) -> None:
        """Test cleaning OID entries for OUD migration."""
        assert len(oid_entries) > 0

        # Remove operational attributes to make OID entries compatible with OUD
        entries_service = FlextLdifEntries()
        result = entries_service.remove_operational_attributes_batch(oid_entries)

        assert result.is_success
        cleaned_entries = result.unwrap()

        # All entries should be cleaned and valid
        assert len(cleaned_entries) == len(oid_entries)
        for entry in cleaned_entries:
            assert entry.dn is not None
            assert len(entry.dn.value) > 0
            assert entry.attributes is not None
            assert len(entry.attributes.attributes) > 0

    def test_multi_server_consolidation(
        self,
        oid_entries: list[m.Entry],
        oud_entries: list[m.Entry],
        openldap2_entries: list[m.Entry],
    ) -> None:
        """Test consolidating entries from multiple servers.

        Simulates gathering LDIF entries from OID, OUD, and OpenLDAP2
        and cleaning them for unified directory.
        """
        all_entries = oid_entries + oud_entries + openldap2_entries
        assert len(all_entries) > 0

        # Remove operational attributes from all entries
        entries_service = FlextLdifEntries()
        result = entries_service.remove_operational_attributes_batch(all_entries)

        assert result.is_success
        cleaned_entries = result.unwrap()

        # All entries preserved and cleaned
        assert len(cleaned_entries) == len(all_entries)

    def test_batch_attribute_cleanup_real_data(
        self,
        oid_entries: list[m.Entry],
    ) -> None:
        """Test batch cleanup of unnecessary attributes from real LDIF."""
        assert len(oid_entries) > 0

        # Attributes to remove during consolidation
        unnecessary_attrs = [
            "description",
            "employeeNumber",
            "departmentNumber",
            "telephoneNumber",
        ]

        entries_service = FlextLdifEntries()
        result = entries_service.remove_attributes_batch(
            entries=oid_entries,
            attributes=unnecessary_attrs,
        )

        assert result.is_success
        cleaned_entries = result.unwrap()

        # Verify unnecessary attributes were removed
        for entry in cleaned_entries:
            assert entry.attributes is not None
            for attr in unnecessary_attrs:
                assert attr.lower() not in [
                    k.lower() for k in entry.attributes.attributes
                ]

    def test_sequential_cleaning_pipeline(
        self,
        oid_entries: list[m.Entry],
    ) -> None:
        """Test sequential cleaning operations on real LDIF data."""
        assert len(oid_entries) > 0

        # Pipeline: remove operational attrs → remove description → remove phone
        entries_service = FlextLdifEntries()
        result1 = entries_service.remove_operational_attributes_batch(oid_entries)
        assert result1.is_success

        cleaned1 = result1.unwrap()
        result2 = entries_service.remove_attributes_batch(
            entries=cleaned1,
            attributes=["description"],
        )
        assert result2.is_success

        cleaned2 = result2.unwrap()
        result3 = entries_service.remove_attributes_batch(
            entries=cleaned2,
            attributes=["telephoneNumber"],
        )
        assert result3.is_success

        final_entries = result3.unwrap()
        assert len(final_entries) == len(oid_entries)


# ════════════════════════════════════════════════════════════════════════════
# TEST EDGE CASES WITH REAL DATA
# ════════════════════════════════════════════════════════════════════════════


class TestEdgeCasesWithRealData:
    """Test edge cases and special scenarios with REAL LDIF data."""

    def test_remove_all_removable_attributes(
        self,
        oid_entries: list[m.Entry],
    ) -> None:
        """Test removing all removable attributes while preserving structure."""
        assert len(oid_entries) > 0

        entry = oid_entries[0]
        assert entry.attributes is not None
        original_attrs = set(entry.attributes.attributes.keys())

        # Try removing all attributes except structural ones
        attrs_to_remove = [
            attr for attr in original_attrs if attr.lower() not in {"dn", "objectclass"}
        ]

        entries_service = FlextLdifEntries()
        result = entries_service.remove_attributes(
            entry,
            attributes_to_remove=attrs_to_remove,
        )

        assert result.is_success
        cleaned = result.unwrap()

        # Entry should still be valid
        assert cleaned.dn is not None
        assert len(cleaned.dn.value) > 0
        assert cleaned.attributes is not None
        assert len(cleaned.attributes.attributes) > 0

    def test_mixed_case_attribute_removal(
        self,
        oud_entries: list[m.Entry],
    ) -> None:
        """Test that attribute removal is case-insensitive on real data."""
        assert len(oud_entries) > 0

        entry = oud_entries[0]

        # Remove with different case
        entries_service = FlextLdifEntries()
        result = entries_service.remove_attributes(
            entry,
            attributes_to_remove=["DESCRIPTION", "TelephoneNumber", "mail"],
        )

        assert result.is_success
        cleaned = result.unwrap()

        # Verify case-insensitive removal worked
        assert cleaned.attributes is not None
        cleaned_keys = {k.lower() for k in cleaned.attributes.attributes}
        assert "description" not in cleaned_keys
        assert "mail" not in cleaned_keys

    def test_entries_with_unicode_and_special_chars(
        self,
        openldap2_entries: list[m.Entry],
    ) -> None:
        """Test operations on real entries with unicode and special characters."""
        assert len(openldap2_entries) > 0

        entries_service = FlextLdifEntries()
        result = entries_service.remove_operational_attributes_batch(openldap2_entries)

        assert result.is_success
        cleaned = result.unwrap()

        # All entries should survive unicode/special char handling
        for entry in cleaned:
            assert entry.dn is not None
            assert len(entry.dn.value) > 0
            assert entry.attributes is not None
            assert all(
                len(attr_values) > 0
                for attr_values in entry.attributes.attributes.values()
            )

    def test_empty_attributes_handling(
        self,
        oid_entries: list[m.Entry],
    ) -> None:
        """Test handling of entries with various attribute value scenarios."""
        assert len(oid_entries) > 0

        # Process multiple entries and ensure robustness
        entries_service = FlextLdifEntries()
        result = entries_service.remove_operational_attributes_batch(oid_entries)

        assert result.is_success
        cleaned_entries = result.unwrap()

        # All entries should have non-empty DN and attributes
        for entry in cleaned_entries:
            assert entry.dn is not None
            assert len(entry.dn.value) > 0
            assert entry.attributes is not None
            assert len(entry.attributes.attributes) > 0
            # All attribute values should be non-empty lists
            for values in entry.attributes.attributes.values():
                assert isinstance(values, list)
                assert all(isinstance(v, str) for v in values)


# ════════════════════════════════════════════════════════════════════════════
# TEST COMPATIBILITY ACROSS SERVER TYPES
# ════════════════════════════════════════════════════════════════════════════


class TestServerCompatibility:
    """Test entry service with entries from different LDAP server types."""

    def test_unified_cleaning_all_servers(
        self,
        oid_entries: list[m.Entry],
        oud_entries: list[m.Entry],
        openldap2_entries: list[m.Entry],
    ) -> None:
        """Test that cleaning works uniformly across all server types."""
        servers_data = [
            ("OID", oid_entries),
            ("OUD", oud_entries),
            ("OpenLDAP2", openldap2_entries),
        ]

        for server_name, entries in servers_data:
            assert len(entries) > 0, f"{server_name} fixtures should have entries"

            entries_service = FlextLdifEntries()
            result = entries_service.remove_operational_attributes_batch(entries)

            assert result.is_success, f"Cleaning {server_name} entries should succeed"
            cleaned = result.unwrap()
            assert len(cleaned) == len(entries), (
                f"{server_name} entry count should match"
            )

    def test_attribute_removal_all_servers(
        self,
        oid_entries: list[m.Entry],
        oud_entries: list[m.Entry],
        openldap2_entries: list[m.Entry],
    ) -> None:
        """Test attribute removal works on all server types."""
        servers_data = [
            ("OID", oid_entries),
            ("OUD", oud_entries),
            ("OpenLDAP2", openldap2_entries),
        ]

        for server_name, entries in servers_data:
            assert len(entries) > 0

            entries_service = FlextLdifEntries()
            result = entries_service.remove_attributes_batch(
                entries,
                attributes=["description", "mail"],
            )

            assert result.is_success, (
                f"Attribute removal on {server_name} should succeed"
            )
            cleaned = result.unwrap()
            assert len(cleaned) == len(entries)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
