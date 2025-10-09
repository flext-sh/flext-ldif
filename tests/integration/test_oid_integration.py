"""Integration tests for OID (Oracle Internet Directory) quirks.

Tests complete workflow with real fixture data:
- Parse OID LDIF fixtures via FlextLdif API
- Process entries with OID quirks automatically
- Convert to RFC format
- Write back to LDIF
- Validate round-trip integrity

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif import FlextLdif
from tests.fixtures.loader import FlextLdifFixtures


class TestOidSchemaIntegration:
    """Integration tests for OID schema processing."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif.get_instance()

    @pytest.fixture
    def schema_fixture(self) -> str:
        """Load OID schema fixture data."""
        loader = FlextLdifFixtures.OID()
        return loader.schema()

    def test_parse_schema_fixture(self, api: FlextLdif, schema_fixture: str) -> None:
        """Test parsing complete OID schema fixture."""
        result = api.parse(schema_fixture)

        assert result.is_success, f"Schema parsing failed: {result.error}"
        entries = result.unwrap()

        # Should have at least one schema entry
        assert len(entries) > 0, "No schema entries parsed"

        # Verify schema entry structure
        schema_entry = entries[0]
        assert schema_entry.dn is not None

    def test_oracle_attributes_in_parsed_schema(
        self, api: FlextLdif, schema_fixture: str
    ) -> None:
        """Test that Oracle attributes are detected in parsed schema."""
        result = api.parse(schema_fixture)
        assert result.is_success

        entries = result.unwrap()
        schema_entry = entries[0]

        # Check for attributetypes attribute
        attrs = schema_entry.attributes.get("attributetypes") or []
        oracle_attr_count = sum(
            1
            for attr in attrs
            if isinstance(attr, str) and "2.16.840.1.113894" in attr
        )

        assert oracle_attr_count > 0, "No Oracle attributes found in parsed schema"

    def test_oracle_objectclasses_in_parsed_schema(
        self, api: FlextLdif, schema_fixture: str
    ) -> None:
        """Test that Oracle objectClasses are detected in parsed schema."""
        result = api.parse(schema_fixture)
        assert result.is_success

        entries = result.unwrap()
        schema_entry = entries[0]

        # Check for objectclasses attribute
        object_classes = schema_entry.attributes.get("objectclasses") or []
        oracle_oc_count = sum(
            1
            for oc in object_classes
            if isinstance(oc, str) and "2.16.840.1.113894" in oc
        )

        assert oracle_oc_count > 0, "No Oracle objectClasses found in parsed schema"


class TestOidEntryIntegration:
    """Integration tests for OID entry processing."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif.get_instance()

    @pytest.fixture
    def integration_fixture(self) -> str:
        """Load OID integration fixture data."""
        loader = FlextLdifFixtures.OID()
        return loader.integration()

    def test_parse_integration_fixture(
        self, api: FlextLdif, integration_fixture: str
    ) -> None:
        """Test parsing complete OID integration fixture."""
        result = api.parse(integration_fixture)

        assert result.is_success, f"Integration fixture parsing failed: {result.error}"
        entries = result.unwrap()

        # Should have many entries
        min_expected_entries = 100
        assert len(entries) > min_expected_entries, f"Expected > {min_expected_entries} entries, got {len(entries)}"

    def test_oracle_acls_preserved_in_parsing(
        self, api: FlextLdif, integration_fixture: str
    ) -> None:
        """Test that Oracle ACLs are preserved during parsing."""
        result = api.parse(integration_fixture)
        assert result.is_success

        entries = result.unwrap()

        # Count entries with Oracle ACLs
        entries_with_orclaci = sum(
            1 for entry in entries if "orclaci" in entry.attributes
        )
        entries_with_orclentrylevelaci = sum(
            1 for entry in entries if "orclentrylevelaci" in entry.attributes
        )

        assert entries_with_orclaci > 0, "No entries with orclaci found"
        assert entries_with_orclentrylevelaci > 0, "No entries with orclentrylevelaci found"

    def test_oracle_attributes_preserved_in_parsing(
        self, api: FlextLdif, integration_fixture: str
    ) -> None:
        """Test that Oracle-specific attributes are preserved during parsing."""
        result = api.parse(integration_fixture)
        assert result.is_success

        entries = result.unwrap()

        # Count entries with actual Oracle attributes from fixture
        oracle_attr_patterns = [
            "orclisenabled",  # 177 occurrences in fixture
            "orclpassword",   # 171 occurrences in fixture
        ]

        for attr_name in oracle_attr_patterns:
            entries_with_attr = sum(1 for entry in entries if attr_name in entry.attributes)
            assert entries_with_attr > 0, f"No entries with {attr_name} found"


class TestOidRoundTripIntegration:
    """Integration tests for OID round-trip: parse → write → parse."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif.get_instance()

    @pytest.fixture
    def integration_fixture(self) -> str:
        """Load OID integration fixture data."""
        loader = FlextLdifFixtures.OID()
        return loader.integration()

    def test_roundtrip_parse_write_parse(
        self, api: FlextLdif, integration_fixture: str
    ) -> None:
        """Test round-trip: parse OID fixture → write to LDIF → parse again."""
        # Parse original
        parse_result_1 = api.parse(integration_fixture)
        assert parse_result_1.is_success, f"First parse failed: {parse_result_1.error}"
        entries_1 = parse_result_1.unwrap()

        original_entry_count = len(entries_1)
        assert original_entry_count > 0, "No entries in original parse"

        # Write to LDIF
        write_result = api.write(entries_1)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        ldif_output = write_result.unwrap()

        # Parse written LDIF
        parse_result_2 = api.parse(ldif_output)
        assert parse_result_2.is_success, f"Second parse failed: {parse_result_2.error}"
        entries_2 = parse_result_2.unwrap()

        # Should have same number of entries
        assert len(entries_2) == original_entry_count, (
            f"Entry count mismatch: original={original_entry_count}, "
            f"after round-trip={len(entries_2)}"
        )

    def test_roundtrip_dn_preservation(
        self, api: FlextLdif, integration_fixture: str
    ) -> None:
        """Test that DNs are preserved in round-trip."""
        # Parse original
        parse_result_1 = api.parse(integration_fixture)
        assert parse_result_1.is_success
        entries_1 = parse_result_1.unwrap()

        original_dns = sorted([str(entry.dn) for entry in entries_1])

        # Write to LDIF and parse again
        write_result = api.write(entries_1)
        assert write_result.is_success

        parse_result_2 = api.parse(write_result.unwrap())
        assert parse_result_2.is_success
        entries_2 = parse_result_2.unwrap()

        roundtrip_dns = sorted([str(entry.dn) for entry in entries_2])

        # All original DNs should be present
        assert original_dns == roundtrip_dns, "DN mismatch after round-trip"

    def test_roundtrip_oracle_acl_preservation(
        self, api: FlextLdif, integration_fixture: str
    ) -> None:
        """Test that Oracle ACLs are preserved in round-trip."""
        # Parse original
        parse_result_1 = api.parse(integration_fixture)
        assert parse_result_1.is_success
        entries_1 = parse_result_1.unwrap()

        # Count ACLs in original
        original_orclaci_count = sum(
            len(entry.attributes.get("orclaci") or [])
            for entry in entries_1
        )
        original_entrylevel_count = sum(
            len(entry.attributes.get("orclentrylevelaci") or [])
            for entry in entries_1
        )

        # Write and parse again
        write_result = api.write(entries_1)
        assert write_result.is_success

        parse_result_2 = api.parse(write_result.unwrap())
        assert parse_result_2.is_success
        entries_2 = parse_result_2.unwrap()

        # Count ACLs after round-trip
        roundtrip_orclaci_count = sum(
            len(entry.attributes.get("orclaci") or [])
            for entry in entries_2
        )
        roundtrip_entrylevel_count = sum(
            len(entry.attributes.get("orclentrylevelaci") or [])
            for entry in entries_2
        )

        # Should have same ACL counts
        assert original_orclaci_count == roundtrip_orclaci_count, (
            f"orclaci count mismatch: original={original_orclaci_count}, "
            f"roundtrip={roundtrip_orclaci_count}"
        )
        assert original_entrylevel_count == roundtrip_entrylevel_count, (
            f"orclentrylevelaci count mismatch: original={original_entrylevel_count}, "
            f"roundtrip={roundtrip_entrylevel_count}"
        )


__all__ = [
    "TestOidEntryIntegration",
    "TestOidRoundTripIntegration",
    "TestOidSchemaIntegration",
]
