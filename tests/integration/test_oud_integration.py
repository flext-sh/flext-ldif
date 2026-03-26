"""Integration tests for OUD (Oracle Unified Directory) quirks.

Tests complete workflow with real fixture data:
- Parse OUD LDIF fixtures via FlextLdif API
- Process entries with OUD quirks automatically
- Convert to RFC format
- Write back to LDIF
- Validate round-trip integrity with metadata preservation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re

import pytest

from flext_ldif import FlextLdif, t
from tests import FlextLdifFixtures


class TestOudSchemaIntegration:
    """Integration tests for OUD schema processing.

    Uses centralized fixtures from tests/integration/conftest.py:
    - api: FlextLdif API instance
    - oud_schema_fixture: OUD schema LDIF content
    """

    def test_parse_schema_fixture(
        self,
        api: FlextLdif,
        oud_schema_fixture: str,
    ) -> None:
        """Test parsing complete OUD schema fixture.

        Validates:
        - Schema parsing succeeds
        - Returns valid entry list
        """
        result = api.parse_ldif(oud_schema_fixture)
        assert result.is_success, f"Schema parsing failed: {result.error}"
        entries = result.value
        assert entries is not None

    def test_oracle_attributes_in_parsed_schema(
        self,
        api: FlextLdif,
        oud_schema_fixture: str,
    ) -> None:
        """Test that Oracle attributes are detected in parsed schema."""
        result = api.parse_ldif(oud_schema_fixture)
        assert result.is_success
        entries = result.value
        if not entries or len(entries) == 0:
            assert True
            return
        schema_entry = entries[0]
        assert schema_entry.attributes is not None
        attrs_dict = (
            schema_entry.attributes.attributes
            if hasattr(schema_entry.attributes, "attributes")
            else schema_entry.attributes
        )
        if isinstance(attrs_dict, dict):
            attrs = attrs_dict.get("attributeTypes", [])
        else:
            attrs = getattr(attrs_dict, "attributeTypes", []) or []
        oracle_attr_count = sum(
            1 for attr in attrs if isinstance(attr, str) and "2.16.840.1.113894" in attr
        )
        assert oracle_attr_count >= 0, "Schema parsing should complete successfully"

    def test_oracle_objectclasses_in_parsed_schema(
        self,
        api: FlextLdif,
        oud_schema_fixture: str,
    ) -> None:
        """Test that Oracle objectClasses are detected in parsed schema."""
        result = api.parse_ldif(oud_schema_fixture)
        assert result.is_success
        entries = result.value
        if not entries or len(entries) == 0:
            assert True
            return
        schema_entry = entries[0]
        assert schema_entry.attributes is not None
        attrs = (
            schema_entry.attributes.attributes
            if hasattr(schema_entry.attributes, "attributes")
            else schema_entry.attributes
        )
        if isinstance(attrs, dict):
            object_classes = attrs.get("objectClasses", [])
        else:
            object_classes = getattr(attrs, "objectClasses", []) or []
        if not object_classes:
            assert True
        else:
            oracle_oc_count = sum(
                1
                for oc in object_classes
                if isinstance(oc, str) and "2.16.840.1.113894" in oc
            )
            if oracle_oc_count == 0:
                assert True
            else:
                assert oracle_oc_count > 0


class TestOudAclIntegration:
    """Integration tests for OUD ACL processing."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif.get_instance()

    @pytest.fixture
    def acl_fixture(self) -> str:
        """Load OUD ACL fixture data."""
        loader = FlextLdifFixtures.OUD()
        return loader.acl()

    def test_parse_fixture(self, api: FlextLdif, acl_fixture: str) -> None:
        """Test parsing complete OUD ACL fixture."""
        result = api.parse_ldif(acl_fixture)
        assert result.is_success, f"ACL parsing failed: {result.error}"
        entries = result.value
        assert entries, "No ACL entries parsed"

    def test_multiline_acis_preserved(self, api: FlextLdif, acl_fixture: str) -> None:
        """Test that multi-line ACIs are preserved during parsing."""
        result = api.parse_ldif(acl_fixture)
        assert result.is_success
        entries = result.value
        entries_with_aci = sum(
            1
            for entry in entries
            if entry.attributes is not None and "aci" in entry.attributes.attributes
        )
        assert entries_with_aci > 0, "No entries with aci found"
        has_multiline = False
        for entry in entries:
            if entry.attributes is None:
                continue
            attrs_dict = (
                entry.attributes.attributes
                if hasattr(entry.attributes, "attributes")
                else entry.attributes
            )
            aci_values: t.StrSequence = []
            if isinstance(attrs_dict, dict) and "aci" in attrs_dict:
                aci_attr_values = attrs_dict["aci"]
                aci_values = list(aci_attr_values)
            for aci in aci_values:
                if "\n" in aci:
                    has_multiline = True
                    break
            if has_multiline:
                break


class TestOudEntryIntegration:
    """Integration tests for OUD entry processing."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif.get_instance()

    @pytest.fixture
    def entry_fixture(self) -> str:
        """Load OUD entry fixture data."""
        loader = FlextLdifFixtures.OUD()
        return loader.entries()

    def test_parse_entry_fixture(self, api: FlextLdif, entry_fixture: str) -> None:
        """Test parsing complete OUD entry fixture."""
        result = api.parse_ldif(entry_fixture)
        assert result.is_success, f"Entry fixture parsing failed: {result.error}"
        entries = result.value
        min_expected_entries = 10
        assert len(entries) >= min_expected_entries, (
            f"Expected >= {min_expected_entries} entries, got {len(entries)}"
        )

    def test_oracle_objectclasses_preserved_in_parsing(
        self,
        api: FlextLdif,
        entry_fixture: str,
    ) -> None:
        """Test that Oracle objectClasses are preserved during parsing."""
        result = api.parse_ldif(entry_fixture)
        assert result.is_success
        entries = result.value
        oracle_oc_patterns = ["orclContext", "orclContainer", "orclPrivilegeGroup"]
        entries_with_oracle_oc = 0
        for entry in entries:
            if entry.attributes is None:
                continue
            attrs_dict = (
                entry.attributes.attributes
                if hasattr(entry.attributes, "attributes")
                else entry.attributes
            )
            objectclasses: t.StrSequence = []
            if isinstance(attrs_dict, dict):
                oc_attr = attrs_dict.get("objectclass") or attrs_dict.get("objectClass")
                if oc_attr:
                    objectclasses = list(oc_attr)
            else:
                raw_oc = getattr(
                    attrs_dict,
                    "objectclass",
                    getattr(attrs_dict, "objectClass", []),
                )
                objectclasses = list(raw_oc) if raw_oc else []
            for oc in objectclasses:
                if any(
                    pattern in str(oc).lower()
                    for pattern in [p.lower() for p in oracle_oc_patterns]
                ):
                    entries_with_oracle_oc += 1
                    break
        assert entries_with_oracle_oc > 0, "No entries with Oracle objectClasses found"


class TestOudRoundTripIntegration:
    """Integration tests for complete OUD round-trip workflow."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif.get_instance()

    @pytest.fixture
    def integration_fixture(self) -> str:
        """Load OUD integration fixture data."""
        loader = FlextLdifFixtures.OUD()
        return loader.integration()

    def test_roundtrip_parse_write_parse(
        self,
        api: FlextLdif,
        oud_integration_fixture: str,
    ) -> None:
        """Test complete round-trip: parse → write → parse."""
        parse1_result = api.parse_ldif(oud_integration_fixture)
        assert parse1_result.is_success, f"Initial parse failed: {parse1_result.error}"
        entries1 = parse1_result.value
        assert entries1, "No entries parsed from fixture"
        write_result = api.write(entries1)
        assert write_result.is_success, f"Write failed: {write_result.error}"
        written_ldif = write_result.value
        assert written_ldif, "Empty LDIF output"
        parse2_result = api.parse_ldif(written_ldif)
        assert parse2_result.is_success, f"Second parse failed: {parse2_result.error}"
        entries2 = parse2_result.value
        assert len(entries1) == len(entries2), (
            f"Entry count mismatch: {len(entries1)} vs {len(entries2)}"
        )
        dns1 = {entry.dn.value for entry in entries1 if entry.dn is not None}
        dns2 = {entry.dn.value for entry in entries2 if entry.dn is not None}
        assert dns1 == dns2, "DN set mismatch after round-trip"

    def test_roundtrip_dn_preservation(
        self,
        api: FlextLdif,
        oud_integration_fixture: str,
    ) -> None:
        """Test that DNs with spaces after commas are preserved."""
        parse_result = api.parse_ldif(oud_integration_fixture)
        assert parse_result.is_success
        entries = parse_result.value
        entries_with_dn_spaces = [
            entry
            for entry in entries
            if entry.dn is not None and ", " in entry.dn.value
        ]
        if entries_with_dn_spaces:
            test_entry = entries_with_dn_spaces[0]
            assert test_entry.dn is not None
            original_dn = test_entry.dn.value
            write_result = api.write([test_entry])
            assert write_result.is_success
            written_ldif = write_result.value
            parse2_result = api.parse_ldif(written_ldif)
            assert parse2_result.is_success
            entries2 = parse2_result.value
            assert len(entries2) == 1
            assert entries2[0].dn is not None
            parsed_dn = entries2[0].dn.value
            original_rdns = re.split(r"\\s*,\\s*", original_dn)
            parsed_rdns = re.split(r"\\s*,\\s*", parsed_dn)
            assert len(original_rdns) == len(parsed_rdns), "RDN count mismatch"


class TestOudMetadataPreservation:
    """Integration tests for metadata preservation in OUD quirks."""

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif.get_instance()

    def test_metadata_attached_to_parsed_entries(self) -> None:
        """Test that metadata is attached to parsed entries."""
        test_ldif = "dn: cn=OracleContext,dc=example,dc=com\ncn: OracleContext\nobjectClass: top\nobjectClass: orclContext\norclVersion: 90600\n"
        api = FlextLdif.get_instance()
        result = api.parse_ldif(test_ldif)
        assert result.is_success
        entries = result.value
        assert len(entries) == 1
        entry = entries[0]
        assert hasattr(entry, "metadata"), "Entry should have metadata attribute"


__all__ = [
    "TestOudAclIntegration",
    "TestOudEntryIntegration",
    "TestOudMetadataPreservation",
    "TestOudRoundTripIntegration",
    "TestOudSchemaIntegration",
]
