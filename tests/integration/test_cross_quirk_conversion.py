"""Cross-quirk conversion integration tests.

Tests conversion between different LDAP server quirk types:
- Parse with source quirk (e.g., OID)
- Convert to RFC representation
- Write with target quirk (e.g., OUD)
- Validate conversion accuracy

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud
from tests.fixtures.loader import FlextLdifFixtures


class TestOidToOudSchemaConversion:
    """Test OID schema → OUD schema conversion."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(
            server_type=FlextLdifConstants.ServerTypes.OID
        )

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(
            server_type=FlextLdifConstants.ServerTypes.OUD
        )

    @pytest.fixture
    def oid_schema_fixture(self) -> str:
        """Load OID schema fixture."""
        loader = FlextLdifFixtures.OID()
        return loader.schema()

    def test_convert_oid_attribute_to_oud(
        self,
        oid_quirk: FlextLdifQuirksServersOid,
        oud_quirk: FlextLdifQuirksServersOud,
    ) -> None:
        """Test converting OID attribute definition to OUD format."""
        # OID attribute definition
        oid_attribute = """( 2.16.840.1.113894.1.1.1 NAME 'orclguid' DESC 'Oracle GUID' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"""

        # Parse with OID quirk
        parse_result = oid_quirk.parse_attribute(oid_attribute)
        assert parse_result.is_success, f"OID parse failed: {parse_result.error}"
        parsed_data = parse_result.unwrap()

        # Verify parsed data
        assert parsed_data["oid"] == "2.16.840.1.113894.1.1.1"
        assert parsed_data["name"] == "orclguid"
        assert "_metadata" in parsed_data  # Metadata preserved

        # Convert to RFC format using OID quirk
        rfc_result = oid_quirk.write_attribute_to_rfc(parsed_data)
        assert rfc_result.is_success, f"OID write failed: {rfc_result.error}"
        rfc_format = rfc_result.unwrap()

        # Parse RFC format with OUD quirk
        oud_parse_result = oud_quirk.parse_attribute(rfc_format)
        assert oud_parse_result.is_success, f"OUD parse failed: {oud_parse_result.error}"
        oud_data = oud_parse_result.unwrap()

        # Verify conversion preserved key fields
        assert oud_data["oid"] == parsed_data["oid"]
        assert oud_data["name"] == parsed_data["name"]
        assert oud_data.get("syntax") == parsed_data.get("syntax")

    def test_convert_oid_objectclass_to_oud(
        self,
        oid_quirk: FlextLdifQuirksServersOid,
        oud_quirk: FlextLdifQuirksServersOud,
    ) -> None:
        """Test converting OID objectClass definition to OUD format."""
        # OID objectClass definition
        oid_objectclass = """( 2.16.840.1.113894.2.1.1 NAME 'orclContainer' DESC 'Oracle Container' SUP top STRUCTURAL MUST cn MAY description )"""

        # Parse with OID quirk
        parse_result = oid_quirk.parse_objectclass(oid_objectclass)
        assert parse_result.is_success, f"OID parse failed: {parse_result.error}"
        parsed_data = parse_result.unwrap()

        # Verify parsed data
        assert parsed_data["oid"] == "2.16.840.1.113894.2.1.1"
        assert parsed_data["name"] == "orclContainer"
        assert parsed_data["kind"] == "STRUCTURAL"
        assert "_metadata" in parsed_data

        # Convert to RFC format using OID quirk
        rfc_result = oid_quirk.write_objectclass_to_rfc(parsed_data)
        assert rfc_result.is_success, f"OID write failed: {rfc_result.error}"
        rfc_format = rfc_result.unwrap()

        # Parse RFC format with OUD quirk
        oud_parse_result = oud_quirk.parse_objectclass(rfc_format)
        assert oud_parse_result.is_success, f"OUD parse failed: {oud_parse_result.error}"
        oud_data = oud_parse_result.unwrap()

        # Verify conversion preserved key fields
        assert oud_data["oid"] == parsed_data["oid"]
        assert oud_data["name"] == parsed_data["name"]
        assert oud_data["kind"] == parsed_data["kind"]
        assert oud_data.get("superior") == parsed_data.get("superior")


class TestOidToOudAclConversion:
    """Test OID ACL parsing and OUD ACL parsing independently.

    Note: Direct ACL conversion between OID and OUD formats is not supported
    because they use fundamentally different ACL models:
    - OID: orclaci format (access to entry/attr by subject (permissions))
    - OUD: ACI format (targetattr)(version; acl "name"; allow/deny)

    For ACL comparison across quirks, use the FlextLdifDiff utility instead.
    """

    @pytest.fixture
    def oid_acl_quirk(self) -> FlextLdifQuirksServersOid.AclQuirk:
        """Create OID ACL quirk instance."""
        return FlextLdifQuirksServersOid.AclQuirk(
            server_type=FlextLdifConstants.ServerTypes.OID
        )

    @pytest.fixture
    def oud_acl_quirk(self) -> FlextLdifQuirksServersOud.AclQuirk:
        """Create OUD ACL quirk instance."""
        return FlextLdifQuirksServersOud.AclQuirk(
            server_type=FlextLdifConstants.ServerTypes.OUD
        )

    def test_oid_acl_parsing_and_roundtrip(
        self,
        oid_acl_quirk: FlextLdifQuirksServersOid.AclQuirk,
    ) -> None:
        """Test OID ACL parsing and round-trip within OID format."""
        # OID ACL definition
        oid_acl = """orclaci: access to entry by * (browse)"""

        # Parse with OID ACL quirk
        parse_result = oid_acl_quirk.parse_acl(oid_acl)
        assert parse_result.is_success, f"OID ACL parse failed: {parse_result.error}"
        parsed_data = parse_result.unwrap()

        # Verify parsed data structure
        assert parsed_data["type"] == "standard"  # orclaci uses "standard" type
        assert parsed_data["target"] == "entry"
        assert "_metadata" in parsed_data
        assert len(parsed_data.get("by_clauses", [])) > 0

        # Write back to OID format for round-trip
        write_result = oid_acl_quirk.write_acl_to_rfc(parsed_data)
        assert write_result.is_success, f"OID ACL write failed: {write_result.error}"
        written_format = write_result.unwrap()

        # Verify round-trip
        assert "orclaci:" in written_format

    def test_oud_acl_parsing_and_roundtrip(
        self,
        oud_acl_quirk: FlextLdifQuirksServersOud.AclQuirk,
    ) -> None:
        """Test OUD ACL parsing and round-trip within OUD format."""
        # OUD ACI format
        oud_aci = """aci: (targetattr="*")(version 3.0; acl "Test ACL"; allow (read,search) userdn="ldap:///anyone";)"""

        # Parse with OUD ACL quirk
        parse_result = oud_acl_quirk.parse_acl(oud_aci)
        assert parse_result.is_success, f"OUD ACL parse failed: {parse_result.error}"
        parsed_data = parse_result.unwrap()

        # Verify parsed data structure
        assert parsed_data["type"] == "oud_acl"
        assert "targetattr" in parsed_data
        assert "_metadata" in parsed_data

        # Write back to OUD format for round-trip
        write_result = oud_acl_quirk.write_acl_to_rfc(parsed_data)
        assert write_result.is_success, f"OUD ACL write failed: {write_result.error}"
        written_format = write_result.unwrap()

        # Verify round-trip (should preserve ACI format)
        assert "targetattr" in written_format


class TestOidToOudIntegrationConversion:
    """Test complete OID fixture → OUD conversion workflow."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(
            server_type=FlextLdifConstants.ServerTypes.OID
        )

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(
            server_type=FlextLdifConstants.ServerTypes.OUD
        )

    @pytest.fixture
    def oid_schema_fixture(self) -> str:
        """Load OID schema fixture."""
        loader = FlextLdifFixtures.OID()
        return loader.schema()

    def test_convert_oid_schema_fixture_to_oud(
        self,
        oid_quirk: FlextLdifQuirksServersOid,
        oud_quirk: FlextLdifQuirksServersOud,
        oid_schema_fixture: str,
    ) -> None:
        """Test converting OID schema fixture to OUD format."""
        # Extract attribute definitions from fixture
        # In a real scenario, we'd parse the LDIF entry and extract attributeTypes
        # For this test, we'll test the conversion pipeline works

        # Count Oracle attributes in OID fixture
        oid_oracle_attrs = sum(
            1 for line in oid_schema_fixture.split("\n")
            if "attributetypes:" in line.lower() and "2.16.840.1.113894" in line
        )

        # Verify we have Oracle attributes in fixture
        assert oid_oracle_attrs > 0, "No Oracle attributes found in OID fixture"

        # Extract one attribute for conversion test
        for line in oid_schema_fixture.split("\n"):
            if "attributetypes:" in line.lower() and "2.16.840.1.113894" in line:
                # Extract the attribute definition (remove "attributetypes: " prefix)
                attr_def = line.split(":", 1)[1].strip()

                # Parse with OID quirk
                parse_result = oid_quirk.parse_attribute(attr_def)
                if not parse_result.is_success:
                    continue

                parsed_data = parse_result.unwrap()

                # Convert to RFC format
                rfc_result = oid_quirk.write_attribute_to_rfc(parsed_data)
                assert rfc_result.is_success

                # Parse with OUD quirk
                oud_result = oud_quirk.parse_attribute(rfc_result.unwrap())
                assert oud_result.is_success, "OUD quirk should parse converted attribute"

                # Verify key fields preserved
                oud_data = oud_result.unwrap()
                assert oud_data["oid"] == parsed_data["oid"]
                assert oud_data["name"] == parsed_data["name"]

                # Successfully converted at least one attribute
                break


__all__ = [
    "TestOidToOudAclConversion",
    "TestOidToOudIntegrationConversion",
    "TestOidToOudSchemaConversion",
]
