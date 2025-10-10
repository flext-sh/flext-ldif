"""Cross-quirk conversion integration tests.

Tests conversion between different LDAP server quirk types:
- Parse with source quirk (e.g., OID)
- Convert to RFC representation
- Write with target quirk (e.g., OUD)
- Validate conversion accuracy

Also tests the QuirksConversionMatrix facade for universal translation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.conversion_matrix import QuirksConversionMatrix
from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud
from tests.fixtures.loader import FlextLdifFixtures


class TestOidToOudSchemaConversion:
    """Test OID schema → OUD schema conversion."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

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
        assert oud_parse_result.is_success, (
            f"OUD parse failed: {oud_parse_result.error}"
        )
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
        assert oud_parse_result.is_success, (
            f"OUD parse failed: {oud_parse_result.error}"
        )
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
        parsed_data = cast("dict[str, object]", parse_result.unwrap())

        # Verify parsed data structure
        assert parsed_data["type"] == "standard"  # orclaci uses "standard" type
        assert parsed_data["target"] == "entry"
        assert "_metadata" in parsed_data
        by_clauses = parsed_data.get("by_clauses", [])
        assert isinstance(by_clauses, list)
        assert len(by_clauses) > 0

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
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

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
            1
            for line in oid_schema_fixture.split("\n")
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
                assert oud_result.is_success, (
                    "OUD quirk should parse converted attribute"
                )

                # Verify key fields preserved
                oud_data = oud_result.unwrap()
                assert oud_data["oid"] == parsed_data["oid"]
                assert oud_data["name"] == parsed_data["name"]

                # Successfully converted at least one attribute
                break


class TestQuirksConversionMatrixFacade:
    """Test QuirksConversionMatrix facade for universal translation."""

    @pytest.fixture
    def matrix(self) -> QuirksConversionMatrix:
        """Create conversion matrix instance."""
        return QuirksConversionMatrix()

    @pytest.fixture
    def oud(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_matrix_instantiation(self, matrix: QuirksConversionMatrix) -> None:
        """Test that conversion matrix can be instantiated."""
        assert matrix is not None

    def test_get_supported_conversions(
        self, matrix: QuirksConversionMatrix, oud: FlextLdifQuirksServersOud
    ) -> None:
        """Test checking supported conversions."""
        supported = matrix.get_supported_conversions(oud)

        # Schema support should be detected
        assert supported["attribute"] is True
        assert supported["objectclass"] is True

        # ACL and Entry are nested classes, not directly accessible
        # So they appear as not supported in this check
        assert supported["acl"] is False  # Nested class pattern
        assert supported["entry"] is False  # Nested class pattern

    def test_convert_attribute_oud_to_oid(
        self,
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test converting attribute via matrix facade."""
        oud_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
        )

        result = matrix.convert(oud, oid, "attribute", oud_attr)

        assert result.is_success, f"Conversion failed: {result.error}"
        oid_attr = result.unwrap()
        assert "2.16.840.1.113894.1.1.1" in oid_attr
        assert "orclGUID" in oid_attr

    def test_convert_objectclass_oid_to_oud(
        self,
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test converting objectClass via matrix facade."""
        oid_oc = (
            "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
        )

        result = matrix.convert(oid, oud, "objectclass", oid_oc)

        assert result.is_success, f"Conversion failed: {result.error}"
        oud_oc = result.unwrap()
        assert "2.16.840.1.113894.1.2.1" in oud_oc
        assert "orclContext" in oud_oc

    def test_batch_convert_attributes(
        self,
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test batch conversion via matrix facade."""
        oud_attrs = [
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
            "( 2.16.840.1.113894.1.1.2 NAME 'orclDBName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
        ]

        result = matrix.batch_convert(oud, oid, "attribute", oud_attrs)

        assert result.is_success, f"Batch conversion failed: {result.error}"
        oid_attrs = result.unwrap()
        assert len(oid_attrs) == 2
        assert "orclGUID" in oid_attrs[0]
        assert "orclDBName" in oid_attrs[1]

    def test_bidirectional_conversion(
        self,
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test bidirectional conversion OUD ↔ OID."""
        original = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )"
        )

        # OUD → OID
        oid_result = matrix.convert(oud, oid, "attribute", original)
        assert oid_result.is_success
        oid_attr = oid_result.unwrap()

        # OID → OUD
        oud_result = matrix.convert(oid, oud, "attribute", oid_attr)
        assert oud_result.is_success
        roundtrip = oud_result.unwrap()

        # Validate semantic equivalence
        assert "2.16.840.1.113894.1.1.1" in roundtrip
        assert "orclGUID" in roundtrip

    def test_invalid_data_type(
        self,
        matrix: QuirksConversionMatrix,
        oud: FlextLdifQuirksServersOud,
        oid: FlextLdifQuirksServersOid,
    ) -> None:
        """Test error handling for invalid data type."""
        result = matrix.convert(oud, oid, "invalid", "test")

        assert result.is_failure
        assert result.error is not None
        assert "Invalid data_type" in result.error


__all__ = [
    "TestOidToOudAclConversion",
    "TestOidToOudIntegrationConversion",
    "TestOidToOudSchemaConversion",
    "TestQuirksConversionMatrixFacade",
]
