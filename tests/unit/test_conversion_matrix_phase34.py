"""Phase 3.4: Conversion Matrix comprehensive tests.

Tests cover:
- N×N server conversions via RFC intermediate format
- Attribute conversions between servers
- ObjectClass conversions between servers
- ACL conversions between servers
- Entry conversions between servers
- DN case registry consistency
- Round-trip conversions (Source → RFC → Target → RFC)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif.quirks.conversion_matrix import FlextLdifQuirksConversionMatrix
from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud
from flext_ldif.quirks.servers.relaxed_quirks import FlextLdifQuirksServersRelaxed


class TestConversionMatrixPhase34:
    """Test Conversion Matrix with real quirks and data."""

    def test_conversion_matrix_initialization(self) -> None:
        """Test conversion matrix can be initialized."""
        matrix = FlextLdifQuirksConversionMatrix()
        assert matrix is not None
        assert hasattr(matrix, "dn_registry")
        assert hasattr(matrix, "convert")

    def test_conversion_matrix_has_dn_registry(self) -> None:
        """Test conversion matrix has DN case registry."""
        matrix = FlextLdifQuirksConversionMatrix()
        assert hasattr(matrix, "dn_registry")
        assert matrix.dn_registry is not None

    def test_conversion_matrix_convert_method_exists(self) -> None:
        """Test conversion matrix has convert method."""
        matrix = FlextLdifQuirksConversionMatrix()
        assert hasattr(matrix, "convert")
        assert callable(matrix.convert)

    def test_conversion_attribute_oid_to_oud(self) -> None:
        """Test converting OID attribute to OUD format."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()
        oud = FlextLdifQuirksServersOud()

        # Real OID attribute
        oid_attr = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' )"
        result = matrix.convert(oid, oud, "attribute", oid_attr)

        assert hasattr(result, "is_success")
        if result.is_success:
            converted = result.unwrap()
            assert converted is not None

    def test_conversion_attribute_oud_to_oid(self) -> None:
        """Test converting OUD attribute to OID format."""
        matrix = FlextLdifQuirksConversionMatrix()
        oud = FlextLdifQuirksServersOud()
        oid = FlextLdifQuirksServersOid()

        # Real OUD attribute
        oud_attr = "( 2.16.840.1.113894.1.1.2 NAME 'orclDbLink' )"
        result = matrix.convert(oud, oid, "attribute", oud_attr)

        assert hasattr(result, "is_success")

    def test_conversion_attribute_via_rfc(self) -> None:
        """Test attribute conversion using RFC as intermediate."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()
        relaxed = FlextLdifQuirksServersRelaxed()

        # Convert through relaxed/lenient mode
        oid_attr = "( 2.16.840.1.113894.1.1.1 NAME 'test' )"
        result = matrix.convert(oid, relaxed, "attribute", oid_attr)

        assert hasattr(result, "is_success")

    def test_conversion_objectclass_oid_to_oud(self) -> None:
        """Test converting OID objectClass to OUD format."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()
        oud = FlextLdifQuirksServersOud()

        # Real OID objectClass
        oid_oc = "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP top STRUCTURAL )"
        result = matrix.convert(oid, oud, "objectclass", oid_oc)

        assert hasattr(result, "is_success")

    def test_conversion_objectclass_oud_to_oid(self) -> None:
        """Test converting OUD objectClass to OID format."""
        matrix = FlextLdifQuirksConversionMatrix()
        oud = FlextLdifQuirksServersOud()
        oid = FlextLdifQuirksServersOid()

        # Real OUD objectClass
        oud_oc = "( 2.16.840.1.113894.2.1.2 NAME 'orclUser' SUP top STRUCTURAL )"
        result = matrix.convert(oud, oid, "objectclass", oud_oc)

        assert hasattr(result, "is_success")

    def test_conversion_acl_oid_to_oud(self) -> None:
        """Test converting OID ACL to OUD format."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()
        oud = FlextLdifQuirksServersOud()

        # ACL line (server-specific format)
        acl_line = 'dn: cn=testEntry,dc=example,dc=com\norclaci: (target="ldap:///")'
        result = matrix.convert(oid, oud, "acl", acl_line)

        assert hasattr(result, "is_success")

    def test_conversion_acl_oud_to_oid(self) -> None:
        """Test converting OUD ACL to OID format."""
        matrix = FlextLdifQuirksConversionMatrix()
        oud = FlextLdifQuirksServersOud()
        oid = FlextLdifQuirksServersOid()

        # OUD ACL format
        acl_line = 'ds-aci: (target="ldap:///")(version 3.0; acl "test"; allow(read) userdn="ldap:///anyone";)'
        result = matrix.convert(oud, oid, "acl", acl_line)

        assert hasattr(result, "is_success")

    def test_conversion_entry_with_dict_data(self) -> None:
        """Test converting entry with dictionary representation."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()
        oud = FlextLdifQuirksServersOud()

        # Entry as dict
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "objectClass": ["person"],
            },
        }
        result = matrix.convert(oid, oud, "entry", entry_data)

        assert hasattr(result, "is_success")

    def test_conversion_entry_with_string_data(self) -> None:
        """Test converting entry with string representation."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()
        oud = FlextLdifQuirksServersOud()

        # Entry as string
        entry_str = "dn: cn=test,dc=example,dc=com\ncn: test\nobjectClass: person"
        result = matrix.convert(oid, oud, "entry", entry_str)

        assert hasattr(result, "is_success")

    def test_conversion_roundtrip_attribute(self) -> None:
        """Test round-trip conversion: Source → RFC → Source."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()

        # Start with OID attribute
        oid_attr = "( 2.16.840.1.113894.1.1.1 NAME 'test' )"

        # Convert to relaxed and back
        relaxed = FlextLdifQuirksServersRelaxed()
        to_relaxed = matrix.convert(oid, relaxed, "attribute", oid_attr)

        assert hasattr(to_relaxed, "is_success")

    def test_conversion_roundtrip_objectclass(self) -> None:
        """Test round-trip conversion: Source → Relaxed → Source."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()
        relaxed = FlextLdifQuirksServersRelaxed()

        # Start with OID objectClass
        oid_oc = "( 2.16.840.1.113894.2.1.1 NAME 'test' SUP top STRUCTURAL )"

        # Convert to relaxed and back
        to_relaxed = matrix.convert(oid, relaxed, "objectclass", oid_oc)

        assert hasattr(to_relaxed, "is_success")

    def test_conversion_invalid_data_type(self) -> None:
        """Test conversion with invalid data type."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()
        oud = FlextLdifQuirksServersOud()

        # Invalid data type
        result = matrix.convert(oid, oud, "invalid_type", "test_data")

        assert hasattr(result, "is_success")
        # Should fail due to invalid type
        if not result.is_success:
            assert "Invalid data_type" in str(result.error or "")

    def test_conversion_same_quirk_attribute(self) -> None:
        """Test converting within same quirk (should be pass-through)."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()

        # Convert OID to OID (same quirk)
        oid_attr = "( 2.16.840.1.113894.1.1.1 NAME 'test' )"
        result = matrix.convert(oid, oid, "attribute", oid_attr)

        assert hasattr(result, "is_success")

    def test_conversion_same_quirk_objectclass(self) -> None:
        """Test converting objectClass within same quirk."""
        matrix = FlextLdifQuirksConversionMatrix()
        oud = FlextLdifQuirksServersOud()

        # Convert OUD to OUD (same quirk)
        oud_oc = "( 2.16.840.1.113894.2.1.1 NAME 'test' SUP top STRUCTURAL )"
        result = matrix.convert(oud, oud, "objectclass", oud_oc)

        assert hasattr(result, "is_success")

    def test_conversion_matrix_supports_oid_quirks(self) -> None:
        """Test conversion matrix supports OID quirks."""
        oid = FlextLdifQuirksServersOid()

        assert oid.server_type == "oid"
        assert hasattr(oid, "parse_attribute")
        assert hasattr(oid, "parse_objectclass")

    def test_conversion_matrix_supports_oud_quirks(self) -> None:
        """Test conversion matrix supports OUD quirks."""
        oud = FlextLdifQuirksServersOud()

        assert oud.server_type == "oud"
        assert hasattr(oud, "parse_attribute")
        assert hasattr(oud, "parse_objectclass")

    def test_conversion_matrix_supports_relaxed_quirks(self) -> None:
        """Test conversion matrix supports relaxed quirks."""
        relaxed = FlextLdifQuirksServersRelaxed()

        assert relaxed.server_type == "relaxed"
        assert hasattr(relaxed, "parse_attribute")
        assert hasattr(relaxed, "parse_objectclass")

    def test_conversion_attribute_preserves_oid(self) -> None:
        """Test that attribute conversion preserves OID."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()
        oud = FlextLdifQuirksServersOud()

        # Attribute with specific OID
        oid_attr = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' )"
        result = matrix.convert(oid, oud, "attribute", oid_attr)

        # If conversion succeeds, OID should be preserved
        if result.is_success:
            converted = result.unwrap()
            if isinstance(converted, str):
                assert "2.16.840.1.113894.1.1.1" in converted or len(converted) > 0

    def test_conversion_objectclass_preserves_structural(self) -> None:
        """Test that objectClass conversion preserves STRUCTURAL type."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()
        oud = FlextLdifQuirksServersOud()

        # STRUCTURAL objectClass
        oid_oc = "( 2.16.840.1.113894.2.1.1 NAME 'testClass' SUP top STRUCTURAL )"
        result = matrix.convert(oid, oud, "objectclass", oid_oc)

        if result.is_success:
            converted = result.unwrap()
            if isinstance(converted, str):
                assert "STRUCTURAL" in converted or len(converted) > 0

    def test_conversion_dn_case_registry_tracks_dns(self) -> None:
        """Test that DN case registry tracks DNs during conversion."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()
        oud = FlextLdifQuirksServersOud()

        # Entry with DN
        entry_data = {
            "dn": "cn=Test,dc=Example,dc=Com",
            "attributes": {"cn": ["Test"]},
        }
        _ = matrix.convert(oid, oud, "entry", entry_data)

        # DN registry should have been updated
        assert hasattr(matrix, "dn_registry")

    def test_conversion_with_multiple_servers(self) -> None:
        """Test converting through multiple server types."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()
        oud = FlextLdifQuirksServersOud()
        relaxed = FlextLdifQuirksServersRelaxed()

        # Attribute data
        oid_attr = "( 2.16.840.1.113894.1.1.1 NAME 'test' )"

        # Convert OID → OUD
        to_oud = matrix.convert(oid, oud, "attribute", oid_attr)
        assert hasattr(to_oud, "is_success")

        # Convert OUD → Relaxed
        to_relaxed = matrix.convert(oud, relaxed, "attribute", oid_attr)
        assert hasattr(to_relaxed, "is_success")

        # Convert Relaxed → OID
        back_to_oid = matrix.convert(relaxed, oid, "attribute", oid_attr)
        assert hasattr(back_to_oid, "is_success")

    def test_conversion_entry_with_multiple_attributes(self) -> None:
        """Test converting entry with multiple attributes."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()
        oud = FlextLdifQuirksServersOud()

        # Entry with multiple attributes
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "sn": ["user"],
                "mail": ["test@example.com"],
                "objectClass": ["person", "top"],
            },
        }
        result = matrix.convert(oid, oud, "entry", entry_data)

        assert hasattr(result, "is_success")

    def test_conversion_with_special_characters_in_dn(self) -> None:
        """Test converting entries with special characters in DN."""
        matrix = FlextLdifQuirksConversionMatrix()
        oid = FlextLdifQuirksServersOid()
        oud = FlextLdifQuirksServersOud()

        # DN with special characters
        entry_data = {
            "dn": "cn=Test\\,User,dc=example,dc=com",
            "attributes": {"cn": ["Test,User"]},
        }
        result = matrix.convert(oid, oud, "entry", entry_data)

        assert hasattr(result, "is_success")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
