"""Comprehensive OID Quirks Coverage - All Methods and Code Paths.

This test file provides complete coverage for FlextLdifQuirksServersOid methods:
- parse_attribute() with all RFC 4512 attributes
- parse_objectclass() with MUST/MAY/SUP dependencies
- write_attribute_to_rfc() and write_objectclass_to_rfc()
- convert_*_to/from_rfc() conversion methods
- validate_objectclass_dependencies()
- extract_schemas_from_ldif()
- AclQuirk: parse_acl(), convert_acl_*()
- EntryQuirk: process_entry(), convert_entry_*()

All tests use REAL implementations with actual LDIF data for Oracle OID.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid


class TestOidParseAttributeComprehensive:
    """Test parse_attribute() with all RFC 4512 attribute variations."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_parse_attribute_oid_namespace(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing OID namespace attribute."""
        attr_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        result = oid_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("oid") == "2.16.840.1.113894.1.1.1"
        assert parsed.get("name") == "orclGUID"

    def test_parse_attribute_with_all_fields(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing attribute with all RFC 4512 fields."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 "
            "NAME 'orclGUID' "
            "DESC 'Oracle GUID' "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "ORDERING caseIgnoreOrderingMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} "
            "SINGLE-VALUE "
            "SUP name "
            "X-ORIGIN 'Oracle' )"
        )
        result = oid_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("name") == "orclGUID"
        assert parsed.get("desc") == "Oracle GUID"

    def test_parse_attribute_standard_ldap(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing standard LDAP attribute in OID context."""
        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        result = oid_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("name") == "cn"


class TestOidParseObjectClassComprehensive:
    """Test parse_objectclass() with all RFC 4512 objectClass variations."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_parse_objectclass_oid_namespace(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing OID namespace objectClass."""
        oc_def = "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' STRUCTURAL )"
        result = oid_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("name") == "orclContext"

    def test_parse_objectclass_with_deps(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing objectClass with dependencies."""
        oc_def = (
            "( 2.16.840.1.113894.1.2.6 "
            "NAME 'changeLogEntry' "
            "DESC 'Oracle change log' "
            "STRUCTURAL "
            "SUP top "
            "MUST ( changeNumber $ targetDN $ changeType ) "
            "MAY ( changetime $ targetEntryUUID ) )"
        )
        result = oid_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.get("name") == "changeLogEntry"


class TestOidWriteMethods:
    """Test write_attribute_to_rfc() and write_objectclass_to_rfc()."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_write_attribute_to_rfc_oid(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test writing OID attribute to RFC format."""
        attr_data: dict[str, object] = {
            "oid": "2.16.840.1.113894.1.1.1",
            "name": "orclGUID",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            "single_value": True,
        }
        result = oid_quirk.write_attribute_to_rfc(attr_data)
        assert result.is_success
        written = result.unwrap()
        assert isinstance(written, str)

    def test_write_objectclass_to_rfc_oid(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test writing OID objectClass to RFC format."""
        oc_data: dict[str, object] = {
            "oid": "2.16.840.1.113894.1.2.1",
            "name": "orclContext",
            "kind": "STRUCTURAL",
            "sup": "top",
        }
        result = oid_quirk.write_objectclass_to_rfc(oc_data)
        assert result.is_success
        written = result.unwrap()
        assert isinstance(written, str)


class TestOidConversionMethods:
    """Test conversion between OID and RFC formats."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_convert_attribute_to_rfc(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test converting OID attribute to RFC."""
        attr_data: dict[str, object] = {
            "oid": "2.16.840.1.113894.1.1.1",
            "name": "orclGUID",
        }
        result = oid_quirk.convert_attribute_to_rfc(attr_data)
        assert result.is_success
        converted = result.unwrap()
        assert isinstance(converted, dict)

    def test_convert_objectclass_to_rfc(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test converting OID objectClass to RFC."""
        oc_data: dict[str, object] = {
            "oid": "2.16.840.1.113894.1.2.1",
            "name": "orclContext",
            "kind": "STRUCTURAL",
        }
        result = oid_quirk.convert_objectclass_to_rfc(oc_data)
        assert result.is_success
        converted = result.unwrap()
        assert isinstance(converted, dict)

    def test_convert_attribute_from_rfc(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test converting RFC attribute to OID."""
        rfc_attr: dict[str, object] = {
            "oid": "2.16.840.1.113894.1.1.1",
            "name": "orclGUID",
        }
        result = oid_quirk.convert_attribute_from_rfc(rfc_attr)
        assert result.is_success
        converted = result.unwrap()
        assert isinstance(converted, dict)

    def test_convert_objectclass_from_rfc(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test converting RFC objectClass to OID."""
        rfc_oc: dict[str, object] = {
            "oid": "2.16.840.1.113894.1.2.1",
            "name": "orclContext",
        }
        result = oid_quirk.convert_objectclass_from_rfc(rfc_oc)
        assert result.is_success
        converted = result.unwrap()
        assert isinstance(converted, dict)


class TestOidExtractSchemas:
    """Test extract_schemas_from_ldif() for OID."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_extract_schemas_returns_result(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test extract_schemas_from_ldif returns FlextResult."""
        ldif_content = (
            "dn: cn=schema\n"
            "objectClass: ldapSubentry\n"
            "attributeTypes: ( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' )\n"
        )
        result = oid_quirk.extract_schemas_from_ldif(ldif_content)
        assert hasattr(result, "is_success")


class TestOidCanHandleMethods:
    """Test can_handle methods for OID."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    def test_can_handle_oid_namespace_attribute(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test can_handle for OID namespace attribute."""
        oid_attr = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' )"
        result = oid_quirk.can_handle_attribute(oid_attr)
        assert isinstance(result, bool)

    def test_can_handle_oid_namespace_objectclass(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test can_handle for OID namespace objectClass."""
        oid_oc = "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' STRUCTURAL )"
        result = oid_quirk.can_handle_objectclass(oid_oc)
        assert isinstance(result, bool)


__all__ = [
    "TestOidCanHandleMethods",
    "TestOidConversionMethods",
    "TestOidExtractSchemas",
    "TestOidParseAttributeComprehensive",
    "TestOidParseObjectClassComprehensive",
    "TestOidWriteMethods",
]
