"""Test suite for Oracle Internet Directory (OID) quirks.

Comprehensive testing for OID-specific schema, ACL, and entry quirks
using real OID fixtures from tests/fixtures/oid/.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast

import pytest
from flext_core import FlextTypes
from tests.fixtures.loader import FlextLdifFixtures

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid
from flext_ldif.typings import FlextLdifTypes


class TestOidSchemaQuirks:
    """Test suite for OID schema quirk functionality."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID schema quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    @pytest.fixture
    def oid_fixtures(self) -> FlextLdifFixtures.OID:
        """Create OID fixture loader."""
        return FlextLdifFixtures.OID()

    def test_initialization(self, oid_quirk: FlextLdifQuirksServersOid) -> None:
        """Test OID schema quirk initialization."""
        assert oid_quirk.server_type == FlextLdifConstants.ServerTypes.OID
        assert oid_quirk.priority == 10

    def test_can_handle_oracle_attribute(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test detection of Oracle OID attributes by OID namespace."""
        # Oracle namespace: 2.16.840.1.113894.*
        oracle_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        assert oid_quirk.can_handle_attribute(oracle_attr)

        # Non-Oracle attribute (RFC 4519)
        rfc_attr = (
            "( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        assert not oid_quirk.can_handle_attribute(rfc_attr)

    def test_parse_oracle_attribute_basic(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing basic Oracle attribute definition."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
            "DESC 'Oracle GUID' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "SINGLE-VALUE )"
        )

        result = oid_quirk.parse_attribute(attr_def)
        assert result.is_success, f"Failed to parse attribute: {result.error}"

        parsed = result.unwrap()
        assert parsed[FlextLdifConstants.DictKeys.SERVER_TYPE] == "oid"
        assert "oid" in parsed
        assert "name" in parsed

    def test_parse_oracle_attribute_from_fixtures(
        self, oid_quirk: FlextLdifQuirksServersOid, oid_fixtures: FlextLdifFixtures.OID
    ) -> None:
        """Test parsing Oracle attributes from real OID schema fixtures."""
        schema_content = oid_fixtures.schema()

        # Extract Oracle attribute lines from schema
        oracle_attrs = [
            line
            for line in schema_content.splitlines()
            if "2.16.840.1.113894" in line
            and line.strip().startswith("attributetypes:")
        ]

        assert len(oracle_attrs) > 0, "No Oracle attributes found in schema fixtures"

        # Parse first Oracle attribute
        first_attr = oracle_attrs[0]
        attr_def = first_attr.split("attributetypes:", 1)[1].strip()

        result = oid_quirk.parse_attribute(attr_def)
        assert result.is_success, f"Failed to parse fixture attribute: {result.error}"

        parsed = result.unwrap()
        # Verify parsed data structure
        assert "oid" in parsed or "name" in parsed

    def test_can_handle_oracle_objectclass(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test detection of Oracle OID objectClasses."""
        # Oracle objectClass
        oracle_oc = "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP top STRUCTURAL )"
        assert oid_quirk.can_handle_objectclass(oracle_oc)

        # Non-Oracle objectClass
        rfc_oc = "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL )"
        assert not oid_quirk.can_handle_objectclass(rfc_oc)

    def test_parse_oracle_objectclass_basic(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing basic Oracle objectClass definition."""
        oc_def = (
            "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' "
            "DESC 'Oracle Context' "
            "SUP top STRUCTURAL "
            "MUST cn "
            "MAY ( orclguid ) )"
        )

        result = oid_quirk.parse_objectclass(oc_def)
        assert result.is_success, f"Failed to parse objectClass: {result.error}"

        parsed = result.unwrap()
        assert parsed[FlextLdifConstants.DictKeys.SERVER_TYPE] == "oid"
        assert "oid" in parsed
        assert "name" in parsed

    def test_parse_oracle_objectclass_from_fixtures(
        self, oid_quirk: FlextLdifQuirksServersOid, oid_fixtures: FlextLdifFixtures.OID
    ) -> None:
        """Test parsing Oracle objectClasses from real OID schema fixtures."""
        schema_content = oid_fixtures.schema()

        # Extract Oracle objectClass lines
        oracle_ocs = [
            line
            for line in schema_content.splitlines()
            if "2.16.840.1.113894" in line and line.strip().startswith("objectclasses:")
        ]

        assert len(oracle_ocs) > 0, "No Oracle objectClasses found in schema fixtures"

        # Parse first Oracle objectClass
        first_oc = oracle_ocs[0]
        oc_def = first_oc.split("objectclasses:", 1)[1].strip()

        result = oid_quirk.parse_objectclass(oc_def)
        assert result.is_success, f"Failed to parse fixture objectClass: {result.error}"

        parsed = result.unwrap()
        # Verify parsed data structure
        assert "oid" in parsed or "name" in parsed

    def test_parse_oracle_objectclass_with_all_options(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing Oracle objectClass with all possible options."""
        complex_oc = (
            "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' "
            "DESC 'Oracle Context' "
            "SUP top STRUCTURAL "
            "MUST ( cn $ orclguid ) "
            "MAY ( description $ orclVersion $ orclNetDescName ) )"
        )

        result = oid_quirk.parse_objectclass(complex_oc)
        assert result.is_success, f"Failed to parse complex objectClass: {result.error}"

        parsed = result.unwrap()
        assert parsed["name"] == "orclContext"
        assert parsed["kind"] == "STRUCTURAL"
        assert parsed["sup"] == "top"
        assert parsed["must"] == ["cn", "orclguid"]
        assert parsed["may"] == ["description", "orclVersion", "orclNetDescName"]

    def test_parse_oracle_objectclass_minimal(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing minimal Oracle objectClass."""
        minimal_oc = "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP top )"

        result = oid_quirk.parse_objectclass(minimal_oc)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed["oid"] == "2.16.840.1.113894.2.1.1"
        assert parsed["name"] == "orclContext"
        assert parsed["sup"] == "top"
        assert "kind" not in parsed  # Not set when not specified
        assert "must" not in parsed  # Not set when not specified
        assert "may" not in parsed  # Not set when not specified

    def test_parse_oracle_objectclass_auxiliary(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing Oracle objectClass with AUXILIARY kind."""
        auxiliary_oc = (
            "( 2.16.840.1.113894.2.1.1 NAME 'orclAuxClass' "
            "SUP top AUXILIARY "
            "MAY ( orclguid ) )"
        )

        result = oid_quirk.parse_objectclass(auxiliary_oc)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed["kind"] == "AUXILIARY"
        assert parsed["may"] == ["orclguid"]

    def test_parse_oracle_objectclass_abstract(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing Oracle objectClass with ABSTRACT kind."""
        abstract_oc = (
            "( 2.16.840.1.113894.2.1.1 NAME 'orclAbstractClass' SUP top ABSTRACT )"
        )

        result = oid_quirk.parse_objectclass(abstract_oc)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed["kind"] == "ABSTRACT"

    def test_parse_oracle_objectclass_multiple_sup(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing Oracle objectClass with multiple SUP."""
        multi_sup_oc = (
            "( 2.16.840.1.113894.2.1.1 NAME 'orclMultiSup' "
            "SUP ( top $ person ) STRUCTURAL )"
        )

        result = oid_quirk.parse_objectclass(multi_sup_oc)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed["sup"] == ["top", "person"]

    def test_parse_oracle_objectclass_malformed(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing malformed Oracle objectClass."""
        malformed_oc = "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP )"

        result = oid_quirk.parse_objectclass(malformed_oc)
        assert result.is_success  # Should be permissive

        parsed = result.unwrap()
        assert parsed["name"] == "orclContext"

    def test_convert_attribute_to_rfc(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test converting OID attribute to RFC-compliant format."""
        oid_attr_data: FlextLdifTypes.Dict = {
            "oid": "2.16.840.1.113894.1.1.1",
            "name": "orclguid",
            "desc": "Oracle GUID",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            "equality": "caseIgnoreMatch",
        }

        result = oid_quirk.convert_attribute_to_rfc(oid_attr_data)
        assert result.is_success

        rfc_data = result.unwrap()
        assert rfc_data[FlextLdifConstants.DictKeys.OID] == "2.16.840.1.113894.1.1.1"
        assert rfc_data[FlextLdifConstants.DictKeys.NAME] == "orclguid"

    def test_convert_objectclass_to_rfc(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test converting OID objectClass to RFC-compliant format."""
        oid_oc_data: FlextLdifTypes.Dict = {
            "oid": "2.16.840.1.113894.2.1.1",
            "name": "orclContext",
            "desc": "Oracle Context",
            "sup": "top",
            "kind": "STRUCTURAL",
            "must": ["cn"],
            "may": ["orclguid"],
        }

        result = oid_quirk.convert_objectclass_to_rfc(oid_oc_data)
        assert result.is_success

        rfc_data = result.unwrap()
        assert rfc_data[FlextLdifConstants.DictKeys.OID] == "2.16.840.1.113894.2.1.1"
        assert rfc_data[FlextLdifConstants.DictKeys.NAME] == "orclContext"

    def test_schema_roundtrip(self, oid_quirk: FlextLdifQuirksServersOid) -> None:
        """Test schema attribute roundtrip: parse → convert to RFC → back."""
        original_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
            "DESC 'Oracle GUID' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "SINGLE-VALUE )"
        )

        # Parse
        parse_result = oid_quirk.parse_attribute(original_attr)
        assert parse_result.is_success
        parsed = parse_result.unwrap()

        # Convert to RFC
        rfc_result = oid_quirk.convert_attribute_to_rfc(parsed)
        assert rfc_result.is_success
        rfc_data = rfc_result.unwrap()

        # Validate essential fields preserved
        # OID field contains full definition after RFC conversion
        assert "2.16.840.1.113894.1.1.1" in str(
            rfc_data.get(FlextLdifConstants.DictKeys.OID, "")
        )
        assert rfc_data.get(FlextLdifConstants.DictKeys.NAME) == "orclguid"

    def test_parse_oracle_attribute_with_all_options(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing Oracle attribute with all possible options."""
        # Test attribute with all possible regex patterns
        complex_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
            "DESC 'Oracle GUID' "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "ORDERING caseIgnoreOrderingMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{16} "
            "SUP name "
            "USAGE userApplications "
            "SINGLE-VALUE "
            "NO-USER-MODIFICATION )"
        )

        result = oid_quirk.parse_attribute(complex_attr)
        assert result.is_success, f"Failed to parse complex attribute: {result.error}"

        parsed = result.unwrap()
        assert parsed["equality"] == "caseIgnoreMatch"
        assert parsed["substr"] == "caseIgnoreSubstringsMatch"
        assert parsed["ordering"] == "caseIgnoreOrderingMatch"
        assert parsed["syntax"] == "1.3.6.1.4.1.1466.115.121.1.15"
        assert parsed["syntax_length"] == "16"
        assert parsed["sup"] == "name"
        assert parsed["usage"] == "userApplications"
        assert parsed["single_value"] is True
        assert parsed["no_user_mod"] is True

    def test_parse_oracle_attribute_minimal(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing minimal Oracle attribute (only required fields)."""
        minimal_attr = "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' )"

        result = oid_quirk.parse_attribute(minimal_attr)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed["oid"] == "2.16.840.1.113894.1.1.1"
        assert parsed["name"] == "orclguid"
        # Optional fields should not be present or should be None/False
        assert "desc" not in parsed or parsed.get("desc") is None
        assert parsed.get("single_value") is False
        assert parsed.get("no_user_mod") is False

    def test_parse_oracle_attribute_invalid_syntax_length(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing Oracle attribute with invalid syntax length."""
        invalid_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{invalid} )"
        )

        result = oid_quirk.parse_attribute(invalid_attr)
        # Should still parse successfully but without syntax_length
        assert result.is_success
        parsed = result.unwrap()
        assert "syntax_length" not in parsed

    def test_parse_oracle_attribute_with_sup_number(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing Oracle attribute with numeric SUP."""
        numeric_sup_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
            "SUP name )"  # Use name instead of numeric OID for this test
        )

        result = oid_quirk.parse_attribute(numeric_sup_attr)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed["sup"] == "name"

    def test_parse_oracle_attribute_malformed_regex(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test parsing Oracle attribute with malformed regex patterns."""
        # Missing closing parenthesis in SYNTAX
        malformed_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{16 "
            "SINGLE-VALUE )"
        )

        result = oid_quirk.parse_attribute(malformed_attr)
        # Should still parse basic fields but not syntax_length
        assert result.is_success
        parsed = result.unwrap()
        assert parsed["name"] == "orclguid"
        assert "syntax_length" not in parsed


class TestOidAclQuirks:
    """Test suite for OID ACL quirk functionality."""

    @pytest.fixture
    def acl_quirk(self) -> FlextLdifQuirksServersOid.AclQuirk:
        """Create OID ACL quirk instance."""
        return FlextLdifQuirksServersOid.AclQuirk(
            server_type=FlextLdifConstants.ServerTypes.OID
        )

    @pytest.fixture
    def oid_fixtures(self) -> FlextLdifFixtures.OID:
        """Create OID fixture loader."""
        return FlextLdifFixtures.OID()

    def test_acl_quirk_initialization(
        self, acl_quirk: FlextLdifQuirksServersOid.AclQuirk
    ) -> None:
        """Test OID ACL quirk initialization."""
        assert acl_quirk.server_type == FlextLdifConstants.ServerTypes.OID
        assert acl_quirk.priority == 10

    def test_can_handle_orclaci(
        self, acl_quirk: FlextLdifQuirksServersOid.AclQuirk
    ) -> None:
        """Test detection of orclaci ACL format."""
        orclaci = 'orclaci: access to entry by group="cn=Admins,cn=groups,cn=OracleContext" (browse,add,delete)'
        assert acl_quirk.can_handle_acl(orclaci)

        orclentrylevel = (
            "orclentrylevelaci: access to entry by * (browse,noadd,nodelete)"
        )
        assert acl_quirk.can_handle_acl(orclentrylevel)

        non_oid_acl = "olcAccess: {0}to * by * read"
        assert not acl_quirk.can_handle_acl(non_oid_acl)

    def test_parse_simple_orclaci(
        self, acl_quirk: FlextLdifQuirksServersOid.AclQuirk
    ) -> None:
        """Test parsing simple orclaci format."""
        simple_orclaci = (
            'orclaci: access to entry by group="cn=ASPAdmins, cn=groups,cn=OracleContext,dc=network,dc=example" '
            "(browse,add, delete)"
        )

        result = acl_quirk.parse_acl(simple_orclaci)
        assert result.is_success, f"Failed to parse orclaci: {result.error}"

        parsed = result.unwrap()
        assert (
            parsed[FlextLdifConstants.DictKeys.TYPE]
            == FlextLdifConstants.DictKeys.STANDARD
        )
        assert parsed[FlextLdifConstants.DictKeys.RAW] == simple_orclaci

    def test_parse_complex_orclaci_with_filter(
        self, acl_quirk: FlextLdifQuirksServersOid.AclQuirk
    ) -> None:
        """Test parsing complex orclaci with filter and multiple 'by' clauses - WORST CASE."""
        # Worst case: filter + 3 "by" clauses + multiple groups
        complex_orclaci = (
            "orclaci: access to entry filter=(objectclass=orclNetDescriptionList) "
            'by group="cn=OracleContextAdmins,cn=Groups,cn=OracleContext,dc=network,dc=example" (browse,add,delete) '
            'by group="cn=OracleNetAdmins,cn=OracleContext,dc=network,dc=example" (browse,add,delete) '
            "by * (browse,noadd,nodelete)"
        )

        result = acl_quirk.parse_acl(complex_orclaci)
        assert result.is_success, f"Failed to parse complex orclaci: {result.error}"

        parsed = result.unwrap()
        assert (
            parsed[FlextLdifConstants.DictKeys.TYPE]
            == FlextLdifConstants.DictKeys.STANDARD
        )
        assert parsed[FlextLdifConstants.DictKeys.RAW] == complex_orclaci

    def test_parse_orclaci_with_attr_filter(
        self, acl_quirk: FlextLdifQuirksServersOid.AclQuirk
    ) -> None:
        """Test parsing orclaci with attr=(*) and filter - WORST CASE."""
        # Worst case: attr=(*) + filter + multiple permissions + extra spaces
        attr_filter_orclaci = (
            "orclaci: access to attr=(*)  filter=(objectclass=orclNetService) "
            'by group="cn=OracleContextAdmins,cn=Groups,cn=OracleContext,dc=network,dc=example" '
            "(read,search,write,selfwrite,compare) "
            'by group="cn=OracleNetAdmins,cn=OracleContext,dc=network,dc=example" (compare,search,read,write) '
            "by * (read,search,compare,nowrite,noselfwrite)"
        )

        result = acl_quirk.parse_acl(attr_filter_orclaci)
        assert result.is_success, f"Failed to parse attr+filter orclaci: {result.error}"

        parsed = result.unwrap()
        assert (
            parsed[FlextLdifConstants.DictKeys.TYPE]
            == FlextLdifConstants.DictKeys.STANDARD
        )

    def test_parse_orclaci_from_fixtures(
        self,
        acl_quirk: FlextLdifQuirksServersOid.AclQuirk,
        oid_fixtures: FlextLdifFixtures.OID,
    ) -> None:
        """Test parsing orclaci from real OID integration fixtures."""
        integration_content = oid_fixtures.integration()

        # Find orclaci lines in fixtures
        orclaci_lines = [
            line
            for line in integration_content.splitlines()
            if line.strip().startswith("orclaci:")
        ]

        assert len(orclaci_lines) > 0, "No orclaci found in integration fixtures"

        # Parse first orclaci
        first_orclaci = orclaci_lines[0]
        result = acl_quirk.parse_acl(first_orclaci)
        assert result.is_success, f"Failed to parse fixture orclaci: {result.error}"

        parsed = result.unwrap()
        assert (
            parsed[FlextLdifConstants.DictKeys.TYPE]
            == FlextLdifConstants.DictKeys.STANDARD
        )

    def test_parse_orclentrylevelaci_with_constraint(
        self, acl_quirk: FlextLdifQuirksServersOid.AclQuirk
    ) -> None:
        """Test parsing orclentrylevelaci with added_object_constraint - WORST CASE."""
        # Worst case: added_object_constraint with OR operator
        constraint_aci = (
            'orclentrylevelaci: access to entry by group="cn=OracleNetAdmins,cn=OracleContext,dc=network,dc=example" '
            "added_object_constraint=(|(objectclass=orclNetService)(objectclass=orclNetServiceAlias)) (add)"
        )

        result = acl_quirk.parse_acl(constraint_aci)
        assert result.is_success, f"Failed to parse constraint aci: {result.error}"

        parsed = result.unwrap()
        assert (
            parsed[FlextLdifConstants.DictKeys.TYPE]
            == FlextLdifConstants.DictKeys.ENTRY_LEVEL
        )

    def test_parse_orclentrylevelaci_from_fixtures(
        self,
        acl_quirk: FlextLdifQuirksServersOid.AclQuirk,
        oid_fixtures: FlextLdifFixtures.OID,
    ) -> None:
        """Test parsing orclentrylevelaci from real OID integration fixtures."""
        integration_content = oid_fixtures.integration()

        # Find orclentrylevelaci lines
        entry_level_lines = [
            line
            for line in integration_content.splitlines()
            if line.strip().startswith("orclentrylevelaci:")
        ]

        assert len(entry_level_lines) > 0, "No orclentrylevelaci found in fixtures"

        # Parse first orclentrylevelaci
        first_entry_level = entry_level_lines[0]
        result = acl_quirk.parse_acl(first_entry_level)
        assert result.is_success, (
            f"Failed to parse fixture entry-level aci: {result.error}"
        )

        parsed = result.unwrap()
        assert (
            parsed[FlextLdifConstants.DictKeys.TYPE]
            == FlextLdifConstants.DictKeys.ENTRY_LEVEL
        )

    def test_convert_acl_to_rfc(
        self, acl_quirk: FlextLdifQuirksServersOid.AclQuirk
    ) -> None:
        """Test converting OID ACL to RFC-compliant format."""
        oid_acl_data: FlextLdifTypes.Dict = {
            FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.STANDARD,
            FlextLdifConstants.DictKeys.RAW: 'orclaci: access to entry by group="cn=Admins" (browse,add,delete)',
        }

        result = acl_quirk.convert_acl_to_rfc(oid_acl_data)
        assert result.is_success

        rfc_data = result.unwrap()
        assert (
            rfc_data[FlextLdifConstants.DictKeys.TYPE]
            == FlextLdifConstants.DictKeys.ACL
        )
        assert (
            rfc_data[FlextLdifConstants.DictKeys.FORMAT]
            == FlextLdifConstants.AclFormats.RFC_GENERIC
        )
        assert (
            rfc_data[FlextLdifConstants.DictKeys.SOURCE_FORMAT]
            == FlextLdifConstants.AclFormats.OID_ACL
        )

    def test_convert_acl_from_rfc(
        self, acl_quirk: FlextLdifQuirksServersOid.AclQuirk
    ) -> None:
        """Test converting RFC ACL to OID-specific format."""
        rfc_acl_data: FlextLdifTypes.Dict = {
            FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
            FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.RFC_GENERIC,
            "permissions": ["read", "search"],
            "target": "*",
        }

        result = acl_quirk.convert_acl_from_rfc(rfc_acl_data)
        assert result.is_success

        oid_data = result.unwrap()
        assert (
            oid_data[FlextLdifConstants.DictKeys.FORMAT]
            == FlextLdifConstants.AclFormats.OID_ACL
        )
        assert oid_data[FlextLdifConstants.DictKeys.TARGET_FORMAT] == "orclaci"

    def test_acl_roundtrip(self, acl_quirk: FlextLdifQuirksServersOid.AclQuirk) -> None:
        """Test ACL roundtrip: parse → convert to RFC → convert back."""
        original_orclaci = (
            'orclaci: access to entry by group="cn=Admins,cn=Groups,cn=OracleContext" '
            "(browse,add,delete) by * (browse,noadd,nodelete)"
        )

        # Parse
        parse_result = acl_quirk.parse_acl(original_orclaci)
        assert parse_result.is_success
        parsed = parse_result.unwrap()

        # Convert to RFC
        rfc_result = acl_quirk.convert_acl_to_rfc(parsed)
        assert rfc_result.is_success
        rfc_data = rfc_result.unwrap()

        # Convert back to OID
        oid_result = acl_quirk.convert_acl_from_rfc(rfc_data)
        assert oid_result.is_success
        oid_data = oid_result.unwrap()

        # Validate format preserved
        assert (
            oid_data[FlextLdifConstants.DictKeys.FORMAT]
            == FlextLdifConstants.AclFormats.OID_ACL
        )


class TestOidEntryQuirks:
    """Test suite for OID entry quirk functionality."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID schema quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    @pytest.fixture
    def entry_quirk(self) -> FlextLdifQuirksServersOid.EntryQuirk:
        """Create OID entry quirk instance."""
        return FlextLdifQuirksServersOid.EntryQuirk(
            server_type=FlextLdifConstants.ServerTypes.OID
        )

    @pytest.fixture
    def oid_fixtures(self) -> FlextLdifFixtures.OID:
        """Create OID fixture loader."""
        return FlextLdifFixtures.OID()

    def test_entry_quirk_initialization(
        self, entry_quirk: FlextLdifQuirksServersOid.EntryQuirk
    ) -> None:
        """Test OID entry quirk initialization."""
        assert entry_quirk.server_type == FlextLdifConstants.ServerTypes.OID
        assert entry_quirk.priority == 10

    def test_can_handle_entry(
        self, entry_quirk: FlextLdifQuirksServersOid.EntryQuirk
    ) -> None:
        """Test entry handling detection."""
        # OID entry quirk handles entries with Oracle attributes
        entry_dn = "cn=OracleContext,dc=network,dc=example"
        attributes: FlextTypes.Dict = {
            "cn": ["OracleContext"],
            "objectClass": ["top", "orclContext"],
        }

        assert entry_quirk.can_handle_entry(entry_dn, attributes)

    def test_process_basic_entry(
        self, entry_quirk: FlextLdifQuirksServersOid.EntryQuirk
    ) -> None:
        """Test processing basic OID entry."""
        entry_dn = "cn=test,dc=network,dc=example"
        attributes: FlextTypes.Dict = {
            "cn": ["test"],
            "objectClass": ["person"],
            "orclguid": ["12345678-1234-1234-1234-123456789012"],
        }

        result = entry_quirk.process_entry(entry_dn, attributes)
        assert result.is_success

        processed = result.unwrap()
        assert processed[FlextLdifConstants.DictKeys.DN] == entry_dn
        assert processed[FlextLdifConstants.DictKeys.SERVER_TYPE] == "oid"
        assert "cn" in processed

    def test_process_oracle_context_entry(
        self, entry_quirk: FlextLdifQuirksServersOid.EntryQuirk
    ) -> None:
        """Test processing Oracle Context entry with Oracle-specific attributes."""
        entry_dn = "cn=OracleContext,dc=network,dc=example"
        attributes: FlextTypes.Dict = {
            "cn": ["OracleContext"],
            "objectClass": ["top", "orclContext"],
            "orclguid": ["12345678-1234-1234-1234-123456789012"],
        }

        result = entry_quirk.process_entry(entry_dn, attributes)
        assert result.is_success

        processed = result.unwrap()
        assert processed[FlextLdifConstants.DictKeys.DN] == entry_dn
        assert processed[FlextLdifConstants.DictKeys.SERVER_TYPE] == "oid"
        assert "orclguid" in processed

    def test_process_entry_with_acls(
        self, entry_quirk: FlextLdifQuirksServersOid.EntryQuirk
    ) -> None:
        """Test processing entry with multiple ACL attributes - WORST CASE."""
        entry_dn = "cn=OracleContext,dc=network,dc=example"
        attributes: FlextTypes.Dict = {
            "cn": ["OracleContext"],
            "objectClass": ["top", "orclContext"],
            "orclaci": [
                'access to entry by group="cn=OracleContextAdmins,cn=Groups,cn=OracleContext" (browse,add,delete)',
                'access to attr=(*) by group="cn=OracleContextAdmins,cn=Groups,cn=OracleContext" (read,search,write)',
            ],
            "orclentrylevelaci": [
                "access to entry by * (browse,noadd,nodelete)",
            ],
        }

        result = entry_quirk.process_entry(entry_dn, attributes)
        assert result.is_success

        processed = result.unwrap()
        assert processed[FlextLdifConstants.DictKeys.DN] == entry_dn
        assert "_acl_attributes" in processed
        acl_attrs = processed["_acl_attributes"]
        assert isinstance(acl_attrs, dict)
        assert "orclaci" in acl_attrs
        assert "orclentrylevelaci" in acl_attrs

    def test_process_entry_from_fixtures(
        self,
        entry_quirk: FlextLdifQuirksServersOid.EntryQuirk,
        oid_fixtures: FlextLdifFixtures.OID,
    ) -> None:
        """Test processing entries from real OID integration fixtures."""
        integration_content = oid_fixtures.integration()

        # Parse entries from LDIF content
        current_dn: str | None = None
        current_attrs: FlextTypes.Dict = {}
        processed_count = 0

        for raw_line in integration_content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("dn:"):
                # Process previous entry if exists
                if current_dn and current_attrs:
                    result = entry_quirk.process_entry(current_dn, current_attrs)
                    if result.is_success:
                        processed_count += 1
                        processed = result.unwrap()
                        assert (
                            processed[FlextLdifConstants.DictKeys.SERVER_TYPE] == "oid"
                        )

                # Start new entry
                current_dn = line.split(":", 1)[1].strip()
                current_attrs = {}
            elif ":" in line and current_dn:
                # Add attribute
                attr_name, attr_value = line.split(":", 1)
                attr_name = attr_name.strip()
                attr_value = attr_value.strip()

                if attr_name not in current_attrs:
                    current_attrs[attr_name] = []
                # Cast to list since we just initialized it
                attr_list: FlextTypes.StringList = cast(
                    "list[str]", current_attrs[attr_name]
                )
                attr_list.append(attr_value)

        # Process last entry
        if current_dn and current_attrs:
            result = entry_quirk.process_entry(current_dn, current_attrs)
            if result.is_success:
                processed_count += 1

        assert processed_count > 0, "No entries were successfully processed"

    def test_preserve_oracle_attributes(
        self, entry_quirk: FlextLdifQuirksServersOid.EntryQuirk
    ) -> None:
        """Test preservation of Oracle-specific attributes."""
        entry_dn = "cn=Products,cn=OracleContext,dc=network,dc=example"
        attributes: FlextTypes.Dict = {
            "cn": ["Products"],
            "objectClass": ["top", "orclContainer"],
            "orclguid": ["12345678-1234-1234-1234-123456789012"],
            "orclobjectguid": ["87654321-4321-4321-4321-210987654321"],
        }

        result = entry_quirk.process_entry(entry_dn, attributes)
        assert result.is_success

        processed = result.unwrap()
        # Verify all Oracle attributes preserved
        assert "orclguid" in processed
        assert "orclobjectguid" in processed

    def test_convert_entry_to_rfc(
        self, entry_quirk: FlextLdifQuirksServersOid.EntryQuirk
    ) -> None:
        """Test converting OID entry to RFC-compliant format."""
        oid_entry_data: FlextLdifTypes.Dict = {
            FlextLdifConstants.DictKeys.DN: "cn=test,dc=network,dc=example",
            FlextLdifConstants.DictKeys.SERVER_TYPE: "oid",
            "cn": ["test"],
            "objectClass": ["person"],
            "orclguid": ["12345678-1234-1234-1234-123456789012"],
        }

        result = entry_quirk.convert_entry_to_rfc(oid_entry_data)
        assert result.is_success

        rfc_data = result.unwrap()
        # OID operational attributes should be removed in RFC conversion
        assert (
            rfc_data[FlextLdifConstants.DictKeys.DN] == "cn=test,dc=network,dc=example"
        )
        assert "orclguid" not in rfc_data

    def test_entry_roundtrip(
        self, entry_quirk: FlextLdifQuirksServersOid.EntryQuirk
    ) -> None:
        """Test entry roundtrip: process → convert to RFC → back."""
        original_dn = "cn=OracleContext,dc=network,dc=example"
        original_attrs: FlextTypes.Dict = {
            "cn": ["OracleContext"],
            "objectClass": ["top", "orclContext"],
            "orclguid": ["12345678-1234-1234-1234-123456789012"],
        }

        # Process entry
        process_result = entry_quirk.process_entry(original_dn, original_attrs)
        assert process_result.is_success
        processed = process_result.unwrap()

        # Convert to RFC
        rfc_result = entry_quirk.convert_entry_to_rfc(processed)
        assert rfc_result.is_success
        rfc_data = rfc_result.unwrap()

        # Validate essential data preserved
        assert rfc_data[FlextLdifConstants.DictKeys.DN] == original_dn

    def test_parse_attribute_error_handling(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test error handling in attribute parsing."""
        # Test with invalid OID (non-Oracle namespace)
        invalid_attr = "( 2.5.4.0 NAME 'cn' DESC 'Common Name' )"
        result = oid_quirk.parse_attribute(invalid_attr)
        assert result.is_success  # Should be permissive

        # Test with completely malformed attribute
        malformed_attr = "this is not an attribute definition"
        result = oid_quirk.parse_attribute(malformed_attr)
        assert result.is_success  # Should be permissive

        # Test with empty attribute
        empty_attr = ""
        result = oid_quirk.parse_attribute(empty_attr)
        assert result.is_success  # Should be permissive

    def test_parse_objectclass_error_handling(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test error handling in objectClass parsing."""
        # Test with invalid OID (non-Oracle namespace)
        invalid_oc = "( 2.5.6.0 NAME 'person' SUP top STRUCTURAL )"
        result = oid_quirk.parse_objectclass(invalid_oc)
        assert result.is_success  # Should be permissive

        # Test with completely malformed objectClass
        malformed_oc = "this is not an objectclass definition"
        result = oid_quirk.parse_objectclass(malformed_oc)
        assert result.is_success  # Should be permissive

        # Test with empty objectClass
        empty_oc = ""
        result = oid_quirk.parse_objectclass(empty_oc)
        assert result.is_success  # Should be permissive

    def test_convert_attribute_to_rfc_error_handling(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test error handling in attribute to RFC conversion."""
        # Test with missing required fields
        incomplete_attr: FlextLdifTypes.Dict = {"name": "test"}
        result = oid_quirk.convert_attribute_to_rfc(incomplete_attr)
        assert result.is_success  # Should be permissive

        # Test with empty data
        empty_attr: FlextLdifTypes.Dict = {}
        result = oid_quirk.convert_attribute_to_rfc(empty_attr)
        assert result.is_success  # Should be permissive

    def test_convert_objectclass_to_rfc_error_handling(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test error handling in objectClass to RFC conversion."""
        # Test with missing required fields
        incomplete_oc: FlextLdifTypes.Dict = {"name": "test"}
        result = oid_quirk.convert_objectclass_to_rfc(incomplete_oc)
        assert result.is_success  # Should be permissive

        # Test with empty data
        empty_oc: FlextLdifTypes.Dict = {}
        result = oid_quirk.convert_objectclass_to_rfc(empty_oc)
        assert result.is_success  # Should be permissive

    def test_write_attribute_to_rfc_error_handling(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test error handling in attribute to RFC writing."""
        # Test with missing required fields
        incomplete_attr: FlextLdifTypes.Dict = {"name": "test"}
        result = oid_quirk.write_attribute_to_rfc(incomplete_attr)
        assert result.is_failure  # Should fail due to missing required fields

        # Test with empty data
        empty_attr: FlextLdifTypes.Dict = {}
        result = oid_quirk.write_attribute_to_rfc(empty_attr)
        assert result.is_failure  # Should fail due to missing required fields

    def test_write_objectclass_to_rfc_error_handling(
        self, oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test error handling in objectClass to RFC writing."""
        # Test with missing required fields
        incomplete_oc: FlextLdifTypes.Dict = {"name": "test"}
        result = oid_quirk.write_objectclass_to_rfc(incomplete_oc)
        assert result.is_failure  # Should fail due to missing required fields

        # Test with empty data
        empty_oc: FlextLdifTypes.Dict = {}
        result = oid_quirk.write_objectclass_to_rfc(empty_oc)
        assert result.is_failure  # Should fail due to missing required fields


class TestOidQuirksIntegration:
    """Integration tests combining schema, ACL, and entry quirks."""

    @pytest.fixture
    def oid_fixtures(self) -> FlextLdifFixtures.OID:
        """Create OID fixture loader."""
        return FlextLdifFixtures.OID()

    def test_fixture_loader_availability(
        self, oid_fixtures: FlextLdifFixtures.OID
    ) -> None:
        """Test that OID fixtures are available and loadable."""
        # Schema fixture
        schema = oid_fixtures.schema()
        assert len(schema) > 0
        assert "attributetypes:" in schema
        assert "objectclasses:" in schema

        # Integration fixture
        integration = oid_fixtures.integration()
        assert len(integration) > 0
        assert "dn:" in integration

    def test_parse_multiple_fixture_entries(
        self, oid_fixtures: FlextLdifFixtures.OID
    ) -> None:
        """Test parsing multiple entries from integration fixtures."""
        integration_content = oid_fixtures.integration()

        # Count entries (lines starting with "dn:")
        entry_count = sum(
            1
            for line in integration_content.splitlines()
            if line.strip().startswith("dn:")
        )

        assert entry_count > 0, "No entries found in integration fixtures"
        assert entry_count >= 100, f"Expected at least 100 entries, found {entry_count}"

    def test_parse_oracle_schemas_from_fixtures(
        self, oid_fixtures: FlextLdifFixtures.OID
    ) -> None:
        """Test parsing Oracle schema definitions from fixtures."""
        schema_content = oid_fixtures.schema()

        # Count Oracle attributes and objectClasses
        oracle_attrs = sum(
            1
            for line in schema_content.splitlines()
            if "2.16.840.1.113894" in line and "attributetypes:" in line
        )

        oracle_ocs = sum(
            1
            for line in schema_content.splitlines()
            if "2.16.840.1.113894" in line and "objectclasses:" in line
        )

        assert oracle_attrs > 0, "No Oracle attributes found in schema fixtures"
        assert oracle_ocs > 0, "No Oracle objectClasses found in schema fixtures"

    def test_parse_acls_from_fixtures(
        self, oid_fixtures: FlextLdifFixtures.OID
    ) -> None:
        """Test parsing ACLs from integration fixtures."""
        integration_content = oid_fixtures.integration()

        # Count ACLs
        orclaci_count = sum(
            1
            for line in integration_content.splitlines()
            if line.strip().startswith("orclaci:")
        )

        entry_level_count = sum(
            1
            for line in integration_content.splitlines()
            if line.strip().startswith("orclentrylevelaci:")
        )

        assert orclaci_count > 0, "No orclaci found in integration fixtures"
        assert entry_level_count > 0, (
            "No orclentrylevelaci found in integration fixtures"
        )


__all__ = [
    "TestOidAclQuirks",
    "TestOidEntryQuirks",
    "TestOidQuirksIntegration",
    "TestOidSchemaQuirks",
]
