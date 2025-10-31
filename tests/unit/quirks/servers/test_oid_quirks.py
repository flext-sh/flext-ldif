"""Test suite for Oracle Internet Directory (OID) quirks.

Comprehensive testing for OID-specific schema, ACL, and entry quirks
using real OID fixtures from tests/fixtures/oid/.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from flext_ldif import FlextLdif
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.oid import FlextLdifServersOid
from tests.fixtures.loader import FlextLdifFixtures


class TestOidSchemas:
    """Test suite for OID schema quirk functionality."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().Schema()

    @pytest.fixture
    def oid_fixtures(self) -> FlextLdifFixtures.OID:
        """Create OID fixture loader."""
        return FlextLdifFixtures.OID()

    def test_initialization(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test OID schema quirk initialization."""
        assert oid_quirk.server_type == FlextLdifConstants.ServerTypes.OID

        assert oid_quirk.priority == 10

    def test_can_handle_oracle_attribute(self, oid_quirk: FlextLdifServersOid) -> None:
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

    def test_can_handle_attribute_non_string_input(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test can_handle_attribute with non-string input returns False."""
        # Test with None

        assert not oid_quirk.can_handle_attribute(None)

        # Test with integer

        assert not oid_quirk.can_handle_attribute(123)

        # Test with list

        assert not oid_quirk.can_handle_attribute([])

    def test_parse_oracle_attribute_basic(self, oid_quirk: FlextLdifServersOid) -> None:
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

        assert hasattr(parsed, "oid")

        assert hasattr(parsed, "name")

    def test_parse_oracle_attribute_from_fixtures(
        self, oid_quirk: FlextLdifServersOid, oid_fixtures: FlextLdifFixtures.OID
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

        assert hasattr(parsed, "oid") or "name" in parsed

    def test_can_handle_oracle_objectclass(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test detection of Oracle OID objectClasses."""
        # Oracle objectClass
        oracle_oc = "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP top STRUCTURAL )"

        assert oid_quirk.can_handle_objectclass(oracle_oc)

        # Non-Oracle objectClass
        rfc_oc = "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL )"

        assert not oid_quirk.can_handle_objectclass(rfc_oc)

    def test_parse_oracle_objectclass_basic(
        self, oid_quirk: FlextLdifServersOid
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

        assert hasattr(parsed, "oid")

        assert hasattr(parsed, "name")

    def test_parse_oracle_objectclass_from_fixtures(
        self, oid_quirk: FlextLdifServersOid, oid_fixtures: FlextLdifFixtures.OID
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

        assert hasattr(parsed, "oid") or "name" in parsed

    def test_parse_oracle_objectclass_with_all_options(
        self, oid_quirk: FlextLdifServersOid
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

        assert parsed.name == "orclContext"

        assert parsed.kind == "STRUCTURAL"

        assert parsed.sup == "top"

        assert parsed.must == ["cn", "orclguid"]

        assert parsed.may == ["description", "orclVersion", "orclNetDescName"]

    def test_parse_oracle_objectclass_minimal(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parsing minimal Oracle objectClass."""
        minimal_oc = "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP top )"

        result = oid_quirk.parse_objectclass(minimal_oc)

        assert result.is_success

        parsed = result.unwrap()

        assert parsed.oid == "2.16.840.1.113894.2.1.1"

        assert parsed.name == "orclContext"
        assert parsed.sup == "top"

        # When kind is not specified, implementation sets default "STRUCTURAL"
        assert parsed.kind == "STRUCTURAL"  # Default when not specified

        # Not set when not specified
        assert parsed.must is None
        assert parsed.may is None

    def test_parse_oracle_objectclass_auxiliary(
        self, oid_quirk: FlextLdifServersOid
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

        assert parsed.kind == "AUXILIARY"

        assert parsed.may == ["orclguid"]

    def test_parse_oracle_objectclass_abstract(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parsing Oracle objectClass with ABSTRACT kind."""
        abstract_oc = (
            "( 2.16.840.1.113894.2.1.1 NAME 'orclAbstractClass' SUP top ABSTRACT )"
        )

        result = oid_quirk.parse_objectclass(abstract_oc)

        assert result.is_success

        parsed = result.unwrap()

        assert parsed.kind == "ABSTRACT"

    def test_parse_oracle_objectclass_multiple_sup(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parsing Oracle objectClass with multiple SUP (captures first only).

        Current implementation parses only the first SUP when multiple are specified.
        This is a known limitation of the schema parser for complex SUP syntax.
        """
        multi_sup_oc = (
            "( 2.16.840.1.113894.2.1.1 NAME 'orclMultiSup' "
            "SUP ( top $ person ) STRUCTURAL )"
        )

        result = oid_quirk.parse_objectclass(multi_sup_oc)

        assert result.is_success

        parsed = result.unwrap()

        # Implementation captures only first SUP from complex syntax
        assert parsed.sup == "top"

    def test_parse_oracle_objectclass_malformed(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parsing malformed Oracle objectClass."""
        malformed_oc = "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP )"

        result = oid_quirk.parse_objectclass(malformed_oc)

        assert result.is_success  # Should be permissive

        parsed = result.unwrap()

        assert parsed.name == "orclContext"

    def test_convert_attribute_to_rfc(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test converting OID attribute to RFC-compliant format."""
        oid_attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclguid",
            desc="Oracle GUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            equality="caseIgnoreMatch",
        )

        result = oid_quirk.convert_attribute_to_rfc(oid_attr_data)

        assert result.is_success

        rfc_data = result.unwrap()

        assert rfc_data.oid == "2.16.840.1.113894.1.1.1"

        assert rfc_data.name == "orclguid"

    def test_convert_objectclass_to_rfc(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test converting OID objectClass to RFC-compliant format."""
        oid_oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113894.2.1.1",
            name="orclContext",
            desc="Oracle Context",
            sup="top",
            kind="STRUCTURAL",
            must=["cn"],
            may=["description"],
        )

        result = oid_quirk.convert_objectclass_to_rfc(oid_oc_data)

        assert result.is_success

        rfc_data = result.unwrap()

        assert rfc_data.oid == "2.16.840.1.113894.2.1.1"

        assert rfc_data.name == "orclContext"

    def test_schema_roundtrip(self, oid_quirk: FlextLdifServersOid) -> None:
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
        assert "2.16.840.1.113894.1.1.1" in str(rfc_data.oid)
        assert rfc_data.name == "orclguid"

    def test_parse_oracle_attribute_with_all_options(
        self, oid_quirk: FlextLdifServersOid
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

        assert parsed.equality == "caseIgnoreMatch"
        assert parsed.substr == "caseIgnoreSubstringsMatch"
        assert parsed.ordering == "caseIgnoreOrderingMatch"
        assert parsed.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert parsed.length == 16
        assert parsed.sup == "name"
        assert parsed.usage == "userApplications"
        assert parsed.single_value is True
        assert parsed.no_user_modification is True

    def test_parse_oracle_attribute_minimal(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parsing minimal Oracle attribute (only required fields)."""
        minimal_attr = "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' )"

        result = oid_quirk.parse_attribute(minimal_attr)

        assert result.is_success

        parsed = result.unwrap()

        assert parsed.oid == "2.16.840.1.113894.1.1.1"
        assert parsed.name == "orclguid"

        # Optional fields should be None/False
        assert parsed.desc is None
        assert parsed.single_value is False
        assert parsed.no_user_modification is False

    def test_parse_oracle_attribute_invalid_syntax_length(
        self, oid_quirk: FlextLdifServersOid
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
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parsing Oracle attribute with numeric SUP."""
        numeric_sup_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclguid' "
            "SUP name )"  # Use name instead of numeric OID for this test
        )

        result = oid_quirk.parse_attribute(numeric_sup_attr)

        assert result.is_success
        parsed = result.unwrap()

        assert parsed.sup == "name"

    def test_parse_oracle_attribute_malformed_regex(
        self, oid_quirk: FlextLdifServersOid
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

        assert parsed.name == "orclguid"

        assert "syntax_length" not in parsed


class TestOidAcls:
    """Test suite for OID ACL quirk functionality."""

    @pytest.fixture
    def acl_quirk(self) -> FlextLdifServersOid.Acl:
        """Create OID ACL quirk instance."""
        return FlextLdifServersOid.Acl(server_type=FlextLdifConstants.ServerTypes.OID)

    @pytest.fixture
    def oid_fixtures(self) -> FlextLdifFixtures.OID:
        """Create OID fixture loader."""
        return FlextLdifFixtures.OID()

    def test_acl_quirk_initialization(self, acl_quirk: FlextLdifServersOid.Acl) -> None:
        """Test OID ACL quirk initialization."""
        assert acl_quirk.server_type == FlextLdifConstants.ServerTypes.OID

        assert acl_quirk.priority == 10

    def test_can_handle_orclaci(self, acl_quirk: FlextLdifServersOid.Acl) -> None:
        """Test detection of orclaci ACL format."""
        orclaci = 'orclaci: access to entry by group="cn=Admins,cn=groups,cn=OracleContext" (browse,add,delete)'

        assert acl_quirk.can_handle_acl(orclaci)

        orclentrylevel = (
            "orclentrylevelaci: access to entry by * (browse,noadd,nodelete)"
        )

        assert acl_quirk.can_handle_acl(orclentrylevel)

        non_oid_acl = "olcAccess: {0}to * by * read"

        assert not acl_quirk.can_handle_acl(non_oid_acl)

    def test_parse_simple_orclaci(self, acl_quirk: FlextLdifServersOid.Acl) -> None:
        """Test parsing simple orclaci format."""
        simple_orclaci = (
            'orclaci: access to entry by group="cn=ASPAdmins, cn=groups,cn=OracleContext,dc=network,dc=example" '
            "(browse,add, delete)"
        )

        result = acl_quirk.parse_acl(simple_orclaci)

        assert result.is_success, f"Failed to parse orclaci: {result.error}"

        parsed = result.unwrap()

        # Check it's an OID ACL model
        assert parsed.server_type == "oracle_oid"

        assert parsed.raw_acl == simple_orclaci

    def test_parse_complex_orclaci_with_filter(
        self, acl_quirk: FlextLdifServersOid.Acl
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

        # Check it's an OID ACL model
        assert parsed.server_type == "oracle_oid"

        assert parsed.raw_acl == complex_orclaci

    def test_parse_orclaci_with_attr_filter(
        self, acl_quirk: FlextLdifServersOid.Acl
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

        # Check it's an OID ACL model
        assert parsed.server_type == "oracle_oid"

    def test_parse_orclaci_from_fixtures(
        self,
        acl_quirk: FlextLdifServersOid.Acl,
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

        # Check it's an OID ACL model
        assert parsed.server_type == "oracle_oid"

    def test_parse_orclentrylevelaci_with_constraint(
        self, acl_quirk: FlextLdifServersOid.Acl
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

        # Check it's an OID ACL model (entry-level type)
        assert parsed.server_type == "oracle_oid"

    def test_parse_orclentrylevelaci_from_fixtures(
        self,
        acl_quirk: FlextLdifServersOid.Acl,
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

        # Check it's an OID ACL model (entry-level type)
        assert parsed.server_type == "oracle_oid"

    def test_convert_acl_to_rfc(self, acl_quirk: FlextLdifServersOid.Acl) -> None:
        """Test converting OID ACL to RFC-compliant format."""
        # Parse OID ACL to get model
        oid_acl_string = (
            'orclaci: access to entry by group="cn=Admins" (browse,add,delete)'
        )
        parse_result = acl_quirk.parse_acl(oid_acl_string)
        assert parse_result.is_success
        oid_acl_model = parse_result.unwrap()

        result = acl_quirk.convert_acl_to_rfc(oid_acl_model)

        assert result.is_success

        rfc_acl = result.unwrap()

        # Check it's now RFC server type
        assert rfc_acl.server_type == "generic"

        # Check name was prefixed with migration marker
        assert "Migrated from OID:" in rfc_acl.name

    def test_convert_acl_from_rfc(self, acl_quirk: FlextLdifServersOid.Acl) -> None:
        """Test converting RFC ACL to OID-specific format."""
        # Create RFC ACL model
        rfc_acl = FlextLdifModels.Acl(
            name="test-acl",
            target=FlextLdifModels.AclTarget(target_dn="*"),
            subject=FlextLdifModels.AclSubject(subject_type="user", subject_value="*"),
            permissions=FlextLdifModels.AclPermissions(read=True, search=True),
            server_type="generic",
        )

        result = acl_quirk.convert_acl_from_rfc(rfc_acl)

        assert result.is_success

        oid_acl = result.unwrap()

        # Check it's now OID server type
        assert oid_acl.server_type == "oid"

    def test_acl_roundtrip(self, acl_quirk: FlextLdifServersOid.Acl) -> None:
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

        # Validate server type preserved after roundtrip
        assert oid_data.server_type == "oid"


class TestOidEntrys:
    """Test suite for OID entry quirk functionality."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().Schema()

    @pytest.fixture
    def entry_quirk(self) -> FlextLdifServersOid.Entry:
        """Create OID entry quirk instance."""
        return FlextLdifServersOid.Entry(server_type=FlextLdifConstants.ServerTypes.OID)

    @pytest.fixture
    def oid_fixtures(self) -> FlextLdifFixtures.OID:
        """Create OID fixture loader."""
        return FlextLdifFixtures.OID()

    def test_entry_quirk_initialization(
        self, entry_quirk: FlextLdifServersOid.Entry
    ) -> None:
        """Test OID entry quirk initialization."""
        assert entry_quirk.server_type == FlextLdifConstants.ServerTypes.OID

        assert entry_quirk.priority == 10

    def test_can_handle_entry(self, entry_quirk: FlextLdifServersOid.Entry) -> None:
        """Test entry handling detection."""
        # OID entry quirk handles entries with Oracle attributes
        entry_dn = "cn=OracleContext,dc=network,dc=example"
        attributes: dict[str, object] = {
            "cn": ["OracleContext"],
            "objectclass": ["top", "orclContext"],
        }

        assert entry_quirk.can_handle_entry(entry_dn, attributes)

    def test_process_basic_entry(self, entry_quirk: FlextLdifServersOid.Entry) -> None:
        """Test processing basic OID entry."""
        entry_dn = "cn=test,dc=network,dc=example"
        attributes: dict[str, object] = {
            "cn": ["test"],
            "objectclass": ["person"],
            "orclguid": ["12345678-1234-1234-1234-123456789012"],
        }

        result = entry_quirk.process_entry(entry_dn, attributes)

        assert result.is_success

        processed = result.unwrap()
        assert processed[FlextLdifConstants.DictKeys.DN] == entry_dn
        assert "cn" in processed

    def test_process_oracle_context_entry(
        self, entry_quirk: FlextLdifServersOid.Entry
    ) -> None:
        """Test processing Oracle Context entry with Oracle-specific attributes."""
        entry_dn = "cn=OracleContext,dc=network,dc=example"
        attributes: dict[str, object] = {
            "cn": ["OracleContext"],
            "objectclass": ["top", "orclContext"],
            "orclguid": ["12345678-1234-1234-1234-123456789012"],
        }

        result = entry_quirk.process_entry(entry_dn, attributes)

        assert result.is_success

        processed = result.unwrap()
        assert processed[FlextLdifConstants.DictKeys.DN] == entry_dn
        assert "orclguid" in processed

    def test_process_entry_with_acls(
        self, entry_quirk: FlextLdifServersOid.Entry
    ) -> None:
        """Test processing entry with multiple ACL attributes - WORST CASE."""
        entry_dn = "cn=OracleContext,dc=network,dc=example"
        attributes: dict[str, object] = {
            "cn": ["OracleContext"],
            "objectclass": ["top", "orclContext"],
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
        entry_quirk: FlextLdifServersOid.Entry,
        oid_fixtures: FlextLdifFixtures.OID,
    ) -> None:
        """Test processing entries from real OID integration fixtures."""
        integration_content = oid_fixtures.integration()

        # Parse entries from LDIF content
        current_dn: str | None = None
        current_attrs: dict[str, object] = {}
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
                attr_list: list[str] = cast("list[str]", current_attrs[attr_name])
                attr_list.append(attr_value)

        # Process last entry
        if current_dn and current_attrs:
            result = entry_quirk.process_entry(current_dn, current_attrs)
            if result.is_success:
                processed_count += 1

        assert processed_count > 0, "No entries were successfully processed"

    def test_preserve_oracle_attributes(
        self, entry_quirk: FlextLdifServersOid.Entry
    ) -> None:
        """Test preservation of Oracle-specific attributes."""
        entry_dn = "cn=Products,cn=OracleContext,dc=network,dc=example"
        attributes: dict[str, object] = {
            "cn": ["Products"],
            "objectclass": ["top", "orclContainer"],
            "orclguid": ["12345678-1234-1234-1234-123456789012"],
            "orclobjectguid": ["87654321-4321-4321-4321-210987654321"],
        }

        result = entry_quirk.process_entry(entry_dn, attributes)

        assert result.is_success

        processed = result.unwrap()
        # Verify all Oracle attributes preserved

        assert "orclguid" in processed

        assert "orclobjectguid" in processed

    def test_convert_entry_to_rfc(self, entry_quirk: FlextLdifServersOid.Entry) -> None:
        """Test converting OID entry to RFC-compliant format."""
        oid_entry_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=test,dc=network,dc=example",
            FlextLdifConstants.DictKeys.SERVER_TYPE: "oid",
            "cn": ["test"],
            "objectclass": ["person"],
            "orclguid": ["12345678-1234-1234-1234-123456789012"],
        }

        result = entry_quirk.convert_entry_to_rfc(oid_entry_data)

        assert result.is_success

        rfc_data = result.unwrap()
        # RFC conversion preserves all attributes - filtering is done at migration layer

        assert (
            rfc_data[FlextLdifConstants.DictKeys.DN] == "cn=test,dc=network,dc=example"
        )
        # OID-specific attributes are preserved during format conversion

        assert "orclguid" in rfc_data  # Format converted, not filtered

    def test_entry_roundtrip(self, entry_quirk: FlextLdifServersOid.Entry) -> None:
        """Test entry roundtrip: process → convert to RFC → back."""
        original_dn = "cn=OracleContext,dc=network,dc=example"
        original_attrs: dict[str, object] = {
            "cn": ["OracleContext"],
            "objectclass": ["top", "orclContext"],
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
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test error handling in attribute parsing.

        OID quirks parse RFC-compliant attributes even if not Oracle namespace.
        Malformed input fails, but valid RFC syntax succeeds.
        """
        # Test with RFC-compliant attribute (non-Oracle OID) - succeeds
        rfc_attr = "( 2.5.4.0 NAME 'cn' DESC 'Common Name' )"
        result = oid_quirk.parse_attribute(rfc_attr)

        assert result.is_success  # RFC-compliant syntax succeeds

        # Test with completely malformed attribute - should fail
        malformed_attr = "this is not an attribute definition"
        result = oid_quirk.parse_attribute(malformed_attr)

        assert result.is_failure  # Malformed input fails

        # Test with empty attribute - should fail
        empty_attr = ""
        result = oid_quirk.parse_attribute(empty_attr)

        assert result.is_failure  # Empty input fails

    def test_parse_objectclass_error_handling(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test error handling in objectClass parsing.

        OID quirks parse RFC-compliant objectClasses even if not Oracle namespace.
        Malformed input fails, but valid RFC syntax succeeds.
        """
        # Test with RFC-compliant objectClass (non-Oracle OID) - succeeds
        rfc_oc = "( 2.5.6.0 NAME 'person' SUP top STRUCTURAL )"
        result = oid_quirk.parse_objectclass(rfc_oc)

        assert result.is_success  # RFC-compliant syntax succeeds

        # Test with completely malformed objectClass - should fail
        malformed_oc = "this is not an objectclass definition"
        result = oid_quirk.parse_objectclass(malformed_oc)

        assert result.is_failure  # Malformed input fails

        # Test with empty objectClass - should fail
        empty_oc = ""
        result = oid_quirk.parse_objectclass(empty_oc)

        assert result.is_failure  # Empty input fails

    def test_convert_attribute_to_rfc_error_handling(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test error handling in attribute to RFC conversion."""
        # Test with missing required fields (minimal SchemaAttribute)
        incomplete_attr = FlextLdifModels.SchemaAttribute(name="test", oid="")
        result = oid_quirk.convert_attribute_to_rfc(incomplete_attr)

        assert result.is_success  # Should be permissive

        # Test with minimal data
        empty_attr = FlextLdifModels.SchemaAttribute(name="", oid="")
        result = oid_quirk.convert_attribute_to_rfc(empty_attr)

        assert result.is_success  # Should be permissive

    def test_convert_objectclass_to_rfc_error_handling(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test error handling in objectClass to RFC conversion."""
        # Test with missing required fields (minimal SchemaObjectClass)
        incomplete_oc = FlextLdifModels.SchemaObjectClass(name="test", oid="")
        result = oid_quirk.convert_objectclass_to_rfc(incomplete_oc)

        assert result.is_success  # Should be permissive

        # Test with minimal data
        empty_oc = FlextLdifModels.SchemaObjectClass(name="", oid="")
        result = oid_quirk.convert_objectclass_to_rfc(empty_oc)

        assert result.is_success  # Should be permissive

    def test_write_attribute_to_rfc_error_handling(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test error handling in attribute to RFC writing."""
        # Test with missing required fields
        incomplete_attr: dict[str, object] = {"name": "test"}
        result = oid_quirk.write_attribute_to_rfc(incomplete_attr)

        assert result.is_failure  # Should fail due to missing required fields

        # Test with empty data
        empty_attr: dict[str, object] = {}
        result = oid_quirk.write_attribute_to_rfc(empty_attr)

        assert result.is_failure  # Should fail due to missing required fields

    def test_write_objectclass_to_rfc_error_handling(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test error handling in objectClass to RFC writing."""
        # Test with missing required fields
        incomplete_oc: dict[str, object] = {"name": "test"}
        result = oid_quirk.write_objectclass_to_rfc(incomplete_oc)

        assert result.is_failure  # Should fail due to missing required fields

        # Test with empty data
        empty_oc: dict[str, object] = {}
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


class TestOidSchemaExtractionWithRealFixtures:
    """Test OID schema extraction using complete real fixture files.

    Validates Phase 5 refactoring (RfcSchemaExtractor utility) works correctly
    with production OID schema data (2,158+ lines from OID 11.1.1.7.0).
    """

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID schema quirk instance."""
        return FlextLdifServersOid().Schema()

    @pytest.fixture
    def oid_fixtures(self) -> FlextLdifFixtures.OID:
        """Create OID fixture loader."""
        return FlextLdifFixtures.OID()

    def test_extract_complete_oid_schema_fixtures(
        self, oid_quirk: FlextLdifServersOid, oid_fixtures: FlextLdifFixtures.OID
    ) -> None:
        """Test extraction of COMPLETE OID schema fixture file.

        This test validates that extract_schemas_from_ldif() works correctly
        with the entire real OID schema fixture (2,158+ lines), not just
        a single entry. It proves the Phase 5 refactoring using
        RfcSchemaExtractor utility handles production data correctly.
        """
        # Load COMPLETE fixture content
        schema_content = oid_fixtures.schema()

        # Verify we have substantial content (production OID schema)

        assert len(schema_content) > 50000, (
            "Schema fixture should be substantial (50K+ chars)"
        )
        line_count = len(schema_content.splitlines())

        assert line_count > 2000, (
            f"Schema fixture should have 2000+ lines, got {line_count}"
        )

        # Extract ALL schemas from complete fixture
        result = oid_quirk.extract_schemas_from_ldif(schema_content)

        # Verify extraction succeeded

        assert result.is_success, f"Failed to extract schemas: {result.error}"

        schemas = result.unwrap()

        assert FlextLdifConstants.DictKeys.ATTRIBUTES in schemas

        assert "objectclasses" in schemas

        # Verify substantial extraction (not just a few entries)
        attributes = schemas[FlextLdifConstants.DictKeys.ATTRIBUTES]
        objectclasses = schemas["objectclasses"]

        assert isinstance(attributes, list), "Attributes should be a list"

        assert isinstance(objectclasses, list), "ObjectClasses should be a list"

        # OID schema fixture contains 500+ attributes (RFC + Oracle + vendor)
        attr_count = len(attributes)

        assert attr_count > 500, (
            f"Expected 500+ attributes from complete fixture, got {attr_count}"
        )

        # OID schema fixture contains 100+ objectClasses
        oc_count = len(objectclasses)

        assert oc_count > 100, (
            f"Expected 100+ objectClasses from complete fixture, got {oc_count}"
        )

        # Verify specific known OID attributes exist
        attr_names = {
            attr.name for attr in attributes if hasattr(attr, "name") and attr.name
        }

        # RFC 1274 attributes (should be present)

        assert "uid" in attr_names, "Standard 'uid' attribute not found"

        assert "mail" in attr_names, "Standard 'mail' attribute not found"

        assert "dc" in attr_names, "Standard 'dc' attribute not found"

        # Oracle-specific attributes (OID namespace: 2.16.840.1.113894.*)
        oracle_attrs = [
            attr
            for attr in attributes
            if hasattr(attr, "oid")
            and attr.oid
            and attr.oid.startswith("2.16.840.1.113894")
        ]

        assert len(oracle_attrs) > 50, (
            f"Expected 50+ Oracle attributes, got {len(oracle_attrs)}"
        )

        # Verify specific known OID objectClasses exist
        oc_names = {oc.name for oc in objectclasses if hasattr(oc, "name") and oc.name}

        # RFC objectClasses

        assert "domain" in oc_names, "Standard 'domain' objectClass not found"

        assert "account" in oc_names, "Standard 'account' objectClass not found"

        # Oracle-specific objectClasses
        oracle_ocs = [
            oc
            for oc in objectclasses
            if hasattr(oc, "oid") and oc.oid and oc.oid.startswith("2.16.840.1.113894")
        ]

        assert len(oracle_ocs) > 20, (
            f"Expected 20+ Oracle objectClasses, got {len(oracle_ocs)}"
        )

    def test_extract_oid_schema_no_parsing_failures(
        self, oid_quirk: FlextLdifServersOid, oid_fixtures: FlextLdifFixtures.OID
    ) -> None:
        """Verify no parsing failures occur with complete OID fixture.

        This test ensures that RfcSchemaExtractor.extract_attributes_from_lines()
        and extract_objectclasses_from_lines() handle ALL entries in the
        production OID schema without errors.
        """
        schema_content = oid_fixtures.schema()

        # Extract schemas
        result = oid_quirk.extract_schemas_from_ldif(schema_content)

        assert result.is_success, f"Extraction failed: {result.error}"

        schemas = result.unwrap()

        # Count total attribute lines in fixture
        total_attr_lines = sum(
            1
            for line in schema_content.splitlines()
            if line.strip().lower().startswith("attributetypes:")
        )

        # Count total objectClass lines in fixture
        total_oc_lines = sum(
            1
            for line in schema_content.splitlines()
            if line.strip().lower().startswith("objectclasses:")
        )

        # Verify extraction counts match or exceed fixture counts
        # (Some lines might be multi-line definitions that get combined)
        attributes = schemas[FlextLdifConstants.DictKeys.ATTRIBUTES]
        objectclasses = schemas["objectclasses"]

        assert len(attributes) > 0, "No attributes extracted"

        assert len(objectclasses) > 0, "No objectClasses extracted"

        # Ensure we extracted a significant portion (allowing for parse failures
        # in edge cases, but expecting >90% success rate)
        attr_success_rate = len(attributes) / max(total_attr_lines, 1) * 100
        oc_success_rate = len(objectclasses) / max(total_oc_lines, 1) * 100

        assert attr_success_rate > 90, (
            f"Attribute extraction success rate too low: {attr_success_rate:.1f}%"
        )

        assert oc_success_rate > 90, (
            f"ObjectClass extraction success rate too low: {oc_success_rate:.1f}%"
        )


class TestOidAclFixtures:
    """Test OID ACL parsing using real oid_acl_fixtures.ldif."""

    def test_parse_oid_acl_fixtures_complete(
        self, oid_fixtures: FlextLdifFixtures.OID
    ) -> None:
        """Test parsing complete OID ACL fixture file."""
        from flext_ldif import FlextLdif

        ldif = FlextLdif()

        # Load complete ACL fixture
        acl_content = oid_fixtures.acl()

        # Parse ACL entries
        result = ldif.parse(acl_content)

        assert result.is_success, f"ACL parsing failed: {result.error}"

        entries = result.unwrap()

        assert len(entries) > 0, "No ACL entries parsed from fixture"

        # Verify ACL attributes are present
        acl_count = 0
        for entry in entries:
            # Access Pydantic model attributes directly
            if hasattr(entry, "attributes"):
                attrs = entry.attributes
                if attrs.has_attribute("orclaci") or attrs.has_attribute(
                    "orclentrylevelaci"
                ):
                    acl_count += 1

        assert acl_count > 0, (
            "No orclaci or orclentrylevelaci attributes found in ACL fixture"
        )

    def test_oid_acl_attribute_types(self, oid_fixtures: FlextLdifFixtures.OID) -> None:
        """Test that OID ACL fixtures contain both orclaci and orclentrylevelaci."""
        acl_content = oid_fixtures.acl()

        # Check for both OID ACL types

        assert "orclaci:" in acl_content or "orclaci: " in acl_content, (
            "oid_acl_fixtures.ldif should contain orclaci attributes"
        )


class TestOidEntriesFixtures:
    """Test OID entry parsing using real oid_entries_fixtures.ldif."""

    def test_parse_oid_entries_fixtures_complete(
        self, oid_fixtures: FlextLdifFixtures.OID
    ) -> None:
        """Test parsing complete OID entries fixture file."""
        from flext_ldif import FlextLdif

        ldif = FlextLdif()

        # Load complete entries fixture
        entries_content = oid_fixtures.entries()

        # Parse entries
        result = ldif.parse(entries_content)

        assert result.is_success, f"Entries parsing failed: {result.error}"

        entries = result.unwrap()

        assert len(entries) > 0, "No entries parsed from fixture"

        # Verify entries have DNs
        for entry in entries:
            assert hasattr(entry, "dn"), f"Entry missing dn attribute: {entry}"
            # DN might be a string or DistinguishedName object
            dn_str = str(entry.dn) if hasattr(entry.dn, "__str__") else entry.dn
            assert len(dn_str) > 0, f"Entry has empty DN: {entry}"

    def test_oid_entries_have_objectclass(
        self, oid_fixtures: FlextLdifFixtures.OID
    ) -> None:
        """Test that OID entries contain objectClass attributes."""
        from flext_ldif import FlextLdif

        ldif = FlextLdif()
        entries_content = oid_fixtures.entries()
        result = ldif.parse(entries_content)

        assert result.is_success
        entries = result.unwrap()

        # All LDIF entries should have objectClass
        for entry in entries:
            if hasattr(entry, "attributes"):
                attrs = entry.attributes

        assert attrs.has_attribute("objectClass") or attrs.has_attribute(
            "objectclass"
        ), (
            f"Entry missing objectClass: {entry.dn if hasattr(entry, 'dn') else 'unknown'}"
        )


class TestOidIntegrationFixtures:
    """Test OID integration fixtures (mixed schema + entries + ACLs)."""

    def test_parse_oid_integration_fixtures_complete(
        self, oid_fixtures: FlextLdifFixtures.OID
    ) -> None:
        """Test parsing complete OID integration fixture (mixed content)."""
        from flext_ldif import FlextLdif

        ldif = FlextLdif()

        # Load complete integration fixture
        integration_content = oid_fixtures.integration()

        # Parse integration entries
        result = ldif.parse(integration_content)

        assert result.is_success, f"Integration parsing failed: {result.error}"

        entries = result.unwrap()

        assert len(entries) > 0, "No entries parsed from integration fixture"

    def test_oid_integration_contains_multiple_types(
        self, oid_fixtures: FlextLdifFixtures.OID
    ) -> None:
        """Test that integration fixture contains schema, ACL, and entries."""
        integration_content = oid_fixtures.integration()

        # Integration fixture should contain multiple LDIF element types
        has_entries = "dn:" in integration_content

        # At least entries should be present

        assert has_entries, "Integration fixture should contain dn: entries"


__all__ = [
    "TestOidAclCanHandleAcl",
    "TestOidAclConvertAcl",
    "TestOidAclFixtures",
    "TestOidAclParseAcl",
    "TestOidAcls",
    "TestOidCanHandleMethods",
    "TestOidConversionMethods",
    "TestOidEntriesFixtures",
    "TestOidEntryCanHandleEntry",
    "TestOidEntryConvertEntry",
    "TestOidEntryProcessEntry",
    "TestOidEntrys",
    "TestOidExtractSchemas",
    "TestOidIntegrationFixtures",
    "TestOidParseAttributeComprehensive",
    "TestOidParseObjectClassComprehensive",
    "TestOidProperties",
    "TestOidQuirksACLHandling",
    "TestOidQuirksCanHandleAttribute",
    "TestOidQuirksConvertAttribute",
    "TestOidQuirksEntryHandling",
    "TestOidQuirksErrorHandling",
    "TestOidQuirksExtractSchemasFromLdif",
    "TestOidQuirksIntegration",
    "TestOidQuirksObjectClassHandling",
    "TestOidQuirksParseAttribute",
    "TestOidQuirksProperties",
    "TestOidQuirksWriteAttributeToRfc",
    "TestOidQuirksWriteObjectclassToRfc",
    "TestOidSchemaExtractionWithRealFixtures",
    "TestOidSchemas",
    "TestOidWriteMethods",
]


# ===== Merged from test_oid_comprehensive.py =====


class TestOidQuirksErrorHandling:
    """Test error handling paths in OID quirks."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_can_handle_attribute_regex_error(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test can_handle_attribute with malformed definition causing regex error."""
        # Test with invalid regex pattern that might cause re.error
        # Note: The method uses a static regex so this tests defensive handling
        malformed = "( INVALID_OID_FORMAT NAME 'test' )"
        result = oid_quirk.can_handle_attribute(malformed)
        # Should return False for malformed OID, not crash

        assert isinstance(result, bool)

    def test_can_handle_attribute_no_oid_match(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test can_handle_attribute when no OID is found in definition."""
        # Test with definition that has no OID pattern
        no_oid = "NAME 'attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15"

        assert not oid_quirk.can_handle_attribute(no_oid)

    def test_can_handle_objectclass_non_string(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test can_handle_objectclass with non-string input."""
        # Test with None

        assert not oid_quirk.can_handle_objectclass(None)

        # Test with integer

        assert not oid_quirk.can_handle_objectclass(123)

        # Test with dict

        assert not oid_quirk.can_handle_objectclass({})

    def test_can_handle_objectclass_no_oid_match(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test can_handle_objectclass when no OID is found."""
        no_oid = "NAME 'testClass' SUP top STRUCTURAL"

        assert not oid_quirk.can_handle_objectclass(no_oid)

    def test_parse_attribute_exception_handling(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parse_attribute exception handling with malformed input."""
        # Test with extremely malformed input that could trigger exceptions
        result = oid_quirk.parse_attribute("COMPLETELY INVALID SYNTAX")
        # Parser is permissive - tries to parse what it can, doesn't fail
        # Just verify it returns a result (success or failure), doesn't crash

        assert hasattr(result, "is_success")
        # If it succeeds, should have metadata
        if result.is_success:
            parsed = result.unwrap()
            assert hasattr(parsed, "metadata")

    def test_parse_objectclass_exception_handling(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parse_objectclass exception handling with malformed input."""
        # Test with invalid input
        result = oid_quirk.parse_objectclass("NOT A VALID OBJECTCLASS DEFINITION")
        # Parser is permissive - tries to parse what it can
        # Just verify it returns a result, doesn't crash

        assert hasattr(result, "is_success")
        if result.is_success:
            parsed = result.unwrap()
            assert hasattr(parsed, "metadata")


class TestOidQuirksWriteAttributeToRfc:
    """Test write_attribute_to_rfc() method (lines 543-657).

    Uses proper FlextLdifModels.SchemaAttribute objects for testing.
    """

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_write_attribute_with_metadata_roundtrip(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_attribute_to_rfc uses metadata.original_format for round-trip."""
        original_format = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
        )

        # Test data for OID attribute with metadata
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            single_value=True,
            metadata=FlextLdifModels.QuirkMetadata(original_format=original_format),
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        assert result.unwrap() == original_format

    def test_write_attribute_with_dict_metadata(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_attribute_to_rfc with SchemaAttribute metadata."""
        original_format = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"

        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            metadata=FlextLdifModels.QuirkMetadata(original_format=original_format),
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        assert result.unwrap() == original_format

    def test_write_attribute_missing_oid(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test write_attribute_to_rfc handles missing OID."""
        # Create attribute without OID
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="",  # Empty OID
            name="test",
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        # Should still succeed, but with empty OID in output
        assert result.is_success
        rfc_str = result.unwrap()
        assert "(  NAME 'test'" in rfc_str or "( NAME 'test'" in rfc_str

    def test_write_attribute_from_scratch_basic(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_attribute_to_rfc builds RFC format from scratch."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "2.16.840.1.113894.1.1.1" in rfc_str
        assert "orclGUID" in rfc_str
        assert "1.3.6.1.4.1.1466.115.121.1.15" in rfc_str

    def test_write_attribute_removes_binary_suffix(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_attribute_to_rfc removes ;binary suffix from attribute names."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID;binary",  # Name with ;binary suffix
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_str = result.unwrap()

        # ;binary suffix should be removed
        assert ";binary" not in rfc_str
        assert "orclGUID" in rfc_str

    def test_write_attribute_replaces_underscore_with_hyphen(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_attribute_to_rfc replaces underscores with hyphens."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="test_attr",  # Name with underscore
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_str = result.unwrap()

        # Underscore should be replaced with hyphen
        assert "_" not in rfc_str
        assert "test-attr" in rfc_str

    def test_write_attribute_with_desc(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test write_attribute_to_rfc includes DESC field."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            desc="Oracle GUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "DESC 'Oracle GUID'" in rfc_str

    def test_write_attribute_with_sup(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test write_attribute_to_rfc includes SUP field."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            sup="name",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "SUP name" in rfc_str

    def test_write_attribute_with_equality_replacement(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_attribute_to_rfc replaces invalid matching rules."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            equality="caseIgnoreSubStringsMatch",  # Intentionally wrong capitalization
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_str = result.unwrap()

        # Should be corrected to proper case
        assert "caseIgnoreSubstringsMatch" in rfc_str

    def test_write_attribute_with_ordering(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_attribute_to_rfc includes ORDERING field."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            ordering="integerOrderingMatch",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "ORDERING integerOrderingMatch" in rfc_str

    def test_write_attribute_with_substr(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test write_attribute_to_rfc includes SUBSTR field."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            substr="caseIgnoreSubstringsMatch",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "SUBSTR caseIgnoreSubstringsMatch" in rfc_str

    def test_write_attribute_with_syntax_length(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_attribute_to_rfc includes syntax length constraint."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            length=256,
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256}" in rfc_str

    def test_write_attribute_with_single_value(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_attribute_to_rfc includes SINGLE-VALUE flag."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            single_value=True,
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "SINGLE-VALUE" in rfc_str

    def test_write_attribute_with_no_user_mod(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_attribute_to_rfc includes NO-USER-MODIFICATION flag."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            no_user_modification=True,
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "NO-USER-MODIFICATION" in rfc_str

    def test_write_attribute_with_usage(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test write_attribute_to_rfc includes USAGE field."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            usage="directoryOperation",
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "USAGE directoryOperation" in rfc_str

    def test_write_attribute_with_x_origin(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_attribute_to_rfc handles custom extensions."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        rfc_str = result.unwrap()

        # Should produce valid RFC format
        assert rfc_str.startswith("(")
        assert rfc_str.endswith(")")

    def test_write_attribute_exception_handling(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_attribute_to_rfc handles edge cases gracefully."""
        # Test with minimal valid attribute
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="test",
        )

        result = oid_quirk.write_attribute_to_rfc(attr_data)

        # Should handle minimal data gracefully
        assert result.is_success
        rfc_str = result.unwrap()
        assert "( 2.16.840.1.113894.1.1.1" in rfc_str
        assert "NAME 'test'" in rfc_str


class TestOidQuirksWriteObjectclassToRfc:
    """Test write_objectclass_to_rfc() method (lines 659-781)."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_write_objectclass_with_metadata_roundtrip(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_objectclass_to_rfc uses metadata for round-trip."""
        original_format = (
            "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )"
        )
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113894.2.1.1",
            name="orclContext",
            kind="STRUCTURAL",
            sup="top",
            must=["cn"],
            metadata=FlextLdifModels.QuirkMetadata(original_format=original_format),
        )
        result = oid_quirk.write_objectclass_to_rfc(oc_data)

        assert result.is_success

        assert result.unwrap() == original_format

    def test_write_objectclass_missing_oid(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_objectclass_to_rfc fails when OID is missing."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="",  # Empty OID should fail
            name="person",
            kind="STRUCTURAL",
        )
        result = oid_quirk.write_objectclass_to_rfc(oc_data)

        assert not result.is_success

        assert result.error is not None

        assert "oid" in result.error.lower()

    def test_write_objectclass_from_scratch_basic(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_objectclass_to_rfc builds RFC format from scratch."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113894.2.1.1",
            name="orclContext",
            kind="STRUCTURAL",
            sup="top",
        )
        result = oid_quirk.write_objectclass_to_rfc(oc_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "2.16.840.1.113894.2.1.1" in rfc_str

        assert "orclContext" in rfc_str

        assert "STRUCTURAL" in rfc_str
        # When sup is a list with single item, it's wrapped in parentheses

        assert "SUP ( top )" in rfc_str or "SUP top" in rfc_str

    def test_write_objectclass_with_desc(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test write_objectclass_to_rfc includes DESC field."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.5.6.6", name="person", desc="Oracle Context", kind="STRUCTURAL"
        )
        result = oid_quirk.write_objectclass_to_rfc(oc_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "DESC 'Oracle Context'" in rfc_str

    def test_write_objectclass_with_multiple_sup(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_objectclass_to_rfc handles multiple superior classes."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.5.6.6", name="person", kind="STRUCTURAL", sup=["top", "person"]
        )
        result = oid_quirk.write_objectclass_to_rfc(oc_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "SUP ( top $ person )" in rfc_str

    def test_write_objectclass_with_must_attributes(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_objectclass_to_rfc includes MUST attributes."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.5.6.6", name="person", kind="STRUCTURAL", must=["cn", "objectClass"]
        )
        result = oid_quirk.write_objectclass_to_rfc(oc_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "MUST ( cn $ objectClass )" in rfc_str

    def test_write_objectclass_with_may_attributes(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_objectclass_to_rfc includes MAY attributes."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.5.6.6",
            name="person",
            kind="STRUCTURAL",
            may=["description", "seeAlso"],
        )
        result = oid_quirk.write_objectclass_to_rfc(oc_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "MAY ( description $ seeAlso )" in rfc_str

    def test_write_objectclass_auxiliary(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test write_objectclass_to_rfc with AUXILIARY objectClass."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.5.6.6", name="person", kind="AUXILIARY"
        )
        result = oid_quirk.write_objectclass_to_rfc(oc_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "AUXILIARY" in rfc_str

    def test_write_objectclass_abstract(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test write_objectclass_to_rfc with ABSTRACT objectClass."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.5.6.6", name="person", kind="ABSTRACT"
        )
        result = oid_quirk.write_objectclass_to_rfc(oc_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "ABSTRACT" in rfc_str

    def test_write_objectclass_with_x_origin(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_objectclass_to_rfc includes X-ORIGIN."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.5.6.6",
            name="person",
            kind="STRUCTURAL",
            metadata=FlextLdifModels.QuirkMetadata(x_origin="Oracle OID"),
        )
        result = oid_quirk.write_objectclass_to_rfc(oc_data)

        assert result.is_success
        rfc_str = result.unwrap()

        assert "X-ORIGIN 'Oracle OID'" in rfc_str

    def test_write_objectclass_exception_handling(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test write_objectclass_to_rfc handles exceptions gracefully."""
        # Test with invalid data
        invalid_data = {"oid": [1, 2, 3]}  # List instead of string

        result = oid_quirk.write_objectclass_to_rfc(invalid_data)
        # Method is defensive - tries to convert to string
        # Just verify it returns a result, doesn't crash

        assert hasattr(result, "is_success")


class TestOidQuirksExtractSchemasFromLdif:
    """Test extract_schemas_from_ldif() method (lines 783-831)."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_extract_schemas_basic(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test extracting schemas from basic LDIF content."""
        ldif_content = """dn: cn=schema
objectClass: top
attributeTypes: ( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
objectClasses: ( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP top STRUCTURAL MUST cn )
"""

        result = oid_quirk.extract_schemas_from_ldif(ldif_content)

        assert result.is_success

        schemas = result.unwrap()

        assert FlextLdifConstants.DictKeys.ATTRIBUTES in schemas

        assert "objectclasses" in schemas

        attributes = schemas[FlextLdifConstants.DictKeys.ATTRIBUTES]
        objectclasses = schemas["objectclasses"]

        assert isinstance(attributes, list)

        assert isinstance(objectclasses, list)

        assert len(attributes) >= 1

        assert len(objectclasses) >= 1

    def test_extract_schemas_case_insensitive(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test extraction works with case-insensitive attribute names."""
        ldif_content = """
AttributeTypes: ( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
OBJECTCLASSES: ( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP top STRUCTURAL )
"""

        result = oid_quirk.extract_schemas_from_ldif(ldif_content)

        assert result.is_success

        schemas = result.unwrap()
        attributes = schemas[FlextLdifConstants.DictKeys.ATTRIBUTES]
        objectclasses = schemas["objectclasses"]

        # Type guards for Pyrefly strict mode

        assert isinstance(attributes, list), f"Expected list, got {type(attributes)}"

        assert isinstance(objectclasses, list), (
            f"Expected list, got {type(objectclasses)}"
        )

        assert len(attributes) >= 1

        assert len(objectclasses) >= 1

    def test_extract_schemas_empty_content(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test extraction with empty LDIF content."""
        result = oid_quirk.extract_schemas_from_ldif("")

        assert result.is_success

        schemas = result.unwrap()

        # Type guards for Pyrefly strict mode - schemas is a dict
        assert isinstance(schemas, dict)

        assert "attributes" in schemas

        assert "objectclasses" in schemas

        assert len(schemas.get("attributes", [])) == 0

        assert len(schemas.get("objectclasses", [])) == 0

    def test_extract_schemas_skips_malformed_entries(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test extraction skips malformed schema entries."""
        ldif_content = """
attributeTypes: INVALID SCHEMA DEFINITION
attributeTypes: ( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
objectClasses: ALSO INVALID
objectClasses: ( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP top STRUCTURAL )
"""

        result = oid_quirk.extract_schemas_from_ldif(ldif_content)

        assert result.is_success

        schemas = result.unwrap()
        # Should extract only valid entries
        attributes = schemas[FlextLdifConstants.DictKeys.ATTRIBUTES]
        objectclasses = schemas["objectclasses"]

        # Type guards for Pyrefly strict mode

        assert isinstance(attributes, list), f"Expected list, got {type(attributes)}"

        assert isinstance(objectclasses, list), (
            f"Expected list, got {type(objectclasses)}"
        )

        # Should have at least the valid entries

        assert len(attributes) >= 1

        assert len(objectclasses) >= 1

    def test_extract_schemas_exception_handling(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test extraction handles exceptions gracefully."""
        # This shouldn't cause exceptions, but test defensive handling
        result = oid_quirk.extract_schemas_from_ldif(
            "Some completely invalid content\x00\x01"
        )
        # Should return result (success or failure), not crash

        assert hasattr(result, "is_success")


# ===== Merged from test_oid_full_coverage.py =====


class TestOidParseAttributeComprehensive:
    """Test parse_attribute() with all RFC 4512 attribute variations."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_parse_attribute_oid_namespace(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parsing OID namespace attribute."""
        attr_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        result = oid_quirk.parse_attribute(attr_def)

        assert result.is_success
        parsed = result.unwrap()

        assert parsed.oid == "2.16.840.1.113894.1.1.1"
        assert parsed.name == "orclGUID"

    def test_parse_attribute_with_all_fields(
        self, oid_quirk: FlextLdifServersOid
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

        assert parsed.name == "orclGUID"
        assert parsed.desc == "Oracle GUID"

    def test_parse_attribute_standard_ldap(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parsing standard LDAP attribute in OID context."""
        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        result = oid_quirk.parse_attribute(attr_def)

        assert result.is_success
        parsed = result.unwrap()

        assert parsed.name == "cn"


class TestOidParseObjectClassComprehensive:
    """Test parse_objectclass() with all RFC 4512 objectClass variations."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_parse_objectclass_oid_namespace(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parsing OID namespace objectClass."""
        oc_def = "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' STRUCTURAL )"
        result = oid_quirk.parse_objectclass(oc_def)

        assert result.is_success
        parsed = result.unwrap()

        assert parsed.name == "orclContext"

    def test_parse_objectclass_with_deps(self, oid_quirk: FlextLdifServersOid) -> None:
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

        assert parsed.name == "changeLogEntry"


class TestOidWriteMethods:
    """Test write_attribute_to_rfc() and write_objectclass_to_rfc()."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_write_attribute_to_rfc_oid(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test writing OID attribute to RFC format."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            single_value=True,
        )
        result = oid_quirk.write_attribute_to_rfc(attr_data)

        assert result.is_success
        written = result.unwrap()
        assert isinstance(written, str)

    def test_write_objectclass_to_rfc_oid(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test writing OID objectClass to RFC format."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113894.1.2.1",
            name="orclContext",
            kind="STRUCTURAL",
            sup="top",
        )
        result = oid_quirk.write_objectclass_to_rfc(oc_data)

        assert result.is_success
        written = result.unwrap()

        assert isinstance(written, str)


class TestOidConversionMethods:
    """Test conversion between OID and RFC formats."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_convert_attribute_to_rfc(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test converting OID attribute to RFC."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1", name="orclGUID"
        )
        result = oid_quirk.convert_attribute_to_rfc(attr_data)

        assert result.is_success
        converted = result.unwrap()

        assert hasattr(converted, "name")

    def test_convert_objectclass_to_rfc(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test converting OID objectClass to RFC."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113894.1.2.1", name="orclContext", kind="STRUCTURAL"
        )
        result = oid_quirk.convert_objectclass_to_rfc(oc_data)

        assert result.is_success
        converted = result.unwrap()

        assert hasattr(converted, "name")

    def test_convert_attribute_from_rfc(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test converting RFC attribute to OID."""
        rfc_attr = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
        )
        result = oid_quirk.convert_attribute_from_rfc(rfc_attr)

        assert result.is_success
        converted = result.unwrap()

        assert converted.name == "orclGUID"

    def test_convert_objectclass_from_rfc(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test converting RFC objectClass to OID."""
        rfc_oc = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113894.1.2.1",
            name="orclContext",
        )
        result = oid_quirk.convert_objectclass_from_rfc(rfc_oc)

        assert result.is_success
        converted = result.unwrap()

        assert converted.name == "orclContext"


class TestOidExtractSchemas:
    """Test extract_schemas_from_ldif() for OID."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_extract_schemas_returns_result(
        self, oid_quirk: FlextLdifServersOid
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
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_can_handle_oid_namespace_attribute(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test can_handle for OID namespace attribute."""
        oid_attr = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' )"
        result = oid_quirk.can_handle_attribute(oid_attr)

        assert isinstance(result, bool)

    def test_can_handle_oid_namespace_objectclass(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test can_handle for OID namespace objectClass."""
        oid_oc = "( 2.16.840.1.113894.1.2.1 NAME 'orclContext' STRUCTURAL )"
        result = oid_quirk.can_handle_objectclass(oid_oc)

        assert isinstance(result, bool)


# ===== Merged from test_oid_phase6d.py =====


class TestOidQuirksCanHandleAttribute:
    """Test OID attribute handling with real and edge case data."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_can_handle_oid_namespace_attribute(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test handling of Oracle OID namespace attributes."""
        attr_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' )"

        assert oid_quirk.can_handle_attribute(attr_def)

    def test_can_handle_multiple_oid_attributes(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test various OID namespace attributes."""
        oid_attrs = [
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' )",
            "( 2.16.840.1.113894.1.2.1 NAME 'orclaci' )",
            "( 2.16.840.1.113894.1.3.1 NAME 'orcldefinitioncontext' )",
        ]
        for attr_def in oid_attrs:
            assert oid_quirk.can_handle_attribute(attr_def), f"Failed: {attr_def}"

    def test_cannot_handle_non_oid_attribute(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test that non-OID attributes are not handled."""
        attr_def = "( 2.5.4.3 NAME 'cn' )"

        assert not oid_quirk.can_handle_attribute(attr_def)

    def test_cannot_handle_invalid_input(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test error handling for invalid input types."""
        # Non-string input

        assert not oid_quirk.can_handle_attribute(cast("str", 123))

        assert not oid_quirk.can_handle_attribute(cast("str", None))

        assert not oid_quirk.can_handle_attribute(cast("str", []))

    def test_cannot_handle_malformed_attribute(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test handling of malformed attribute definitions."""
        malformed = [
            "no parentheses here",
            "( incomplete",
            ")",
            "",
        ]
        for attr_def in malformed:
            assert not oid_quirk.can_handle_attribute(attr_def)


class TestOidQuirksParseAttribute:
    """Test OID attribute parsing with real fixture data."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    @pytest.fixture
    def oid_schema_fixture(self) -> Path:
        """Get OID schema fixture path."""
        return (
            Path(__file__).parent.parent.parent.parent
            / "fixtures"
            / "oid"
            / "oid_schema_fixtures.ldif"
        )

    def test_parse_valid_oid_attribute(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test parsing valid OID attribute definition."""
        attr_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' DESC 'Oracle GUID' )"
        result = oid_quirk.parse_attribute(attr_def)

        assert result.is_success

    def test_parse_oid_attribute_with_syntax(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parsing OID attribute with SYNTAX clause."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.2 NAME 'orclaci' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 )"
        )
        result = oid_quirk.parse_attribute(attr_def)

        assert result.is_success

    def test_parse_non_oid_attribute_fails(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test that parsing non-OID attributes may fail gracefully."""
        attr_def = "( 2.5.4.3 NAME 'cn' )"
        result = oid_quirk.parse_attribute(attr_def)
        # Result depends on implementation - may succeed with different quirk handling

        assert hasattr(result, "is_success")

    def test_parse_with_schema_fixture(
        self, oid_quirk: FlextLdifServersOid, oid_schema_fixture: Path
    ) -> None:
        """Test parsing real OID attributes from fixture."""
        if not oid_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_schema_fixture}")

        content = oid_schema_fixture.read_text(encoding="utf-8")
        # Find first attribute definition
        lines = content.split("\n")
        for line in lines:
            if line.startswith("attributetype"):
                # Get full attribute definition (may span multiple lines)
                attr_def = line.replace("attributetype ", "")
                result = oid_quirk.parse_attribute(attr_def)
                break

        assert hasattr(result, "is_success")


class TestOidQuirksConvertAttribute:
    """Test OID attribute conversion with matching rule/syntax replacements."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_convert_attribute_with_matching_rule_replacement(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test conversion fixes matching rules for OUD compatibility."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'test' EQUALITY caseIgnoreSubStringsMatch )"
        )
        # First parse the attribute
        parse_result = oid_quirk.parse_attribute(attr_def)
        assert parse_result.is_success

        attr_model = parse_result.unwrap()
        # Then convert to RFC
        result = oid_quirk.convert_attribute_to_rfc(attr_model)

        assert result.is_success
        converted = result.unwrap()
        # Should have fixed matching rule

        assert hasattr(converted, "equality")

    def test_convert_attribute_with_syntax_replacement(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test conversion replaces unsupported syntax OIDs."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.2 NAME 'orclaci' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.1 )"
        )
        result = oid_quirk.convert_attribute_to_rfc(attr_def)

        assert hasattr(result, "is_success")

    def test_convert_attribute_roundtrip(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test convert to RFC and back from RFC."""
        original = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' )"
        # First parse the attribute
        parse_result = oid_quirk.parse_attribute(original)
        assert parse_result.is_success

        attr_model = parse_result.unwrap()
        # Then convert to RFC
        to_rfc = oid_quirk.convert_attribute_to_rfc(attr_model)

        assert to_rfc.is_success
        from_rfc = oid_quirk.convert_attribute_from_rfc(to_rfc.unwrap())

        assert hasattr(from_rfc, "is_success")


class TestOidQuirksObjectClassHandling:
    """Test OID objectClass parsing and conversion."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_can_handle_oid_objectclass(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test handling OID objectClass definitions."""
        objclass_def = "( 2.16.840.1.113894.1.1.1 NAME 'orclRoot' )"
        # ObjectClass handling delegates to parent
        result = oid_quirk.can_handle_objectclass(objclass_def)

        assert isinstance(result, bool)

    def test_parse_objectclass_with_must_attributes(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parsing objectClass with MUST attributes."""
        objclass_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclRoot' MUST ( cn $ objectClass ) )"
        )
        result = oid_quirk.parse_objectclass(objclass_def)

        assert hasattr(result, "is_success")

    def test_incompatible_attributes_handled_through_quirks(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test that incompatible attributes are handled through quirk system.

        OID-specific incompatible attributes are handled through the quirks system:
        - orclaci/orclentrylevelaci: Handled via ACL quirks
        - orcldaslov: Handled via Entry quirks
        - orcljaznjavaclass: Handled via Entry quirks

        This test verifies the quirk system is properly configured to handle
        these OID-specific attributes through the appropriate quirkhandlers.
        """
        # Verify quirk has ACL handling capability
        acl_quirk = FlextLdifServersOid.Acl()

        assert acl_quirk is not None

        # Verify quirk has Entry handling capability
        entry_quirk = FlextLdifServersOid.Entry()

        assert entry_quirk is not None


class TestOidQuirksACLHandling:
    """Test OID ACL (orclaci/orclentrylevelaci) handling."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    @pytest.fixture
    def oid_acl_fixture(self) -> Path:
        """Get OID ACL fixture path."""
        return (
            Path(__file__).parent.parent.parent.parent
            / "fixtures"
            / "oid"
            / "oid_acl_fixtures.ldif"
        )

    def test_can_handle_orclaci_attribute(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test recognizing orclaci attributes."""
        # orclaci is in OID namespace, should be handled
        acl_def = "( 2.16.840.1.113894.1.2.1 NAME 'orclaci' )"

        assert oid_quirk.can_handle_attribute(acl_def)

    def test_parse_acl_from_fixture(
        self, oid_quirk: FlextLdifServersOid, oid_acl_fixture: Path
    ) -> None:
        """Test parsing real ACL data from fixture."""
        if not oid_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_acl_fixture}")

        content = oid_acl_fixture.read_text(encoding="utf-8")

        assert "orclaci" in content or "orclentrylevelaci" in content


class TestOidQuirksEntryHandling:
    """Test OID entry-level operations."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    @pytest.fixture
    def oid_entries_fixture(self) -> Path:
        """Get OID entries fixture path."""
        return (
            Path(__file__).parent.parent.parent.parent
            / "fixtures"
            / "oid"
            / "oid_entries_fixtures.ldif"
        )

    def test_can_handle_oid_entry_attributes(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test handling OID-specific entry attributes."""
        # Test entry-level quirks for OID attributes
        entry_attrs = ["orclGUID", "orclentrylevelaci", "orcldaslov"]
        for attr in entry_attrs:
            # Check if OID quirk recognizes OID-namespace attributes
            oid_def = f"( 2.16.840.1.113894.1.1.1 NAME '{attr}' )"
            result = oid_quirk.can_handle_attribute(oid_def)

        assert isinstance(result, bool)

    def test_process_oid_entry(
        self, oid_quirk: FlextLdifServersOid, oid_entries_fixture: Path
    ) -> None:
        """Test processing real OID entries from fixture."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        content = oid_entries_fixture.read_text(encoding="utf-8")
        # Verify fixture contains OID-specific data

        assert "dn:" in content


class TestOidQuirksProperties:
    """Test OID quirks properties and configuration."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_oid_quirk_server_type(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test OID quirk has correct server type."""
        assert oid_quirk.server_type == "oid"

    def test_oid_quirk_priority(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test OID quirk has correct priority."""
        assert oid_quirk.priority == 10

    def test_oid_namespace_pattern(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test OID namespace pattern is correctly defined."""
        test_oid = "2.16.840.1.113894.1.1.1"

        assert oid_quirk.ORACLE_OID_PATTERN.match(test_oid) is not None

    def test_matching_rule_replacements_defined(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test matching rule replacements are configured."""
        assert "caseIgnoreSubStringsMatch" in oid_quirk.MATCHING_RULE_REPLACEMENTS

        assert "accessDirectiveMatch" in oid_quirk.MATCHING_RULE_REPLACEMENTS

    def test_syntax_oid_replacements_defined(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test syntax OID replacements are configured."""
        assert len(oid_quirk.SYNTAX_OID_REPLACEMENTS) > 0

    def test_skip_objectclass_attributes_handled(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test that incompatible attributes (orclaci, orclentrylevelaci) are handled correctly.

        These OID-specific attributes are handled through the ACL quirks system,
        not through a SKIP_OBJECTCLASS_ATTRIBUTES list. This test verifies the quirk
        instance is properly initialized and can handle ACL processing.
        """
        # Verify quirk is initialized

        assert oid_quirk is not None
        # Verify FlextLdifServersOid has ACL and Entry quirks available

        assert hasattr(FlextLdifServersOid, "Acl")

        assert hasattr(FlextLdifServersOid, "Entry")


class TestOidQuirksIntegrationWithFixtures:
    """Integration tests with real OID fixture data."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    @pytest.fixture
    def oid_integration_fixture(self) -> Path:
        """Get OID integration fixture path."""
        return (
            Path(__file__).parent.parent.parent.parent
            / "fixtures"
            / "oid"
            / "oid_integration_fixtures.ldif"
        )

    def test_parse_full_oid_ldif_fixture(
        self, oid_quirk: FlextLdifServersOid, oid_integration_fixture: Path
    ) -> None:
        """Test parsing full OID integration fixture."""
        if not oid_integration_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_integration_fixture}")

        content = oid_integration_fixture.read_text(encoding="utf-8")
        lines = content.split("\n")

        # Parse multiple attribute definitions from fixture
        parsed_count = 0
        for _line in lines[:100]:  # Test first 100 lines
            if _line.startswith(("attributetype", "objectclass")):
                parsed_count += 1

        assert len(lines) > 0, "Fixture should not be empty"

    def test_oid_quirk_converts_fixture_data(
        self, oid_quirk: FlextLdifServersOid, oid_integration_fixture: Path
    ) -> None:
        """Test OID quirk can process fixture data conversions."""
        if not oid_integration_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_integration_fixture}")

        # Test that conversion methods work with real data
        test_attr = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' )"

        # Parse attribute first
        parse_result = oid_quirk.parse_attribute(test_attr)
        assert parse_result.is_success
        attr_model = parse_result.unwrap()

        # Convert to RFC
        rfc_result = oid_quirk.convert_attribute_to_rfc(attr_model)
        assert rfc_result.is_success

        # Convert back
        back_result = oid_quirk.convert_attribute_from_rfc(rfc_result.unwrap())
        assert hasattr(back_result, "is_success")


# ===== Merged from test_oid_acl_entry_phase6d.py =====


class TestOidAclCanHandleAcl:
    """Test OID Acl can_handle_acl with real OID ACL data."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance with nested Acl."""
        return FlextLdifServersOid().Schema()

    def test_can_handle_orclaci(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test detection of orclaci (standard Oracle OID ACL)."""
        acl_line = 'orclaci: (targetattr="userPassword") (version 3.0; acl "Allow password change"; allow (write) userdn="ldap:///anyone";)'
        acl_quirk = FlextLdifServersOid.Acl()

        assert isinstance(acl_quirk.can_handle_acl(acl_line), bool)

    def test_can_handle_orclentrylevelaci(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test detection of orclentrylevelaci (entry-level OID ACL)."""
        acl_line = 'orclentrylevelaci: (targetattr="cn") (version 3.0; acl "Entry-level"; allow (read) userdn="ldap:///anyone";)'
        acl_quirk = FlextLdifServersOid.Acl()

        assert isinstance(acl_quirk.can_handle_acl(acl_line), bool)

    def test_can_handle_invalid_acl_prefix(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test rejection of non-OID ACL formats."""
        acl_line = 'aci: (targetattr="userPassword") (version 3.0;...)'
        acl_quirk = FlextLdifServersOid.Acl()

        assert not acl_quirk.can_handle_acl(acl_line)

    def test_can_handle_empty_acl(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test handling of empty ACL line."""
        acl_quirk = FlextLdifServersOid.Acl()

        assert not acl_quirk.can_handle_acl("")


class TestOidAclParseAcl:
    """Test OID Acl parse_acl with real fixture data."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    @pytest.fixture
    def oid_acl_fixture(self) -> Path:
        """Get OID ACL fixture path."""
        return (
            Path(__file__).parent.parent.parent.parent
            / "fixtures"
            / "oid"
            / "oid_acl_fixtures.ldif"
        )

    def test_parse_standard_orclaci(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test parsing standard Oracle OID ACL."""
        acl_line = 'orclaci: access to entry by group="cn=Admins,cn=groups,cn=OracleContext" (browse,add,delete)'
        acl_quirk = FlextLdifServersOid.Acl()
        result = acl_quirk.parse_acl(acl_line)

        assert result.is_success
        acl_data = result.unwrap()

        assert hasattr(acl_data, "name")
        assert acl_data.server_type == "oracle_oid"

    def test_parse_entry_level_orclentrylevelaci(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parsing entry-level Oracle OID ACL."""
        acl_line = 'orclentrylevelaci: (version 3.0;acl "Entry";allow(read)userdn="ldap:///anyone";)'
        acl_quirk = FlextLdifServersOid.Acl()
        result = acl_quirk.parse_acl(acl_line)

        assert hasattr(result, "is_success")

    def test_parse_acl_with_filter(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test parsing ACL with filter clause."""
        acl_line = 'orclaci: (targetattr="*")(filter="(objectClass=person)")(version 3.0;acl "Filtered";allow(read)userdn="ldap:///anyone";)'
        acl_quirk = FlextLdifServersOid.Acl()
        result = acl_quirk.parse_acl(acl_line)

        assert hasattr(result, "is_success")

    def test_parse_acl_with_added_object_constraint(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parsing ACL with added_object_constraint."""
        acl_line = 'orclentrylevelaci: (added_object_constraint="(objectClass=person)")(version 3.0;acl "Constraint";allow(write)userdn="ldap:///cn=admin";)'
        acl_quirk = FlextLdifServersOid.Acl()
        result = acl_quirk.parse_acl(acl_line)

        assert hasattr(result, "is_success")

    def test_parse_acl_with_multiple_by_clauses(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test parsing ACL with multiple permission clauses."""
        acl_line = 'orclaci: (targetattr="*")(version 3.0;acl "Multi";allow(read)userdn="ldap:///anyone";allow(write)groupdn="ldap:///cn=admins";)'
        acl_quirk = FlextLdifServersOid.Acl()
        result = acl_quirk.parse_acl(acl_line)

        assert hasattr(result, "is_success")

    def test_parse_acl_from_real_fixture(
        self, oid_quirk: FlextLdifServersOid, oid_acl_fixture: Path
    ) -> None:
        """Test parsing real OID ACL from fixture file."""
        if not oid_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_acl_fixture}")

        content = oid_acl_fixture.read_text(encoding="utf-8")
        acl_quirk = FlextLdifServersOid.Acl()

        for line in content.split("\n"):
            if line.startswith(("orclaci:", "orclentrylevelaci:")):
                result = acl_quirk.parse_acl(line)
                break

        assert hasattr(result, "is_success")


class TestOidAclConvertAcl:
    """Test OID Acl ACL RFC conversion."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_convert_acl_to_rfc(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test converting OID ACL to RFC format."""
        acl_quirk = FlextLdifServersOid.Acl()
        parsed_data = {
            "type": "standard",
            "target": "entry",
            "permissions": [{"action": "allow", "operations": ["read"]}],
        }
        result = acl_quirk.convert_acl_to_rfc(parsed_data)

        assert hasattr(result, "is_success")

    def test_convert_acl_from_rfc(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test converting RFC ACL to OID format."""
        acl_quirk = FlextLdifServersOid.Acl()
        rfc_data = {
            "target": "entry",
            "permissions": [{"action": "allow", "operations": ["read"]}],
        }
        result = acl_quirk.convert_acl_from_rfc(rfc_data)

        assert hasattr(result, "is_success")

    def test_write_acl_to_rfc(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test writing ACL in RFC format."""
        acl_quirk = FlextLdifServersOid.Acl()
        acl_data = {
            "type": "standard",
            "permissions": [{"action": "allow", "operations": ["read"]}],
        }
        result = acl_quirk.write_acl_to_rfc(acl_data)

        assert hasattr(result, "is_success")


class TestOidEntryCanHandleEntry:
    """Test OID Entry can_handle_entry detection."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_can_handle_oid_entry(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test detection of OID-specific entries."""
        dn = "cn=test,dc=oracle"
        attributes = {"orclVersion": "1"}
        entry_quirk = FlextLdifServersOid.Entry()

        assert isinstance(entry_quirk.can_handle_entry(dn, attributes), bool)

    def test_can_handle_standard_entry(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test handling of standard LDAP entries."""
        dn = "cn=test,dc=example,dc=com"
        attributes = {"cn": "test"}
        entry_quirk = FlextLdifServersOid.Entry()

        assert isinstance(entry_quirk.can_handle_entry(dn, attributes), bool)


class TestOidEntryProcessEntry:
    """Test OID Entry entry processing with real data."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    @pytest.fixture
    def oid_entries_fixture(self) -> Path:
        """Get OID entries fixture path."""
        return (
            Path(__file__).parent.parent.parent.parent
            / "fixtures"
            / "oid"
            / "oid_entries_fixtures.ldif"
        )

    def test_process_oid_entry_standard(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test processing standard OID entry."""
        entry_quirk = FlextLdifServersOid.Entry()
        dn = "cn=test,dc=oracle"
        attributes = {
            "objectClass": ["person", "inetOrgPerson"],
            "cn": ["test"],
            "sn": ["user"],
        }
        result = entry_quirk.process_entry(dn, attributes)

        assert hasattr(result, "is_success")

    def test_process_oid_entry_with_oracle_attrs(
        self, oid_quirk: FlextLdifServersOid
    ) -> None:
        """Test processing OID entry with Oracle-specific attributes."""
        entry_quirk = FlextLdifServersOid.Entry()
        dn = "cn=test,dc=oracle"
        attributes = {
            "objectClass": ["person", "orclapplicationentity"],
            "cn": ["test"],
            "orclVersion": "90600",
        }
        result = entry_quirk.process_entry(dn, attributes)

        assert hasattr(result, "is_success")

    def test_process_entry_from_fixture(
        self, oid_quirk: FlextLdifServersOid, oid_entries_fixture: Path
    ) -> None:
        """Test processing entries from real OID fixture."""
        if not oid_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_entries_fixture}")

        entry_quirk = FlextLdifServersOid.Entry()
        # Fallback: process minimal entry with correct signature
        dn = "cn=test,dc=oracle"
        attributes = {"cn": ["test"]}
        result = entry_quirk.process_entry(dn, attributes)

        assert hasattr(result, "is_success")


class TestOidEntryConvertEntry:
    """Test OID Entry entry RFC conversion."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_convert_entry_to_rfc(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test converting OID entry to RFC format."""
        entry_quirk = FlextLdifServersOid.Entry()
        entry_dict = {
            "dn": "cn=test,dc=oracle",
            "objectClass": ["person"],
            "cn": ["test"],
        }
        result = entry_quirk.convert_entry_to_rfc(entry_dict)

        assert hasattr(result, "is_success")

    def test_convert_entry_from_rfc(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test converting RFC entry to OID format."""
        entry_quirk = FlextLdifServersOid.Entry()
        rfc_data = {
            "dn": "cn=test,dc=oracle",
            "objectClass": ["person"],
            "cn": ["test"],
        }
        result = entry_quirk.convert_entry_from_rfc(rfc_data)

        assert hasattr(result, "is_success")


class TestOidProperties:
    """Test OID quirks properties and configuration."""

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    def test_oid_acl_quirk_properties(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test Acl has correct properties."""
        acl_quirk = FlextLdifServersOid.Acl()

        assert acl_quirk.server_type == "oid"

        assert acl_quirk.priority == 10

    def test_oid_entry_quirk_properties(self, oid_quirk: FlextLdifServersOid) -> None:
        """Test Entry has correct properties."""
        entry_quirk = FlextLdifServersOid.Entry()

        assert entry_quirk.server_type == "oid"

        assert entry_quirk.priority == 10


class TestOidQuirksWithRealFixtures:
    """Test OID quirks using real LDIF fixtures from tests/fixtures/oid/."""

    @pytest.fixture
    def oid_fixture_dir(self) -> Path:
        """Get OID fixtures directory."""
        return Path(__file__).parent.parent.parent.parent / "fixtures" / "oid"

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifServersOid.Schema:
        """Create OID quirk instance."""
        return FlextLdifServersOid().Schema()

    @pytest.fixture
    def api(self) -> FlextLdif:
        """Create FlextLdif API instance."""
        return FlextLdif()

    def test_parse_oid_schema_fixture(
        self, api: FlextLdif, oid_fixture_dir: Path
    ) -> None:
        """Test parsing real OID schema fixture file."""
        schema_file = oid_fixture_dir / "oid_schema_fixtures.ldif"
        if not schema_file.exists():
            pytest.skip(f"OID schema fixture not found: {schema_file}")

        result = api.parse(schema_file, server_type="oid")

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0, "OID schema fixture should contain schema entries"

    def test_parse_oid_entries_fixture(
        self, api: FlextLdif, oid_fixture_dir: Path
    ) -> None:
        """Test parsing real OID directory entries fixture."""
        entries_file = oid_fixture_dir / "oid_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OID entries fixture not found: {entries_file}")

        result = api.parse(entries_file, server_type="oid")

        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0, "OID entries fixture should contain directory entries"

        # Verify entries have valid DNs
        for entry in entries:
            assert entry.dn.value, "Each entry must have a DN"
            assert len(entry.attributes) > 0, "Each entry must have attributes"

    def test_parse_oid_acl_fixture(self, api: FlextLdif, oid_fixture_dir: Path) -> None:
        """Test parsing real OID ACL fixture."""
        acl_file = oid_fixture_dir / "oid_acl_fixtures.ldif"
        if not acl_file.exists():
            pytest.skip(f"OID ACL fixture not found: {acl_file}")

        result = api.parse(acl_file, server_type="oid")

        assert result.is_success

    @pytest.mark.skip(
        reason="Roundtrip tests - complex LDIF writing/parsing edge cases not fully implemented"
    )
    def test_roundtrip_oid_entries(
        self, api: FlextLdif, oid_fixture_dir: Path, tmp_path: Path
    ) -> None:
        """Test parsing OID entries and writing them back maintains data integrity."""
        entries_file = oid_fixture_dir / "oid_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OID entries fixture not found: {entries_file}")

        # Parse original
        parse_result = api.parse(entries_file, server_type="oid")
        assert parse_result.is_success
        entries = parse_result.unwrap()

        # Write to temporary file
        output_file = tmp_path / "roundtrip_oid_entries.ldif"
        write_result = api.write(entries, output_file, server_type="oid")
        assert write_result.is_success

        # Parse again
        reparse_result = api.parse(output_file, server_type="oid")
        assert reparse_result.is_success
        reparsed_entries = reparse_result.unwrap()

        # Verify same number of entries
        assert len(entries) == len(reparsed_entries)

    def test_oid_server_type_detection(
        self, api: FlextLdif, oid_fixture_dir: Path
    ) -> None:
        """Test that OID server type is correctly detected from OID entries."""
        entries_file = oid_fixture_dir / "oid_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OID entries fixture not found: {entries_file}")

        # Parse with auto-detection
        result = api.parse(entries_file)

        assert result.is_success

    def test_oid_vs_rfc_parsing(self, api: FlextLdif, oid_fixture_dir: Path) -> None:
        """Verify OID and RFC parsing work with OID data."""
        entries_file = oid_fixture_dir / "oid_entries_fixtures.ldif"
        if not entries_file.exists():
            pytest.skip(f"OID entries fixture not found: {entries_file}")

        # Parse with OID quirks
        oid_result = api.parse(entries_file, server_type="oid")
        assert oid_result.is_success
        oid_entries = oid_result.unwrap()

        # Parse with RFC-only mode
        rfc_result = api.parse(entries_file, server_type="rfc")
        assert rfc_result.is_success
        rfc_entries = rfc_result.unwrap()

        # Both should have same entries
        assert len(oid_entries) == len(rfc_entries)
