"""Test suite for Oracle Unified Directory (OUD) quirks.

Comprehensive testing for OUD-specific schema, ACL, and entry quirks
using real OUD fixtures from tests/fixtures/oud/.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextCore
from tests.fixtures.loader import FlextLdifFixtures

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud
from flext_ldif.typings import FlextLdifTypes


class TestOudSchemaQuirks:
    """Test suite for OUD schema quirk functionality."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD schema quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oud_fixtures(self) -> FlextLdifFixtures.OUD:
        """Create OUD fixture loader."""
        return FlextLdifFixtures.OUD()

    def test_initialization(self, oud_quirk: FlextLdifQuirksServersOud) -> None:
        """Test OUD schema quirk initialization."""
        assert oud_quirk.server_type == FlextLdifConstants.ServerTypes.OUD
        assert oud_quirk.priority == 10

    def test_can_handle_oracle_attribute(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test detection of Oracle OUD attributes by OID namespace."""
        # Oracle namespace: 2.16.840.1.113894.*
        oracle_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclVersion' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        assert oud_quirk.can_handle_attribute(oracle_attr)

        # Non-Oracle attribute (RFC 4519)
        rfc_attr = (
            "( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        assert not oud_quirk.can_handle_attribute(rfc_attr)

    def test_parse_oracle_attribute_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing basic Oracle attribute definition."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclVersion' "
            "DESC 'Oracle version number' "
            "EQUALITY integerMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
            "SINGLE-VALUE )"
        )

        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success, f"Failed to parse attribute: {result.error}"

        parsed = result.unwrap()
        assert parsed[FlextLdifConstants.DictKeys.SERVER_TYPE] == "oud"
        assert "oid" in parsed
        assert "name" in parsed

    def test_parse_oracle_attribute_from_fixtures(
        self, oud_quirk: FlextLdifQuirksServersOud, oud_fixtures: FlextLdifFixtures.OUD
    ) -> None:
        """Test parsing Oracle attributes from real OUD schema fixtures."""
        schema_content = oud_fixtures.schema()

        # Extract an Oracle attribute line from schema
        # Looking for orclVersion or similar Oracle attributes
        oracle_attrs = [
            line
            for line in schema_content.splitlines()
            if "2.16.840.1.113894" in line
            and line.strip().startswith("attributeTypes:")
        ]

        assert len(oracle_attrs) > 0, "No Oracle attributes found in schema fixtures"

        # Parse first Oracle attribute
        first_attr = oracle_attrs[0]
        # Extract just the definition part after "attributeTypes: "
        attr_def = first_attr.split("attributeTypes:", 1)[1].strip()

        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success, f"Failed to parse fixture attribute: {result.error}"

        parsed = result.unwrap()
        assert parsed[FlextLdifConstants.DictKeys.SERVER_TYPE] == "oud"

    def test_can_handle_oracle_objectclass(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test detection of Oracle OUD objectClasses."""
        # Oracle objectClass
        oracle_oc = "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP top STRUCTURAL )"
        assert oud_quirk.can_handle_objectclass(oracle_oc)

        # Non-Oracle objectClass
        rfc_oc = "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL )"
        assert not oud_quirk.can_handle_objectclass(rfc_oc)

    def test_parse_oracle_objectclass_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing basic Oracle objectClass definition."""
        oc_def = (
            "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' "
            "DESC 'Oracle Context' "
            "SUP top STRUCTURAL "
            "MUST cn "
            "MAY ( orclVersion ) )"
        )

        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success, f"Failed to parse objectClass: {result.error}"

        parsed = result.unwrap()
        assert parsed[FlextLdifConstants.DictKeys.SERVER_TYPE] == "oud"
        assert "oid" in parsed
        assert "name" in parsed

    def test_parse_oracle_objectclass_from_fixtures(
        self, oud_quirk: FlextLdifQuirksServersOud, oud_fixtures: FlextLdifFixtures.OUD
    ) -> None:
        """Test parsing Oracle objectClasses from real OUD schema fixtures."""
        schema_content = oud_fixtures.schema()

        # Extract Oracle objectClass lines
        oracle_ocs = [
            line
            for line in schema_content.splitlines()
            if "2.16.840.1.113894" in line and line.strip().startswith("objectClasses:")
        ]

        assert len(oracle_ocs) > 0, "No Oracle objectClasses found in schema fixtures"

        # Parse first Oracle objectClass
        first_oc = oracle_ocs[0]
        oc_def = first_oc.split("objectClasses:", 1)[1].strip()

        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success, f"Failed to parse fixture objectClass: {result.error}"

        parsed = result.unwrap()
        assert parsed[FlextLdifConstants.DictKeys.SERVER_TYPE] == "oud"

    def test_convert_attribute_to_rfc(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting OUD attribute to RFC-compliant format."""
        oud_attr_data: FlextLdifTypes.Dict = {
            "oid": "2.16.840.1.113894.1.1.1",
            "name": "orclVersion",
            "desc": "Oracle version",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.27",
            "equality": "integerMatch",
        }

        result = oud_quirk.convert_attribute_to_rfc(oud_attr_data)
        assert result.is_success

        rfc_data = result.unwrap()
        assert rfc_data[FlextLdifConstants.DictKeys.OID] == "2.16.840.1.113894.1.1.1"
        assert rfc_data[FlextLdifConstants.DictKeys.NAME] == "orclVersion"

    def test_convert_objectclass_to_rfc(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting OUD objectClass to RFC-compliant format."""
        oud_oc_data: FlextLdifTypes.Dict = {
            "oid": "2.16.840.1.113894.2.1.1",
            "name": "orclContext",
            "desc": "Oracle Context",
            "sup": "top",
            "kind": "STRUCTURAL",
            "must": ["cn"],
            "may": ["orclVersion"],
        }

        result = oud_quirk.convert_objectclass_to_rfc(oud_oc_data)
        assert result.is_success

        rfc_data = result.unwrap()
        assert rfc_data[FlextLdifConstants.DictKeys.OID] == "2.16.840.1.113894.2.1.1"
        assert rfc_data[FlextLdifConstants.DictKeys.NAME] == "orclContext"

    def test_schema_roundtrip(self, oud_quirk: FlextLdifQuirksServersOud) -> None:
        """Test schema attribute roundtrip: parse → convert to RFC → back."""
        original_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclVersion' "
            "DESC 'Oracle version' "
            "EQUALITY integerMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
            "SINGLE-VALUE )"
        )

        # Parse
        parse_result = oud_quirk.parse_attribute(original_attr)
        assert parse_result.is_success
        parsed = parse_result.unwrap()

        # Convert to RFC
        rfc_result = oud_quirk.convert_attribute_to_rfc(parsed)
        assert rfc_result.is_success
        rfc_data = rfc_result.unwrap()

        # Validate essential fields preserved
        assert rfc_data[FlextLdifConstants.DictKeys.OID] == "2.16.840.1.113894.1.1.1"
        assert rfc_data[FlextLdifConstants.DictKeys.NAME] == "orclVersion"


class TestOudAclQuirks:
    """Test suite for OUD ACL quirk functionality."""

    @pytest.fixture
    def acl_quirk(self) -> FlextLdifQuirksServersOud.AclQuirk:
        """Create OUD ACL quirk instance."""
        return FlextLdifQuirksServersOud.AclQuirk(
            server_type=FlextLdifConstants.ServerTypes.OUD
        )

    @pytest.fixture
    def oud_fixtures(self) -> FlextLdifFixtures.OUD:
        """Create OUD fixture loader."""
        return FlextLdifFixtures.OUD()

    def test_acl_quirk_initialization(
        self, acl_quirk: FlextLdifQuirksServersOud.AclQuirk
    ) -> None:
        """Test OUD ACL quirk initialization."""
        assert acl_quirk.server_type == FlextLdifConstants.ServerTypes.OUD
        assert acl_quirk.priority == 10

    def test_can_handle_ds_cfg_acl(
        self, acl_quirk: FlextLdifQuirksServersOud.AclQuirk
    ) -> None:
        """Test detection of ds-cfg- ACL format."""
        ds_cfg_acl = "ds-cfg-access-control-handler: cn=Access Control Handler"
        assert acl_quirk.can_handle_acl(ds_cfg_acl)

        aci_acl = 'aci: (targetattr="*")(version 3.0; acl "test"; allow (read) userdn="ldap:///anyone";)'
        assert acl_quirk.can_handle_acl(aci_acl)

        non_oud_acl = "olcAccess: {0}to * by * read"
        assert not acl_quirk.can_handle_acl(non_oud_acl)

    def test_parse_simple_aci(
        self, acl_quirk: FlextLdifQuirksServersOud.AclQuirk
    ) -> None:
        """Test parsing simple ACI format."""
        simple_aci = (
            'aci: (targetattr="*")(version 3.0; '
            'acl "Anonymous read"; '
            'allow (read,search,compare) userdn="ldap:///anyone";)'
        )

        result = acl_quirk.parse_acl(simple_aci)
        assert result.is_success, f"Failed to parse ACI: {result.error}"

        parsed = result.unwrap()
        assert parsed[FlextLdifConstants.DictKeys.TYPE] == "oud_acl"
        assert (
            parsed[FlextLdifConstants.DictKeys.FORMAT]
            == FlextLdifConstants.AclFormats.ACI
        )
        assert parsed[FlextLdifConstants.DictKeys.RAW] == simple_aci

    def test_parse_complex_aci_with_targetattr(
        self, acl_quirk: FlextLdifQuirksServersOud.AclQuirk
    ) -> None:
        """Test parsing complex ACI with targetattr and targetscope."""
        complex_aci = (
            'aci: (targetattr!="userpassword||authpassword||aci")'
            '(targetscope="base")'
            '(version 3.0; acl "Context Admins"; '
            'allow (all) groupdn="ldap:///cn=OracleContextAdmins,cn=groups,cn=OracleContext";)'
        )

        result = acl_quirk.parse_acl(complex_aci)
        assert result.is_success, f"Failed to parse complex ACI: {result.error}"

        parsed = result.unwrap()
        assert parsed[FlextLdifConstants.DictKeys.TYPE] == "oud_acl"
        assert parsed[FlextLdifConstants.DictKeys.RAW] == complex_aci

    def test_parse_multiline_aci_from_fixtures(
        self,
        acl_quirk: FlextLdifQuirksServersOud.AclQuirk,
        oud_fixtures: FlextLdifFixtures.OUD,
    ) -> None:
        """Test parsing multi-line ACIs from real OUD integration fixtures."""
        integration_content = oud_fixtures.integration()

        # Find ACI lines in fixtures
        aci_lines = [
            line
            for line in integration_content.splitlines()
            if line.strip().startswith("aci:")
        ]

        assert len(aci_lines) > 0, "No ACIs found in integration fixtures"

        # Parse first ACI
        first_aci = aci_lines[0]
        result = acl_quirk.parse_acl(first_aci)
        assert result.is_success, f"Failed to parse fixture ACI: {result.error}"

        parsed = result.unwrap()
        assert parsed[FlextLdifConstants.DictKeys.TYPE] == "oud_acl"
        assert (
            parsed[FlextLdifConstants.DictKeys.FORMAT]
            == FlextLdifConstants.AclFormats.ACI
        )

    def test_parse_ds_cfg_acl(
        self, acl_quirk: FlextLdifQuirksServersOud.AclQuirk
    ) -> None:
        """Test parsing ds-cfg- format ACL."""
        ds_cfg_acl = (
            "ds-cfg-access-control-handler: cn=Access Control Handler,cn=config"
        )

        result = acl_quirk.parse_acl(ds_cfg_acl)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed[FlextLdifConstants.DictKeys.TYPE] == "oud_acl"
        assert parsed[FlextLdifConstants.DictKeys.FORMAT] == "ds-cfg"

    def test_convert_acl_to_rfc(
        self, acl_quirk: FlextLdifQuirksServersOud.AclQuirk
    ) -> None:
        """Test converting OUD ACL to RFC-compliant format."""
        oud_acl_data: FlextLdifTypes.Dict = {
            FlextLdifConstants.DictKeys.TYPE: "oud_acl",
            FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.ACI,
            FlextLdifConstants.DictKeys.RAW: 'aci: (targetattr="*")(version 3.0; acl "test"; allow (read) userdn="ldap:///anyone";)',
        }

        result = acl_quirk.convert_acl_to_rfc(oud_acl_data)
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
            == FlextLdifConstants.AclFormats.OUD_ACL
        )

    def test_convert_acl_from_rfc(
        self, acl_quirk: FlextLdifQuirksServersOud.AclQuirk
    ) -> None:
        """Test converting RFC ACL to OUD-specific format."""
        rfc_acl_data: FlextLdifTypes.Dict = {
            FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
            FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.RFC_GENERIC,
            "permissions": ["read", "search"],
            "target": "*",
        }

        result = acl_quirk.convert_acl_from_rfc(rfc_acl_data)
        assert result.is_success

        oud_data = result.unwrap()
        assert (
            oud_data[FlextLdifConstants.DictKeys.FORMAT]
            == FlextLdifConstants.AclFormats.OUD_ACL
        )
        assert oud_data[FlextLdifConstants.DictKeys.TARGET_FORMAT] == "ds-cfg"

    def test_acl_roundtrip(self, acl_quirk: FlextLdifQuirksServersOud.AclQuirk) -> None:
        """Test ACL roundtrip: parse → convert to RFC → convert back."""
        original_aci = (
            'aci: (targetattr="*")(version 3.0; '
            'acl "Test ACL"; '
            'allow (read,search) userdn="ldap:///anyone";)'
        )

        # Parse
        parse_result = acl_quirk.parse_acl(original_aci)
        assert parse_result.is_success
        parsed = parse_result.unwrap()

        # Convert to RFC
        rfc_result = acl_quirk.convert_acl_to_rfc(parsed)
        assert rfc_result.is_success
        rfc_data = rfc_result.unwrap()

        # Convert back to OUD
        oud_result = acl_quirk.convert_acl_from_rfc(rfc_data)
        assert oud_result.is_success
        oud_data = oud_result.unwrap()

        # Validate format preserved
        assert (
            oud_data[FlextLdifConstants.DictKeys.FORMAT]
            == FlextLdifConstants.AclFormats.OUD_ACL
        )


class TestOudEntryQuirks:
    """Test suite for OUD entry quirk functionality."""

    @pytest.fixture
    def entry_quirk(self) -> FlextLdifQuirksServersOud.EntryQuirk:
        """Create OUD entry quirk instance."""
        return FlextLdifQuirksServersOud.EntryQuirk(
            server_type=FlextLdifConstants.ServerTypes.OUD
        )

    @pytest.fixture
    def oud_fixtures(self) -> FlextLdifFixtures.OUD:
        """Create OUD fixture loader."""
        return FlextLdifFixtures.OUD()

    def test_entry_quirk_initialization(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test OUD entry quirk initialization."""
        assert entry_quirk.server_type == FlextLdifConstants.ServerTypes.OUD
        assert entry_quirk.priority == 10

    def test_can_handle_entry(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test entry handling detection."""
        # OUD entry quirk handles all entries for OUD target
        entry_dn = "cn=OracleContext,dc=example,dc=com"
        attributes: FlextCore.Types.Dict = {
            "cn": ["OracleContext"],
            "objectClass": ["top", "orclContext"],
        }

        assert entry_quirk.can_handle_entry(entry_dn, attributes)

    def test_process_basic_entry(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test processing basic OUD entry."""
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: FlextCore.Types.Dict = {
            "cn": ["test"],
            "objectClass": ["person"],
        }

        result = entry_quirk.process_entry(entry_dn, attributes)
        assert result.is_success

        processed = result.unwrap()
        assert processed[FlextLdifConstants.DictKeys.DN] == entry_dn
        assert processed[FlextLdifConstants.DictKeys.SERVER_TYPE] == "oud"
        assert "cn" in processed

    def test_process_oracle_context_entry(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test processing Oracle Context entry with Oracle-specific attributes."""
        entry_dn = "cn=OracleContext,dc=example,dc=com"
        attributes: FlextCore.Types.Dict = {
            "cn": ["OracleContext"],
            "objectClass": ["top", "orclContext", "orclContextAux82"],
            "orclVersion": ["90600"],
        }

        result = entry_quirk.process_entry(entry_dn, attributes)
        assert result.is_success

        processed = result.unwrap()
        assert processed[FlextLdifConstants.DictKeys.DN] == entry_dn
        assert processed[FlextLdifConstants.DictKeys.SERVER_TYPE] == "oud"
        assert "orclVersion" in processed

    def test_process_entry_with_acl(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test processing entry with ACL attribute."""
        entry_dn = "cn=OracleContext,dc=example,dc=com"
        attributes: FlextCore.Types.Dict = {
            "cn": ["OracleContext"],
            "objectClass": ["top", "orclContext"],
            "aci": [
                '(targetattr="*")(version 3.0; acl "OracleContext accessible"; '
                'allow (all) groupdn="ldap:///cn=OracleContextAdmins,cn=groups,cn=OracleContext,dc=example,dc=com";)'
            ],
        }

        result = entry_quirk.process_entry(entry_dn, attributes)
        assert result.is_success

        processed = result.unwrap()
        assert processed[FlextLdifConstants.DictKeys.DN] == entry_dn
        assert "aci" in processed

    def test_process_entry_from_fixtures(
        self,
        entry_quirk: FlextLdifQuirksServersOud.EntryQuirk,
        oud_fixtures: FlextLdifFixtures.OUD,
    ) -> None:
        """Test processing entries from real OUD integration fixtures."""
        integration_content = oud_fixtures.integration()

        # Parse entries from LDIF content
        current_dn = None
        current_attrs: dict[str, FlextCore.Types.StringList] = {}

        for raw_line in integration_content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("dn:"):
                # Process previous entry if exists
                if current_dn and current_attrs:
                    result = entry_quirk.process_entry(current_dn, current_attrs)
                    assert result.is_success, (
                        f"Failed to process entry {current_dn}: {result.error}"
                    )

                    processed = result.unwrap()
                    assert processed[FlextLdifConstants.DictKeys.SERVER_TYPE] == "oud"

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
                current_attrs[attr_name].append(attr_value)

        # Process last entry
        if current_dn and current_attrs:
            result = entry_quirk.process_entry(current_dn, current_attrs)
            assert result.is_success

    def test_preserve_oracle_attributes(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test preservation of Oracle-specific attributes."""
        entry_dn = "cn=OracleDBSecurity,cn=Products,cn=OracleContext,dc=example,dc=com"
        attributes: FlextCore.Types.Dict = {
            "cn": ["OracleDBSecurity"],
            "objectClass": ["top", "orclContainer", "orclDBSecConfig"],
            "orclDBOIDAuthentication": ["PASSWORD"],
            "orclDBVersionCompatibility": ["90000"],
            "orclVersion": ["102000"],
        }

        result = entry_quirk.process_entry(entry_dn, attributes)
        assert result.is_success

        processed = result.unwrap()
        # Verify all Oracle attributes preserved
        assert "orclDBOIDAuthentication" in processed
        assert "orclDBVersionCompatibility" in processed
        assert "orclVersion" in processed

    def test_convert_entry_to_rfc(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test converting OUD entry to RFC-compliant format."""
        oud_entry_data: FlextLdifTypes.Dict = {
            FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
            FlextLdifConstants.DictKeys.SERVER_TYPE: "oud",
            "cn": ["test"],
            "objectClass": ["person"],
        }

        result = entry_quirk.convert_entry_to_rfc(oud_entry_data)
        assert result.is_success

        rfc_data = result.unwrap()
        # OUD entries are RFC-compliant, should pass through
        assert rfc_data[FlextLdifConstants.DictKeys.DN] == "cn=test,dc=example,dc=com"

    def test_entry_roundtrip(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test entry roundtrip: process → convert to RFC → back."""
        original_dn = "cn=OracleContext,dc=example,dc=com"
        original_attrs: FlextCore.Types.Dict = {
            "cn": ["OracleContext"],
            "objectClass": ["top", "orclContext"],
            "orclVersion": ["90600"],
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
        assert "orclVersion" in rfc_data


class TestOudQuirksIntegration:
    """Integration tests combining schema, ACL, and entry quirks."""

    @pytest.fixture
    def oud_fixtures(self) -> FlextLdifFixtures.OUD:
        """Create OUD fixture loader."""
        return FlextLdifFixtures.OUD()

    def test_fixture_loader_availability(
        self, oud_fixtures: FlextLdifFixtures.OUD
    ) -> None:
        """Test that OUD fixtures are available and loadable."""
        # Schema fixture
        schema = oud_fixtures.schema()
        assert len(schema) > 0
        assert "attributeTypes:" in schema
        assert "objectClasses:" in schema

        # Integration fixture
        integration = oud_fixtures.integration()
        assert len(integration) > 0
        assert "dn:" in integration

    def test_parse_multiple_fixture_entries(
        self, oud_fixtures: FlextLdifFixtures.OUD
    ) -> None:
        """Test parsing multiple entries from integration fixtures."""
        integration_content = oud_fixtures.integration()

        # Count entries (lines starting with "dn:")
        entry_count = sum(
            1
            for line in integration_content.splitlines()
            if line.strip().startswith("dn:")
        )

        assert entry_count > 0, "No entries found in integration fixtures"
        assert entry_count >= 50, f"Expected at least 50 entries, found {entry_count}"

    def test_parse_oracle_schemas_from_fixtures(
        self, oud_fixtures: FlextLdifFixtures.OUD
    ) -> None:
        """Test parsing Oracle schema definitions from fixtures."""
        schema_content = oud_fixtures.schema()

        # Count Oracle attributes and objectClasses
        oracle_attrs = sum(
            1
            for line in schema_content.splitlines()
            if "2.16.840.1.113894" in line and "attributeTypes:" in line
        )

        oracle_ocs = sum(
            1
            for line in schema_content.splitlines()
            if "2.16.840.1.113894" in line and "objectClasses:" in line
        )

        assert oracle_attrs > 0, "No Oracle attributes found in schema fixtures"
        assert oracle_ocs > 0, "No Oracle objectClasses found in schema fixtures"

    def test_parse_aci_from_fixtures(self, oud_fixtures: FlextLdifFixtures.OUD) -> None:
        """Test parsing ACIs from integration fixtures."""
        integration_content = oud_fixtures.integration()

        # Count ACIs
        aci_count = sum(
            1
            for line in integration_content.splitlines()
            if line.strip().startswith("aci:")
        )

        assert aci_count > 0, "No ACIs found in integration fixtures"
        assert aci_count >= 10, f"Expected at least 10 ACIs, found {aci_count}"


class TestOudSchemaRoundTrip:
    """Test suite for OUD schema write operations and round-trip validation."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD schema quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oud_fixtures(self) -> FlextLdifFixtures.OUD:
        """Create OUD fixture loader."""
        return FlextLdifFixtures.OUD()

    def test_write_attribute_to_rfc(self, oud_quirk: FlextLdifQuirksServersOud) -> None:
        """Test writing attribute data to RFC 4512 format."""
        attr_data: FlextLdifTypes.Dict = {
            "oid": "2.16.840.1.113894.1.1.1",
            "name": "orclGUID",
            "desc": "Oracle GUID",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            "equality": "caseIgnoreMatch",
        }

        result = oud_quirk.write_attribute_to_rfc(attr_data)
        assert result.is_success, f"Failed to write attribute: {result.error}"

        rfc_string = result.unwrap()
        assert "( 2.16.840.1.113894.1.1.1" in rfc_string
        assert "NAME 'orclGUID'" in rfc_string
        assert "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15" in rfc_string

    def test_write_attribute_with_metadata(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test writing attribute with metadata for perfect round-trip."""
        from flext_ldif.models import FlextLdifModels

        original_format = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        attr_data: FlextLdifTypes.Dict = {
            "oid": "2.16.840.1.113894.1.1.1",
            "name": "orclGUID",
            "_metadata": FlextLdifModels.QuirkMetadata(
                original_format=original_format, quirk_type="oud"
            ),
        }

        result = oud_quirk.write_attribute_to_rfc(attr_data)
        assert result.is_success

        # Should return exact original format when metadata present
        rfc_string = result.unwrap()
        assert rfc_string == original_format

    def test_roundtrip_attribute_parse_write_parse(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test complete round-trip: parse → write → parse for attribute."""
        original_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclVersion' "
            "DESC 'Oracle version number' "
            "EQUALITY integerMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
            "SINGLE-VALUE )"
        )

        # Step 1: Parse original
        parse1_result = oud_quirk.parse_attribute(original_attr)
        assert parse1_result.is_success
        parsed1 = parse1_result.unwrap()

        # Step 2: Write to RFC
        write_result = oud_quirk.write_attribute_to_rfc(parsed1)
        assert write_result.is_success
        written_rfc = write_result.unwrap()

        # Step 3: Parse again
        parse2_result = oud_quirk.parse_attribute(written_rfc)
        assert parse2_result.is_success
        parsed2 = parse2_result.unwrap()

        # Validate: second parse should match first parse
        assert parsed1["oid"] == parsed2["oid"]
        assert parsed1["name"] == parsed2["name"]
        assert parsed1.get("single_value") == parsed2.get("single_value")

    def test_write_objectclass_to_rfc(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test writing objectClass data to RFC 4512 format."""
        oc_data: FlextLdifTypes.Dict = {
            "oid": "2.16.840.1.113894.2.1.1",
            "name": "orclContext",
            "desc": "Oracle Context",
            "sup": "top",
            "kind": "STRUCTURAL",
            "must": ["cn"],
            "may": ["description", "orclVersion"],
        }

        result = oud_quirk.write_objectclass_to_rfc(oc_data)
        assert result.is_success, f"Failed to write objectClass: {result.error}"

        rfc_string = result.unwrap()
        assert "( 2.16.840.1.113894.2.1.1" in rfc_string
        assert "NAME 'orclContext'" in rfc_string
        assert "STRUCTURAL" in rfc_string
        assert "MUST cn" in rfc_string

    def test_roundtrip_objectclass_parse_write_parse(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test complete round-trip: parse → write → parse for objectClass."""
        original_oc = (
            "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' "
            "DESC 'Oracle Context' "
            "SUP top STRUCTURAL "
            "MUST cn "
            "MAY ( description $ orclVersion ) )"
        )

        # Step 1: Parse original
        parse1_result = oud_quirk.parse_objectclass(original_oc)
        assert parse1_result.is_success
        parsed1 = parse1_result.unwrap()

        # Step 2: Write to RFC
        write_result = oud_quirk.write_objectclass_to_rfc(parsed1)
        assert write_result.is_success
        written_rfc = write_result.unwrap()

        # Step 3: Parse again
        parse2_result = oud_quirk.parse_objectclass(written_rfc)
        assert parse2_result.is_success
        parsed2 = parse2_result.unwrap()

        # Validate: second parse should match first parse
        assert parsed1["oid"] == parsed2["oid"]
        assert parsed1["name"] == parsed2["name"]
        assert parsed1["kind"] == parsed2["kind"]


class TestOudAclRoundTrip:
    """Test suite for OUD ACL write operations and round-trip validation."""

    @pytest.fixture
    def acl_quirk(self) -> FlextLdifQuirksServersOud.AclQuirk:
        """Create OUD ACL quirk instance."""
        return FlextLdifQuirksServersOud.AclQuirk(
            server_type=FlextLdifConstants.ServerTypes.OUD
        )

    @pytest.fixture
    def oud_fixtures(self) -> FlextLdifFixtures.OUD:
        """Create OUD fixture loader."""
        return FlextLdifFixtures.OUD()

    def test_write_simple_acl_to_rfc(
        self, acl_quirk: FlextLdifQuirksServersOud.AclQuirk
    ) -> None:
        """Test writing simple ACL data to ACI format."""
        acl_data: FlextLdifTypes.Dict = {
            "targetattr": "*",
            "version": "3.0",
            "acl_name": "Test ACL",
            "permissions": [{"action": "allow", "operations": ["read", "search"]}],
            "bind_rules": [{"type": "userdn", "value": "ldap:///anyone"}],
        }

        result = acl_quirk.write_acl_to_rfc(acl_data)
        assert result.is_success, f"Failed to write ACL: {result.error}"

        aci_string = result.unwrap()
        assert '(targetattr="*")' in aci_string
        assert 'acl "Test ACL"' in aci_string
        assert "allow" in aci_string

    def test_write_multiline_acl_with_metadata(
        self, acl_quirk: FlextLdifQuirksServersOud.AclQuirk
    ) -> None:
        """Test writing multi-line ACL with metadata preservation."""
        from flext_ldif.models import FlextLdifModels

        original_multiline = (
            '(targetattr="*")(version 3.0; acl "Multi ACL";\n'
            '      allow (read,search) groupdn="ldap:///cn=Group1,dc=example,dc=com";\n'
            '      allow (write) groupdn="ldap:///cn=Group2,dc=example,dc=com";)'
        )

        acl_data: FlextLdifTypes.Dict = {
            "targetattr": "*",
            "_metadata": FlextLdifModels.QuirkMetadata(
                original_format=original_multiline,
                quirk_type="oud",
                extensions={"is_multiline": True, "line_breaks": [50, 120]},
            ),
        }

        result = acl_quirk.write_acl_to_rfc(acl_data)
        assert result.is_success

        # Should return exact original format when metadata present
        aci_string = result.unwrap()
        assert aci_string == original_multiline

    def test_roundtrip_acl_parse_write_parse(
        self, acl_quirk: FlextLdifQuirksServersOud.AclQuirk
    ) -> None:
        """Test complete round-trip: parse → write → parse for ACL."""
        original_aci = (
            'aci: (targetattr="*")(version 3.0; '
            'acl "Anonymous read access"; '
            'allow (read,search,compare) userdn="ldap:///anyone";)'
        )

        # Step 1: Parse original
        parse1_result = acl_quirk.parse_acl(original_aci)
        assert parse1_result.is_success
        parsed1 = parse1_result.unwrap()

        # Step 2: Write to RFC (returns ACI format)
        write_result = acl_quirk.write_acl_to_rfc(parsed1)
        assert write_result.is_success
        written_aci = write_result.unwrap()

        # Step 3: Parse again (need to re-add "aci: " prefix for parsing)
        if not written_aci.startswith("aci:"):
            written_aci = f"aci: {written_aci}"

        parse2_result = acl_quirk.parse_acl(written_aci)
        assert parse2_result.is_success
        parsed2 = parse2_result.unwrap()

        # Validate: essential data preserved
        assert parsed1.get("targetattr") == parsed2.get("targetattr")
        assert parsed1.get("acl_name") == parsed2.get("acl_name")


class TestOudEntryRoundTrip:
    """Test suite for OUD entry write operations and round-trip validation."""

    @pytest.fixture
    def entry_quirk(self) -> FlextLdifQuirksServersOud.EntryQuirk:
        """Create OUD entry quirk instance."""
        return FlextLdifQuirksServersOud.EntryQuirk(
            server_type=FlextLdifConstants.ServerTypes.OUD
        )

    @pytest.fixture
    def oud_fixtures(self) -> FlextLdifFixtures.OUD:
        """Create OUD fixture loader."""
        return FlextLdifFixtures.OUD()

    def test_write_simple_entry_to_ldif(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test writing simple entry data to LDIF format."""
        entry_data: FlextLdifTypes.Dict = {
            FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
            "cn": ["test"],
            "objectClass": ["top", "person"],
            "sn": ["Test User"],
        }

        result = entry_quirk.write_entry_to_ldif(entry_data)
        assert result.is_success, f"Failed to write entry: {result.error}"

        ldif_string = result.unwrap()
        assert "dn: cn=test,dc=example,dc=com" in ldif_string
        assert "cn: test" in ldif_string
        assert "objectClass: top" in ldif_string

    def test_write_entry_preserves_attribute_order(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test that writing entry preserves attribute ordering from metadata."""
        from flext_ldif.models import FlextLdifModels

        entry_data: FlextLdifTypes.Dict = {
            FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
            "cn": ["test"],
            "objectClass": ["person"],
            "sn": ["User"],
            "_metadata": FlextLdifModels.QuirkMetadata(
                quirk_type="oud",
                extensions={"attribute_order": ["cn", "objectClass", "sn"]},
            ),
        }

        result = entry_quirk.write_entry_to_ldif(entry_data)
        assert result.is_success

        ldif_string = result.unwrap()
        lines = ldif_string.strip().split("\n")

        # Find attribute positions (skip dn line)
        cn_idx = next(i for i, line in enumerate(lines) if line.startswith("cn:"))
        oc_idx = next(
            i for i, line in enumerate(lines) if line.startswith("objectClass:")
        )
        sn_idx = next(i for i, line in enumerate(lines) if line.startswith("sn:"))

        # Verify ordering: cn < objectClass < sn
        assert cn_idx < oc_idx < sn_idx

    def test_roundtrip_entry_process_write_process(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test complete round-trip: process → write → parse → process for entry."""
        original_dn = "cn=OracleContext,dc=example,dc=com"
        original_attrs: FlextCore.Types.Dict = {
            "cn": ["OracleContext"],
            "objectClass": ["top", "orclContext"],
            "orclVersion": ["90600"],
        }

        # Step 1: Process entry
        process1_result = entry_quirk.process_entry(original_dn, original_attrs)
        assert process1_result.is_success
        processed1 = process1_result.unwrap()

        # Step 2: Write to LDIF
        write_result = entry_quirk.write_entry_to_ldif(processed1)
        assert write_result.is_success
        written_ldif = write_result.unwrap()

        # Step 3: Parse LDIF back to entry dict[str, object] (simple parsing)
        lines = written_ldif.strip().split("\n")
        parsed_dn = None
        parsed_attrs: dict[str, FlextCore.Types.StringList] = {}

        for line in lines:
            if line.startswith("dn:"):
                parsed_dn = line.split(":", 1)[1].strip()
            elif ":" in line:
                attr_name, attr_value = line.split(":", 1)
                attr_name = attr_name.strip()
                attr_value = attr_value.strip()
                if attr_name not in parsed_attrs:
                    parsed_attrs[attr_name] = []
                parsed_attrs[attr_name].append(attr_value)

        # Step 4: Process again
        assert parsed_dn is not None
        process2_result = entry_quirk.process_entry(parsed_dn, parsed_attrs)
        assert process2_result.is_success
        processed2 = process2_result.unwrap()

        # Validate: essential data preserved
        assert (
            processed1[FlextLdifConstants.DictKeys.DN]
            == processed2[FlextLdifConstants.DictKeys.DN]
        )
        assert processed1.get("cn") == processed2.get("cn")
        assert processed1.get("orclVersion") == processed2.get("orclVersion")


__all__ = [
    "TestOudAclQuirks",
    "TestOudAclRoundTrip",
    "TestOudEntryQuirks",
    "TestOudEntryRoundTrip",
    "TestOudQuirksIntegration",
    "TestOudSchemaQuirks",
    "TestOudSchemaRoundTrip",
]
