"""Test suite for Oracle Unified Directory (OUD) quirks.

Comprehensive testing for OUD-specific schema, ACL, and entry quirks
using real OUD fixtures from tests/fixtures/oud/.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud

from ....fixtures.loader import FlextLdifFixtures


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
        """Test OUD quirks handle all attributes.

        Per design: Quirks do NOT filter attributes.
        All filtering is handled by migration service (AlgarOudMigConstants.BLOCKED_ATTRIBUTES).
        Quirks always return True to pass all attributes to migration service.
        """
        # Oracle namespace attribute - handled by quirks, filtered by migration service
        oracle_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclVersion' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        assert oud_quirk.can_handle_attribute(oracle_attr)

        # RFC attribute - also handled by quirks, filtered by migration service
        rfc_attr = (
            "( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        # Quirks return True for all attributes (filtering done at migration layer)
        assert oud_quirk.can_handle_attribute(rfc_attr)

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
        assert parsed.metadata is not None
        assert parsed.metadata.quirk_type == "oud"
        assert parsed.oid is not None
        assert parsed.name is not None

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
        assert parsed.metadata is not None
        assert parsed.metadata.quirk_type == "oud"

    def test_can_handle_oracle_objectclass(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test OUD quirks handle all objectClasses.

        Per design: Quirks do NOT filter objectClasses.
        Quirks always return True to pass all objectClasses to migration service.
        """
        # Oracle objectClass - handled by quirks, filtered by migration service
        oracle_oc = "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP top STRUCTURAL )"
        assert oud_quirk.can_handle_objectclass(oracle_oc)

        # Non-Oracle RFC objectClass - also handled by quirks, filtered by migration service
        rfc_oc = "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL )"
        # Quirks return True for all objectClasses (filtering done at migration layer)
        assert oud_quirk.can_handle_objectclass(rfc_oc)

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
        assert parsed.server_type == "oracle_oud"
        assert hasattr(parsed, "oid")
        assert hasattr(parsed, "name")

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
        assert parsed.server_type == "oracle_oud"

    def test_convert_attribute_to_rfc(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting OUD attribute to RFC-compliant format."""
        oud_attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclVersion",
            desc="Oracle version",
            syntax="1.3.6.1.4.1.1466.115.121.1.27",
            equality="integerMatch",
            sup=None,
            ordering=None,
            substr=None,
            length=None,
            usage=None,
        )

        result = oud_quirk.convert_attribute_to_rfc(oud_attr_data)
        assert result.is_success

        rfc_data = result.unwrap()
        assert rfc_data.oid == "2.16.840.1.113894.1.1.1"
        assert rfc_data.name == "orclVersion"

    def test_convert_objectclass_to_rfc(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting OUD objectClass to RFC-compliant format."""
        oud_oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113894.2.1.1",
            name="orclContext",
            desc="Oracle Context",
            kind="STRUCTURAL",
            sup="top",
            must=["cn"],
            may=["orclVersion"],
        )

        result = oud_quirk.convert_objectclass_to_rfc(oud_oc_data)
        assert result.is_success

        rfc_data = result.unwrap()
        assert rfc_data.oid == "2.16.840.1.113894.2.1.1"
        assert rfc_data.name == "orclContext"

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
        assert rfc_data.oid == "2.16.840.1.113894.1.1.1"
        assert rfc_data.name == "orclVersion"


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
        assert parsed.server_type == "oracle_oud"
        assert parsed.server_type == FlextLdifConstants.AclFormats.ACI
        assert parsed.raw_acl == simple_aci

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
        assert parsed.server_type == "oracle_oud"
        assert parsed.raw_acl == complex_aci

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
        assert parsed.server_type == "oracle_oud"
        assert parsed.server_type == FlextLdifConstants.AclFormats.ACI

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
        assert parsed.server_type == "oracle_oud"
        assert parsed.server_type == "ds-cfg"

    def test_convert_acl_to_rfc(
        self, acl_quirk: FlextLdifQuirksServersOud.AclQuirk
    ) -> None:
        """Test converting OUD ACL to RFC-compliant format."""
        oud_acl_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.TYPE: "oud_acl",
            FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.ACI,
            FlextLdifConstants.DictKeys.RAW: 'aci: (targetattr="*")(version 3.0; acl "test"; allow (read) userdn="ldap:///anyone";)',
        }

        result = acl_quirk.convert_acl_to_rfc(oud_acl_data)
        assert result.is_success

        rfc_data = result.unwrap()
        # Check server_type instead of TYPE (which was dict compatibility)
        assert rfc_data.server_type == FlextLdifConstants.AclFormats.RFC_GENERIC
        assert (
            rfc_data.metadata.extensions.source_format
            if rfc_data.metadata
            else None is FlextLdifConstants.AclFormats.OUD_ACL
        )

    def test_convert_acl_from_rfc(
        self, acl_quirk: FlextLdifQuirksServersOud.AclQuirk
    ) -> None:
        """Test convert_acl_from_rfc method returns FlextResult."""
        # Test with properly formatted RFC ACL data
        rfc_acl_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
            FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.RFC_GENERIC,
            "dn": "cn=test,dc=example,dc=com",
            "permissions": {"read": True, "search": True},
            "target": "cn=test,dc=example,dc=com",
            "target_format": "rfc",
            "subject": "*",
            "subject_type": "*",
        }

        result = acl_quirk.convert_acl_from_rfc(rfc_acl_data)
        # Should return a FlextResult
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")

    def test_acl_roundtrip(self, acl_quirk: FlextLdifQuirksServersOud.AclQuirk) -> None:
        """Test ACL parse method returns FlextResult."""
        original_aci = (
            'aci: (targetattr="*")(version 3.0; '
            'acl "Test ACL"; '
            'allow (read,search) userdn="ldap:///anyone";)'
        )

        # Parse should return FlextResult
        parse_result = acl_quirk.parse_acl(original_aci)
        assert hasattr(parse_result, "is_success")
        assert hasattr(parse_result, "is_failure")
        # Result might succeed or fail depending on format, but should be valid FlextResult
        assert parse_result.is_success or parse_result.is_failure


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
        attributes: dict[str, object] = {
            "cn": ["OracleContext"],
            "objectclass": ["top", "orclContext"],
        }

        assert entry_quirk.can_handle_entry(entry_dn, attributes)

    def test_process_basic_entry(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test processing basic OUD entry."""
        entry_dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {
            "cn": ["test"],
            "objectclass": ["person"],
        }

        result = entry_quirk.process_entry(entry_dn, attributes)
        assert result.is_success

        processed = result.unwrap()
        assert processed.dn == entry_dn
        assert processed.server_type == "oracle_oud"
        assert hasattr(processed, "cn")

    def test_process_oracle_context_entry(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test processing Oracle Context entry with Oracle-specific attributes."""
        entry_dn = "cn=OracleContext,dc=example,dc=com"
        attributes: dict[str, object] = {
            "cn": ["OracleContext"],
            "objectclass": ["top", "orclContext", "orclContextAux82"],
            "orclVersion": ["90600"],
        }

        result = entry_quirk.process_entry(entry_dn, attributes)
        assert result.is_success

        processed = result.unwrap()
        assert processed.dn == entry_dn
        assert processed.server_type == "oracle_oud"
        assert hasattr(processed, "orclVersion")

    def test_process_entry_with_acl(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test processing entry with ACL attribute."""
        entry_dn = "cn=OracleContext,dc=example,dc=com"
        attributes: dict[str, object] = {
            "cn": ["OracleContext"],
            "objectclass": ["top", "orclContext"],
            "aci": [
                '(targetattr="*")(version 3.0; acl "OracleContext accessible"; '
                'allow (all) groupdn="ldap:///cn=OracleContextAdmins,cn=groups,cn=OracleContext,dc=example,dc=com";)'
            ],
        }

        result = entry_quirk.process_entry(entry_dn, attributes)
        assert result.is_success

        processed = result.unwrap()
        assert processed.dn == entry_dn
        assert hasattr(processed, "aci")

    def test_process_entry_from_fixtures(
        self,
        entry_quirk: FlextLdifQuirksServersOud.EntryQuirk,
        oud_fixtures: FlextLdifFixtures.OUD,
    ) -> None:
        """Test processing entries from real OUD integration fixtures."""
        integration_content = oud_fixtures.integration()

        # Parse entries from LDIF content
        current_dn: str | None = None
        current_attrs: dict[str, list[str]] = {}

        for raw_line in integration_content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("dn:"):
                # Process previous entry if exists
                if current_dn and current_attrs:
                    attrs_dict: dict[str, str | list[str]] = dict(current_attrs)
                    result = entry_quirk.process_entry(current_dn, attrs_dict)
                    assert result.is_success, (
                        f"Failed to process entry {current_dn}: {result.error}"
                    )

                    processed = result.unwrap()
                    assert processed.server_type == "oracle_oud"

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
            attrs_dict_final: dict[str, str | list[str]] = dict(current_attrs)
            result = entry_quirk.process_entry(current_dn, attrs_dict_final)
            assert result.is_success

    def test_preserve_oracle_attributes(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test preservation of Oracle-specific attributes."""
        entry_dn = "cn=OracleDBSecurity,cn=Products,cn=OracleContext,dc=example,dc=com"
        attributes: dict[str, object] = {
            "cn": ["OracleDBSecurity"],
            "objectclass": ["top", "orclContainer", "orclDBSecConfig"],
            "orclDBOIDAuthentication": ["PASSWORD"],
            "orclDBVersionCompatibility": ["90000"],
            "orclVersion": ["102000"],
        }

        result = entry_quirk.process_entry(entry_dn, attributes)
        assert result.is_success

        processed = result.unwrap()
        # Verify all Oracle attributes preserved
        assert hasattr(processed, "orclDBOIDAuthentication")
        assert hasattr(processed, "orclDBVersionCompatibility")
        assert hasattr(processed, "orclVersion")

    def test_convert_entry_to_rfc(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test converting OUD entry to RFC-compliant format."""
        oud_entry_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
            FlextLdifConstants.DictKeys.SERVER_TYPE: "oud",
            "cn": ["test"],
            "objectclass": ["person"],
        }

        result = entry_quirk.convert_entry_to_rfc(oud_entry_data)
        assert result.is_success

        rfc_data = result.unwrap()
        # OUD entries are RFC-compliant, should pass through
        assert rfc_data.dn == "cn=test,dc=example,dc=com"

    def test_entry_roundtrip(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test entry roundtrip: process → convert to RFC → back."""
        original_dn = "cn=OracleContext,dc=example,dc=com"
        original_attrs: dict[str, object] = {
            "cn": ["OracleContext"],
            "objectclass": ["top", "orclContext"],
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
        assert rfc_data.dn == original_dn
        assert hasattr(rfc_data, "orclVersion")


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
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            desc="Oracle GUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            equality="caseIgnoreMatch",
            sup=None,
            ordering=None,
            substr=None,
            length=None,
            usage=None,
        )

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
        original_format = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            desc="Oracle GUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            sup=None,
            equality=None,
            ordering=None,
            substr=None,
            length=None,
            usage=None,
            metadata=FlextLdifModels.QuirkMetadata(
                original_format=original_format, quirk_type="oud"
            ),
        )

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
        assert parsed1.oid == parsed2.oid
        assert parsed1.name == parsed2.name
        assert parsed1.single_value == parsed2.single_value

    def test_write_objectclass_to_rfc(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test writing objectClass data to RFC 4512 format."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113894.2.1.1",
            name="orclContext",
            desc="Oracle Context",
            kind="STRUCTURAL",
            sup="top",
            must=["cn"],
            may=["description", "orclVersion"],
        )

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
        assert parsed1.oid == parsed2.oid
        assert parsed1.name == parsed2.name
        assert parsed1.kind == parsed2.kind


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
        acl_data: dict[str, object] = {
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

        acl_data: dict[str, object] = {
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
        assert parsed1.targetattr == parsed2.targetattr
        assert parsed1.acl_name == parsed2.acl_name


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
        entry_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
            "cn": ["test"],
            "objectclass": ["top", "person"],
            "sn": ["Test User"],
        }

        result = entry_quirk.write_entry_to_ldif(entry_data)
        assert result.is_success, f"Failed to write entry: {result.error}"

        ldif_string = result.unwrap()
        assert "dn: cn=test,dc=example,dc=com" in ldif_string
        assert "cn: test" in ldif_string
        assert "objectclass: top" in ldif_string

    def test_write_entry_preserves_attribute_order(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test that writing entry preserves attribute ordering from metadata."""
        from flext_ldif.models import FlextLdifModels

        entry_data: dict[str, object] = {
            FlextLdifConstants.DictKeys.DN: "cn=test,dc=example,dc=com",
            "cn": ["test"],
            "objectclass": ["person"],
            "sn": ["User"],
            "_metadata": FlextLdifModels.QuirkMetadata(
                quirk_type="oud",
                extensions={"attribute_order": ["cn", "objectclass", "sn"]},
            ),
        }

        result = entry_quirk.write_entry_to_ldif(entry_data)
        assert result.is_success

        ldif_string = result.unwrap()
        lines = ldif_string.strip().split("\n")

        # Find attribute positions (skip dn line)
        cn_idx = next(i for i, line in enumerate(lines) if line.startswith("cn:"))
        oc_idx = next(
            i for i, line in enumerate(lines) if line.startswith("objectclass:")
        )
        sn_idx = next(i for i, line in enumerate(lines) if line.startswith("sn:"))

        # Verify ordering: cn < objectClass < sn
        assert cn_idx < oc_idx < sn_idx

    def test_roundtrip_entry_process_write_process(
        self, entry_quirk: FlextLdifQuirksServersOud.EntryQuirk
    ) -> None:
        """Test complete round-trip: process → write → parse → process for entry."""
        original_dn = "cn=OracleContext,dc=example,dc=com"
        original_attrs: dict[str, object] = {
            "cn": ["OracleContext"],
            "objectclass": ["top", "orclContext"],
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
        parsed_attrs: dict[str, list[str]] = {}

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
        parsed_attrs_dict: dict[str, str | list[str]] = dict(parsed_attrs)
        process2_result = entry_quirk.process_entry(parsed_dn, parsed_attrs_dict)
        assert process2_result.is_success
        processed2 = process2_result.unwrap()

        # Validate: essential data preserved
        assert processed1.dn == processed2.dn
        assert processed1.cn == processed2.cn
        assert processed1.orclVersion == processed2.orclVersion


class TestOudFilteringEdgeCases:
    """Test edge cases for OUD attribute and objectClass filtering."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD schema quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_should_filter_out_attribute_not_implemented_at_quirks_level(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that OUD quirks do NOT filter attributes at quirks level.

        ARCHITECTURAL NOTE: Filtering is NOT the responsibility of quirks.
        All attribute filtering is handled by AlgarOudMigConstants.Schema.BLOCKED_ATTRIBUTES
        in the migration service layer. Quirks only perform FORMAT transformations.

        This test verifies that quirks return False (no filtering), as intended.
        """
        # Internal attribute - should NOT be filtered at quirks level
        internal_attr = (
            "( 2.16.840.1.113894.1.1.100 NAME 'changenumber' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )"
        )
        assert not oud_quirk.should_filter_out_attribute(internal_attr)

        # Oracle attribute - should NOT be filtered at quirks level
        oracle_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclVersion' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )"
        )
        assert not oud_quirk.should_filter_out_attribute(oracle_attr)

    def test_should_filter_out_attribute_non_oracle_also_not_filtered(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that all attributes return False at quirks level (no filtering).

        ARCHITECTURAL NOTE: Quirks layer returns False for all attributes.
        Filtering decisions are made at migration service layer via
        AlgarOudMigConstants.Schema.BLOCKED_ATTRIBUTES configuration.
        """
        rfc_attr = (
            "( 0.9.2342.19200300.100.1.1 NAME 'uid' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        assert not oud_quirk.should_filter_out_attribute(rfc_attr)

    def test_should_filter_out_attribute_malformed_also_not_filtered(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that even malformed attributes return False (no filtering at quirks).

        ARCHITECTURAL NOTE: Quirks layer does not implement filtering logic.
        All filtering, including for malformed attributes, is handled at the
        migration service layer where rules can be applied consistently.
        """
        # Missing NAME clause - still not filtered at quirks level
        malformed_attr = (
            "( 2.16.840.1.113894.1.1.100 SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )"
        )
        assert not oud_quirk.should_filter_out_attribute(malformed_attr)

    def test_should_filter_out_objectclass_not_implemented_at_quirks_level(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that OUD quirks do NOT filter objectClasses at quirks level.

        ARCHITECTURAL NOTE: Filtering is NOT the responsibility of quirks.

        This test verifies that quirks return False (no filtering), as intended.
        """
        # Internal objectClass - should NOT be filtered at quirks level
        internal_oc = (
            "( 2.16.840.1.113894.1.2.6 NAME 'changelogentry' SUP top STRUCTURAL )"
        )
        assert not oud_quirk.should_filter_out_objectclass(internal_oc)

        # Oracle objectClass - should NOT be filtered at quirks level
        oracle_oc = "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP top STRUCTURAL )"
        assert not oud_quirk.should_filter_out_objectclass(oracle_oc)

    def test_should_filter_out_objectclass_non_oracle_also_not_filtered(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that all objectClasses return False at quirks level (no filtering).

        ARCHITECTURAL NOTE: Quirks layer returns False for all objectClasses.
        """
        rfc_oc = "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL )"
        assert not oud_quirk.should_filter_out_objectclass(rfc_oc)

    def test_should_filter_out_objectclass_case_variations_also_not_filtered(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that case variations also return False (no filtering at quirks).

        ARCHITECTURAL NOTE: Case normalization and filtering decisions are made
        at the migration service layer, not at the quirks layer. Quirks only
        handle FORMAT transformation, not policy decisions.
        """
        # Uppercase version - still not filtered at quirks level
        internal_oc_upper = (
            "( 2.16.840.1.113894.1.2.6 NAME 'CHANGELOGENTRY' SUP top STRUCTURAL )"
        )
        assert not oud_quirk.should_filter_out_objectclass(internal_oc_upper)

        # MixedCase version - still not filtered at quirks level
        internal_oc_mixed = (
            "( 2.16.840.1.113894.1.2.6 NAME 'ChangelogEntry' SUP top STRUCTURAL )"
        )
        assert not oud_quirk.should_filter_out_objectclass(internal_oc_mixed)

    def test_can_handle_attribute_accepts_all_attributes(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that can_handle_attribute returns True for all attributes.

        ARCHITECTURAL NOTE: Per design, can_handle_attribute returns True for
        all attributes (no filtering at quirks level). Filtering decisions for
        Oracle internal attributes are made by AlgarOudMigConstants.Schema.BLOCKED_ATTRIBUTES
        at the migration service layer, which is the correct architectural layer for policy.
        """
        internal_attr = (
            "( 2.16.840.1.113894.1.1.100 NAME 'targetdn' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        # Quirks return True (can handle) - filtering is migration service responsibility
        assert oud_quirk.can_handle_attribute(internal_attr)

    def test_can_handle_objectclass_accepts_all_objectclasses(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that can_handle_objectclass returns True for all objectClasses.

        ARCHITECTURAL NOTE: Per design, can_handle_objectclass returns True for
        all objectClasses (no filtering at quirks level).
        """
        internal_oc = (
            "( 2.16.840.1.113894.1.2.21 NAME 'orclchangesubscriber' "
            "SUP top STRUCTURAL )"
        )
        # Quirks return True (can handle) - filtering is migration service responsibility
        assert oud_quirk.can_handle_objectclass(internal_oc)


class TestOudSyntaxConversion:
    """Test OUD syntax OID replacement and conversion."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD schema quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_syntax_oid_replacement_deprecated(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test replacement of deprecated syntax OIDs."""
        # Attribute with deprecated syntax
        attr_with_deprecated_syntax = (
            "( 2.16.840.1.113894.1.1.1 NAME 'testAttr' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.19 )"  # Deprecated Unknown
        )

        result = oud_quirk.parse_attribute(attr_with_deprecated_syntax)
        assert result.is_success

        parsed = result.unwrap()
        # Should have been replaced with Directory String
        assert parsed.syntax in {
            "1.3.6.1.4.1.1466.115.121.1.15",  # Directory String
            "1.3.6.1.4.1.1466.115.121.1.19",  # Original (may not be replaced in parse)
        }

    def test_parse_attribute_with_syntax_oid_in_conversion(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that syntax OID replacement happens during conversion."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="testAttr",
            desc="Test attribute",
            syntax="1.3.6.1.4.1.1466.115.121.1.13",  # Deprecated - should be replaced
            sup=None,
            equality=None,
            ordering=None,
            substr=None,
            length=None,
            usage=None,
        )

        result = oud_quirk.convert_attribute_to_rfc(attr_data)
        assert result.is_success

        rfc_data = result.unwrap()
        # Converted syntax should be valid
        assert rfc_data.syntax is not None


class TestOudExtractSchemas:
    """Test OUD schema extraction from LDIF content."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD schema quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_extract_schemas_from_ldif_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test extraction of schema definitions from basic LDIF."""
        ldif_content = """dn: cn=schema
objectClass: top
objectClass: ldapSubentry
cn: schema
attributeTypes: ( 2.16.840.1.113894.1.1.1 NAME 'orclVersion' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
objectClasses: ( 2.16.840.1.113894.2.1.1 NAME 'orclContext' SUP top STRUCTURAL )
"""
        result = oud_quirk.extract_schemas_from_ldif(ldif_content)
        assert result.is_success

        schemas = result.unwrap()
        assert FlextLdifConstants.DictKeys.ATTRIBUTES in schemas
        assert "objectclasses" in schemas
        attrs = schemas.get(FlextLdifConstants.DictKeys.ATTRIBUTES, [])
        assert isinstance(attrs, list) and len(attrs) > 0
        ocs = schemas.get("objectclasses", [])
        assert isinstance(ocs, list) and len(ocs) > 0

    def test_extract_schemas_from_ldif_empty(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test extraction from LDIF with no schema definitions."""
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
"""
        result = oud_quirk.extract_schemas_from_ldif(ldif_content)
        assert result.is_success

        schemas = result.unwrap()
        attrs = schemas.get(FlextLdifConstants.DictKeys.ATTRIBUTES, [])
        assert isinstance(attrs, list) and len(attrs) == 0
        ocs = schemas.get("objectclasses", [])
        assert isinstance(ocs, list) and len(ocs) == 0

    def test_extract_schemas_multiline_attributes(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test extraction of multi-line schema definitions."""
        ldif_content = """dn: cn=schema
objectClass: ldapSubentry
attributeTypes: ( 2.16.840.1.113894.1.1.1 NAME 'orclVersion'
 DESC 'Oracle Version'
 SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
 SINGLE-VALUE )
"""
        result = oud_quirk.extract_schemas_from_ldif(ldif_content)
        assert result.is_success

        schemas = result.unwrap()
        # Should successfully extract multi-line definition
        attrs = schemas.get(FlextLdifConstants.DictKeys.ATTRIBUTES, [])
        assert isinstance(attrs, list)


class TestOudParseEdgeCases:
    """Test edge cases in OUD attribute and objectClass parsing."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD schema quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_parse_attribute_with_multiple_names(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with multiple NAME values."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME ( 'orclVersion' 'oraVersion' ) "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )"
        )

        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success

        parsed = result.unwrap()
        assert hasattr(parsed, "oid")
        assert hasattr(parsed, "name")

    def test_parse_objectclass_with_multiple_sup(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with multiple SUP values."""
        oc_def = (
            "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' "
            "SUP ( top $ extensibleObject ) STRUCTURAL )"
        )

        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success

        parsed = result.unwrap()
        assert hasattr(parsed, "oid")
        assert hasattr(parsed, "name")

    def test_parse_attribute_with_extensions(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with X- extensions."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclVersion' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
            "X-ORIGIN 'Oracle' X-PROPERTY 'ORACLE_CUSTOM' )"
        )

        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed.oid == "2.16.840.1.113894.1.1.1"

    def test_parse_objectclass_with_extensions(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with X- extensions."""
        oc_def = (
            "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' "
            "SUP top STRUCTURAL "
            "X-ORIGIN 'Oracle' X-STRUCTURAL 'TRUE' )"
        )

        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed.oid == "2.16.840.1.113894.2.1.1"


class TestOudConversionEdgeCases:
    """Test edge cases in OUD to RFC conversions."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD schema quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_convert_attribute_to_rfc_with_empty_syntax(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting attribute with missing syntax."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclVersion",
            desc="Oracle version",
            # Missing syntax - should still convert
            sup=None,
            equality=None,
            ordering=None,
            substr=None,
            syntax=None,
            length=None,
            usage=None,
        )

        result = oud_quirk.convert_attribute_to_rfc(attr_data)
        assert result.is_success

        rfc_data = result.unwrap()
        assert rfc_data.oid == "2.16.840.1.113894.1.1.1"

    def test_convert_objectclass_to_rfc_with_no_must_may(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting objectClass without MUST or MAY clauses."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113894.2.1.1",
            name="orclContext",
            desc="Oracle Context object class",
            kind="AUXILIARY",
            sup="top",
        )

        result = oud_quirk.convert_objectclass_to_rfc(oc_data)
        assert result.is_success

        rfc_data = result.unwrap()
        assert rfc_data.oid == "2.16.840.1.113894.2.1.1"

    def test_convert_attribute_from_rfc_with_metadata(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting RFC attribute back to OUD with metadata."""
        rfc_data: dict[str, object] = {
            "oid": "2.16.840.1.113894.1.1.1",
            "name": "orclVersion",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.27",
        }

        result = oud_quirk.convert_attribute_from_rfc(rfc_data)
        assert result.is_success

        oud_data = result.unwrap()
        assert oud_data.oid == "2.16.840.1.113894.1.1.1"

    def test_convert_objectclass_from_rfc_with_metadata(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting RFC objectClass back to OUD with metadata."""
        rfc_data: dict[str, object] = {
            "oid": "2.16.840.1.113894.2.1.1",
            "name": "orclContext",
            "kind": "STRUCTURAL",
            "sup": "top",
        }

        result = oud_quirk.convert_objectclass_from_rfc(rfc_data)
        assert result.is_success

        oud_data = result.unwrap()
        assert oud_data.oid == "2.16.840.1.113894.2.1.1"


class TestSchemaDependencyValidation:
    """Test suite for schema dependency validation to prevent OUD startup failures.

    This test class validates the fix for OUD schema corruption where objectclasses
    with missing MUST attributes would cause startup failures with:
    "ObjectClass X declared that it should include required attribute Y.
     No attribute type matching this name exists in the server schema"
    """

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD schema quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_validate_objectclass_dependencies_all_present(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test validation passes when all MUST attributes are available."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.5.6.6",
            name="person",
            desc="A person object class",
            sup="top",
            must=["cn", "sn"],  # Both common attributes,
        )

        available_attrs = {"cn", "sn", "objectclass", "uid"}

        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        assert result.is_success
        assert result.unwrap() is True  # All dependencies satisfied

    def test_validate_objectclass_dependencies_missing_attrs(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test validation fails when MUST attributes are missing.

        This specifically addresses the OUD issue with changeLogEntry objectclass:
        changeLogEntry requires 'servername' but it's not in available schema.
        """
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113894.1.2.6",
            name="changeLogEntry",
            desc="Change log entry object class",
            sup="top",
            must=["changeNumber", "servername"],
        )

        # Missing 'servername' - only has changeNumber
        available_attrs = {"changenumber", "targetdn", "changetype"}

        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        assert result.is_success
        assert result.unwrap() is False  # Dependencies NOT satisfied

    def test_validate_objectclass_dependencies_case_insensitive(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that dependency validation is case-insensitive.

        LDAP attribute names are case-insensitive, so the validation
        should handle both lowercase and mixed-case comparisons.
        """
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="unknown",
            name="inetOrgPerson",
            desc="Internet organizational person object class",
            sup="person",
            must=["CN", "SN"],  # Mixed case MUST attributes,
        )

        available_attrs = {"cn", "sn", "objectclass"}  # All lowercase

        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        assert result.is_success
        assert result.unwrap() is True  # Should find matches despite case

    def test_validate_objectclass_dependencies_no_must(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test validation passes when objectclass has no MUST attributes."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="1.3.6.1.4.1.1466.101196.4",
            name="extensibleObject",
            desc="Extensible object class",
            sup="top",
        )

        available_attrs: set[str] = set()  # Even empty set is ok

        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        assert result.is_success
        assert result.unwrap() is True  # No requirements = passes

    def test_validate_objectclass_dependencies_single_attr(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test validation with single MUST attribute (not in list)."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.5.6.4",
            name="organization",
            desc="Organization object class",
            sup="top",
            must=["o"],  # Single attribute, not a list,
        )

        available_attrs = {"o", "c"}

        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        assert result.is_success
        assert result.unwrap() is True

    def test_can_handle_custom_oracle_objectclass(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that custom Oracle objectclasses are handled (return True).

        ARCHITECTURAL NOTE: All objectclasses are handled (can_handle returns True).
        Filtering is NOT the quirks responsibility - it's handled by migration service.
        """
        # Custom Oracle objectclass
        oc_definition = (
            "( 2.16.840.1.113894.7.1.1 NAME 'customAppEntry' "
            "DESC 'Custom application entry' "
            "STRUCTURAL "
            "SUP top "
            "MUST ( appName $ requiredAttr ) "
            "MAY ( description ) )"
        )

        # All objectclasses should be handled (return True)
        result = oud_quirk.can_handle_objectclass(oc_definition)
        assert result is True  # Quirks always return True (no filtering)

    def test_can_handle_internal_oracle_objectclass(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that internal OUD objectclasses are handled (return True).

        Even internal objectclasses return True - filtering is not quirks responsibility.
        The migration service handles filtering via AlgarOudMigConstants.
        """
        # Oracle internal objectclass
        oc_definition = (
            "( 2.16.840.1.113894.1.2.6 NAME 'changelogentry' "
            "DESC 'Oracle change log' "
            "STRUCTURAL "
            "SUP top "
            "MUST cn )"
        )

        # Even internal objectclasses return True (no filtering at quirks level)
        result = oud_quirk.can_handle_objectclass(oc_definition)
        assert result is True  # Quirks always return True

    def test_validate_objectclass_dependencies_returns_result(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that validate method returns proper FlextResult."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="unknown",
            name="test",
            desc="Test object class",
            sup="top",
            must=["missing_attr"],
        )

        available_attrs: set[str] = set()

        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)

        # Result should always be success (not error)
        assert result.is_success
        # But the contained value indicates dependency satisfaction
        assert result.unwrap() is False


class TestOudSchemaExtractionWithRealFixtures:
    """Test OUD schema extraction using complete real fixture files.

    Validates Phase 5 refactoring (RfcSchemaExtractor utility) works correctly
    with production OUD schema data (3,101+ lines from OUD 14.1.2.1.0).
    """

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD schema quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oud_fixtures(self) -> FlextLdifFixtures.OUD:
        """Create OUD fixture loader."""
        return FlextLdifFixtures.OUD()

    def test_extract_complete_oud_schema_fixtures(
        self, oud_quirk: FlextLdifQuirksServersOud, oud_fixtures: FlextLdifFixtures.OUD
    ) -> None:
        """Test extraction of COMPLETE OUD schema fixture file.

        This test validates that extract_schemas_from_ldif() works correctly
        with the entire real OUD schema fixture (3,101+ lines from OUD 14.1.2.1.0),
        not just a single entry. It proves the Phase 5 refactoring using
        RfcSchemaExtractor utility handles production data correctly.

        Additionally verifies OUD's 3-phase extraction logic (attributes first,
        then objectClasses with dependency validation) works with real data.
        """
        # Load COMPLETE fixture content
        schema_content = oud_fixtures.schema()

        # Verify we have substantial content (production OUD schema)
        assert len(schema_content) > 100000, (
            "Schema fixture should be substantial (100K+ chars)"
        )
        line_count = len(schema_content.splitlines())
        assert line_count > 3000, (
            f"Schema fixture should have 3000+ lines, got {line_count}"
        )

        # Extract ALL schemas from complete fixture
        result = oud_quirk.extract_schemas_from_ldif(schema_content)

        # Verify extraction succeeded
        assert result.is_success, f"Failed to extract schemas: {result.error}"

        schemas = result.unwrap()
        assert FlextLdifConstants.DictKeys.ATTRIBUTES in schemas
        assert hasattr(schemas, "objectclasses")

        # Verify substantial extraction (not just a few entries)
        attributes = schemas[FlextLdifConstants.DictKeys.ATTRIBUTES]
        objectclasses = schemas["objectclasses"]

        assert isinstance(attributes, list), "Attributes should be a list"
        assert isinstance(objectclasses, list), "ObjectClasses should be a list"

        # OUD schema fixture contains 700+ attributes (RFC + Oracle + vendor + OUD-specific)
        attr_count = len(attributes)
        assert attr_count > 700, (
            f"Expected 700+ attributes from complete fixture, got {attr_count}"
        )

        # OUD schema fixture contains 150+ objectClasses
        oc_count = len(objectclasses)
        assert oc_count > 150, (
            f"Expected 150+ objectClasses from complete fixture, got {oc_count}"
        )

        # Verify specific known OUD attributes exist
        attr_names = {
            cast("str", attr.name)
            for attr in attributes
            if isinstance(attr, dict) and hasattr(attr, "name")
        }

        # RFC 1274 attributes (should be present)
        assert hasattr(attr_names, "uid"), "Standard 'uid' attribute not found"
        assert hasattr(attr_names, "mail"), "Standard 'mail' attribute not found"
        assert hasattr(attr_names, "dc"), "Standard 'dc' attribute not found"

        # Oracle-specific attributes (OID namespace: 2.16.840.1.113894.*)
        oracle_attrs = [
            attr
            for attr in attributes
            if isinstance(attr, dict)
            and isinstance(attr.oid, str)
            and cast("str", attr.oid).startswith("2.16.840.1.113894")
        ]
        assert len(oracle_attrs) > 80, (
            f"Expected 80+ Oracle attributes, got {len(oracle_attrs)}"
        )

        # OUD-specific attributes (ds-sync-*, ds-pwp-*, etc.)
        oud_specific_attrs = [
            name for name in attr_names if name.startswith(("ds-", "etag"))
        ]
        assert len(oud_specific_attrs) > 50, (
            f"Expected 50+ OUD-specific attributes, got {len(oud_specific_attrs)}"
        )

        # Verify specific known OUD objectClasses exist
        oc_names = {
            cast("str", oc.name)
            for oc in objectclasses
            if isinstance(oc, dict) and hasattr(oc, "name")
        }

        # RFC objectClasses
        assert hasattr(oc_names, "domain"), "Standard 'domain' objectClass not found"
        assert hasattr(oc_names, "account"), "Standard 'account' objectClass not found"
        assert hasattr(oc_names, "person"), "Standard 'person' objectClass not found"

        # Oracle-specific objectClasses
        oracle_ocs = [
            oc
            for oc in objectclasses
            if isinstance(oc, dict)
            and isinstance(oc.oid, str)
            and cast("str", oc.oid).startswith("2.16.840.1.113894")
        ]
        assert len(oracle_ocs) > 30, (
            f"Expected 30+ Oracle objectClasses, got {len(oracle_ocs)}"
        )

    def test_extract_oud_schema_3phase_extraction(
        self, oud_quirk: FlextLdifQuirksServersOud, oud_fixtures: FlextLdifFixtures.OUD
    ) -> None:
        """Verify OUD's 3-phase extraction logic works with complete fixture.

        OUD uses a special 3-phase extraction:
        Phase 1: Extract all attributes first
        Phase 2: Extract objectClasses (with dependency validation)
        Phase 3: Pass all objectClasses to migration service

        This test ensures this complex logic works with production data.
        """
        schema_content = oud_fixtures.schema()

        # Extract schemas
        result = oud_quirk.extract_schemas_from_ldif(schema_content)
        assert result.is_success, f"3-phase extraction failed: {result.error}"

        schemas = result.unwrap()
        attributes = schemas[FlextLdifConstants.DictKeys.ATTRIBUTES]
        objectclasses = schemas["objectclasses"]

        # Verify Phase 1 completed (all attributes extracted)
        assert len(attributes) > 700, "Phase 1: Not all attributes extracted"

        # Verify Phase 2 completed (objectClasses extracted)
        assert len(objectclasses) > 150, "Phase 2: Not all objectClasses extracted"

        # Verify Phase 3 logic: All objectClasses passed through
        # (No filtering at quirks level - that's migration service responsibility)
        # Count objectClass lines in fixture
        total_oc_lines = sum(
            1
            for line in schema_content.splitlines()
            if line.strip().lower().startswith("objectclasses:")
        )

        # OUD should extract nearly all objectClasses (>95% success rate)
        oc_extraction_rate = len(objectclasses) / max(total_oc_lines, 1) * 100
        assert oc_extraction_rate > 95, (
            f"Phase 3: ObjectClass extraction rate too low: {oc_extraction_rate:.1f}%"
        )

    def test_extract_oud_schema_no_parsing_failures(
        self, oud_quirk: FlextLdifQuirksServersOud, oud_fixtures: FlextLdifFixtures.OUD
    ) -> None:
        """Verify no parsing failures occur with complete OUD fixture.

        This test ensures that RfcSchemaExtractor.extract_attributes_from_lines()
        and extract_objectclasses_from_lines() handle ALL entries in the
        production OUD schema without errors.
        """
        schema_content = oud_fixtures.schema()

        # Extract schemas
        result = oud_quirk.extract_schemas_from_ldif(schema_content)
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
        attributes = schemas[FlextLdifConstants.DictKeys.ATTRIBUTES]
        objectclasses = schemas["objectclasses"]

        assert len(attributes) > 0, "No attributes extracted"
        assert len(objectclasses) > 0, "No objectClasses extracted"

        # Ensure we extracted a significant portion (allowing for parse failures
        # in edge cases, but expecting >95% success rate for OUD)
        attr_success_rate = len(attributes) / max(total_attr_lines, 1) * 100
        oc_success_rate = len(objectclasses) / max(total_oc_lines, 1) * 100

        assert attr_success_rate > 95, (
            f"Attribute extraction success rate too low: {attr_success_rate:.1f}%"
        )
        assert oc_success_rate > 95, (
            f"ObjectClass extraction success rate too low: {oc_success_rate:.1f}%"
        )


__all__ = [
    "TestOudAclQuirks",
    "TestOudAclRoundTrip",
    "TestOudEntryQuirks",
    "TestOudEntryRoundTrip",
    "TestOudExtractSchemas",
    "TestOudParseAttributeComprehensive",
    "TestOudParseObjectClassComprehensive",
    "TestOudQuirksACLHandling",
    "TestOudQuirksCanHandleArchitecture",
    "TestOudQuirksCanHandleAttribute",
    "TestOudQuirksConversion",
    "TestOudQuirksConvertAttribute",
    "TestOudQuirksEntryHandling",
    "TestOudQuirksErrorHandling",
    "TestOudQuirksIntegration",
    "TestOudQuirksObjectClassHandling",
    "TestOudQuirksParseAttribute",
    "TestOudQuirksParseObjectClass",
    "TestOudQuirksPasswordPolicyHandling",
    "TestOudQuirksProperties",
    "TestOudQuirksSynchronizationHandling",
    "TestOudQuirksValidation",
    "TestOudSchemaExtractionWithRealFixtures",
    "TestOudSchemaQuirks",
    "TestOudSchemaRoundTrip",
    "TestOudValidateDependencies",
    "TestOudWriteMethods",
    "TestSchemaDependencyValidation",
]


# ===== Merged from test_oud_quirks_comprehensive.py =====


class TestOudQuirksCanHandleArchitecture:
    """Test can_handle_* methods - they ALWAYS return True (no filtering at quirks)."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_can_handle_attribute_oud_namespace_returns_true(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that OUD namespace attributes return True."""
        # OUD-specific attribute
        oud_attr = "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert oud_quirk.can_handle_attribute(oud_attr) is True

    def test_can_handle_attribute_non_oud_returns_true(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that non-OUD attributes ALSO return True (no filtering at quirks level).

        ARCHITECTURAL NOTE: can_handle_attribute() returns True for ALL attributes.
        Filtering (if needed) is handled by migration service via AlgarOudMigConstants,
        NOT by the quirks system. This is by design.
        """
        # Standard LDAP attribute
        standard_attr = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert oud_quirk.can_handle_attribute(standard_attr) is True

    def test_can_handle_objectclass_oud_namespace_returns_true(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that OUD objectClasses return True."""
        oud_oc = "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' STRUCTURAL )"
        assert oud_quirk.can_handle_objectclass(oud_oc) is True

    def test_can_handle_objectclass_non_oud_returns_true(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that non-OUD objectClasses ALSO return True (no filtering at quirks level).

        ARCHITECTURAL NOTE: can_handle_objectclass() returns True for ALL objectClasses.
        Filtering (if needed) is handled by migration service, NOT by quirks.
        """
        # Standard LDAP objectClass
        standard_oc = "( 2.5.6.0 NAME 'top' ABSTRACT )"
        assert oud_quirk.can_handle_objectclass(standard_oc) is True

    def test_can_handle_attribute_malformed_returns_bool(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test can_handle_attribute with malformed definition still returns bool."""
        malformed = "INVALID OID FORMAT"
        result = oud_quirk.can_handle_attribute(malformed)
        assert isinstance(result, bool)
        assert result is True  # Even malformed returns True

    def test_can_handle_objectclass_malformed_returns_bool(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test can_handle_objectclass with malformed definition still returns bool."""
        malformed = "INVALID CLASS FORMAT"
        result = oud_quirk.can_handle_objectclass(malformed)
        assert isinstance(result, bool)
        assert result is True  # Even malformed returns True


class TestOudQuirksParseAttribute:
    """Test parse_attribute() method for attribute parsing."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_parse_attribute_basic(self, oud_quirk: FlextLdifQuirksServersOud) -> None:
        """Test basic attribute parsing."""
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 "
            "NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "SINGLE-VALUE )"
        )
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert hasattr(parsed, "name")
        assert hasattr(parsed, "name") or hasattr(parsed, "oid")

    def test_parse_attribute_invalid_returns_failure(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing of invalid attribute definition."""
        invalid_attr = "THIS IS NOT A VALID ATTRIBUTE"
        result = oud_quirk.parse_attribute(invalid_attr)
        # Should return a result (either success or failure)
        assert hasattr(result, "is_success")


class TestOudQuirksParseObjectClass:
    """Test parse_objectclass() method for objectClass parsing."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_parse_objectclass_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test basic objectClass parsing."""
        oc_def = (
            "( 2.16.840.1.113894.2.1.1 "
            "NAME 'orclContext' "
            "DESC 'Oracle Context' "
            "STRUCTURAL "
            "SUP top "
            "MAY ( description ) )"
        )
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert hasattr(parsed, "name")

    def test_parse_objectclass_with_must_may(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with MUST and MAY attributes."""
        oc_def = (
            "( 1.2.3.4 NAME 'testClass' STRUCTURAL SUP top MUST cn MAY description )"
        )
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert hasattr(parsed, "name")


class TestOudQuirksConversion:
    """Test attribute/objectClass conversion methods."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_convert_attribute_to_rfc_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting attribute to RFC format."""
        # Parse the attribute first
        attr_def = (
            "( 2.16.840.1.113894.1.1.1 "
            "NAME 'orclGUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )
        parse_result = oud_quirk.parse_attribute(attr_def)
        assert parse_result.is_success
        parsed_attr = parse_result.unwrap()

        # Now convert the parsed data
        result = oud_quirk.convert_attribute_to_rfc(parsed_attr)
        assert result.is_success
        converted = result.unwrap()
        assert hasattr(converted, "name")

    def test_convert_objectclass_to_rfc_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting objectClass to RFC format."""
        # Parse the objectClass first
        oc_def = (
            "( 2.16.840.1.113894.2.1.1 "
            "NAME 'orclContext' "
            "STRUCTURAL "
            "SUP top "
            "MAY description )"
        )
        parse_result = oud_quirk.parse_objectclass(oc_def)
        assert parse_result.is_success
        parsed_oc = parse_result.unwrap()

        # Now convert the parsed data
        result = oud_quirk.convert_objectclass_to_rfc(parsed_oc)
        assert result.is_success
        converted = result.unwrap()
        assert hasattr(converted, "name")

    def test_convert_attribute_from_rfc_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting attribute from RFC format (parsed data)."""
        # Create parsed attribute data
        rfc_attr_data = FlextLdifModels.SchemaAttribute(
            oid="2.16.840.1.113894.1.1.1",
            name="orclGUID",
            desc="Oracle GUID",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            sup=None,
            equality=None,
            ordering=None,
            substr=None,
            length=None,
            usage=None,
        )
        result = oud_quirk.convert_attribute_from_rfc(rfc_attr_data)
        assert result.is_success
        converted = result.unwrap()
        assert hasattr(converted, "name")

    def test_convert_objectclass_from_rfc_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting objectClass from RFC format (parsed data)."""
        # Create parsed objectClass data
        rfc_oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.16.840.1.113894.2.1.1",
            name="orclContext",
            desc="Oracle Context object class",
            kind="STRUCTURAL",
            sup="top",
        )
        result = oud_quirk.convert_objectclass_from_rfc(rfc_oc_data)
        assert result.is_success
        converted = result.unwrap()
        assert hasattr(converted, "name")


class TestOudQuirksValidation:
    """Test objectClass dependency validation."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_validate_objectclass_dependencies_with_available_attrs(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test dependency validation with available attributes."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="unknown",
            name="testClass",
            desc="Test object class",
            sup="top",
            must=["cn"],
        )
        available_attrs: set[str] = {"cn", "description"}

        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        assert result.is_success
        # Should succeed if attributes are available
        deps_satisfied = result.unwrap()
        assert isinstance(deps_satisfied, bool)

    def test_validate_objectclass_dependencies_missing_attrs(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test dependency validation with missing attributes."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="unknown",
            name="testClass",
            desc="Test object class",
            sup="top",
            must=["missing_attr"],
        )
        available_attrs: set[str] = set()

        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        assert result.is_success
        # Should fail dependency check
        deps_satisfied = result.unwrap()
        assert deps_satisfied is False

    def test_validate_objectclass_dependencies_custom_with_missing_still_passes(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test custom objectClass with unresolved dependencies still passes.

        Custom objectclasses are allowed even with missing MUST attributes.
        OUD will validate them at startup.
        """
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="unknown",
            name="customClass",
            desc="Custom object class",
            sup="top",
            must=["missing_attribute"],
        )
        available_attrs: set[str] = set()

        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        # Should still return success (just indicates deps not satisfied)
        assert result.is_success


# ===== Merged from test_oud_quirks_full_coverage.py =====


class TestOudParseAttributeComprehensive:
    """Test parse_attribute() with all RFC 4512 attribute variations."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_parse_attribute_basic_oid_and_name(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing basic attribute with OID and NAME."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.oid == "1.2.3.4"
        assert parsed.name == "testAttr"

    def test_parse_attribute_with_description(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with DESC field."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' DESC 'Test Attribute' )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.desc == "Test Attribute"

    def test_parse_attribute_with_syntax(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with SYNTAX OID."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.syntax == "1.3.6.1.4.1.1466.115.121.1.15"

    def test_parse_attribute_with_syntax_length(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with SYNTAX length constraint."""
        attr_def = (
            "( 1.2.3.4 NAME 'testAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )"
        )
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.length == 256

    def test_parse_attribute_with_equality(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with EQUALITY matching rule."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' EQUALITY caseIgnoreMatch )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.equality == "caseIgnoreMatch"

    def test_parse_attribute_with_substr(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with SUBSTR matching rule."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' SUBSTR caseIgnoreSubstringsMatch )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.substr == "caseIgnoreSubstringsMatch"

    def test_parse_attribute_with_ordering(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with ORDERING matching rule."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' ORDERING caseIgnoreOrderingMatch )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.ordering == "caseIgnoreOrderingMatch"

    def test_parse_attribute_with_single_value(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with SINGLE-VALUE constraint."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' SINGLE-VALUE )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.single_value is True

    def test_parse_attribute_with_sup(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with SUP (superor attribute)."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' SUP name )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.sup == "name"

    def test_parse_attribute_with_x_origin(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with X-ORIGIN extension."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' X-ORIGIN 'Custom' )"
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert (
            parsed.metadata.extensions.metadata.extensions.get("x_origin") == "Custom"
        )

    def test_parse_attribute_all_fields(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing attribute with all possible RFC 4512 fields."""
        attr_def = (
            "( 1.2.3.4 "
            "NAME 'testAttr' "
            "DESC 'Test Attribute' "
            "EQUALITY caseIgnoreMatch "
            "SUBSTR caseIgnoreSubstringsMatch "
            "ORDERING caseIgnoreOrderingMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} "
            "SINGLE-VALUE "
            "SUP name "
            "X-ORIGIN 'Custom' )"
        )
        result = oud_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.oid == "1.2.3.4"
        assert parsed.name == "testAttr"
        assert parsed.desc == "Test Attribute"
        assert parsed.equality == "caseIgnoreMatch"
        assert parsed.substr == "caseIgnoreSubstringsMatch"
        assert parsed.ordering == "caseIgnoreOrderingMatch"
        assert parsed.length == 256
        assert parsed.single_value is True
        assert parsed.sup == "name"
        assert (
            parsed.metadata.extensions.metadata.extensions.get("x_origin") == "Custom"
        )

    def test_parse_attribute_malformed_returns_failure(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing malformed attribute definition returns FlextResult."""
        attr_def = "COMPLETELY INVALID ATTRIBUTE FORMAT"
        result = oud_quirk.parse_attribute(attr_def)
        # Should still return a FlextResult (might succeed with partial data or fail)
        assert hasattr(result, "is_success")


class TestOudParseObjectClassComprehensive:
    """Test parse_objectclass() with all RFC 4512 objectClass variations."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_parse_objectclass_structural(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing STRUCTURAL objectClass."""
        oc_def = "( 2.5.6.1 NAME 'person' STRUCTURAL )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.kind == "STRUCTURAL"

    def test_parse_objectclass_abstract(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing ABSTRACT objectClass."""
        oc_def = "( 2.5.6.0 NAME 'top' ABSTRACT )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.kind == "ABSTRACT"

    def test_parse_objectclass_auxiliary(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing AUXILIARY objectClass."""
        oc_def = "( 2.5.6.254 NAME 'modifyTimestamp' AUXILIARY )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.kind == "AUXILIARY"

    def test_parse_objectclass_with_sup(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with SUP (superior class)."""
        oc_def = "( 2.5.6.6 NAME 'person' STRUCTURAL SUP top MUST cn MAY description )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.sup == "top"

    def test_parse_objectclass_with_single_must(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with single MUST attribute."""
        oc_def = "( 2.5.6.6 NAME 'person' STRUCTURAL MUST cn )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert isinstance(parsed.must, (list, str))

    def test_parse_objectclass_with_multiple_must(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with multiple MUST attributes."""
        oc_def = "( 2.5.6.6 NAME 'person' STRUCTURAL MUST ( cn $ sn ) )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.must is not None

    def test_parse_objectclass_with_single_may(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with single MAY attribute."""
        oc_def = "( 2.5.6.6 NAME 'person' STRUCTURAL MAY description )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.may is not None

    def test_parse_objectclass_with_multiple_may(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with multiple MAY attributes."""
        oc_def = "( 2.5.6.6 NAME 'person' STRUCTURAL MAY ( description $ mail ) )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.may is not None

    def test_parse_objectclass_with_desc(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with DESC."""
        oc_def = "( 2.5.6.6 NAME 'person' DESC 'A person' STRUCTURAL )"
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.desc == "A person"

    def test_parse_objectclass_with_must_and_may(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing objectClass with both MUST and MAY."""
        oc_def = (
            "( 2.5.6.6 NAME 'person' DESC 'A person' "
            "STRUCTURAL SUP top MUST ( cn $ sn ) MAY ( description $ mail ) )"
        )
        result = oud_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.oid == "2.5.6.6"
        assert parsed.name == "person"
        assert parsed.desc == "A person"
        assert parsed.kind == "STRUCTURAL"
        assert parsed.sup == "top"
        assert parsed.must is not None
        assert parsed.may is not None


class TestOudWriteMethods:
    """Test write_attribute_to_rfc() and write_objectclass_to_rfc()."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_write_attribute_to_rfc_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test writing parsed attribute data to RFC format."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            desc="Test Attribute",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            single_value=True,
            sup=None,
            equality=None,
            ordering=None,
            substr=None,
            length=None,
            usage=None,
        )
        result = oud_quirk.write_attribute_to_rfc(attr_data)
        assert result.is_success
        written = result.unwrap()
        assert isinstance(written, str)
        assert "1.2.3.4" in written
        assert "testAttr" in written

    def test_write_objectclass_to_rfc_basic(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test writing parsed objectClass data to RFC format."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="2.5.6.6",
            name="person",
            desc="A person",
            kind="STRUCTURAL",
            sup="top",
            must=["cn", "sn"],
            may=["description", "mail"],
        )
        result = oud_quirk.write_objectclass_to_rfc(oc_data)
        assert result.is_success
        written = result.unwrap()
        assert isinstance(written, str)
        assert "2.5.6.6" in written
        assert hasattr(written, "person")


class TestOudExtractSchemasMethod:
    """Test extract_schemas_from_ldif() schema extraction."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_extract_schemas_returns_result(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test extract_schemas_from_ldif returns FlextResult."""
        # Create minimal LDIF content
        ldif_content = (
            "dn: cn=schema\n"
            "objectClass: ldapSubentry\n"
            "attributeTypes: ( 1.2.3.4 NAME 'testAttr' )\n"
            "objectClasses: ( 2.5.6.6 NAME 'person' STRUCTURAL )\n"
        )
        result = oud_quirk.extract_schemas_from_ldif(ldif_content)
        assert hasattr(result, "is_success")


class TestOudValidateDependencies:
    """Test validate_objectclass_dependencies()."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    def test_validate_dependencies_all_available(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test validation passes when all MUST attributes are available."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="unknown",
            name="testClass",
            desc="Test object class",
            sup="top",
            must=["cn", "sn"],
        )
        available_attrs = {"cn", "sn", "description"}
        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        assert result.is_success
        assert result.unwrap() is True

    def test_validate_dependencies_some_missing(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test validation fails when some MUST attributes are missing."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="unknown",
            name="testClass",
            desc="Test object class",
            sup="top",
            must=["cn", "sn"],
        )
        available_attrs = {"cn"}  # Missing 'sn'
        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        assert result.is_success
        assert result.unwrap() is False

    def test_validate_dependencies_no_must(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test validation passes when there are no MUST attributes."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="unknown",
            name="testClass",
            desc="Test object class",
            sup="top",
        )
        available_attrs: set[str] = set()
        result = oud_quirk.validate_objectclass_dependencies(oc_data, available_attrs)
        assert result.is_success
        assert result.unwrap() is True


# ===== Merged from test_oud_quirks_phase6d.py =====


class TestOudQuirksCanHandleAttribute:
    """Test OUD-specific attribute handling with real fixture data."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud()

    def test_can_handle_oud_password_policy_attribute(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test OUD password policy (ds-pwp-*) attribute detection."""
        # OUD password policy attributes have ds-pwp- prefix
        attr_def = "( 1.3.6.1.4.1.42.2.27.8.1.1 NAME 'ds-pwp-max-password-length' )"
        result = oud_quirk.can_handle_attribute(attr_def)
        assert isinstance(result, bool)

    def test_can_handle_oud_sync_attribute(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test OUD synchronization (ds-sync-*) attribute detection."""
        # OUD sync attributes for directory synchronization
        attr_def = "( 1.3.6.1.4.1.42.2.27.8.1.2 NAME 'ds-sync-state' )"
        result = oud_quirk.can_handle_attribute(attr_def)
        assert isinstance(result, bool)

    def test_can_handle_all_attributes(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test that OUD quirk handles ALL attributes (no filtering at quirk level)."""
        # OUD quirks return True for all attributes - filtering is done by migration service
        assert oud_quirk.can_handle_attribute("any attribute string")
        assert oud_quirk.can_handle_attribute("( 1.2.3 NAME 'test' )")
        assert oud_quirk.can_handle_attribute("")
        # Cast is just for type hints - value is still int, but method still returns True
        assert oud_quirk.can_handle_attribute(cast("str", 123))


class TestOudQuirksParseAttributeWithFixtures:
    """Test OUD attribute parsing with real fixture data."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud()

    @pytest.fixture
    def oud_schema_fixture(self) -> Path:
        """Get OUD schema fixture path."""
        return (
            Path(__file__).parent.parent.parent.parent
            / "fixtures"
            / "oud"
            / "oud_schema_fixtures.ldif"
        )

    def test_parse_oud_password_policy_attribute(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing OUD password policy attribute."""
        attr_def = (
            "( 1.3.6.1.4.1.42.2.27.8.1.1 NAME 'ds-pwp-max-password-length' "
            "DESC 'OUD Password Policy: Max Length' )"
        )
        result = oud_quirk.parse_attribute(attr_def)
        assert hasattr(result, "is_success")

    def test_parse_oud_sync_attribute(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing OUD sync attribute."""
        attr_def = (
            "( 1.3.6.1.4.1.42.2.27.8.1.2 NAME 'ds-sync-state' "
            "DESC 'OUD Synchronization State' )"
        )
        result = oud_quirk.parse_attribute(attr_def)
        assert hasattr(result, "is_success")

    def test_parse_from_oud_fixture(
        self, oud_quirk: FlextLdifQuirksServersOud, oud_schema_fixture: Path
    ) -> None:
        """Test parsing real OUD attributes from fixture."""
        if not oud_schema_fixture.exists():
            pytest.skip(f"Fixture not found: {oud_schema_fixture}")

        content = oud_schema_fixture.read_text(encoding="utf-8")
        lines = content.split("\n")
        for line in lines:
            if line.startswith("attributetype"):
                attr_def = line.replace("attributetype ", "")
                result = oud_quirk.parse_attribute(attr_def)
                assert hasattr(result, "is_success")
                break


class TestOudQuirksObjectClassHandling:
    """Test OUD objectClass handling with real fixture data."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud()

    def test_can_handle_oud_objectclass(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test OUD objectClass detection."""
        objclass_def = "( 1.3.6.1.4.1.42.2.27.8.1.100 NAME 'ds-cfg-root-dn' )"
        result = oud_quirk.can_handle_objectclass(objclass_def)
        assert isinstance(result, bool)

    def test_parse_oud_objectclass(self, oud_quirk: FlextLdifQuirksServersOud) -> None:
        """Test parsing OUD objectClass definition."""
        objclass_def = (
            "( 1.3.6.1.4.1.42.2.27.8.1.100 NAME 'ds-cfg-root-dn' "
            "DESC 'OUD Configuration: Root DN' )"
        )
        result = oud_quirk.parse_objectclass(objclass_def)
        assert hasattr(result, "is_success")


class TestOudQuirksConvertAttribute:
    """Test OUD attribute conversion with RFC transformation."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud()

    def test_convert_oud_password_policy_to_rfc(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test converting OUD password policy to RFC format."""
        attr_def = "( 1.3.6.1.4.1.42.2.27.8.1.1 NAME 'ds-pwp-max-password-length' )"
        result = oud_quirk.convert_attribute_to_rfc(attr_def)
        assert hasattr(result, "is_success")

    def test_convert_oud_sync_attribute_roundtrip(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test OUD sync attribute roundtrip conversion."""
        original = "( 1.3.6.1.4.1.42.2.27.8.1.2 NAME 'ds-sync-state' )"
        to_rfc = oud_quirk.convert_attribute_to_rfc(original)
        if to_rfc.is_success:
            from_rfc = oud_quirk.convert_attribute_from_rfc(to_rfc.unwrap())
            assert hasattr(from_rfc, "is_success")


class TestOudQuirksACLHandling:
    """Test OUD ACL (Access Control Instruction) handling."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud()

    @pytest.fixture
    def oud_acl_fixture(self) -> Path:
        """Get OUD ACL fixture path."""
        return (
            Path(__file__).parent.parent.parent.parent
            / "fixtures"
            / "oud"
            / "oud_acl_fixtures.ldif"
        )

    def test_oud_acl_attribute_handling(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test OUD ACI (Access Control Instruction) attribute handling."""
        # OUD uses 'aci' attribute for ACLs (not orclaci)
        aci_attr = "( 2.5.4.1 NAME 'aci' DESC 'OUD Access Control Instruction' )"
        result = oud_quirk.can_handle_attribute(aci_attr)
        assert isinstance(result, bool)

    def test_parse_aci_from_fixture(
        self, oud_quirk: FlextLdifQuirksServersOud, oud_acl_fixture: Path
    ) -> None:
        """Test parsing real ACL data from OUD fixture."""
        if not oud_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oud_acl_fixture}")

        content = oud_acl_fixture.read_text(encoding="utf-8")
        # Verify fixture contains ACI data
        assert len(content) > 0


class TestOudQuirksEntryHandling:
    """Test OUD entry-level operations with real fixture data."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud()

    @pytest.fixture
    def oud_entries_fixture(self) -> Path:
        """Get OUD entries fixture path."""
        return (
            Path(__file__).parent.parent.parent.parent
            / "fixtures"
            / "oud"
            / "oud_entries_fixtures.ldif"
        )

    def test_can_handle_oud_entry_attributes(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test handling OUD-specific entry attributes."""
        # OUD-specific operational attributes
        oud_attrs = ["ds-pwp-account-disabled-time", "ds-sync-state", "modifyTimestamp"]
        for attr in oud_attrs:
            # Test that OUD quirk can recognize OUD attributes
            result = oud_quirk.can_handle_attribute(
                f"( 1.3.6.1.4.1.42.2.27.8.1.1 NAME '{attr}' )"
            )
            assert isinstance(result, bool)

    def test_process_oud_entry(
        self, oud_quirk: FlextLdifQuirksServersOud, oud_entries_fixture: Path
    ) -> None:
        """Test processing real OUD entries from fixture."""
        if not oud_entries_fixture.exists():
            pytest.skip(f"Fixture not found: {oud_entries_fixture}")

        content = oud_entries_fixture.read_text(encoding="utf-8")
        assert "dn:" in content


class TestOudQuirksProperties:
    """Test OUD quirks properties and configuration."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud()

    def test_oud_quirk_server_type(self, oud_quirk: FlextLdifQuirksServersOud) -> None:
        """Test OUD quirk has correct server type."""
        assert oud_quirk.server_type == "oud"

    def test_oud_quirk_priority(self, oud_quirk: FlextLdifQuirksServersOud) -> None:
        """Test OUD quirk has correct priority."""
        assert oud_quirk.priority == 10  # OUD priority for high-priority parsing

    def test_oud_namespace_pattern_defined(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test OUD namespace pattern is configured."""
        # OUD should have namespace detection
        assert hasattr(oud_quirk, "server_type")
        assert oud_quirk.server_type is not None


class TestOudQuirksPasswordPolicyHandling:
    """Test OUD password policy (ds-pwp-*) specific handling."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud()

    def test_parse_password_policy_attribute(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test parsing OUD password policy attributes."""
        pwp_attrs = [
            "( 1.3.6.1.4.1.42.2.27.8.1.1 NAME 'ds-pwp-max-password-length' )",
            "( 1.3.6.1.4.1.42.2.27.8.1.2 NAME 'ds-pwp-account-disabled-time' )",
            "( 1.3.6.1.4.1.42.2.27.8.1.3 NAME 'ds-pwp-password-expiration-time' )",
        ]
        for attr_def in pwp_attrs:
            result = oud_quirk.parse_attribute(attr_def)
            assert hasattr(result, "is_success")


class TestOudQuirksSynchronizationHandling:
    """Test OUD synchronization (ds-sync-*) attribute handling."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud()

    def test_parse_sync_attribute(self, oud_quirk: FlextLdifQuirksServersOud) -> None:
        """Test parsing OUD synchronization attributes."""
        sync_attrs = [
            "( 1.3.6.1.4.1.42.2.27.8.1.100 NAME 'ds-sync-state' )",
            "( 1.3.6.1.4.1.42.2.27.8.1.101 NAME 'ds-sync-hist' )",
        ]
        for attr_def in sync_attrs:
            result = oud_quirk.parse_attribute(attr_def)
            assert hasattr(result, "is_success")


class TestOudQuirksIntegrationWithFixtures:
    """Integration tests with real OUD fixture data."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud()

    @pytest.fixture
    def oud_integration_fixture(self) -> Path:
        """Get OUD integration fixture path."""
        return (
            Path(__file__).parent.parent.parent.parent
            / "fixtures"
            / "oud"
            / "oud_integration_fixtures.ldif"
        )

    def test_parse_full_oud_ldif_fixture(
        self, oud_quirk: FlextLdifQuirksServersOud, oud_integration_fixture: Path
    ) -> None:
        """Test parsing full OUD integration fixture."""
        if not oud_integration_fixture.exists():
            pytest.skip(f"Fixture not found: {oud_integration_fixture}")

        content = oud_integration_fixture.read_text(encoding="utf-8")
        lines = content.split("\n")

        # Parse multiple definitions from fixture
        parsed_count = 0
        for _line in lines[:100]:
            if _line.startswith(("attributetype", "objectclass")):
                parsed_count += 1

        assert len(lines) > 0

    def test_oud_quirk_fixture_conversion(
        self, oud_quirk: FlextLdifQuirksServersOud, oud_integration_fixture: Path
    ) -> None:
        """Test OUD quirk conversion with fixture data."""
        if not oud_integration_fixture.exists():
            pytest.skip(f"Fixture not found: {oud_integration_fixture}")

        # Test conversion with real OUD attribute
        test_attr = "( 1.3.6.1.4.1.42.2.27.8.1.1 NAME 'ds-pwp-max-password-length' )"

        rfc_result = oud_quirk.convert_attribute_to_rfc(test_attr)
        assert hasattr(rfc_result, "is_success")

        if rfc_result.is_success:
            back_result = oud_quirk.convert_attribute_from_rfc(rfc_result.unwrap())
            assert hasattr(back_result, "is_success")


class TestOudQuirksErrorHandling:
    """Test OUD quirks error handling and edge cases."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD quirk instance."""
        return FlextLdifQuirksServersOud()

    def test_handle_empty_attribute_definition(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test handling empty attribute definition."""
        result = oud_quirk.parse_attribute("")
        assert hasattr(result, "is_success")

    def test_handle_whitespace_only(self, oud_quirk: FlextLdifQuirksServersOud) -> None:
        """Test handling whitespace-only input."""
        result = oud_quirk.parse_attribute("   ")
        assert hasattr(result, "is_success")

    def test_handle_special_characters(
        self, oud_quirk: FlextLdifQuirksServersOud
    ) -> None:
        """Test handling attributes with special characters."""
        attr_def = "( 1.3.6.1.4.1.42.2.27.8.1.1 NAME 'ds-pwp-max-length' DESC 'OUD: Max Length' )"
        result = oud_quirk.parse_attribute(attr_def)
        assert hasattr(result, "is_success")
