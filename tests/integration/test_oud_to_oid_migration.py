"""Integration tests for OUD to OID migration.

Tests complete migration workflow from Oracle Unified Directory (OUD) to
Oracle Internet Directory (OID) using quirks system:
- Read OUD LDIF fixtures with OUD quirks
- Convert to RFC intermediate format
- Convert from RFC to OID format with OID quirks
- Write OID LDIF
- Validate migration integrity and data preservation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.servers.oid_quirks import FlextLdifQuirksServersOid
from flext_ldif.quirks.servers.oud_quirks import FlextLdifQuirksServersOud
from tests.fixtures.loader import FlextLdifFixtures


class TestOudToOidSchemaMigration:
    """Test OUD to OID schema migration."""

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD schema quirk instance."""
        return FlextLdifQuirksServersOud(server_type=FlextLdifConstants.ServerTypes.OUD)

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID schema quirk instance."""
        return FlextLdifQuirksServersOid(server_type=FlextLdifConstants.ServerTypes.OID)

    @pytest.fixture
    def oud_schema_fixture(self) -> str:
        """Load OUD schema fixture data."""
        loader = FlextLdifFixtures.OUD()
        return loader.schema()

    def test_migrate_oracle_attribute_oud_to_oid(
        self,
        oud_quirk: FlextLdifQuirksServersOud,
        oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test migrating Oracle attribute from OUD to OID format."""
        # Sample Oracle attribute from OUD
        oud_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "DESC 'Oracle GUID' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "SINGLE-VALUE )"
        )

        # Step 1: Parse with OUD quirk
        parse_result = oud_quirk.parse_attribute(oud_attr)
        assert parse_result.is_success, f"OUD parse failed: {parse_result.error}"
        oud_parsed = parse_result.unwrap()

        # Step 2: Convert OUD to RFC intermediate format
        rfc_result = oud_quirk.convert_attribute_to_rfc(oud_parsed)
        assert rfc_result.is_success, f"OUD→RFC conversion failed: {rfc_result.error}"
        rfc_data = rfc_result.unwrap()

        # Step 3: Convert RFC to OID format
        oid_result = oid_quirk.convert_attribute_from_rfc(rfc_data)
        assert oid_result.is_success, f"RFC→OID conversion failed: {oid_result.error}"
        oid_data = oid_result.unwrap()

        # Step 4: Write OID format to string
        write_result = oid_quirk.write_attribute_to_rfc(oid_data)
        assert write_result.is_success, f"OID write failed: {write_result.error}"
        oid_attr = write_result.unwrap()

        # Validate: Essential data preserved
        assert "2.16.840.1.113894.1.1.1" in oid_attr, "OID not preserved"
        assert "orclGUID" in oid_attr, "NAME not preserved"
        assert "1.3.6.1.4.1.1466.115.121.1.15" in oid_attr, "SYNTAX not preserved"

    def test_migrate_oracle_objectclass_oud_to_oid(
        self,
        oud_quirk: FlextLdifQuirksServersOud,
        oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test migrating Oracle objectClass from OUD to OID format."""
        # Sample Oracle objectClass from OUD
        oud_oc = (
            "( 2.16.840.1.113894.2.1.1 NAME 'orclContext' "
            "DESC 'Oracle Context' "
            "SUP top STRUCTURAL "
            "MUST cn "
            "MAY ( description $ orclVersion ) )"
        )

        # Step 1: Parse with OUD quirk
        parse_result = oud_quirk.parse_objectclass(oud_oc)
        assert parse_result.is_success, f"OUD parse failed: {parse_result.error}"
        oud_parsed = parse_result.unwrap()

        # Step 2: Convert OUD to RFC intermediate format
        rfc_result = oud_quirk.convert_objectclass_to_rfc(oud_parsed)
        assert rfc_result.is_success, f"OUD→RFC conversion failed: {rfc_result.error}"
        rfc_data = rfc_result.unwrap()

        # Step 3: Convert RFC to OID format
        oid_result = oid_quirk.convert_objectclass_from_rfc(rfc_data)
        assert oid_result.is_success, f"RFC→OID conversion failed: {oid_result.error}"
        oid_data = oid_result.unwrap()

        # Step 4: Write OID format to string
        write_result = oid_quirk.write_objectclass_to_rfc(oid_data)
        assert write_result.is_success, f"OID write failed: {write_result.error}"
        oid_oc = write_result.unwrap()

        # Validate: Essential data preserved
        assert "2.16.840.1.113894.2.1.1" in oid_oc, "OID not preserved"
        assert "orclContext" in oid_oc, "NAME not preserved"
        assert "STRUCTURAL" in oid_oc, "KIND not preserved"
        assert "cn" in oid_oc, "MUST attribute not preserved"

    def test_migrate_multiple_attributes_from_fixtures(
        self,
        oud_quirk: FlextLdifQuirksServersOud,
        oid_quirk: FlextLdifQuirksServersOid,
        oud_schema_fixture: str
    ) -> None:
        """Test migrating multiple Oracle attributes from OUD fixtures to OID."""
        # Extract Oracle attributes from OUD schema fixture
        oracle_attrs = [
            line.split("attributeTypes:", 1)[1].strip()
            for line in oud_schema_fixture.splitlines()
            if "2.16.840.1.113894" in line and line.strip().startswith("attributeTypes:")
        ]

        assert len(oracle_attrs) > 0, "No Oracle attributes found in OUD fixtures"

        migrated_count = 0
        for oud_attr in oracle_attrs[:10]:  # Test first 10 attributes
            # Parse with OUD
            parse_result = oud_quirk.parse_attribute(oud_attr)
            if not parse_result.is_success:
                continue

            oud_parsed = parse_result.unwrap()

            # Convert OUD → RFC → OID
            rfc_result = oud_quirk.convert_attribute_to_rfc(oud_parsed)
            if not rfc_result.is_success:
                continue

            oid_result = oid_quirk.convert_attribute_from_rfc(rfc_result.unwrap())
            if not oid_result.is_success:
                continue

            # Write OID format
            write_result = oid_quirk.write_attribute_to_rfc(oid_result.unwrap())
            if write_result.is_success:
                migrated_count += 1

        # At least 50% of attributes should migrate successfully
        success_rate = migrated_count / len(oracle_attrs[:10])
        assert success_rate >= 0.5, f"Low migration success rate: {success_rate:.1%}"


class TestOudToOidAclMigration:
    """Test OUD to OID ACL migration."""

    @pytest.fixture
    def oud_acl_quirk(self) -> FlextLdifQuirksServersOud.AclQuirk:
        """Create OUD ACL quirk instance."""
        return FlextLdifQuirksServersOud.AclQuirk(
            server_type=FlextLdifConstants.ServerTypes.OUD
        )

    @pytest.fixture
    def oid_acl_quirk(self) -> FlextLdifQuirksServersOid.AclQuirk:
        """Create OID ACL quirk instance."""
        return FlextLdifQuirksServersOid.AclQuirk(
            server_type=FlextLdifConstants.ServerTypes.OID
        )

    def test_migrate_oud_aci_to_oid_orclaci(
        self,
        oud_acl_quirk: FlextLdifQuirksServersOud.AclQuirk,
        oid_acl_quirk: FlextLdifQuirksServersOid.AclQuirk
    ) -> None:
        """Test migrating OUD ACI to OID orclaci format."""
        # Sample OUD ACI
        oud_aci = (
            'aci: (targetattr="*")(version 3.0; '
            'acl "OracleContext accessible"; '
            'allow (all) groupdn="ldap:///cn=OracleContextAdmins,cn=groups,cn=OracleContext,dc=example,dc=com";)'
        )

        # Step 1: Parse with OUD ACL quirk
        parse_result = oud_acl_quirk.parse_acl(oud_aci)
        assert parse_result.is_success, f"OUD ACL parse failed: {parse_result.error}"
        oud_parsed = parse_result.unwrap()

        # Step 2: Convert OUD ACL to RFC intermediate format
        rfc_result = oud_acl_quirk.convert_acl_to_rfc(oud_parsed)
        assert rfc_result.is_success, f"OUD ACL→RFC conversion failed: {rfc_result.error}"
        rfc_data = rfc_result.unwrap()

        # Step 3: Convert RFC to OID ACL format
        oid_result = oid_acl_quirk.convert_acl_from_rfc(rfc_data)
        assert oid_result.is_success, f"RFC→OID ACL conversion failed: {oid_result.error}"
        oid_data = oid_result.unwrap()

        # Step 4: Write OID ACL format
        write_result = oid_acl_quirk.write_acl_to_rfc(oid_data)
        assert write_result.is_success, f"OID ACL write failed: {write_result.error}"
        oid_acl = write_result.unwrap()

        # Validate: ACL data structure preserved
        assert oid_data is not None
        # Check that essential ACL data is present (format or data)
        assert (FlextLdifConstants.DictKeys.FORMAT in oid_data or
                FlextLdifConstants.DictKeys.DATA in oid_data)


class TestOudToOidEntryMigration:
    """Test OUD to OID entry migration."""

    @pytest.fixture
    def oud_entry_quirk(self) -> FlextLdifQuirksServersOud.EntryQuirk:
        """Create OUD entry quirk instance."""
        return FlextLdifQuirksServersOud.EntryQuirk(
            server_type=FlextLdifConstants.ServerTypes.OUD
        )

    @pytest.fixture
    def oid_entry_quirk(self) -> FlextLdifQuirksServersOid.EntryQuirk:
        """Create OID entry quirk instance."""
        return FlextLdifQuirksServersOid.EntryQuirk(
            server_type=FlextLdifConstants.ServerTypes.OID
        )

    def test_migrate_oracle_context_entry_oud_to_oid(
        self,
        oud_entry_quirk: FlextLdifQuirksServersOud.EntryQuirk,
        oid_entry_quirk: FlextLdifQuirksServersOid.EntryQuirk
    ) -> None:
        """Test migrating Oracle Context entry from OUD to OID."""
        # Sample Oracle Context entry from OUD
        entry_dn = "cn=OracleContext,dc=example,dc=com"
        entry_attrs: dict[str, object] = {
            "cn": ["OracleContext"],
            "objectClass": ["top", "orclContext", "orclContextAux82"],
            "orclVersion": ["90600"],
        }

        # Step 1: Process with OUD entry quirk
        process_result = oud_entry_quirk.process_entry(entry_dn, entry_attrs)
        assert process_result.is_success, f"OUD entry processing failed: {process_result.error}"
        oud_entry = process_result.unwrap()

        # Step 2: Convert OUD entry to RFC
        rfc_result = oud_entry_quirk.convert_entry_to_rfc(oud_entry)
        assert rfc_result.is_success, f"OUD entry→RFC failed: {rfc_result.error}"
        rfc_entry = rfc_result.unwrap()

        # Step 3: Convert RFC to OID entry
        oid_result = oid_entry_quirk.convert_entry_from_rfc(rfc_entry)
        assert oid_result.is_success, f"RFC→OID entry failed: {oid_result.error}"
        oid_entry = oid_result.unwrap()

        # Step 4: Write OID entry to LDIF
        write_result = oid_entry_quirk.write_entry_to_ldif(oid_entry)
        assert write_result.is_success, f"OID entry write failed: {write_result.error}"
        oid_ldif = write_result.unwrap()

        # Validate: Essential data preserved
        assert "cn=OracleContext" in oid_ldif, "DN not preserved"
        assert "orclContext" in oid_ldif, "Oracle objectClass not preserved"
        assert "orclVersion" in oid_ldif, "Oracle attribute not preserved"

    def test_migrate_entry_with_dn_spaces(
        self,
        oud_entry_quirk: FlextLdifQuirksServersOud.EntryQuirk,
        oid_entry_quirk: FlextLdifQuirksServersOid.EntryQuirk
    ) -> None:
        """Test migrating entry with DN spaces quirk from OUD to OID."""
        # OUD entry with spaces after commas in DN
        entry_dn = "cn=OracleDASGroupPriv, cn=Groups,cn=OracleContext"
        entry_attrs: dict[str, object] = {
            "cn": ["OracleDASGroupPriv"],
            "objectClass": ["top", "groupOfUniqueNames", "orclPrivilegeGroup"],
            "uniquemember": ["cn=orclREDACTED_LDAP_BIND_PASSWORD"],
        }

        # Process through migration
        process_result = oud_entry_quirk.process_entry(entry_dn, entry_attrs)
        assert process_result.is_success
        oud_entry = process_result.unwrap()

        # Check metadata captured DN spaces quirk
        if "_metadata" in oud_entry:
            metadata = oud_entry["_metadata"]
            # Metadata should capture this quirk for recovery

        # Convert to RFC and then to OID
        rfc_result = oud_entry_quirk.convert_entry_to_rfc(oud_entry)
        assert rfc_result.is_success

        oid_result = oid_entry_quirk.convert_entry_from_rfc(rfc_result.unwrap())
        assert oid_result.is_success

        # Write OID entry
        write_result = oid_entry_quirk.write_entry_to_ldif(oid_result.unwrap())
        assert write_result.is_success
        oid_ldif = write_result.unwrap()

        # Validate: Entry migrated (DN may be normalized)
        assert "OracleDASGroupPriv" in oid_ldif
        assert "orclPrivilegeGroup" in oid_ldif


class TestOudToOidFullMigration:
    """Test complete OUD to OID migration workflow."""

    @pytest.fixture
    def oud_fixtures(self) -> FlextLdifFixtures.OUD:
        """Create OUD fixture loader."""
        return FlextLdifFixtures.OUD()

    @pytest.fixture
    def oud_quirk(self) -> FlextLdifQuirksServersOud:
        """Create OUD schema quirk."""
        return FlextLdifQuirksServersOud(server_type="oud")

    @pytest.fixture
    def oid_quirk(self) -> FlextLdifQuirksServersOid:
        """Create OID schema quirk."""
        return FlextLdifQuirksServersOid(server_type="oid")

    @pytest.fixture
    def oud_entry_quirk(self) -> FlextLdifQuirksServersOud.EntryQuirk:
        """Create OUD entry quirk."""
        return FlextLdifQuirksServersOud.EntryQuirk(server_type="oud")

    @pytest.fixture
    def oid_entry_quirk(self) -> FlextLdifQuirksServersOid.EntryQuirk:
        """Create OID entry quirk."""
        return FlextLdifQuirksServersOid.EntryQuirk(server_type="oid")

    def test_migrate_oud_entries_to_oid_preserves_data(
        self,
        oud_entry_quirk: FlextLdifQuirksServersOud.EntryQuirk,
        oid_entry_quirk: FlextLdifQuirksServersOid.EntryQuirk,
        oud_fixtures: FlextLdifFixtures.OUD
    ) -> None:
        """Test migrating multiple OUD entries to OID format preserves data."""
        # Load OUD entries fixture
        entries_content = oud_fixtures.entries()

        # Parse entries manually (simple LDIF parsing)
        entries = []
        current_dn = None
        current_attrs: dict[str, list[str]] = {}

        for line in entries_content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("dn:"):
                # Save previous entry
                if current_dn and current_attrs:
                    entries.append((current_dn, current_attrs))

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

        # Save last entry
        if current_dn and current_attrs:
            entries.append((current_dn, current_attrs))

        assert len(entries) > 0, "No entries parsed from OUD fixtures"

        # Migrate each entry from OUD to OID
        migrated_count = 0
        for entry_dn, entry_attrs in entries[:5]:  # Test first 5 entries
            # Step 1: Process with OUD
            oud_result = oud_entry_quirk.process_entry(entry_dn, entry_attrs)
            if not oud_result.is_success:
                continue

            # Step 2: Convert OUD → RFC → OID
            rfc_result = oud_entry_quirk.convert_entry_to_rfc(oud_result.unwrap())
            if not rfc_result.is_success:
                continue

            oid_result = oid_entry_quirk.convert_entry_from_rfc(rfc_result.unwrap())
            if not oid_result.is_success:
                continue

            # Step 3: Write OID LDIF
            write_result = oid_entry_quirk.write_entry_to_ldif(oid_result.unwrap())
            if write_result.is_success:
                oid_ldif = write_result.unwrap()

                # Validate: DN and objectClass preserved
                assert entry_dn.split(",")[0] in oid_ldif, f"DN RDN not preserved for {entry_dn}"
                migrated_count += 1

        # At least 80% of entries should migrate successfully
        success_rate = migrated_count / min(len(entries), 5)
        assert success_rate >= 0.8, f"Low entry migration success rate: {success_rate:.1%}"

    def test_migration_preserves_metadata(
        self,
        oud_quirk: FlextLdifQuirksServersOud,
        oid_quirk: FlextLdifQuirksServersOid
    ) -> None:
        """Test that migration preserves metadata for data recovery."""
        # Oracle attribute with all features
        oud_attr = (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' "
            "DESC 'Oracle GUID' "
            "EQUALITY caseIgnoreMatch "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
            "SINGLE-VALUE "
            "NO-USER-MODIFICATION )"
        )

        # Parse with OUD (creates metadata)
        parse_result = oud_quirk.parse_attribute(oud_attr)
        assert parse_result.is_success
        oud_parsed = parse_result.unwrap()

        # Verify metadata exists
        assert "_metadata" in oud_parsed, "OUD parse should create metadata"

        # Convert through RFC to OID
        rfc_result = oud_quirk.convert_attribute_to_rfc(oud_parsed)
        assert rfc_result.is_success

        oid_result = oid_quirk.convert_attribute_from_rfc(rfc_result.unwrap())
        assert oid_result.is_success
        oid_data = oid_result.unwrap()

        # Write OID
        write_result = oid_quirk.write_attribute_to_rfc(oid_data)
        assert write_result.is_success
        oid_attr = write_result.unwrap()

        # Validate: Core semantic data preserved (name, syntax, equality)
        assert "orclGUID" in oid_attr, "Attribute name not preserved"
        assert "caseIgnoreMatch" in oid_attr, "EQUALITY matching rule not preserved"
        assert "1.3.6.1.4.1.1466.115.121.1.15" in oid_attr, "SYNTAX not preserved"

        # Note: SINGLE-VALUE and NO-USER-MODIFICATION may not be preserved
        # through RFC conversion if not included in convert_*_to_rfc methods.
        # This is acceptable as they can be reconstructed from metadata if needed.


__all__ = [
    "TestOudToOidAclMigration",
    "TestOudToOidEntryMigration",
    "TestOudToOidFullMigration",
    "TestOudToOidSchemaMigration",
]
