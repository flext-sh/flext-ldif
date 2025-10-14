"""Tests for operational attributes stripping in entry quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.entry_quirks import FlextLdifEntryQuirks
from flext_ldif.quirks.manager import FlextLdifQuirksManager


class TestOperationalAttributesStripping:
    """Test operational attributes stripping functionality."""

    def _create_entry(
        self, dn_string: str, attributes: dict[str, list[str]]
    ) -> FlextLdifModels.Entry:
        """Helper to create entry with DN and attributes.

        Args:
            dn_string: DN as string
            attributes: Attributes dict

        Returns:
            Entry instance

        """
        dn_result = FlextLdifModels.DistinguishedName.create(dn_string)
        assert dn_result.is_success, f"Failed to create DN: {dn_result.error}"
        dn = dn_result.unwrap()

        # Convert attributes to LdifAttributes format manually
        # Entry.create() doesn't automatically convert dict[str, list[str]] to AttributeValues
        ldif_attributes = FlextLdifModels.LdifAttributes(
            attributes={
                name: FlextLdifModels.AttributeValues(values=values)
                for name, values in attributes.items()
            }
        )

        entry_result = FlextLdifModels.Entry.create(dn=dn, attributes=ldif_attributes)
        assert entry_result.is_success, f"Failed to create entry: {entry_result.error}"
        return entry_result.unwrap()

    def test_strip_common_operational_attrs(self) -> None:
        """Common operational attributes should be stripped."""
        quirks_manager = FlextLdifQuirksManager(server_type="oracle_oid")
        entry_quirks = FlextLdifEntryQuirks(quirks_manager=quirks_manager)

        # Create entry with operational attributes
        entry = self._create_entry(
            "cn=test,dc=client-a",
            {
                "cn": ["test"],
                "objectClass": ["person", "top"],
                "createTimestamp": ["20250113100000Z"],
                "modifyTimestamp": ["20250113100000Z"],
                "entryUUID": ["12345-67890-abcdef"],
            },
        )

        # Adapt for OUD (source server is "oracle_oid" from quirks_manager)
        result = entry_quirks.adapt_entry(entry, target_server="oracle_oud")

        assert result.is_success
        adapted = result.unwrap()

        # User attributes should be preserved
        assert adapted.has_attribute("cn")
        assert adapted.has_attribute("objectClass")

        # Operational attributes should be stripped
        assert not adapted.has_attribute("createTimestamp")
        assert not adapted.has_attribute("modifyTimestamp")
        assert not adapted.has_attribute("entryUUID")

    def test_strip_oid_specific_operational_attrs(self) -> None:
        """OID-specific operational attributes should be stripped."""
        quirks_manager = FlextLdifQuirksManager(server_type="oracle_oid")
        entry_quirks = FlextLdifEntryQuirks(quirks_manager=quirks_manager)

        entry = self._create_entry(
            "cn=test,dc=client-a",
            {
                "cn": ["test"],
                "orclGUID": ["ABC123"],
                "orclPasswordChangedTime": ["20250113"],
            },
        )

        result = entry_quirks.adapt_entry(entry, target_server="oracle_oud")

        assert result.is_success
        adapted = result.unwrap()

        # User attributes preserved
        assert adapted.has_attribute("cn")

        # OID operational attributes stripped
        assert not adapted.has_attribute("orclGUID")
        assert not adapted.has_attribute("orclPasswordChangedTime")

    def test_preserve_user_attributes(self) -> None:
        """User attributes should never be stripped."""
        quirks_manager = FlextLdifQuirksManager(server_type="oracle_oid")
        entry_quirks = FlextLdifEntryQuirks(quirks_manager=quirks_manager)

        # Entry with only user attributes (no operational)
        entry = self._create_entry(
            "cn=user,ou=Users,dc=client-a",
            {
                "cn": ["user"],
                "sn": ["User"],
                "mail": ["user@client-a.com"],
                "uid": ["user123"],
                "userPassword": ["{SSHA}abcdef"],
                "objectClass": ["inetOrgPerson", "person", "top"],
            },
        )

        result = entry_quirks.adapt_entry(entry, target_server="oracle_oud")

        assert result.is_success
        adapted = result.unwrap()

        # ALL user attributes should be preserved
        assert adapted.has_attribute("cn")
        assert adapted.has_attribute("sn")
        assert adapted.has_attribute("mail")
        assert adapted.has_attribute("uid")
        assert adapted.has_attribute("userPassword")
        assert adapted.has_attribute("objectClass")

    def test_case_insensitive_stripping(self) -> None:
        """Operational attributes should be stripped case-insensitively."""
        quirks_manager = FlextLdifQuirksManager(server_type="oracle_oid")
        entry_quirks = FlextLdifEntryQuirks(quirks_manager=quirks_manager)

        entry = self._create_entry(
            "cn=test,dc=client-a",
            {
                "cn": ["test"],
                "CreateTimestamp": ["20250113100000Z"],  # Mixed case
                "MODIFYTIMESTAMP": ["20250113100000Z"],  # Upper case
            },
        )

        result = entry_quirks.adapt_entry(entry, target_server="oracle_oud")

        assert result.is_success
        adapted = result.unwrap()

        # User attribute preserved
        assert adapted.has_attribute("cn")

        # Operational attributes stripped (case-insensitive)
        assert not adapted.has_attribute("CreateTimestamp")
        assert not adapted.has_attribute("MODIFYTIMESTAMP")

    def test_integration_with_real_ldif(self) -> None:
        """Test with realistic LDIF entry from OID export."""
        quirks_manager = FlextLdifQuirksManager(server_type="oracle_oid")
        entry_quirks = FlextLdifEntryQuirks(quirks_manager=quirks_manager)

        # Realistic OID entry
        entry = self._create_entry(
            "cn=John Doe,ou=Users,dc=ctbc",
            {
                "cn": ["John Doe"],
                "sn": ["Doe"],
                "givenName": ["John"],
                "mail": ["john.doe@ctbc.com.br"],
                "uid": ["jdoe"],
                "objectClass": [
                    "top",
                    "person",
                    "organizationalPerson",
                    "inetOrgPerson",
                ],
                # Operational attributes from OID
                "orclGUID": ["F1234567890ABCDEF"],
                "createTimestamp": ["20230601120000Z"],
                "modifyTimestamp": ["20250113100000Z"],
                "creatorsName": ["cn=orclREDACTED_LDAP_BIND_PASSWORD"],
                "modifiersName": ["cn=orclREDACTED_LDAP_BIND_PASSWORD"],
            },
        )

        result = entry_quirks.adapt_entry(entry, target_server="oracle_oud")

        assert result.is_success
        adapted = result.unwrap()

        # All user attributes preserved
        assert adapted.has_attribute("cn")
        assert adapted.has_attribute("sn")
        assert adapted.has_attribute("givenName")
        assert adapted.has_attribute("mail")
        assert adapted.has_attribute("uid")
        assert adapted.has_attribute("objectClass")

        # All operational attributes stripped
        assert not adapted.has_attribute("orclGUID")
        assert not adapted.has_attribute("createTimestamp")
        assert not adapted.has_attribute("modifyTimestamp")
        assert not adapted.has_attribute("creatorsName")
        assert not adapted.has_attribute("modifiersName")

    def test_strip_oud_specific_operational_attrs(self) -> None:
        """OUD-specific operational attributes should be stripped."""
        quirks_manager = FlextLdifQuirksManager(server_type="oracle_oud")
        entry_quirks = FlextLdifEntryQuirks(quirks_manager=quirks_manager)

        entry = self._create_entry(
            "cn=test,dc=client-a",
            {
                "cn": ["test"],
                "ds-sync-hist": ["sync-data"],
                "ds-sync-state": ["active"],
                "ds-pwp-account-disabled": ["false"],
            },
        )

        result = entry_quirks.adapt_entry(entry, target_server="openldap")

        assert result.is_success
        adapted = result.unwrap()

        # User attribute preserved
        assert adapted.has_attribute("cn")

        # OUD operational attributes stripped
        assert not adapted.has_attribute("ds-sync-hist")
        assert not adapted.has_attribute("ds-sync-state")
        assert not adapted.has_attribute("ds-pwp-account-disabled")

    def test_strip_openldap_specific_operational_attrs(self) -> None:
        """OpenLDAP-specific operational attributes should be stripped."""
        quirks_manager = FlextLdifQuirksManager(server_type="openldap")
        entry_quirks = FlextLdifEntryQuirks(quirks_manager=quirks_manager)

        entry = self._create_entry(
            "cn=test,dc=client-a",
            {
                "cn": ["test"],
                "structuralObjectClass": ["person"],
                "contextCSN": ["20250113100000.000000Z#000000#000#000000"],
                "entryCSN": ["20250113100000.000000Z#000000#000#000000"],
            },
        )

        result = entry_quirks.adapt_entry(entry, target_server="oracle_oud")

        assert result.is_success
        adapted = result.unwrap()

        # User attribute preserved
        assert adapted.has_attribute("cn")

        # OpenLDAP operational attributes stripped
        assert not adapted.has_attribute("structuralObjectClass")
        assert not adapted.has_attribute("contextCSN")
        assert not adapted.has_attribute("entryCSN")

    def test_strip_ad_specific_operational_attrs(self) -> None:
        """Active Directory-specific operational attributes should be stripped."""
        quirks_manager = FlextLdifQuirksManager(server_type="active_directory")
        entry_quirks = FlextLdifEntryQuirks(quirks_manager=quirks_manager)

        entry = self._create_entry(
            "cn=test,dc=client-a",
            {
                "cn": ["test"],
                "objectGUID": ["guid-12345"],
                "objectSid": ["S-1-5-21-..."],
                "whenCreated": ["20250113100000.0Z"],
                "whenChanged": ["20250113100000.0Z"],
                "uSNCreated": ["12345"],
                "uSNChanged": ["12346"],
            },
        )

        result = entry_quirks.adapt_entry(entry, target_server="oracle_oud")

        assert result.is_success
        adapted = result.unwrap()

        # User attribute preserved
        assert adapted.has_attribute("cn")

        # AD operational attributes stripped
        assert not adapted.has_attribute("objectGUID")
        assert not adapted.has_attribute("objectSid")
        assert not adapted.has_attribute("whenCreated")
        assert not adapted.has_attribute("whenChanged")
        assert not adapted.has_attribute("uSNCreated")
        assert not adapted.has_attribute("uSNChanged")

    def test_no_source_server_defaults_to_generic(self) -> None:
        """Entry with generic source_server should strip COMMON only."""
        quirks_manager = FlextLdifQuirksManager(server_type="generic")
        entry_quirks = FlextLdifEntryQuirks(quirks_manager=quirks_manager)

        entry = self._create_entry(
            "cn=test,dc=client-a",
            {
                "cn": ["test"],
                "createTimestamp": ["20250113100000Z"],  # COMMON
                "orclGUID": ["ABC123"],  # OID-specific - should NOT be stripped
            },
        )
        # Don't set source_server - defaults to "generic"

        result = entry_quirks.adapt_entry(entry, target_server="oracle_oud")

        assert result.is_success
        adapted = result.unwrap()

        # User attribute preserved
        assert adapted.has_attribute("cn")

        # COMMON operational attribute stripped
        assert not adapted.has_attribute("createTimestamp")

        # OID-specific NOT stripped (no source_server = generic)
        assert adapted.has_attribute("orclGUID")

    def test_mixed_operational_and_user_attributes(self) -> None:
        """Mix of operational and user attributes should filter correctly."""
        quirks_manager = FlextLdifQuirksManager(server_type="oracle_oid")
        entry_quirks = FlextLdifEntryQuirks(quirks_manager=quirks_manager)

        entry = self._create_entry(
            "cn=mixed,dc=client-a",
            {
                # User attributes
                "cn": ["mixed"],
                "sn": ["Test"],
                "mail": ["test@client-a.com"],
                "objectClass": ["inetOrgPerson", "person", "top"],
                # COMMON operational
                "createTimestamp": ["20250113100000Z"],
                "modifyTimestamp": ["20250113100000Z"],
                # OID operational
                "orclGUID": ["GUID123"],
                # More user attributes
                "telephoneNumber": ["+55 11 1234-5678"],
                "title": ["Engineer"],
                # More operational
                "creatorsName": ["cn=REDACTED_LDAP_BIND_PASSWORD"],
                "entryUUID": ["uuid-12345"],
            },
        )

        result = entry_quirks.adapt_entry(entry, target_server="oracle_oud")

        assert result.is_success
        adapted = result.unwrap()

        # All user attributes preserved
        assert adapted.has_attribute("cn")
        assert adapted.has_attribute("sn")
        assert adapted.has_attribute("mail")
        assert adapted.has_attribute("objectClass")
        assert adapted.has_attribute("telephoneNumber")
        assert adapted.has_attribute("title")

        # All operational attributes stripped
        assert not adapted.has_attribute("createTimestamp")
        assert not adapted.has_attribute("modifyTimestamp")
        assert not adapted.has_attribute("orclGUID")
        assert not adapted.has_attribute("creatorsName")
        assert not adapted.has_attribute("entryUUID")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
