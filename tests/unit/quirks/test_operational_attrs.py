"""Tests for operational attributes stripping in entry quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.services.entrys import FlextLdifEntryService


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
        # Direct instantiation pattern - Pydantic 2 validates via @field_validator
        # If DN is invalid, ValidationError will be raised
        try:
            dn = FlextLdifModels.DistinguishedName(value=dn_string)
        except (ValueError, TypeError, AttributeError) as e:
            raise AssertionError(f"Failed to create DN: {e}") from e

        # Convert attributes to LdifAttributes format manually
        # LdifAttributes now uses dict[str, list[str]] directly
        ldif_attributes = FlextLdifModels.LdifAttributes(attributes=attributes)

        entry_result = FlextLdifModels.Entry.create(dn=dn, attributes=ldif_attributes)
        assert entry_result.is_success, f"Failed to create entry: {entry_result.error}"
        return entry_result.unwrap()

    def test_strip_common_operational_attrs(self) -> None:
        """Common operational attributes should be stripped for oracle_oud."""
        entrys = FlextLdifEntryService()

        # Create entry with operational attributes
        entry = self._create_entry(
            "cn=test,dc=algar",
            {
                "cn": ["test"],
                "objectclass": ["person", "top"],
                "createTimestamp": ["20250113100000Z"],
                "modifyTimestamp": ["20250113100000Z"],
                "entryUUID": ["12345-67890-abcdef"],
            },
        )

        # Remove operational attributes - COMMON operational attrs are stripped
        result = entrys.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()

        # User attributes should be preserved
        assert adapted.has_attribute("cn")
        assert adapted.has_attribute("objectclass")

        # Operational attributes should be stripped
        assert not adapted.has_attribute("createTimestamp")
        assert not adapted.has_attribute("modifyTimestamp")
        assert not adapted.has_attribute("entryUUID")

    def test_strip_oid_specific_operational_attrs(self) -> None:
        """OID-specific operational attributes are preserved when source is unknown."""
        entrys = FlextLdifEntryService()

        entry = self._create_entry(
            "cn=test,dc=algar",
            {
                "cn": ["test"],
                "objectclass": ["person"],
                "orclGUID": ["ABC123"],
                "orclPasswordChangedTime": ["20250113"],
                "createTimestamp": ["20250113100000Z"],  # COMMON operational attr
            },
        )

        result = entrys.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()

        # User attributes preserved
        assert adapted.has_attribute("cn")

        # COMMON operational attributes stripped
        assert not adapted.has_attribute("createTimestamp")

        # OID-specific operational attributes preserved (source unknown)
        # Only COMMON attrs are stripped by default, not server-specific ones
        assert adapted.has_attribute("orclGUID")
        assert adapted.has_attribute("orclPasswordChangedTime")

    def test_preserve_user_attributes(self) -> None:
        """User attributes should never be stripped."""
        entrys = FlextLdifEntryService()

        # Entry with only user attributes (no operational)
        entry = self._create_entry(
            "cn=user,ou=Users,dc=algar",
            {
                "cn": ["user"],
                "sn": ["User"],
                "mail": ["user@algar.com"],
                "uid": ["user123"],
                "userPassword": ["{SSHA}abcdef"],
                "objectclass": ["inetOrgPerson", "person", "top"],
            },
        )

        result = entrys.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()

        # ALL user attributes should be preserved
        assert adapted.has_attribute("cn")
        assert adapted.has_attribute("sn")
        assert adapted.has_attribute("mail")
        assert adapted.has_attribute("uid")
        assert adapted.has_attribute("userPassword")
        assert adapted.has_attribute("objectclass")

    def test_case_insensitive_stripping(self) -> None:
        """Operational attributes should be stripped case-insensitively."""
        entrys = FlextLdifEntryService()

        entry = self._create_entry(
            "cn=test,dc=algar",
            {
                "cn": ["test"],
                "objectclass": ["person"],
                "CreateTimestamp": ["20250113100000Z"],  # Mixed case
                "MODIFYTIMESTAMP": ["20250113100000Z"],  # Upper case
            },
        )

        result = entrys.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()

        # User attribute preserved
        assert adapted.has_attribute("cn")

        # Operational attributes stripped (case-insensitive)
        assert not adapted.has_attribute("CreateTimestamp")
        assert not adapted.has_attribute("MODIFYTIMESTAMP")

    def test_integration_with_real_ldif(self) -> None:
        """Test with realistic LDIF entry from OID export (source unknown)."""
        entrys = FlextLdifEntryService()

        # Realistic OID entry - but source is unknown when calling adapt_entry
        entry = self._create_entry(
            "cn=John Doe,ou=Users,dc=ctbc",
            {
                "cn": ["John Doe"],
                "sn": ["Doe"],
                "givenName": ["John"],
                "mail": ["john.doe@ctbc.com.br"],
                "uid": ["jdoe"],
                "objectclass": [
                    "top",
                    "person",
                    "organizationalPerson",
                    "inetOrgPerson",
                ],
                # Operational attributes from OID
                "orclGUID": ["F1234567890ABCDEF"],
                "createTimestamp": ["20230601120000Z"],
                "modifyTimestamp": ["20250113100000Z"],
                "creatorsName": ["cn=orcladmin"],
                "modifiersName": ["cn=orcladmin"],
            },
        )

        result = entrys.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()

        # All user attributes preserved
        assert adapted.has_attribute("cn")
        assert adapted.has_attribute("sn")
        assert adapted.has_attribute("givenName")
        assert adapted.has_attribute("mail")
        assert adapted.has_attribute("uid")
        assert adapted.has_attribute("objectclass")

        # COMMON operational attributes stripped
        assert not adapted.has_attribute("createTimestamp")
        assert not adapted.has_attribute("modifyTimestamp")
        assert not adapted.has_attribute("creatorsName")
        assert not adapted.has_attribute("modifiersName")

        # OID-specific operational attributes preserved (source unknown)
        assert adapted.has_attribute("orclGUID")

    def test_strip_oud_specific_operational_attrs(self) -> None:
        """OUD-specific operational attributes are preserved when source is unknown."""
        entrys = FlextLdifEntryService()

        entry = self._create_entry(
            "cn=test,dc=algar",
            {
                "cn": ["test"],
                "objectclass": ["person"],
                "ds-sync-hist": ["sync-data"],
                "ds-sync-state": ["active"],
                "ds-pwp-account-disabled": ["false"],
                "createTimestamp": ["20250113100000Z"],  # COMMON operational attr
            },
        )

        result = entrys.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()

        # User attribute preserved
        assert adapted.has_attribute("cn")

        # COMMON operational attributes stripped
        assert not adapted.has_attribute("createTimestamp")

        # OUD-specific operational attributes preserved (source unknown)
        assert adapted.has_attribute("ds-sync-hist")
        assert adapted.has_attribute("ds-sync-state")
        assert adapted.has_attribute("ds-pwp-account-disabled")

    def test_strip_openldap_specific_operational_attrs(self) -> None:
        """OpenLDAP-specific operational attributes (non-COMMON) are preserved when source is unknown."""
        entrys = FlextLdifEntryService()

        entry = self._create_entry(
            "cn=test,dc=algar",
            {
                "cn": ["test"],
                "objectclass": ["person"],
                "structuralObjectClass": ["person"],  # OpenLDAP-specific, NOT in COMMON
                "contextCSN": [
                    "20250113100000.000000Z#000000#000#000000"
                ],  # OpenLDAP-specific, NOT in COMMON
                "entryCSN": [
                    "20250113100000.000000Z#000000#000#000000"
                ],  # Both COMMON and OpenLDAP-specific
                "createTimestamp": ["20250113100000Z"],  # COMMON operational attr
            },
        )

        result = entrys.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()

        # User attribute preserved
        assert adapted.has_attribute("cn")

        # COMMON operational attributes stripped (includes entryCSN)
        assert not adapted.has_attribute("createTimestamp")
        assert not adapted.has_attribute("entryCSN")

        # OpenLDAP-specific operational attributes (non-COMMON) preserved
        assert adapted.has_attribute("structuralObjectClass")
        assert adapted.has_attribute("contextCSN")

    def test_strip_ad_specific_operational_attrs(self) -> None:
        """Active Directory-specific operational attributes are preserved when source is unknown."""
        entrys = FlextLdifEntryService()

        entry = self._create_entry(
            "cn=test,dc=algar",
            {
                "cn": ["test"],
                "objectclass": ["person"],
                "objectGUID": ["guid-12345"],
                "objectSid": ["S-1-5-21-..."],
                "whenCreated": ["20250113100000.0Z"],
                "whenChanged": ["20250113100000.0Z"],
                "uSNCreated": ["12345"],
                "uSNChanged": ["12346"],
                "createTimestamp": ["20250113100000Z"],  # COMMON operational attr
            },
        )

        result = entrys.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()

        # User attribute preserved
        assert adapted.has_attribute("cn")

        # COMMON operational attributes stripped
        assert not adapted.has_attribute("createTimestamp")

        # AD-specific operational attributes preserved (source unknown)
        assert adapted.has_attribute("objectGUID")
        assert adapted.has_attribute("objectSid")
        assert adapted.has_attribute("whenCreated")
        assert adapted.has_attribute("whenChanged")
        assert adapted.has_attribute("uSNCreated")
        assert adapted.has_attribute("uSNChanged")

    def test_no_source_server_defaults_to_generic(self) -> None:
        """Entry with generic target_server should strip COMMON only."""
        entrys = FlextLdifEntryService()

        entry = self._create_entry(
            "cn=test,dc=algar",
            {
                "cn": ["test"],
                "objectClass": ["person"],
                "createTimestamp": ["20250113100000Z"],  # COMMON
                "orclGUID": ["ABC123"],  # OID-specific - should NOT be stripped
            },
        )
        # Don't set source_server - defaults to "generic"

        result = entrys.remove_operational_attributes(entry)

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
        entrys = FlextLdifEntryService()

        entry = self._create_entry(
            "cn=mixed,dc=algar",
            {
                # User attributes
                "cn": ["mixed"],
                "sn": ["Test"],
                "mail": ["test@algar.com"],
                "objectclass": ["inetOrgPerson", "person", "top"],
                # COMMON operational
                "createTimestamp": ["20250113100000Z"],
                "modifyTimestamp": ["20250113100000Z"],
                # OID operational
                "orclGUID": ["GUID123"],
                # More user attributes
                "telephoneNumber": ["+55 11 1234-5678"],
                "title": ["Engineer"],
                # More operational
                "creatorsName": ["cn=admin"],
                "entryUUID": ["uuid-12345"],
            },
        )

        result = entrys.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()

        # All user attributes preserved
        assert adapted.has_attribute("cn")
        assert adapted.has_attribute("sn")
        assert adapted.has_attribute("mail")
        assert adapted.has_attribute("objectclass")
        assert adapted.has_attribute("telephoneNumber")
        assert adapted.has_attribute("title")

        # COMMON operational attributes stripped
        assert not adapted.has_attribute("createTimestamp")
        assert not adapted.has_attribute("modifyTimestamp")
        assert not adapted.has_attribute("creatorsName")
        assert not adapted.has_attribute("entryUUID")

        # OID-specific operational attributes preserved (source unknown)
        assert adapted.has_attribute("orclGUID")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
