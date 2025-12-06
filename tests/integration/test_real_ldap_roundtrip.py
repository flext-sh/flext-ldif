"""LDIF roundtrip operations with live LDAP server.

Test suite verifying LDIF operations against an actual LDAP server:
    - Parse and write LDIF from/to LDAP server
    - Validate roundtrip data integrity (LDAP → LDIF → LDAP)
    - Extract and process schema information
    - Handle ACL entries
    - Perform CRUD operations
    - Process batches of entries

Uses Docker fixture infrastructure from conftest.py for automatic
container management via FlextTestsDocker.ldap_container fixture.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from ldap3 import Connection

from flext_ldif import FlextLdif
from tests import GenericFieldsDict


# TypedDicts (GenericFieldsDict, GenericTestCaseDict, etc.) are available from conftest.py
def flext_api() -> FlextLdif:
    """FlextLdif API instance."""
    return FlextLdif.get_instance()


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestRealLdapRoundtrip:
    """Test LDAP → LDIF → LDAP data roundtrip."""

    def test_roundtrip_preserves_data(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Verify LDAP → LDIF → LDAP preserves data integrity."""
        # Create original LDAP entry with isolated username
        unique_username = make_test_username("RoundtripTest")
        original_dn = f"cn={unique_username},{clean_test_ou}"
        original_attrs: GenericFieldsDict = {
            "cn": unique_username,
            "sn": "Test",
            "mail": "roundtrip@example.com",
            "telephoneNumber": ["+1-555-1111", "+1-555-2222"],
            "description": "Multi-line\ndescription\ntest",
        }

        ldap_connection.add(
            original_dn,
            ["person", "inetOrgPerson"],
            original_attrs,
        )

        # Export to LDIF
        ldap_connection.search(original_dn, "(objectClass=*)", attributes=["*"])
        ldap_entry = ldap_connection.entries[0]

        # Convert ldap3 entry attributes to dict format
        attrs_dict = {}
        for attr_name in ldap_entry.entry_attributes:
            attr_obj = ldap_entry[attr_name]
            # Extract values from ldap3 Attribute object
            if hasattr(attr_obj, "values"):
                # ldap3 Attribute object with .values property
                values = [str(v) if not isinstance(v, str) else v for v in attr_obj]
            elif isinstance(attr_obj, list):
                # Already a list
                values = [str(v) for v in attr_obj]
            else:
                # Single value
                values = [str(attr_obj)]
            attrs_dict[attr_name] = values

        entry_result = flext_api.models.Entry.create(
            dn=ldap_entry.entry_dn,
            attributes=attrs_dict,
            metadata=None,
        )
        assert entry_result.is_success
        flext_entry = entry_result.unwrap()

        write_result = flext_api.write([flext_entry])
        assert write_result.is_success
        ldif_output = write_result.unwrap()

        # Re-import from LDIF (to different DN with isolated username)
        unique_username_copy = make_test_username("RoundtripTestCopy")
        reimport_dn = f"cn={unique_username_copy},{clean_test_ou}"
        parse_result = flext_api.parse(ldif_output)
        assert parse_result.is_success
        parsed_entries = parse_result.unwrap()
        assert len(parsed_entries) == 1

        reimport_entry = parsed_entries[0]
        # Change DN for reimport
        # Build reimport_attrs from FlextLdif entry attributes
        # Filter out LDIF-specific attributes (changetype, control, etc.)
        ldif_special_attrs = {
            "changetype",
            "control",
            "modifyTimestamp",
            "modifiersName",
        }
        reimport_attrs: dict[str, list[str]] = {
            attr_name: attr_values
            for attr_name, attr_values in reimport_entry.attributes.attributes.items()
            if attr_name.lower() not in ldif_special_attrs
            and attr_name.lower() != "objectclass"
        }
        reimport_attrs["cn"] = [unique_username_copy]

        obj_class_values = reimport_entry.get_attribute_values("objectclass")
        assert isinstance(obj_class_values, list)
        ldap_connection.add(
            reimport_dn,
            obj_class_values,
            attributes={
                attr: reimport_entry.attributes.attributes[attr]
                for attr in reimport_entry.attributes.attributes
                if attr.lower() not in ldif_special_attrs
                and attr.lower() != "objectclass"
            },
        )

        # Verify reimported entry
        assert ldap_connection.search(reimport_dn, "(objectClass=*)", attributes=["*"])
        reimported = ldap_connection.entries[0]

        # Verify attributes preserved
        assert reimported["sn"].value == original_attrs["sn"]
        assert reimported["mail"].value == original_attrs["mail"]
        assert set(reimported["telephoneNumber"].values) == set(
            original_attrs["telephoneNumber"],
        )


__all__ = ["TestRealLdapRoundtrip"]
