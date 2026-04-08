"""LDIF roundtrip operations with live LDAP server.

Test suite verifying LDIF operations against an actual LDAP server:
    - Parse and write LDIF from/to LDAP server
    - Validate roundtrip data integrity (LDAP → LDIF → LDAP)
    - Extract and process schema information
    - Handle ACL entries
    - Perform CRUD operations
    - Process batches of entries

Uses Docker fixture infrastructure from conftest.py for automatic
container management via tk.ldap_container fixture.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import (
    Callable,
)

import pytest

from flext_ldif import ldif
from tests import m, p, t, u


@pytest.fixture
def flext_api() -> ldif:
    """Ldif API instance."""
    return ldif.get_instance()


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestRealLdapRoundtrip:
    """Test LDAP → LDIF → LDAP data roundtrip."""

    def test_roundtrip_preserves_data(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: ldif,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Verify LDAP → LDIF → LDAP preserves data integrity."""
        unique_username = make_test_username("RoundtripTest")
        original_dn = f"cn={unique_username},{clean_test_ou}"
        original_attrs: t.MutableAttributeMapping = {
            "cn": unique_username,
            "sn": "Test",
            "mail": "roundtrip@example.com",
            "telephoneNumber": ["+1-555-1111", "+1-555-2222"],
            "description": "Multi-line\ndescription\ntest",
        }
        ldap_connection.add(original_dn, ["person", "inetOrgPerson"], original_attrs)
        ldap_connection.search(original_dn, "(objectClass=*)", attributes=["*"])
        ldap_entry = ldap_connection.entries[0]
        attrs_dict: t.MutableAttributeMapping = {}
        for attr_name in ldap_entry.entry_attributes:
            attr_obj = ldap_entry[attr_name]
            if hasattr(attr_obj, "values"):
                values = [
                    str(v) if not isinstance(v, str) else v for v in attr_obj.values
                ]
            else:
                values = [str(attr_obj)]
            attrs_dict[attr_name] = values
        assert ldap_entry.entry_dn is not None
        entry_result = m.Ldif.Entry.create(
            dn=ldap_entry.entry_dn,
            attributes=attrs_dict,
            metadata=None,
        )
        assert entry_result.is_success
        flext_entry = entry_result.value
        write_result = flext_api.write([flext_entry])
        assert write_result.is_success
        ldif_output = write_result.value.content
        assert ldif_output is not None
        unique_username_copy = make_test_username("RoundtripTestCopy")
        reimport_dn = f"cn={unique_username_copy},{clean_test_ou}"
        parse_result = flext_api.parse_ldif(ldif_output)
        assert parse_result.is_success
        parsed_entries = parse_result.value.entries
        assert len(parsed_entries) == 1
        reimport_entry = parsed_entries[0]
        ldif_special_attrs = {
            "changetype",
            "control",
            "modifyTimestamp",
            "modifiersName",
        }
        attrs = reimport_entry.attributes
        assert attrs is not None
        obj_class_values = u.Ldif.get_attribute_values(reimport_entry, "objectclass")
        assert isinstance(obj_class_values, list)
        ldap_connection.add(
            reimport_dn,
            obj_class_values,
            attributes={
                attr: attrs.attributes[attr]
                for attr in attrs.attributes
                if attr.lower() not in ldif_special_attrs
                and attr.lower() != "objectclass"
            },
        )
        assert ldap_connection.search(reimport_dn, "(objectClass=*)", attributes=["*"])
        reimported = ldap_connection.entries[0]
        assert isinstance(original_attrs["sn"], str)
        assert isinstance(original_attrs["mail"], str)
        assert isinstance(original_attrs["telephoneNumber"], list)
        assert reimported["sn"].value == original_attrs["sn"]
        assert reimported["mail"].value == original_attrs["mail"]
        assert set(reimported["telephoneNumber"].values) == set(
            original_attrs["telephoneNumber"],
        )


__all__ = ["TestRealLdapRoundtrip"]
