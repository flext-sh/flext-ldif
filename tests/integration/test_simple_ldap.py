"""Simplified LDAP integration test to debug connection issues."""

from __future__ import annotations

import contextlib
from collections.abc import Callable, MutableMapping, MutableSequence

from ldap3 import Connection

from flext_ldif import FlextLdif, m
from tests import GenericFieldsDict


def test_ldap_connection(ldap_connection: Connection) -> None:
    """Test basic LDAP connection."""
    assert ldap_connection.bound
    server_info = getattr(ldap_connection.server, "info", None)
    assert server_info is not None
    naming_contexts: list[str] = list(getattr(server_info, "naming_contexts", []))
    assert "dc=flext,dc=local" in naming_contexts


def test_simple_ldap_search(
    ldap_connection: Connection,
    ldap_container: GenericFieldsDict,
) -> None:
    """Test simple LDAP search."""
    base_dn = str(ldap_container.get("base_dn", "dc=flext,dc=local"))
    result = ldap_connection.search(base_dn, "(objectClass=*)", search_scope="BASE")
    assert result is True
    assert len(ldap_connection.entries) >= 1


def test_create_and_export_entry(
    ldap_connection: Connection,
    ldap_container: GenericFieldsDict,
    make_test_username: Callable[[str], str],
) -> None:
    """Create LDAP entry and export to LDIF."""
    base_dn = str(ldap_container.get("base_dn", "dc=flext,dc=local"))
    unique_username = make_test_username("SimpleTest")
    test_dn = f"cn={unique_username},{base_dn}"
    with contextlib.suppress(Exception):
        ldap_connection.delete(test_dn)
    ldap_connection.add(test_dn, ["person"], {"cn": unique_username, "sn": "Test"})
    ldap_connection.search(
        test_dn,
        "(objectClass=*)",
        search_scope="BASE",
        attributes=["*"],
    )
    assert len(ldap_connection.entries) == 1
    ldap_entry = ldap_connection.entries[0]
    api = FlextLdif.get_instance()
    attrs: MutableMapping[str, MutableSequence[str] | str] = {
        attr: [str(v) for v in ldap_entry[attr].values]
        for attr in ldap_entry.entry_attributes
    }
    entry_result = m.Ldif.Entry.create(
        dn=ldap_entry.entry_dn,
        attributes=attrs,
    )
    assert entry_result.is_success
    flext_entry = entry_result.value
    write_result = api.write([flext_entry])
    assert write_result.is_success
    ldif_output = write_result.value
    assert f"cn: {unique_username}" in ldif_output
    assert "sn: Test" in ldif_output
    ldap_connection.delete(test_dn)
