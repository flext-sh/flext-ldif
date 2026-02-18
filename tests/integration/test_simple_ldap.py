"""Simplified LDAP integration test to debug connection issues."""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from typing import cast

import pytest
from ldap3 import Connection

from flext_ldif import FlextLdif
from tests import GenericFieldsDict


# TypedDicts (GenericFieldsDict, GenericTestCaseDict, etc.) are available from conftest.py
@pytest.mark.skip(
    reason="LDAP connection fixtures not implemented - requires real LDAP server"
)
def test_ldap_connection(ldap_connection: Connection) -> None:
    """Test basic LDAP connection."""
    assert ldap_connection.bound
    assert ldap_connection.server.info is not None
    assert "dc=flext,dc=local" in ldap_connection.server.info.naming_contexts


@pytest.mark.skip(
    reason="LDAP connection fixtures not implemented - requires real LDAP server"
)
def test_simple_ldap_search(
    ldap_connection: Connection,
    ldap_container: GenericFieldsDict,
) -> None:
    """Test simple LDAP search."""
    base_dn = str(cast("dict[str, object]", ldap_container)["base_dn"])

    # Search for base DN
    result = ldap_connection.search(
        base_dn,
        "(objectClass=*)",
        search_scope="BASE",
    )

    assert result is True
    assert len(ldap_connection.entries) >= 1


@pytest.mark.skip(
    reason="LDAP connection fixtures not implemented - requires real LDAP server"
)
def test_create_and_export_entry(
    ldap_connection: Connection,
    ldap_container: GenericFieldsDict,
    make_test_username: Callable[[str], str],
) -> None:
    """Create LDAP entry and export to LDIF."""
    base_dn = str(cast("dict[str, object]", ldap_container)["base_dn"])
    unique_username = make_test_username("SimpleTest")
    test_dn = f"cn={unique_username},{base_dn}"

    # Delete if exists
    with contextlib.suppress(Exception):
        ldap_connection.delete(test_dn)

    # Add entry
    ldap_connection.add(
        test_dn,
        ["person"],
        {"cn": unique_username, "sn": "Test"},
    )

    # Search for it
    ldap_connection.search(
        test_dn,
        "(objectClass=*)",
        search_scope="BASE",
        attributes=["*"],
    )

    assert len(ldap_connection.entries) == 1
    ldap_entry = ldap_connection.entries[0]

    # Convert to FlextLdif entry
    api = FlextLdif.get_instance()
    entry_result = cast("object", api).models.Entry.create(
        dn=ldap_entry.entry_dn,
        attributes={
            attr: list(ldap_entry[attr].values) for attr in ldap_entry.entry_attributes
        },
    )
    assert entry_result.is_success
    flext_entry = entry_result.value

    # Write to LDIF
    write_result = api.write([flext_entry])
    assert write_result.is_success

    ldif_output = write_result.value
    assert f"cn: {unique_username}" in ldif_output
    assert "sn: Test" in ldif_output

    # Cleanup
    ldap_connection.delete(test_dn)
