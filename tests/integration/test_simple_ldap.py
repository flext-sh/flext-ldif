"""Simplified LDAP integration test to debug connection issues."""

from __future__ import annotations

import contextlib
from typing import cast

from ldap3 import ALL, Connection, Server

from flext_ldif import FlextLdif


def test_ldap_connection() -> None:
    """Test basic LDAP connection."""
    import pytest

    server = Server("localhost:3390", get_info=ALL)
    conn = Connection(
        server,
        user="cn=admin,dc=flext,dc=local",
        password="admin123",
    )

    try:
        if not conn.bind():
            pytest.skip("LDAP server not available at localhost:3390")
    except Exception:
        pytest.skip("LDAP server not available at localhost:3390")

    assert conn.bound
    assert server.info is not None
    assert "dc=flext,dc=local" in server.info.naming_contexts

    conn.unbind()


def test_simple_ldap_search() -> None:
    """Test simple LDAP search."""
    import pytest

    server = Server("localhost:3390")
    conn = Connection(
        server,
        user="cn=admin,dc=flext,dc=local",
        password="admin123",
    )

    try:
        if not conn.bind():
            pytest.skip("LDAP server not available at localhost:3390")
    except Exception:
        pytest.skip("LDAP server not available at localhost:3390")

    # Search for base DN
    result = conn.search(
        "dc=flext,dc=local",
        "(objectClass=*)",
        search_scope="BASE",
    )

    assert result is True
    assert len(conn.entries) >= 1

    conn.unbind()


def test_create_and_export_entry() -> None:
    """Create LDAP entry and export to LDIF."""
    import pytest

    server = Server("localhost:3390")
    conn = Connection(
        server,
        user="cn=admin,dc=flext,dc=local",
        password="admin123",
    )

    try:
        if not conn.bind():
            pytest.skip("LDAP server not available at localhost:3390")
    except Exception:
        pytest.skip("LDAP server not available at localhost:3390")

    # Create test entry
    test_dn = "cn=SimpleTest,dc=flext,dc=local"

    # Delete if exists
    with contextlib.suppress(Exception):
        conn.delete(test_dn)

    # Add entry
    conn.add(
        test_dn,
        ["person"],
        {"cn": "SimpleTest", "sn": "Test"},
    )

    # Search for it
    conn.search(test_dn, "(objectClass=*)", search_scope="BASE", attributes=["*"])

    assert len(conn.entries) == 1
    ldap_entry = conn.entries[0]

    # Convert to FlextLdif entry
    api = FlextLdif.get_instance()
    entry_result = api.models.Entry.create(
        dn=ldap_entry.entry_dn,
        attributes=cast(
            "dict[str, list[str]]",
            {
                attr: list(ldap_entry[attr].values)
                for attr in ldap_entry.entry_attributes
            },
        ),
    )
    assert entry_result.is_success
    flext_entry = entry_result.unwrap()

    # Write to LDIF
    write_result = api.write([flext_entry])
    assert write_result.is_success

    ldif_output = write_result.unwrap()
    assert "cn: SimpleTest" in ldif_output
    assert "sn: Test" in ldif_output

    # Cleanup
    conn.delete(test_dn)
    conn.unbind()
