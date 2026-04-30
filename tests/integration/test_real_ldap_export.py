"""LDIF export operations with live LDAP server.

Test suite verifying LDIF export functionality:
    - Export single entries to LDIF format
    - Export multiple entries in batch
    - Export hierarchical LDAP directory structures
    - Export to LDIF files with file I/O

Uses Docker fixture infrastructure from conftest.py for automatic
container management via tk.ldap_container fixture.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import (
    Callable,
    MutableSequence,
)
from pathlib import Path

import pytest
from flext_ldap import FlextLdapEntryAdapter

from flext_ldif import FlextLdif, ldif
from tests import c, m, p


@pytest.fixture
def flext_api() -> FlextLdif:
    """Ldif API instance."""
    return ldif()


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestsFlextLdifRealLdapExport:
    """Test LDIF export from real LDAP server."""

    def test_export_single_entry(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Export single LDAP entry to LDIF."""
        unique_username = make_test_username("TestUser")
        person_dn = f"cn={unique_username},{clean_test_ou}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {
                "cn": unique_username,
                "sn": "User",
                "mail": "test@example.com",
                "telephoneNumber": "+1-555-1234",
            },
        )
        ldap_connection.search(
            clean_test_ou,
            f"(cn={unique_username})",
            attributes=["*"],
        )
        assert len(ldap_connection.entries) == 1
        entry_result = FlextLdapEntryAdapter().ldap3_to_ldif_entry(
            ldap_connection.entries[0],
        )
        assert entry_result.success
        write_result = flext_api.write([entry_result.value])
        assert write_result.success
        ldif_output = write_result.value.content
        assert ldif_output is not None
        assert f"dn: cn={unique_username}" in ldif_output
        assert f"cn: {unique_username}" in ldif_output
        assert "sn: User" in ldif_output
        assert "mail: test@example.com" in ldif_output

    def test_export_multiple_entries(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Export multiple LDAP entries to LDIF."""
        unique_usernames = [make_test_username(f"User{i}") for i in range(5)]
        for i, unique_username in enumerate(unique_usernames):
            person_dn = f"cn={unique_username},{clean_test_ou}"
            ldap_connection.add(
                person_dn,
                ["person", "inetOrgPerson"],
                {
                    "cn": unique_username,
                    "sn": f"Surname{i}",
                    "mail": f"user{i}@example.com",
                },
            )
        ldap_connection.search(clean_test_ou, "(objectClass=person)", attributes=["*"])
        assert len(ldap_connection.entries) == 5
        adapter = FlextLdapEntryAdapter()
        entries: MutableSequence[m.Ldif.Entry] = []
        for ldap3_entry in ldap_connection.entries:
            result = adapter.ldap3_to_ldif_entry(ldap3_entry)
            assert result.success
            entries.append(result.value)
        write_result = flext_api.write(entries)
        assert write_result.success
        ldif_output = write_result.value.content
        assert ldif_output is not None
        for unique_username in unique_usernames:
            assert f"cn: {unique_username}" in ldif_output

    def test_export_hierarchical_structure(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Export hierarchical LDAP structure to LDIF."""
        unique_person_name = make_test_username("Alice")
        unique_group_name = make_test_username("Admins")
        groups_ou_dn = f"ou=Groups,{clean_test_ou}"
        people_ou_dn = f"ou=People,{clean_test_ou}"
        ldap_connection.add(groups_ou_dn, ["organizationalUnit"], {"ou": "Groups"})
        ldap_connection.add(people_ou_dn, ["organizationalUnit"], {"ou": "People"})
        person_dn = f"cn={unique_person_name},{people_ou_dn}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {"cn": unique_person_name, "sn": "Johnson"},
        )
        group_dn = f"cn={unique_group_name},{groups_ou_dn}"
        ldap_connection.add(
            group_dn,
            ["groupOfNames"],
            {"cn": unique_group_name, "member": person_dn},
        )
        ldap_connection.search(
            clean_test_ou,
            "(objectClass=*)",
            search_scope=c.Ldap.Ldap3SearchScope.SUBTREE.value,
            attributes=["*"],
        )
        adapter = FlextLdapEntryAdapter()
        entries: MutableSequence[m.Ldif.Entry] = []
        for ldap3_entry in ldap_connection.entries:
            result = adapter.ldap3_to_ldif_entry(ldap3_entry)
            assert result.success
            entries.append(result.value)
        write_result = flext_api.write(entries)
        assert write_result.success
        ldif_output = write_result.value.content
        assert ldif_output is not None
        assert "ou=Groups" in ldif_output
        assert "ou=People" in ldif_output
        assert f"cn={unique_person_name}" in ldif_output
        assert f"cn={unique_group_name}" in ldif_output

    def test_export_to_file(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        tmp_path: Path,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Export LDAP data to LDIF file."""
        unique_username = make_test_username("FileExport")
        person_dn = f"cn={unique_username},{clean_test_ou}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {"cn": unique_username, "sn": "Test", "mail": "export@example.com"},
        )
        ldap_connection.search(person_dn, "(objectClass=*)", attributes=["*"])
        entry_result = FlextLdapEntryAdapter().ldap3_to_ldif_entry(
            ldap_connection.entries[0],
        )
        assert entry_result.success
        output_file = tmp_path / "export.ldif"
        write_result = flext_api.write_ldif_file([entry_result.value], output_file)
        assert write_result.success
        assert output_file.exists()
        content = output_file.read_text()
        assert f"cn: {unique_username}" in content


__all__: list[str] = ["TestsFlextLdifRealLdapExport"]
