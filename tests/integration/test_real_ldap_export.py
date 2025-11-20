"""LDIF export operations with live LDAP server.

Test suite verifying LDIF export functionality:
    - Export single entries to LDIF format
    - Export multiple entries in batch
    - Export hierarchical LDAP directory structures
    - Export to LDIF files with file I/O

Uses Docker fixture infrastructure from conftest.py for automatic
container management via FlextTestsDocker.ldap_container fixture.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from ldap3 import Connection

from flext_ldif import FlextLdif

# Note: ldap_connection and clean_test_ou fixtures are provided by conftest.py
# They use unique_dn_suffix for isolation and indepotency in parallel execution


@pytest.fixture
def flext_api() -> FlextLdif:
    """FlextLdif API instance."""
    return FlextLdif.get_instance()


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestRealLdapExport:
    """Test LDIF export from real LDAP server."""

    def test_export_single_entry(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Export single LDAP entry to LDIF."""
        # Use isolated username for parallel execution
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
        ldap_entry = ldap_connection.entries[0]

        attrs_dict = {}
        for attr_name in ldap_entry.entry_attributes:
            attr_obj = ldap_entry[attr_name]
            if hasattr(attr_obj, "raw_values"):
                values = [
                    v.decode("utf-8") if isinstance(v, bytes) else str(v)
                    for v in attr_obj.raw_values
                ]
            elif hasattr(attr_obj, "value"):
                val = attr_obj.value
                if isinstance(val, bytes):
                    values = [val.decode("utf-8")]
                elif isinstance(val, list):
                    values = [
                        v.decode("utf-8") if isinstance(v, bytes) else str(v)
                        for v in val
                    ]
                else:
                    values = [str(val)]
            else:
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

        assert f"dn: cn={unique_username}" in ldif_output
        assert f"cn: {unique_username}" in ldif_output
        assert "sn: User" in ldif_output
        assert "mail: test@example.com" in ldif_output

    def test_export_multiple_entries(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Export multiple LDAP entries to LDIF."""
        # Use isolated usernames for parallel execution
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

        ldap_connection.search(
            clean_test_ou,
            "(objectClass=person)",
            attributes=["*"],
        )

        assert len(ldap_connection.entries) == 5

        entries = []
        for entry in ldap_connection.entries:
            attrs_dict = {}
            for attr_name in entry.entry_attributes:
                attr_obj = entry[attr_name]
                if hasattr(attr_obj, "raw_values"):
                    values = [
                        v.decode("utf-8") if isinstance(v, bytes) else str(v)
                        for v in attr_obj.raw_values
                    ]
                elif hasattr(attr_obj, "value"):
                    val = attr_obj.value
                    if isinstance(val, bytes):
                        values = [val.decode("utf-8")]
                    elif isinstance(val, list):
                        values = [
                            v.decode("utf-8") if isinstance(v, bytes) else str(v)
                            for v in val
                        ]
                    else:
                        values = [str(val)]
                else:
                    values = [str(attr_obj)]
                attrs_dict[attr_name] = values

            result = flext_api.models.Entry.create(
                dn=entry.entry_dn,
                attributes=attrs_dict,
                metadata=None,
            )
            assert result.is_success
            entries.append(result.unwrap())

        write_result = flext_api.write(entries)
        assert write_result.is_success
        ldif_output = write_result.unwrap()

        for unique_username in unique_usernames:
            assert f"cn: {unique_username}" in ldif_output

    def test_export_hierarchical_structure(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Export hierarchical LDAP structure to LDIF."""
        # Use isolated usernames for parallel execution
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
            search_scope="SUBTREE",
            attributes=["*"],
        )

        entries = []
        for entry in ldap_connection.entries:
            attrs_dict = {}
            for attr_name in entry.entry_attributes:
                attr_obj = entry[attr_name]
                if hasattr(attr_obj, "raw_values"):
                    values = [
                        v.decode("utf-8") if isinstance(v, bytes) else str(v)
                        for v in attr_obj.raw_values
                    ]
                elif hasattr(attr_obj, "value"):
                    val = attr_obj.value
                    if isinstance(val, bytes):
                        values = [val.decode("utf-8")]
                    elif isinstance(val, list):
                        values = [
                            v.decode("utf-8") if isinstance(v, bytes) else str(v)
                            for v in val
                        ]
                    else:
                        values = [str(val)]
                else:
                    values = [str(attr_obj)]
                attrs_dict[attr_name] = values

            result = flext_api.models.Entry.create(
                dn=entry.entry_dn,
                attributes=attrs_dict,
                metadata=None,
            )
            assert result.is_success
            entries.append(result.unwrap())

        write_result = flext_api.write(entries)
        assert write_result.is_success
        ldif_output = write_result.unwrap()

        assert "ou=Groups" in ldif_output
        assert "ou=People" in ldif_output
        assert f"cn={unique_person_name}" in ldif_output
        assert f"cn={unique_group_name}" in ldif_output

    def test_export_to_file(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        tmp_path: Path,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Export LDAP data to LDIF file."""
        # Use isolated username for parallel execution
        unique_username = make_test_username("FileExport")
        person_dn = f"cn={unique_username},{clean_test_ou}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {"cn": unique_username, "sn": "Test", "mail": "export@example.com"},
        )

        ldap_connection.search(person_dn, "(objectClass=*)", attributes=["*"])
        ldap_entry = ldap_connection.entries[0]

        attrs_dict = {}
        for attr_name in ldap_entry.entry_attributes:
            attr_obj = ldap_entry[attr_name]
            if hasattr(attr_obj, "values"):
                values = [str(v) if not isinstance(v, str) else v for v in attr_obj]
            elif isinstance(attr_obj, list):
                values = [str(v) for v in attr_obj]
            else:
                values = [str(attr_obj)]
            attrs_dict[attr_name] = values

        entry_result = flext_api.models.Entry.create(
            dn=ldap_entry.entry_dn,
            attributes=attrs_dict,
            metadata=None,
        )
        assert entry_result.is_success
        flext_entry = entry_result.unwrap()

        output_file = tmp_path / "export.ldif"
        write_result = flext_api.write([flext_entry], output_file)
        assert write_result.is_success

        assert output_file.exists()
        content = output_file.read_text()
        assert f"cn: {unique_username}" in content


__all__ = [
    "TestRealLdapExport",
]
