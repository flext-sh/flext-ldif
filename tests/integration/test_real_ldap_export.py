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

from collections.abc import Generator
from pathlib import Path

import pytest
from ldap3 import ALL, Connection, Server

from flext_ldif import FlextLdif

# LDAP connection details for flext-openldap-test container
LDAP_ADMIN_DN = "cn=admin,dc=flext,dc=local"
LDAP_ADMIN_PASSWORD = "admin123"
LDAP_BASE_DN = "dc=flext,dc=local"


@pytest.fixture(scope="module")
def ldap_connection(ldap_container: str) -> Generator[Connection]:
    """Create connection to real LDAP server via Docker fixture.

    Args:
        ldap_container: Docker LDAP connection string from conftest fixture

    Yields:
        Connection: ldap3 connection to LDAP server

    """
    host_port = ldap_container.replace("ldap://", "").replace("ldaps://", "")

    server = Server(f"ldap://{host_port}", get_info=ALL)
    conn = Connection(
        server,
        user=LDAP_ADMIN_DN,
        password=LDAP_ADMIN_PASSWORD,
    )

    try:
        if not conn.bind():
            pytest.skip(f"LDAP server not available at {host_port}")
    except Exception as e:
        pytest.skip(f"LDAP server not available at {host_port}: {e}")

    yield conn
    conn.unbind()


@pytest.fixture
def clean_test_ou(ldap_connection: Connection) -> Generator[str]:
    """Create and clean up test OU."""
    test_ou_dn = f"ou=FlextLdifTests,{LDAP_BASE_DN}"

    try:
        found = ldap_connection.search(
            test_ou_dn,
            "(objectClass=*)",
            search_scope="SUBTREE",
            attributes=["*"],
        )
        if found:
            dns_to_delete = [entry.entry_dn for entry in ldap_connection.entries]
            for dn in reversed(dns_to_delete):
                try:
                    ldap_connection.delete(dn)
                except Exception:
                    pass
    except Exception:
        pass

    try:
        ldap_connection.add(
            test_ou_dn,
            ["organizationalUnit"],
            {"ou": "FlextLdifTests"},
        )
    except Exception:
        pass

    yield test_ou_dn

    try:
        found = ldap_connection.search(
            test_ou_dn,
            "(objectClass=*)",
            search_scope="SUBTREE",
            attributes=["*"],
        )
        if found:
            dns_to_delete = [entry.entry_dn for entry in ldap_connection.entries]
            for dn in reversed(dns_to_delete):
                try:
                    ldap_connection.delete(dn)
                except Exception:
                    pass
    except Exception:
        pass


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
    ) -> None:
        """Export single LDAP entry to LDIF."""
        person_dn = f"cn=Test User,{clean_test_ou}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {
                "cn": "Test User",
                "sn": "User",
                "mail": "test@example.com",
                "telephoneNumber": "+1-555-1234",
            },
        )

        ldap_connection.search(
            clean_test_ou,
            "(cn=Test User)",
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

        assert "dn: cn=Test User" in ldif_output
        assert "cn: Test User" in ldif_output
        assert "sn: User" in ldif_output
        assert "mail: test@example.com" in ldif_output

    def test_export_multiple_entries(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
    ) -> None:
        """Export multiple LDAP entries to LDIF."""
        for i in range(5):
            person_dn = f"cn=User{i},{clean_test_ou}"
            ldap_connection.add(
                person_dn,
                ["person", "inetOrgPerson"],
                {
                    "cn": f"User{i}",
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

        for i in range(5):
            assert f"cn: User{i}" in ldif_output
            assert f"user{i}@example.com" in ldif_output

    def test_export_hierarchical_structure(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
    ) -> None:
        """Export hierarchical LDAP structure to LDIF."""
        groups_ou_dn = f"ou=Groups,{clean_test_ou}"
        people_ou_dn = f"ou=People,{clean_test_ou}"

        ldap_connection.add(groups_ou_dn, ["organizationalUnit"], {"ou": "Groups"})
        ldap_connection.add(people_ou_dn, ["organizationalUnit"], {"ou": "People"})

        person_dn = f"cn=Alice,{people_ou_dn}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {"cn": "Alice", "sn": "Johnson"},
        )

        group_dn = f"cn=Admins,{groups_ou_dn}"
        ldap_connection.add(
            group_dn,
            ["groupOfNames"],
            {"cn": "Admins", "member": person_dn},
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
        assert "cn=Alice" in ldif_output
        assert "cn=Admins" in ldif_output

    def test_export_to_file(
        self,
        ldap_connection: Connection,
        clean_test_ou: str,
        flext_api: FlextLdif,
        tmp_path: Path,
    ) -> None:
        """Export LDAP data to LDIF file."""
        person_dn = f"cn=File Export,{clean_test_ou}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {"cn": "File Export", "sn": "Test", "mail": "export@example.com"},
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
        assert "cn: File Export" in content


__all__ = [
    "TestRealLdapExport",
]
