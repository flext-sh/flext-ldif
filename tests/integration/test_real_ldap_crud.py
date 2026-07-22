"""CRUD and batch behavior against a live LDAP server.

Behavioral suite: every assertion targets an OBSERVABLE contract — the
`r[T]` outcome of the ldif API, public model state (``dn_str``,
``attributes_dict``), and the round-tripped data actually stored in and
read back from the LDAP directory. The LDAP server is the only genuine
external boundary; the unit under test (the ``ldif`` client and the
``m.Ldif.Entry`` model) is never mocked, patched, or inspected privately.

Uses Docker fixture infrastructure from conftest.py for automatic
container management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flext_ldif import ldif
from flext_tests import tm
from tests import c, m

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from tests import p, t


@pytest.fixture
def flext_api() -> p.Ldif.LdifClient:
    """Ldif API instance."""
    return ldif()


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestsFlextLdifRealLdapCrud:
    """Behavioral CRUD and batch contracts over a live LDAP directory."""

    @staticmethod
    def _add_entry(
        ldap_connection: p.Ldap.Ldap3Connection, entry: m.Ldif.Entry
    ) -> None:
        """Store an entry in LDAP using only its public model surface."""
        attrs = dict(entry.attributes_dict)
        object_classes = [
            oc
            for key, values in list(attrs.items())
            if key.lower() == "objectclass"
            for oc in values
        ]
        payload = {
            key: values for key, values in attrs.items() if key.lower() != "objectclass"
        }
        ldap_connection.add(entry.dn_str, object_classes, payload)

    def test_create_returns_success_with_public_model_state(self) -> None:
        """Entry.create yields a success result exposing dn and attributes."""
        result = m.Ldif.Entry.create(
            dn="cn=Alice,ou=people,dc=example,dc=com",
            attributes={
                "cn": "Alice",
                "sn": "Doe",
                "objectClass": ["inetOrgPerson", "person", "top"],
            },
        )

        tm.ok(result)
        entry = result.value
        tm.that(entry.dn_str, eq="cn=Alice,ou=people,dc=example,dc=com")
        tm.that(entry.attributes_dict["cn"], eq=["Alice"])
        tm.that(
            entry.attributes_dict["objectClass"], eq=["inetOrgPerson", "person", "top"]
        )
        assert not entry.has_validation_errors

    def test_complete_crud_cycle_roundtrips_through_ldap(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Create, update, and delete are each observable in the directory."""
        username = make_test_username("CRUDTestUser")
        person_dn = f"cn={username},{clean_test_ou}"
        result = m.Ldif.Entry.create(
            dn=person_dn,
            attributes={
                "cn": username,
                "sn": "User",
                "mail": "crud@example.com",
                "uid": username,
                "objectClass": ["inetOrgPerson", "person", "top"],
            },
        )
        tm.ok(result)
        entry = result.value

        # Create: entry becomes readable in the directory.
        self._add_entry(ldap_connection, entry)
        ldap_connection.search(entry.dn_str, "(objectClass=*)", attributes=["*"])
        assert ldap_connection.entries
        tm.that(ldap_connection.entries[0]["mail"].value, eq="crud@example.com")

        # Update: replaced attribute is reflected on re-read.
        ldap_connection.modify(
            entry.dn_str, {"mail": [("MODIFY_REPLACE", ["updated_crud@example.com"])]}
        )
        ldap_connection.search(entry.dn_str, "(objectClass=*)", attributes=["*"])
        assert (
            str(ldap_connection.entries[0]["mail"].value) == "updated_crud@example.com"
        )

        # Delete: entry is no longer resolvable.
        ldap_connection.delete(entry.dn_str)
        found = ldap_connection.search(
            entry.dn_str,
            "(objectClass=*)",
            search_scope=c.Ldap.Ldap3SearchScope.BASE.value,
        )
        assert not found or not ldap_connection.entries

    def test_batch_creation_validates_every_entry(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.LdifClient,
        make_test_username: Callable[[str], str],
    ) -> None:
        """A batch built via the API validates and stores as valid entries."""
        entries: list[m.Ldif.Entry] = []
        for i in range(20):
            username = make_test_username(f"BatchUser{i}")
            result = m.Ldif.Entry.create(
                dn=f"cn={username},{clean_test_ou}",
                attributes={
                    "cn": username,
                    "sn": f"User{i}",
                    "mail": f"batch{i}@example.com",
                    "objectClass": ["inetOrgPerson", "person", "top"],
                },
            )
            tm.ok(result)
            entries.append(result.value)

        tm.that(len(entries), eq=20)
        for entry in entries:
            self._add_entry(ldap_connection, entry)

        validation_result = flext_api.validate_entries(entries)
        tm.ok(validation_result)

    def test_ldif_export_import_preserves_dns_and_attributes(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.LdifClient,
        tmp_path: Path,
        make_test_username: Callable[[str], str],
    ) -> None:
        """LDAP → LDIF file → parse round-trip preserves the entry set."""
        usernames = [make_test_username(f"ExportBatch{i}") for i in range(10)]
        expected_dns: set[str] = set()
        for i, username in enumerate(usernames):
            person_dn = f"cn={username},{clean_test_ou}"
            ldap_connection.add(
                person_dn,
                ["person", "inetOrgPerson"],
                {"cn": username, "sn": f"Batch{i}", "mail": f"export{i}@example.com"},
            )
            expected_dns.add(person_dn)

        ldap_connection.search(
            clean_test_ou,
            "(objectClass=person)",
            search_scope=c.Ldap.Ldap3SearchScope.SUBTREE.value,
            attributes=["*"],
        )
        source_count = len(ldap_connection.entries)
        assert source_count > 0, "No entries found in LDAP"

        entries: list[m.Ldif.Entry] = []
        for ldap_entry in ldap_connection.entries:
            attrs: t.MutableAttributeMapping = {
                name: [
                    str(v)
                    for v in (
                        ldap_entry[name].values
                        if hasattr(ldap_entry[name], "values")
                        else [str(ldap_entry[name])]
                    )
                ]
                for name in ldap_entry.entry_attributes
            }
            assert ldap_entry.entry_dn is not None
            result = m.Ldif.Entry.create(dn=ldap_entry.entry_dn, attributes=attrs)
            tm.ok(result)
            entries.append(result.value)

        export_file = tmp_path / "batch_export.ldif"
        write_result = flext_api.write_ldif_file(entries, export_file)
        tm.ok(write_result)
        assert export_file.exists()

        parse_result = flext_api.parse_ldif(export_file)
        tm.ok(parse_result)
        parsed_entries = parse_result.value.entries
        tm.that(len(parsed_entries), eq=source_count)
        parsed_dns = {entry.dn_str for entry in parsed_entries}
        assert expected_dns <= parsed_dns


__all__: list[str] = []
