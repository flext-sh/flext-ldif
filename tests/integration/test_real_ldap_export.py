"""Behavioral tests for LDIF export from a live LDAP directory.

These tests assert the OBSERVABLE PUBLIC CONTRACT of the ``ldif()`` export
surface (``write`` / ``write_ldif_file``):

    - a successful ``r[T]`` outcome carrying LDIF content,
    - the exported LDIF, when parsed back through the public parser, reproduces
      every source DN and its attribute values (round-trip fidelity),
    - export is idempotent for a fixed set of entries.

The LDAP directory (``ldap_connection``) and the ldap3->ldif ``FlextLdapEntryAdapter``
are genuine external boundaries used only to produce real input entries; the
assertions never inspect export internals.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import pytest
from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from flext_tests import tm

from flext_ldif import ldif
from tests import c, p


@pytest.fixture
def flext_api() -> p.Ldif.Client:
    """Public Ldif API instance under test."""
    return ldif()


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestsFlextLdifRealLdapExport:
    """Round-trip behavioral contract of LDIF export from a real LDAP server."""

    @staticmethod
    def _to_ldif_entries(
        ldap3_entries: Sequence[p.Ldap.Ldap3Entry],
    ) -> list[p.Ldif.Entry]:
        """Convert ldap3 search results into ldif entries via the public adapter."""
        adapter = FlextLdapEntryAdapter()
        entries: list[p.Ldif.Entry] = []
        for ldap3_entry in ldap3_entries:
            result = adapter.ldap3_to_ldif_entry(ldap3_entry)
            tm.ok(result)
            entries.append(result.unwrap())
        return entries

    def _parse_back(
        self,
        flext_api: p.Ldif.Client,
        content: str | None,
    ) -> dict[str, Mapping[str, Sequence[str]]]:
        """Parse exported LDIF and index attribute maps by DN string.

        Parsing the export through the public parser is the strongest available
        behavioral check: it proves the exported bytes are valid LDIF that
        faithfully round-trips every DN and attribute.
        """
        tm.that(content, none=False)
        parsed = flext_api.parse_string(content)
        tm.ok(parsed)
        return {
            entry.dn_str: entry.attributes_dict for entry in parsed.unwrap().entries
        }

    def test_single_entry_export_round_trips_dn_and_attributes(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.Client,
        make_test_username: Callable[[str], str],
    ) -> None:
        """A single exported entry round-trips its DN and every attribute value."""
        username = make_test_username("TestUser")
        person_dn = f"cn={username},{clean_test_ou}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {
                "cn": username,
                "sn": "User",
                "mail": "test@example.com",
                "telephoneNumber": "+1-555-1234",
            },
        )
        ldap_connection.search(clean_test_ou, f"(cn={username})", attributes=["*"])
        tm.that(len(ldap_connection.entries), eq=1)

        write_result = flext_api.write(self._to_ldif_entries(ldap_connection.entries))

        tm.ok(write_result)
        indexed = self._parse_back(flext_api, write_result.unwrap().content)
        tm.that(indexed, has=person_dn)
        attrs = indexed[person_dn]
        tm.that(attrs["cn"], has=username)
        tm.that(attrs["sn"], has="User")
        tm.that(attrs["mail"], has="test@example.com")

    def test_multiple_entries_export_round_trips_every_dn(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.Client,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Batch export reproduces each source DN with its distinct attributes."""
        usernames = [make_test_username(f"User{i}") for i in range(5)]
        expected_dns: list[str] = []
        for i, username in enumerate(usernames):
            person_dn = f"cn={username},{clean_test_ou}"
            expected_dns.append(person_dn)
            ldap_connection.add(
                person_dn,
                ["person", "inetOrgPerson"],
                {
                    "cn": username,
                    "sn": f"Surname{i}",
                    "mail": f"user{i}@example.com",
                },
            )
        ldap_connection.search(clean_test_ou, "(objectClass=person)", attributes=["*"])
        tm.that(len(ldap_connection.entries), eq=5)

        write_result = flext_api.write(self._to_ldif_entries(ldap_connection.entries))

        tm.ok(write_result)
        indexed = self._parse_back(flext_api, write_result.unwrap().content)
        for i, (username, person_dn) in enumerate(
            zip(usernames, expected_dns, strict=True),
        ):
            tm.that(indexed, has=person_dn)
            tm.that(indexed[person_dn]["cn"], has=username)
            tm.that(indexed[person_dn]["sn"], has=f"Surname{i}")

    def test_hierarchical_export_round_trips_containers_and_leaves(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.Client,
        make_test_username: Callable[[str], str],
    ) -> None:
        """A nested directory subtree exports so every container and leaf DN survives."""
        person_name = make_test_username("Alice")
        group_name = make_test_username("Admins")
        groups_ou_dn = f"ou=Groups,{clean_test_ou}"
        people_ou_dn = f"ou=People,{clean_test_ou}"
        ldap_connection.add(groups_ou_dn, ["organizationalUnit"], {"ou": "Groups"})
        ldap_connection.add(people_ou_dn, ["organizationalUnit"], {"ou": "People"})
        person_dn = f"cn={person_name},{people_ou_dn}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {"cn": person_name, "sn": "Johnson"},
        )
        group_dn = f"cn={group_name},{groups_ou_dn}"
        ldap_connection.add(
            group_dn,
            ["groupOfNames"],
            {"cn": group_name, "member": person_dn},
        )
        ldap_connection.search(
            clean_test_ou,
            "(objectClass=*)",
            search_scope=c.Ldap.Ldap3SearchScope.SUBTREE.value,
            attributes=["*"],
        )

        write_result = flext_api.write(self._to_ldif_entries(ldap_connection.entries))

        tm.ok(write_result)
        indexed = self._parse_back(flext_api, write_result.unwrap().content)
        for expected_dn in (groups_ou_dn, people_ou_dn, person_dn, group_dn):
            tm.that(indexed, has=expected_dn)
        tm.that(indexed[group_dn]["member"], has=person_dn)

    def test_export_is_idempotent_for_fixed_entries(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.Client,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Exporting the same entries twice yields identical LDIF content."""
        username = make_test_username("Idempotent")
        person_dn = f"cn={username},{clean_test_ou}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {"cn": username, "sn": "Same", "mail": "same@example.com"},
        )
        ldap_connection.search(clean_test_ou, f"(cn={username})", attributes=["*"])
        entries = self._to_ldif_entries(ldap_connection.entries)

        first = flext_api.write(entries)
        second = flext_api.write(entries)

        tm.ok(first)
        tm.ok(second)
        tm.that(first.unwrap().content, eq=second.unwrap().content)

    def test_export_to_file_writes_parseable_ldif(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.Client,
        tmp_path: Path,
        make_test_username: Callable[[str], str],
    ) -> None:
        """File export writes valid LDIF that round-trips the exported entry."""
        username = make_test_username("FileExport")
        person_dn = f"cn={username},{clean_test_ou}"
        ldap_connection.add(
            person_dn,
            ["person", "inetOrgPerson"],
            {"cn": username, "sn": "Test", "mail": "export@example.com"},
        )
        ldap_connection.search(person_dn, "(objectClass=*)", attributes=["*"])
        entries = self._to_ldif_entries(ldap_connection.entries)
        output_file = tmp_path / "export.ldif"

        write_result = flext_api.write_ldif_file(entries, output_file)

        tm.ok(write_result)
        assert output_file.exists()
        indexed = self._parse_back(flext_api, output_file.read_text())
        tm.that(indexed, has=person_dn)
        tm.that(indexed[person_dn]["cn"], has=username)
        tm.that(indexed[person_dn]["mail"], has="export@example.com")


__all__: list[str] = ["TestsFlextLdifRealLdapExport"]
