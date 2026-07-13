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

from typing import TYPE_CHECKING

import pytest
from flext_ldap.adapters.entry import FlextLdapEntryAdapter

from flext_ldif import ldif
from tests.constants import c

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from pathlib import Path

    from tests.models import m
    from tests.protocols import p


@pytest.fixture
def flext_api() -> p.Ldif.LdifClient:
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
    ) -> list[m.Ldif.Entry]:
        """Convert ldap3 search results into ldif entries via the public adapter."""
        adapter = FlextLdapEntryAdapter()
        entries: list[m.Ldif.Entry] = []
        for ldap3_entry in ldap3_entries:
            result = adapter.ldap3_to_ldif_entry(ldap3_entry)
            assert result.success, result.error
            entries.append(result.unwrap())
        return entries

    def _parse_back(
        self,
        flext_api: p.Ldif.LdifClient,
        content: str | None,
    ) -> dict[str, Mapping[str, Sequence[str]]]:
        """Parse exported LDIF and index attribute maps by DN string.

        Parsing the export through the public parser is the strongest available
        behavioral check: it proves the exported bytes are valid LDIF that
        faithfully round-trips every DN and attribute.
        """
        assert content is not None
        parsed = flext_api.parse_string(content)
        assert parsed.success, parsed.error
        return {
            entry.dn_str: entry.attributes_dict for entry in parsed.unwrap().entries
        }

    def test_single_entry_export_round_trips_dn_and_attributes(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.LdifClient,
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
        assert len(ldap_connection.entries) == 1

        write_result = flext_api.write(self._to_ldif_entries(ldap_connection.entries))

        assert write_result.success, write_result.error
        indexed = self._parse_back(flext_api, write_result.unwrap().content)
        assert person_dn in indexed
        attrs = indexed[person_dn]
        assert username in attrs["cn"]
        assert "User" in attrs["sn"]
        assert "test@example.com" in attrs["mail"]

    def test_multiple_entries_export_round_trips_every_dn(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.LdifClient,
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
        assert len(ldap_connection.entries) == 5

        write_result = flext_api.write(self._to_ldif_entries(ldap_connection.entries))

        assert write_result.success, write_result.error
        indexed = self._parse_back(flext_api, write_result.unwrap().content)
        for i, (username, person_dn) in enumerate(
            zip(usernames, expected_dns, strict=True),
        ):
            assert person_dn in indexed
            assert username in indexed[person_dn]["cn"]
            assert f"Surname{i}" in indexed[person_dn]["sn"]

    def test_hierarchical_export_round_trips_containers_and_leaves(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.LdifClient,
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

        assert write_result.success, write_result.error
        indexed = self._parse_back(flext_api, write_result.unwrap().content)
        for expected_dn in (groups_ou_dn, people_ou_dn, person_dn, group_dn):
            assert expected_dn in indexed
        assert person_dn in indexed[group_dn]["member"]

    def test_export_is_idempotent_for_fixed_entries(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.LdifClient,
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

        assert first.success, first.error
        assert second.success, second.error
        assert first.unwrap().content == second.unwrap().content

    def test_export_to_file_writes_parseable_ldif(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.LdifClient,
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

        assert write_result.success, write_result.error
        assert output_file.exists()
        indexed = self._parse_back(flext_api, output_file.read_text())
        assert person_dn in indexed
        assert username in indexed[person_dn]["cn"]
        assert "export@example.com" in indexed[person_dn]["mail"]


__all__: list[str] = ["TestsFlextLdifRealLdapExport"]
