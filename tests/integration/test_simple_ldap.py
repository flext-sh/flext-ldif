"""Behavioral integration tests for the flext-ldif facade against live LDAP.

These tests assert observable public behavior of the ``ldif()`` facade and the
``m.Ldif.Entry`` model contract: capturing a live LDAP entry, serializing it to
LDIF text, and parsing that text back. Only the ldap3 connection is treated as
an external boundary; every flext-ldif assertion goes through the public API.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldif import ldif
from tests.constants import c
from tests.models import m

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests.protocols import p
    from tests.typings import t


class TestsFlextLdifSimpleLdap:
    """Behavior contract for the flext-ldif facade over live LDAP data."""

    def _capture_live_entry(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        base_dn: str,
        username: str,
    ) -> m.Ldif.Entry:
        """Create a person entry in LDAP and return it as an ``m.Ldif.Entry``.

        The ldap3 connection is the external boundary; the returned value is the
        public flext-ldif model the tests assert against.
        """
        test_dn = f"cn={username},{base_dn}"
        ldap_connection.search(
            test_dn,
            "(objectClass=*)",
            search_scope=c.Ldap.Ldap3SearchScope.BASE.value,
        )
        if ldap_connection.entries:
            ldap_connection.delete(test_dn)
        ldap_connection.add(
            test_dn,
            ["person"],
            {"cn": username, "sn": "Test"},
        )
        ldap_connection.search(
            test_dn,
            "(objectClass=*)",
            search_scope=c.Ldap.Ldap3SearchScope.BASE.value,
            attributes=["*"],
        )
        ldap_entry = ldap_connection.entries[0]
        assert ldap_entry.entry_dn is not None
        attrs: t.MutableAttributeMapping = {
            attr: [str(value) for value in ldap_entry[attr].values]
            for attr in ldap_entry.entry_attributes
        }
        entry_result = m.Ldif.Entry.create(dn=ldap_entry.entry_dn, attributes=attrs)
        assert entry_result.success, entry_result.error
        entry: m.Ldif.Entry = entry_result.unwrap()
        return entry

    def test_bound_connection_reaches_configured_base_dn(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        ldap_container: t.StrMapping,
    ) -> None:
        """A base-scoped search on the configured base DN yields its entry."""
        base_dn = ldap_container.get("base_dn", "dc=flext,dc=local")

        found = ldap_connection.search(
            base_dn,
            "(objectClass=*)",
            search_scope=c.Ldap.Ldap3SearchScope.BASE.value,
        )

        assert ldap_connection.bound
        assert found
        assert len(ldap_connection.entries) >= 1

    def test_entry_create_exposes_attributes_through_public_api(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        ldap_container: t.StrMapping,
        make_test_username: Callable[[str], str],
    ) -> None:
        """A model built from a live entry exposes dn and attributes publicly."""
        base_dn = ldap_container.get("base_dn", "dc=flext,dc=local")
        username = make_test_username("CreateTest")

        entry = self._capture_live_entry(ldap_connection, base_dn, username)

        try:
            attributes = entry.attributes_dict
            assert entry.dn_str == f"cn={username},{base_dn}"
            assert "cn" in attributes
            assert "sn" in attributes
            assert username in attributes["cn"]
            assert "Test" in attributes["sn"]
        finally:
            ldap_connection.delete(f"cn={username},{base_dn}")

    def test_write_serializes_entry_to_ldif_content(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        ldap_container: t.StrMapping,
        make_test_username: Callable[[str], str],
    ) -> None:
        """write() returns success with LDIF content and matching statistics."""
        base_dn = ldap_container.get("base_dn", "dc=flext,dc=local")
        username = make_test_username("WriteTest")
        entry = self._capture_live_entry(ldap_connection, base_dn, username)

        try:
            write_result = ldif().write([entry])

            assert write_result.success, write_result.error
            response = write_result.unwrap()
            assert response.content is not None
            assert response.statistics.total_entries == 1
            assert response.statistics.processed_entries == 1
            assert f"cn: {username}" in response.content
            assert "sn: Test" in response.content
        finally:
            ldap_connection.delete(f"cn={username},{base_dn}")

    def test_written_entry_roundtrips_through_parse(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        ldap_container: t.StrMapping,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Parsing the LDIF produced by write() recovers the original entry."""
        base_dn = ldap_container.get("base_dn", "dc=flext,dc=local")
        username = make_test_username("RoundtripTest")
        entry = self._capture_live_entry(ldap_connection, base_dn, username)
        api = ldif()

        try:
            write_result = api.write([entry])
            assert write_result.success, write_result.error
            content = write_result.unwrap().content
            assert content is not None

            parse_result = api.parse_string(content)

            assert parse_result.success, parse_result.error
            parsed = parse_result.unwrap().entries
            assert len(parsed) == 1
            recovered = parsed[0]
            assert recovered.dn_str == entry.dn_str
            recovered_values = [
                value
                for values in recovered.attributes_dict.values()
                for value in values
            ]
            assert username in recovered_values
            assert "Test" in recovered_values
        finally:
            ldap_connection.delete(f"cn={username},{base_dn}")
