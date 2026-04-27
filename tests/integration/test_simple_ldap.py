"""Simplified LDAP integration test to debug connection issues."""

from __future__ import annotations

from collections.abc import (
    Callable,
)

from ldap3 import Connection

from flext_ldif import ldif
from tests import c, m, t


class TestsFlextLdifSimpleLdap:
    """Behavior contract for test_simple_ldap."""

    def test_ldap_connection(self, ldap_connection: Connection) -> None:
        """Test basic LDAP connection."""
        assert ldap_connection.bound
        server_info = getattr(ldap_connection.server, "info", None)
        assert server_info is not None
        naming_contexts = getattr(server_info, "naming_contexts", None)
        if naming_contexts is None:
            naming_contexts = getattr(server_info, "other", {}).get(
                "namingContexts", []
            )
        assert "dc=flext,dc=local" in naming_contexts

    def test_simple_ldap_search(
        self,
        ldap_connection: Connection,
        ldap_container: t.StrMapping,
    ) -> None:
        """Test simple LDAP search."""
        base_dn = str(ldap_container.get("base_dn", "dc=flext,dc=local"))
        result = ldap_connection.search(
            base_dn,
            "(objectClass=*)",
            search_scope=c.Ldap.Ldap3SearchScope.BASE.value,
        )
        assert result is True
        assert len(ldap_connection.entries) >= 1

    def test_create_and_export_entry(
        self,
        ldap_connection: Connection,
        ldap_container: t.StrMapping,
        make_test_username: Callable[[str], str],
    ) -> None:
        """Create LDAP entry and export to LDIF."""
        base_dn = str(ldap_container.get("base_dn", "dc=flext,dc=local"))
        unique_username = make_test_username("SimpleTest")
        test_dn = f"cn={unique_username},{base_dn}"
        ldap_connection.search(
            test_dn,
            "(objectClass=*)",
            search_scope=c.Ldap.Ldap3SearchScope.BASE.value,
        )
        if ldap_connection.entries:
            ldap_connection.delete(test_dn)
        ldap_connection.add(test_dn, ["person"], {"cn": unique_username, "sn": "Test"})
        ldap_connection.search(
            test_dn,
            "(objectClass=*)",
            search_scope=c.Ldap.Ldap3SearchScope.BASE.value,
            attributes=["*"],
        )
        assert len(ldap_connection.entries) == 1
        ldap_entry = ldap_connection.entries[0]
        api = ldif()
        attrs: t.MutableAttributeMapping = {
            attr: [str(v) for v in ldap_entry[attr].values]
            for attr in ldap_entry.entry_attributes
        }
        assert ldap_entry.entry_dn is not None
        entry_result = m.Ldif.Entry.create(
            dn=ldap_entry.entry_dn,
            attributes=attrs,
        )
        assert entry_result.success
        flext_entry = entry_result.value
        write_result = api.write([flext_entry])
        assert write_result.success
        ldif_output = write_result.value.content
        assert ldif_output is not None
        assert f"cn: {unique_username}" in ldif_output
        assert "sn: Test" in ldif_output
        ldap_connection.delete(test_dn)
