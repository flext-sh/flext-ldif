"""Behavioral roundtrip test for LDIF operations against a live LDAP server.

Verifies the observable public contract of the ``ldif()`` API end to end:
an entry read from a real LDAP server, serialized to LDIF and parsed back,
must re-materialize into an entry whose public state (DN, objectClass set,
scalar and multi-valued attributes) is identical to the original. Only the
public surface is exercised -- ``write``/``parse_ldif`` returning ``r[T]``,
``m.Ldif.Entry.create``, the ``attributes_dict`` computed field and the
``u.Ldif.get_attribute_values`` utility. The LDAP server is a genuine
external boundary reached through the ``ldap_connection`` fixture.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from flext_ldif import ldif
from tests import m, u

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests import p, t

# Attributes that LDIF/LDAP layers may inject and that are not part of the
# user-supplied contract under test.
_LDIF_OPERATIONAL_ATTRS: frozenset[str] = frozenset({
    "changetype",
    "control",
    "modifytimestamp",
    "modifiersname",
})


@pytest.fixture
def flext_api() -> p.Ldif.LdifClient:
    """Live ``ldif()`` API instance."""
    return ldif()


@pytest.mark.docker
@pytest.mark.integration
@pytest.mark.real_ldap
class TestsFlextLdifRealLdapRoundtrip:
    """Behavioral contract: LDAP -> LDIF -> LDAP preserves entry state."""

    @staticmethod
    def _read_ldap_attrs(
        ldap_connection: p.Ldap.Ldap3Connection,
        dn: str,
    ) -> t.MutableAttributeMapping:
        """Read one LDAP entry back as a plain attribute mapping (boundary)."""
        assert ldap_connection.search(dn, "(objectClass=*)", attributes=["*"])
        entry = ldap_connection.entries[0]
        attrs: t.MutableAttributeMapping = {}
        for name in entry.entry_attributes:
            value = entry[name]
            if hasattr(value, "values"):
                attrs[name] = [
                    v if isinstance(v, str) else str(v) for v in value.values
                ]
            else:
                attrs[name] = [str(value)]
        return attrs

    def test_roundtrip_through_ldif_preserves_entry_state(
        self,
        ldap_connection: p.Ldap.Ldap3Connection,
        clean_test_ou: str,
        flext_api: p.Ldif.LdifClient,
        make_test_username: Callable[[str], str],
    ) -> None:
        """LDAP -> LDIF -> LDAP yields an entry with identical public state."""
        # Arrange: create a source entry directly in LDAP.
        username = make_test_username("RoundtripTest")
        source_dn = f"cn={username},{clean_test_ou}"
        source_attrs: t.MutableAttributeMapping = {
            "cn": username,
            "sn": "Test",
            "mail": "roundtrip@example.com",
            "telephoneNumber": ["+1-555-1111", "+1-555-2222"],
            "description": "Multi-line\ndescription\ntest",
        }
        ldap_connection.add(source_dn, ["person", "inetOrgPerson"], source_attrs)
        read_back = self._read_ldap_attrs(ldap_connection, source_dn)

        entry_result = m.Ldif.Entry.create(
            dn=source_dn,
            attributes=read_back,
            metadata=None,
        )
        tm.ok(entry_result)
        source_entry = entry_result.unwrap()

        # Act: serialize to LDIF, then parse the LDIF back.
        write_result = flext_api.write([source_entry])
        tm.ok(write_result)
        ldif_text = write_result.unwrap().content
        assert ldif_text

        parse_result = flext_api.parse_ldif(ldif_text)
        tm.ok(parse_result)
        parsed_entries = parse_result.unwrap().entries

        # Assert: exactly one entry survives, with the same DN.
        tm.that(len(parsed_entries), eq=1)
        parsed_entry = parsed_entries[0]
        tm.that(parsed_entry.dn_str, eq=source_dn)

        # Assert: objectClass set is preserved through the roundtrip.
        object_classes = u.Ldif.get_attribute_values(parsed_entry, "objectclass")
        tm.that({oc.lower() for oc in object_classes}, eq={"person", "inetorgperson"})

        # Re-import the parsed entry into LDAP via its PUBLIC attribute view.
        copy_dn = f"cn={make_test_username('RoundtripTestCopy')},{clean_test_ou}"
        parsed_attrs = parsed_entry.attributes_dict
        add_attrs: t.MutableAttributeMapping = {
            name: values
            for name, values in parsed_attrs.items()
            if name.lower() not in _LDIF_OPERATIONAL_ATTRS
            and name.lower() != "objectclass"
        }
        ldap_connection.add(copy_dn, object_classes, attributes=add_attrs)

        # Assert: the re-imported LDAP entry matches the original observable values.
        reimported = self._read_ldap_attrs(ldap_connection, copy_dn)
        tm.that(reimported["sn"], eq=["Test"])
        tm.that(reimported["mail"], eq=["roundtrip@example.com"])
        tm.that(set(reimported["telephoneNumber"]), eq={"+1-555-1111", "+1-555-2222"})
        tm.that(reimported["description"], eq=["Multi-line\ndescription\ntest"])


__all__: list[str] = ["TestsFlextLdifRealLdapRoundtrip"]
