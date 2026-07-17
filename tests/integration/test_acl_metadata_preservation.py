"""ACL Metadata Preservation Tests for OID and OUD.

Behavioral contract: parsing server-specific ACLs preserves each ACL feature in
the entry's public metadata extensions, and the extensions survive a
parse -> write -> parse round-trip. Every assertion targets observable public
behavior: the `r[T]` outcome of `parse_ldif` / `write`, the parsed entry count,
and the public `entry.metadata.extensions` mapping state.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from flext_ldif import ldif
from tests import c, t

if TYPE_CHECKING:
    from tests import m, p


class TestsFlextLdifAclMetadataPreservation:
    """Behavioral tests for OID/OUD ACL metadata preservation and round-trips."""

    @pytest.fixture
    def api(self) -> p.Ldif.LdifClient:
        """Provide a real LDIF client (public facade, no mocked internals)."""
        return ldif()

    @staticmethod
    def _extensions(entry: m.Ldif.Entry) -> t.JsonMapping:
        """Read the entry's public metadata extensions as a plain mapping."""
        metadata = entry.metadata
        assert metadata is not None
        extensions = metadata.extensions
        assert extensions is not None
        extensions_dump: t.JsonMapping = t.json_mapping_adapter().validate_python(
            dict(extensions),
        )
        return extensions_dump

    def _parse_single(
        self,
        api: p.Ldif.LdifClient,
        ldif_text: str,
        server_type: str,
    ) -> m.Ldif.Entry:
        """Parse LDIF that must yield exactly one entry; assert the r[T] success."""
        result = api.parse_ldif(ldif_text, server_type=server_type)
        tm.ok(result)
        response: m.Ldif.ParseResponse = result.unwrap()
        entries = response.entries
        tm.that(len(entries), eq=1)
        entry: m.Ldif.Entry = entries[0]
        return entry

    # -- OID ACL feature preservation ------------------------------------

    @pytest.mark.parametrize(
        ("acl_clause", "extension_key", "expected"),
        [
            pytest.param(
                "access to entry by * (browse) bindmode=(Simple)",
                c.Ldif.ACL_BINDMODE,
                "Simple",
                id="bindmode",
            ),
            pytest.param(
                "access to entry by * (browse) DenyGroupOverride",
                c.Ldif.ACL_DENY_GROUP_OVERRIDE,
                True,
                id="deny-group-override",
            ),
            pytest.param(
                "access to entry by * (browse) AppendToAll",
                c.Ldif.ACL_APPEND_TO_ALL,
                True,
                id="append-to-all",
            ),
            pytest.param(
                "access to entry by * (browse) bindipfilter=(orclipaddress=192.168.1.*)",
                c.Ldif.ACL_BIND_IP_FILTER,
                "orclipaddress=192.168.1.*",
                id="bind-ip-filter",
            ),
            pytest.param(
                "access to entry by * (add) constraintonaddedobject=(objectclass=person)",
                c.Ldif.ACL_CONSTRAIN_TO_ADDED_OBJECT,
                "objectclass=person",
                id="constrain-to-added-object",
            ),
        ],
    )
    def test_oid_feature_preserved_in_extensions(
        self,
        api: p.Ldif.LdifClient,
        acl_clause: str,
        extension_key: str,
        expected: str | bool,
    ) -> None:
        """Each OID ACL feature surfaces under its extension key after parsing."""
        ldif_text = (
            "dn: cn=test,dc=example,dc=com\n"
            f"orclaci: {acl_clause}\n"
            "objectClass: person\n"
            "cn: test\n"
        )
        entry = self._parse_single(api, ldif_text, c.Tests.OID)
        tm.that(self._extensions(entry).get(extension_key), eq=expected)

    def test_oid_all_features_preserved_together(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """A single OID ACL carrying every feature preserves them all at once."""
        ldif_text = (
            "dn: cn=test,dc=example,dc=com\n"
            "orclaci: access to entry by * (browse) bindmode=(Simple) "
            "DenyGroupOverride AppendToAll "
            "bindipfilter=(orclipaddress=192.168.1.*) "
            "constraintonaddedobject=(objectclass=person)\n"
            "objectClass: person\n"
            "cn: test\n"
        )
        extensions = self._extensions(self._parse_single(api, ldif_text, c.Tests.OID))
        tm.that(extensions.get(c.Ldif.ACL_BINDMODE), eq="Simple")
        tm.that(extensions.get(c.Ldif.ACL_DENY_GROUP_OVERRIDE), eq=True)
        tm.that(extensions.get(c.Ldif.ACL_APPEND_TO_ALL), eq=True)
        tm.that(
            extensions.get(c.Ldif.ACL_BIND_IP_FILTER), eq="orclipaddress=192.168.1.*"
        )
        assert (
            extensions.get(c.Ldif.ACL_CONSTRAIN_TO_ADDED_OBJECT) == "objectclass=person"
        )

    # -- OUD ACI feature preservation ------------------------------------

    @pytest.mark.parametrize(
        ("aci", "extension_key", "expected"),
        [
            pytest.param(
                '(targetattr="cn")(targattrfilters="add=cn:(cn=REDACTED_LDAP_BIND_PASSWORD)")'
                '(version 3.0; acl "test"; allow (read) userdn="ldap:///self";)',
                c.Ldif.ACL_TARGETATTR_FILTERS,
                "add=cn:(cn=REDACTED_LDAP_BIND_PASSWORD)",
                id="targattrfilters",
            ),
            pytest.param(
                '(targetattr="*")(targetcontrol="1.3.6.1.4.1.42.2.27.9.5.2")'
                '(version 3.0; acl "test"; allow (read) userdn="ldap:///self";)',
                c.Ldif.ACL_TARGET_CONTROL,
                "1.3.6.1.4.1.42.2.27.9.5.2",
                id="targetcontrol",
            ),
            pytest.param(
                '(targetattr="*")(extop="1.3.6.1.4.1.26027.1.6.1")'
                '(version 3.0; acl "test"; allow (read) userdn="ldap:///self";)',
                c.Ldif.ACL_EXTOP,
                "1.3.6.1.4.1.26027.1.6.1",
                id="extop",
            ),
            pytest.param(
                '(targetattr="*")(version 3.0; acl "test"; allow (read) '
                'userdn="ldap:///self" and ip="192.168.1.0/24";)',
                c.Ldif.ACL_BIND_IP_FILTER,
                "192.168.1.0/24",
                id="bind-ip",
            ),
            pytest.param(
                '(targetattr="*")(version 3.0; acl "test"; allow (read) '
                'userdn="ldap:///self" and dns="*.example.com";)',
                c.Ldif.ACL_BIND_DNS,
                "*.example.com",
                id="bind-dns",
            ),
            pytest.param(
                '(targetattr="*")(version 3.0; acl "test"; allow (read) '
                'userdn="ldap:///self" and dayofweek="Mon,Tue,Wed";)',
                c.Ldif.ACL_BIND_DAYOFWEEK,
                "Mon,Tue,Wed",
                id="bind-dayofweek",
            ),
            pytest.param(
                '(targetattr="*")(version 3.0; acl "test"; allow (read) '
                'userdn="ldap:///self" and timeofday >= "0800";)',
                c.Ldif.ACL_BIND_TIMEOFDAY,
                ">=0800",
                id="bind-timeofday",
            ),
            pytest.param(
                '(targetattr="*")(version 3.0; acl "test"; allow (read) '
                'userdn="ldap:///self" and authmethod = "ssl";)',
                c.Ldif.ACL_AUTHMETHOD,
                "ssl",
                id="bind-authmethod",
            ),
            pytest.param(
                '(targetattr="*")(version 3.0; acl "test"; allow (read) '
                'userdn="ldap:///self" and ssf >= "128";)',
                c.Ldif.ACL_SSF,
                ">=128",
                id="bind-ssf",
            ),
        ],
    )
    def test_oud_feature_preserved_in_extensions(
        self,
        api: p.Ldif.LdifClient,
        aci: str,
        extension_key: str,
        expected: str,
    ) -> None:
        """Each OUD ACI feature surfaces under its extension key after parsing."""
        ldif_text = (
            "dn: cn=test,dc=example,dc=com\n"
            f"aci: {aci}\n"
            "objectClass: person\n"
            "cn: test\n"
        )
        entry = self._parse_single(api, ldif_text, c.Tests.OUD)
        tm.that(self._extensions(entry).get(extension_key), eq=expected)

    def test_oud_all_features_preserved_together(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """A single OUD ACI carrying every feature preserves them all at once."""
        ldif_text = (
            "dn: cn=test,dc=example,dc=com\n"
            'aci: (targetattr="cn")(targattrfilters="add=cn:(cn=REDACTED_LDAP_BIND_PASSWORD)")'
            '(targetcontrol="1.3.6.1.4.1.42.2.27.9.5.2")'
            '(extop="1.3.6.1.4.1.26027.1.6.1")'
            '(version 3.0; acl "test"; allow (read) userdn="ldap:///self" '
            'and ip="192.168.1.0/24" and dns="*.example.com" '
            'and dayofweek="Mon,Tue,Wed" and timeofday >= "0800" '
            'and authmethod = "ssl" and ssf >= "128";)\n'
            "objectClass: person\n"
            "cn: test\n"
        )
        extensions = self._extensions(self._parse_single(api, ldif_text, c.Tests.OUD))
        assert (
            extensions.get(c.Ldif.ACL_TARGETATTR_FILTERS)
            == "add=cn:(cn=REDACTED_LDAP_BIND_PASSWORD)"
        )
        tm.that(
            extensions.get(c.Ldif.ACL_TARGET_CONTROL), eq="1.3.6.1.4.1.42.2.27.9.5.2"
        )
        tm.that(extensions.get(c.Ldif.ACL_EXTOP), eq="1.3.6.1.4.1.26027.1.6.1")
        tm.that(extensions.get(c.Ldif.ACL_BIND_IP_FILTER), eq="192.168.1.0/24")
        tm.that(extensions.get(c.Ldif.ACL_BIND_DNS), eq="*.example.com")
        tm.that(extensions.get(c.Ldif.ACL_BIND_DAYOFWEEK), eq="Mon,Tue,Wed")
        assert extensions.get(c.Ldif.ACL_BIND_TIMEOFDAY) is not None
        tm.that(extensions.get(c.Ldif.ACL_AUTHMETHOD), eq="ssl")
        assert extensions.get(c.Ldif.ACL_SSF) is not None

    # -- Round-trip preservation (parse -> write -> parse) ----------------

    def test_oid_acl_survives_round_trip(self, api: p.Ldif.LdifClient) -> None:
        """OID ACL metadata is identical after a write/re-parse round-trip."""
        original = (
            "dn: cn=test,dc=example,dc=com\n"
            "orclaci: access to entry by * (browse) bindmode=(Simple) "
            "DenyGroupOverride\n"
            "objectClass: person\n"
            "cn: test\n"
        )
        entry = self._parse_single(api, original, c.Tests.OID)

        write_result = api.write([entry], server_type=c.Tests.OID)
        tm.ok(write_result)
        written = write_result.unwrap().content
        assert written is not None

        reparsed = self._parse_single(api, written, c.Tests.OID)
        extensions = self._extensions(reparsed)
        tm.that(extensions.get(c.Ldif.ACL_BINDMODE), eq="Simple")
        tm.that(extensions.get(c.Ldif.ACL_DENY_GROUP_OVERRIDE), eq=True)

    def test_oud_aci_survives_round_trip(self, api: p.Ldif.LdifClient) -> None:
        """OUD ACI metadata is identical after a write/re-parse round-trip."""
        original = (
            "dn: cn=test,dc=example,dc=com\n"
            'aci: (targetattr="*")(targattrfilters="add=cn:(cn=REDACTED_LDAP_BIND_PASSWORD)")'
            '(version 3.0; acl "test"; allow (read) userdn="ldap:///self" '
            'and ip="192.168.1.0/24";)\n'
            "objectClass: person\n"
            "cn: test\n"
        )
        entry = self._parse_single(api, original, c.Tests.OUD)

        write_result = api.write([entry], server_type=c.Tests.OUD)
        tm.ok(write_result)
        written = write_result.unwrap().content
        assert written is not None

        reparsed = self._parse_single(api, written, c.Tests.OUD)
        extensions = self._extensions(reparsed)
        assert (
            extensions.get(c.Ldif.ACL_TARGETATTR_FILTERS)
            == "add=cn:(cn=REDACTED_LDAP_BIND_PASSWORD)"
        )
        tm.that(extensions.get(c.Ldif.ACL_BIND_IP_FILTER), eq="192.168.1.0/24")
