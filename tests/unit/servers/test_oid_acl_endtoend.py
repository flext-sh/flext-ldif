"""End-to-end OID→OUD ACL conversion via the public convert_model API.

Asserts that an OID entry's orclaci/orclentrylevelaci attributes convert to
``aci`` values byte-matching the OUD migration oracle ``to_aci_string`` output.
"""

from __future__ import annotations

from flext_tests import tm

from flext_ldif.services.conversion import FlextLdifConversion
from tests.constants import c
from tests.models import m
from tests.protocols import p
from tests.typings import t
from tests.utilities import u


class TestsFlextLdifOidAclEndToEnd:
    """Full pipeline: convert_model('oid','oud', entry) → aci attribute values."""

    @staticmethod
    def _convert(
        api: p.Ldif.LdifClient,
        dn: str,
        attrs: dict[str, list[str]],
    ) -> t.MutableStrSequenceMapping:
        entry = u.Tests.create_real_entry(dn=dn, attributes=attrs)
        result = api.convert_model(
            c.Ldif.ServerTypes.OID,
            c.Ldif.ServerTypes.OUD,
            entry,
        )
        converted = u.Tests.assert_success(result)
        if not isinstance(converted, m.Ldif.Entry) or converted.attributes is None:
            msg = "convert_model did not return an Entry with attributes"
            raise AssertionError(msg)
        return converted.attributes.attributes

    def test_group_with_deny_fallback_entry(self, api: p.Ldif.LdifClient) -> None:
        attrs = self._convert(
            api,
            "cn=users,dc=ctbc",
            {
                "objectClass": ["top"],
                "orclaci": [
                    (
                        'access to entry by group="cn=admins,dc=ctbc" '
                        "(browse,add,delete) by * (none)"
                    ),
                ],
            },
        )

        tm.that("orclaci" not in attrs, eq=True)
        tm.that(
            attrs["aci"],
            eq=[
                (
                    '(targetattr="*")(version 3.0; acl "users Entry by admins"; '
                    "allow (read, search, add, delete) "
                    'groupdn="ldap:///cn=admins,dc=ctbc";)'
                ),
            ],
        )

    def test_attr_list_anyone_pins_targetscope_base(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        attrs = self._convert(
            api,
            "cn=users,dc=ctbc",
            {
                "objectClass": ["top"],
                "orclaci": ["access to attr=(cn,sn,mail) by * (read,search)"],
            },
        )

        tm.that(
            attrs["aci"],
            eq=[
                (
                    '(targetattr="cn||sn||mail")(targetscope="base")'
                    '(version 3.0; acl "users Attrs by anyone"; '
                    'allow (read, search) userdn="ldap:///anyone";)'
                ),
            ],
        )

    def test_dnattr_becomes_userattr(self, api: p.Ldif.LdifClient) -> None:
        attrs = self._convert(
            api,
            "cn=users,dc=ctbc",
            {
                "objectClass": ["top"],
                "orclaci": ["access to entry by dnattr=(manager) (browse)"],
            },
        )

        tm.that(
            attrs["aci"],
            eq=[
                (
                    '(targetattr="*")(version 3.0; acl "users Entry by manager"; '
                    'allow (read, search) userattr="manager#USERDN";)'
                ),
            ],
        )

    def test_orclentrylevelaci_pins_targetscope_base(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        attrs = self._convert(
            api,
            "cn=users,dc=ctbc",
            {
                "objectClass": ["top"],
                "orclentrylevelaci": [
                    'access to entry by group="cn=g,dc=ctbc" (browse)',
                ],
            },
        )

        tm.that("orclentrylevelaci" not in attrs, eq=True)
        tm.that(
            attrs["aci"],
            eq=[
                (
                    '(targetattr="*")(targetscope="base")'
                    '(version 3.0; acl "users Entry by g"; '
                    'allow (read, search) groupdn="ldap:///cn=g,dc=ctbc";)'
                ),
            ],
        )

    def test_base_dn_field_excludes_out_of_scope_bind_dn(self) -> None:
        # FlextLdifConversion(base_dn=...) activates the out-of-scope filter:
        # a bind DN outside base_dn is dropped from the emitted aci.
        entry = u.Tests.create_real_entry(
            dn="cn=users,dc=ctbc",
            attributes={
                "objectClass": ["top"],
                "orclaci": [
                    (
                        'access to entry by group="cn=x,dc=other" (browse) '
                        'by group="cn=a,dc=ctbc" (browse)'
                    ),
                ],
            },
        )
        svc = FlextLdifConversion(base_dn="dc=ctbc")

        converted = u.Tests.assert_success(
            svc.convert_model(c.Ldif.ServerTypes.OID, c.Ldif.ServerTypes.OUD, entry),
        )
        if not isinstance(converted, m.Ldif.Entry) or converted.attributes is None:
            msg = "convert_model did not return an Entry with attributes"
            raise AssertionError(msg)

        tm.that(
            converted.attributes.attributes["aci"],
            eq=[
                (
                    '(targetattr="*")(version 3.0; acl "users Entry by x"; '
                    'allow (read, search) groupdn="ldap:///cn=a,dc=ctbc";)'
                ),
            ],
        )
