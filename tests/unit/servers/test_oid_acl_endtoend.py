"""End-to-end OID→OUD ACL conversion via the public convert_model API.

Asserts that an OID entry's orclaci/orclentrylevelaci attributes convert to
``aci`` values byte-matching the OUD migration oracle ``to_aci_string`` output.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from flext_ldif.services.conversion import FlextLdifConversion
from tests import c, m, u

if TYPE_CHECKING:
    from tests import p, t


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

    @pytest.mark.parametrize(
        ("source_attr", "source_value", "expected_aci"),
        [
            pytest.param(
                "orclaci",
                (
                    'access to entry by group="cn=admins,dc=ctbc" '
                    "(browse,add,delete) by * (none)"
                ),
                '(targetattr="*")(version 3.0; acl "users Entry by admins"; '
                "allow (read, search, add, delete) "
                'groupdn="ldap:///cn=admins,dc=ctbc";)',
                id="group-with-deny-fallback",
            ),
            pytest.param(
                "orclaci",
                "access to attr=(cn,sn,mail) by * (read,search)",
                '(targetattr="cn||sn||mail")(targetscope="base")'
                '(version 3.0; acl "users Attrs by anyone"; '
                'allow (read, search) userdn="ldap:///anyone";)',
                id="attr-list-anyone-pins-targetscope-base",
            ),
            pytest.param(
                "orclaci",
                "access to entry by dnattr=(manager) (browse)",
                '(targetattr="*")(version 3.0; acl "users Entry by manager"; '
                'allow (read, search) userattr="manager#USERDN";)',
                id="dnattr-becomes-userattr",
            ),
            pytest.param(
                "orclentrylevelaci",
                'access to entry by group="cn=g,dc=ctbc" (browse)',
                '(targetattr="*")(targetscope="base")'
                '(version 3.0; acl "users Entry by g"; '
                'allow (read, search) groupdn="ldap:///cn=g,dc=ctbc";)',
                id="orclentrylevelaci-pins-targetscope-base",
            ),
        ],
    )
    def test_oid_acl_converts_to_expected_aci_and_drops_source_attr(
        self,
        api: p.Ldif.LdifClient,
        source_attr: str,
        source_value: str,
        expected_aci: str,
    ) -> None:
        attrs = self._convert(
            api,
            "cn=users,dc=ctbc",
            {"objectClass": ["top"], source_attr: [source_value]},
        )

        # Public contract: the OID source ACL attribute is consumed, not passed
        # through, and a single equivalent OUD ``aci`` value is emitted.
        tm.that(source_attr not in attrs, eq=True)
        tm.that(attrs["aci"], eq=[expected_aci])

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
