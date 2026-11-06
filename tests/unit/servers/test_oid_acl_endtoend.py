"""End-to-end OID→OUD ACL conversion via the public convert_model API.

Asserts that an OID entry's orclaci/orclentrylevelaci attributes convert to
the expected ``aci`` values. Group subjects convert only for the security
groups the conversion service is given.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from flext_ldif import FlextLdif
from flext_ldif.servers import FlextLdifServersOidAclPipeline
from flext_ldif.services import FlextLdifConversion
from tests import c, m, t, tm, u


class TestsFlextLdifOidAclEndToEnd:
    """Full pipeline: convert_model('oid','oud', entry) → aci attribute values."""

    @staticmethod
    def _access_groups() -> frozenset[str]:
        """Return the access groups proven by real ACP group entries."""
        return FlextLdifServersOidAclPipeline.security_group_dns([
            u.Tests.oid_security_group_entry("cn=admins,dc=ctbc"),
            u.Tests.oid_security_group_entry("cn=g,dc=ctbc"),
            u.Tests.oid_security_group_entry("cn=a,dc=ctbc"),
        ])

    @classmethod
    def _convert(
        cls,
        dn: str,
        attrs: Mapping[str, Sequence[str]],
    ) -> t.MutableStrSequenceMapping:
        entry = u.Tests.create_real_entry(dn=dn, attributes=attrs)
        service = FlextLdifConversion(
            registry=FlextLdif().registry,
            access_groups=cls._access_groups(),
        )
        result = service.convert_model(
            c.Ldif.ServerTypes.OID,
            c.Ldif.ServerTypes.OUD,
            entry,
        )
        converted = u.Tests.assert_success(result)
        if not isinstance(converted, m.Ldif.Entry) or converted.attributes is None:
            msg = "convert_model did not return an Entry with attributes"
            tm.reject(msg)
        return converted.attributes.attributes

    @c.Tests.MARK.parametrize(
        ("source_attr", "source_value", "expected_acis"),
        [
            u.Tests.param(
                "orclaci",
                (
                    'access to entry by group="cn=admins,dc=ctbc" '
                    "(browse,add,delete) by * (none)"
                ),
                (
                    (
                        '(targetattr="*")    (version 3.0; acl "users Entry by admins";'
                        "     deny (read, search, add, delete, proxy)    "
                        'userdn="ldap:///anyone";)'
                    ),
                    (
                        '(targetattr="createTimestamp||creatorsName||modifiersName'
                        "||modifyTimestamp||entryDN||entryUUID||subschemaSubentry"
                        '||orclguid||nsuniqueid")'
                        '    (version 3.0; acl "users Entry by admins";'
                        '     deny (read, search, compare)    userdn="ldap:///anyone";)'
                    ),
                ),
                id="catch-all-none-cancels-group-grant",
            ),
            u.Tests.param(
                "orclaci",
                "access to attr=(cn,sn,mail) by * (read,search)",
                (
                    (
                        '(targetattr="cn||sn||mail")    (targetscope="base")'
                        '    (version 3.0; acl "users Attrs by anyone";'
                        '     allow (read, search)    userdn="ldap:///anyone";)'
                    ),
                ),
                id="attr-list-anyone-pins-targetscope-base",
            ),
            u.Tests.param(
                "orclaci",
                "access to entry by dnattr=(manager) (browse)",
                (
                    (
                        '(targetattr="objectClass")'
                        '    (version 3.0; acl "users Entry by manager";'
                        '     allow (read, search)    userattr="manager#USERDN";)'
                    ),
                ),
                id="dnattr-becomes-userattr",
            ),
            u.Tests.param(
                "orclentrylevelaci",
                'access to entry by group="cn=g,dc=ctbc" (browse)',
                (
                    (
                        '(targetattr="objectClass")    (targetscope="base")'
                        '    (version 3.0; acl "users Entry by g";'
                        '     allow (read, search)    groupdn="ldap:///cn=g,dc=ctbc";)'
                    ),
                ),
                id="orclentrylevelaci-pins-targetscope-base",
            ),
        ],
    )
    def test_oid_acl_converts_to_expected_aci_and_drops_source_attr(
        self,
        source_attr: str,
        source_value: str,
        expected_acis: tuple[str, ...],
    ) -> None:
        """Test oid acl converts to expected aci and drops source attr."""
        attrs = self._convert(
            "cn=users,dc=ctbc",
            {"objectClass": ["top"], source_attr: [source_value]},
        )

        # Public contract: the OID source ACL attribute is consumed, not passed
        # through, and the equivalent OUD ``aci`` values are emitted.
        tm.ok(source_attr not in attrs)
        tm.that(attrs["aci"], eq=list(expected_acis))

    def test_base_dn_field_excludes_out_of_scope_bind_dn(self) -> None:
        # FlextLdifConversion(base_dn=...) activates the out-of-scope filter:
        # a bind DN outside base_dn is dropped from the emitted aci.
        """Test base dn field excludes out of scope bind dn."""
        entry = u.Tests.orclaci_base_dn_entry(dn="cn=users,dc=ctbc")
        svc = FlextLdifConversion(
            registry=FlextLdif().registry,
            base_dn="dc=ctbc",
            access_groups=self._access_groups(),
        )

        converted = u.Tests.assert_success(
            svc.convert_model(c.Ldif.ServerTypes.OID, c.Ldif.ServerTypes.OUD, entry),
        )
        if not isinstance(converted, m.Ldif.Entry) or converted.attributes is None:
            msg = "convert_model did not return an Entry with attributes"
            tm.reject(msg)

        tm.that(
            converted.attributes.attributes["aci"],
            eq=[
                (
                    '(targetattr="objectClass")'
                    '    (version 3.0; acl "users Entry by x";'
                    '     allow (read, search)    groupdn="ldap:///cn=a,dc=ctbc";)'
                ),
            ],
        )
