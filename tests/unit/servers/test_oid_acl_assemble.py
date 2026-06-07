"""Tests for OUD aci-string assembly (AciRule → aci: line)."""

from __future__ import annotations

from flext_tests import tm

from flext_ldif import m
from flext_ldif.servers._oid.acl_assemble import FlextLdifServersOidAclAssemble as Asm


class TestsFlextLdifOidAclAssemble:
    """render_aci_string parity with the algar-oud-mig oracle to_aci_string."""

    def test_entry_two_distinct_perm_allows_with_targetscope(self) -> None:
        aci = m.Ldif.AciRule(
            dn="dc=ctbc",
            targetattr="*",
            targetscope="base",
            acl_name="ctbc Entry by admins",
            allows=(
                m.Ldif.AciAllow(
                    subject_type="groupdn",
                    subject_value="cn=admins,dc=ctbc",
                    permissions=("read", "search", "add", "delete"),
                ),
                m.Ldif.AciAllow(
                    subject_type="userdn",
                    subject_value="anyone",
                    permissions=("read", "search"),
                ),
            ),
        )

        tm.that(
            Asm.render_aci_string(aci),
            eq=(
                'aci: (targetattr="*")(targetscope="base")'
                '(version 3.0; acl "ctbc Entry by admins"; '
                'allow (read, search, add, delete) groupdn="ldap:///cn=admins,dc=ctbc"; '
                'allow (read, search) userdn="ldap:///anyone";)'
            ),
        )

    def test_same_perms_collapse_into_one_or_joined_allow(self) -> None:
        aci = m.Ldif.AciRule(
            dn="dc=ctbc",
            targetattr="cn||sn||mail",
            acl_name="ctbc Attrs by mgr",
            allows=(
                m.Ldif.AciAllow(
                    subject_type="userattr",
                    subject_value="manager#USERDN",
                    permissions=("read", "search"),
                ),
                m.Ldif.AciAllow(
                    subject_type="groupdn",
                    subject_value="cn=g,dc=ctbc",
                    permissions=("read", "search"),
                ),
            ),
        )

        tm.that(
            Asm.render_aci_string(aci),
            eq=(
                'aci: (targetattr="cn||sn||mail")'
                '(version 3.0; acl "ctbc Attrs by mgr"; '
                'allow (read, search) userattr="manager#USERDN" '
                'or groupdn="ldap:///cn=g,dc=ctbc";)'
            ),
        )

    def test_negation_targetattr_and_filter(self) -> None:
        aci = m.Ldif.AciRule(
            dn="dc=ctbc",
            targetattr="!=userpassword",
            targetfilter="objectclass=person",
            acl_name="n",
            allows=(
                m.Ldif.AciAllow(
                    subject_type="userdn",
                    subject_value="self",
                    permissions=("read", "write"),
                ),
            ),
        )

        tm.that(
            Asm.render_aci_string(aci),
            eq=(
                'aci: (targetattr!="userpassword")'
                '(targetfilter="(objectclass=person)")'
                '(version 3.0; acl "n"; allow (read, write) userdn="ldap:///self";)'
            ),
        )

    def test_userattr_bind_omits_ldap_prefix(self) -> None:
        aci = m.Ldif.AciRule(
            dn="dc=ctbc",
            targetattr="*",
            acl_name="x",
            allows=(
                m.Ldif.AciAllow(
                    subject_type="userattr",
                    subject_value="owner#GROUPDN",
                    permissions=("read",),
                ),
            ),
        )

        tm.that(
            Asm.render_aci_string(aci),
            eq=(
                'aci: (targetattr="*")(version 3.0; acl "x"; '
                'allow (read) userattr="owner#GROUPDN";)'
            ),
        )
