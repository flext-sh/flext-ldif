"""Tests for OUD aci-string assembly (AciRule → aci: line)."""

from __future__ import annotations

from flext_tests import tm

from flext_ldif import m
from flext_ldif.servers._oid.acl_assemble import FlextLdifServersOidAclAssemble as Asm
from flext_ldif.servers._oid.acl_convert import FlextLdifServersOidAclConvert as Parser


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


class TestsFlextLdifOidAclBuild:
    """build_aci_rule end-to-end parity with the oracle (parse → build → render)."""

    @staticmethod
    def _build(dn: str, line: str) -> m.Ldif.AciRule:
        rule = Parser.parse_oid_acl_line(dn, line).unwrap()
        return Asm.build_aci_rule(rule).unwrap()

    def test_group_with_deny_fallback_keeps_group_drops_anyone(self) -> None:
        aci = self._build(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=admins,dc=ctbc" '
            "(browse,add) by * (none)",
        )

        tm.that(len(aci.allows), eq=1)
        tm.that(aci.allows[0].subject_type, eq="groupdn")
        tm.that(aci.allows[0].permissions, eq=("read", "search", "add"))
        tm.that(aci.targetscope is None, eq=True)
        tm.that(aci.acl_name, eq="users Entry by admins")
        tm.that(any("default-deny" in note for note in aci.notes), eq=True)

    def test_anyone_attr_rule_pins_targetscope_base(self) -> None:
        aci = self._build(
            "cn=users,dc=ctbc",
            "orclaci: access to attr=(cn,sn,mail) by * (read,search)",
        )

        tm.that(aci.targetattr, eq="cn||sn||mail")
        tm.that(aci.targetscope, eq="base")
        tm.that(aci.allows[0].subject_type, eq="userdn")
        tm.that(aci.allows[0].subject_value, eq="anyone")

    def test_deny_only_rule_yields_empty_allows_with_notes(self) -> None:
        aci = self._build(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by * (none) by group="cn=x,dc=ctbc" (browse)',
        )

        tm.that(aci.allows, eq=())
        tm.that(any("dead code" in note for note in aci.notes), eq=True)

    def test_guidattr_dropped_with_note_other_subject_survives(self) -> None:
        aci = self._build(
            "cn=users,dc=ctbc",
            "orclaci: access to entry by guidattr=(orclguid) (browse) "
            'by group="cn=a,dc=ctbc" (browse)',
        )

        tm.that(len(aci.allows), eq=1)
        tm.that(aci.allows[0].subject_type, eq="groupdn")
        tm.that(any("guidattr" in note for note in aci.notes), eq=True)

    def test_two_perm_groups_append_plus_count_to_acl_name(self) -> None:
        aci = self._build(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" (browse,add) '
            'by group="cn=b,dc=ctbc" (browse)',
        )

        tm.that(len(aci.allows), eq=2)
        tm.that(aci.acl_name.endswith("(+1)"), eq=True)

    def test_unknown_permission_token_surfaces_failure(self) -> None:
        rule = Parser.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" (bogus)',
        ).unwrap()

        tm.that(Asm.build_aci_rule(rule).failure, eq=True)
