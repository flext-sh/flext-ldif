"""Behavioral tests for OID→OUD ACL assembly, rendering, and conversion.

Every assertion exercises observable public contract: rendered ``aci:`` strings,
``r[T]`` success/failure outcomes, and public Pydantic model fields
(``allows``, ``denies``, ``outcomes`` with their ``allow``/``deny`` clauses,
``targetscope``, ``subjects``, ``metadata.acl_conversion``). No private attribute
or method is touched.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from flext_ldif.servers import (
    FlextLdifConstantsServersOid,
    FlextLdifServersOidAclAssemble,
    FlextLdifServersOidAclConvert,
    FlextLdifServersOidAclPipeline,
    FlextLdifServersOidAclRender,
)
from tests import c, m, p, tm, u

_KIND = c.Ldif.AclSubjectOutcomeKind
_GROUPS = FlextLdifServersOidAclPipeline.security_group_dns([
    u.Tests.oid_security_group_entry(dn)
    for dn in (
        "cn=a,dc=ctbc",
        "cn=b,dc=ctbc",
        "cn=admins,dc=ctbc",
        "cn=x,dc=ctbc",
        "cn=x,dc=other",
    )
])
_OPERATIONAL_TARGETATTR = FlextLdifConstantsServersOid.OUD_TARGETATTR_ALL


def _acl_entry(attributes: Mapping[str, Sequence[str]]) -> p.Ldif.Entry:
    """Build one real entry at the shared ACL test DN.

    Returns:
        The resulting ``m.Ldif.Entry``.

    """
    return u.Tests.create_real_entry(dn="cn=users,dc=ctbc", attributes=attributes)


class TestsFlextLdifOidAclAssemble:
    """OID ACL assemble/render/convert public-contract behavior."""

    # ---- helpers -------------------------------------------------------

    @staticmethod
    def _build(dn: str, line: str) -> p.Ldif.AciRule:
        """Parse an OID line then build the OUD AciRule (parse → build).

        Returns:
            The resulting ``m.Ldif.AciRule``.

        """
        rule: p.Ldif.OidAclRule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            dn, line
        ).unwrap()
        aci_rule: p.Ldif.AciRule = FlextLdifServersOidAclAssemble.build_aci_rule(
            rule,
            access_groups=_GROUPS,
        ).unwrap()
        return aci_rule

    # ---- render_aci_strings: AciRule → aci: lines ----------------------

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("aci", "expected"),
        [
            u.Tests.param(
                m.Ldif.AciRule(
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
                ),
                'aci: (targetattr="*")    (targetscope="base")'
                '    (version 3.0; acl "ctbc Entry by admins";'
                "     allow (read, search, add, delete)    "
                'groupdn="ldap:///cn=admins,dc=ctbc";'
                "     allow (read, search)" + " " * 17 + 'userdn="ldap:///anyone";)',
                id="two-distinct-perm-allows-with-targetscope",
            ),
            u.Tests.param(
                m.Ldif.AciRule(
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
                ),
                'aci: (targetattr="cn||sn||mail")'
                '    (version 3.0; acl "ctbc Attrs by mgr";'
                '     allow (read, search)    userattr="manager#USERDN"'
                + " " * 26
                + 'or groupdn="ldap:///cn=g,dc=ctbc";)',
                id="same-perms-collapse-into-one-or-joined-allow",
            ),
            u.Tests.param(
                m.Ldif.AciRule(
                    dn="dc=ctbc",
                    targetattr="*",
                    acl_name="ctbc Entry by admins",
                    allows=(
                        m.Ldif.AciAllow(
                            subject_type="groupdn",
                            subject_value="cn=ssl,dc=ctbc",
                            permissions=("read", "search"),
                            authmethod="SSL",
                        ),
                        m.Ldif.AciAllow(
                            subject_type="groupdn",
                            subject_value="cn=simple,dc=ctbc",
                            permissions=("read", "search"),
                            authmethod="Simple",
                        ),
                    ),
                ),
                'aci: (targetattr="*")    (version 3.0; acl "ctbc Entry by admins";'
                '     allow (read, search)    groupdn="ldap:///cn=ssl,dc=ctbc" '
                'and authmethod="SSL";'
                '     allow (read, search)    groupdn="ldap:///cn=simple,dc=ctbc" '
                'and authmethod="Simple";)',
                id="same-perms-different-modifiers-render-separate-allows",
            ),
            u.Tests.param(
                m.Ldif.AciRule(
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
                ),
                'aci: (targetattr!="userpassword")'
                '    (targetfilter="(objectclass=person)")'
                '    (version 3.0; acl "n";'
                '     allow (read, write)    userdn="ldap:///self";)',
                id="negation-targetattr-and-filter",
            ),
            u.Tests.param(
                m.Ldif.AciRule(
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
                ),
                'aci: (targetattr="*")    (version 3.0; acl "x";'
                '     allow (read)    userattr="owner#GROUPDN";)',
                id="userattr-bind-omits-ldap-prefix",
            ),
        ],
    )
    def test_render_aci_strings_matches_oud_oracle(
        aci: p.Ldif.AciRule,
        expected: str,
    ) -> None:
        """A single-target rule renders exactly the expected ``aci:`` line."""
        tm.that(FlextLdifServersOidAclRender.render_aci_strings(aci), eq=(expected,))

    @staticmethod
    def test_clauses_with_distinct_targetattrs_render_separate_lines() -> None:
        """A clause targetattr override renders its own ``aci:`` line."""
        aci = m.Ldif.AciRule(
            dn="dc=ctbc",
            acl_name="x",
            allows=(
                m.Ldif.AciAllow(
                    subject_type="userdn",
                    subject_value="anyone",
                    permissions=("read", "search"),
                    targetattr="objectClass",
                ),
                m.Ldif.AciAllow(
                    subject_type="userdn",
                    subject_value="anyone",
                    permissions=("add",),
                ),
            ),
        )

        tm.that(
            FlextLdifServersOidAclRender.render_aci_strings(aci),
            eq=(
                (
                    'aci: (targetattr="objectClass")    (version 3.0; acl "x";'
                    '     allow (read, search)    userdn="ldap:///anyone";)'
                ),
                (
                    'aci: (targetattr="*")    (version 3.0; acl "x";'
                    '     allow (add)    userdn="ldap:///anyone";)'
                ),
            ),
        )

    # ---- build_aci_rule: parse → build parity --------------------------

    def test_anyone_none_cancels_every_grant_of_the_rule(self) -> None:
        """``by * (none)`` denies every right to every session of the rule.

        Every session matches ``*``, so the union-minus-denials rule (OID-30
        §30.1.6.2) leaves the group grant nothing, whatever the clause order.
        """
        aci = self._build(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=admins,dc=ctbc" '
            "(browse,add) by * (none)",
        )

        tm.that(aci.allows, eq=())
        tm.ok(aci.targetscope is None)
        tm.that(aci.acl_name, eq="users Entry by admins")
        tm.that(
            [outcome.kind for outcome in aci.outcomes],
            eq=[_KIND.CANCELLED, _KIND.DENIED_ALL],
        )
        tm.that(aci.outcomes[0].allow, eq=None)
        denial = tm.not_none(aci.outcomes[1].deny)
        tm.that(denial.subject_value, eq="anyone")
        tm.that(
            tuple(denial.permissions),
            eq=("read", "search", "add", "delete", "proxy"),
        )
        tm.that(aci.denies[0], eq=denial)
        tm.that(aci.denies[1].targetattr, eq=_OPERATIONAL_TARGETATTR)
        tm.that(tuple(aci.denies[1].permissions), eq=("read", "search", "compare"))

    def test_anyone_attr_rule_pins_targetscope_base(self) -> None:
        """Test anyone attr rule pins targetscope base."""
        aci = self._build(
            "cn=users,dc=ctbc",
            "orclaci: access to attr=(cn,sn,mail) by * (read,search)",
        )

        tm.that(aci.targetattr, eq="cn||sn||mail")
        tm.that(aci.targetscope, eq="base")
        tm.that(aci.allows[0].subject_type, eq="userdn")
        tm.that(aci.allows[0].subject_value, eq="anyone")

    def test_deny_only_rule_yields_empty_allows_with_outcomes(self) -> None:
        """A catch-all ``(none)`` first cancels the later grant the same way."""
        aci = self._build(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by * (none) by group="cn=x,dc=ctbc" (browse)',
        )

        tm.that(aci.allows, eq=())
        tm.that(
            [outcome.kind for outcome in aci.outcomes],
            eq=[_KIND.DENIED_ALL, _KIND.CANCELLED],
        )
        tm.that(len(aci.denies), eq=2)

    def test_mixed_none_list_is_a_total_denial(self) -> None:
        """``(none, nobrowse)`` and ``(browse, none)`` deny every right."""
        for perms in ("none, nobrowse", "browse,none"):
            aci = self._build(
                "cn=users,dc=ctbc",
                f'orclaci: access to entry by * ({perms}) by group="cn=a,dc=ctbc" '
                "(browse)",
            )

            tm.that(
                [outcome.kind for outcome in aci.outcomes],
                eq=[_KIND.DENIED_ALL, _KIND.CANCELLED],
            )
            tm.that(aci.allows, eq=())

    @staticmethod
    def test_guidattr_subject_fails_the_whole_rule() -> None:
        """A guidattr subject has no OUD form; the rule fails, never partial."""
        tm.fail(
            FlextLdifServersOidAclPipeline.convert_acl_values(
                "cn=users,dc=ctbc",
                (
                    (
                        "orclaci: access to entry by guidattr=(orclguid) (nobrowse) "
                        "by * (browse)"
                    ),
                ),
                access_groups=_GROUPS,
            ),
            has="guidattr",
        )

    def test_two_perm_groups_append_plus_count_to_acl_name(self) -> None:
        """Test two perm groups append plus count to acl name."""
        aci = self._build(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" (browse,add) '
            'by group="cn=b,dc=ctbc" (browse)',
        )

        tm.that(len(aci.allows), eq=3)
        tm.ok(aci.acl_name.endswith("(+1)"))

    @staticmethod
    def test_unknown_permission_token_surfaces_failure() -> None:
        """Test unknown permission token surfaces failure."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" (bogus)',
        ).unwrap()

        tm.fail(
            FlextLdifServersOidAclAssemble.build_aci_rule(rule, access_groups=_GROUPS),
            has="Unknown OID permission token",
        )

    @staticmethod
    def test_cross_level_perm_fails_loud() -> None:
        """An attribute right on an entry rule fails instead of granting nothing."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" (read)',
        ).unwrap()

        tm.fail(
            FlextLdifServersOidAclAssemble.build_aci_rule(rule, access_groups=_GROUPS),
            has="not a right of an 'entry' object",
        )

    @staticmethod
    def test_anyone_at_base_dn_is_granted_without_container_policy() -> None:
        """No client container policy is defaulted: ``anyone`` at base is kept."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "dc=ctbc",
            'orclaci: access to entry by * (browse) by group="cn=a,dc=ctbc" (browse)',
        ).unwrap()
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(
            rule,
            base_dn="dc=ctbc",
            access_groups=_GROUPS,
        ).unwrap()

        tm.that(len(aci.allows), eq=2)
        tm.that(aci.allows[0].subject_value, eq="anyone")
        tm.that(aci.targetscope, eq="base")
        tm.that(
            [outcome.kind for outcome in aci.outcomes],
            eq=[_KIND.GRANTED, _KIND.GRANTED],
        )

    @staticmethod
    def test_out_of_scope_dn_is_excluded() -> None:
        """Test out of scope dn is excluded."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=x,dc=other" (browse)',
        ).unwrap()
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(
            rule,
            base_dn="dc=ctbc",
            access_groups=_GROUPS,
        ).unwrap()

        tm.that(aci.allows, eq=())
        tm.that(aci.outcomes[0].kind, eq=_KIND.OUT_OF_SCOPE)
        tm.that(aci.outcomes[0].display_value, eq="cn=x,dc=other")

    @staticmethod
    def test_regex_dn_converts_to_wildcard_in_scope() -> None:
        """Test regex dn converts to wildcard in scope."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by dn=".*,dc=ctbc" (browse)',
        ).unwrap()
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(
            rule,
            base_dn="dc=ctbc",
            access_groups=_GROUPS,
        ).unwrap()

        tm.that(len(aci.allows), eq=1)
        tm.that(aci.allows[0].subject_value, eq="**,dc=ctbc")
        tm.ok(aci.outcomes[0].wildcard_rewritten)

    @staticmethod
    def test_no_base_dn_skips_scope_filtering() -> None:
        """Test no base dn skips scope filtering."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=x,dc=other" (browse)',
        ).unwrap()
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(
            rule, access_groups=_GROUPS
        ).unwrap()

        tm.that(len(aci.allows), eq=1)

    # ---- convert_acl_values: OID lines → deduped aci values ------------

    @staticmethod
    def test_multiple_lines_produce_aci_values_without_prefix() -> None:
        """Test multiple lines produce aci values without prefix."""
        result = FlextLdifServersOidAclPipeline.convert_acl_values(
            "cn=users,dc=ctbc",
            (
                'orclaci: access to entry by group="cn=a,dc=ctbc" (browse)',
                "orclentrylevelaci: access to attr=(cn) by * (read)",
            ),
            access_groups=_GROUPS,
        )

        values = result.unwrap()
        tm.that(len(values), eq=2)
        tm.ok(all(not v.startswith("aci: ") for v in values))
        tm.ok(values[0].startswith('(targetattr="objectClass")'))

    @staticmethod
    def test_identical_aci_values_are_deduplicated() -> None:
        """Test identical aci values are deduplicated."""
        line = 'orclaci: access to entry by group="cn=a,dc=ctbc" (browse)'
        result = FlextLdifServersOidAclPipeline.convert_acl_values(
            "cn=users,dc=ctbc",
            (line, line),
            access_groups=_GROUPS,
        )

        tm.that(len(result.unwrap()), eq=1)

    @staticmethod
    def test_deny_only_line_emits_deny_value() -> None:
        """A denial is rendered as an OUD ``deny`` clause, never dropped."""
        result = FlextLdifServersOidAclPipeline.convert_acl_values(
            "cn=users,dc=ctbc",
            ("orclaci: access to entry by * (none)",),
            access_groups=_GROUPS,
        )

        tm.that(
            result.unwrap(),
            eq=(
                (
                    '(targetattr="*")    (version 3.0; acl "users Entry by anyone";'
                    "     deny (read, search, add, delete, proxy)    "
                    'userdn="ldap:///anyone";)'
                ),
                (
                    f'(targetattr="{_OPERATIONAL_TARGETATTR}")'
                    '    (version 3.0; acl "users Entry by anyone";'
                    '     deny (read, search, compare)    userdn="ldap:///anyone";)'
                ),
            ),
        )

    @staticmethod
    def test_malformed_line_surfaces_failure() -> None:
        """Test malformed line surfaces failure."""
        result = FlextLdifServersOidAclPipeline.convert_acl_values(
            "cn=users,dc=ctbc",
            ("orclaci: this is not a valid acl",),
            access_groups=_GROUPS,
        )

        tm.fail(result, has="missing 'access to'")


class TestsFlextLdifOidAclDenials:
    """Explicit OID denials and untranslatable constructs (bead flext-ws7iv).

    Each OID access level is granted or denied on its own and ``noxxx``
    denies ``xxx`` (OID 12.2.1.3 §30.1.4.3); denials surface as typed
    ``deny`` clauses, never as a complement grant.
    """

    @staticmethod
    def _build(dn: str, line: str) -> p.Ldif.AciRule:
        """Parse an OID line then build the OUD AciRule (parse → build).

        Returns:
            The resulting ``m.Ldif.AciRule``.

        """
        rule: p.Ldif.OidAclRule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            dn, line
        ).unwrap()
        aci_rule: p.Ldif.AciRule = FlextLdifServersOidAclAssemble.build_aci_rule(
            rule,
            access_groups=_GROUPS,
        ).unwrap()
        return aci_rule

    def test_subject_none_is_typed_total_denial(self) -> None:
        """``by group (none)`` surfaces as DENIED_ALL, never a silent drop."""
        aci = self._build(
            "cn=users,dc=ctbc",
            'orclaci: access to attr=(cn) by group="cn=x,dc=ctbc" (none) '
            "by self (read)",
        )

        tm.that(
            [outcome.kind for outcome in aci.outcomes],
            eq=[_KIND.DENIED_ALL, _KIND.GRANTED],
        )
        denial = tm.not_none(aci.outcomes[0].deny)
        tm.that(denial.subject_type, eq="groupdn")
        tm.that(
            tuple(denial.permissions),
            eq=("read", "search", "write", "selfwrite", "compare"),
        )

    def test_pure_negation_clause_denies_and_grants_nothing(self) -> None:
        """``by * (nobrowse,noadd,nodelete)`` emits no allow (OID-30 §30.1.4.3)."""
        aci = self._build(
            "cn=users,dc=ctbc",
            "orclaci: access to entry by * (nobrowse,noadd,nodelete)",
        )

        tm.that(aci.allows, eq=())
        tm.that(aci.outcomes[0].kind, eq=_KIND.DENIED)
        tm.that(aci.outcomes[0].allow, eq=None)
        tm.that(
            tuple(tm.not_none(aci.outcomes[0].deny).permissions),
            eq=("read", "search", "add", "delete"),
        )
        tm.that(aci.targetscope, eq=None)

    def test_mixed_clause_grants_positive_and_denies_negation(self) -> None:
        """``(add,nodelete)`` grants add to authenticated sessions, denies delete."""
        aci = self._build(
            "cn=users,dc=ctbc",
            "orclaci: access to entry by * (add,nodelete)",
        )

        tm.that(tuple(aci.allows[0].permissions), eq=("add",))
        tm.that(aci.allows[0].subject_value, eq="all")
        tm.that(aci.outcomes[0].kind, eq=_KIND.GRANTED)
        tm.that(aci.targetscope, eq=None)
        tm.that(tuple(aci.denies[0].permissions), eq=("delete",))
        tm.that(aci.denies[0].subject_value, eq="anyone")
        tm.that(
            FlextLdifServersOidAclRender.render_aci_strings(aci),
            eq=(
                (
                    'aci: (targetattr="*")'
                    '    (version 3.0; acl "users Entry by anyone";'
                    '     allow (add)      userdn="ldap:///all";'
                    '     deny (delete)    userdn="ldap:///anyone";)'
                ),
            ),
        )

    @staticmethod
    def test_entry_browse_grant_fails_loud() -> None:
        """OID browse exposes the DN only; OUD has no exact right for it."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            "orclaci: access to entry by * (browse,noadd)",
        ).unwrap()
        tm.fail(
            FlextLdifServersOidAclAssemble.build_aci_rule(rule),
            has="exposes the DN only",
        )

    @staticmethod
    def test_negation_only_subject_never_receives_complement_grant() -> None:
        """A ``* (noread)`` denies read to all; no complement grant appears."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to attr=(cn) by group="cn=a,dc=ctbc" (read,search) '
            "by * (noread)",
        ).unwrap()
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(
            rule, access_groups=_GROUPS
        ).unwrap()

        tm.that(len(aci.allows), eq=1)
        tm.that(tuple(aci.allows[0].permissions), eq=("search",))
        tm.that(
            [outcome.kind for outcome in aci.outcomes],
            eq=[_KIND.GRANTED, _KIND.DENIED],
        )
        tm.that(tuple(aci.denies[0].permissions), eq=("read",))
        tm.that(aci.target_type, eq="attr")

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("line", "message"),
        [
            u.Tests.param(
                'orclaci: access to entry by group="cn=a,dc=ctbc" '
                "bindmode=(Simple) (browse)",
                "bindmode",
                id="bindmode",
            ),
            u.Tests.param(
                'orclaci: access to entry by group="cn=a,dc=ctbc" '
                "bindipfilter=(&(orclipaddress!=1.2.*)(orclipaddress!=3.4.*)) "
                "(browse)",
                "bindipfilter",
                id="bindipfilter-complex",
            ),
            u.Tests.param(
                "orclentrylevelaci: access to entry by * (browse,noadd) "
                "DenyGroupOverride",
                "DenyGroupOverride",
                id="deny-group-override",
            ),
            u.Tests.param(
                'orclaci: access to entry by group="cn=a,dc=ctbc" (browse) AppendToAll',
                "AppendToAll",
                id="append-to-all",
            ),
            u.Tests.param(
                'orclaci: access to entry by dn="cn=a[0-9],dc=ctbc" (browse)',
                "no exact OUD wildcard",
                id="regex-dn",
            ),
            u.Tests.param(
                'orclaci: access to entry by group="cn=a,dc=ctbc" '
                "added_object_constraint=(objectclass=person) (browse,add)",
                "added_object_constraint",
                id="added-object-constraint",
            ),
            u.Tests.param(
                "orclaci: access to entry by dnattr=(manager) (browse) "
                "bindmode=(Simple)",
                "bindmode",
                id="dnattr-trailing-bindmode",
            ),
            u.Tests.param(
                "orclaci: access to entry by groupattr=(owner) bindmode=(Simple) "
                "(browse)",
                "bindmode",
                id="groupattr-leading-bindmode",
            ),
            u.Tests.param(
                "orclaci: access to entry by SuperUser (browse) bindmode=(Simple)",
                "bindmode",
                id="superuser-bindmode",
            ),
            u.Tests.param(
                'orclaci: access to entry by group="cn=a,dc=ctbc" (browse) '
                "by dn=cn=x,dc=ctbc (nobrowse)",
                "Unrecognized OID ACL text",
                id="unrecognized-second-clause",
            ),
            u.Tests.param(
                'orclaci: access to entry by group="cn=a,dc=ctbc" (browse) '
                'by group="cn=b,dc=ctbc" bindmode=Simple (browse)',
                "Unrecognized OID ACL text",
                id="unparenthesized-modifier",
            ),
            u.Tests.param(
                "orclaci: access to entry by * (browse) by bogus",
                "Unrecognized OID ACL text",
                id="trailing-garbage",
            ),
            u.Tests.param(
                'orclaci: access to entry by dn="cn=adm*,dc=ctbc" (browse)',
                "no exact OUD wildcard",
                id="bare-star-quantifier",
            ),
            u.Tests.param(
                'orclaci: access to entry by group="cn=.*,dc=ctbc" (browse)',
                "no exact OUD groupdn",
                id="wildcard-group",
            ),
            u.Tests.param(
                "orclaci: access to attr=(*) by * (all)",
                "'all'",
                id="all-token",
            ),
            u.Tests.param(
                "orclaci: access to entry by * bindipfilter=(orclipaddress=1.1.1.1) "
                "bindipfilter=(orclipaddress=2.2.2.2) (browse)",
                "Repeated OID 'bindipfilter'",
                id="repeated-modifier",
            ),
            u.Tests.param(
                "orclaci: access to entry by * bindipfilter=() (browse)",
                "Empty OID 'bindipfilter'",
                id="empty-bindipfilter",
            ),
            u.Tests.param(
                "orclaci: access to entry by * (browse,)",
                "Empty token",
                id="empty-permission-token",
            ),
            u.Tests.param(
                "orclaci: access to attr=() by * (read)",
                "is not '*' or a list",
                id="empty-attr-list",
            ),
            u.Tests.param(
                "orclaci: access to attr=(cn,*) by * (read)",
                "is not '*' or a list",
                id="star-inside-attr-list",
            ),
            u.Tests.param(
                'orclaci: access to entry filter=(cn=a"b) by * (browse)',
                "carries a quote",
                id="quote-in-filter",
            ),
            u.Tests.param(
                "orclaci: access to entry by dnattr=(manager, owner) (browse)",
                "is not one attribute description",
                id="dnattr-list",
            ),
            u.Tests.param(
                'orclaci: access to entry by group="cn=other,dc=ctbc" (browse)',
                "not a verified security group",
                id="unverified-group",
            ),
        ],
    )
    def test_untranslatable_construct_fails_loud(line: str, message: str) -> None:
        """Constructs without an exact OUD form fail; none passes raw or silent."""
        tm.fail(
            FlextLdifServersOidAclPipeline.convert_acl_values(
                "cn=users,dc=ctbc",
                (line,),
                access_groups=_GROUPS,
            ),
            has=message,
        )

    @staticmethod
    def test_out_of_scope_denial_fails_instead_of_dropping() -> None:
        """A denial bound outside base_dn fails; its grants never survive alone."""
        tm.fail(
            FlextLdifServersOidAclPipeline.convert_acl_values(
                "cn=users,dc=ctbc",
                (
                    (
                        'orclaci: access to entry by group="cn=x,dc=other" (nobrowse) '
                        "by * (browse)"
                    ),
                ),
                base_dn="dc=ctbc",
                access_groups=_GROUPS,
            ),
            has="cannot be dropped",
        )

    def test_conditional_catch_all_denial_keeps_other_grants(self) -> None:
        """A ``*`` denial limited by an ip only denies sessions from that ip."""
        aci = self._build(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" (browse) '
            "by * bindipfilter=(orclipaddress=9.9.9.9) (none)",
        )

        tm.that(
            [outcome.kind for outcome in aci.outcomes],
            eq=[_KIND.GRANTED, _KIND.DENIED_ALL],
        )
        tm.that(tuple(aci.allows[0].permissions), eq=("read", "search"))
        tm.that(aci.denies[0].ip, eq="9.9.9.9")

    @staticmethod
    def test_entry_level_add_renders_under_onelevel_scope() -> None:
        """Entry-level ``add`` targets the children; other rights stay base."""
        result = FlextLdifServersOidAclPipeline.convert_acl_values(
            "cn=users,dc=ctbc",
            (
                (
                    'orclentrylevelaci: access to entry by group="cn=a,dc=ctbc" '
                    "(browse,add,nodelete)"
                ),
            ),
            access_groups=_GROUPS,
        )

        tm.that(
            result.unwrap(),
            eq=(
                (
                    '(targetattr="objectClass")    (targetscope="base")'
                    '    (version 3.0; acl "users Entry by a";'
                    '     allow (read, search)    groupdn="ldap:///cn=a,dc=ctbc";)'
                ),
                (
                    '(targetattr="*")    (targetscope="onelevel")'
                    '    (version 3.0; acl "users Entry by a";'
                    '     allow (add)    groupdn="ldap:///cn=a,dc=ctbc";)'
                ),
                (
                    '(targetattr="*")    (targetscope="base")'
                    '    (version 3.0; acl "users Entry by a";'
                    '     deny (delete)    groupdn="ldap:///cn=a,dc=ctbc";)'
                ),
            ),
        )

    @staticmethod
    def test_bindipfilter_becomes_oud_ip() -> None:
        """An orclipaddress prefix filter becomes the OUD ip bind constraint."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" '
            "bindipfilter=(orclipaddress=10.0.*) (browse,add)",
        ).unwrap()

        tm.that(rule.subjects[0].bindipfilter, eq="orclipaddress=10.0.*")
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(
            rule, access_groups=_GROUPS
        ).unwrap()
        tm.that(aci.allows[0].ip, eq="10.0.*.*")
        tm.that(
            FlextLdifServersOidAclRender.render_aci_strings(aci),
            eq=(
                (
                    'aci: (targetattr="objectClass")'
                    '    (version 3.0; acl "users Entry by a";'
                    '     allow (read, search)    groupdn="ldap:///cn=a,dc=ctbc" '
                    'and ip="10.0.*.*";)'
                ),
                (
                    'aci: (targetattr="*")    (version 3.0; acl "users Entry by a";'
                    '     allow (add)    groupdn="ldap:///cn=a,dc=ctbc" '
                    'and ip="10.0.*.*";)'
                ),
            ),
        )


class TestsFlextLdifOidAclFixtureAndEntry:
    """OID ACL fixture conversion and entry-level orclaci conversion."""

    @staticmethod
    def test_oid_acl_fixture_lines_convert_or_fail_loud() -> None:
        """Each fixture line converts, or fails loud on an untranslatable form.

        bindmode, DenyGroupOverride, AppendToAll, added-object constraints,
        guidattr, misplaced text and rights of the other object kind have no
        exact OUD form and surface as typed failures, never raw output.
        """
        fixture_path = (
            Path(__file__).parents[2] / "fixtures" / "oid" / "oid_acl_fixtures.ldif"
        )
        dn = ""
        rules_seen = 0
        failures = 0
        values_emitted = 0
        for line in fixture_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("dn:"):
                dn = line.removeprefix("dn:").strip()
                continue
            if not line.startswith(("orclaci:", "orclentrylevelaci:")):
                continue
            result = FlextLdifServersOidAclPipeline.convert_acl_values(
                dn,
                (line,),
                base_dn="dc=example,dc=com",
                access_groups=_GROUPS,
            )
            rules_seen += 1
            if result.failure:
                failures += 1
                tm.that(result.error, contains="manual review required")
                continue
            values_emitted += len(result.unwrap())

        tm.that(rules_seen, eq=16)
        tm.that(failures, eq=13)
        tm.that(values_emitted, eq=5)

    @staticmethod
    def test_out_of_scope_dn_excluded_with_base_dn() -> None:
        """Test out of scope dn excluded with base dn."""
        result = FlextLdifServersOidAclPipeline.convert_acl_values(
            "cn=users,dc=ctbc",
            ('orclaci: access to entry by group="cn=x,dc=other" (browse)',),
            base_dn="dc=ctbc",
            access_groups=_GROUPS,
        )

        tm.that(result.unwrap(), eq=())

    @staticmethod
    def test_entry_conversion_records_typed_outcomes_on_metadata() -> None:
        """convert_entry_acls records per-subject outcomes on entry metadata."""
        entry = _acl_entry({
            "orclaci": [
                ('access to entry by group="cn=a,dc=ctbc" (browse) by * (none)'),
            ],
        })

        converted = FlextLdifServersOidAclPipeline.convert_entry_acls(
            entry,
            "oid",
            "oud",
            access_groups=_GROUPS,
        ).unwrap()
        conversion = tm.not_none(tm.not_none(converted.metadata).acl_conversion)

        tm.fail(conversion.oracle_internal_skip)
        tm.that(
            [outcome.kind for outcome in conversion.rules[0].outcomes],
            eq=[_KIND.CANCELLED, _KIND.DENIED_ALL],
        )

    @staticmethod
    def test_oracle_internal_dn_records_skip_without_aci() -> None:
        """An Oracle-internal DN loses its OID ACLs and records the skip."""
        entry = u.Tests.create_real_entry(
            dn="cn=orclaci,cn=users,dc=ctbc",
            attributes={
                "orclaci": ['access to entry by group="cn=a,dc=ctbc" (browse)'],
            },
        )

        converted = FlextLdifServersOidAclPipeline.convert_entry_acls(
            entry,
            "oid",
            "oud",
            access_groups=_GROUPS,
        ).unwrap()
        conversion = tm.not_none(tm.not_none(converted.metadata).acl_conversion)

        tm.ok(conversion.oracle_internal_skip)
        tm.that(conversion.rules, eq=())
        tm.that(tm.not_none(converted.attributes).attributes, lacks="aci")

    # ---- convert_entry_acls: entry orclaci → aci attribute -------------

    @staticmethod
    def test_oid_to_oud_replaces_orclaci_with_aci() -> None:
        """Test oid to oud replaces orclaci with aci."""
        entry = _acl_entry({
            "objectClass": ["top"],
            "orclaci": ['access to entry by group="cn=a,dc=ctbc" (browse)'],
        })

        converted = FlextLdifServersOidAclPipeline.convert_entry_acls(
            entry,
            "oid",
            "oud",
            access_groups=_GROUPS,
        ).unwrap()
        attrs = tm.not_none(converted.attributes).attributes

        tm.ok("orclaci" not in attrs)
        tm.ok("aci" in attrs)
        tm.that(len(attrs["aci"]), eq=1)
        tm.ok(attrs["aci"][0].startswith('(targetattr="objectClass")'))

    @staticmethod
    def test_non_oid_to_oud_passes_through_unchanged() -> None:
        """Test non oid to oud passes through unchanged."""
        entry = _acl_entry({
            "orclaci": ['access to entry by group="cn=a,dc=ctbc" (browse)'],
        })

        converted = FlextLdifServersOidAclPipeline.convert_entry_acls(
            entry,
            "oid",
            "rfc",
            access_groups=_GROUPS,
        ).unwrap()
        tm.ok("orclaci" in tm.not_none(converted.attributes).attributes)

    @staticmethod
    def test_entry_without_acl_attrs_unchanged() -> None:
        """Test entry without acl attrs unchanged."""
        entry = _acl_entry({"cn": ["x"], "objectClass": ["top"]})

        converted = FlextLdifServersOidAclPipeline.convert_entry_acls(
            entry,
            "oid",
            "oud",
            access_groups=_GROUPS,
        ).unwrap()
        attrs = tm.not_none(converted.attributes).attributes

        tm.ok("aci" not in attrs)
        tm.ok("cn" in attrs)

    @staticmethod
    def test_malformed_acl_surfaces_failure() -> None:
        """Test malformed acl surfaces failure."""
        entry = _acl_entry({"orclaci": ["not a valid acl"]})

        tm.fail(
            FlextLdifServersOidAclPipeline.convert_entry_acls(
                entry, "oid", "oud", access_groups=_GROUPS
            ),
            has="missing 'access to'",
        )

    @staticmethod
    def test_unknown_perm_token_surfaces_failure() -> None:
        """Test unknown perm token surfaces failure."""
        result = FlextLdifServersOidAclPipeline.convert_acl_values(
            "cn=users,dc=ctbc",
            ('orclaci: access to entry by group="cn=a,dc=ctbc" (bogus)',),
            access_groups=_GROUPS,
        )

        tm.fail(result, has="Unknown OID permission token")
