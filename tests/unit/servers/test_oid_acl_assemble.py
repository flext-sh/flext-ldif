"""Behavioral tests for OID→OUD ACL assembly, rendering, and conversion.

Every assertion exercises observable public contract: rendered ``aci:`` strings,
``r[T]`` success/failure outcomes, and public Pydantic model fields
(``allows``, ``outcomes`` with their ``complement_calculated`` flags,
``targetscope``, ``subjects``, ``metadata.acl_conversion``). No private attribute
or method is touched.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import Sequence
from pathlib import Path

import pytest

from flext_ldif.servers import (
    FlextLdifServersOidAclAssemble,
    FlextLdifServersOidAclConvert,
    FlextLdifServersOidAclPipeline,
    FlextLdifServersOidAclRender,
)
from tests import c, m, tm, u

_KIND = c.Ldif.AclSubjectOutcomeKind


def _acl_entry(attributes: Mapping[str, Sequence[str]]) -> m.Ldif.Entry:
    """Build one real entry at the shared ACL test DN.

    Returns:
        The resulting ``m.Ldif.Entry``.

    """
    return u.Tests.create_real_entry(dn="cn=users,dc=ctbc", attributes=attributes)


class TestsFlextLdifOidAclAssemble:
    """OID ACL assemble/render/convert public-contract behavior."""

    # ---- helpers -------------------------------------------------------

    @staticmethod
    def _build(dn: str, line: str) -> m.Ldif.AciRule:
        """Parse an OID line then build the OUD AciRule (parse → build).

        Returns:
            The resulting ``m.Ldif.AciRule``.

        """
        rule: m.Ldif.OidAclRule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            dn, line
        ).unwrap()
        aci_rule: m.Ldif.AciRule = FlextLdifServersOidAclAssemble.build_aci_rule(
            rule
        ).unwrap()
        return aci_rule

    # ---- render_aci_string: AciRule → aci: line ------------------------

    @staticmethod
    @pytest.mark.parametrize(
        ("aci", "expected"),
        [
            pytest.param(
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
            pytest.param(
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
            pytest.param(
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
            pytest.param(
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
            pytest.param(
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
    def test_render_aci_string_matches_oud_oracle(
        aci: m.Ldif.AciRule,
        expected: str,
    ) -> None:
        """Test render aci string matches oud oracle."""
        tm.that(FlextLdifServersOidAclRender.render_aci_string(aci), eq=expected)

    # ---- build_aci_rule: parse → build parity --------------------------

    def test_group_with_deny_fallback_keeps_group_drops_anyone(self) -> None:
        """Test group with deny fallback keeps group drops anyone."""
        aci = self._build(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=admins,dc=ctbc" '
            "(browse,add) by * (none)",
        )

        tm.that(len(aci.allows), eq=1)
        tm.that(aci.allows[0].subject_type, eq="groupdn")
        tm.that(aci.allows[0].permissions, eq=("read", "search", "add"))
        tm.ok(aci.targetscope is None)
        tm.that(aci.acl_name, eq="users Entry by admins")
        tm.that(
            [outcome.kind for outcome in aci.outcomes],
            eq=[_KIND.GRANTED, _KIND.EXCLUDED_DENY_NONE],
        )
        tm.that(aci.outcomes[0].allow, eq=aci.allows[0])

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
        """A deny-first rule grants nothing and dead-codes the later subject."""
        aci = self._build(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by * (none) by group="cn=x,dc=ctbc" (browse)',
        )

        tm.that(aci.allows, eq=())
        tm.that(
            [outcome.kind for outcome in aci.outcomes],
            eq=[_KIND.EXCLUDED_DENY_NONE, _KIND.EXCLUDED_DEAD_CODE],
        )

    def test_guidattr_unsupported_other_subject_survives(self) -> None:
        """A guidattr subject is UNSUPPORTED while the other subject is granted."""
        aci = self._build(
            "cn=users,dc=ctbc",
            "orclaci: access to entry by guidattr=(orclguid) (browse) "
            'by group="cn=a,dc=ctbc" (browse)',
        )

        tm.that(len(aci.allows), eq=1)
        tm.that(aci.allows[0].subject_type, eq="groupdn")
        tm.that(
            [outcome.kind for outcome in aci.outcomes],
            eq=[_KIND.UNSUPPORTED, _KIND.GRANTED],
        )
        tm.that(aci.outcomes[0].subject.subject_type, eq="guidattr")

    def test_two_perm_groups_append_plus_count_to_acl_name(self) -> None:
        """Test two perm groups append plus count to acl name."""
        aci = self._build(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" (browse,add) '
            'by group="cn=b,dc=ctbc" (browse)',
        )

        tm.that(len(aci.allows), eq=2)
        tm.ok(aci.acl_name.endswith("(+1)"))

    @staticmethod
    def test_unknown_permission_token_surfaces_failure() -> None:
        """Test unknown permission token surfaces failure."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" (bogus)',
        ).unwrap()

        tm.ok(FlextLdifServersOidAclAssemble.build_aci_rule(rule).failure)

    @staticmethod
    def test_cross_level_perm_grants_nothing_not_failure() -> None:
        # 'read' is an attribute perm; on an entry rule it grants nothing.
        """Test cross level perm grants nothing not failure."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" (read)',
        ).unwrap()
        result = FlextLdifServersOidAclAssemble.build_aci_rule(rule)

        tm.ok(result.success)
        tm.that(result.unwrap().allows, eq=())

    @staticmethod
    def test_negation_only_perms_mark_complement_calculated() -> None:
        # 'by * (noread)' on attr complements to write/selfwrite/... for anyone.
        """Each negation-only granted subject flags its own complement."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to attr=(cn) by group="cn=a,dc=ctbc" (read) by * (noread)',
        ).unwrap()
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(rule).unwrap()

        tm.ok("write" in aci.allows[1].permissions)
        tm.that(
            [outcome.complement_calculated for outcome in aci.outcomes],
            eq=[False, True],
        )
        tm.that(aci.target_type, eq="attr")

    @staticmethod
    def test_positive_perms_do_not_mark_complement_calculated() -> None:
        """Positive permissions grant as written without a complement."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            "orclaci: access to attr=(cn) by * (read,search)",
        ).unwrap()
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(rule).unwrap()

        tm.fail(aci.outcomes[0].complement_calculated)

    @staticmethod
    def test_bindmode_and_bindipfilter_become_authmethod_and_ip() -> None:
        """Test bindmode and bindipfilter become authmethod and ip."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" '
            "bindmode=(SSL) bindipfilter=(10.0.0.0) (browse,add)",
        ).unwrap()

        tm.that(rule.subjects[0].bindmode, eq="SSL")
        tm.that(rule.subjects[0].bindipfilter, eq="10.0.0.0")
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(rule).unwrap()
        tm.that(aci.allows[0].authmethod, eq="SSL")
        tm.that(aci.allows[0].ip, eq="10.0.0.0")
        tm.that(
            FlextLdifServersOidAclRender.render_aci_string(aci),
            eq=(
                'aci: (targetattr="*")    (version 3.0; acl "users Entry by a";'
                '     allow (read, search, add)    groupdn="ldap:///cn=a,dc=ctbc" '
                'and authmethod="SSL" and ip="10.0.0.0";)'
            ),
        )

    @staticmethod
    def test_added_object_constraint_stays_on_the_outcome_subject() -> None:
        """The granted outcome keeps the subject's added_object_constraint."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" '
            "added_object_constraint=(objectclass=person) (browse)",
        ).unwrap()
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(rule).unwrap()

        tm.that(rule.subjects[0].added_object_constraint, eq="objectclass=person")
        tm.that(aci.outcomes[0].subject, eq=rule.subjects[0])

    @staticmethod
    def test_anyone_at_high_level_container_is_skipped() -> None:
        """Test anyone at high level container is skipped."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "dc=ctbc",
            'orclaci: access to entry by * (browse) by group="cn=a,dc=ctbc" (browse)',
        ).unwrap()
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(
            rule, base_dn="dc=ctbc"
        ).unwrap()

        tm.that(len(aci.allows), eq=1)
        tm.that(aci.allows[0].subject_type, eq="groupdn")
        tm.that(
            [outcome.kind for outcome in aci.outcomes],
            eq=[_KIND.EXCLUDED_CONTAINER, _KIND.GRANTED],
        )

    @staticmethod
    def test_out_of_scope_dn_is_excluded() -> None:
        """Test out of scope dn is excluded."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=x,dc=other" (browse)',
        ).unwrap()
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(
            rule, base_dn="dc=ctbc"
        ).unwrap()

        tm.that(aci.allows, eq=())
        tm.that(aci.outcomes[0].kind, eq=_KIND.OUT_OF_SCOPE)
        tm.that(aci.outcomes[0].display_value, eq="cn=x,dc=other")

    @staticmethod
    def test_regex_dn_converts_to_wildcard_in_scope() -> None:
        """Test regex dn converts to wildcard in scope."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=.*,dc=ctbc" (browse)',
        ).unwrap()
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(
            rule, base_dn="dc=ctbc"
        ).unwrap()

        tm.that(len(aci.allows), eq=1)
        tm.that(aci.allows[0].subject_value, eq="cn=*,dc=ctbc")
        tm.ok(aci.outcomes[0].wildcard_rewritten)

    @staticmethod
    def test_no_base_dn_skips_scope_filtering() -> None:
        """Test no base dn skips scope filtering."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=x,dc=other" (browse)',
        ).unwrap()
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(rule).unwrap()

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
        )

        values = result.unwrap()
        tm.that(len(values), eq=2)
        tm.ok(all(not v.startswith("aci: ") for v in values))
        tm.ok(values[0].startswith('(targetattr="*")'))

    @staticmethod
    def test_identical_aci_values_are_deduplicated() -> None:
        """Test identical aci values are deduplicated."""
        line = 'orclaci: access to entry by group="cn=a,dc=ctbc" (browse)'
        result = FlextLdifServersOidAclPipeline.convert_acl_values(
            "cn=users,dc=ctbc", (line, line)
        )

        tm.that(len(result.unwrap()), eq=1)

    @staticmethod
    def test_deny_only_line_emits_no_value() -> None:
        """Test deny only line emits no value."""
        result = FlextLdifServersOidAclPipeline.convert_acl_values(
            "cn=users,dc=ctbc",
            ("orclaci: access to entry by * (none)",),
        )

        tm.that(result.unwrap(), eq=())

    @staticmethod
    def test_malformed_line_surfaces_failure() -> None:
        """Test malformed line surfaces failure."""
        result = FlextLdifServersOidAclPipeline.convert_acl_values(
            "cn=users,dc=ctbc",
            ("orclaci: this is not a valid acl",),
        )

        tm.ok(result.failure)


class TestsFlextLdifOidAclFixtureAndEntry:
    """OID ACL fixture conversion and entry-level orclaci conversion."""

    @staticmethod
    def test_oid_acl_fixture_lines_convert_without_partial_failures() -> None:
        """Test oid acl fixture lines convert without partial failures."""
        fixture_path = (
            Path(__file__).parents[2] / "fixtures" / "oid" / "oid_acl_fixtures.ldif"
        )
        dn = ""
        rules_seen = 0
        values_emitted = 0
        for line in fixture_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("dn:"):
                dn = line.removeprefix("dn:").strip()
                continue
            if not line.startswith(("orclaci:", "orclentrylevelaci:")):
                continue
            result = FlextLdifServersOidAclPipeline.convert_acl_values(
                dn, (line,), base_dn="dc=example,dc=com"
            )
            tm.ok(result.success)
            rules_seen += 1
            values_emitted += len(result.unwrap())

        tm.that(rules_seen, eq=16)
        tm.that(values_emitted, eq=11)

    @staticmethod
    def test_out_of_scope_dn_excluded_with_base_dn() -> None:
        """Test out of scope dn excluded with base dn."""
        result = FlextLdifServersOidAclPipeline.convert_acl_values(
            "cn=users,dc=ctbc",
            ('orclaci: access to entry by group="cn=x,dc=other" (browse)',),
            base_dn="dc=ctbc",
        )

        tm.that(result.unwrap(), eq=())

    @staticmethod
    def test_entry_conversion_records_typed_outcomes_on_metadata() -> None:
        """convert_entry_acls records per-subject outcomes on entry metadata."""
        entry = _acl_entry({
            "orclaci": [
                (
                    "access to entry by guidattr=(g) (browse) "
                    'by group="cn=a,dc=ctbc" (browse)'
                ),
            ],
        })

        converted = FlextLdifServersOidAclPipeline.convert_entry_acls(
            entry, "oid", "oud"
        ).unwrap()
        conversion = tm.not_none(tm.not_none(converted.metadata).acl_conversion)

        tm.fail(conversion.oracle_internal_skip)
        tm.that(
            [outcome.kind for outcome in conversion.rules[0].outcomes],
            eq=[_KIND.UNSUPPORTED, _KIND.GRANTED],
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
            entry, "oid", "oud"
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
            entry, "oid", "oud"
        ).unwrap()
        attrs = tm.not_none(converted.attributes).attributes

        tm.ok("orclaci" not in attrs)
        tm.ok("aci" in attrs)
        tm.that(len(attrs["aci"]), eq=1)
        tm.ok(attrs["aci"][0].startswith('(targetattr="*")'))

    @staticmethod
    def test_non_oid_to_oud_passes_through_unchanged() -> None:
        """Test non oid to oud passes through unchanged."""
        entry = _acl_entry({
            "orclaci": ['access to entry by group="cn=a,dc=ctbc" (browse)'],
        })

        converted = FlextLdifServersOidAclPipeline.convert_entry_acls(
            entry, "oid", "rfc"
        ).unwrap()
        tm.ok("orclaci" in tm.not_none(converted.attributes).attributes)

    @staticmethod
    def test_entry_without_acl_attrs_unchanged() -> None:
        """Test entry without acl attrs unchanged."""
        entry = _acl_entry({"cn": ["x"], "objectClass": ["top"]})

        converted = FlextLdifServersOidAclPipeline.convert_entry_acls(
            entry, "oid", "oud"
        ).unwrap()
        attrs = tm.not_none(converted.attributes).attributes

        tm.ok("aci" not in attrs)
        tm.ok("cn" in attrs)

    @staticmethod
    def test_malformed_acl_surfaces_failure() -> None:
        """Test malformed acl surfaces failure."""
        entry = _acl_entry({"orclaci": ["not a valid acl"]})

        tm.that(
            FlextLdifServersOidAclPipeline.convert_entry_acls(
                entry, "oid", "oud"
            ).failure,
            eq=True,
        )

    @staticmethod
    def test_unknown_perm_token_surfaces_failure() -> None:
        """Test unknown perm token surfaces failure."""
        result = FlextLdifServersOidAclPipeline.convert_acl_values(
            "cn=users,dc=ctbc",
            ('orclaci: access to entry by group="cn=a,dc=ctbc" (bogus)',),
        )

        tm.ok(result.failure)
