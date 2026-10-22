"""Behavioral tests for OID→OUD ACL assembly, rendering, and conversion.

Every assertion exercises observable public contract: rendered ``aci:`` strings,
``r[T]`` success/failure outcomes, and public Pydantic model fields
(``allows``, ``notes``, ``targetscope``, ``subjects``). No private attribute or
method is touched; the only collaborator observed at a boundary is the fleet
logging surface (``u.structlog().testing.capture_logs``; conversion notes are
a logged contract, also mirrored on ``aci.notes``).

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.servers import (
    FlextLdifServersOidAclAssemble,
    FlextLdifServersOidAclConvert,
    FlextLdifServersOidAclPipeline,
    FlextLdifServersOidAclRender,
)
from tests import m, t, tm, u


def _acl_entry(attributes: t.MappingKV[str, t.StrSequence]) -> m.Ldif.Entry:
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
        tm.ok(any("default-deny" in note for note in aci.notes))

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

    def test_deny_only_rule_yields_empty_allows_with_notes(self) -> None:
        """Test deny only rule yields empty allows with notes."""
        aci = self._build(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by * (none) by group="cn=x,dc=ctbc" (browse)',
        )

        tm.that(aci.allows, eq=())
        tm.ok(any("dead code" in note for note in aci.notes))

    def test_guidattr_dropped_with_note_other_subject_survives(self) -> None:
        """Test guidattr dropped with note other subject survives."""
        aci = self._build(
            "cn=users,dc=ctbc",
            "orclaci: access to entry by guidattr=(orclguid) (browse) "
            'by group="cn=a,dc=ctbc" (browse)',
        )

        tm.that(len(aci.allows), eq=1)
        tm.that(aci.allows[0].subject_type, eq="groupdn")
        tm.ok(any("guidattr" in note for note in aci.notes))

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
    def test_anyone_with_sensitive_perms_emits_review_note() -> None:
        # 'by * (noread)' on attr complements to write/selfwrite/... for anyone.
        """Test anyone with sensitive perms emits review note."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            "orclaci: access to attr=(cn) by * (noread)",
        ).unwrap()
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(rule).unwrap()

        tm.ok("write" in aci.allows[0].permissions)
        tm.ok(any("sensitive perms" in note for note in aci.notes))

    @staticmethod
    def test_anyone_with_only_read_search_emits_no_sensitive_note() -> None:
        """Test anyone with only read search emits no sensitive note."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            "orclaci: access to attr=(cn) by * (read,search)",
        ).unwrap()
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(rule).unwrap()

        tm.fail(any("sensitive perms" in note for note in aci.notes))

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
    def test_added_object_constraint_emits_review_note() -> None:
        """Test added object constraint emits review note."""
        rule = FlextLdifServersOidAclConvert.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" '
            "added_object_constraint=(objectclass=person) (browse)",
        ).unwrap()
        aci = FlextLdifServersOidAclAssemble.build_aci_rule(rule).unwrap()

        tm.that(rule.subjects[0].added_object_constraint, eq="objectclass=person")
        tm.ok(any("added_object_constraint" in n for n in aci.notes))

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
        tm.ok(any("high-level container" in note for note in aci.notes))

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
        tm.ok(any("out of scope" in note for note in aci.notes))

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
    def test_conversion_notes_are_surfaced_via_logging() -> None:
        """Test conversion notes are surfaced via logging."""
        with u.structlog().testing.capture_logs() as captured:
            FlextLdifServersOidAclPipeline.convert_acl_values(
                "cn=users,dc=ctbc",
                (
                    (
                        "orclaci: access to entry by guidattr=(g) (browse) "
                        'by group="cn=a,dc=ctbc" (browse)'
                    ),
                ),
            )

        note_events = [
            event
            for event in captured
            if event.get("event") == "OID ACL conversion notes"
        ]
        tm.that(len(note_events), eq=1)
        tm.that(
            any("guidattr" in note for note in note_events[0].get("notes", [])),
            eq=True,
        )

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
        tm.not_none(converted.attributes)
        attrs = converted.attributes.attributes

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
        tm.not_none(converted.attributes)

        tm.ok("orclaci" in converted.attributes.attributes)

    @staticmethod
    def test_entry_without_acl_attrs_unchanged() -> None:
        """Test entry without acl attrs unchanged."""
        entry = _acl_entry({"cn": ["x"], "objectClass": ["top"]})

        converted = FlextLdifServersOidAclPipeline.convert_entry_acls(
            entry, "oid", "oud"
        ).unwrap()
        tm.not_none(converted.attributes)

        tm.ok("aci" not in converted.attributes.attributes)
        tm.ok("cn" in converted.attributes.attributes)

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
