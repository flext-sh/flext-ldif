"""Tests for OUD aci-string assembly (AciRule → aci: line)."""

from __future__ import annotations

from pathlib import Path

from flext_tests import tm
from structlog.testing import capture_logs

from flext_ldif import m
from flext_ldif.servers._oid.acl_assemble import FlextLdifServersOidAclAssemble as Asm
from flext_ldif.servers._oid.acl_convert import FlextLdifServersOidAclConvert as Parser
from flext_ldif.servers._oid.acl_pipeline import FlextLdifServersOidAclPipeline as Pipe
from flext_ldif.servers._oid.acl_render import FlextLdifServersOidAclRender as Render
from tests.utilities import TestsFlextLdifUtilities as u


class TestsFlextLdifOidAclAssemble:
    """render_aci_string parity with the OUD migration oracle to_aci_string."""

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
            Render.render_aci_string(aci),
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
            Render.render_aci_string(aci),
            eq=(
                'aci: (targetattr="cn||sn||mail")'
                '(version 3.0; acl "ctbc Attrs by mgr"; '
                'allow (read, search) userattr="manager#USERDN" '
                'or groupdn="ldap:///cn=g,dc=ctbc";)'
            ),
        )

    def test_same_perms_with_different_modifiers_render_separate_allows(self) -> None:
        aci = m.Ldif.AciRule(
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
        )

        tm.that(
            Render.render_aci_string(aci),
            eq=(
                'aci: (targetattr="*")(version 3.0; acl "ctbc Entry by admins"; '
                'allow (read, search) groupdn="ldap:///cn=ssl,dc=ctbc" '
                'and authmethod="SSL"; '
                'allow (read, search) groupdn="ldap:///cn=simple,dc=ctbc" '
                'and authmethod="Simple";)'
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
            Render.render_aci_string(aci),
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
            Render.render_aci_string(aci),
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

    def test_cross_level_perm_grants_nothing_not_failure(self) -> None:
        # 'read' is an attribute perm; on an entry rule it grants nothing.
        rule = Parser.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" (read)',
        ).unwrap()
        result = Asm.build_aci_rule(rule)

        tm.that(result.success, eq=True)
        tm.that(result.unwrap().allows, eq=())

    def test_anyone_with_sensitive_perms_emits_review_note(self) -> None:
        # 'by * (noread)' on attr complements to write/selfwrite/... for anyone.
        rule = Parser.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            "orclaci: access to attr=(cn) by * (noread)",
        ).unwrap()
        aci = Asm.build_aci_rule(rule).unwrap()

        tm.that("write" in aci.allows[0].permissions, eq=True)
        tm.that(any("sensitive perms" in note for note in aci.notes), eq=True)

    def test_anyone_with_only_read_search_emits_no_sensitive_note(self) -> None:
        rule = Parser.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            "orclaci: access to attr=(cn) by * (read,search)",
        ).unwrap()
        aci = Asm.build_aci_rule(rule).unwrap()

        tm.that(any("sensitive perms" in note for note in aci.notes), eq=False)

    def test_bindmode_and_bindipfilter_become_authmethod_and_ip(self) -> None:
        rule = Parser.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" '
            "bindmode=(SSL) bindipfilter=(10.0.0.0) (browse,add)",
        ).unwrap()

        tm.that(rule.subjects[0].bindmode, eq="SSL")
        tm.that(rule.subjects[0].bindipfilter, eq="10.0.0.0")
        aci = Asm.build_aci_rule(rule).unwrap()
        tm.that(aci.allows[0].authmethod, eq="SSL")
        tm.that(aci.allows[0].ip, eq="10.0.0.0")
        tm.that(
            Render.render_aci_string(aci),
            eq=(
                'aci: (targetattr="*")(version 3.0; acl "users Entry by a"; '
                'allow (read, search, add) groupdn="ldap:///cn=a,dc=ctbc" '
                'and authmethod="SSL" and ip="10.0.0.0";)'
            ),
        )

    def test_added_object_constraint_emits_review_note(self) -> None:
        rule = Parser.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=a,dc=ctbc" '
            "added_object_constraint=(objectclass=person) (browse)",
        ).unwrap()
        aci = Asm.build_aci_rule(rule).unwrap()

        tm.that(rule.subjects[0].added_object_constraint, eq="objectclass=person")
        tm.that(any("added_object_constraint" in n for n in aci.notes), eq=True)

    def test_anyone_at_high_level_container_is_skipped(self) -> None:
        rule = Parser.parse_oid_acl_line(
            "dc=ctbc",
            'orclaci: access to entry by * (browse) by group="cn=a,dc=ctbc" (browse)',
        ).unwrap()
        aci = Asm.build_aci_rule(rule, base_dn="dc=ctbc").unwrap()

        tm.that(len(aci.allows), eq=1)
        tm.that(aci.allows[0].subject_type, eq="groupdn")
        tm.that(any("high-level container" in note for note in aci.notes), eq=True)

    def test_out_of_scope_dn_is_excluded(self) -> None:
        rule = Parser.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=x,dc=other" (browse)',
        ).unwrap()
        aci = Asm.build_aci_rule(rule, base_dn="dc=ctbc").unwrap()

        tm.that(aci.allows, eq=())
        tm.that(any("out of scope" in note for note in aci.notes), eq=True)

    def test_regex_dn_converts_to_wildcard_in_scope(self) -> None:
        rule = Parser.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=.*,dc=ctbc" (browse)',
        ).unwrap()
        aci = Asm.build_aci_rule(rule, base_dn="dc=ctbc").unwrap()

        tm.that(len(aci.allows), eq=1)
        tm.that(aci.allows[0].subject_value, eq="cn=*,dc=ctbc")

    def test_no_base_dn_skips_scope_filtering(self) -> None:
        rule = Parser.parse_oid_acl_line(
            "cn=users,dc=ctbc",
            'orclaci: access to entry by group="cn=x,dc=other" (browse)',
        ).unwrap()
        aci = Asm.build_aci_rule(rule).unwrap()

        tm.that(len(aci.allows), eq=1)


class TestsFlextLdifOidAclConvertValues:
    """convert_acl_values: whole-entry OID ACL lines → deduped aci values."""

    def test_multiple_lines_produce_aci_values_without_prefix(self) -> None:
        result = Pipe.convert_acl_values(
            "cn=users,dc=ctbc",
            (
                'orclaci: access to entry by group="cn=a,dc=ctbc" (browse)',
                "orclentrylevelaci: access to attr=(cn) by * (read)",
            ),
        )

        values = result.unwrap()
        tm.that(len(values), eq=2)
        tm.that(all(not v.startswith("aci: ") for v in values), eq=True)
        tm.that(values[0].startswith('(targetattr="*")'), eq=True)

    def test_identical_aci_values_are_deduplicated(self) -> None:
        line = 'orclaci: access to entry by group="cn=a,dc=ctbc" (browse)'
        result = Pipe.convert_acl_values("cn=users,dc=ctbc", (line, line))

        tm.that(len(result.unwrap()), eq=1)

    def test_deny_only_line_emits_no_value(self) -> None:
        result = Pipe.convert_acl_values(
            "cn=users,dc=ctbc",
            ("orclaci: access to entry by * (none)",),
        )

        tm.that(result.unwrap(), eq=())

    def test_malformed_line_surfaces_failure(self) -> None:
        result = Pipe.convert_acl_values(
            "cn=users,dc=ctbc",
            ("orclaci: this is not a valid acl",),
        )

        tm.that(result.failure, eq=True)

    def test_unknown_perm_token_surfaces_failure(self) -> None:
        result = Pipe.convert_acl_values(
            "cn=users,dc=ctbc",
            ('orclaci: access to entry by group="cn=a,dc=ctbc" (bogus)',),
        )

        tm.that(result.failure, eq=True)

    def test_oid_acl_fixture_lines_convert_without_partial_failures(self) -> None:
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
            result = Pipe.convert_acl_values(
                dn,
                (line,),
                base_dn="dc=example,dc=com",
            )
            tm.that(result.success, eq=True)
            rules_seen += 1
            values_emitted += len(result.unwrap())

        tm.that(rules_seen, eq=16)
        tm.that(values_emitted, eq=11)

    def test_out_of_scope_dn_excluded_with_base_dn(self) -> None:
        result = Pipe.convert_acl_values(
            "cn=users,dc=ctbc",
            ('orclaci: access to entry by group="cn=x,dc=other" (browse)',),
            base_dn="dc=ctbc",
        )

        tm.that(result.unwrap(), eq=())

    def test_conversion_notes_are_surfaced_via_logging(self) -> None:
        with capture_logs() as captured:
            Pipe.convert_acl_values(
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


class TestsFlextLdifOidAclConvertEntryAcls:
    """convert_entry_acls: OID entry orclaci/orclentrylevelaci → aci attribute."""

    @staticmethod
    def _entry(attributes: dict[str, list[str]]) -> m.Ldif.Entry:
        return u.Tests.create_real_entry(dn="cn=users,dc=ctbc", attributes=attributes)

    def test_oid_to_oud_replaces_orclaci_with_aci(self) -> None:
        entry = self._entry({
            "objectClass": ["top"],
            "orclaci": ['access to entry by group="cn=a,dc=ctbc" (browse)'],
        })

        converted = Pipe.convert_entry_acls(entry, "oid", "oud").unwrap()
        assert converted.attributes is not None
        attrs = converted.attributes.attributes

        tm.that("orclaci" not in attrs, eq=True)
        tm.that("aci" in attrs, eq=True)
        tm.that(len(attrs["aci"]), eq=1)
        tm.that(attrs["aci"][0].startswith('(targetattr="*")'), eq=True)

    def test_non_oid_to_oud_passes_through_unchanged(self) -> None:
        entry = self._entry({
            "orclaci": ['access to entry by group="cn=a,dc=ctbc" (browse)'],
        })

        converted = Pipe.convert_entry_acls(entry, "oid", "rfc").unwrap()
        assert converted.attributes is not None

        tm.that("orclaci" in converted.attributes.attributes, eq=True)

    def test_entry_without_acl_attrs_unchanged(self) -> None:
        entry = self._entry({"cn": ["x"], "objectClass": ["top"]})

        converted = Pipe.convert_entry_acls(entry, "oid", "oud").unwrap()
        assert converted.attributes is not None

        tm.that("aci" not in converted.attributes.attributes, eq=True)
        tm.that("cn" in converted.attributes.attributes, eq=True)

    def test_malformed_acl_surfaces_failure(self) -> None:
        entry = self._entry({"orclaci": ["not a valid acl"]})

        tm.that(Pipe.convert_entry_acls(entry, "oid", "oud").failure, eq=True)
