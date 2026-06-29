"""Tests for OID ACL line parsing (orclaci/orclentrylevelaci → OidAclRule)."""

from __future__ import annotations

from flext_tests import tm

from flext_ldif import m
from flext_ldif.servers._oid.acl_convert import FlextLdifServersOidAclConvert as Parser


class TestsFlextLdifOidAclConvertParse:
    """parse_oid_acl_line + parse_subject parity with the OUD migration oracle."""

    def test_entry_rule_with_group_and_anyone_subjects(self) -> None:
        line = (
            'orclaci: access to entry by group="cn=admins,dc=ctbc" '
            "(browse,add,delete) by * (browse,noadd,nodelete)"
        )
        result = Parser.parse_oid_acl_line("dc=ctbc", line)

        tm.that(result.success, eq=True)
        rule = result.unwrap()
        tm.that(rule.acl_type, eq="orclaci")
        tm.that(rule.target_type, eq="entry")
        tm.that(rule.target_attrs, eq="*")
        tm.that(rule.target_filter is None, eq=True)
        tm.that(len(rule.subjects), eq=2)
        tm.that(rule.subjects[0].subject_type, eq="group")
        tm.that(rule.subjects[0].value, eq="cn=admins,dc=ctbc")
        tm.that(rule.subjects[0].permissions, eq=("browse", "add", "delete"))
        tm.that(rule.subjects[1].subject_type, eq="anyone")
        tm.that(rule.subjects[1].value, eq="anyone")
        tm.that(rule.subjects[1].permissions, eq=("browse", "noadd", "nodelete"))

    def test_attr_list_target_with_anyone(self) -> None:
        result = Parser.parse_oid_acl_line(
            "dc=ctbc",
            "orclaci: access to attr=(cn,sn,mail) by * (read,search)",
        )

        rule = result.unwrap()
        tm.that(rule.target_type, eq="attr")
        tm.that(rule.target_attrs, eq="cn,sn,mail")
        tm.that(rule.subjects[0].subject_type, eq="anyone")
        tm.that(rule.subjects[0].permissions, eq=("read", "search"))

    def test_attr_negation_target(self) -> None:
        result = Parser.parse_oid_acl_line(
            "dc=ctbc",
            'orclaci: access to attr!=(userpassword) by group="cn=g,dc=ctbc" (read)',
        )

        rule = result.unwrap()
        tm.that(rule.target_attrs, eq="!=userpassword")
        tm.that(rule.subjects[0].subject_type, eq="group")

    def test_filter_clause_balanced_paren_scan(self) -> None:
        result = Parser.parse_oid_acl_line(
            "dc=ctbc",
            "orclaci: access to attr=(userpassword) "
            "filter=(objectclass=person) by self (read,write)",
        )

        rule = result.unwrap()
        tm.that(rule.target_filter, eq="objectclass=person")
        tm.that(rule.subjects[0].subject_type, eq="self")
        tm.that(rule.subjects[0].value, eq="self")
        tm.that(rule.subjects[0].permissions, eq=("read", "write"))

    def test_orclentrylevelaci_dnattr_subject(self) -> None:
        result = Parser.parse_oid_acl_line(
            "dc=ctbc",
            "orclentrylevelaci: access to entry by dnattr=(manager) (browse)",
        )

        rule = result.unwrap()
        tm.that(rule.acl_type, eq="orclentrylevelaci")
        tm.that(rule.subjects[0].subject_type, eq="dnattr")
        tm.that(rule.subjects[0].value, eq="manager")

    def test_superuser_subject_maps_to_directory_manager(self) -> None:
        subject = Parser.parse_subject("by SuperUser (browse,add)")

        tm.that(subject.subject_type, eq="superuser")
        tm.that(subject.value, eq="cn=Directory Manager")
        tm.that(subject.permissions, eq=("browse", "add"))

    def test_bare_quoted_dn_subject_maps_to_user(self) -> None:
        subject = Parser.parse_subject('by "cn=admin,dc=example,dc=com" (proxy,add)')

        tm.that(subject.subject_type, eq="user")
        tm.that(subject.value, eq="cn=admin,dc=example,dc=com")
        tm.that(subject.permissions, eq=("proxy", "add"))

    def test_constraintonaddedobject_modifier_is_canonical_constraint(self) -> None:
        subject = Parser.parse_subject(
            "by * (browse) constraintonaddedobject=(objectClass=person)",
        )

        tm.that(subject.subject_type, eq="anyone")
        tm.that(subject.permissions, eq=("browse",))
        tm.that(subject.added_object_constraint, eq="objectClass=person")

    def test_unknown_subject_returns_unknown_type(self) -> None:
        subject = Parser.parse_subject("by nonsense clause")

        tm.that(subject.subject_type, eq="unknown")

    def test_subject_matchers_use_typed_catalog(self) -> None:
        catalog = Parser.subject_matcher_catalog()

        tm.that(isinstance(catalog, m.Ldif.AclSubjectMatcherCatalog), eq=True)
        tm.that(len(catalog.matchers), eq=9)

    def test_non_acl_line_surfaces_failure(self) -> None:
        result = Parser.parse_oid_acl_line("dc=ctbc", "cn: not an acl")

        tm.that(result.failure, eq=True)

    def test_missing_access_to_surfaces_failure(self) -> None:
        result = Parser.parse_oid_acl_line("dc=ctbc", "orclaci: entry by * (read)")

        tm.that(result.failure, eq=True)

    def test_unbalanced_filter_surfaces_failure(self) -> None:
        result = Parser.parse_oid_acl_line(
            "dc=ctbc",
            "orclaci: access to attr=(cn) filter=(objectclass=person by self (read)",
        )

        tm.that(result.failure, eq=True)

    def test_no_subjects_surfaces_failure(self) -> None:
        result = Parser.parse_oid_acl_line(
            "dc=ctbc",
            "orclaci: access to entry by nonsense",
        )

        tm.that(result.failure, eq=True)
