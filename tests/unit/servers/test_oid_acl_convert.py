"""Behavioral tests for OID ACL line parsing.

Exercises the PUBLIC contract of
:class:`flext_ldif.servers._oid.acl_convert.FlextLdifServersOidAclConvert`:

* ``parse_oid_acl_line`` returns ``r[m.Ldif.OidAclRule]`` — success carries the
  typed rule, malformation surfaces as a failure with a descriptive error.
* ``parse_subject`` maps one ``by <subject> (perms)`` clause to a typed
  ``m.Ldif.OidAclSubject`` value object.
* ``subject_matcher_catalog`` returns the typed catalog that backs subject
  recognition.

All assertions target observable return values / public model state only.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from flext_ldif import m
from flext_ldif.servers.oid import FlextLdifServersOidAclConvert as Parser

if TYPE_CHECKING:
    from tests import t

_DN: str = "dc=ctbc"


class TestsFlextLdifOidAclConvert:
    """Public parsing contract of the OID ACL convert facade."""

    # ------------------------------------------------------------------ #
    # parse_oid_acl_line — full-line success behavior
    # ------------------------------------------------------------------ #

    @staticmethod
    def test_entry_rule_exposes_ordered_typed_subjects() -> None:
        """Test entry rule exposes ordered typed subjects."""
        line = (
            'orclaci: access to entry by group="cn=admins,dc=ctbc" '
            "(browse,add,delete) by * (browse,noadd,nodelete)"
        )

        rule: m.Ldif.OidAclRule = tm.ok(Parser.parse_oid_acl_line(_DN, line))

        tm.that(rule.dn, eq=_DN)
        tm.that(rule.acl_type, eq="orclaci")
        tm.that(rule.target_type, eq="entry")
        tm.that(rule.target_attrs, eq="*")
        tm.that(rule.target_filter, none=True)
        tm.that(rule.subjects, len=2)
        tm.that(rule.subjects[0].subject_type, eq="group")
        tm.that(rule.subjects[0].value, eq="cn=admins,dc=ctbc")
        tm.that(rule.subjects[0].permissions, eq=("browse", "add", "delete"))
        tm.that(rule.subjects[1].subject_type, eq="anyone")
        tm.that(rule.subjects[1].value, eq="anyone")
        tm.that(rule.subjects[1].permissions, eq=("browse", "noadd", "nodelete"))

    @staticmethod
    def test_rule_preserves_raw_line_for_round_trip() -> None:
        """Test rule preserves raw line for round trip."""
        line = "orclaci: access to entry by * (browse)"

        rule: m.Ldif.OidAclRule = tm.ok(Parser.parse_oid_acl_line(_DN, line))

        tm.that(rule.raw_line, eq=line)

    @staticmethod
    @pytest.mark.parametrize(
        ("content", "expected_type", "expected_attrs"),
        [
            ("attr=(cn,sn,mail) by * (read,search)", "attr", "cn,sn,mail"),
            (
                'attr!=(userpassword) by group="cn=g,dc=ctbc" (read)',
                "attr",
                "!=userpassword",
            ),
            ("entry by * (browse)", "entry", "*"),
        ],
    )
    def test_target_clause_shapes_map_to_public_target_fields(
        content: str,
        expected_type: str,
        expected_attrs: str,
    ) -> None:
        """Test target clause shapes map to public target fields."""
        rule: m.Ldif.OidAclRule = tm.ok(
            Parser.parse_oid_acl_line(_DN, f"orclaci: access to {content}"),
        )

        tm.that(rule.target_type, eq=expected_type)
        tm.that(rule.target_attrs, eq=expected_attrs)

    @staticmethod
    def test_filter_clause_is_extracted_via_balanced_paren_scan() -> None:
        """Test filter clause is extracted via balanced paren scan."""
        line = (
            "orclaci: access to attr=(userpassword) "
            "filter=(objectclass=person) by self (read,write)"
        )

        rule: m.Ldif.OidAclRule = tm.ok(Parser.parse_oid_acl_line(_DN, line))

        tm.that(rule.target_filter, eq="objectclass=person")
        tm.that(rule.subjects[0].subject_type, eq="self")
        tm.that(rule.subjects[0].value, eq="self")
        tm.that(rule.subjects[0].permissions, eq=("read", "write"))

    @staticmethod
    def test_orclentrylevelaci_line_records_its_acl_type() -> None:
        """Test orclentrylevelaci line records its acl type."""
        line = "orclentrylevelaci: access to entry by dnattr=(manager) (browse)"

        rule: m.Ldif.OidAclRule = tm.ok(Parser.parse_oid_acl_line(_DN, line))

        tm.that(rule.acl_type, eq="orclentrylevelaci")
        tm.that(rule.subjects[0].subject_type, eq="dnattr")
        tm.that(rule.subjects[0].value, eq="manager")

    # ------------------------------------------------------------------ #
    # parse_oid_acl_line — malformation surfaces as descriptive failure
    # ------------------------------------------------------------------ #

    @staticmethod
    @pytest.mark.parametrize(
        ("line", "error_fragment"),
        [
            ("cn: not an acl", "Not an OID ACL line"),
            ("orclaci: entry by * (read)", "access to"),
            (
                (
                    "orclaci: access to attr=(cn) filter=(objectclass=person by self "
                    "(read)"
                ),
                "Unbalanced ACL filter clause",
            ),
            ("orclaci: access to entry by nonsense", "No subjects in ACL"),
            ("orclaci: access to bogustarget by * (read)", "Unknown ACL target"),
        ],
    )
    def test_malformed_line_fails_with_descriptive_error(
        line: str,
        error_fragment: str,
    ) -> None:
        """Test malformed line fails with descriptive error."""
        result = Parser.parse_oid_acl_line(_DN, line)

        tm.that(result.failure, eq=True)
        tm.fail(result, has=error_fragment)

    # ------------------------------------------------------------------ #
    # parse_subject — one by-clause to a typed subject value object
    # ------------------------------------------------------------------ #

    @staticmethod
    @pytest.mark.parametrize(
        ("clause", "subject_type", "value", "permissions"),
        [
            (
                "by SuperUser (browse,add)",
                "superuser",
                "cn=Directory Manager",
                ("browse", "add"),
            ),
            ('by group="cn=g,dc=x" (read)', "group", "cn=g,dc=x", ("read",)),
            ('by dn="cn=u,dc=x" (read)', "user", "cn=u,dc=x", ("read",)),
            (
                'by "cn=admin,dc=example,dc=com" (proxy,add)',
                "user",
                "cn=admin,dc=example,dc=com",
                ("proxy", "add"),
            ),
            ("by self (read,write)", "self", "self", ("read", "write")),
            ("by * (read)", "anyone", "anyone", ("read",)),
            ("by dnattr=(manager) (browse)", "dnattr", "manager", ("browse",)),
            ("by groupattr=(owner) (read)", "groupattr", "owner", ("read",)),
            ("by guidattr=(entryUUID) (read)", "guidattr", "entryUUID", ("read",)),
        ],
    )
    def test_subject_clause_maps_to_typed_subject(
        clause: str,
        subject_type: str,
        value: str,
        permissions: t.VariadicTuple[str],
    ) -> None:
        """Test subject clause maps to typed subject."""
        subject = Parser.parse_subject(clause)

        tm.that(subject.subject_type, eq=subject_type)
        tm.that(subject.value, eq=value)
        tm.that(subject.permissions, eq=permissions)

    @staticmethod
    def test_constraint_modifier_populates_added_object_constraint() -> None:
        """Test constraint modifier populates added object constraint."""
        subject = Parser.parse_subject(
            "by * (browse) constraintonaddedobject=(objectClass=person)",
        )

        tm.that(subject.subject_type, eq="anyone")
        tm.that(subject.permissions, eq=("browse",))
        tm.that(subject.added_object_constraint, eq="objectClass=person")

    @staticmethod
    def test_unrecognized_subject_yields_unknown_type() -> None:
        """Test unrecognized subject yields unknown type."""
        subject = Parser.parse_subject("by nonsense clause")

        tm.that(subject.subject_type, eq="unknown")
        tm.that(subject.value, empty=True)
        tm.that(subject.permissions, empty=True)

    # ------------------------------------------------------------------ #
    # subject_matcher_catalog — typed catalog contract
    # ------------------------------------------------------------------ #

    @staticmethod
    def test_subject_matcher_catalog_returns_typed_non_empty_catalog() -> None:
        """Test subject matcher catalog returns typed non empty catalog."""
        catalog = Parser.subject_matcher_catalog()

        tm.that(catalog, is_=m.Ldif.AclSubjectMatcherCatalog)
        tm.that(catalog.matchers, empty=False)
