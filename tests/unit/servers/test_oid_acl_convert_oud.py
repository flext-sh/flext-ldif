"""Behavioral tests for the OID→OUD ACL converter public contract.

Exercises the observable behavior of
:class:`flext_ldif.servers._oid.acl_convert_oud.FlextLdifServersOidAclToOud`:
subject → OUD bind-rule mapping, permission-token conversion, targetattr /
targetscope computation, and the DN-scoping helpers. Every assertion targets a
public return value or the ``r[T]`` outcome — never an implementation detail.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.servers import FlextLdifConstantsServersOid, FlextLdifServersOidAclToOud
from tests import c, m, p, tm


class TestsFlextLdifOidAclConvertOud:
    """Public contract of FlextLdifServersOidAclToOud."""

    @staticmethod
    def _subject(kind: str, value: str = "") -> p.Ldif.OidAclSubject:
        return m.Ldif.OidAclSubject(subject_type=kind, value=value)

    @staticmethod
    def _rule(
        target_type: str,
        target_attrs: str = "*",
        acl_type: str = "orclaci",
    ) -> p.Ldif.OidAclRule:
        return m.Ldif.OidAclRule(
            dn="dc=ctbc",
            acl_type=acl_type,
            target_type=target_type,
            target_attrs=target_attrs,
        )

    # -- convert_subject_to_oud: bind-rule mapping -------------------------

    # -- resolve_permissions ----------------------------------------------

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("permissions", "is_entry", "allow", "deny"),
        [
            (
                ("browse", "add", "delete"),
                True,
                ("read", "search", "add", "delete"),
                (),
            ),
            (("search", "read"), False, ("read", "search"), ()),
            (("browse", "nobrowse"), True, (), ("read", "search")),
            (
                ("browse", "none"),
                True,
                (),
                ("read", "search", "add", "delete", "proxy"),
            ),
            (("browse", "noadd"), True, ("read", "search"), ("add",)),
            (("noadd",), True, (), ("add",)),
            (
                ("nobrowse", "noadd", "nodelete"),
                True,
                (),
                ("read", "search", "add", "delete"),
            ),
            (("noread",), False, (), ("read",)),
            (
                ("search", "read", "nowrite", "nocompare"),
                False,
                ("read", "search"),
                ("write", "compare"),
            ),
            (("none",), True, (), ("read", "search", "add", "delete", "proxy")),
            (("none",), False, (), ("read", "search", "write", "selfwrite", "compare")),
        ],
    )
    def test_resolve_permissions_resolves_grants_and_denials(
        permissions: tuple[str, ...],
        *,
        is_entry: bool,
        allow: tuple[str, ...],
        deny: tuple[str, ...],
    ) -> None:
        """Each OID access level is granted or denied on its own (OID-30 §30.1.4.3).

        A pure-negation list denies exactly the named rights and grants
        nothing; a right both granted and denied is denied.
        """
        resolved = FlextLdifServersOidAclToOud.resolve_permissions(
            permissions, is_entry=is_entry
        ).unwrap()

        tm.that(tuple(resolved.allow), eq=allow)
        tm.that(tuple(resolved.deny), eq=deny)

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("permissions", "is_entry", "message"),
        [
            (("bogus",), False, "Unknown OID permission token"),
            (("nofoo",), False, "Unknown OID permission token"),
            (("all",), True, "Unknown OID permission token 'all'"),
            (("all", "noread"), False, "Unknown OID permission token 'all'"),
            (("*",), False, "Unknown OID permission token"),
            (("read",), True, "not a right of an 'entry' object"),
            (("noread",), True, "not a right of an 'entry' object"),
            (("browse",), False, "not a right of an 'attr' object"),
            ((), True, "Empty OID access list"),
            ((" ",), True, "Empty token in OID access list"),
            (("browse", ""), True, "Empty token in OID access list"),
        ],
    )
    def test_token_outside_access_grammar_surfaces_failure(
        permissions: tuple[str, ...],
        *,
        is_entry: bool,
        message: str,
    ) -> None:
        """Tokens outside the OID access grammar of the object kind fail loud."""
        tm.fail(
            FlextLdifServersOidAclToOud.resolve_permissions(
                permissions, is_entry=is_entry
            ),
            has=message,
        )

    # -- convert_targetattr --------------------------------------------------

    @c.Tests.MARK.parametrize(
        ("target_type", "target_attrs", "siblings", "expected"),
        [
            ("entry", "*", (), "*"),
            ("attr", "cn,sn,mail", (), "cn||sn||mail"),
            ("attr", "*", (), "*"),
            ("attr", "*", ("userpassword", "cn"), "!=userpassword||cn"),
            ("attr", "!=userpassword", (), "!=userpassword"),
            ("attr", "!=a, b", (), "!=a||b"),
            ("attr", "createTimestamp", (), "createTimestamp"),
        ],
    )
    def test_convert_targetattr(
        self,
        target_type: str,
        target_attrs: str,
        siblings: tuple[str, ...],
        expected: str,
    ) -> None:
        """``attr=(*)`` excludes the attributes its ACP siblings name."""
        tm.that(
            FlextLdifServersOidAclToOud.convert_targetattr(
                self._rule(target_type, target_attrs),
                sibling_attrs=siblings,
            ).unwrap(),
            eq=expected,
        )

    @c.Tests.MARK.parametrize(
        ("target_attrs", "siblings", "message"),
        [
            ("!=sn", ("cn",), "combination undefined"),
            ("cn,createTimestamp", (), "operational attributes"),
            ("!=createTimestamp", (), "operational attributes"),
            ("*", ("createTimestamp",), "operational attributes"),
            ("orclaci", (), "ACL attributes"),
        ],
    )
    def test_targetattr_without_exact_oud_form_fails(
        self,
        target_attrs: str,
        siblings: tuple[str, ...],
        message: str,
    ) -> None:
        """Undefined, illegal or vanishing OUD targetattr forms fail loud."""
        tm.fail(
            FlextLdifServersOidAclToOud.convert_targetattr(
                self._rule("attr", target_attrs),
                sibling_attrs=siblings,
            ),
            has=message,
        )

    # -- rule_targetscope ---------------------------------------------------

    @c.Tests.MARK.parametrize(
        ("acl_type", "expected"),
        [("orclaci", None), ("orclentrylevelaci", "base")],
    )
    def test_rule_targetscope(self, acl_type: str, expected: str | None) -> None:
        """An orclaci is prescriptive over its subtree; entry-level is base."""
        tm.that(
            FlextLdifServersOidAclToOud.rule_targetscope(
                self._rule("entry", acl_type=acl_type),
            ),
            eq=expected,
        )

    # -- validate_ldap_filter -----------------------------------------------

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("value", "expected"),
        [
            ("objectclass=person", "(objectclass=person)"),
            ("&(a=b)(!(c=*))", "(&(a=b)(!(c=*)))"),
            ("(cn=a*b)", "(cn=a*b)"),
            ("cn:dn:2.5.13.5:=x", "(cn:dn:2.5.13.5:=x)"),
            ("foo", ""),
            ("!(a=b)(c=d)", ""),
            ("&", ""),
            ("(a=b)x", ""),
        ],
    )
    def test_ldap_filter_is_validated(value: str, expected: str) -> None:
        """An RFC 4515 filter renders parenthesized; any other text fails."""
        result = FlextLdifServersOidAclToOud.validate_ldap_filter(value)
        if expected:
            tm.that(result.unwrap(), eq=expected)
        else:
            tm.fail(result, has="not one RFC 4515 LDAP filter")

    # -- regex_dn_to_wildcard / convert_bind_dn ----------------------------

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("value", "expected"),
        [
            (".*,dc=ctbc", "**,dc=ctbc"),
            (".+, dc=ctbc", "**,dc=ctbc"),
            ("*,ou=people,dc=ctbc", "**,ou=people,dc=ctbc"),
            (r"cn=a\.b,dc=ctbc", "cn=a.b,dc=ctbc"),
            (r"cn=Doe\, John,dc=ctbc", r"cn=Doe\, John,dc=ctbc"),
            ("uid=joe,dc=ctbc", "uid=joe,dc=ctbc"),
            ("", ""),
        ],
    )
    def test_regex_dn_to_wildcard(value: str, expected: str) -> None:
        """A plain DN stays; the leading subtree regex becomes OUD ``**,``."""
        tm.that(
            FlextLdifServersOidAclToOud.regex_dn_to_wildcard(value).unwrap(),
            eq=expected,
        )

    @staticmethod
    @c.Tests.MARK.parametrize(
        "value",
        [
            "cn=.*,dc=ctbc",
            "cn=adm*,dc=ctbc",
            r"cn=a\d,dc=ctbc",
            r"cn=a\.*,dc=ctbc",
            "cn=ab+,dc=ctbc",
            "cn=a[0-9]b",
            "cn=(a|b),dc=ctbc",
            "^cn=a$",
        ],
    )
    def test_unconvertible_regex_dn_surfaces_failure(value: str) -> None:
        """A regex DN beyond the leading subtree wildcard fails, never raw."""
        tm.fail(
            FlextLdifServersOidAclToOud.regex_dn_to_wildcard(value),
            has="no exact OUD wildcard",
        )

    @staticmethod
    def test_group_dn_with_wildcard_surfaces_failure() -> None:
        """A ``group=`` subject names one DN; a wildcard there fails loud."""
        tm.fail(
            FlextLdifServersOidAclToOud.convert_bind_dn("groupdn", ".*,dc=ctbc"),
            has="no exact OUD groupdn",
        )
        tm.that(
            FlextLdifServersOidAclToOud.convert_bind_dn(
                "groupdn", "cn=g,dc=ctbc"
            ).unwrap(),
            eq="cn=g,dc=ctbc",
        )

    # -- convert_bindipfilter / convert_bind_modifiers ------------------------

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("value", "expected"),
        [
            ("orclipaddress=10.1.2.3", "10.1.2.3"),
            ("orclipaddress=10.10.*", "10.10.*.*"),
            (
                "|(orclipaddress=1.2.3.*)(orclipaddress=1.2.4.*)",
                "1.2.3.*,1.2.4.*",
            ),
        ],
    )
    def test_bindipfilter_translates_to_oud_ip(value: str, expected: str) -> None:
        """An orclipaddress equality (or OR of them) becomes an OUD ip list."""
        tm.that(
            FlextLdifServersOidAclToOud.convert_bindipfilter(value).unwrap(),
            eq=expected,
        )

    @staticmethod
    @c.Tests.MARK.parametrize(
        "value",
        [
            "",
            "10.0.0.0",
            "&(orclipaddress!=1.2.*)(orclipaddress!=3.4.*)",
            "orclipaddress=1.2.3*",
            "orclipaddress=1.*.3.4",
            "orclipaddress=300.1.1.1",
        ],
    )
    def test_untranslatable_bindipfilter_surfaces_failure(value: str) -> None:
        """A bindipfilter without an exact OUD ip form fails loud."""
        tm.fail(
            FlextLdifServersOidAclToOud.convert_bindipfilter(value),
            has="no exact OUD ip",
        )

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("subject", "message"),
        [
            (
                m.Ldif.OidAclSubject(subject_type="anyone", bindmode="Simple"),
                "bindmode",
            ),
            (
                m.Ldif.OidAclSubject(
                    subject_type="anyone",
                    added_object_constraint="objectclass=person",
                ),
                "added_object_constraint",
            ),
        ],
    )
    def test_bindmode_and_add_constraint_surface_failure(
        subject: p.Ldif.OidAclSubject,
        message: str,
    ) -> None:
        """Modifiers without an exact OUD form fail instead of passing raw."""
        tm.fail(
            FlextLdifServersOidAclToOud.convert_bind_modifiers(subject),
            has=message,
        )

    @c.Tests.MARK.parametrize(
        ("acl_type", "deny", "plain", "operational"),
        [
            (
                "orclentrylevelaci",
                False,
                ((None, None, ("read", "search")), (None, "onelevel", ("add",))),
                None,
            ),
            (
                "orclentrylevelaci",
                True,
                ((None, None, ("read", "search")), (None, "onelevel", ("add",))),
                "own",
            ),
            ("orclaci", True, ((None, None, ("read", "search", "add")),), "own"),
            ("orclaci", False, ((None, None, ("read", "search", "add")),), None),
        ],
    )
    def test_clause_parts_partition_entry_rights(
        self,
        acl_type: str,
        *,
        deny: bool,
        plain: tuple[tuple[str | None, str | None, tuple[str, ...]], ...],
        operational: str | None,
    ) -> None:
        """Entry-level ``add`` targets children; a visibility denial hides more.

        A denial of read or search on an entry also denies, in its own aci,
        the operational attributes the default global ACIs grant.
        """
        constants = FlextLdifConstantsServersOid
        expected = list(plain)
        if operational is not None:
            expected.insert(
                1 if acl_type == "orclaci" else 2,
                (
                    constants.OUD_TARGETATTR_ALL,
                    None,
                    constants.OUD_GLOBAL_OPERATIONAL_PERMS,
                ),
            )

        tm.that(
            FlextLdifServersOidAclToOud.clause_parts(
                self._rule("entry", acl_type=acl_type),
                ("read", "search", "add"),
                deny=deny,
            ),
            eq=tuple(expected),
        )

    def test_clause_parts_keep_attribute_rights_whole(self) -> None:
        """Attribute rules render every right under the rule's own target."""
        tm.that(
            FlextLdifServersOidAclToOud.clause_parts(
                self._rule("attr", "cn"),
                ("read", "search"),
                deny=True,
            ),
            eq=((None, None, ("read", "search")),),
        )

    # -- in_scope ------------------------------------------------------

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("dn", "base_dn", "expected"),
        [
            ("dc=ctbc", "dc=ctbc", True),
            ("uid=joe,dc=ctbc", "dc=ctbc", True),
            ("dc=other", "dc=ctbc", False),
            ("dc=x", "", True),
        ],
    )
    def test_is_in_scope(dn: str, base_dn: str, *, expected: bool) -> None:
        """Test is in scope."""
        tm.that(FlextLdifServersOidAclToOud.in_scope(dn, base_dn), eq=expected)
